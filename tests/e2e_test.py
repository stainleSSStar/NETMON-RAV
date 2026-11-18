"""End-to-end tests for NetMon (no Docker needed).

Spins up the mini SNMP agent, the mini SSH server and the real FastAPI app,
then exercises the whole stack: first-run setup, auth/roles, host CRUD, live
polling (up/down transitions, SNMP sampling, charts data), OID browsing,
uptime statistics, the WebSocket SSH terminal, saved credentials, rate
limiting, password change and secret hygiene.

    python3 tests/e2e_test.py
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import time

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENV_PY = os.path.join(ROOT, ".venv", "bin", "python")
BASE = "http://127.0.0.1:8899"
APP_PORT = 8899
SNMP_PORT = None
SSH_PORT = None
ICMP_OK = None

results = []
skipped = []


def check(name, condition, detail="", skip=False):
    if skip:
        skipped.append(name)
        print(f"  [SKIP] {name} — {detail}", flush=True)
        return
    results.append((name, bool(condition), detail))
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail and not condition else ""), flush=True)


def free_port():
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def icmp_available():
    """True only when raw ICMP echo works here (sandboxes often block it)."""
    import subprocess as sp
    try:
        rc = sp.run(["ping", "-n", "-c", "1", "-W", "1000", "127.0.0.1"],
                    stdout=sp.DEVNULL, stderr=sp.DEVNULL, timeout=5).returncode
    except Exception:
        return False
    return rc == 0


def wait_port(port, timeout=15):
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def wait_snmp(port, timeout=15):
    """UDP readiness probe: send a real GET for sysName and expect a reply."""
    import socket
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    import snmp_agent
    request = snmp_agent.tlv(
        0x30,
        snmp_agent.enc_int(1) + snmp_agent.enc_octet("public")
        + snmp_agent.tlv(
            0xA0,
            snmp_agent.enc_int(1) + snmp_agent.enc_int(0) + snmp_agent.enc_int(0)
            + snmp_agent.tlv(0x30, snmp_agent.tlv(0x30,
                  snmp_agent.enc_oid("1.3.6.1.2.1.1.5.0") + snmp_agent.enc_null())),
        ),
    )
    deadline = time.time() + timeout
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    try:
        while time.time() < deadline:
            try:
                sock.sendto(request, ("127.0.0.1", port))
                data, _ = sock.recvfrom(4096)
                if data:
                    return True
            except OSError:
                time.sleep(0.3)
    finally:
        sock.close()
    return False


def main():
    global BASE, APP_PORT, SNMP_PORT, SSH_PORT, ICMP_OK
    ICMP_OK = icmp_available()
    print(f"== environment: ICMP echo {'available' if ICMP_OK else 'BLOCKED (checks will skip)'} ==",
          flush=True)

    data_dir = os.path.join(ROOT, "data-e2e")
    shutil.rmtree(data_dir, ignore_errors=True)
    os.makedirs(data_dir, exist_ok=True)

    env = dict(os.environ)
    env.update({
        "NETMON_DATA_DIR": data_dir,
        "NETMON_FRONTEND_DIR": os.path.join(ROOT, "frontend"),
        "NETMON_POLL_INTERVAL": "10",
        "NETMON_RETENTION_DAYS": "30",
        "PYTHONUNBUFFERED": "1",
    })

    # Free ports so repeated runs (or a stale agent) never collide.
    SNMP_PORT = free_port()
    SSH_PORT = free_port()
    APP_PORT = free_port()
    BASE = f"http://127.0.0.1:{APP_PORT}"

    procs = []
    try:
        print(f"== starting test servers (snmp={SNMP_PORT} ssh={SSH_PORT} app={APP_PORT}) ==",
              flush=True)
        snmp = subprocess.Popen([VENV_PY, os.path.join(ROOT, "tests", "snmp_agent.py"),
                                 "--port", str(SNMP_PORT)], env=env)
        sshsrv = subprocess.Popen([VENV_PY, os.path.join(ROOT, "tests", "ssh_server.py"),
                                   "--port", str(SSH_PORT)], env=env)
        procs += [snmp, sshsrv]
        assert wait_snmp(SNMP_PORT), "snmp agent did not start"
        assert wait_port(SSH_PORT), "ssh server did not start"

        app = subprocess.Popen(
            [VENV_PY, "-m", "uvicorn", "backend.app:app", "--host", "127.0.0.1",
             "--port", str(APP_PORT), "--log-level", "info"],
            cwd=ROOT, env=env)
        procs.append(app)
        assert wait_port(APP_PORT, 30), "app did not start"
        time.sleep(1)

        run_tests()

    finally:
        print("\n== shutting down ==", flush=True)
        for proc in procs:
            proc.send_signal(signal.SIGTERM)
        for proc in procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(data_dir, ignore_errors=True)

    failed = [r for r in results if not r[1]]
    print(f"\n===== {len(results) - len(failed)}/{len(results)} checks passed"
          f" ({len(skipped)} skipped) =====", flush=True)
    if skipped:
        print("SKIPPED (environment limitation, not a product defect):")
        for name in skipped:
            print(f"  - {name}")
    if failed:
        print("FAILED:")
        for name, _ok, detail in failed:
            print(f"  - {name} {detail}")
        sys.exit(1)


def run_tests():
    s = requests.Session()

    print("\n== first-run setup & auth ==", flush=True)
    r = s.get(BASE + "/api/state", timeout=5)
    check("state: uninitialised before setup", r.status_code == 200 and r.json()["initialized"] is False, r.text)
    check("state: no user before setup", r.json()["user"] is None)

    r = s.post(BASE + "/api/setup", json={"username": "admin", "password": "short"}, timeout=5)
    check("setup rejects short password", r.status_code == 422, f"got {r.status_code}")

    r = s.post(BASE + "/api/setup", json={"username": "ad", "password": "longenoughpassword"}, timeout=5)
    check("setup rejects short username", r.status_code == 422, f"got {r.status_code}")

    r = s.post(BASE + "/api/setup", json={"username": "admin", "password": "longenoughpassword"}, timeout=5)
    check("setup creates admin", r.status_code == 200 and r.json()["user"]["role"] == "admin", r.text)
    admin_cookie = s.cookies.get("session")
    check("setup sets session cookie", bool(admin_cookie))

    r = s.post(BASE + "/api/setup", json={"username": "other", "password": "longenoughpassword"}, timeout=5)
    check("second setup refused (409)", r.status_code == 409, f"got {r.status_code}")

    r = s.get(BASE + "/api/me", timeout=5)
    check("me returns admin", r.status_code == 200 and r.json()["user"]["username"] == "admin")

    r = s.post(BASE + "/api/login", json={"username": "admin", "password": "wrong"}, timeout=5)
    check("login with wrong password rejected", r.status_code == 401, f"got {r.status_code}")

    print("\n== hosts ==", flush=True)
    def add_host(payload):
        return s.post(BASE + "/api/hosts", json=payload, timeout=5)

    h1 = add_host({
        "name": "snmp-agent-host", "address": "127.0.0.1",
        "check_method": "snmp", "snmp_version": "2c", "community": "public",
        "snmp_port": SNMP_PORT, "poll_interval": 10, "ssh_port": SSH_PORT,
    })
    check("create v2c host", h1.status_code == 200, h1.text)
    host1 = h1.json()["host"]
    check("community never returned to client", "community" not in host1 and host1["has_community"] is True)

    h2 = add_host({
        "name": "unreachable-host", "address": "192.0.2.1",
        "check_method": "tcp", "check_port": 81, "snmp_enabled": False,
        "poll_interval": 10,
    })
    check("create host without SNMP", h2.status_code == 200, h2.text)
    host2 = h2.json()["host"]

    h3 = add_host({
        "name": "tcp-check-host", "address": "127.0.0.1",
        "check_method": "tcp", "check_port": SSH_PORT, "snmp_enabled": False,
        "poll_interval": 10,
    })
    check("create TCP-check host", h3.status_code == 200, h3.text)
    host3 = h3.json()["host"]

    h4 = add_host({
        "name": "snmp-check-host", "address": "127.0.0.1",
        "check_method": "snmp", "snmp_version": "2c", "community": "public",
        "snmp_port": SNMP_PORT, "poll_interval": 10,
    })
    check("create SNMP-check host", h4.status_code == 200, h4.text)
    host4 = h4.json()["host"]

    h6 = add_host({
        "name": "icmp-check-host", "address": "127.0.0.1",
        "check_method": "icmp", "snmp_enabled": False, "poll_interval": 10,
    })
    check("create ICMP-check host", h6.status_code == 200, h6.text)
    host6 = h6.json()["host"]

    h7 = add_host({
        "name": "v1-host", "address": "127.0.0.1", "check_method": "snmp",
        "snmp_version": "1", "community": "public",
        "snmp_port": SNMP_PORT, "poll_interval": 10,
    })
    check("create v1 host", h7.status_code == 200, h7.text)
    host7 = h7.json()["host"]

    h5 = add_host({
        "name": "v3-host", "address": "127.0.0.1", "check_method": "snmp",
        "snmp_version": "3", "v3_user": "secuser", "v3_auth_proto": "SHA",
        "v3_auth_key": "authkey12345", "v3_priv_proto": "AES", "v3_priv_key": "privkey12345",
        "snmp_port": SNMP_PORT, "poll_interval": 10,
    })
    check("create v3 host (authPriv)", h5.status_code == 200, h5.text)
    host5 = h5.json()["host"]
    check("v3 keys never returned", "v3_auth_key" not in host5 and host5["has_v3_auth"] is True)

    bad = add_host({"name": "no-community", "address": "127.0.0.1", "snmp_version": "2c"})
    check("v2c host without community rejected", bad.status_code == 422, f"got {bad.status_code}")

    bad = add_host({"name": "bad-v3", "address": "127.0.0.1", "snmp_version": "3",
                    "v3_priv_key": "privkey12345"})
    check("v3 priv without auth rejected", bad.status_code == 422, f"got {bad.status_code}")

    print("\n== polling & events ==", flush=True)
    def status_of(hid):
        return s.get(BASE + f"/api/hosts/{hid}/status", timeout=5).json()

    deadline = time.time() + 25
    while time.time() < deadline:
        st1, st4, st7 = (status_of(host1["id"]), status_of(host4["id"]),
                         status_of(host7["id"]))
        if st1.get("up") is True and st4.get("up") is True and st7.get("up") is True:
            break
        time.sleep(1)

    # Slow checks (unreachable TCP, v3 timeouts) finish after the fast ones, so
    # wait until every host has actually been probed at least once.
    every_host = [host1, host2, host3, host4, host5, host6, host7]
    deadline = time.time() + 30
    while time.time() < deadline:
        if all(status_of(h["id"]).get("last_check") for h in every_host):
            break
        time.sleep(1)
    check("snmp-check host (v2c) detected UP", status_of(host1["id"]).get("up") is True,
          json.dumps(status_of(host1["id"])))
    check("snmp-check host detected UP", status_of(host4["id"]).get("up") is True,
          json.dumps(status_of(host4["id"])))
    check("v1 host detected UP", status_of(host7["id"]).get("up") is True,
          json.dumps(status_of(host7["id"])))
    check("tcp host detected UP", status_of(host3["id"]).get("up") is True,
          json.dumps(status_of(host3["id"])))
    check("icmp host detected UP", status_of(host6["id"]).get("up") is True,
          json.dumps(status_of(host6["id"])),
          skip=not ICMP_OK)
    check("unreachable host detected DOWN", status_of(host2["id"]).get("up") is False,
          json.dumps(status_of(host2["id"])))
    check("v3 host fails gracefully (DOWN, no crash)",
          status_of(host5["id"]).get("up") is False)

    events = s.get(BASE + f"/api/hosts/{host1['id']}/events?limit=50", timeout=5).json()["events"]
    types = [e["type"] for e in events]
    check("host events include up transition", "up" in types, str(types))

    all_events = s.get(BASE + "/api/events?limit=50", timeout=5).json()["events"]
    check("event feed includes host_added", any(e["type"] == "host_added" for e in all_events))
    check("event feed includes setup", any(e["type"] == "setup" for e in all_events))
    check("unreachable host logged DOWN", any(
        e["type"] == "down" and e["host_id"] == host2["id"] for e in all_events))

    print("\n== snmp values, oids, charts ==", flush=True)
    oids = s.get(BASE + f"/api/hosts/{host1['id']}/oids", timeout=5).json()["oids"]
    by_oid = {o["oid"]: o for o in oids}
    check("built-in sysName sampled", by_oid.get("1.3.6.1.2.1.1.5.0", {}).get("last_value") == "netmon-test",
          json.dumps(by_oid.get("1.3.6.1.2.1.1.5.0")))
    check("built-in sysUpTime sampled", by_oid.get("1.3.6.1.2.1.1.3.0", {}).get("last_num") is not None,
          json.dumps(by_oid.get("1.3.6.1.2.1.1.3.0")))

    v1_oids = s.get(BASE + f"/api/hosts/{host7['id']}/oids", timeout=5).json()["oids"]
    v1_by_oid = {o["oid"]: o for o in v1_oids}
    check("v1 host samples sysName",
          v1_by_oid.get("1.3.6.1.2.1.1.5.0", {}).get("last_value") == "netmon-test",
          json.dumps(v1_by_oid.get("1.3.6.1.2.1.1.5.0")))

    r = s.post(BASE + f"/api/hosts/{host1['id']}/oids",
               json={"oid": "1.3.6.1.2.1.2.2.1.10.1", "label": "ifInOctets.1"}, timeout=5)
    check("add custom OID", r.status_code == 200, r.text)

    r = s.post(BASE + f"/api/hosts/{host1['id']}/oids", json={"oid": "not-an-oid"}, timeout=5)
    check("invalid OID rejected", r.status_code == 422, f"got {r.status_code}")

    deadline = time.time() + 25
    while time.time() < deadline:
        series = s.get(BASE + f"/api/hosts/{host1['id']}/series"
                       "?oid=1.3.6.1.2.1.2.2.1.10.1&hours=1", timeout=5).json()
        if len(series["points"]) >= 2:
            break
        time.sleep(2)
    vals = [p["v"] for p in series["points"]]
    check("custom OID series has samples", len(vals) >= 2, str(vals))
    check("counter values increase", len(vals) >= 2 and vals[-1] > vals[0], str(vals))

    walk = s.post(BASE + f"/api/hosts/{host1['id']}/walk",
                  json={"oid": "1.3.6.1.2.1.2.2.1.2"}, timeout=15).json()
    check("walk returns ifDescr rows", walk.get("ok") and len(walk.get("rows", [])) >= 3, json.dumps(walk)[:200])
    if walk.get("rows"):
        check("walk values correct", any(r["value"] == "eth0" for r in walk["rows"]), str(walk["rows"]))

    walk_leaf = s.post(BASE + f"/api/hosts/{host1['id']}/walk",
                       json={"oid": "1.3.6.1.2.1.1.5.0"}, timeout=15).json()
    check("walk of a scalar OID returns that value",
          walk_leaf.get("ok") and any(r["oid"] == "1.3.6.1.2.1.1.5.0" and r["value"] == "netmon-test"
                                      for r in walk_leaf.get("rows", [])),
          json.dumps(walk_leaf)[:200])

    walk_v1 = s.post(BASE + f"/api/hosts/{host7['id']}/walk",
                     json={"oid": "1.3.6.1.2.1.1"}, timeout=15).json()
    check("v1 walk (GETNEXT) returns system rows",
          walk_v1.get("ok") and len(walk_v1.get("rows", [])) >= 3, json.dumps(walk_v1)[:200])

    test = s.post(BASE + f"/api/hosts/{host1['id']}/test", timeout=20).json()
    check("test endpoint: ping ok", test["ping"]["ok"] is True, json.dumps(test["ping"]),
          skip=not ICMP_OK)
    check("test endpoint: snmp values", test["snmp"]["ok"] and
          test["snmp"]["values"].get("1.3.6.1.2.1.1.5.0") == "netmon-test",
          json.dumps(test["snmp"])[:200])

    uptime = s.get(BASE + f"/api/hosts/{host1['id']}/uptime?hours=24", timeout=5).json()
    check("uptime buckets present", len(uptime["buckets"]) > 0)
    check("availability computed", uptime["availability"]["availability_pct"] is not None,
          json.dumps(uptime["availability"]))

    print("\n== roles ==", flush=True)
    r = s.post(BASE + "/api/users", json={"username": "viewer", "password": "viewerpassword",
                                          "role": "readonly"}, timeout=5)
    check("create read-only user", r.status_code == 200, r.text)

    ro = requests.Session()
    r = ro.post(BASE + "/api/login", json={"username": "viewer", "password": "viewerpassword"}, timeout=5)
    check("read-only login", r.status_code == 200, r.text)

    r = ro.get(BASE + "/api/hosts", timeout=5)
    check("read-only can list hosts", r.status_code == 200, f"got {r.status_code}")
    r = ro.post(BASE + "/api/hosts", json={"name": "x", "address": "127.0.0.1"}, timeout=5)
    check("read-only cannot create host", r.status_code == 403, f"got {r.status_code}")
    r = ro.post(BASE + f"/api/hosts/{host1['id']}/test", timeout=5)
    check("read-only cannot test host", r.status_code == 403, f"got {r.status_code}")
    r = ro.get(BASE + "/api/users", timeout=5)
    check("read-only cannot list users", r.status_code == 403, f"got {r.status_code}")
    r = ro.post(BASE + f"/api/hosts/{host1['id']}/ssh-credentials",
                json={"username": "u", "password": "p"}, timeout=5)
    check("read-only cannot save ssh creds", r.status_code == 403, f"got {r.status_code}")

    print("\n== ssh terminal ==", flush=True)
    import asyncio
    import websockets

    async def ws_probe(cookie, payload, expect, timeout=20):
        uri = f"ws://127.0.0.1:{APP_PORT}/ws/ssh/{host1['id']}"
        async with websockets.connect(uri, additional_headers={"Cookie": f"session={cookie}"},
                                      open_timeout=10) as ws:
            await ws.send(json.dumps(payload))
            chunks = []
            try:
                while True:
                    msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    if isinstance(msg, bytes):
                        chunks.append(msg.decode("utf-8", "replace"))
                    else:
                        data = json.loads(msg)
                        if data.get("type") == "status" and data.get("phase") == "error":
                            return "ERROR:" + data["message"], chunks
                    if any(expect in c for c in chunks):
                        break
            except asyncio.TimeoutError:
                pass
            return None, chunks

    r = s.post(BASE + f"/api/hosts/{host1['id']}/ssh-credentials",
               json={"username": "sshtest", "password": "sshpass123"}, timeout=5)
    check("admin saves ssh credentials", r.status_code == 200, r.text)
    r = s.get(BASE + f"/api/hosts/{host1['id']}/ssh-credentials", timeout=5)
    check("saved creds expose username only", r.json() == {"has_saved": True, "username": "sshtest"}, r.text)

    async def ws_session():
        uri = f"ws://127.0.0.1:{APP_PORT}/ws/ssh/{host1['id']}"
        async with websockets.connect(uri, additional_headers={"Cookie": f"session={admin_cookie}"},
                                      open_timeout=10) as ws:
            await ws.send(json.dumps({
                "username": "sshtest", "password": "sshpass123",
                "use_saved": True, "cols": 100, "rows": 30,
            }))
            output = ""
            banner = False
            try:
                while True:
                    msg = await asyncio.wait_for(ws.recv(), timeout=15)
                    if isinstance(msg, bytes):
                        output += msg.decode("utf-8", "replace")
                        if "mini-ssh$" in output:
                            banner = True
                            break
                    else:
                        data = json.loads(msg)
                        if data.get("phase") == "error":
                            return False, data["message"]
            except asyncio.TimeoutError:
                return banner, output
            if not banner:
                return False, output
            await ws.send(b"echo hello-netmon\r")
            reply = ""
            try:
                while "you said: echo hello-netmon" not in reply:
                    msg = await asyncio.wait_for(ws.recv(), timeout=10)
                    if isinstance(msg, bytes):
                        reply += msg.decode("utf-8", "replace")
            except asyncio.TimeoutError:
                return False, reply
            await ws.send(b"\x03")  # Ctrl-C, ignored by mini shell
            await ws.send(json.dumps({"type": "resize", "cols": 120, "rows": 40}))
            await asyncio.sleep(0.3)
            return True, output + reply

    ok, detail = asyncio.run(ws_session())
    check("ssh terminal round-trip (saved creds)", ok, str(detail)[:300])

    err, _chunks = asyncio.run(
        ws_probe(admin_cookie,
                 {"username": "sshtest", "password": "wrongpass", "cols": 80, "rows": 24},
                 "nothing-expected", timeout=10))
    check("ssh with wrong password reports error", isinstance(err, str) and err.startswith("ERROR"), str(err))

    async def ws_readonly():
        ro_cookie = ro.cookies.get("session")
        uri = f"ws://127.0.0.1:{APP_PORT}/ws/ssh/{host1['id']}"
        # The server rejects read-only sockets right after the handshake, which
        # can race ahead of the client's init frame — both outcomes are valid
        # rejections as long as the close code is 1008 (policy violation).
        try:
            async with websockets.connect(uri, additional_headers={"Cookie": f"session={ro_cookie}"},
                                          open_timeout=10) as ws:
                await ws.send(json.dumps({"username": "a", "password": "b", "cols": 80, "rows": 24}))
                msg = await asyncio.wait_for(ws.recv(), timeout=10)
                data = json.loads(msg)
                return data.get("phase") == "error" and "administrator" in data.get("message", "")
        except websockets.exceptions.ConnectionClosedError as exc:
            return getattr(getattr(exc, "rcvd", None), "code", None) == 1008

    check("read-only cannot open ssh", asyncio.run(ws_readonly()))

    time.sleep(1)
    all_events = s.get(BASE + "/api/events?limit=100", timeout=5).json()["events"]
    types = [e["type"] for e in all_events]
    check("ssh_open event logged", "ssh_open" in types, str(types))
    check("ssh_fail event logged", "ssh_fail" in types, str(types))
    check("ssh_close event logged", "ssh_close" in types, str(types))
    check("ssh creds saved event logged", "ssh_creds_saved" in types, str(types))

    print("\n== account security ==", flush=True)
    time.sleep(1)
    r = s.post(BASE + "/api/me/password",
               json={"old_password": "longenoughpassword", "new_password": "newpassword123"}, timeout=5)
    check("password change works", r.status_code == 200, r.text)
    r = s.get(BASE + "/api/me", timeout=5)
    check("old session invalidated after password change", r.status_code == 401, f"got {r.status_code}")

    s2 = requests.Session()
    r = s2.post(BASE + "/api/login", json={"username": "admin", "password": "newpassword123"}, timeout=5)
    check("login with new password", r.status_code == 200, r.text)
    s.cookies.clear()
    s.cookies.set("session", s2.cookies.get("session"))

    r = s.delete(BASE + f"/api/users/{ [u['id'] for u in s.get(BASE + '/api/users').json()['users'] if u['username']=='admin'][0] }", timeout=5)
    check("cannot delete own account", r.status_code == 422, f"got {r.status_code}")

    r = s.post(BASE + "/api/users", json={"username": "admin2", "password": "admin2password",
                                          "role": "admin"}, timeout=5)
    check("create second admin", r.status_code == 200, r.text)
    admin2_id = r.json()["user"]["id"]
    r = s.delete(BASE + f"/api/users/{admin2_id}", timeout=5)
    check("delete second admin", r.status_code == 200, f"got {r.status_code}")

    viewer_id = [u["id"] for u in s.get(BASE + "/api/users").json()["users"] if u["username"] == "viewer"][0]
    r = s.delete(BASE + f"/api/users/{viewer_id}", timeout=5)
    check("delete read-only user", r.status_code == 200, f"got {r.status_code}")

    print("\n== login rate limiting ==", flush=True)
    rl = requests.Session()
    for i in range(5):
        rl.post(BASE + "/api/login", json={"username": "admin", "password": f"wrong{i}"}, timeout=5)
    r = rl.post(BASE + "/api/login", json={"username": "admin", "password": "wrong-again"}, timeout=5)
    check("login rate limit kicks in (429)", r.status_code == 429, f"got {r.status_code}")
    r = s.get(BASE + "/api/me", timeout=5)
    check("existing session survives lockout", r.status_code == 200, f"got {r.status_code}")

    print("\n== host lifecycle ==", flush=True)
    r = s.put(BASE + f"/api/hosts/{host1['id']}", json={
        "name": "snmp-agent-host", "address": "127.0.0.1", "check_method": "icmp",
        "snmp_version": "2c", "community": "", "snmp_port": SNMP_PORT,
        "poll_interval": 10, "ssh_port": SSH_PORT, "notes": "updated",
    }, timeout=5)
    check("update host keeps community when blank", r.status_code == 200 and
          r.json()["host"]["has_community"] is True, r.text)

    r = s.delete(BASE + f"/api/hosts/{host5['id']}", timeout=5)
    check("delete v3 host", r.status_code == 200, f"got {r.status_code}")
    r = s.get(BASE + f"/api/hosts/{host5['id']}/oids", timeout=5)
    check("deleted host data gone", r.status_code == 404, f"got {r.status_code}")

    print("\n== static frontend ==", flush=True)
    r = requests.get(BASE + "/", timeout=5)
    check("index.html served", r.status_code == 200 and "NetMon" in r.text)
    for path in ("/static/app.js", "/static/styles.css",
                 "/static/vendor/chart.umd.min.js", "/static/vendor/xterm.js",
                 "/static/vendor/addon-fit.js", "/static/vendor/xterm.css"):
        r = requests.get(BASE + path, timeout=5)
        check(f"served {path}", r.status_code == 200 and len(r.content) > 100, f"got {r.status_code}")


if __name__ == "__main__":
    main()
