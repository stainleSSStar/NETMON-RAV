"""NetMon — HTTP API and app wiring.

Authentication: cookie session, PBKDF2 password hashing, first-run setup
creates the only initial account (an administrator). There are no default
credentials anywhere. Roles: ``admin`` (full control incl. SSH) and
``readonly`` (dashboards, charts, history — no changes, no shells).

Secrets (SNMP community / v3 keys / saved SSH passwords) are decrypted only
inside the server when a poll, test, walk or SSH connection needs them; they
are never included in API responses.
"""
import asyncio
import re
import sqlite3
import threading
import time
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager

from . import db, security, snmp as snmplib, stats
from .config import COOKIE_SECURE, DEFAULT_POLL_INTERVAL, FRONTEND_DIR, SESSION_TTL_HOURS
from .poller import Poller, ping, tcp_check
from .sshtransport import handle_ssh_ws

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,32}$")
_OID_RE = re.compile(r"^\.?\d+(\.\d+)*$")

poller = Poller()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init()
    await poller.start()
    yield
    await poller.stop()


app = FastAPI(
    title="NetMon",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,  # do not expose the schema publicly
)

_V3_AUTH_PROTOCOLS = ("SHA", "SHA224", "SHA256", "SHA384", "SHA512", "MD5")
_V3_PRIV_PROTOCOLS = ("AES", "AES128", "AES192", "AES256", "DES", "3DES")
_MAX_LOGIN_FAILURES = 10_000


# ------------------------------------------------------------------ helpers
def _user_dict(row) -> dict:
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "created_at": row["created_at"],
    }


def _set_cookie(response: JSONResponse, token: str):
    response.set_cookie(
        "session", token,
        httponly=True, samesite="lax", secure=COOKIE_SECURE,
        max_age=SESSION_TTL_HOURS * 3600, path="/",
    )


def get_current_user(request: Request):
    token = request.cookies.get("session")
    if not token:
        raise HTTPException(401, "Not authenticated")
    user = db.session_user(security.token_hash(token))
    if not user:
        raise HTTPException(401, "Session expired, please sign in again")
    return user


def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator role required")
    return user


def _decrypt_host_secrets(host: dict) -> dict:
    """Return a host dict with secrets decrypted for server-side use only."""
    try:
        return security.decrypt_host_secrets(host)
    except RuntimeError as exc:
        raise HTTPException(500, str(exc))


def _public_host(host) -> dict:
    cred = db.get_ssh_cred(host["id"])
    return {
        "id": host["id"],
        "name": host["name"],
        "address": host["address"],
        "ssh_port": host["ssh_port"],
        "snmp_port": host["snmp_port"],
        "snmp_enabled": bool(host["snmp_enabled"]),
        "snmp_version": host["snmp_version"],
        "has_community": bool(host["community"]),
        "v3_user": host["v3_user"],
        "v3_auth_proto": host["v3_auth_proto"],
        "v3_priv_proto": host["v3_priv_proto"],
        "has_v3_auth": bool(host["v3_auth_key"]),
        "has_v3_priv": bool(host["v3_priv_key"]),
        "check_method": host["check_method"],
        "check_port": host["check_port"],
        "poll_interval": host["poll_interval"],
        "enabled": bool(host["enabled"]),
        "notes": host["notes"] or "",
        "ssh_cred_username": cred["username"] if cred else None,
        "created_at": host["created_at"],
    }


def _parse_host_payload(payload: dict, existing=None) -> dict:
    """Validate a host create/update payload; blank secret fields keep old values."""
    data = {}

    name = str(payload.get("name") or "").strip()
    if not 1 <= len(name) <= 64:
        raise HTTPException(422, "Host name is required (max 64 characters)")
    data["name"] = name

    address = str(payload.get("address") or "").strip()
    if not address or len(address) > 255 or re.search(r"\s", address):
        raise HTTPException(422, "A valid host address (IP or DNS name) is required")
    data["address"] = address

    data["ssh_port"] = _int_field(payload, "ssh_port", 22, 1, 65535)
    data["snmp_port"] = _int_field(payload, "snmp_port", 161, 1, 65535)
    data["check_port"] = _int_field(payload, "check_port", 22, 1, 65535)
    data["poll_interval"] = _int_field(
        payload, "poll_interval", DEFAULT_POLL_INTERVAL, 10, 3600
    )
    data["snmp_enabled"] = 1 if payload.get("snmp_enabled", True) else 0

    version = str(payload.get("snmp_version") or "2c")
    if version not in ("1", "2c", "3"):
        raise HTTPException(422, "SNMP version must be 1, 2c or 3")
    data["snmp_version"] = version

    method = str(payload.get("check_method") or "icmp")
    if method not in ("icmp", "tcp", "snmp"):
        raise HTTPException(422, "Check method must be icmp, tcp or snmp")
    data["check_method"] = method

    data["enabled"] = 1 if payload.get("enabled", True) else 0
    data["notes"] = str(payload.get("notes") or "")[:500]
    snmp_enabled = bool(payload.get("snmp_enabled", True))
    data["snmp_enabled"] = 1 if snmp_enabled else 0

    def secret(field: str):
        value = payload.get(field)
        if value is None or value == "":
            return None  # keep existing
        value = str(value)
        # Cap secret length: they are encrypted and stored, and an unbounded
        # value would bloat the database and the PBKDF2-free crypto path.
        if len(value) > 512:
            raise HTTPException(422, f"Field '{field}' is too long (max 512 characters)")
        return security.encrypt_str(value)

    if not snmp_enabled:
        # SNMP off: no credentials required, stored ones are kept untouched.
        pass
    elif version == "3":
        user = str(payload.get("v3_user") or "").strip()
        if not user:
            raise HTTPException(422, "SNMPv3 requires a username (security name)")
        data["v3_user"] = user
        data["community"] = None
        data["v3_auth_proto"] = _choice(
            payload.get("v3_auth_proto"), _V3_AUTH_PROTOCOLS, "SHA", "SNMPv3 auth protocol"
        )
        data["v3_priv_proto"] = _choice(
            payload.get("v3_priv_proto"), _V3_PRIV_PROTOCOLS, "AES", "SNMPv3 privacy protocol"
        )
        has_existing_auth = bool(existing and existing["v3_auth_key"])
        if payload.get("v3_priv_key") and not payload.get("v3_auth_key") and not has_existing_auth:
            raise HTTPException(422, "SNMPv3 privacy requires an authentication key")
        for field in ("v3_auth_key", "v3_priv_key"):
            encrypted = secret(field)
            if encrypted is not None:
                data[field] = encrypted
            # blank/omitted -> keep the stored key (see the v2c branch)
    else:
        community = payload.get("community")
        if community:
            community = str(community)
            if len(community) > 512:
                raise HTTPException(422, "Community string is too long (max 512 characters)")
            data["community"] = security.encrypt_str(community)
        elif existing and existing["community"]:
            # Blank or omitted field: the edit form always posts an empty string
            # for untouched secrets, so this must mean "keep the stored value".
            pass
        else:
            raise HTTPException(422, f"SNMPv{version} requires a community string")
        data["v3_user"] = None
        data["v3_auth_proto"] = None
        data["v3_auth_key"] = None
        data["v3_priv_proto"] = None
        data["v3_priv_key"] = None

    return data


def _choice(value, allowed, default: str, label: str) -> str:
    """Normalise an enum-ish payload field, rejecting unknown values."""
    value = str(value or default).strip()
    if value not in allowed:
        raise HTTPException(422, f"{label} must be one of: {', '.join(allowed)}")
    return value


def _check_password(password: str, field: str = "Password"):
    """Reject empty / too-short / too-long passwords before hashing."""
    if len(password) < 10:
        raise HTTPException(422, f"{field} must be at least 10 characters")
    if len(password.encode("utf-8")) > security.MAX_PASSWORD_BYTES:
        raise HTTPException(422, f"{field} is too long (max 1 KB)")


def _int_field(payload: dict, field: str, default: int, low: int, high: int) -> int:
    # Clamp the default too, so an out-of-range NETMON_* env value cannot
    # smuggle a value past the per-field validation below.
    default = max(low, min(high, default))
    try:
        value = int(payload.get(field, default))
    except (TypeError, ValueError):
        raise HTTPException(422, f"Field '{field}' must be an integer")
    if not low <= value <= high:
        raise HTTPException(422, f"Field '{field}' must be between {low} and {high}")
    return value


_login_failures: dict = {}
_login_failures_lock = threading.Lock()


def _rate_limit_login(username: str):
    now = time.time()
    with _login_failures_lock:
        record = _login_failures.get(username)
        if record and record["count"] >= 5 and now - record["first"] < 300:
            raise HTTPException(429, "Too many failed attempts, please wait a few minutes")
        if record and now - record["first"] >= 300:
            _login_failures.pop(username, None)
        # Bound the map: without this, an attacker spraying random usernames
        # grows it until the process runs out of memory.
        if len(_login_failures) > _MAX_LOGIN_FAILURES:
            oldest = min(_login_failures, key=lambda k: _login_failures[k]["first"])
            _login_failures.pop(oldest, None)


def _note_login_failure(username: str):
    now = time.time()
    with _login_failures_lock:
        record = _login_failures.get(username)
        if record is None or now - record["first"] >= 300:
            _login_failures[username] = {"count": 1, "first": now}
        else:
            record["count"] += 1


# ------------------------------------------------------------------ public
@app.get("/api/state")
def api_state(request: Request):
    """Bootstrap state: is setup needed, and who (if anyone) is signed in."""
    user = None
    token = request.cookies.get("session")
    if token:
        row = db.session_user(security.token_hash(token))
        if row:
            user = _user_dict(row)
    return {"initialized": db.has_users(), "app_name": "NetMon", "user": user}


@app.get("/api/health")
def api_health():
    return {"ok": True, "ts": time.time()}


@app.post("/api/setup")
def api_setup(payload: dict):
    if db.has_users():
        raise HTTPException(409, "NetMon is already initialised")
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    if not _USERNAME_RE.match(username):
        raise HTTPException(
            422, "Username must be 3-32 characters: letters, digits, '_', '.', '-'"
        )
    _check_password(password)
    salt, digest = security.hash_password(password)
    try:
        user_id = db.create_user(username, salt, digest, "admin")
    except sqlite3.IntegrityError:
        # Two setups submitted at once: the first one won, this is not a crash.
        raise HTTPException(409, "NetMon is already initialised")
    token = security.new_token()
    db.create_session(security.token_hash(token), user_id, SESSION_TTL_HOURS * 3600)
    db.add_event(
        None, "setup", f"Administrator account '{username}' created on first run",
        actor=username,
    )
    response = JSONResponse({"user": _user_dict(db.get_user(user_id))})
    _set_cookie(response, token)
    return response


@app.post("/api/login")
def api_login(payload: dict):
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    _rate_limit_login(username)
    user = db.get_user_by_username(username)
    if not user or not security.verify_password(
        password, user["pass_salt"], user["pass_hash"]
    ):
        _note_login_failure(username)
        raise HTTPException(401, "Invalid username or password")
    _login_failures.pop(username, None)
    token = security.new_token()
    db.create_session(security.token_hash(token), user["id"], SESSION_TTL_HOURS * 3600)
    db.add_event(None, "login", f"User '{username}' signed in", actor=username)
    response = JSONResponse({"user": _user_dict(user)})
    _set_cookie(response, token)
    return response


@app.post("/api/logout")
def api_logout(request: Request):
    token = request.cookies.get("session")
    if token:
        db.delete_session(security.token_hash(token))
    response = JSONResponse({"ok": True})
    response.delete_cookie("session", path="/")
    return response


# ------------------------------------------------------------------ account
@app.get("/api/me")
def api_me(user=Depends(get_current_user)):
    return {"user": _user_dict(user)}


@app.post("/api/me/password")
def api_change_password(payload: dict, user=Depends(get_current_user)):
    old_password = str(payload.get("old_password") or "")
    new_password = str(payload.get("new_password") or "")
    if not security.verify_password(old_password, user["pass_salt"], user["pass_hash"]):
        raise HTTPException(401, "Current password is incorrect")
    if len(new_password) < 10:
        raise HTTPException(422, "New password must be at least 10 characters")
    _check_password(new_password, "New password")
    salt, digest = security.hash_password(new_password)
    db.update_user_password(user["id"], salt, digest)
    db.delete_user_sessions(user["id"])  # force re-login everywhere
    db.add_event(None, "password_changed", f"Password changed for '{user['username']}'",
                 actor=user["username"])
    response = JSONResponse({"ok": True})
    response.delete_cookie("session", path="/")
    return response


# ------------------------------------------------------------------ users
@app.get("/api/users")
def api_list_users(user=Depends(require_admin)):
    return {"users": [_user_dict(row) for row in db.list_users()]}


@app.post("/api/users")
def api_create_user(payload: dict, admin=Depends(require_admin)):
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    role = str(payload.get("role") or "readonly")
    if not _USERNAME_RE.match(username):
        raise HTTPException(
            422, "Username must be 3-32 characters: letters, digits, '_', '.', '-'"
        )
    if db.get_user_by_username(username):
        raise HTTPException(409, "That username already exists")
    if len(password) < 10:
        raise HTTPException(422, "Password must be at least 10 characters")
    _check_password(password)
    if role not in ("admin", "readonly"):
        raise HTTPException(422, "Role must be 'admin' or 'readonly'")
    try:
        salt, digest = security.hash_password(password)
        user_id = db.create_user(username, salt, digest, role)
    except sqlite3.IntegrityError:
        # Two concurrent creates both passed the existence check above.
        raise HTTPException(409, "That username already exists")
    db.add_event(None, "user_created",
                 f"{role.capitalize()} account '{username}' created",
                 actor=admin["username"])
    return {"user": _user_dict(db.get_user(user_id))}


@app.delete("/api/users/{user_id}")
def api_delete_user(user_id: int, admin=Depends(require_admin)):
    if user_id == admin["id"]:
        raise HTTPException(422, "You cannot delete your own account")
    target = db.get_user(user_id)
    if not target:
        raise HTTPException(404, "User not found")
    if target["role"] == "admin" and db.admin_count() <= 1:
        raise HTTPException(422, "At least one administrator account must remain")
    db.delete_user(user_id)
    db.delete_user_sessions(user_id)
    db.add_event(None, "user_deleted", f"Account '{target['username']}' deleted",
                 actor=admin["username"])
    return {"ok": True}


# ------------------------------------------------------------------ hosts
@app.get("/api/hosts")
def api_list_hosts(user=Depends(get_current_user)):
    hosts = []
    for host in db.all_hosts():
        item = _public_host(host)
        status = poller.status.get(host["id"], {})
        item["status"] = {
            "up": status.get("up"),
            "last_check": status.get("last_check"),
            "last_change": status.get("last_change"),
            "latency_ms": status.get("latency_ms"),
            "detail": status.get("detail"),
        }
        hosts.append(item)
    return {"hosts": hosts}


@app.get("/api/devices")
def api_devices(user=Depends(get_current_user)):
    """Flat device inventory for the Devices page.

    Deliberately separate from /api/hosts: this is the "every device I have,
    with its address and whether it is up" view, so it carries the monitoring
    summary rather than the full editable configuration.
    """
    devices = []
    for host in db.all_hosts():
        status = poller.status.get(host["id"], {})
        oids = db.host_oids(host["id"])
        enabled_oids = [r for r in oids if r["enabled"]]
        triggers = db.host_triggers(host["id"])
        breached = [t for t in triggers if t["breached"] and t["enabled"]]
        devices.append({
            "id": host["id"],
            "name": host["name"],
            "address": host["address"],
            "enabled": bool(host["enabled"]),
            "snmp_enabled": bool(host["snmp_enabled"]),
            "snmp_discovered": bool(host["snmp_discovered"]),
            "check_method": host["check_method"],
            "poll_interval": host["poll_interval"],
            "up": status.get("up"),
            "last_check": status.get("last_check"),
            "last_change": status.get("last_change"),
            "latency_ms": status.get("latency_ms"),
            "detail": status.get("detail"),
            "availability_24h": stats.compute_availability(host["id"], 24 * 3600),
            "oids_total": len(oids),
            "oids_enabled": len(enabled_oids),
            "triggers_total": len(triggers),
            "triggers_breached": len(breached),
        })
    return {"devices": devices}


@app.post("/api/hosts")
def api_create_host(payload: dict, admin=Depends(require_admin)):
    data = _parse_host_payload(payload)
    host_id = db.create_host(data)
    db.add_event(host_id, "host_added", f"Host '{data['name']}' added",
                 actor=admin["username"])
    await_reload()
    return {"host": _public_host(db.get_host(host_id))}


@app.get("/api/hosts/{host_id}")
def api_get_host(host_id: int, user=Depends(get_current_user)):
    host = db.get_host(host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    return {"host": _public_host(host)}


@app.put("/api/hosts/{host_id}")
def api_update_host(host_id: int, payload: dict, admin=Depends(require_admin)):
    host = db.get_host(host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    data = _parse_host_payload(payload, existing=host)
    db.update_host(host_id, data)
    db.add_event(host_id, "host_updated", f"Host '{data['name']}' updated",
                 actor=admin["username"])
    await_reload(host_id)
    return {"host": _public_host(db.get_host(host_id))}


@app.delete("/api/hosts/{host_id}")
def api_delete_host(host_id: int, admin=Depends(require_admin)):
    host = db.get_host(host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    name = host["name"]
    db.delete_host(host_id)
    db.add_event(None, "host_deleted", f"Host '{name}' deleted", actor=admin["username"])
    await_reload(host_id)
    return {"ok": True}


@app.post("/api/hosts/{host_id}/test")
async def api_test_host(host_id: int, admin=Depends(require_admin)):
    """Live connectivity + SNMP probe (runs the checks immediately)."""
    host = db.get_host(host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    host = _decrypt_host_secrets(host)
    result = {"address": host["address"], "ping": None, "snmp": None}

    ok, detail = await ping(host["address"])
    result["ping"] = {"ok": bool(ok), "detail": detail}

    if host["snmp_enabled"]:
        oids = [oid for oid, _ in db.DEFAULT_OIDS]
        oids += [row["oid"] for row in db.host_oids(host_id) if row["oid"] not in oids]
        snmp_result = await snmplib.snmp_get_multi(host, oids, 3.0, 1)
        if snmp_result.get("ok"):
            result["snmp"] = {
                "ok": True,
                "values": {
                    oid: text for oid, (text, _num) in snmp_result["values"].items()
                },
            }
        else:
            result["snmp"] = {"ok": False, "error": snmp_result.get("error")}
    return result


@app.post("/api/hosts/{host_id}/walk")
async def api_walk_host(host_id: int, payload: dict, admin=Depends(require_admin)):
    """Walk an SNMP subtree so the UI can offer OIDs to chart."""
    host = db.get_host(host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    host = _decrypt_host_secrets(host)
    base = str(payload.get("oid") or "1.3.6.1.2.1").strip()
    if not _OID_RE.match(base):
        raise HTTPException(422, "Invalid OID")
    result = await snmplib.snmp_walk(host, base, 250, 3.0)
    return result


# ------------------------------------------------------------------ oids
@app.get("/api/hosts/{host_id}/oids")
def api_list_oids(host_id: int, user=Depends(get_current_user)):
    if not db.get_host(host_id):
        raise HTTPException(404, "Host not found")
    latest = {row["oid"]: row for row in db.latest_values(host_id)}
    items = []
    for row in db.host_oids(host_id):
        sample = latest.get(row["oid"])
        items.append({
            "oid": row["oid"],
            "label": row["label"],
            "enabled": bool(row["enabled"]),
            "last_value": sample["value"] if sample else None,
            "last_num": sample["num"] if sample else None,
            "last_ts": sample["ts"] if sample else None,
        })
    for oid, label in db.DEFAULT_OIDS:
        if oid not in {i["oid"] for i in items}:
            sample = latest.get(oid)
            items.append({
                "oid": oid, "label": label, "builtin": True, "enabled": True,
                "last_value": sample["value"] if sample else None,
                "last_num": sample["num"] if sample else None,
                "last_ts": sample["ts"] if sample else None,
            })
    return {"oids": items}


@app.post("/api/hosts/{host_id}/oids")
def api_add_oid(host_id: int, payload: dict, admin=Depends(require_admin)):
    if not db.get_host(host_id):
        raise HTTPException(404, "Host not found")
    oid = str(payload.get("oid") or "").strip()
    label = str(payload.get("label") or "").strip()[:128]
    if not _OID_RE.match(oid):
        raise HTTPException(422, "Invalid OID (expected e.g. 1.3.6.1.2.1.1.3.0)")
    oid = oid.lstrip(".")
    db.add_oid(host_id, oid, label or oid)
    return {"ok": True}


@app.patch("/api/hosts/{host_id}/oids/{oid:path}")
def api_set_oid_enabled(host_id: int, oid: str, payload: dict,
                        admin=Depends(require_admin)):
    """Enable or disable polling for one OID.

    Disabling stops sampling but keeps the OID's config and its whole history,
    so it can be switched back on later without losing anything.
    """
    if not db.get_host(host_id):
        raise HTTPException(404, "Host not found")
    if "enabled" not in payload:
        raise HTTPException(422, "Body must contain 'enabled' (true or false)")
    oid = oid.lstrip(".")
    if not db.set_oid_enabled(host_id, oid, bool(payload["enabled"])):
        raise HTTPException(404, "OID not found for this host")
    return {"ok": True, "oid": oid, "enabled": bool(payload["enabled"])}


@app.post("/api/hosts/{host_id}/discover")
async def api_discover_host(host_id: int, admin=Depends(require_admin)):
    """Re-run the OID walk for a host, registering anything new.

    Discovery is idempotent: existing OIDs keep the enabled flag the user chose,
    so this is safe to run repeatedly and only ever adds.
    """
    host = db.get_host(host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    if not host["snmp_enabled"]:
        raise HTTPException(422, "SNMP is disabled for this host")
    try:
        host = _decrypt_host_secrets(host)
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))
    result = await snmplib.discover_oids(host)
    if not result.get("ok"):
        raise HTTPException(502, f"Discovery failed: {result.get('error', 'unknown')}")
    rows = [
        (oid, label, int(snmplib.is_essential_oid(oid)))
        for oid, label in result["oids"]
    ]
    db.add_oids_bulk(host_id, rows)
    db.mark_host_discovered(host_id)
    enabled = sum(1 for _, _, e in rows if e)
    db.add_event(
        host_id, "discovery",
        f"Discovered {len(rows)} OIDs; {enabled} enabled for polling"
        + (" (walk hit the discovery cap)" if result.get("capped") else ""),
        actor=admin["username"],
    )
    await_reload(host_id)
    return {
        "ok": True,
        "discovered": len(rows),
        "enabled": enabled,
        "capped": bool(result.get("capped")),
    }


@app.delete("/api/hosts/{host_id}/oids/{oid:path}")
def api_delete_oid(host_id: int, oid: str, admin=Depends(require_admin)):
    if not db.get_host(host_id):
        raise HTTPException(404, "Host not found")
    db.delete_oid(host_id, oid.lstrip("."))
    return {"ok": True}


# ------------------------------------------------------------------ charts
@app.get("/api/hosts/{host_id}/status")
def api_host_status(host_id: int, user=Depends(get_current_user)):
    if not db.get_host(host_id):
        raise HTTPException(404, "Host not found")
    status = dict(poller.status.get(host_id, {}))
    status["up"] = status.get("up")
    status["availability_24h"] = stats.compute_availability(host_id, 24 * 3600)
    status["availability_7d"] = stats.compute_availability(host_id, 7 * 86400)
    return status


@app.get("/api/hosts/{host_id}/uptime")
def api_host_uptime(host_id: int, hours: float = 24, user=Depends(get_current_user)):
    if not db.get_host(host_id):
        raise HTTPException(404, "Host not found")
    if hours <= 0 or hours > 24 * 90:
        raise HTTPException(422, "hours must be between 0 and 2160")
    return stats.uptime_buckets(host_id, hours)


@app.get("/api/hosts/{host_id}/series")
def api_host_series(
    host_id: int, oid: str, hours: float = 24, max_points: int = 600,
    user=Depends(get_current_user),
):
    if not db.get_host(host_id):
        raise HTTPException(404, "Host not found")
    if hours <= 0 or hours > 24 * 90:
        raise HTTPException(422, "hours must be between 0 and 2160")
    max_points = max(10, min(int(max_points), 3000))
    rows = db.samples_for_oid(host_id, oid, time.time() - hours * 3600)
    if len(rows) > max_points:
        step = len(rows) / max_points
        rows = [rows[int(i * step)] for i in range(max_points)]
    return {
        "oid": oid,
        "points": [
            {"t": row["ts"] * 1000, "v": row["num"], "s": row["value"]}
            for row in rows
        ],
    }


@app.get("/api/hosts/{host_id}/events")
def api_host_events(host_id: int, limit: int = 100, user=Depends(get_current_user)):
    if not db.get_host(host_id):
        raise HTTPException(404, "Host not found")
    limit = max(1, min(int(limit), 500))
    return {"events": [dict(row) for row in db.events(host_id, limit)]}


# ------------------------------------------------------------------ events
@app.get("/api/events")
def api_events(host_id: int = None, limit: int = 100,
               user=Depends(get_current_user)):
    limit = max(1, min(int(limit), 500))
    return {"events": [dict(row) for row in db.events(host_id, limit)]}


# ---------------------------------------------------------------- triggers
@app.get("/api/hosts/{host_id}/triggers")
def api_list_triggers(host_id: int, user=Depends(get_current_user)):
    if not db.get_host(host_id):
        raise HTTPException(404, "Host not found")
    return {"triggers": [dict(row) for row in db.host_triggers(host_id)]}


@app.post("/api/hosts/{host_id}/triggers")
def api_add_trigger(host_id: int, payload: dict, admin=Depends(require_admin)):
    if not db.get_host(host_id):
        raise HTTPException(404, "Host not found")
    oid = str(payload.get("oid") or "").strip().lstrip(".")
    if not _OID_RE.match(oid):
        raise HTTPException(422, "Invalid OID (expected e.g. 1.3.6.1.2.1.1.3.0)")
    op = str(payload.get("op") or ">=")
    if op not in db.TRIGGER_OPS:
        raise HTTPException(422, f"op must be one of {', '.join(db.TRIGGER_OPS)}")
    try:
        value = float(payload.get("value"))
    except (TypeError, ValueError):
        raise HTTPException(422, "value must be a number")
    trigger_id = db.add_trigger(
        host_id,
        oid,
        str(payload.get("label") or "").strip()[:128] or oid,
        op,
        value,
        delta=bool(payload.get("delta")),
        enabled=bool(payload.get("enabled", True)),
    )
    db.add_event(
        host_id, "trigger_added",
        f"Trigger '{oid} {op} {value}' added", actor=admin["username"],
    )
    return {"ok": True, "id": trigger_id}


@app.patch("/api/hosts/{host_id}/triggers/{trigger_id}")
def api_update_trigger(host_id: int, trigger_id: int, payload: dict,
                       admin=Depends(require_admin)):
    if not db.get_host(host_id):
        raise HTTPException(404, "Host not found")
    if not any(t["id"] == trigger_id for t in db.host_triggers(host_id)):
        raise HTTPException(404, "Trigger not found for this host")
    if "op" in payload and payload["op"] not in db.TRIGGER_OPS:
        raise HTTPException(422, f"op must be one of {', '.join(db.TRIGGER_OPS)}")
    if "value" in payload:
        try:
            payload["value"] = float(payload["value"])
        except (TypeError, ValueError):
            raise HTTPException(422, "value must be a number")
    try:
        db.update_trigger(trigger_id, **{
            k: v for k, v in payload.items()
            if k in ("label", "op", "value", "delta", "enabled")
        })
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    return {"ok": True}


@app.delete("/api/hosts/{host_id}/triggers/{trigger_id}")
def api_delete_trigger(host_id: int, trigger_id: int,
                       admin=Depends(require_admin)):
    if not db.get_host(host_id):
        raise HTTPException(404, "Host not found")
    if not any(t["id"] == trigger_id for t in db.host_triggers(host_id)):
        raise HTTPException(404, "Trigger not found for this host")
    db.delete_trigger(trigger_id)
    return {"ok": True}


# ---------------------------------------------------------------- compare
@app.get("/api/compare")
def api_compare(oid: str, hours: float = 24, user=Depends(get_current_user)):
    """Cross-host comparison table for one OID."""
    oid = (oid or "").strip().lstrip(".")
    if not _OID_RE.match(oid):
        raise HTTPException(422, "Invalid OID")
    if hours <= 0 or hours > 24 * 90:
        raise HTTPException(422, "hours must be between 0 and 2160")
    return {
        "oid": oid,
        "hours": hours,
        "rows": db.compare_oid(oid, time.time() - hours * 3600),
    }


@app.get("/api/compare/oids")
def api_compare_oids(user=Depends(get_current_user)):
    """OIDs available for comparison, most widely monitored first."""
    return {"oids": [dict(row) for row in db.distinct_oids_with_labels()]}


# ------------------------------------------------------------------ ssh creds
@app.get("/api/hosts/{host_id}/ssh-credentials")
def api_get_ssh_creds(host_id: int, admin=Depends(require_admin)):
    if not db.get_host(host_id):
        raise HTTPException(404, "Host not found")
    cred = db.get_ssh_cred(host_id)
    if not cred:
        return {"has_saved": False}
    return {"has_saved": True, "username": cred["username"]}


@app.post("/api/hosts/{host_id}/ssh-credentials")
def api_save_ssh_creds(host_id: int, payload: dict, admin=Depends(require_admin)):
    if not db.get_host(host_id):
        raise HTTPException(404, "Host not found")
    username = str(payload.get("username") or "").strip()[:128]
    password = str(payload.get("password") or "")
    if not username or not password:
        raise HTTPException(422, "Username and password are required")
    if len(password) > 1024 or len(username) > 128:
        raise HTTPException(422, "Credentials are too long")
    db.save_ssh_cred(host_id, username, security.encrypt_str(password))
    db.add_event(host_id, "ssh_creds_saved",
                 f"SSH credentials saved for '{username}'", actor=admin["username"])
    return {"ok": True}


@app.delete("/api/hosts/{host_id}/ssh-credentials")
def api_delete_ssh_creds(host_id: int, admin=Depends(require_admin)):
    if not db.get_host(host_id):
        raise HTTPException(404, "Host not found")
    db.delete_ssh_cred(host_id)
    db.add_event(host_id, "ssh_creds_deleted", "Saved SSH credentials removed",
                 actor=admin["username"])
    return {"ok": True}


# ------------------------------------------------------------------ websocket
@app.websocket("/ws/ssh/{host_id}")
async def websocket_ssh(websocket: WebSocket, host_id: int):
    # Cross-site WebSocket hijacking guard: a browser always sends Origin on an
    # upgrade, and the SPA is served from this same host, so anything else is a
    # foreign page trying to ride the admin's cookie.
    origin = websocket.headers.get("origin")
    if origin:
        origin_host = urlparse(origin).netloc.lower()
        host_header = (websocket.headers.get("host") or "").lower()
        if not origin_host or origin_host != host_header:
            await websocket.close(code=1008)
            return
    await websocket.accept()
    token = websocket.cookies.get("session")
    user = db.session_user(security.token_hash(token)) if token else None
    if not user:
        await websocket.send_text('{"type":"status","phase":"error","message":"Not authenticated"}')
        await websocket.close(code=1008)
        return
    await handle_ssh_ws(websocket, host_id, dict(user))


# ------------------------------------------------------------------ static
def _mount_static():
    if FRONTEND_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


_mount_static()


@app.get("/{full_path:path}", include_in_schema=False)
def spa_fallback(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(404, "Not found")
    index = FRONTEND_DIR / "index.html"
    if index.is_file():
        return FileResponse(index)
    return JSONResponse({"error": "frontend not found"}, status_code=500)


# ------------------------------------------------------------------ utils
def await_reload(host_id: int = None):
    """Schedule a poller reload from a sync endpoint (which runs in a worker
    thread, so we must hop onto the server's event loop)."""
    loop = getattr(poller, "loop", None)
    if loop is not None and loop.is_running():
        try:
            asyncio.run_coroutine_threadsafe(poller.reload(host_id), loop)
        except Exception:
            pass
