# Installing NetMon

NetMon is a single self-hosted service: one container, one state directory. This
guide covers every supported way to install it, how to verify it works, how to
put it behind HTTPS, and how to back the state up.

- [What you need](#what-you-need)
- [Quick start (Docker Compose)](#quick-start-docker-compose)
- [First run — create the administrator](#first-run--create-the-administrator)
- [Verify the install](#verify-the-install)
- [Other install methods](#other-install-methods)
- [Platform notes](#platform-notes)
- [Putting it behind HTTPS](#putting-it-behind-https)
- [Configuration](#configuration)
- [Backup and restore](#backup-and-restore)
- [Updating](#updating)
- [Uninstalling](#uninstalling)
- [Troubleshooting](#troubleshooting)

---

## What you need

| Requirement | For Docker install | For a bare install |
| --- | --- | --- |
| Engine | Docker 20.10+ **or** Podman with `compose` | — |
| Python | — | 3.10 or newer |
| RAM | ~150 MB | ~150 MB |
| Disk | ~1 GB for the image + your history | ~200 MB |
| Network | one free TCP port (8080 by default) | same |

Nothing else. No database server, no Redis, no message queue — NetMon uses
SQLite and stores everything in one directory.

You do **not** need to open any inbound ports to the internet. This is a tool for
internal networks; see [Putting it behind HTTPS](#putting-it-behind-https) before
you expose it anywhere.

---

## Quick start (Docker Compose)

```bash
git clone https://github.com/stainleSSStar/NETMON-RAV.git
cd NETMON-RAV
docker compose up -d --build
```

That is the whole install. It builds the image, starts the container, and creates
`./data/` next to `docker-compose.yml` on first run.

Then open <http://localhost:8080> and create your administrator account
([next section](#first-run--create-the-administrator)).

### macOS, or Docker Desktop with a bind mount

`docker-compose.yml` stores state in `./data`, a **bind mount**. The image runs as
uid 10001, but a bind mount on macOS is owned by your host user — so the
container cannot write to it and you get an error about the database. Pass your
own ids:

```bash
NETMON_UID=$(id -u) NETMON_GID=$(id -g) docker compose up -d --build
```

To make it permanent, put it in a `.env` file next to `docker-compose.yml`:

```
NETMON_UID=501
NETMON_GID=20
```

(Find yours with `id -u` and `id -g`.) On Linux with a local directory, or
anywhere with a named Docker volume instead of `./data`, the defaults work and
you can skip this.

### Plain `docker run` instead of Compose

```bash
docker build -t netmon:latest .
docker run -d \
  --name netmon \
  -p 8080:8080 \
  --cap-add NET_RAW \
  -v "$PWD/data:/data" \
  --restart unless-stopped \
  netmon:latest
```

`--cap-add NET_RAW` is what lets the unprivileged container user run ICMP ping.
If your policy forbids raw sockets, drop the flag and use the TCP or SNMP check
method for your hosts instead — everything else works unchanged.

---

## First run — create the administrator

The very first page you see is the setup screen. **There are no default
credentials** — nothing is pre-set, and nothing is printed anywhere.

1. **Username** — 3–32 characters: letters, digits, `_`, `.`, `-`.
2. **Password** — at least 10 characters. There is no composition rule, but use a
   password manager value; this account can open a shell on your devices.

After that you land on the dashboard. The setup screen never appears again: the
database records that it has been initialised.

> **Never commit `data/`.** It holds `netmon.db` and `secret.key` — the Fernet key
> that decrypts every stored SNMP community, v3 key and saved SSH password.
> `.gitignore` already excludes it. Keep it that way, especially in a public repo.

---

## Verify the install

Four checks, fastest first:

```bash
# 1. Is the container healthy?
docker compose ps          # STATUS should read "healthy" (takes ~10 s)

# 2. Does the API answer?
curl http://localhost:8080/api/health
# {"ok":true,"ts":...}

# 3. Is it asking for setup (i.e. a fresh, un-initialised database)?
curl http://localhost:8080/api/state
# {"initialized":false,...}   → still needs the admin account
# {"initialized":true,...}    → already set up
```

4. Open <http://localhost:8080> in a browser, sign in, then **+ Add host** and add
   something you know is reachable — your router, a switch, `127.0.0.1` itself for
   a TCP check. The first poll happens immediately and the card should flip to
   **up** within a few seconds, with an entry in the event log.

If step 2 fails, see [Troubleshooting](#troubleshooting).

---

## Other install methods

### From a release tarball

Every release on the [releases page](https://github.com/stainleSSStar/NETMON-RAV/releases)
has a source archive — no `git` needed:

```bash
curl -LO https://github.com/stainleSSStar/NETMON-RAV/archive/refs/tags/v1.1.0.tar.gz
tar xzf v1.1.0.tar.gz
cd NETMON-RAV-1.1.0
docker compose up -d --build
```

### Without Docker (development / bare metal)

```bash
git clone https://github.com/stainleSSStar/NETMON-RAV.git
cd NETMON-RAV
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt

NETMON_DATA_DIR=./data NETMON_FRONTEND_DIR=./frontend \
  .venv/bin/uvicorn backend.app:app --host 0.0.0.0 --port 8080
```

Notes for a bare install:

- `pysnmp` is pinned to `>=6.1,<6.2` on purpose. The SNMP code uses the native
  asyncio API (`pysnmp.hlapi.asyncio`), whose signatures changed in 6.2 and 7.x.
  `pip install pysnmp` without the pin resolves to 7.x and the polls fail.
- ICMP ping needs privileges outside a container: run with `sudo`, or just use
  TCP/SNMP check methods and skip ping entirely.
- `NETMON_DATA_DIR` must be writable and **must not** be inside a directory you
  later delete; it holds the only copy of your history and the encryption key.
- The test suite needs no Docker and runs the whole stack:

  ```bash
  .venv/bin/python tests/e2e_test.py
  ```

### Podman

Compose works with the `podman-compose` shim. The one thing to watch is SELinux:
a bind-mounted `./data` needs the `:z` label or the container gets denied:

```bash
podman-compose up -d --build    # with -v "$PWD/data:/data:z"
```

---

## Platform notes

**Linux (native Docker)** — nothing special. Use the defaults.

**macOS** — see the uid/gid note in
[Quick start](#quick-start-docker-compose). Docker Desktop is fine; Colima works
too as long as the VM can write the bind mount.

**Windows / WSL2** — run everything from inside WSL2 (Ubuntu), not from
PowerShell, so paths and `id -u` behave. Clone into the Linux filesystem
(`~/netmon`), not `/mnt/c/...`, or SQLite performance and file locking get ugly.

**Synology / QNAP NAS** — Container Manager works. Mount the state directory to a
path you back up, and note that these run on ARM or x86 depending on model; the
image is multi-arch via `python:3.12-slim`.

**Raspberry Pi (64-bit)** — fine. The app idles at ~150 MB RAM. Prefer the SNMP or
TCP check method over ICMP: raw sockets on some Pi kernels need the container to
run privileged, which `--cap-add NET_RAW` avoids.

---

## Putting it behind HTTPS

The SSH console is a remote shell into your devices, so **do not expose port 8080
to the internet over plain HTTP**. Two things matter:

1. **Serve it over TLS.** Any reverse proxy works — nginx, Caddy, Traefik.
2. **Set `NETMON_COOKIE_SECURE=1`** so the session cookie carries the `Secure`
   flag. Without it the cookie can leak over a downgraded connection.
3. **Preserve the `Host` header.** NetMon validates the WebSocket `Origin` against
   the request `Host`, so a proxy that rewrites `Host` breaks the SSH console.

### nginx

```nginx
server {
    listen 443 ssl;
    server_name netmon.example.com;

    ssl_certificate     /etc/letsencrypt/live/netmon.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/netmon.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;

        # Required for the WebSocket SSH console.
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Keep Host intact — the Origin check depends on it.
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # The SSH console is long-lived.
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

Set `NETMON_COOKIE_SECURE=1` in `.env` before restarting:

```bash
echo 'NETMON_COOKIE_SECURE=1' >> .env
docker compose up -d
```

### Caddy (automatic TLS, less to get wrong)

```caddy
netmon.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy terminates TLS and passes the WebSocket upgrade through by default; it also
forwards `Host` unchanged, so the Origin check just works.

---

## Configuration

Everything is optional. Defaults are sensible for a small internal network.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NETMON_POLL_INTERVAL` | `60` | Default poll interval for **new** hosts (seconds) |
| `NETMON_RETENTION_DAYS` | `30` | How long SNMP samples are kept |
| `NETMON_EVENT_RETENTION_DAYS` | `365` | How long the event history is kept |
| `NETMON_SESSION_TTL` | `168` | Session lifetime (hours) |
| `NETMON_COOKIE_SECURE` | `0` | Set `1` when serving over HTTPS |
| `NETMON_PING_TIMEOUT` | `2.0` | ICMP probe timeout (seconds) |
| `NETMON_DISCOVERY_MAX` | `2000` | Safety cap on OIDs registered per host by first-run discovery |
| `NETMON_DISCOVERY_TIMEOUT` | `120` | Wall-clock cap (s) on one discovery walk, so an agent that answers nothing cannot hold the task open |
| `NETMON_DATA_DIR` | `/data` (container) | Where the database and `secret.key` live |
| `NETMON_FRONTEND_DIR` | `/app/frontend` | Where the static SPA is served from |
| `NETMON_UID` / `NETMON_GID` | `10001` | Container user for the `./data` volume |

Set them in a `.env` file next to `docker-compose.yml` (Compose reads it
automatically) or inline:

```bash
NETMON_POLL_INTERVAL=30 NETMON_RETENTION_DAYS=90 docker compose up -d
```

The published port and volume live in `docker-compose.yml` — change `"8080:8080"`
to `"8443:8080"` to serve on a different port without touching the app.

---

## Backup and restore

All state is in one directory. Back up **both** files in it:

```
data/
├── netmon.db      accounts, hosts, OIDs, samples, events, triggers
└── secret.key     Fernet key for SNMP communities, v3 keys, saved SSH passwords
```

```bash
# Back up (stop first for a consistent copy, or use sqlite3's .backup)
docker compose stop
tar czf netmon-backup-$(date +%F).tar.gz data/
docker compose start
```

**`secret.key` is not optional.** Without it the stored credentials cannot be
decrypted and every host needs its community / v3 keys / SSH password re-entered.
The database itself contains no plaintext secrets, so a database-only backup is
still safe to store — just incomplete.

To restore, stop the container, replace `data/`, and start again:

```bash
docker compose down
rm -rf data && tar xzf netmon-backup-2026-11-18.tar.gz
docker compose up -d
```

---

## Updating

```bash
cd NETMON-RAV
git pull
docker compose up -d --build
```

State in `data/` survives updates — accounts, hosts, configuration and all
history are kept, and you stay logged in. Nothing is re-entered.

Database schema changes are applied automatically at startup, in a transaction,
before the app serves a request. If a schema change ever cannot be applied, the
app refuses to start with a message naming the problem rather than running with a
half-migrated database.

---

## Uninstalling

```bash
docker compose down          # stop the container, keep data/
docker compose down -v       # also delete the state volume
rm -rf data                  # delete the bind-mounted state (if you used one)
```

`docker compose down -v` deletes **accounts, hosts, history and the encryption
key**. Back up first if there is anything you want to keep. Removing the clone
directory and the image afterwards:

```bash
cd .. && rm -rf NETMON-RAV
docker rmi netmon:latest
```

---

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Container exits, logs say the database is unwritable | macOS/Colima bind mount owned by your host user while the image runs as uid 10001. Run `NETMON_UID=$(id -u) NETMON_GID=$(id -g) docker compose up -d --build`. |
| `sqlite3.OperationalError: unable to open database file` | Same uid mismatch. See above. |
| Every host reports down, logs say `no ICMP reply (rc=2)` | Raw sockets are blocked in this environment (some NAS kernels, hardened containers, or a container started without `NET_RAW`). Switch the host's check method to **TCP** or **SNMP** — both work without privileges. |
| Host is up but no SNMP values | Check the community string and SNMP version, then use **Test connectivity** on the host. A wrong community is the usual cause. For v3, confirm the auth/priv protocol and key lengths. |
| `unable to resolve ... to an IPv4 address for SNMP` | The address is an IPv6 literal or a name that only resolves to IPv6. NetMon's SNMP transport is IPv4-only; use the device's IPv4 address. |
| Discovery registered nothing, host still shows as undiscovered | The agent did not answer a full walk. Use **Browse OIDs** on the host to see the actual error. A device that permits only a few OIDs is common. |
| SSH console connects then immediately closes | The console needs the WebSocket upgrade. Behind a proxy, check `Upgrade`/`Connection` headers are forwarded (see [nginx](#nginx) above). |
| SSH console refuses with an Origin error | The proxy rewrote the `Host` header. Set `proxy_set_header Host $host;`. |
| Login says "too many attempts" | Five failed logins lock that username for 5 minutes. Wait, or restart the container to clear the in-memory counter. |
| Logged out constantly | `NETMON_COOKIE_SECURE=1` while serving over plain HTTP — the browser drops a `Secure` cookie over HTTP. Remove the flag unless you are behind TLS. |
| Nothing is reachable at `localhost:8080` | Confirm the port mapping with `docker compose ps` and try `curl http://127.0.0.1:8080/api/health` — if that answers, the app is fine and the issue is the port or a firewall. |

Still stuck? The container log is the fastest source of truth:

```bash
docker compose logs -f --tail=100
```

---

## Where to go next

- `README.md` — the full feature list, the roles matrix, and the configuration
  reference.
- The dashboard's **+ Add host** is the fastest way in: name, address, SNMP
  version and community, check method, poll interval.
- **Browse OIDs** on a host shows everything the device actually exposes; tick
  the ones you want charted.
