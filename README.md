# NetMon — uptime, SNMP and web-SSH monitor

Self-hosted monitoring for internal networks: host reachability (ICMP / TCP /
SNMP), SNMP v1 / v2c / v3 value polling with charts and history, an interactive
SSH console in the browser, and an event log that records every state change
and every SSH session. Everything runs in one container with a single volume
for state.

## Install

Docker is the supported way to run it — one container, one state directory.

```bash
git clone https://github.com/stainleSSStar/NETMON-RAV.git
cd NETMON-RAV
docker compose up -d --build
```

Then open <http://localhost:8080> and create the administrator account.

**First run:** the app asks you to create the administrator account — there are
no default credentials anywhere. Choose a username (3–32 chars: letters,
digits, `_`, `.`, `-`) and a password of at least 10 characters.

> **Never commit `data/`.** It holds `netmon.db` and `secret.key` — the Fernet key
> that decrypts every stored SNMP community, v3 key and saved SSH password.
> `.gitignore` already excludes it; keep it that way, especially in a public repo.

**macOS / colima:** a bind mount is owned by your host user, while the image's
app user is uid 10001 — so pass your own ids or the container cannot write
`./data`:

```bash
NETMON_UID=$(id -u) NETMON_GID=$(id -g) docker compose up -d --build
```

(Put `NETMON_UID`/`NETMON_GID` in a `.env` file next to `docker-compose.yml` to
make it permanent. On Linux, or with a named volume instead of `./data`, the
defaults work.)

**First run:** the app asks you to create the administrator account — there are
no default credentials anywhere. Choose a username (3–32 chars: letters,
digits, `_`, `.`, `-`) and a password of at least 10 characters.

## Features

- **Uptime monitoring** per host: ICMP ping (default), TCP connect, or an SNMP
  `sysUpTime.0` query as the reachability probe. Configurable poll interval
  (10 s – 1 h).
- **SNMP v1 / v2c / v3**: community string for v1/v2c; for v3 you get security
  name, auth protocol (SHA/MD5/SHA224/SHA256), auth key, priv protocol
  (AES/AES192/AES256/DES) and priv key, including noAuthNoPriv, authNoPriv and
  authPriv.
- **Built-in OIDs** always polled: `sysUpTime`, `sysName`, `sysDescr`. Add any
  other OID manually, or **browse the agent's tree** (SNMP walk) and pick from
  what the device actually exposes.
- **First-run discovery**: the first time an SNMP host answers, NetMon walks the
  device and registers **every** OID it exposes. Only the essentials (the system
  group and interface status) are switched on, so polling stays fast; everything
  else is stored ready to be enabled with one tick. Re-running discovery only
  ever adds — it never overrides a choice you already made.
- **Per-OID collection switches**: tick any OID on or off at any time. Turning
  one off stops sampling it but keeps its configuration and its entire history,
  so it can be switched back on later without losing anything.
- **Triggers**: thresholds you define yourself — none exist until you create
  one. Fire when a polled value crosses an absolute level (`>=`, `>`, `<=`,
  `<`, `==`, `!=`) or on how much it changed since the previous poll (delta),
  which is what you want for counters like printer page counts. A trigger fires
  on the transition into the breached state, writes to that device's history and
  the event log, and re-arms when the value leaves it — so a printer sitting
  above its limit does not write an event on every poll.
- **Devices page**: the full inventory in one table — name, address, online /
  offline / paused, last check, latency, 24 h availability, how many OIDs are
  being collected, and how many triggers are breached, with links straight to
  each device's history and configuration.
- **Compare devices**: pick one OID and see it side by side across every device
  that reports it — current value, min / max / average over the window, number
  of samples, downtime count, trigger breaches and when the last one fired.
- **Charts**: uptime availability per 5 min / hour / day bucket for the last
  24 h / 7 d / 30 d, plus line charts for any selected numeric OID values
  (counters, gauges, TimeTicks are converted to numbers).
- **History**: every up/down transition, SNMP error, host change, SSH
  open/close and account action is in the event log. Downtime periods are
  listed with start, end and duration.
- **Web SSH**: full interactive shell (xterm.js) through a WebSocket, using
  your own username and password. Optionally save credentials per host — they
  are stored encrypted (Fernet) with the key kept outside the database. Every
  session open/close/failure is logged to the host history.
- **Accounts**: admin (full control incl. SSH) and read-only (view only).
  Password change from the UI; sessions are invalidated on password change.

## Roles

| Capability                     | admin | read-only |
| ------------------------------ | :---: | :-------: |
| Dashboard, charts, history     |  yes  |    yes    |
| Add / edit / delete hosts, OIDs|  yes  |    no     |
| Test connectivity, browse OIDs |  yes  |    no     |
| SSH console                    |  yes  |    no     |
| Account management             |  yes  |    no     |

## Configuration

`docker-compose.yml` maps port 8080 and stores state in `./data`:

```
netmon/
├── docker-compose.yml
├── Dockerfile
├── backend/      FastAPI app (app, db, snmp, poller, stats, sshtransport)
├── frontend/     static SPA (index.html, app.js, styles.css, vendor/)
└── data/         created at runtime: netmon.db + secret.key
```

Environment variables (optional):

| Variable                 | Default | Meaning                                   |
| ------------------------ | ------- | ----------------------------------------- |
| `NETMON_POLL_INTERVAL`   | `60`    | Default poll interval for new hosts (s)   |
| `NETMON_RETENTION_DAYS`  | `30`    | How long SNMP samples are kept            |
| `NETMON_EVENT_RETENTION_DAYS` | `365` | How long the event history is kept     |
| `NETMON_SESSION_TTL`     | `168`   | Session lifetime in hours                 |
| `NETMON_COOKIE_SECURE`   | `0`     | Set `1` when serving over HTTPS           |
| `NETMON_PING_TIMEOUT`    | `2.0`   | ICMP probe timeout in seconds             |
| `NETMON_DISCOVERY_MAX`   | `2000`  | Safety cap on OIDs registered per host by first-run discovery |
| `NETMON_DISCOVERY_TIMEOUT` | `120` | Wall-clock cap (s) on one discovery walk, so an agent that answers nothing cannot hold the task open indefinitely |
| `NETMON_UID` / `NETMON_GID` | `10001` | Container user for the `./data` volume |

Any of these can also be set in a `.env` file next to `docker-compose.yml`.

`data/secret.key` encrypts SNMP communities, v3 keys and saved SSH passwords.
**Back it up together with `data/`** — without it those secrets cannot be
decrypted (hosts would need their credentials re-entered). The database itself
contains no plaintext secrets.

## Test suite

`tests/e2e_test.py` runs the whole stack without Docker: it starts a purpose
built mini SNMP agent (`tests/snmp_agent.py`, v1/v2c, GET/GETNEXT/GETBULK) and a
mini SSH server (`tests/ssh_server.py`), boots the real FastAPI app on a free
port with a throwaway data dir, and exercises setup, roles, host CRUD, secret
hygiene, live polling, SNMP sampling and charts, OID walking, uptime statistics,
the WebSocket SSH terminal (including saved credentials), rate limiting,
password change and account lifecycle.

```bash
cd NETMON-RAV
.venv/bin/python tests/e2e_test.py        # or: python3 tests/e2e_test.py
```

Last run: **117/117 checks passed**, 0 skipped — on a machine where raw ICMP
sockets are permitted. On a host that forbids them the two ICMP checks are
skipped (the ping exits with "no ICMP reply"), giving 115/117 + 2 skipped. Those
two checks run and pass anywhere ping is allowed; the poller code path itself is
exercised either way (the event is recorded, the host is reported down).

## Security notes

- The container runs as an unprivileged user; `cap_add: NET_RAW` is only there
  so ICMP ping works. If your network policy forbids raw sockets, switch hosts
  to the TCP or SNMP check method.
- Put the service behind HTTPS (reverse proxy) before exposing it beyond your
  LAN — the SSH console is a remote shell.
- Brute-force protection: 5 failed logins per username lock that username for
  5 minutes.
- SSH host keys are accepted on first use (typical for an internal tool); the
  fingerprint is written to the event log so you can spot changes.

## Running without Docker (development)

```bash
cd NETMON-RAV
pip install -r backend/requirements.txt
NETMON_DATA_DIR=./data NETMON_FRONTEND_DIR=./frontend \
  uvicorn backend.app:app --reload --port 8080
```

ICMP ping needs privileges when running outside the container (run with
`sudo`, or use TCP/SNMP checks).

## Typical workflow

1. Open the dashboard → **+ Add host** → name, address, SNMP version and
   community (or v3 credentials), check method, poll interval → save.
2. The first poll happens immediately; the host card shows up/down and the
   event log fills with state changes.
3. Open the host → **Browse OIDs** to find interesting values (e.g.
   `1.3.6.1.2.1.2.2.1.10` = ifInOctets, `1.3.6.1.2.1.2.2.1.16` = ifOutOctets)
   → **+ Add OID** with a label.
4. Tick the OIDs, pick a range, **Plot selected** — charts of the values you
   chose.
5. **SSH →** opens the console: username + password, optional "save
   credentials", then a normal shell.

## Updating

```bash
cd NETMON-RAV
git pull
docker compose up -d --build
```

State in `data/` (accounts, hosts, history) survives updates — you stay logged in
and nothing is re-entered.

## Stopping

```bash
docker compose down          # stop the container (data/ is kept)
docker compose down -v       # also delete state (accounts, history, secrets)
```
