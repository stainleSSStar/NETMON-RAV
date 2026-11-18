"""SQLite storage layer for NetMon.

All writes go through a single connection guarded by a re-entrant lock; the
database runs in WAL mode so the poller and the web workers can share it.
"""
import sqlite3
import threading
import time

from .config import DB_PATH

# OIDs that are always polled in addition to the per-host custom list.
DEFAULT_OIDS = [
    ("1.3.6.1.2.1.1.3.0", "sysUpTime"),
    ("1.3.6.1.2.1.1.5.0", "sysName"),
    ("1.3.6.1.2.1.1.1.0", "sysDescr"),
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  pass_salt TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'readonly',
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  ssh_port INTEGER NOT NULL DEFAULT 22,
  snmp_port INTEGER NOT NULL DEFAULT 161,
  snmp_enabled INTEGER NOT NULL DEFAULT 1,
  snmp_version TEXT NOT NULL DEFAULT '2c',
  community TEXT,
  v3_user TEXT,
  v3_auth_proto TEXT,
  v3_auth_key TEXT,
  v3_priv_proto TEXT,
  v3_priv_key TEXT,
  check_method TEXT NOT NULL DEFAULT 'icmp',
  check_port INTEGER NOT NULL DEFAULT 22,
  poll_interval INTEGER NOT NULL DEFAULT 60,
  enabled INTEGER NOT NULL DEFAULT 1,
  notes TEXT,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS oids (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id INTEGER NOT NULL,
  oid TEXT NOT NULL,
  label TEXT NOT NULL,
  created_at REAL NOT NULL,
  UNIQUE(host_id, oid)
);
CREATE TABLE IF NOT EXISTS samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id INTEGER NOT NULL,
  oid TEXT NOT NULL,
  ts REAL NOT NULL,
  value TEXT,
  num REAL
);
CREATE INDEX IF NOT EXISTS idx_samples_host_oid_ts ON samples(host_id, oid, ts);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id INTEGER,
  type TEXT NOT NULL,
  ts REAL NOT NULL,
  message TEXT,
  actor TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_host_ts ON events(host_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS ssh_credentials (
  host_id INTEGER PRIMARY KEY,
  username TEXT NOT NULL,
  password_enc TEXT NOT NULL,
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
"""

_lock = threading.RLock()
_conn = None


def _read_one(sql, params=()):
    """Run a SELECT on the shared connection under the lock.

    ``sqlite3.Connection`` is not safe for concurrent use even with
    ``check_same_thread=False``: the poller writes from the event-loop thread
    while FastAPI runs sync endpoints in a threadpool, and unsynchronized
    access raises intermittent ``InterfaceError``. Every read therefore takes
    the same lock the writers take.
    """
    with _write() as conn:
        return conn.execute(sql, params).fetchone()


def _read_all(sql, params=()):
    with _write() as conn:
        return conn.execute(sql, params).fetchall()


def _write():
    """Context manager: run writes, roll back instead of leaving a transaction open.

    Without the rollback, a failed write leaves ``in_transaction`` set, so the
    next unrelated commit silently persists the failed row and readers observe
    uncommitted data.
    """
    class _Tx:
        def __enter__(self):
            _lock.acquire()
            return connect()

        def __exit__(self, exc_type, exc, tb):
            try:
                if exc_type is not None:
                    try:
                        connect().rollback()
                    except Exception:
                        pass
            finally:
                _lock.release()
            return False

    return _Tx()


_DATA_DIR_HINT = (
    "If NetMon runs in Docker with a bind mount (macOS/colima), the container "
    "user must match the owner of that directory — start it with "
    "NETMON_UID=$(id -u) NETMON_GID=$(id -g) docker compose up -d."
)


def connect() -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is None:
            try:
                DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise RuntimeError(
                    f"Cannot create the data directory {DB_PATH.parent}: {exc}. "
                    + _DATA_DIR_HINT
                ) from exc
            try:
                _conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15)
                _conn.row_factory = sqlite3.Row
                _conn.execute("PRAGMA journal_mode=WAL")
                _conn.execute("PRAGMA busy_timeout=15000")
                _conn.execute("PRAGMA foreign_keys=ON")
                _conn.executescript(SCHEMA)
                _conn.commit()
            except sqlite3.DatabaseError as exc:
                # A corrupt or non-SQLite file must not leave a half-open
                # connection behind, or every later call fails the same way.
                if _conn is not None:
                    try:
                        _conn.close()
                    except Exception:
                        pass
                    _conn = None
                raise RuntimeError(
                    f"Cannot open the database at {DB_PATH}: {exc}. "
                    "If the file is corrupt, move it aside and let NetMon create "
                    "a fresh one. " + _DATA_DIR_HINT
                ) from exc
        return _conn


def init():
    connect()


# ---------------------------------------------------------------- users
def has_users() -> bool:
    return _read_one("SELECT 1 FROM users LIMIT 1") is not None


def create_user(username: str, pass_salt: str, pass_hash: str, role: str) -> int:
    with _write() as conn:
        cur = conn.execute(
            "INSERT INTO users(username, pass_salt, pass_hash, role, created_at) VALUES (?,?,?,?,?)",
            (username, pass_salt, pass_hash, role, time.time()),
        )
        conn.commit()
        return cur.lastrowid


def get_user(user_id: int):
    return _read_one(
        "SELECT * FROM users WHERE id=?",
        (user_id,),
    )


def get_user_by_username(username: str):
    return _read_one(
        "SELECT * FROM users WHERE username=?",
        (username,),
    )


def list_users():
    return _read_all("SELECT * FROM users ORDER BY id")


def delete_user(user_id: int):
    with _write() as conn:
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        conn.commit()


def update_user_password(user_id: int, pass_salt: str, pass_hash: str):
    with _write() as conn:
        conn.execute(
            "UPDATE users SET pass_salt=?, pass_hash=? WHERE id=?", (pass_salt, pass_hash, user_id)
        )
        conn.commit()


def admin_count() -> int:
    return _read_one("SELECT COUNT(*) FROM users WHERE role='admin'")[0]


# ---------------------------------------------------------------- sessions
def create_session(token_hash: str, user_id: int, ttl_seconds: int):
    now = time.time()
    with _write() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO sessions(token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (token_hash, user_id, now, now + ttl_seconds),
        )
        conn.commit()


def session_user(token_hash: str):
    return _read_one(
        """SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ? AND s.expires_at > ?""",
        (token_hash, time.time()),
    )


def delete_session(token_hash: str):
    with _write() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
        conn.commit()


def delete_user_sessions(user_id: int):
    with _write() as conn:
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        conn.commit()


def purge_expired_sessions() -> int:
    with _write() as conn:
        cur = conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (time.time(),))
        conn.commit()
        return cur.rowcount


# ---------------------------------------------------------------- hosts
HOST_COLUMNS = (
    "name", "address", "ssh_port", "snmp_port", "snmp_enabled", "snmp_version",
    "community", "v3_user", "v3_auth_proto", "v3_auth_key", "v3_priv_proto",
    "v3_priv_key", "check_method", "check_port", "poll_interval", "enabled", "notes",
)


def create_host(data: dict) -> int:
    cols = [c for c in HOST_COLUMNS if c in data]
    sql = "INSERT INTO hosts({}, created_at) VALUES ({}, ?)".format(
        ",".join(cols), ",".join("?" for _ in cols)
    )
    with _write() as conn:
        cur = conn.execute(sql, [data[c] for c in cols] + [time.time()])
        conn.commit()
        return cur.lastrowid


def update_host(host_id: int, data: dict):
    cols = [c for c in HOST_COLUMNS if c in data]
    if not cols:
        return
    sql = "UPDATE hosts SET {} WHERE id=?".format(",".join(f"{c}=?" for c in cols))
    with _write() as conn:
        conn.execute(sql, [data[c] for c in cols] + [host_id])
        conn.commit()


def get_host(host_id: int):
    return _read_one(
        "SELECT * FROM hosts WHERE id=?",
        (host_id,),
    )


def all_hosts(enabled_only: bool = False):
    sql = "SELECT * FROM hosts"
    if enabled_only:
        sql += " WHERE enabled=1"
    return _read_all(sql + " ORDER BY id")


def delete_host(host_id: int):
    with _write() as conn:
        for table in ("oids", "samples", "events", "ssh_credentials"):
            conn.execute(f"DELETE FROM {table} WHERE host_id=?", (host_id,))
        conn.execute("DELETE FROM hosts WHERE id=?", (host_id,))
        conn.commit()


# ---------------------------------------------------------------- oids
def add_oid(host_id: int, oid: str, label: str):
    with _write() as conn:
        # Upsert: re-adding a known OID with a new label must update it,
        # otherwise the UI reports success and nothing changes.
        conn.execute(
            """INSERT INTO oids(host_id, oid, label, created_at) VALUES (?,?,?,?)
               ON CONFLICT(host_id, oid) DO UPDATE SET label=excluded.label""",
            (host_id, oid, label, time.time()),
        )
        conn.commit()


def delete_oid(host_id: int, oid: str):
    with _write() as conn:
        conn.execute("DELETE FROM oids WHERE host_id=? AND oid=?", (host_id, oid))
        conn.commit()


def host_oids(host_id: int):
    return _read_all(
        "SELECT * FROM oids WHERE host_id=? ORDER BY oid", (host_id,)
    )


# ---------------------------------------------------------------- samples
def add_samples(rows):
    """rows: iterable of (host_id, oid, ts, value_text, value_num)."""
    with _write() as conn:
        conn.executemany(
            "INSERT INTO samples(host_id, oid, ts, value, num) VALUES (?,?,?,?,?)", rows
        )
        conn.commit()


def latest_values(host_id: int):
    """Latest sample per OID for one host."""
    sql = """
        SELECT s.oid, s.value, s.num, s.ts FROM samples s
        JOIN (SELECT oid, MAX(ts) AS mt FROM samples WHERE host_id=? GROUP BY oid) m
          ON s.oid = m.oid AND s.ts = m.mt AND s.host_id = ?
        ORDER BY s.oid
    """
    return _read_all(sql, (host_id, host_id))


def samples_for_oid(host_id: int, oid: str, since_ts: float):
    return _read_all(
        "SELECT ts, value, num FROM samples WHERE host_id=? AND oid=? AND ts>=? ORDER BY ts ASC",
        (host_id, oid, since_ts),
    )


def prune_samples(older_than_ts: float) -> int:
    with _write() as conn:
        cur = conn.execute("DELETE FROM samples WHERE ts < ?", (older_than_ts,))
        conn.commit()
        return cur.rowcount


def prune_events(older_than_ts: float) -> int:
    """Drop old history rows so the events table cannot grow without bound."""
    with _write() as conn:
        cur = conn.execute("DELETE FROM events WHERE ts < ?", (older_than_ts,))
        conn.commit()
        return cur.rowcount


# ---------------------------------------------------------------- events
def add_event(host_id, type_: str, message: str, actor: str = None):
    with _write() as conn:
        conn.execute(
            "INSERT INTO events(host_id, type, ts, message, actor) VALUES (?,?,?,?,?)",
            (host_id, type_, time.time(), message, actor),
        )
        conn.commit()


def events(host_id=None, limit: int = 100, since_ts: float = None):
    sql = """SELECT e.*, h.name AS host_name FROM events e
             LEFT JOIN hosts h ON h.id = e.host_id"""
    clauses, params = [], []
    if host_id is not None:
        clauses.append("e.host_id=?")
        params.append(host_id)
    if since_ts is not None:
        clauses.append("e.ts>=?")
        params.append(since_ts)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY e.ts DESC LIMIT ?"
    params.append(limit)
    return _read_all(sql, params)


def last_state_event(host_id: int):
    return _read_one(
        "SELECT * FROM events WHERE host_id=? AND type IN ('up','down') ORDER BY ts DESC LIMIT 1",
        (host_id,),
    )


def last_state_event_before(host_id: int, ts: float):
    return _read_one(
        "SELECT type, ts FROM events WHERE host_id=? AND type IN ('up','down') AND ts<? ORDER BY ts DESC LIMIT 1",
        (host_id, ts),
    )


def state_events_since(host_id: int, since_ts: float):
    return _read_all(
        "SELECT type, ts FROM events WHERE host_id=? AND type IN ('up','down') AND ts>=? ORDER BY ts ASC",
        (host_id, since_ts),
    )


# ---------------------------------------------------------------- settings
def get_setting(key: str, default=None):
    row = _read_one("SELECT value FROM settings WHERE key=?", (key,))
    return row["value"] if row else default


def set_setting(key: str, value: str):
    with _write() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO settings(key, value) VALUES (?,?)", (key, str(value))
        )
        conn.commit()


# ---------------------------------------------------------------- ssh creds
def save_ssh_cred(host_id: int, username: str, password_enc: str):
    with _write() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO ssh_credentials(host_id, username, password_enc, updated_at)
               VALUES (?,?,?,?)""",
            (host_id, username, password_enc, time.time()),
        )
        conn.commit()


def get_ssh_cred(host_id: int):
    return _read_one(
        "SELECT * FROM ssh_credentials WHERE host_id=?",
        (host_id,),
    )


def delete_ssh_cred(host_id: int):
    with _write() as conn:
        conn.execute("DELETE FROM ssh_credentials WHERE host_id=?", (host_id,))
        conn.commit()
