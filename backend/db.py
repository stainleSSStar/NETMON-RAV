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
  snmp_discovered INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS oids (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id INTEGER NOT NULL,
  oid TEXT NOT NULL,
  label TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at REAL NOT NULL,
  UNIQUE(host_id, oid)
);
CREATE TABLE IF NOT EXISTS triggers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id INTEGER NOT NULL,
  oid TEXT NOT NULL,
  label TEXT NOT NULL,
  op TEXT NOT NULL,
  value REAL NOT NULL,
  delta INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  breached INTEGER NOT NULL DEFAULT 0,
  last_fired REAL,
  last_value REAL,
  created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_triggers_host ON triggers(host_id);
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


def has_stored_ciphertext() -> bool:
    """Whether the database holds any encrypted credential.

    Lives here rather than in ``security.py`` so the check takes the same lock
    as every other read. ``sqlite3.Connection`` is not safe for concurrent use
    even with ``check_same_thread=False``: the poller writes from the
    event-loop thread while FastAPI runs sync endpoints in a threadpool, and
    unsynchronized access raises intermittent ``InterfaceError``.
    """
    with _write() as conn:
        for sql in (
            "SELECT 1 FROM hosts"
            " WHERE community IS NOT NULL OR v3_auth_key IS NOT NULL"
            "   OR v3_priv_key IS NOT NULL LIMIT 1",
            "SELECT 1 FROM ssh_credentials"
            " WHERE password_enc IS NOT NULL LIMIT 1",
        ):
            if conn.execute(sql).fetchone():
                return True
        return False


def _write():
    """Context manager: run writes, roll back instead of leaving a transaction open.

    Without the rollback, a failed write leaves ``in_transaction`` set, so the
    next unrelated commit silently persists the failed row and readers observe
    uncommitted data.
    """
    class _Tx:
        def __enter__(self):
            # connect() can raise (unwritable data dir, corrupt file, a lock
            # race on the WAL pragma). __exit__ is not called when __enter__
            # raises, so a bare acquire() would leak the RLock -- and the
            # failing thread is normally a long-lived AnyIO pool or event-loop
            # thread, which means every later DB call blocks forever with no
            # error and no timeout. Release on the way out.
            _lock.acquire()
            try:
                return connect()
            except Exception:
                _lock.release()
                raise

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


def _migrate(conn: sqlite3.Connection):
    """Bring pre-existing databases up to the current schema.

    ``CREATE TABLE IF NOT EXISTS`` cannot add a column, so a database created
    before a column existed would keep failing every query that names it. Each
    migration is guarded by ``PRAGMA table_info`` so it runs exactly once and
    stays a no-op on a fresh database.

    Both ``ALTER``s run inside one transaction: with the default
    ``isolation_level`` SQLite executes DDL in autocommit, so without an
    explicit ``BEGIN`` a crash between the two would leave ``hosts`` migrated
    and ``oids`` not, and every ``oids.enabled`` query would fail until a later
    process happened to retry.
    """
    def columns(table):
        return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}

    pending = [
        (table, column, ddl)
        for table, column, ddl in (
            ("hosts", "snmp_discovered", "INTEGER NOT NULL DEFAULT 0"),
            ("oids", "enabled", "INTEGER NOT NULL DEFAULT 1"),
        )
        if column not in columns(table)
    ]
    if not pending:
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        for table, column, ddl in pending:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


# Columns NetMon's own triggers table must have.
_TRIGGER_COLUMNS = {
    "host_id", "oid", "label", "op", "value", "delta", "enabled",
    "breached", "last_fired", "last_value", "created_at",
}


def _check_foreign_triggers_table(conn: sqlite3.Connection):
    """Refuse to run against a ``triggers`` table NetMon did not create.

    ``triggers`` is a generic name (MySQL/MariaDB expose a TRIGGERS table and
    plenty of applications ship one), so a database pointed at this data
    directory can already hold one with a completely different shape.
    ``CREATE TABLE IF NOT EXISTS`` cannot reconcile it, and the index that
    follows it in SCHEMA names columns the foreign table does not have -- and
    ``executescript`` stops at the first failing statement. ``samples``,
    ``events``, ``ssh_credentials`` and ``settings`` all come later in SCHEMA,
    so they would never be created: the app would be permanently dead and
    would blame a corrupt file. Failing here instead names the real problem.
    """
    rows = conn.execute("PRAGMA table_info(triggers)").fetchall()
    if not rows:
        return
    have = {row["name"] for row in rows}
    if _TRIGGER_COLUMNS <= have:
        return
    raise RuntimeError(
        f"{DB_PATH} already holds a `triggers` table that NetMon did not "
        f"create (it has {', '.join(sorted(have))}, but NetMon needs "
        f"{', '.join(sorted(_TRIGGER_COLUMNS))}). NetMon cannot reinterpret "
        "that data, and guessing would silently corrupt it. Move the database "
        "aside, or point NETMON_DATA_DIR at a fresh directory."
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
                _check_foreign_triggers_table(_conn)
                _conn.executescript(SCHEMA)
                _migrate(_conn)
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


def delete_user_guarded(user_id: int) -> str:
    """Delete a user atomically, refusing to remove the last administrator.

    Returns ``"deleted"`` or ``"missing"``; raises ValueError when the target is
    the only administrator left.

    The count and the delete share one ``_write()`` transaction. As two
    separate steps, two concurrent requests -- each admin deleting the other --
    both read ``admin_count() == 2`` and both deleted, leaving zero accounts
    and a login page with no way back in.
    """
    with _write() as conn:
        row = conn.execute(
            "SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
        if row is None:
            return "missing"
        if row["role"] == "admin":
            others = conn.execute(
                "SELECT COUNT(*) FROM users WHERE role='admin' AND id!=?",
                (user_id,),
            ).fetchone()[0]
            if others <= 0:
                raise ValueError(
                    "At least one administrator account must remain")
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        return "deleted"


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
        for table in ("oids", "samples", "events", "ssh_credentials", "triggers"):
            conn.execute(f"DELETE FROM {table} WHERE host_id=?", (host_id,))
        conn.execute("DELETE FROM hosts WHERE id=?", (host_id,))
        conn.commit()


# ---------------------------------------------------------------- oids
def add_oid(host_id: int, oid: str, label: str, enabled: int = 1):
    """Register an OID the user explicitly asked to monitor.

    Unlike discovery, an explicit add is a statement of intent, so it also sets
    ``enabled``: adding an OID that first-run discovery found and left switched
    off must actually start polling it, not silently change only its label.
    """
    with _write() as conn:
        conn.execute(
            """INSERT INTO oids(host_id, oid, label, enabled, created_at)
               VALUES (?,?,?,?,?)
               ON CONFLICT(host_id, oid) DO UPDATE SET
                   label=excluded.label, enabled=excluded.enabled""",
            (host_id, oid, label, int(enabled), time.time()),
        )
        conn.commit()


def add_oids_bulk(host_id: int, rows):
    """Register many OIDs at once (first-run discovery).

    ``rows`` is an iterable of (oid, label, enabled). Existing rows keep their
    ``enabled`` flag — discovery must never override a choice the user already
    made, otherwise re-walking a device would undo every manual toggle.
    """
    now = time.time()
    with _write() as conn:
        conn.executemany(
            """INSERT INTO oids(host_id, oid, label, enabled, created_at)
               VALUES (?,?,?,?,?)
               ON CONFLICT(host_id, oid) DO UPDATE SET label=excluded.label""",
            [(host_id, oid, label, int(enabled), now) for oid, label, enabled in rows],
        )
        conn.commit()


def set_oid_enabled(host_id: int, oid: str, enabled: bool):
    """Toggle polling for one OID without deleting its config or history."""
    with _write() as conn:
        cur = conn.execute(
            "UPDATE oids SET enabled=? WHERE host_id=? AND oid=?",
            (int(bool(enabled)), host_id, oid),
        )
        conn.commit()
        return cur.rowcount > 0


def delete_oid(host_id: int, oid: str) -> bool:
    """Remove an OID together with everything derived from it.

    Samples and triggers go with it. A trigger left behind would keep
    evaluating against the last stored sample of an OID the user believes is
    gone, and the samples would keep the table growing for an OID nobody
    watches any more. Unlike ``set_oid_enabled`` this is a real removal: the
    user asked for the OID to disappear, not to pause.

    Returns whether a row was actually deleted, so the caller can 404.
    """
    with _write() as conn:
        cur = conn.execute(
            "DELETE FROM oids WHERE host_id=? AND oid=?", (host_id, oid))
        removed = cur.rowcount > 0
        conn.execute(
            "DELETE FROM samples WHERE host_id=? AND oid=?", (host_id, oid))
        conn.execute(
            "DELETE FROM triggers WHERE host_id=? AND oid=?", (host_id, oid))
        conn.commit()
        return removed


def host_oids(host_id: int, enabled_only: bool = False):
    sql = "SELECT * FROM oids WHERE host_id=?"
    if enabled_only:
        sql += " AND enabled=1"
    return _read_all(sql + " ORDER BY oid", (host_id,))


def enabled_oids_for_host(host_id: int):
    """OIDs the poller should actually sample for this host."""
    return [row["oid"] for row in host_oids(host_id, enabled_only=True)]


def mark_host_discovered(host_id: int):
    with _write() as conn:
        conn.execute("UPDATE hosts SET snmp_discovered=1 WHERE id=?", (host_id,))
        conn.commit()


def reset_host_discovered(host_id: int):
    """Force the next poll to run discovery again (after an OID reset)."""
    with _write() as conn:
        conn.execute("UPDATE hosts SET snmp_discovered=0 WHERE id=?", (host_id,))
        conn.commit()


# ---------------------------------------------------------------- triggers
TRIGGER_OPS = (">", ">=", "<", "<=", "==", "!=")


def add_trigger(host_id: int, oid: str, label: str, op: str, value: float,
                delta: bool = False, enabled: bool = True) -> int:
    if op not in TRIGGER_OPS:
        raise ValueError(f"op must be one of {TRIGGER_OPS}")
    with _write() as conn:
        cur = conn.execute(
            """INSERT INTO triggers(host_id, oid, label, op, value, delta, enabled,
                                    created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (host_id, oid, label, op, float(value), int(bool(delta)),
             int(bool(enabled)), time.time()),
        )
        conn.commit()
        return cur.lastrowid


def update_trigger(trigger_id: int, **fields):
    allowed = {"label", "op", "value", "delta", "enabled"}
    cols = [c for c in fields if c in allowed]
    if "op" in cols and fields["op"] not in TRIGGER_OPS:
        raise ValueError(f"op must be one of {TRIGGER_OPS}")
    if not cols:
        return
    assignments = []
    params = []
    for c in cols:
        v = fields[c]
        if c in ("delta", "enabled"):
            v = int(bool(v))
        elif c == "value":
            v = float(v)
        assignments.append(f"{c}=?")
        params.append(v)
    # Editing a rule re-arms it, otherwise a rule edited while breached stays
    # silent until the value crosses back and forth again.
    assignments.append("breached=0")
    params.append(trigger_id)
    with _write() as conn:
        conn.execute(
            f"UPDATE triggers SET {','.join(assignments)} WHERE id=?", params
        )
        conn.commit()


def delete_trigger(trigger_id: int):
    with _write() as conn:
        conn.execute("DELETE FROM triggers WHERE id=?", (trigger_id,))
        conn.commit()


def host_triggers(host_id: int):
    return _read_all(
        "SELECT * FROM triggers WHERE host_id=? ORDER BY oid, id", (host_id,)
    )


def all_enabled_triggers():
    return _read_all("SELECT * FROM triggers WHERE enabled=1 ORDER BY host_id, id")


def triggers_for_oid(host_id: int, oid: str):
    return _read_all(
        "SELECT * FROM triggers WHERE host_id=? AND oid=? ORDER BY id",
        (host_id, oid),
    )


def set_trigger_state(trigger_id: int, breached: bool, value, fired_ts=None):
    """Record a trigger's evaluation result.

    ``last_fired`` is only written when ``fired_ts`` is given: clearing the
    breach (re-arm) must not erase when the threshold last fired, which is the
    timestamp the UI shows and ``last_trigger_ts`` aggregates.
    """
    with _write() as conn:
        if fired_ts is None:
            conn.execute(
                "UPDATE triggers SET breached=?, last_value=? WHERE id=?",
                (int(bool(breached)), value, trigger_id),
            )
        else:
            conn.execute(
                "UPDATE triggers SET breached=?, last_value=?, last_fired=? WHERE id=?",
                (int(bool(breached)), value, fired_ts, trigger_id),
            )
        conn.commit()


def last_value_for_oid(host_id: int, oid: str):
    """Most recent sample for an OID, used to evaluate delta triggers."""
    return _read_one(
        """SELECT value, num, ts FROM samples
           WHERE host_id=? AND oid=? ORDER BY ts DESC LIMIT 1""",
        (host_id, oid),
    )


def last_values_for_oids(host_id: int, oids):
    """Most recent sample per OID, in one query.

    Delta triggers need the *previous* value, so this must be read before the
    new samples are written — doing it afterwards compares a value with itself.
    """
    if not oids:
        return {}
    placeholders = ",".join("?" for _ in oids)
    rows = _read_all(
        f"""SELECT s.oid, s.value, s.num, s.ts
            FROM samples s
            JOIN (SELECT oid, MAX(ts) AS mts FROM samples
                  WHERE host_id=? AND oid IN ({placeholders}) GROUP BY oid) m
              ON s.oid = m.oid AND s.ts = m.mts
            WHERE s.host_id=?""",
        (host_id, *oids, host_id),
    )
    return {row["oid"]: row for row in rows}


# ---------------------------------------------------------------- comparison
def compare_oid(oid: str, since_ts: float):
    """Cross-host comparison for a single OID.

    One row per host that has samples for ``oid`` inside the window, carrying
    the current value, min/max/avg over the window, how often the host went
    down, and when a threshold on this OID last fired. This is the "compare my
    printers" view: same metric, every device, side by side.
    """
    aggregates = _read_all(
        """SELECT host_id,
                  MIN(num) AS min_num, MAX(num) AS max_num, AVG(num) AS avg_num,
                  MAX(ts) AS last_ts, COUNT(*) AS points
           FROM samples WHERE oid=? AND ts>=? GROUP BY host_id""",
        (oid, since_ts),
    )
    hosts = {row["id"]: row for row in all_hosts()}
    rows = []
    for agg in aggregates:
        host = hosts.get(agg["host_id"])
        if host is None:
            continue
        latest = last_value_for_oid(host["id"], oid)
        downs = _read_one(
            """SELECT COUNT(*) AS n FROM events
               WHERE host_id=? AND type='down' AND ts>=?""",
            (host["id"], since_ts),
        )["n"]
        alerts = _read_one(
            """SELECT COUNT(*) AS n FROM events
               WHERE host_id=? AND type='trigger' AND ts>=?""",
            (host["id"], since_ts),
        )["n"]
        breach = _read_one(
            """SELECT MAX(last_fired) AS ts FROM triggers
               WHERE host_id=? AND oid=? AND last_fired IS NOT NULL AND last_fired>=?""",
            (host["id"], oid, since_ts),
        )["ts"]
        rows.append({
            "host_id": host["id"],
            "name": host["name"],
            "address": host["address"],
            "enabled": bool(host["enabled"]),
            "current": latest["value"] if latest else None,
            "current_num": latest["num"] if latest else None,
            "current_ts": latest["ts"] if latest else None,
            "min": agg["min_num"],
            "max": agg["max_num"],
            "avg": round(agg["avg_num"], 3) if agg["avg_num"] is not None else None,
            "points": agg["points"],
            "downs": downs,
            "alerts": alerts,
            "last_breach": breach,
        })
    rows.sort(key=lambda r: (r["name"] or "").lower())
    return rows


def distinct_oids_with_labels():
    """Every registered OID with a label, for the comparison page's picker."""
    return _read_all(
        """SELECT oid, label, COUNT(DISTINCT host_id) AS hosts
           FROM oids GROUP BY oid ORDER BY hosts DESC, oid"""
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
