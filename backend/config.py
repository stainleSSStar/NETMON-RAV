"""Runtime configuration for NetMon.

All paths are resolved from the active data directory so the image stays
stateless: the database, the secret key and the SSH credential cipher live in
NETMON_DATA_DIR (mounted as a volume in docker-compose).
"""
import math
import os
from pathlib import Path

def _env_path(name: str, default: Path) -> Path:
    val = os.environ.get(name)
    if not val:
        return default
    # expanduser + resolve: a relative or "~" value would otherwise silently
    # point at a different database (and mint a different secret.key) whenever
    # the process CWD changes.
    path = Path(val).expanduser()
    try:
        path = path.resolve()
    except OSError:
        pass
    return path

def _env_int(name: str, default: int, minimum: int = None, maximum: int = None) -> int:
    """Parse an integer env var, failing with a message that names the variable."""
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}, got {value}")
    return value

def _env_float(name: str, default: float, minimum: float = None) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number, got {raw!r}") from None
    # Every comparison against NaN is False, so a NaN slips past the minimum
    # guard below and reaches the poller, where int(timeout * 1000) raises
    # ValueError. inf passes the same way and raises OverflowError. Reject both
    # here rather than crashing inside a per-host poll loop.
    if not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number, got {raw!r}")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    return value

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = _env_path("NETMON_DATA_DIR", _PROJECT_ROOT / "data")
DB_PATH = DATA_DIR / "netmon.db"
SECRET_KEY_PATH = DATA_DIR / "secret.key"

FRONTEND_DIR = _env_path("NETMON_FRONTEND_DIR", _PROJECT_ROOT / "frontend")

DEFAULT_POLL_INTERVAL = _env_int("NETMON_POLL_INTERVAL", 60, minimum=5, maximum=86400)
SAMPLE_RETENTION_DAYS = _env_int("NETMON_RETENTION_DAYS", 30, minimum=1, maximum=3650)
# Events (down/reconnect/SSH history) are the audit trail the user browses in the
# UI, so they are kept far longer than raw samples. 3650 days = ~10 years.
EVENT_RETENTION_DAYS = _env_int(
    "NETMON_EVENT_RETENTION_DAYS", 365, minimum=7, maximum=3650
)
# A zero/negative TTL would make every login expire instantly, so clamp it.
SESSION_TTL_HOURS = _env_int("NETMON_SESSION_TTL", 168, minimum=1, maximum=8760)


def _env_flag(name: str, default: bool) -> bool:
    """Read a boolean env var, accepting the spellings .env files actually use.

    Comparing against "1" alone made ``true``, ``True``, ``yes`` and ``on``
    evaluate to False -- a session cookie issued without ``Secure`` while the
    operator believes HTTPS is enforced, with nothing in the log to say so.
    """
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


COOKIE_SECURE = _env_flag("NETMON_COOKIE_SECURE", False)
PING_TIMEOUT = _env_float("NETMON_PING_TIMEOUT", 2.0, minimum=0.1)
# Safety cap on first-run OID discovery. A large switch or printer can expose
# thousands of OIDs; registering every one of them would make each poll slow
# and the samples table huge. Everything found is stored, but polling only
# touches the OIDs the user leaves enabled.
DISCOVERY_MAX_OIDS = _env_int("NETMON_DISCOVERY_MAX", 2000, minimum=10, maximum=100000)
# Wall-clock bound on the discovery walk. max_rows alone does not stop an agent
# that answers nothing: each request then costs timeout x retries, so 2000 rows
# is ~13 min (v2c/v3) to ~5.5 h (v1) of a task nobody can cancel.
DISCOVERY_MAX_SECONDS = _env_float("NETMON_DISCOVERY_TIMEOUT", 120.0, minimum=5.0)
APP_NAME = "NetMon"
