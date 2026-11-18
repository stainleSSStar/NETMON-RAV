"""Password hashing, session tokens and at-rest encryption for secrets.

Design rules (deliberate):
- No default credentials exist anywhere. The first run forces creation of an
  administrator account through /api/setup.
- Passwords are stored as PBKDF2-SHA256 with a per-user random salt.
- Session tokens are random; only their SHA-256 hash is stored.
- SNMP community strings / v3 keys and saved SSH passwords are encrypted with
  Fernet. The key lives in DATA_DIR/secret.key (mode 0600), outside the image
  and outside the database file, so a stolen netmon.db alone is not enough.
"""
import hashlib
import hmac
import os
import secrets
import threading

from cryptography.fernet import Fernet

from .config import SECRET_KEY_PATH

PBKDF2_ROUNDS = 260_000

# Upper bound on accepted password length. PBKDF2 runs over the whole string,
# so an unbounded value lets an unauthenticated caller pin a worker thread.
MAX_PASSWORD_BYTES = 1024

_fernet = None
_fernet_lock = threading.Lock()


def _has_stored_ciphertext() -> bool:
    """True if the database already holds encrypted secrets.

    Used to refuse a silent re-key: minting a new secret.key while ciphertext
    exists would orphan every stored community string, v3 key and saved SSH
    password without any visible error.
    """
    try:
        from . import db
        from .config import DB_PATH

        # No database file yet => nothing can possibly be encrypted.
        if not DB_PATH.exists() or DB_PATH.stat().st_size == 0:
            return False

        # db.connect() returns a process-wide singleton; never close it here.
        conn = db.connect()
        cur = conn.execute(
            "SELECT 1 FROM hosts"
            " WHERE community IS NOT NULL OR v3_auth_key IS NOT NULL"
            "   OR v3_priv_key IS NOT NULL LIMIT 1"
        )
        if cur.fetchone():
            return True
        cur = conn.execute(
            "SELECT 1 FROM ssh_credentials"
            " WHERE password_enc IS NOT NULL LIMIT 1"
        )
        return cur.fetchone() is not None
    except Exception:
        # If the database is unreadable we cannot tell; fail closed so a
        # re-key never happens by accident.
        return True


def get_fernet() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet
    with _fernet_lock:
        if _fernet is not None:
            return _fernet
        if SECRET_KEY_PATH.exists():
            key = SECRET_KEY_PATH.read_bytes().strip()
            try:
                os.chmod(SECRET_KEY_PATH, 0o600)
            except OSError:
                pass
        else:
            if _has_stored_ciphertext() and os.environ.get("NETMON_ALLOW_REKEY") != "1":
                raise RuntimeError(
                    f"No secret key at {SECRET_KEY_PATH}, but the database already "
                    "holds encrypted secrets (SNMP community/v3 keys or saved SSH "
                    "passwords). Refusing to generate a new key, because that would "
                    "make every stored secret permanently undecryptable. Restore the "
                    "original secret.key, or set NETMON_ALLOW_REKEY=1 to intentionally "
                    "discard it (you will then have to re-enter every credential)."
                )
            key = Fernet.generate_key()
            try:
                SECRET_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
                tmp = SECRET_KEY_PATH.with_suffix(".key.tmp")
                fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                try:
                    os.write(fd, key)
                finally:
                    os.close(fd)
                os.chmod(tmp, 0o600)
                tmp.replace(SECRET_KEY_PATH)
            except OSError as exc:
                raise RuntimeError(
                    f"Cannot write the secret key to {SECRET_KEY_PATH}: {exc}. "
                    "With a Docker bind mount on macOS, run the container as your "
                    "host user (NETMON_UID=$(id -u) NETMON_GID=$(id -g))."
                ) from exc
        _fernet = Fernet(key)
    return _fernet


def hash_password(password: str):
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError("password too long")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return salt.hex(), dk.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, TypeError):
        return False
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return hmac.compare_digest(dk, expected)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def encrypt_str(value: str) -> str:
    return get_fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_str(value: str) -> str:
    return get_fernet().decrypt(value.encode("utf-8")).decode("utf-8")


def try_decrypt_str(value: str):
    """Decrypt, returning None instead of raising (e.g. after a key change)."""
    try:
        return decrypt_str(value)
    except Exception:
        return None


def decrypt_host_secrets(host: dict) -> dict:
    """Return a copy of a host row with community / v3 keys decrypted.

    Server-side use only (poller, test/walk/SSH endpoints). Raises RuntimeError
    if a stored secret cannot be decrypted, which happens when secret.key was
    replaced or lost — the host then needs its credentials re-entered.
    """
    data = dict(host)
    for field in ("community", "v3_auth_key", "v3_priv_key"):
        if data.get(field):
            plain = try_decrypt_str(data[field])
            if plain is None:
                raise RuntimeError(
                    f"stored {field} cannot be decrypted (secret.key changed?)"
                )
            data[field] = plain
    return data
