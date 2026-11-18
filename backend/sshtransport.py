"""SSH-over-WebSocket bridge.

Flow: browser opens /ws/ssh/{host_id} -> sends a JSON init frame with
username/password (or asks the server to use the saved credential) -> server
opens a paramiko shell -> input frames are forwarded to the channel, output
frames are pushed back. Every connect/close/failure is written to the events
table so the host history shows who logged in and when.

SSH access is restricted to the admin role: read-only accounts can watch
monitoring data but cannot open shells.

Hardening notes (why this file looks the way it does):
- ``channel.sendall`` blocks without a timeout when the remote pty stops being
  drained, so it must never run on the event loop.
- The paramiko reader thread ACKs the channel window on every ``recv``, so the
  output queue must be bounded or a browser that stops reading turns into an
  OOM. Bounding it also propagates backpressure to the remote's TCP window.
- A remote EOF (``exit``, sshd restart) has to tear the whole session down, not
  just stop the pump, otherwise the browser sits on a dead terminal and the
  event history never records the close.
"""
import asyncio
import concurrent.futures
import json
import threading
import time

import paramiko

from . import db, security

# Chunks buffered for a browser that stopped reading. 512 * 32 KiB = 16 MiB is
# far more than any interactive session needs, and reaching it means the peer
# is gone rather than slow.
_OUTPUT_QUEUE_MAX = 512
_READ_CHUNK = 32768

# Each session costs a paramiko Transport plus a reader thread; cap them so one
# admin cookie cannot exhaust the container's threads and file descriptors.
_MAX_SSH_SESSIONS = 20

# channel.sendall blocks without a timeout when the remote pty stops being
# drained. Running it on the loop's shared default executor starves *every*
# other to_thread caller -- new SSH connects and all db writes go through that
# same pool -- so a couple of wedged sessions used to make the whole app unable
# to open a terminal or record an event. Writes get their own bounded pool: a
# stuck session can only ever stall its own input.
_WRITE_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=_MAX_SSH_SESSIONS, thread_name_prefix="netmon-ssh-write")


def _close_quietly(client):
    """Close a paramiko client, ignoring errors.

    SSHClient.connect() has no try/finally of its own: on a failed auth the
    Transport (and its socket fd) stays referenced by the transport thread for
    the life of the process. paramiko's Transport subclasses threading.Thread
    with no __del__, so nothing else will ever release it.
    """
    if client is None:
        return
    try:
        client.close()
    except Exception:
        pass

_MIN_COLS, _MAX_COLS = 1, 500
_MIN_ROWS, _MAX_ROWS = 1, 200

_ssh_sessions = 0
_ssh_sessions_lock = threading.Lock()


def _acquire_ssh_slot() -> bool:
    global _ssh_sessions
    with _ssh_sessions_lock:
        if _ssh_sessions >= _MAX_SSH_SESSIONS:
            return False
        _ssh_sessions += 1
        return True


def _release_ssh_slot():
    global _ssh_sessions
    with _ssh_sessions_lock:
        _ssh_sessions = max(0, _ssh_sessions - 1)


def _decrypt_cred(host_id: int):
    """Return {username, password} for the saved credential, or None.

    ``reason`` distinguishes "nothing stored" from "stored but undecryptable",
    which is what happens after secret.key is lost — the admin needs to be told
    to re-enter the credential, not that none exists.
    """
    cred = db.get_ssh_cred(host_id)
    if not cred:
        return None, "none"
    password = security.try_decrypt_str(cred["password_enc"])
    if password is None:
        return None, "undecryptable"
    return {"username": cred["username"], "password": password}, "ok"


async def _safe_send_text(websocket, text: str) -> bool:
    """Send a text frame, swallowing errors from a peer that already left."""
    try:
        await websocket.send_text(text)
        return True
    except Exception:
        return False


async def _safe_close(websocket, code: int = 1000):
    try:
        await websocket.close(code=code)
    except Exception:
        pass


def _status(phase: str, message: str) -> str:
    return json.dumps({"type": "status", "phase": phase, "message": message})


async def handle_ssh_ws(websocket, host_id: int, user: dict):
    """Handle an already-accepted WebSocket for one SSH session.

    The route accepts the socket first (so an unauthenticated handshake gets a
    clean HTTP-level rejection); this function owns everything after that.
    """
    if user["role"] != "admin":
        await _safe_send_text(websocket, _status(
            "error", "SSH access requires an administrator account."))
        await _safe_close(websocket, 1008)
        return

    if not _acquire_ssh_slot():
        await _safe_send_text(websocket, _status(
            "error",
            f"Too many concurrent SSH sessions (limit {_MAX_SSH_SESSIONS}). "
            "Close another terminal and try again."))
        await _safe_close(websocket, 1008)
        return

    try:
        await _run_ssh_session(websocket, host_id, user)
    finally:
        _release_ssh_slot()


async def _run_ssh_session(websocket, host_id: int, user: dict):
    host = db.get_host(host_id)
    if not host:
        await _safe_send_text(websocket, _status("error", "Host not found."))
        await _safe_close(websocket, 1008)
        return
    host = dict(host)  # sqlite3.Row has no .get()

    # ---- init frame -------------------------------------------------
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=30)
        init = json.loads(raw)
        if not isinstance(init, dict):
            raise ValueError("init frame must be a JSON object")
    except Exception:
        await _safe_close(websocket, 1008)
        return

    try:
        cols = _clamp(init.get("cols"), 80, _MIN_COLS, _MAX_COLS)
        rows = _clamp(init.get("rows"), 24, _MIN_ROWS, _MAX_ROWS)
    except Exception:
        await _safe_close(websocket, 1008)
        return

    username = str(init.get("username") or "").strip()[:128]
    password = str(init.get("password") or "")[:1024]
    used_saved = False

    if init.get("use_saved"):
        saved, reason = _decrypt_cred(host_id)
        if not saved:
            if reason == "undecryptable":
                message = (
                    "The stored SSH credential cannot be decrypted — the server's "
                    "secret.key was replaced or lost. Enter the password manually, "
                    "then save the credential again."
                )
            else:
                message = "No saved credentials for this host."
            await _safe_send_text(websocket, _status("error", message))
            await _safe_close(websocket, 1008)
            return
        username, password = saved["username"], saved["password"]
        used_saved = True

    if not username or not password:
        await _safe_send_text(websocket, _status(
            "error", "Username and password are required."))
        await _safe_close(websocket, 1008)
        return

    await _safe_send_text(websocket, _status(
        "connecting",
        f"Connecting to {host['address']}:{host['ssh_port']} as {username}..."))

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def _connect():
        client.connect(
            host["address"],
            port=int(host.get("ssh_port") or 22),
            username=username,
            password=password,
            timeout=12,
            banner_timeout=15,
            auth_timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )

    try:
        await asyncio.to_thread(_connect)
    except Exception as exc:
        _add_event(host_id, "ssh_fail",
                   f"SSH login failed for '{username}': {exc}", user["username"])
        await _safe_send_text(websocket, _status(
            "error", f"SSH authentication failed: {exc}"))
        await _safe_close(websocket, 1008)
        _close_quietly(client)
        return

    # Everything past a successful TCP+auth connection must run the same
    # cleanup, including the case where the browser tab was closed while
    # _connect() was still running.
    channel = None
    try:
        try:
            channel = client.invoke_shell(
                term="xterm-256color", width=cols, height=rows)
        except Exception as exc:
            _add_event(host_id, "ssh_fail", f"SSH shell failed: {exc}",
                       user["username"])
            await _safe_send_text(websocket, _status(
                "error", f"Could not open shell: {exc}"))
            return

        key_fp = ""
        try:
            key = client.get_transport().get_remote_server_key()
            key_fp = key.get_fingerprint().hex()[:16] if key else ""
        except Exception:
            pass

        _add_event(
            host_id, "ssh_open",
            f"SSH session opened by {user['username']} as '{username}'"
            + (f" (host key {key_fp})" if key_fp else "")
            + (" [saved credentials]" if used_saved else ""),
            actor=user["username"],
        )
        await _safe_send_text(websocket, _status("connected", "Connected."))

        await _bridge(websocket, channel, host_id, username, user["username"])
    finally:
        if channel is not None:
            try:
                channel.close()
            except Exception:
                pass
        try:
            client.close()
        except Exception:
            pass
        _add_event(
            host_id, "ssh_close",
            f"SSH session closed ({user['username']} as '{username}')",
            actor=user["username"],
        )
        await _safe_close(websocket)


def _clamp(value, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def _add_event(host_id, type_: str, message: str, actor: str):
    """Write an event without letting a DB hiccup kill a live SSH session."""
    try:
        db.add_event(host_id, type_, message, actor=actor)
    except Exception:
        pass


async def _bridge(websocket, channel, host_id: int, username: str, actor: str):
    """Move bytes between the websocket and an open paramiko channel."""
    output_queue: asyncio.Queue = asyncio.Queue(maxsize=_OUTPUT_QUEUE_MAX)
    loop = asyncio.get_running_loop()
    stop = threading.Event()
    # Set when the pump has delivered everything, so the main loop can exit
    # promptly instead of waiting for the browser to close the socket.
    remote_done = asyncio.Event()
    # Set by the reader when it is gone, whatever the reason. The pump watches
    # this as well as the queue sentinel, because the sentinel itself can be
    # dropped when the queue is full (see _put).
    reader_done = threading.Event()

    def _put(data):
        try:
            output_queue.put_nowait(data)
        except asyncio.QueueFull:
            # The pump is wedged on a peer that stopped reading. Dropping the
            # newest chunk is the only option that does not grow the process.
            pass

    def _reader():
        try:
            while not stop.is_set():
                # Backpressure: while the browser is not draining, do not read
                # (and therefore do not ACK) the channel. The remote's TCP
                # window then fills and sshd stops sending.
                while output_queue.full() and not stop.is_set():
                    time.sleep(0.05)
                if stop.is_set():
                    break
                data = channel.recv(_READ_CHUNK)
                if not data:
                    break
                loop.call_soon_threadsafe(_put, data)
        except Exception:
            pass
        finally:
            reader_done.set()
            if not loop.is_closed():
                try:
                    loop.call_soon_threadsafe(_put, None)
                except RuntimeError:
                    pass

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    async def _pump_output():
        try:
            while True:
                try:
                    data = await asyncio.wait_for(output_queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    # The sentinel is best-effort: _put drops it when the queue
                    # is full, so also exit once the reader is gone and the
                    # queue has drained. Without this a dropped sentinel hangs
                    # the pump on get() forever and the session slot is never
                    # released.
                    if reader_done.is_set() and output_queue.empty():
                        break
                    continue
                if data is None:
                    break
                await websocket.send_bytes(data)
        except Exception:
            pass
        finally:
            remote_done.set()
            # Tell the browser the shell is gone and drop the socket so the
            # pending receive() in the main loop unblocks and the finally
            # block records ssh_close.
            await _safe_send_text(websocket, _status(
                "closed", "Remote shell closed the connection."))
            await _safe_close(websocket)

    pump_task = asyncio.create_task(_pump_output())

    try:
        while True:
            if remote_done.is_set():
                break
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                break
            payload = message.get("bytes")
            if payload:
                # sendall blocks indefinitely once the remote pty stops being
                # drained, so it must stay off the event loop -- and off the
                # loop's shared executor, which every db write also uses.
                await loop.run_in_executor(
                    _WRITE_EXECUTOR, channel.sendall, payload)
                continue
            text = message.get("text")
            if text:
                try:
                    control = json.loads(text)
                except ValueError:
                    continue
                if isinstance(control, dict) and control.get("type") == "resize":
                    try:
                        channel.resize_pty(
                            width=_clamp(control.get("cols"), cols,
                                         _MIN_COLS, _MAX_COLS),
                            height=_clamp(control.get("rows"), rows,
                                          _MIN_ROWS, _MAX_ROWS),
                        )
                    except Exception:
                        pass
    except Exception:
        pass
    finally:
        stop.set()
        # Closing the channel makes the reader's recv() raise, so the thread
        # exits even while it is parked in the backpressure sleep.
        try:
            channel.close()
        except Exception:
            pass
        pump_task.cancel()
