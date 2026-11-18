"""Minimal SSH server for testing NetMon's web terminal.

Password auth against fixed credentials, a PTY-backed "shell" that answers a
few commands and echoes everything else. Enough to exercise the whole
WebSocket -> paramiko path without a real sshd.

    python3 tests/ssh_server.py [--port 2222] [--user test] [--password test]
"""
import argparse
import logging
import socket
import threading
import time

import paramiko

# The NetMon TCP check probes this port and closes immediately; keep paramiko
# from printing a banner traceback for those non-SSH connections.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

HOST_KEY = paramiko.RSAKey.generate(2048)


class MiniShellServer(paramiko.ServerInterface):
    def __init__(self, user: str, password: str):
        self.user = user
        self.password = password
        self.shell = threading.Event()
        self.pty = threading.Event()
        self.resizes = []

    def check_auth_password(self, username, password):
        if username == self.user and password == self.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        self.pty.set()
        return True

    def check_channel_shell_request(self, channel):
        self.shell.set()
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        self.resizes.append((width, height))
        return True


def handle_client(client: socket.socket, user: str, password: str):
    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)
    transport.local_version = "SSH-2.0-MiniSSH"
    server = MiniShellServer(user, password)
    try:
        transport.start_server(server=server)
    except Exception:
        try:
            transport.close()
        except Exception:
            pass
        return
    channel = transport.accept(timeout=15)
    if channel is None:
        transport.close()
        return
    server.shell.wait(5)
    try:
        channel.sendall(b"mini-ssh$ ")
        buffer = ""
        while True:
            data = channel.recv(4096)
            if not data:
                break
            # A real pty echoes what you type (the kernel line discipline does
            # it). Echo it here too, otherwise the web terminal can only ever be
            # tested for one-way output and a broken echo path goes unnoticed.
            channel.sendall(data)
            text = data.decode("utf-8", "replace")
            buffer += text
            while "\r" in buffer or "\n" in buffer:
                idx = min([i for i in (buffer.find("\r"), buffer.find("\n")) if i >= 0])
                line = buffer[:idx].strip()
                buffer = buffer[idx + 1:]
                if line == "exit":
                    channel.sendall(b"bye\r\n")
                    channel.close()
                    transport.close()
                    return
                channel.sendall(f"\r\nyou said: {line}\r\nmini-ssh$ ".encode())
    except Exception:
        pass
    finally:
        try:
            channel.close()
        except Exception:
            pass
        try:
            transport.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--user", default="sshtest")
    parser.add_argument("--password", default="sshpass123")
    args = parser.parse_args()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.port))
    listener.listen(8)
    print(f"mini-ssh listening on 127.0.0.1:{args.port} user={args.user}", flush=True)
    try:
        while True:
            client, _ = listener.accept()
            threading.Thread(target=handle_client, args=(client, args.user, args.password), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()


if __name__ == "__main__":
    main()
