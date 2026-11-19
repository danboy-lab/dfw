#!/usr/bin/env python3
"""Internet-facing honeypot emulating SSH, Telnet, HTTP and HTTP-alt."""

import os
import signal
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path

HOST = "0.0.0.0"
PORTS = (22, 23, 80, 8080)
BANNERS = {
    22: b"SSH-2.0-OpenSSH_9.6\r\n",
    23: b"Ubuntu 22.04 login: ",
    80: b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n",
    8080: b"HTTP/1.1 403 Forbidden\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n",
}
DEFAULT_LOG = Path.home() / "Documents" / "bugbounty" / "honeypot" / "connections.log"
LOG = Path(os.environ.get("BB_HONEYPOT_LOG", str(DEFAULT_LOG)))
LOG.parent.mkdir(parents=True, exist_ok=True)


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_hit(port: int, addr: tuple, payload: bytes) -> None:
    with LOG.open("a", encoding="utf-8") as log:
        log.write(
            f"{timestamp()} port={port} src={addr[0]}:{addr[1]} "
            f"data={payload[:120]!r}\n"
        )


def log_error(message: str) -> None:
    with LOG.open("a", encoding="utf-8") as log:
        log.write(f"{timestamp()} error={message}\n")


def handle(conn: socket.socket, addr: tuple, port: int) -> None:
    try:
        conn.settimeout(3)
        payload = conn.recv(256)
        log_hit(port, addr, payload)
        conn.sendall(BANNERS.get(port, b"\r\n"))
    except Exception as exc:  # noqa: BLE001 - decoy must never kill the listener
        log_error(f"{type(exc).__name__}: {exc}")
    finally:
        conn.close()


def serve(port: int) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((HOST, port))
            server.listen(32)
            while True:
                conn, addr = server.accept()
                threading.Thread(
                    target=handle, args=(conn, addr, port), daemon=True
                ).start()
    except OSError as exc:
        log_error(f"listen port={port} failed: {exc}")


def main() -> None:
    print(f"honeypot {HOST}:{list(PORTS)} -> {LOG}", flush=True)
    for port in PORTS:
        threading.Thread(target=serve, args=(port,), daemon=True).start()
    try:
        while True:
            signal.pause()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
