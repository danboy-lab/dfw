#!/usr/bin/env python3
"""Local canary: listens on 127.0.0.1:8088 and logs connections.

It does NOT open a port on the network (ufw stays deny-incoming). Useful to
detect an unexpected local process connecting to a decoy port.
"""

import os
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8088
DEFAULT_LOG = Path.home() / "Documents" / "bugbounty" / "honeypot" / "connections.log"
LOG = Path(os.environ.get("BB_HONEYPOT_LOG", str(DEFAULT_LOG)))
LOG.parent.mkdir(parents=True, exist_ok=True)


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def handle(conn: socket.socket, addr: tuple) -> None:
    try:
        conn.settimeout(2)
        data = conn.recv(256)
        with LOG.open("a", encoding="utf-8") as log:
            log.write(f"{_timestamp()} {addr[0]}:{addr[1]} {data[:80]!r}\n")
    except Exception as exc:  # noqa: BLE001 - canary must never kill the listener
        with LOG.open("a", encoding="utf-8") as log:
            log.write(f"{_timestamp()} erro {exc}\n")
    finally:
        conn.close()


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(16)
        print(f"canario em {HOST}:{PORT} -> {LOG}", flush=True)
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
