"""Unit tests for the internet honeypot. No sockets are opened."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

TMP_DIR = tempfile.mkdtemp(prefix="dfw-honeypot-")
os.environ["BB_HONEYPOT_LOG"] = str(Path(TMP_DIR) / "connections.log")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import honeypot  # noqa: E402


class FakeSocket:
    def __init__(self, payload: bytes = b"GET / HTTP/1.1") -> None:
        self.payload = payload
        self.sent = b""
        self.timeout = None
        self.closed = False

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def recv(self, size: int) -> bytes:
        return self.payload[:size]

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def close(self) -> None:
        self.closed = True


class HoneypotTests(unittest.TestCase):
    def tearDown(self) -> None:
        log = Path(os.environ["BB_HONEYPOT_LOG"])
        if log.exists():
            log.unlink()

    def test_timestamp_is_utc_iso8601(self) -> None:
        stamp = honeypot.timestamp()
        self.assertIn("T", stamp)
        self.assertIn("+00:00", stamp)

    def test_all_exposed_ports_have_a_banner(self) -> None:
        self.assertTrue(set(honeypot.PORTS).issubset(honeypot.BANNERS))

    def test_handle_logs_peer_port_and_payload(self) -> None:
        sock = FakeSocket()
        honeypot.handle(sock, ("198.51.100.10", 44444), 80)

        line = Path(os.environ["BB_HONEYPOT_LOG"]).read_text(encoding="utf-8").strip()
        self.assertIn("port=80", line)
        self.assertIn("198.51.100.10:44444", line)
        self.assertIn("GET / HTTP/1.1", line)
        self.assertEqual(sock.sent, honeypot.BANNERS[80])
        self.assertTrue(sock.closed)

    def test_handle_truncates_long_payload(self) -> None:
        sock = FakeSocket(b"A" * 500)
        honeypot.handle(sock, ("198.51.100.10", 55555), 22)

        line = Path(os.environ["BB_HONEYPOT_LOG"]).read_text(encoding="utf-8").strip()
        self.assertIn("A" * 120, line)
        self.assertNotIn("A" * 121, line)


if __name__ == "__main__":
    unittest.main()
