"""Unit tests for the local canary. No sockets are opened."""

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
        self.timeout = None
        self.closed = False

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def recv(self, size: int) -> bytes:
        return self.payload[:size]

    def close(self) -> None:
        self.closed = True


class HoneypotTests(unittest.TestCase):
    def tearDown(self) -> None:
        log = Path(os.environ["BB_HONEYPOT_LOG"])
        if log.exists():
            log.unlink()

    def test_timestamp_is_utc_iso8601(self) -> None:
        stamp = honeypot._timestamp()
        self.assertIn("T", stamp)
        self.assertIn("+00:00", stamp)

    def test_handle_logs_peer_and_payload(self) -> None:
        sock = FakeSocket()
        honeypot.handle(sock, ("127.0.0.1", 44444))

        line = Path(os.environ["BB_HONEYPOT_LOG"]).read_text(encoding="utf-8").strip()
        self.assertIn("127.0.0.1:44444", line)
        self.assertIn("GET / HTTP/1.1", line)
        self.assertTrue(sock.closed)

    def test_handle_truncates_long_payload(self) -> None:
        sock = FakeSocket(b"A" * 500)
        honeypot.handle(sock, ("127.0.0.1", 55555))

        line = Path(os.environ["BB_HONEYPOT_LOG"]).read_text(encoding="utf-8").strip()
        self.assertIn("A" * 80, line)
        self.assertNotIn("A" * 81, line)


if __name__ == "__main__":
    unittest.main()
