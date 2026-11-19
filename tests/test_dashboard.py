"""Unit tests for dashboard helpers. curses is never initialized."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import dashboard  # noqa: E402


class DashboardTests(unittest.TestCase):
    def test_parse_log_line(self) -> None:
        line = (
            "2026-11-18T20:00:00+00:00 port=22 src=198.51.100.10:44444 "
            "data=b'SSH-2.0-Client'"
        )
        parsed = dashboard.parse_log_line(line)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed["port"], "22")
        self.assertEqual(parsed["src"], "198.51.100.10:44444")
        self.assertEqual(parsed["time"], "2026-11-18T20:00:00+00:00")

    def test_parse_log_line_rejects_short_line(self) -> None:
        self.assertIsNone(dashboard.parse_log_line("garbage"))

    def test_blocklist_members(self) -> None:
        lines = ["Name: bb-blocklist", "Members: 4122", "Members bonus: 9"]
        self.assertEqual(dashboard.blocklist_members(lines), "4122")

    def test_load_hits_reads_newest_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "connections.log"
            log.write_text(
                "2026-11-18T20:00:00+00:00 port=22 src=198.51.100.1:1 data=b'a'\n"
                "2026-11-18T20:01:00+00:00 port=80 src=198.51.100.2:2 data=b'b'\n",
                encoding="utf-8",
            )
            hits = dashboard.load_hits(log, limit=2)
        self.assertEqual([hit["port"] for hit in hits], ["80", "22"])

    def test_load_hits_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(dashboard.load_hits(Path(tmp) / "missing.log"), [])

    def test_default_log_path_uses_sudo_user_home(self) -> None:
        class FakeUser:
            pw_dir = "/home/operator"

        with mock.patch.dict(os.environ, {"SUDO_USER": "operator"}), mock.patch(
            "dashboard.pwd.getpwnam", return_value=FakeUser()
        ):
            path = dashboard.default_log_path()
        self.assertEqual(
            path,
            Path("/home/operator/Documents/bugbounty/honeypot/connections.log"),
        )


if __name__ == "__main__":
    unittest.main()
