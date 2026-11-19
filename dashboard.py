#!/usr/bin/env python3
"""Terminal dashboard for the dfw firewall and honeypot (curses, no deps)."""

import curses
import os
import subprocess
import time
from pathlib import Path

LOG = Path(
    os.environ.get(
        "BB_HONEYPOT_LOG",
        str(Path.home() / "Documents" / "bugbounty" / "honeypot" / "connections.log"),
    )
)
REFRESH_SECONDS = 2


def run_cmd(argv: list[str]) -> list[str]:
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        return (result.stdout or result.stderr).splitlines()[:20]
    except Exception as exc:  # noqa: BLE001 - dashboard must keep rendering
        return [f"unavailable: {type(exc).__name__}"]


def parse_log_line(line: str) -> dict | None:
    parts = line.strip().split()
    if len(parts) < 3:
        return None
    parsed = {"time": parts[0], "port": "-", "src": "-", "raw": line.strip()}
    for part in parts[1:]:
        if part.startswith("port="):
            parsed["port"] = part.split("=", 1)[1]
        elif part.startswith("src="):
            parsed["src"] = part.split("=", 1)[1]
    return parsed


def load_hits(path: Path, limit: int = 14) -> list[dict]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    hits = []
    for line in reversed(lines):
        parsed = parse_log_line(line)
        if parsed is not None:
            hits.append(parsed)
        if len(hits) >= limit:
            break
    return hits


def blocklist_members(lines: list[str]) -> str:
    for line in lines:
        if line.startswith("Members:"):
            return line.split(":", 1)[1].strip()
    return "0"


def safe_add(stdscr, y: int, x: int, text: str) -> None:
    height, width = stdscr.getmaxyx()
    if y < 0 or y >= height or x < 0 or x >= width:
        return
    stdscr.addnstr(y, x, text, max(0, width - x - 1))


def draw(stdscr) -> None:
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(1000)

    while True:
        key = stdscr.getch()
        if key in (ord("q"), ord("Q")):
            return

        ufw_lines = run_cmd(["ufw", "status", "verbose"])
        ipset_lines = run_cmd(["ipset", "list", "bb-blocklist"])
        conn_lines = [
            line for line in run_cmd(["ss", "-tnp", "state", "established"])
            if "ESTAB" in line
        ]
        hits = load_hits(LOG)

        stdscr.clear()
        height, _ = stdscr.getmaxyx()
        row = 0

        def section(title: str, lines: list[str]) -> None:
            nonlocal row
            if row >= height - 1:
                return
            safe_add(stdscr, row, 0, f"== {title} ==")
            row += 1
            for line in lines[:6]:
                if row >= height - 1:
                    return
                safe_add(stdscr, row, 2, line)
                row += 1
            if row < height - 1:
                row += 1

        safe_add(stdscr, row, 0, "dfw — firewall / honeypot monitor  (q to quit)")
        row += 2
        section("UFW", ufw_lines)
        section("BLOCKLIST (networks)", [f"members={blocklist_members(ipset_lines)}"])
        section("ESTABLISHED CONNECTIONS", conn_lines or ["none"])
        section("HONEYPOT HITS", [hit["raw"] for hit in hits] or ["no hits yet"])

        if row < height - 1:
            safe_add(stdscr, row, 0, f"refresh {REFRESH_SECONDS}s | log: {LOG}")
        stdscr.refresh()
        time.sleep(REFRESH_SECONDS)


def main() -> None:
    curses.wrapper(draw)


if __name__ == "__main__":
    main()
