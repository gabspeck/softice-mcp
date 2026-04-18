#!/usr/bin/env python3
"""
Drive SoftICE 3.2 running in VT100-over-serial mode through the socat PTY
bridge at /tmp/softice_host.

Layout: inside the Win95 VM SoftICE is configured with
    SERIAL ON 1 115200    ; plus DISPLAY VT100
and 86Box's COM1 passthrough is wired to /tmp/softice_guest, which socat
mirrors to /tmp/softice_host on the host.

This module speaks the raw VT100 stream SoftICE emits, feeds it into a
pyte-backed 80x25 virtual screen, and exposes:

    SoftICE.open() / .close()
    SoftICE.popup()                  -- Ctrl-D to break into SoftICE
    SoftICE.send_keys(s)             -- raw keystrokes, no terminator
    SoftICE.cmd(line)                -- line + CR, wait for paint to settle
    SoftICE.drain(timeout, settle)   -- passive read
    SoftICE.screen                   -- pyte.Screen (.display is the grid)
    SoftICE.render()                 -- list[str] of the 25 rendered rows

CLI:
    softice.py popup                 Ctrl-D, dump screen
    softice.py cmd "d 400000"        run a command, dump screen
    softice.py keys "G\\r"           raw keystrokes (shell-quoted, \\r / \\e OK)
    softice.py screen                just dump what's currently painted
    softice.py reset                 try to exit any help pager and clear
"""

from __future__ import annotations

import argparse
import os
import select
import sys
import time

import pyte

HOST_PTY = "/tmp/softice_host"


class SoftICE:
    def __init__(self, path: str = HOST_PTY, rows: int = 25, cols: int = 80):
        self.path = path
        self.fd: int | None = None
        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.Stream(self.screen)

    def open(self) -> None:
        if self.fd is None:
            self.fd = os.open(
                self.path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK
            )

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    def drain(self, timeout: float = 1.5, settle: float = 0.35) -> bytes:
        """Read until no new bytes arrive for `settle` seconds,
        or `timeout` elapses with no data at all."""
        assert self.fd is not None
        data = bytearray()
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if r:
                try:
                    chunk = os.read(self.fd, 65536)
                except BlockingIOError:
                    continue
                if chunk:
                    data.extend(chunk)
                    end = time.monotonic() + settle
        if data:
            self.stream.feed(data.decode("latin-1"))
        return bytes(data)

    def send_keys(self, s: str | bytes) -> None:
        """Write raw bytes, no terminator added."""
        assert self.fd is not None
        if isinstance(s, str):
            s = s.encode("latin-1")
        os.write(self.fd, s)

    def cmd(self, line: str, timeout: float = 1.5) -> bytes:
        """Send a SoftICE command + CR, wait for paint, return raw bytes.

        Sends a bare CR first to reset any half-typed line state (SoftICE
        will answer an empty line with a no-op new prompt). Does NOT prepend
        Esc — Esc + letter acts as a meta shortcut in SoftICE serial mode
        and swallows the first character of the next command.
        """
        self.send_keys(b"\r")
        self.drain(0.3, 0.15)
        self.send_keys(line + "\r")
        return self.drain(timeout=timeout)

    def popup(self, timeout: float = 1.5) -> bytes:
        """Ctrl-D to break into SoftICE."""
        self.send_keys(b"\x04")
        return self.drain(timeout=timeout)

    def reset(self) -> None:
        """Best-effort: try to escape a help pager and get back to the prompt."""
        # Esc + a few CRs in case Esc is ignored and we need to page through.
        for _ in range(4):
            self.send_keys(b"\x1b")
            self.drain(0.3, 0.15)
        self.send_keys(b"\r")
        self.drain(0.3, 0.15)

    def render(self) -> list[str]:
        return [line.rstrip() for line in self.screen.display]

    def render_bold(self) -> list[bool]:
        """Per-row flag: True when any cell on that row is rendered bold.

        SoftICE 4.2 bolds the active row in the ADDR table (and only that
        row, within the table) — the parser uses this to flag `active`.
        """
        buf = self.screen.buffer
        cols = self.screen.columns
        return [
            any(buf[y][x].bold for x in range(cols))
            for y in range(self.screen.lines)
        ]


def _format_screen(rows: list[str]) -> str:
    width = max((len(r) for r in rows), default=0)
    width = max(width, 40)
    bar = "+" + "-" * width + "+"
    body = "\n".join(f"{i:02d}|{r:<{width}}|" for i, r in enumerate(rows))
    return f"{bar}\n{body}\n{bar}"


def _main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("popup", help="Ctrl-D into SoftICE, then dump screen")
    sub.add_parser("screen", help="drain passively and dump screen")
    sub.add_parser("reset", help="try to escape a help pager")

    c = sub.add_parser("cmd", help="send a SoftICE command line (CR added)")
    c.add_argument("line")
    c.add_argument("--timeout", type=float, default=1.5)

    k = sub.add_parser("keys", help="send raw keystrokes (supports \\r \\e \\n)")
    k.add_argument("keys")

    args = ap.parse_args(argv)

    with SoftICE() as s:
        if args.cmd == "popup":
            s.popup()
        elif args.cmd == "cmd":
            s.cmd(args.line, timeout=args.timeout)
        elif args.cmd == "keys":
            decoded = args.keys.encode("latin-1").decode("unicode_escape")
            s.send_keys(decoded)
            s.drain()
        elif args.cmd == "reset":
            s.reset()
        elif args.cmd == "screen":
            s.drain(timeout=0.6, settle=0.2)
        print(_format_screen(s.render()))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
