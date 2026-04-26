#!/usr/bin/env python3
"""
Drive SoftICE 3.2 running in VT100-over-serial mode over 86Box Named Pipe /
UNIX FIFO character devices.

Preferred layout: inside the Win95 VM SoftICE is configured with
    SERIAL ON 1 115200    ; plus DISPLAY VT100
and 86Box's COM1 backend is set to Named Pipe / UNIX FIFO in Server mode with
path /tmp/softice. That yields:
    /tmp/softice.in       host -> guest writes
    /tmp/softice.out      guest -> host reads

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
import errno
import os
import select
import sys
import time

import pyte

from .profiling import span

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None

HOST_PATH = "/tmp/softice"
WRITE_TIMEOUT = 1.0
INTER_BYTE_DELAY = 0.01
PIPE_OPEN_TIMEOUT = 3.0
PIPE_OPEN_RETRY_DELAY = 0.05


class SoftICEBusyError(RuntimeError):
    """Another process already owns the SoftICE FIFO transport."""


def _char_pipe_base(path: str) -> str:
    if path.endswith(".in"):
        return path[:-3]
    if path.endswith(".out"):
        return path[:-4]
    return path


class SoftICE:
    def __init__(self, path: str = HOST_PATH, rows: int = 25, cols: int = 80):
        self.path = path
        self.fd_in: int | None = None
        self.fd_out: int | None = None
        self._lock_fd: int | None = None
        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.Stream(self.screen)

    @property
    def fd(self) -> int | None:
        return self.fd_out

    @fd.setter
    def fd(self, value: int | None) -> None:
        self.fd_in = value
        self.fd_out = value

    def _lock_target(self) -> str:
        return _char_pipe_base(self.path)

    def _acquire_lock(self) -> None:
        if self._lock_fd is not None or fcntl is None:
            return
        lock_path = f"{self._lock_target()}.lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o666)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                raise SoftICEBusyError(
                    f"SoftICE transport is already in use: {self._lock_target()}"
                ) from exc
            raise
        self._lock_fd = fd

    def _release_lock(self) -> None:
        if self._lock_fd is None:
            return
        if fcntl is not None:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
        os.close(self._lock_fd)
        self._lock_fd = None

    def _open_fifo_read(self, path: str, deadline: float) -> int:
        while True:
            try:
                return os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            except OSError as exc:
                if exc.errno not in (errno.ENOENT,):
                    raise
                if time.monotonic() >= deadline:
                    raise FileNotFoundError(
                        f"SoftICE read endpoint not available: {path}"
                    ) from exc
                time.sleep(PIPE_OPEN_RETRY_DELAY)

    def _open_fifo_write(self, path: str, deadline: float) -> int:
        while True:
            try:
                return os.open(path, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as exc:
                if exc.errno not in (
                    errno.ENOENT,
                    errno.ENXIO,
                    errno.EAGAIN,
                    errno.EWOULDBLOCK,
                ):
                    raise
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"SoftICE write endpoint did not become ready: {path}"
                    ) from exc
                time.sleep(PIPE_OPEN_RETRY_DELAY)

    def _open_char_pipe(self) -> None:
        base = _char_pipe_base(self.path)
        deadline = time.monotonic() + PIPE_OPEN_TIMEOUT
        self.fd_in = self._open_fifo_read(f"{base}.out", deadline)
        try:
            self.fd_out = self._open_fifo_write(f"{base}.in", deadline)
        except Exception:
            assert self.fd_in is not None
            os.close(self.fd_in)
            self.fd_in = None
            raise

    def open(self) -> None:
        if self.fd_in is not None and self.fd_out is not None:
            return
        self._acquire_lock()
        try:
            self._open_char_pipe()
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        fds: list[int] = []
        if self.fd_in is not None:
            fds.append(self.fd_in)
        if self.fd_out is not None and self.fd_out != self.fd_in:
            fds.append(self.fd_out)
        for fd in fds:
            os.close(fd)
        self.fd_in = None
        self.fd_out = None
        self._release_lock()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    def drain(self, timeout: float = 1.5, settle: float = 0.35) -> bytes:
        """Read until no new bytes arrive for `settle` seconds,
        or `timeout` elapses with no data at all."""
        assert self.fd_in is not None
        with span("drain.io") as s:
            data = bytearray()
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                r, _, _ = select.select([self.fd_in], [], [], 0.1)
                if r:
                    try:
                        chunk = os.read(self.fd_in, 65536)
                    except BlockingIOError:
                        continue
                    except OSError as exc:
                        if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                            continue
                        raise
                    if chunk:
                        data.extend(chunk)
                        end = time.monotonic() + settle
            if data:
                self.stream.feed(data.decode("latin-1"))
            s.add(bytes=len(data))
            return bytes(data)

    def _write_all(self, data: bytes, timeout: float = WRITE_TIMEOUT) -> None:
        """Write the full buffer to the nonblocking transport or raise on timeout."""
        assert self.fd_out is not None
        if not data:
            return

        deadline = time.monotonic() + timeout
        view = memoryview(data)
        while view:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    "SoftICE transport did not become writable before the write timeout expired"
                )
            try:
                _, writable, _ = select.select([], [self.fd_out], [], remaining)
            except InterruptedError:
                continue
            if not writable:
                raise TimeoutError(
                    "SoftICE transport did not become writable before the write timeout expired"
                )
            try:
                written = os.write(self.fd_out, view)
            except BlockingIOError:
                continue
            except OSError as exc:
                if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    continue
                raise
            if written == 0:
                continue
            view = view[written:]

    def _send_paced(self, data: bytes) -> None:
        # 86Box now drains host bytes before checking guest RX capacity, so a
        # bursty host write can drop characters inside the guest UART path.
        # We intentionally trade throughput for deterministic delivery here.
        with span("send_paced", n=len(data)):
            for i, byte in enumerate(data):
                self._write_all(bytes((byte,)))
                if i + 1 < len(data):
                    time.sleep(INTER_BYTE_DELAY)

    def send_keys(self, s: str | bytes) -> None:
        """Write raw bytes, no terminator added."""
        assert self.fd_out is not None
        if isinstance(s, str):
            s = s.encode("latin-1")
        self._send_paced(s)

    def cmd(self, line: str, timeout: float = 1.5) -> bytes:
        """Send a SoftICE command + CR, wait for paint, return raw bytes.

        Sends a bare CR first to reset any half-typed line state (SoftICE
        will answer an empty line with a no-op new prompt). Does NOT prepend
        Esc — Esc + letter acts as a meta shortcut in SoftICE serial mode
        and swallows the first character of the next command.
        """
        with span("softice.cmd", line=line):
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
        with span("pyte.render"):
            return [line.rstrip() for line in self.screen.display]

    def render_bold(self) -> list[bool]:
        """Per-row flag: True when any cell on that row is rendered bold.

        SoftICE 4.2 bolds the active row in the ADDR table (and only that
        row, within the table) — the parser uses this to flag `active`.
        """
        with span("pyte.render"):
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
