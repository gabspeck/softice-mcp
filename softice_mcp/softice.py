#!/usr/bin/env python3
"""
Drive SoftICE 3.2 running in VT100-over-serial mode over a UNIX PTY device
exposed by 86Box's Virtual Console backend.

Preferred layout: inside the Win95 VM SoftICE is configured with
    SERIAL ON 1 115200    ; plus DISPLAY VT100
86Box's COM1 backend is set to ``Virtual Console``. 86Box allocates the PTY
pair itself and exposes the host side at the configured path (e.g.
``/tmp/softice_host``). This module opens that path as a single non-blocking,
raw-mode, 8N1 / 115200 PTY fd.

Public API:

    SoftICE.open() / .close()
    SoftICE.popup()                  -- Ctrl-D to break into SoftICE
    SoftICE.send_keys(s)             -- raw keystrokes, no terminator
    SoftICE.cmd(line)                -- line + CR, wait for paint to settle
    SoftICE.drain(timeout, settle)   -- passive read
    SoftICE.screen                   -- pyte.HistoryScreen (.display is the grid)
    SoftICE.render()                 -- list[str] of the 25 rendered rows
    SoftICE.history_top_len()        -- snapshot the scrollback length
    SoftICE.render_with_history(n)   -- combined scrollback-since-n + visible

CLI:
    softice.py --path /tmp/softice_host popup
    softice.py --path /tmp/softice_host cmd "d 400000"
    softice.py --path /tmp/softice_host keys "G\\r"
    softice.py --path /tmp/softice_host screen
    softice.py --path /tmp/softice_host reset
"""

from __future__ import annotations

import argparse
import errno
import os
import select
import stat as stat_mod
import sys
import termios
import time
import tty
from collections.abc import Callable

import pyte

from .profiling import span

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None

WRITE_TIMEOUT = 1.0
BAUD = termios.B115200

# Pace host writes so the guest 16550's 16-byte RX FIFO never overruns.
# Multi-byte chunks (8, 12) still drop bytes — the kernel coalesces our
# back-to-back writes into one read on the 86Box side, so the chunk
# boundary disappears by the time bytes reach the guest UART. Per-byte
# writes work because 86Box can only read one byte at a time when the
# PTY only ever holds one. 10 ms is the same delay the FIFO-transport
# code used; restoring it here for the same reason.
WRITE_CHUNK_SIZE = 1
WRITE_CHUNK_DELAY = 0.010


class SoftICEBusyError(RuntimeError):
    """Another process already owns the SoftICE PTY transport."""


class NotATTYError(RuntimeError):
    """Configured transport path is not a character device (PTY)."""


SCROLLBACK_LINES = 500


class SoftICE:
    def __init__(self, path: str, rows: int = 25, cols: int = 80):
        self.path = path
        self.fd: int | None = None
        self._lock_fd: int | None = None
        self.screen = pyte.HistoryScreen(cols, rows, history=SCROLLBACK_LINES, ratio=0.5)
        self.stream = pyte.Stream(self.screen)

    def _acquire_lock(self) -> None:
        if self._lock_fd is not None or fcntl is None:
            return
        lock_path = f"{self.path}.lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o666)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                raise SoftICEBusyError(
                    f"SoftICE transport is already in use: {self.path}"
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

    def _configure_termios(self, fd: int) -> None:
        # Raw mode first — disables canonical processing, echo, signal
        # generation, and the assorted \r/\n translations that would otherwise
        # eat SoftICE's VT100 stream.
        tty.setraw(fd, termios.TCSANOW)
        # Re-fetch and force 8N1 + 115200 + no flow control. The PTY may
        # inherit IXON/CRTSCTS from whoever opened the slave, which would
        # silently throttle SoftICE's output mid-frame.
        iflag, oflag, cflag, lflag, _ispeed, _ospeed, cc = termios.tcgetattr(fd)
        cflag &= ~(termios.CSIZE | termios.PARENB | termios.CSTOPB | termios.CRTSCTS)
        cflag |= termios.CS8 | termios.CLOCAL | termios.CREAD
        iflag &= ~(termios.IXON | termios.IXOFF | termios.IXANY)
        termios.tcsetattr(
            fd,
            termios.TCSANOW,
            [iflag, oflag, cflag, lflag, BAUD, BAUD, cc],
        )
        termios.tcflush(fd, termios.TCIOFLUSH)

    def _open_pty(self) -> int:
        st = os.stat(self.path)
        if not stat_mod.S_ISCHR(st.st_mode):
            raise NotATTYError(
                f"SoftICE transport path is not a character device: {self.path}"
            )
        fd = os.open(self.path, os.O_RDWR | os.O_NONBLOCK | os.O_NOCTTY)
        try:
            self._configure_termios(fd)
        except Exception:
            os.close(fd)
            raise
        return fd

    def open(self) -> None:
        if self.fd is not None:
            return
        self._acquire_lock()
        try:
            self.fd = self._open_pty()
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self._release_lock()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    def drain(
        self,
        timeout: float = 1.5,
        settle: float = 0.35,
        is_done: Callable[[], bool] | None = None,
    ) -> bytes:
        """Read until no new bytes arrive for `settle` seconds,
        or `timeout` elapses with no data at all.

        When ``is_done`` is supplied it's invoked after each chunk has been
        fed into the pyte stream (only when fresh bytes actually arrived —
        the no-data path stays cheap). The first ``True`` return latches:
        we stop calling the predicate but keep reading for ``settle`` more
        seconds of quiet so trailing redraws (status bar, cursor parking,
        repaints SoftICE issues right after the prompt) land on the screen
        before the next command goes out. Without this, trailing bytes
        race the next ``send_keys`` and corrupt the next command's output.

        A zero-byte read after select reports the fd readable means the PTY
        peer hung up; raise EIO so the driver's reconnect path triggers.
        """
        assert self.fd is not None
        with span("drain.io") as s:
            data = bytearray()
            end = time.monotonic() + timeout
            done_at: float | None = None
            while time.monotonic() < end:
                r, _, _ = select.select([self.fd], [], [], 0.1)
                if r:
                    try:
                        chunk = os.read(self.fd, 65536)
                    except BlockingIOError:
                        continue
                    except OSError as exc:
                        if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                            continue
                        raise
                    if not chunk:
                        raise OSError(errno.EIO, "PTY peer closed")
                    data.extend(chunk)
                    end = time.monotonic() + settle
                    # Feed incrementally so the rendered grid reflects the
                    # latest bytes when ``is_done`` runs. pyte handles
                    # partial feeds correctly.
                    self.stream.feed(chunk.decode("latin-1"))
                    if done_at is None and is_done is not None and is_done():
                        done_at = time.monotonic()
                    elif done_at is not None:
                        done_at = time.monotonic()
                elif done_at is not None and time.monotonic() - done_at >= settle:
                    break
            s.add(bytes=len(data))
            return bytes(data)

    def _write_all(self, data: bytes, timeout: float = WRITE_TIMEOUT) -> None:
        """Write the full buffer to the nonblocking transport or raise on timeout."""
        assert self.fd is not None
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
                _, writable, _ = select.select([], [self.fd], [], remaining)
            except InterruptedError:
                continue
            if not writable:
                raise TimeoutError(
                    "SoftICE transport did not become writable before the write timeout expired"
                )
            try:
                written = os.write(self.fd, view)
            except BlockingIOError:
                continue
            except OSError as exc:
                if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    continue
                raise
            if written == 0:
                continue
            view = view[written:]

    def send_keys(self, s: str | bytes) -> None:
        """Write raw bytes, no terminator added.

        Splits at ``WRITE_CHUNK_SIZE`` boundaries with a small inter-chunk
        sleep so we don't overrun the guest 16550's 16-byte RX FIFO. Short
        commands (≤12 bytes) write in a single shot with no extra latency;
        long commands (BPX with IF/DO, large macro blocks) pay one ~5 ms
        gap per ~12 bytes, which is invisible alongside SoftICE's own
        per-keystroke echo + status-bar repaint cost.
        """
        assert self.fd is not None
        if isinstance(s, str):
            s = s.encode("latin-1")
        with span("send_keys", n=len(s)):
            view = memoryview(s)
            first = True
            while view:
                if not first:
                    time.sleep(WRITE_CHUNK_DELAY)
                chunk = view[:WRITE_CHUNK_SIZE]
                self._write_all(bytes(chunk))
                view = view[WRITE_CHUNK_SIZE:]
                first = False

    def _bottom_prompt_row(self) -> int | None:
        """Visible-grid index of the bottommost row that strips to ``:``."""
        cols = self.screen.columns
        buf = self.screen.buffer
        for r in range(self.screen.lines - 1, -1, -1):
            line = "".join(buf[r][x].data for x in range(cols)).strip()
            if line == ":":
                return r
        return None

    def cmd(
        self,
        line: str,
        timeout: float = 1.5,
        is_done: Callable[[int | None, int], Callable[[], bool] | None] | None = None,
    ) -> bytes:
        """Send a SoftICE command + CR, wait for paint, return raw bytes.

        Sends a bare CR first to reset any half-typed line state (SoftICE
        will answer an empty line with a no-op new prompt). Does NOT prepend
        Esc — Esc + letter acts as a meta shortcut in SoftICE serial mode
        and swallows the first character of the next command.

        ``is_done`` is a *factory*: called as
        ``is_done(prompt_floor, history_marker)`` once before each drain. It
        returns the actual ``() -> bool`` predicate (or ``None``). The factory
        runs twice: first as ``(None, history_len)`` for the primer drain
        (no row floor — any prompt is acceptable), then as
        ``(floor_row, floor_hist)`` for the main drain where ``floor_row`` is
        the bottommost ``:`` row visible after the primer settles. Passing the
        floor lets the predicate reject a stale prompt left over from the
        primer (or the previous command) and only fire once SoftICE paints a
        NEW prompt — the absence of pacing on the PTY transport otherwise
        races the predicate against the in-flight command's first echo.
        """
        with span("softice.cmd", line=line):
            self.send_keys(b"\r")
            primer_pred = is_done(None, self.history_top_len()) if is_done else None
            self.drain(0.3, 0.05, is_done=primer_pred)
            floor_row = self._bottom_prompt_row()
            floor_hist = self.history_top_len()
            self.send_keys(line + "\r")
            main_pred = is_done(floor_row, floor_hist) if is_done else None
            return self.drain(timeout=timeout, is_done=main_pred)

    def popup(
        self,
        timeout: float = 1.5,
        is_done: Callable[[], bool] | None = None,
    ) -> bytes:
        """Ctrl-D to break into SoftICE.

        Ctrl-D is a toggle, so the optional ``is_done`` predicate is the
        caller's responsibility — pass one only when the desired end state
        is unambiguous (e.g. ``ensure_popped`` knows it wants popped_in).
        """
        self.send_keys(b"\x04")
        return self.drain(timeout=timeout, is_done=is_done)

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

    def history_top_len(self) -> int:
        """Snapshot of the scrollback length, used as a marker before a command."""
        return len(self.screen.history.top)

    def render_with_history(
        self, since_top_len: int
    ) -> tuple[list[str], list[bool]]:
        """Combined scrollback (since marker) + visible rows, plus per-row bold.

        With ``PAUSE OFF`` SoftICE emits long output as a continuous scroll;
        rows pushed past the top of the visible 25-row grid land in
        ``screen.history.top``. We slice the history added since the caller
        snapshotted ``history_top_len()`` and concatenate it with the
        currently visible rows so command-output extraction can see the whole
        thing.
        """
        with span("pyte.render"):
            cols = self.screen.columns
            hist = list(self.screen.history.top)[since_top_len:]
            hist_rows = [
                "".join(line[x].data for x in range(cols)).rstrip() for line in hist
            ]
            hist_bold = [
                any(line[x].bold for x in range(cols)) for line in hist
            ]
            visible_rows = [row.rstrip() for row in self.screen.display]
            buf = self.screen.buffer
            visible_bold = [
                any(buf[y][x].bold for x in range(cols))
                for y in range(self.screen.lines)
            ]
            return hist_rows + visible_rows, hist_bold + visible_bold

    def clear_render_state(self) -> None:
        """Forget the current VT100 screen image.

        After `G` / resume the serial UI is effectively detached, so any
        still-painted prompt/code/register rows are stale local state until
        SoftICE is popped again.
        """
        rows = self.screen.lines
        cols = self.screen.columns
        self.screen = pyte.HistoryScreen(
            cols, rows, history=SCROLLBACK_LINES, ratio=0.5
        )
        self.stream = pyte.Stream(self.screen)


def _format_screen(rows: list[str]) -> str:
    width = max((len(r) for r in rows), default=0)
    width = max(width, 40)
    bar = "+" + "-" * width + "+"
    body = "\n".join(f"{i:02d}|{r:<{width}}|" for i, r in enumerate(rows))
    return f"{bar}\n{body}\n{bar}"


def _main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--path",
        required=True,
        help="PTY device path (e.g. /tmp/softice_host or /dev/pts/12)",
    )
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

    with SoftICE(args.path) as s:
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
