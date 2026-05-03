"""Runtime wrapper around the SoftICE PTY driver.

Owns the single pyte-backed transport connection (a UNIX PTY served by 86Box's
Virtual Console backend), handles one-shot reconnect on bad-fd errors,
exposes a ``cmd_with_extract`` primitive that slices command output out of the
80x25 grid, and assumes SoftICE starts in a maximized command-window layout
with the non-command panes disabled by startup settings.
"""

from __future__ import annotations

import contextlib
import errno
import time
from typing import Any

from .parsers import (
    detect_command_bounds,
    detect_popped_in,
    extract_command_output,
)
from .profiling import span
from .softice import SoftICE

MAXIMIZED_COMMAND_BOUNDS: tuple[int, int] = (0, 24)
DEFAULT_SEND_KEYS_DRAIN_TIMEOUT = 0.6


class SoftICEIOError(RuntimeError):
    """Transport read/write failed, including after one automatic reconnect."""


class SoftICEStateError(RuntimeError):
    """SoftICE is not in a state that can accept this command."""


def _is_recoverable(exc: BaseException) -> bool:
    if isinstance(exc, OSError) and exc.errno in (errno.EBADF, errno.EIO, errno.ENXIO):
        return True
    if isinstance(exc, ValueError) and "closed" in str(exc).lower():
        return True
    return False


class SoftICEDriver:
    def __init__(self) -> None:
        self._path: str | None = None
        self._sice: SoftICE | None = None
        self._bounds: tuple[int, int] = MAXIMIZED_COMMAND_BOUNDS
        self._popped_in: bool | None = None
        self._layout_initialized = False

    # ---- lifecycle ---------------------------------------------------

    def connect(self, path: str) -> dict[str, Any]:
        """Open a fresh transport connection. Replaces any existing one.

        Eagerly opens so permission/ENOENT errors surface at connect-time
        rather than being deferred to the first command.
        """
        if not isinstance(path, str) or not path.strip():
            raise ValueError("path must be a non-empty string")
        if self._sice is not None:
            with contextlib.suppress(Exception):
                self._sice.close()
            self._sice = None
        self._path = path
        sice = SoftICE(path=path)
        sice.open()
        self._sice = sice
        self._bounds = MAXIMIZED_COMMAND_BOUNDS
        self._popped_in = None
        self._layout_initialized = False
        return {"path": path, "connected": True}

    def ensure_open(self) -> SoftICE:
        if self._sice is not None and self._sice.fd is not None:
            return self._sice
        if self._path is None:
            raise SoftICEStateError(
                "Not connected. Call `connect(path=...)` with the 86Box "
                "Virtual Console PTY path "
                "(e.g. /tmp/softice_host or /dev/pts/12) before issuing commands."
            )
        sice = SoftICE(path=self._path)
        sice.open()
        self._sice = sice
        return sice

    def disconnect(self) -> dict[str, Any]:
        had = self._sice is not None and self._sice.fd is not None
        if self._sice is not None:
            with contextlib.suppress(Exception):
                self._sice.close()
        self._sice = None
        self._path = None
        self._popped_in = None
        self._layout_initialized = False
        return {"was_open": had}

    def _retry_once(self, method: str, *args: Any, **kwargs: Any) -> Any:
        """Call ``self._sice.<method>(*args, **kwargs)``; on a recoverable
        transport error, close/reopen and resolve the method fresh against the
        new instance before retrying once.
        """
        with span(f"transport.{method}"):
            sice = self.ensure_open()
            try:
                return getattr(sice, method)(*args, **kwargs)
            except (OSError, ValueError) as exc:
                if not _is_recoverable(exc):
                    raise
            # reconnect once
            with contextlib.suppress(Exception):
                sice.close()
            self._sice = None
            try:
                sice = self.ensure_open()
                return getattr(sice, method)(*args, **kwargs)
            except (OSError, ValueError) as exc2:
                raise SoftICEIOError(
                    f"SoftICE transport I/O failed after reconnect: {exc2}"
                ) from exc2

    @property
    def bounds(self) -> tuple[int, int]:
        return self._bounds

    # ---- primitives --------------------------------------------------

    def send_keys(
        self,
        data: bytes | str,
        drain_timeout: float = DEFAULT_SEND_KEYS_DRAIN_TIMEOUT,
        settle: float = 0.15,
    ) -> dict[str, Any]:
        self._retry_once("send_keys", data)
        raw = b""
        if drain_timeout > 0:
            raw = self._retry_once("drain", drain_timeout, settle)
        snap = self._snapshot(raw)
        if drain_timeout <= 0:
            # No drain ran, so _snapshot's popped_in reflects pre-keypress
            # state. The user's bytes may toggle it (Ctrl-D, `G`); re-probe.
            self._popped_in = None
        return snap

    def raw_cmd(self, line: str, timeout: float = 1.5) -> dict[str, Any]:
        raw = self._retry_once(
            "cmd",
            line,
            timeout=timeout,
            is_done=lambda floor, hist: lambda: self._is_prompt_settled(
                require_cursor=True, prompt_floor=floor, floor_history=hist
            ),
        )
        return self._snapshot(raw)

    def resume(self, line: str) -> dict[str, Any]:
        """Send `G` (optionally with an address) and mark the session detached.

        There is no useful prompt or stable VT100 screen to snapshot after a
        successful resume; keeping the old rendered prompt around only poisons
        the next popped/detached state probe.
        """
        self.ensure_popped()
        self._retry_once("send_keys", f"\r{line}\r")
        self.ensure_open().clear_render_state()
        self._popped_in = False
        return {
            "raw": b"",
            "raw_rows": [],
            "cursor": [0, 0],
            "bounds": list(self._bounds),
            "popped_in": False,
            "line": line,
        }

    def drain(self, timeout: float = 0.6, settle: float = 0.2) -> dict[str, Any]:
        raw = self._retry_once(
            "drain",
            timeout,
            settle,
            is_done=lambda: self._is_prompt_settled(require_cursor=False),
        )
        return self._snapshot(raw)

    def _is_prompt_settled(
        self,
        *,
        require_cursor: bool,
        prompt_floor: int | None = None,
        floor_history: int = 0,
    ) -> bool:
        """True iff the rendered grid currently shows a fresh ``:`` prompt
        at the bottom of the Command window.

        Walks up from ``self._bounds[1]`` skipping blank rows, separator
        rows, and the ``Enter a command`` status row — the same shape
        ``extract_command_output`` uses. When ``require_cursor`` is True,
        also require that pyte's cursor is parked on the prompt row, which
        avoids a false positive where a stale ``:`` prompt is still visible
        from a previous turn.

        ``prompt_floor`` (with ``floor_history``) lets the caller pin a
        baseline: the bottommost ``:`` row index at the moment the predicate
        was issued, plus the scrollback length at that moment. The check
        accepts a prompt only when it sits STRICTLY BELOW the (possibly
        scrolled) floor, so the predicate doesn't false-fire on the prompt
        the previous command (or the cmd primer) left behind. If the screen
        scrolled enough that the floor row has moved off the visible grid
        into history, the constraint is dropped — any visible prompt is by
        definition new.
        """
        sice = self._sice
        if sice is None or sice.fd is None:
            return False
        effective_floor = prompt_floor
        if effective_floor is not None:
            history_growth = sice.history_top_len() - floor_history
            effective_floor -= history_growth
            if effective_floor < 0:
                effective_floor = None
        rows = sice.render()
        top, bot = self._bounds
        top = max(0, top)
        bot = min(len(rows) - 1, bot)
        if top > bot:
            return False
        for r in range(bot, top - 1, -1):
            stripped = rows[r].strip()
            if not stripped:
                continue
            if "--------" in stripped:
                continue
            if "Enter a command" in stripped:
                continue
            if stripped == ":":
                if effective_floor is not None and r <= effective_floor:
                    return False
                if require_cursor and sice.screen.cursor.y != r:
                    return False
                return True
            return False
        return False

    def popup(self, timeout: float = 1.5) -> dict[str, Any]:
        sent = self.ensure_popped(timeout=timeout)
        return self._snapshot(b"\x04" if sent else b"")

    def wait_for_popup(
        self,
        *,
        timeout_ms: int = 30_000,
        poll_interval_ms: int = 100,
    ) -> dict[str, Any]:
        if timeout_ms < 0:
            raise ValueError("timeout_ms must be >= 0")
        if poll_interval_ms < 1:
            raise ValueError("poll_interval_ms must be >= 1")

        started = time.monotonic()
        if self._popped_in is True:
            snap = self._snapshot(b"")
            snap["popped_in"] = True
            snap["elapsed_ms"] = int((time.monotonic() - started) * 1000)
            snap["timed_out"] = False
            return snap

        deadline = started + (timeout_ms / 1000.0)
        last_snap = self.drain(timeout=0.0, settle=0.0)
        if last_snap["popped_in"]:
            last_snap["elapsed_ms"] = int((time.monotonic() - started) * 1000)
            last_snap["timed_out"] = False
            return last_snap

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                last_snap["elapsed_ms"] = timeout_ms
                last_snap["timed_out"] = True
                return last_snap
            wait_s = min(remaining, poll_interval_ms / 1000.0)
            last_snap = self.drain(timeout=wait_s, settle=0.0)
            if last_snap["popped_in"]:
                last_snap["elapsed_ms"] = int((time.monotonic() - started) * 1000)
                last_snap["timed_out"] = False
                return last_snap

    def _snapshot(self, raw: bytes) -> dict[str, Any]:
        with span("snapshot"):
            s = self.ensure_open()
            rows = s.render()
            bounds = detect_command_bounds(rows, self._bounds)
            popped_in = detect_popped_in(rows, bounds)
            self._popped_in = popped_in
            return {
                "raw": raw,
                "raw_rows": rows,
                "cursor": [s.screen.cursor.y, s.screen.cursor.x],
                "bounds": list(bounds),
                "popped_in": popped_in,
            }

    def ensure_popped(self, timeout: float = 0.5) -> bool:
        """Pop SoftICE if currently detached. Returns True if Ctrl-D was sent.

        Ctrl-D is a toggle (si30ug.pdf), so a blind send while popped would
        resume. Always probe via a short drain — the cached ``_popped_in``
        is set during transitional renders (e.g. right after ``G``) and
        cannot be trusted as a control-flow input. Only send Ctrl-D when
        the probe says we're genuinely detached.
        """
        if self.drain(timeout=0.1, settle=0.05)["popped_in"]:
            self._ensure_session_layout()
            return False
        # We confirmed detached above, so the desired end state is unambiguous:
        # exit drain as soon as detect_popped_in() flips True. Safe because the
        # predicate only short-circuits on a positive observation — if SoftICE
        # doesn't actually pop, we still time out.
        self._retry_once(
            "popup",
            timeout=timeout,
            is_done=lambda: self._observed_popped_in(),
        )
        self._ensure_session_layout()
        return True

    def _observed_popped_in(self) -> bool:
        sice = self._sice
        if sice is None or sice.fd is None:
            return False
        rows = sice.render()
        bounds = detect_command_bounds(rows, self._bounds)
        return detect_popped_in(rows, bounds)

    # ---- startup baseline ------------------------------------------

    def _session_cmd(self, line: str, timeout: float = 1.0) -> bytes:
        """Run a startup-cleanup command outside the typed-tool parser flow."""
        return self._retry_once("cmd", line, timeout=timeout)

    def _register_row_visible(self, rows: list[str] | None = None) -> bool:
        painted = rows if rows is not None else self.ensure_open().render()
        return bool(painted) and painted[0].lstrip().startswith("EAX=")

    def registers_visible(self) -> bool:
        return self._register_row_visible()

    def _ensure_session_layout(self) -> None:
        if self._layout_initialized:
            return
        rows = self.ensure_open().render()
        if self._register_row_visible(rows):
            self._session_cmd("WR")
        self._bounds = MAXIMIZED_COMMAND_BOUNDS
        self._layout_initialized = True

    # ---- structured command -----------------------------------------

    def cmd_with_extract(
        self,
        line: str,
        *,
        timeout: float = 1.5,
    ) -> dict[str, Any]:
        """Send a command, drain to a fresh prompt, extract its full output.

        Assumes SoftICE has ``PAUSE OFF`` so output streams without the
        interactive ``More?`` pager. Long output that scrolls past the
        visible 25-row grid is recovered from the pyte ``HistoryScreen``
        scrollback so ``command_rows`` always reflects the complete capture
        (up to the configured scrollback depth).
        """
        with span("cmd_with_extract", line=line):
            with span("ensure_popped"):
                self.ensure_popped()
            s = self.ensure_open()
            with span("render.pre"):
                pre_rows = s.render()
            history_marker = s.history_top_len()

            raw = self._retry_once(
                "cmd",
                line,
                timeout=timeout,
                is_done=lambda floor, hist: lambda: self._is_prompt_settled(
                    require_cursor=True, prompt_floor=floor, floor_history=hist
                ),
            )

            s = self.ensure_open()
            with span("render.combined"):
                combined_rows, combined_bold = s.render_with_history(history_marker)
            visible_rows = combined_rows[-s.screen.lines:]
            with span("detect.bounds"):
                chrome_bounds = detect_command_bounds(visible_rows, self._bounds)
            history_rows = len(combined_rows) - s.screen.lines
            combined_bot = history_rows + chrome_bounds[1]
            with span("extract"):
                page_rows, parse_error, page_idx = extract_command_output(
                    combined_rows,
                    line,
                    (0, combined_bot),
                    s.screen.cursor.y + history_rows,
                )
            command_rows_bold = [combined_bold[i] for i in page_idx]

            cursor = [s.screen.cursor.y, s.screen.cursor.x]
            final_rows = visible_rows
            popped_in = detect_popped_in(final_rows, chrome_bounds)
            return {
                "line": line,
                "raw": bytes(raw),
                "raw_rows": final_rows,
                "pre_rows": pre_rows,
                "final_rows": final_rows,
                "cursor": cursor,
                "bounds": list(chrome_bounds),
                "command_rows": page_rows,
                "command_rows_bold": command_rows_bold,
                "parse_error": parse_error,
                "popped_in": popped_in,
            }

    # ---- helpers -----------------------------------------------------

    def assert_popped(self, snapshot: dict[str, Any]) -> None:
        """Raise ``SoftICEStateError`` when ``popped_in`` looks false.

        Structured tools use this before trusting output as valid SoftICE
        response — otherwise a command typed while SoftICE is detached just
        gets fed into the Windows shell and our grid is stale.
        """
        if not snapshot.get("popped_in"):
            raise SoftICEStateError(
                "SoftICE is not popped in — send `popup` (Ctrl-D) first."
            )
