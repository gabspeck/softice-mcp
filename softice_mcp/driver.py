"""Runtime wrapper around the SoftICE serial driver.

Owns the single pyte-backed transport connection, handles one-shot reconnect
on bad-fd errors, exposes a ``cmd_with_extract`` primitive that slices command
output out of the 80x25 grid, and provides a context manager that hides the
Code/Data panes so long output can land in a 21-row Command window without
triggering SoftICE's ``Press any key...`` pager.
"""

from __future__ import annotations

import contextlib
import errno
import time
from collections.abc import Iterator
from typing import Any

from .parsers import (
    detect_command_bounds,
    detect_popped_in,
    extract_command_output,
    has_more_pager,
)
from .profiling import span
from .softice import SoftICE

DEFAULT_COMMAND_BOUNDS: tuple[int, int] = (17, 24)
EXPANDED_COMMAND_BOUNDS: tuple[int, int] = (4, 24)
DEFAULT_CODE_LINES = 8
DEFAULT_DATA_LINES = 8

MAX_PAGER_STEPS = 32


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
        self._bounds: tuple[int, int] = DEFAULT_COMMAND_BOUNDS
        self._popped_in: bool | None = None

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
        self._bounds = DEFAULT_COMMAND_BOUNDS
        self._popped_in = None
        return {"path": path, "connected": True}

    def ensure_open(self) -> SoftICE:
        if self._sice is not None and self._sice.fd is not None:
            return self._sice
        if self._path is None:
            raise SoftICEStateError(
                "Not connected. Call `connect(path=...)` with the 86Box "
                "Named Pipe / UNIX FIFO base path (e.g. /tmp/softice) "
                "before issuing commands."
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

    def send_keys(self, data: bytes | str, drain_timeout: float = 0.0, settle: float = 0.15) -> dict[str, Any]:
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
            is_done=lambda: self._is_prompt_settled(require_cursor=True),
        )
        return self._snapshot(raw)

    def drain(self, timeout: float = 0.6, settle: float = 0.2) -> dict[str, Any]:
        raw = self._retry_once(
            "drain",
            timeout,
            settle,
            is_done=lambda: self._is_prompt_settled(require_cursor=False),
        )
        return self._snapshot(raw)

    def _is_prompt_settled(self, *, require_cursor: bool) -> bool:
        """True iff the rendered grid currently shows a fresh ``:`` prompt
        at the bottom of the Command window.

        Walks up from ``self._bounds[1]`` skipping blank rows, separator
        rows, and the ``Enter a command`` status row — the same shape
        ``extract_command_output`` uses. When ``require_cursor`` is True,
        also require that pyte's cursor is parked on the prompt row, which
        avoids a false positive where a stale ``:`` prompt is still visible
        from a previous turn.
        """
        sice = self._sice
        if sice is None or sice.fd is None:
            return False
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
                if require_cursor and sice.screen.cursor.y != r:
                    return False
                return True
            return False
        return False

    def popup(self, timeout: float = 1.5) -> dict[str, Any]:
        raw = self._retry_once("popup", timeout=timeout)
        return self._snapshot(raw)

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
        resume. Trust a cached True to skip the probe; otherwise drain (which
        also refreshes the popped_in cache via _snapshot) and only send Ctrl-D
        when genuinely detached.
        """
        if self._popped_in is True:
            return False
        if self.drain(timeout=0.1, settle=0.05)["popped_in"]:
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
        self._popped_in = True
        return True

    def _observed_popped_in(self) -> bool:
        sice = self._sice
        if sice is None or sice.fd is None:
            return False
        rows = sice.render()
        bounds = detect_command_bounds(rows, self._bounds)
        return detect_popped_in(rows, bounds)

    # ---- window management ------------------------------------------

    def default_layout(self) -> None:
        """Force the stock 4-pane layout. Idempotent.

        ``WC n`` opens the Code window to n lines (or resizes it if open).
        ``WD n`` does the same for the Data window. Reissuing with the
        default sizes gives us a known command-area of rows 17..24.
        """
        is_done = lambda: self._is_prompt_settled(require_cursor=True)
        self._retry_once("cmd", f"WC {DEFAULT_CODE_LINES}", is_done=is_done)
        self._retry_once("cmd", f"WD {DEFAULT_DATA_LINES}", is_done=is_done)
        self._bounds = DEFAULT_COMMAND_BOUNDS

    @contextlib.contextmanager
    def expanded_command_window(self) -> Iterator[None]:
        """Hide the Code and Data panes for the duration of the block.

        Extra rows collapse into the Command window (per WC/WD semantics in
        si30cr.pdf p.222-223). Restores the default 4-pane layout on exit,
        even if the wrapped call raises.
        """
        old_bounds = self._bounds
        is_done = lambda: self._is_prompt_settled(require_cursor=True)
        self._retry_once("cmd", "WC", is_done=is_done)
        self._retry_once("cmd", "WD", is_done=is_done)
        self._bounds = EXPANDED_COMMAND_BOUNDS
        try:
            yield
        finally:
            self._bounds = old_bounds
            restore_done = lambda: self._is_prompt_settled(require_cursor=True)
            with contextlib.suppress(Exception):
                self._retry_once(
                    "cmd", f"WC {DEFAULT_CODE_LINES}", is_done=restore_done
                )
            with contextlib.suppress(Exception):
                self._retry_once(
                    "cmd", f"WD {DEFAULT_DATA_LINES}", is_done=restore_done
                )

    # ---- structured command -----------------------------------------

    def cmd_with_extract(
        self,
        line: str,
        *,
        timeout: float = 1.5,
        expand_window: bool = False,
    ) -> dict[str, Any]:
        """Send a command, extract its output, auto-page through ``More?``."""
        with span("cmd_with_extract", line=line, expand=expand_window):
            with span("ensure_popped"):
                self.ensure_popped()
            with span("render.pre"):
                pre_rows = self.ensure_open().render()
            with self._window_context(expand_window):
                raw = bytearray()
                raw.extend(
                    self._retry_once(
                        "cmd",
                        line,
                        timeout=timeout,
                        is_done=lambda: self._is_prompt_settled(require_cursor=True),
                    )
                )
                command_rows: list[str] = []
                command_rows_bold: list[bool] = []
                parse_error: str | None = None
                steps = 0
                bounds = self._bounds
                while True:
                    with span("page_iter", step=steps) as ps:
                        s = self.ensure_open()
                        with span("render.loop"):
                            rows = s.render()
                            bold = s.render_bold()
                        with span("detect.bounds"):
                            bounds = detect_command_bounds(rows, self._bounds)
                        with span("extract"):
                            page_rows, parse_error, page_idx = extract_command_output(
                                rows, line if steps == 0 else "", bounds, s.screen.cursor.y
                            )
                        ps.add(rows=len(page_rows))
                        command_rows.extend(page_rows)
                        command_rows_bold.extend(bold[i] for i in page_idx)
                        with span("has_more"):
                            more = has_more_pager(rows, bounds)
                        if not more or steps >= MAX_PAGER_STEPS:
                            break
                        raw.extend(self._retry_once("send_keys", b" ") or b"")
                        raw.extend(
                            self._retry_once(
                                "drain",
                                1.0,
                                0.2,
                                is_done=lambda: self._is_prompt_settled(require_cursor=False),
                            )
                        )
                        steps += 1
                s = self.ensure_open()
                raw_rows = s.render()
                cursor = [s.screen.cursor.y, s.screen.cursor.x]
            # outside the window context: raw_rows captured inside; snapshot
            # again for popped_in under restored bounds
            final_rows = self.ensure_open().render()
            popped_in = detect_popped_in(
                final_rows, detect_command_bounds(final_rows, self._bounds)
            )
            # Sync the cache so the next tool call doesn't re-probe via
            # ensure_popped's drain when we already know the state.
            self._popped_in = popped_in
            return {
                "line": line,
                "raw": bytes(raw),
                "raw_rows": raw_rows,
                "pre_rows": pre_rows,
                "final_rows": final_rows,
                "cursor": cursor,
                "bounds": list(bounds),
                "command_rows": command_rows,
                "command_rows_bold": command_rows_bold,
                "parse_error": parse_error,
                "popped_in": popped_in,
                "pager_steps": steps,
            }

    @contextlib.contextmanager
    def _window_context(self, expand: bool) -> Iterator[None]:
        if expand:
            with self.expanded_command_window():
                yield
        else:
            yield

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
