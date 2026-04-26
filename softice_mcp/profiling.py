"""Optional, default-off profiling log for the MCP server.

Module-level singleton + context manager. A ``Profiler`` instance lives as
``_PROFILER``. Pure parsers and low-level transport code import the
module-level :func:`span` helper without any signature changes; ``connect()``
on the MCP server swaps in a real :class:`JsonlProfiler` when ``profile_log``
is given, ``disconnect()`` (and re-``connect()``) swaps back to the no-op
base class.

Disabled-path cost: :func:`span` does one global read + one attribute check
and returns the cached :data:`_NULL_SPAN`. Its ``__enter__``/``__exit__`` are
no-ops. **No** ``time.perf_counter`` call when disabled.

Each :func:`install` truncates (``"w"``) — each profiling session is
self-contained. Line-buffered + per-write ``flush()`` so live ``tail -f``
works and a hard kill loses at most the in-flight event.
"""

from __future__ import annotations

import atexit
import json
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterator


class _NullSpan:
    """No-op context manager returned when profiling is disabled."""

    def __enter__(self) -> "_NullSpan":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False

    def add(self, **fields: Any) -> None:
        pass


_NULL_SPAN = _NullSpan()


class Profiler:
    """Disabled base profiler. ``span()`` returns the shared :data:`_NULL_SPAN`."""

    enabled = False

    def span(self, name: str, **fields: Any) -> Any:
        return _NULL_SPAN

    def close(self) -> None:
        pass


class _LiveSpan:
    """Mutable per-span field bag for the enabled path."""

    __slots__ = ("fields",)

    def __init__(self, fields: dict[str, Any]) -> None:
        self.fields = fields

    def add(self, **kv: Any) -> None:
        self.fields.update(kv)


class JsonlProfiler(Profiler):
    """Writes one JSONL event per completed span to an open file handle."""

    enabled = True

    def __init__(self, fh: Any, t0: float) -> None:
        self._fh = fh
        self._t0 = t0
        self._lock = threading.Lock()
        self._next_id = 1
        self._stack: list[int] = []

    @contextmanager
    def span(self, name: str, **fields: Any) -> Iterator[_LiveSpan]:
        cid = self._next_id
        self._next_id += 1
        parent = self._stack[-1] if self._stack else None
        self._stack.append(cid)
        live = _LiveSpan(fields)
        t0 = time.perf_counter()
        try:
            yield live
        finally:
            dur_ms = (time.perf_counter() - t0) * 1000.0
            self._stack.pop()
            evt = {
                "t_rel": round(time.perf_counter() - self._t0, 6),
                "name": name,
                "dur_ms": round(dur_ms, 3),
                "id": cid,
                "parent": parent,
                "extra": live.fields,
            }
            with self._lock:
                try:
                    self._fh.write(json.dumps(evt, separators=(",", ":")) + "\n")
                    self._fh.flush()
                except Exception:
                    # Profiling must never break the host call.
                    pass

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


_PROFILER: Profiler = Profiler()


def span(name: str, **fields: Any) -> Any:
    """Return a context manager for the named span.

    When profiling is disabled (the default), this returns :data:`_NULL_SPAN`
    without invoking :func:`time.perf_counter` or allocating any per-call
    objects. When enabled, it delegates to the active profiler.
    """
    p = _PROFILER
    return p.span(name, **fields) if p.enabled else _NULL_SPAN


def install(path: str) -> tuple[Profiler, str | None]:
    """Activate JSONL profiling at ``path``. Truncates an existing file.

    Returns a ``(profiler, note)`` pair. ``note`` is ``None`` on success or a
    short human-readable failure reason; on failure profiling falls back to
    the disabled base profiler so the caller can keep going.
    """
    global _PROFILER
    _PROFILER.close()
    try:
        fh = open(path, "w", buffering=1, encoding="utf-8")
    except OSError as e:
        _PROFILER = Profiler()
        return _PROFILER, f"profile_log disabled: {e}"
    _PROFILER = JsonlProfiler(fh, time.perf_counter())
    return _PROFILER, None


def uninstall() -> None:
    """Close the active profiler (if any) and switch back to disabled."""
    global _PROFILER
    _PROFILER.close()
    _PROFILER = Profiler()


atexit.register(uninstall)
