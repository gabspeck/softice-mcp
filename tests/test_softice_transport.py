from __future__ import annotations

import errno
import stat
from types import SimpleNamespace

import pytest

from softice_mcp import softice as softice_mod
from softice_mcp.softice import INTER_BYTE_DELAY, SoftICE


def _ready(_rlist, wlist, _xlist, _timeout):
    return ([], wlist, [])


def test_write_all_retries_until_buffer_is_fully_written(monkeypatch):
    sice = SoftICE("/tmp/softice")
    sice.fd_in = 7
    sice.fd_out = 7
    attempts: list[bytes] = []
    counts = iter([1, 2, 1])

    monkeypatch.setattr(softice_mod.select, "select", _ready)

    def fake_write(fd: int, data) -> int:
        chunk = bytes(data)
        attempts.append(chunk)
        return next(counts)

    monkeypatch.setattr(softice_mod.os, "write", fake_write)

    sice._write_all(b"ABCD")

    assert attempts == [b"ABCD", b"BCD", b"D"]


def test_send_keys_retries_on_blocking_write_and_completes(monkeypatch):
    sice = SoftICE("/tmp/softice")
    sice.fd_in = 7
    sice.fd_out = 7
    attempts: list[bytes] = []
    written: list[bytes] = []
    events = iter(
        [
            BlockingIOError(errno.EAGAIN, "try again"),
            1,
            OSError(errno.EWOULDBLOCK, "would block"),
            1,
            1,
        ]
    )

    monkeypatch.setattr(softice_mod.select, "select", _ready)

    def fake_write(fd: int, data) -> int:
        chunk = bytes(data)
        attempts.append(chunk)
        event = next(events)
        if isinstance(event, BaseException):
            raise event
        written.append(chunk[:event])
        return event

    monkeypatch.setattr(softice_mod.os, "write", fake_write)
    monkeypatch.setattr(softice_mod.time, "sleep", lambda delay: None)

    sice.send_keys("ABC")

    assert attempts == [b"A", b"A", b"B", b"B", b"C"]
    assert b"".join(written) == b"ABC"


def test_send_keys_preserves_byte_order_across_retries(monkeypatch):
    sice = SoftICE("/tmp/softice")
    sice.fd_in = 7
    sice.fd_out = 7
    written: list[bytes] = []
    sleeps: list[float] = []
    counts = iter([0, 1, 0, 1, 1])

    monkeypatch.setattr(softice_mod.select, "select", _ready)

    def fake_write(fd: int, data) -> int:
        chunk = bytes(data)
        count = next(counts)
        if count:
            written.append(chunk[:count])
        return count

    monkeypatch.setattr(softice_mod.os, "write", fake_write)
    monkeypatch.setattr(softice_mod.time, "sleep", sleeps.append)

    sice.send_keys(b"XYZ")

    assert b"".join(written) == b"XYZ"
    assert sleeps == [INTER_BYTE_DELAY, INTER_BYTE_DELAY]


def test_cmd_sends_reset_cr_then_command_through_paced_path(monkeypatch):
    sice = SoftICE("/tmp/softice")
    sice.fd_in = 7
    sice.fd_out = 7
    sent: list[bytes] = []
    drains: list[tuple[float, float]] = []

    monkeypatch.setattr(sice, "_send_paced", lambda data: sent.append(bytes(data)))

    def fake_drain(timeout: float = 1.5, settle: float = 0.35) -> bytes:
        drains.append((timeout, settle))
        return b"screen"

    monkeypatch.setattr(sice, "drain", fake_drain)

    raw = sice.cmd("TABLE", timeout=2.0)

    assert sent == [b"\r", b"TABLE\r"]
    assert drains == [(0.3, 0.15), (2.0, 0.35)]
    assert raw == b"screen"


def test_popup_sends_ctrl_d_through_paced_path(monkeypatch):
    sice = SoftICE("/tmp/softice")
    sice.fd_in = 7
    sice.fd_out = 7
    sent: list[bytes] = []

    monkeypatch.setattr(sice, "_send_paced", lambda data: sent.append(bytes(data)))
    monkeypatch.setattr(sice, "drain", lambda timeout=1.5, settle=0.35: b"popup")

    raw = sice.popup(timeout=0.5)

    assert sent == [b"\x04"]
    assert raw == b"popup"


def test_open_detects_char_pipe_base_and_uses_split_endpoints(monkeypatch, tmp_path):
    base = str(tmp_path / "softice")
    opened: list[tuple[str, int]] = []
    closed: list[int] = []

    monkeypatch.setattr(SoftICE, "_acquire_lock", lambda self: None)
    monkeypatch.setattr(SoftICE, "_release_lock", lambda self: None)

    def fake_stat(path: str):
        if path in {f"{base}.in", f"{base}.out"}:
            return SimpleNamespace(st_mode=stat.S_IFIFO)
        raise FileNotFoundError(path)

    def fake_open(path: str, flags: int, mode: int = 0o777) -> int:
        opened.append((path, flags))
        if path.endswith(".out"):
            return 10
        if path.endswith(".in"):
            return 11
        raise AssertionError(path)

    monkeypatch.setattr(softice_mod.os, "stat", fake_stat)
    monkeypatch.setattr(softice_mod.os, "open", fake_open)
    monkeypatch.setattr(softice_mod.os, "close", closed.append)

    sice = SoftICE(base)
    sice.open()

    assert sice.fd_in == 10
    assert sice.fd_out == 11
    assert opened == [
        (f"{base}.out", softice_mod.os.O_RDONLY | softice_mod.os.O_NONBLOCK),
        (f"{base}.in", softice_mod.os.O_WRONLY | softice_mod.os.O_NONBLOCK),
    ]

    sice.close()

    assert closed == [10, 11]


@pytest.mark.parametrize("path", ["/tmp/softice", "/tmp/softice.in", "/tmp/softice.out"])
def test_char_pipe_paths_normalize_to_the_same_base(monkeypatch, path):
    opened: list[str] = []

    monkeypatch.setattr(SoftICE, "_acquire_lock", lambda self: None)
    monkeypatch.setattr(SoftICE, "_release_lock", lambda self: None)
    monkeypatch.setattr(softice_mod.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(
        softice_mod.os,
        "open",
        lambda open_path, _flags, mode=0o777: opened.append(open_path) or (10 if open_path.endswith(".out") else 11),
    )
    monkeypatch.setattr(softice_mod.os, "close", lambda _fd: None)

    sice = SoftICE(path)
    sice.open()

    assert opened == ["/tmp/softice.out", "/tmp/softice.in"]


def test_open_char_pipe_retries_write_endpoint_until_server_is_ready(monkeypatch, tmp_path):
    base = str(tmp_path / "softice")
    attempts = 0
    sleeps: list[float] = []

    monkeypatch.setattr(SoftICE, "_acquire_lock", lambda self: None)
    monkeypatch.setattr(SoftICE, "_release_lock", lambda self: None)
    monkeypatch.setattr(
        softice_mod.os,
        "stat",
        lambda path: SimpleNamespace(st_mode=stat.S_IFIFO)
        if path in {f"{base}.in", f"{base}.out"}
        else (_ for _ in ()).throw(FileNotFoundError(path)),
    )

    def fake_open(path: str, flags: int, mode: int = 0o777) -> int:
        nonlocal attempts
        if path.endswith(".out"):
            return 10
        if path.endswith(".in"):
            attempts += 1
            if attempts < 3:
                raise OSError(errno.ENXIO, "no reader yet")
            return 11
        raise AssertionError(path)

    monkeypatch.setattr(softice_mod.os, "open", fake_open)
    monkeypatch.setattr(softice_mod.time, "sleep", sleeps.append)
    monkeypatch.setattr(softice_mod.os, "close", lambda fd: None)

    sice = SoftICE(base)
    sice.open()

    assert sice.fd_in == 10
    assert sice.fd_out == 11
    assert attempts == 3
    assert sleeps == [
        softice_mod.PIPE_OPEN_RETRY_DELAY,
        softice_mod.PIPE_OPEN_RETRY_DELAY,
    ]


def test_drain_reads_from_input_endpoint(monkeypatch):
    sice = SoftICE("/tmp/softice")
    sice.fd_in = 3
    sice.fd_out = 4
    reads: list[int] = []
    ticks = iter([0.0, 0.01, 0.02, 0.5])

    monkeypatch.setattr(softice_mod.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(
        softice_mod.select,
        "select",
        lambda rlist, _wlist, _xlist, _timeout: (rlist, [], []),
    )
    monkeypatch.setattr(
        softice_mod.os,
        "read",
        lambda fd, _size: reads.append(fd) or b"A",
    )

    raw = sice.drain(timeout=0.1, settle=0.35)

    assert raw == b"A"
    assert reads == [3]


def test_acquire_lock_rejects_second_instance(tmp_path):
    if softice_mod.fcntl is None:
        pytest.skip("fcntl locking unavailable on this platform")

    path = str(tmp_path / "softice")
    first = SoftICE(path)
    second = SoftICE(path)

    first._acquire_lock()
    try:
        with pytest.raises(softice_mod.SoftICEBusyError, match="already in use"):
            second._acquire_lock()
    finally:
        first._release_lock()
        second._release_lock()
