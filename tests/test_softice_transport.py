from __future__ import annotations

import errno
import stat
import termios
from types import SimpleNamespace

import pytest

from softice_mcp import softice as softice_mod
from softice_mcp.softice import BAUD, NotATTYError, SoftICE


def _ready(_rlist, wlist, _xlist, _timeout):
    return ([], wlist, [])


def test_write_all_retries_until_buffer_is_fully_written(monkeypatch):
    sice = SoftICE("/tmp/softice_host")
    sice.fd = 7
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


def test_send_keys_writes_one_byte_per_chunk_with_inter_chunk_sleep(monkeypatch):
    sice = SoftICE("/tmp/softice_host")
    sice.fd = 7
    written: list[bytes] = []
    sleeps: list[float] = []

    monkeypatch.setattr(softice_mod.select, "select", _ready)

    def fake_write(fd: int, data) -> int:
        chunk = bytes(data)
        written.append(chunk)
        return len(chunk)

    monkeypatch.setattr(softice_mod.os, "write", fake_write)
    monkeypatch.setattr(softice_mod.time, "sleep", sleeps.append)

    sice.send_keys("ABC")

    assert written == [b"A", b"B", b"C"]
    assert sleeps == [softice_mod.WRITE_CHUNK_DELAY, softice_mod.WRITE_CHUNK_DELAY]


def test_send_keys_single_byte_send_does_not_sleep(monkeypatch):
    sice = SoftICE("/tmp/softice_host")
    sice.fd = 7
    written: list[bytes] = []
    sleeps: list[float] = []

    monkeypatch.setattr(softice_mod.select, "select", _ready)
    monkeypatch.setattr(
        softice_mod.os,
        "write",
        lambda _fd, data: written.append(bytes(data)) or len(data),
    )
    monkeypatch.setattr(softice_mod.time, "sleep", sleeps.append)

    sice.send_keys(b"\r")

    assert written == [b"\r"]
    assert sleeps == []


def test_send_keys_retries_eagain_per_chunk(monkeypatch):
    sice = SoftICE("/tmp/softice_host")
    sice.fd = 7
    attempts: list[bytes] = []
    written: list[bytes] = []
    events = iter(
        [
            BlockingIOError(errno.EAGAIN, "try again"),
            1,
            1,
            1,
        ]
    )

    monkeypatch.setattr(softice_mod.select, "select", _ready)
    monkeypatch.setattr(softice_mod.time, "sleep", lambda _delay: None)

    def fake_write(fd: int, data) -> int:
        chunk = bytes(data)
        attempts.append(chunk)
        event = next(events)
        if isinstance(event, BaseException):
            raise event
        written.append(chunk[:event])
        return event

    monkeypatch.setattr(softice_mod.os, "write", fake_write)

    sice.send_keys("ABC")

    assert attempts == [b"A", b"A", b"B", b"C"]
    assert b"".join(written) == b"ABC"


def test_cmd_sends_reset_cr_then_command(monkeypatch):
    sice = SoftICE("/tmp/softice_host")
    sice.fd = 7
    sent: list[bytes] = []
    drains: list[tuple[float, float]] = []

    monkeypatch.setattr(softice_mod.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(sice, "_write_all", lambda data: sent.append(bytes(data)))

    def fake_drain(timeout: float = 1.5, settle: float = 0.35, is_done=None) -> bytes:
        drains.append((timeout, settle))
        return b"screen"

    monkeypatch.setattr(sice, "drain", fake_drain)

    raw = sice.cmd("TABLE", timeout=2.0)

    # Per-byte chunking calls _write_all per byte; the primer is one byte,
    # the command is six (T A B L E \r).
    assert sent == [b"\r", b"T", b"A", b"B", b"L", b"E", b"\r"]
    assert drains == [(0.3, 0.05), (2.0, 0.35)]
    assert raw == b"screen"


def test_popup_sends_ctrl_d(monkeypatch):
    sice = SoftICE("/tmp/softice_host")
    sice.fd = 7
    sent: list[bytes] = []

    monkeypatch.setattr(sice, "_write_all", lambda data: sent.append(bytes(data)))
    monkeypatch.setattr(
        sice,
        "drain",
        lambda timeout=1.5, settle=0.35, is_done=None: b"popup",
    )

    raw = sice.popup(timeout=0.5)

    assert sent == [b"\x04"]
    assert raw == b"popup"


def test_open_rejects_non_character_device(monkeypatch, tmp_path):
    path = str(tmp_path / "softice_host")

    monkeypatch.setattr(SoftICE, "_acquire_lock", lambda self: None)
    monkeypatch.setattr(SoftICE, "_release_lock", lambda self: None)
    monkeypatch.setattr(
        softice_mod.os,
        "stat",
        lambda _path: SimpleNamespace(st_mode=stat.S_IFREG | 0o600),
    )

    sice = SoftICE(path)
    with pytest.raises(NotATTYError, match="character device"):
        sice.open()


def test_open_uses_rdwr_nonblock_noctty_on_char_device(monkeypatch, tmp_path):
    path = str(tmp_path / "softice_host")
    opened: list[tuple[str, int]] = []

    monkeypatch.setattr(SoftICE, "_acquire_lock", lambda self: None)
    monkeypatch.setattr(SoftICE, "_release_lock", lambda self: None)
    monkeypatch.setattr(SoftICE, "_configure_termios", lambda self, fd: None)
    monkeypatch.setattr(
        softice_mod.os,
        "stat",
        lambda _path: SimpleNamespace(st_mode=stat.S_IFCHR | 0o620),
    )
    monkeypatch.setattr(
        softice_mod.os,
        "open",
        lambda open_path, flags: opened.append((open_path, flags)) or 42,
    )
    monkeypatch.setattr(softice_mod.os, "close", lambda _fd: None)

    sice = SoftICE(path)
    sice.open()

    assert sice.fd == 42
    assert opened == [
        (
            path,
            softice_mod.os.O_RDWR
            | softice_mod.os.O_NONBLOCK
            | softice_mod.os.O_NOCTTY,
        )
    ]


def test_open_configures_termios_for_raw_115200_8n1_no_flow(monkeypatch, tmp_path):
    path = str(tmp_path / "softice_host")
    set_calls: list[tuple[int, int, list]] = []
    flushed: list[tuple[int, int]] = []
    setraw_calls: list[tuple[int, int]] = []

    initial = [
        termios.IXON | termios.IXOFF,  # iflag — flow control on
        0,  # oflag
        termios.PARENB | termios.CSTOPB | termios.CRTSCTS | termios.CS7,  # cflag
        termios.ECHO | termios.ICANON,  # lflag (setraw will clear)
        termios.B9600,  # ispeed
        termios.B9600,  # ospeed
        [b"\x00"] * 32,  # cc
    ]

    def fake_tcgetattr(fd: int):
        return list(initial)

    def fake_tcsetattr(fd: int, when: int, attrs):
        set_calls.append((fd, when, list(attrs)))

    def fake_setraw(fd: int, when: int):
        setraw_calls.append((fd, when))

    def fake_tcflush(fd: int, queue: int):
        flushed.append((fd, queue))

    monkeypatch.setattr(SoftICE, "_acquire_lock", lambda self: None)
    monkeypatch.setattr(SoftICE, "_release_lock", lambda self: None)
    monkeypatch.setattr(
        softice_mod.os,
        "stat",
        lambda _path: SimpleNamespace(st_mode=stat.S_IFCHR | 0o620),
    )
    monkeypatch.setattr(softice_mod.os, "open", lambda *_args: 42)
    monkeypatch.setattr(softice_mod.os, "close", lambda _fd: None)
    monkeypatch.setattr(softice_mod.tty, "setraw", fake_setraw)
    monkeypatch.setattr(softice_mod.termios, "tcgetattr", fake_tcgetattr)
    monkeypatch.setattr(softice_mod.termios, "tcsetattr", fake_tcsetattr)
    monkeypatch.setattr(softice_mod.termios, "tcflush", fake_tcflush)

    sice = SoftICE(path)
    sice.open()

    assert setraw_calls == [(42, termios.TCSANOW)]
    assert len(set_calls) == 1
    fd, when, attrs = set_calls[0]
    iflag, _oflag, cflag, _lflag, ispeed, ospeed, _cc = attrs
    assert fd == 42
    assert when == termios.TCSANOW
    assert ispeed == BAUD
    assert ospeed == BAUD
    assert cflag & termios.CS8
    assert cflag & termios.CLOCAL
    assert cflag & termios.CREAD
    assert not (cflag & termios.PARENB)
    assert not (cflag & termios.CSTOPB)
    assert not (cflag & termios.CRTSCTS)
    assert not (cflag & termios.CSIZE & ~termios.CS8)
    assert not (iflag & termios.IXON)
    assert not (iflag & termios.IXOFF)
    assert not (iflag & termios.IXANY)
    assert flushed == [(42, termios.TCIOFLUSH)]


def test_open_closes_fd_when_termios_setup_fails(monkeypatch, tmp_path):
    path = str(tmp_path / "softice_host")
    closed: list[int] = []

    monkeypatch.setattr(SoftICE, "_acquire_lock", lambda self: None)
    monkeypatch.setattr(SoftICE, "_release_lock", lambda self: None)
    monkeypatch.setattr(
        softice_mod.os,
        "stat",
        lambda _path: SimpleNamespace(st_mode=stat.S_IFCHR | 0o620),
    )
    monkeypatch.setattr(softice_mod.os, "open", lambda *_args: 99)
    monkeypatch.setattr(softice_mod.os, "close", closed.append)

    def boom(self, fd):
        raise OSError(errno.EIO, "termios poof")

    monkeypatch.setattr(SoftICE, "_configure_termios", boom)

    sice = SoftICE(path)
    with pytest.raises(OSError):
        sice.open()
    assert closed == [99]
    assert sice.fd is None


def test_close_releases_fd_and_lock(monkeypatch, tmp_path):
    path = str(tmp_path / "softice_host")
    closed: list[int] = []
    released: list[bool] = []

    monkeypatch.setattr(softice_mod.os, "close", closed.append)

    sice = SoftICE(path)
    sice.fd = 17
    monkeypatch.setattr(sice, "_release_lock", lambda: released.append(True))

    sice.close()

    assert closed == [17]
    assert sice.fd is None
    assert released == [True]


def test_drain_reads_from_pty_fd(monkeypatch):
    sice = SoftICE("/tmp/softice_host")
    sice.fd = 3
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


def test_drain_treats_zero_byte_read_as_io_error(monkeypatch):
    sice = SoftICE("/tmp/softice_host")
    sice.fd = 4
    ticks = iter([0.0, 0.01])

    monkeypatch.setattr(softice_mod.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(
        softice_mod.select,
        "select",
        lambda rlist, _wlist, _xlist, _timeout: (rlist, [], []),
    )
    monkeypatch.setattr(softice_mod.os, "read", lambda _fd, _size: b"")

    with pytest.raises(OSError) as excinfo:
        sice.drain(timeout=0.1, settle=0.35)
    assert excinfo.value.errno == errno.EIO


def test_acquire_lock_rejects_second_instance(tmp_path):
    if softice_mod.fcntl is None:
        pytest.skip("fcntl locking unavailable on this platform")

    path = str(tmp_path / "softice_host")
    first = SoftICE(path)
    second = SoftICE(path)

    first._acquire_lock()
    try:
        with pytest.raises(softice_mod.SoftICEBusyError, match="already in use"):
            second._acquire_lock()
    finally:
        first._release_lock()
        second._release_lock()
