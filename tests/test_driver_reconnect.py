"""Driver reconnect behaviour without touching a real PTY.

We inject a fake SoftICE class that records open/close counts and can be
primed to fail on the next call. The driver's ``_retry_once`` should close
the dead fd, call ``open()`` again, and retry the operation once.
"""

from __future__ import annotations

import errno
from typing import Any

import pytest

from softice_mcp import driver as driver_mod
from softice_mcp.driver import SoftICEDriver, SoftICEIOError, SoftICEStateError


class FakeScreen:
    def __init__(self):
        self.cursor = type("C", (), {"y": 24, "x": 0})()

    @property
    def display(self):
        return [" " * 80 for _ in range(25)]


class FakeSoftICE:
    instances: list["FakeSoftICE"] = []
    render_sequence: list[list[str]] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.path = kwargs.get("path") or (args[0] if args else None)
        self.fd: int | None = None
        self.opens = 0
        self.closes = 0
        self.cmd_calls: list[str] = []
        self.send_calls: list[bytes] = []
        self.drain_calls = 0
        self.fail_next_cmd: BaseException | None = None
        self.fail_next_drain: BaseException | None = None
        self.screen = FakeScreen()
        FakeSoftICE.instances.append(self)

    def open(self) -> None:
        self.fd = 1
        self.opens += 1

    def close(self) -> None:
        self.fd = None
        self.closes += 1

    def cmd(self, line: str, timeout: float = 1.5) -> bytes:
        self.cmd_calls.append(line)
        if self.fail_next_cmd is not None:
            exc, self.fail_next_cmd = self.fail_next_cmd, None
            raise exc
        return b"ok\r\n"

    def send_keys(self, s: bytes | str) -> None:
        self.send_calls.append(s if isinstance(s, bytes) else s.encode("latin-1"))
        if self.fail_next_cmd is not None:
            exc, self.fail_next_cmd = self.fail_next_cmd, None
            raise exc

    def drain(self, timeout: float = 0.6, settle: float = 0.2) -> bytes:
        self.drain_calls += 1
        if self.fail_next_drain is not None:
            exc, self.fail_next_drain = self.fail_next_drain, None
            raise exc
        return b""

    def popup(self, timeout: float = 1.5) -> bytes:
        return b""

    def render(self) -> list[str]:
        if FakeSoftICE.render_sequence:
            return FakeSoftICE.render_sequence.pop(0)
        return [" " * 80 for _ in range(25)]


@pytest.fixture
def fake_softice(monkeypatch):
    FakeSoftICE.instances = []
    FakeSoftICE.render_sequence = []
    monkeypatch.setattr(driver_mod, "SoftICE", FakeSoftICE)
    yield FakeSoftICE


class TestConnect:
    def test_driver_does_not_open_without_connect(self, fake_softice):
        drv = SoftICEDriver()
        assert not fake_softice.instances

    def test_ensure_open_without_connect_raises(self, fake_softice):
        drv = SoftICEDriver()
        with pytest.raises(SoftICEStateError, match="Not connected"):
            drv.ensure_open()
        assert not fake_softice.instances

    def test_raw_cmd_without_connect_raises(self, fake_softice):
        drv = SoftICEDriver()
        with pytest.raises(SoftICEStateError, match="Not connected"):
            drv.raw_cmd("R", timeout=0.1)

    def test_connect_opens_eagerly_with_path(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/custom-pty")
        assert len(fake_softice.instances) == 1
        assert fake_softice.instances[0].opens == 1
        assert fake_softice.instances[0].path == "/tmp/custom-pty"

    def test_connect_rejects_empty_path(self, fake_softice):
        drv = SoftICEDriver()
        with pytest.raises(ValueError):
            drv.connect("")

    def test_connect_twice_replaces_connection(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/first")
        drv.connect("/tmp/second")
        assert len(fake_softice.instances) == 2
        assert fake_softice.instances[0].closes == 1
        assert fake_softice.instances[1].path == "/tmp/second"

    def test_disconnect_then_ensure_open_raises(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")
        drv.disconnect()
        with pytest.raises(SoftICEStateError, match="Not connected"):
            drv.ensure_open()


class TestReconnect:
    def test_ensure_open_reuses(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")
        drv.ensure_open()
        assert len(fake_softice.instances) == 1

    def test_retry_on_ebadf(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")
        first = fake_softice.instances[0]
        first.fail_next_cmd = OSError(errno.EBADF, "bad fd")
        result = drv.raw_cmd("R", timeout=0.1)
        assert result["raw"] == b"ok\r\n"
        assert len(fake_softice.instances) == 2
        assert first.closes == 1
        assert fake_softice.instances[1].opens == 1
        assert fake_softice.instances[1].cmd_calls == ["R"]

    def test_retry_on_eio(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")
        fake_softice.instances[0].fail_next_cmd = OSError(errno.EIO, "io error")
        drv.raw_cmd("R", timeout=0.1)
        assert len(fake_softice.instances) == 2

    def test_retry_on_closed_fd_value_error(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")
        fake_softice.instances[0].fail_next_cmd = ValueError("I/O on closed file")
        drv.raw_cmd("R", timeout=0.1)
        assert len(fake_softice.instances) == 2

    def test_non_recoverable_propagates(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")
        fake_softice.instances[0].fail_next_cmd = OSError(errno.EPERM, "denied")
        with pytest.raises(OSError):
            drv.raw_cmd("R", timeout=0.1)
        assert len(fake_softice.instances) == 1

    def test_second_failure_becomes_io_error(self, fake_softice, monkeypatch):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")
        original_cmd = FakeSoftICE.cmd

        def always_fail(self, line, timeout=1.5):
            raise OSError(errno.EBADF, "still broken")

        monkeypatch.setattr(FakeSoftICE, "cmd", always_fail)
        with pytest.raises(SoftICEIOError, match="after reconnect"):
            drv.raw_cmd("R", timeout=0.1)
        monkeypatch.setattr(FakeSoftICE, "cmd", original_cmd)

    def test_disconnect(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")
        result = drv.disconnect()
        assert result["was_open"] is True
        assert fake_softice.instances[0].closes == 1
        result2 = drv.disconnect()
        assert result2["was_open"] is False


class TestSnapshot:
    def test_popped_in_flag(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")
        result = drv.raw_cmd("R", timeout=0.1)
        assert "popped_in" in result
        assert result["cursor"] == [24, 0]


class TestWaitForPopup:
    def test_returns_immediately_when_cached_popped(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")
        drv._popped_in = True

        result = drv.wait_for_popup(timeout_ms=1000, poll_interval_ms=10)

        assert result["popped_in"] is True
        assert result["timed_out"] is False
        assert result["elapsed_ms"] >= 0
        assert fake_softice.instances[0].drain_calls == 0

    def test_detects_popup_after_polling(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")
        blank = [" " * 80 for _ in range(25)]
        popped = blank.copy()
        popped[24] = ":"
        fake_softice.render_sequence = [blank, blank, popped]

        result = drv.wait_for_popup(timeout_ms=50, poll_interval_ms=1)

        assert result["popped_in"] is True
        assert result["timed_out"] is False
        assert result["elapsed_ms"] >= 0

    def test_times_out_cleanly(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")

        result = drv.wait_for_popup(timeout_ms=5, poll_interval_ms=1)

        assert result["popped_in"] is False
        assert result["timed_out"] is True
        assert result["elapsed_ms"] == 5

    def test_retries_recoverable_drain_error(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")
        first = fake_softice.instances[0]
        first.fail_next_drain = OSError(errno.EIO, "io error")
        blank = [" " * 80 for _ in range(25)]
        popped = blank.copy()
        popped[24] = ":"
        fake_softice.render_sequence = [blank, popped]

        result = drv.wait_for_popup(timeout_ms=50, poll_interval_ms=1)

        assert result["popped_in"] is True
        assert len(fake_softice.instances) == 2

    @pytest.mark.parametrize(
        ("timeout_ms", "poll_interval_ms", "message"),
        [
            (-1, 10, "timeout_ms must be >= 0"),
            (10, 0, "poll_interval_ms must be >= 1"),
        ],
    )
    def test_rejects_invalid_arguments(self, fake_softice, timeout_ms, poll_interval_ms, message):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")

        with pytest.raises(ValueError, match=message):
            drv.wait_for_popup(timeout_ms=timeout_ms, poll_interval_ms=poll_interval_ms)


class TestExpandedWindow:
    def test_context_manager_restores_bounds(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")
        assert drv.bounds == (17, 24)
        with drv.expanded_command_window():
            assert drv.bounds == (4, 24)
        assert drv.bounds == (17, 24)

    def test_context_manager_issues_wc_wd(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")
        with drv.expanded_command_window():
            pass
        calls = fake_softice.instances[0].cmd_calls
        assert "WC" in calls
        assert "WD" in calls
        # restore issued too
        assert any(c.startswith("WC ") for c in calls)
        assert any(c.startswith("WD ") for c in calls)

    def test_restores_on_exception(self, fake_softice):
        drv = SoftICEDriver()
        drv.connect("/tmp/fake-pty")
        with pytest.raises(RuntimeError):
            with drv.expanded_command_window():
                assert drv.bounds == (4, 24)
                raise RuntimeError("boom")
        assert drv.bounds == (17, 24)
