from __future__ import annotations

import pytest

from softice_mcp.server import MCPServer


def test_wait_for_popup_is_listed():
    server = MCPServer()

    assert any(tool["name"] == "wait_for_popup" for tool in server._build_tools())


def test_wait_for_popup_returns_success_envelope(monkeypatch):
    server = MCPServer()

    def fake_wait_for_popup(*, timeout_ms: int, poll_interval_ms: int):
        assert timeout_ms == 500
        assert poll_interval_ms == 25
        return {"popped_in": True, "timed_out": False, "elapsed_ms": 123}

    monkeypatch.setattr(server._driver, "wait_for_popup", fake_wait_for_popup)

    result = server._call_tool(
        "wait_for_popup",
        {"timeout_ms": 500, "poll_interval_ms": 25},
    )

    assert result["ok"] is True
    assert result["popped_in"] is True
    assert result["parsed"] == {
        "detected": True,
        "timed_out": False,
        "elapsed_ms": 123,
    }


def test_wait_for_popup_returns_timeout_envelope(monkeypatch):
    server = MCPServer()

    monkeypatch.setattr(
        server._driver,
        "wait_for_popup",
        lambda *, timeout_ms, poll_interval_ms: {
            "popped_in": False,
            "timed_out": True,
            "elapsed_ms": 30000,
        },
    )

    result = server._call_tool("wait_for_popup", {})

    assert result["ok"] is True
    assert result["popped_in"] is False
    assert result["parsed"] == {
        "detected": False,
        "timed_out": True,
        "elapsed_ms": 30000,
    }


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"timeout_ms": -1}, "timeout_ms must be >= 0"),
        ({"poll_interval_ms": 0}, "poll_interval_ms must be >= 1"),
    ],
)
def test_wait_for_popup_rejects_invalid_arguments(arguments, message):
    server = MCPServer()

    with pytest.raises(ValueError, match=message):
        server._call_tool("wait_for_popup", arguments)
