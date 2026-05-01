from __future__ import annotations

from softice_mcp.driver import DEFAULT_SEND_KEYS_DRAIN_TIMEOUT
from softice_mcp.server import MCPServer


def test_send_keys_drains_by_default(monkeypatch):
    server = MCPServer()
    seen: dict[str, object] = {}

    def fake_send_keys(data: str, *, drain_timeout: float):
        seen["data"] = data
        seen["drain_timeout"] = drain_timeout
        return {
            "raw": b"\x04",
            "raw_rows": ["after"],
            "cursor": [24, 0],
            "bounds": [17, 24],
            "popped_in": True,
        }

    monkeypatch.setattr(server._driver, "send_keys", fake_send_keys)

    result = server._call_tool("send_keys", {"keys": "\\x04"})

    assert seen == {
        "data": "\x04",
        "drain_timeout": DEFAULT_SEND_KEYS_DRAIN_TIMEOUT,
    }
    assert result["ok"] is True
    assert result["parsed"] == {"sent_bytes": 1}
    assert result["raw_rows"] == ["after"]
    assert result["popped_in"] is True


def test_send_keys_allows_explicit_zero_timeout(monkeypatch):
    server = MCPServer()
    seen: dict[str, object] = {}

    def fake_send_keys(data: str, *, drain_timeout: float):
        seen["data"] = data
        seen["drain_timeout"] = drain_timeout
        return {
            "raw": b"",
            "raw_rows": ["stale on purpose"],
            "cursor": [24, 0],
            "bounds": [17, 24],
            "popped_in": False,
        }

    monkeypatch.setattr(server._driver, "send_keys", fake_send_keys)

    result = server._call_tool("send_keys", {"keys": "A", "drain_timeout": 0.0})

    assert seen == {"data": "A", "drain_timeout": 0.0}
    assert result["ok"] is True
    assert result["parsed"] == {"sent_bytes": 1}
