from __future__ import annotations

from softice_mcp.server import MCPServer


def _snap(
    *,
    command_rows: list[str] | None = None,
    command_rows_bold: list[bool] | None = None,
    popped_in: bool = True,
) -> dict[str, object]:
    return {
        "command_rows": command_rows or [],
        "command_rows_bold": command_rows_bold or [],
        "raw_rows": [],
        "cursor": [24, 0],
        "bounds": [17, 24],
        "popped_in": popped_in,
    }


def test_addr_context_switch_verifies_via_addr_listing(monkeypatch):
    server = MCPServer()
    calls: list[tuple[str, bool]] = []
    responses = [
        _snap(
            command_rows=[
                "WINICE: Load32 KERNEL32",
                "WINICE: LogError ERR_00",
                "Windows is active, press CTRL Z to pop up WINICE",
            ]
        ),
        _snap(
            command_rows=[
                "Handle  Owner",
                "  FFBEAE58  Explorer",
                "  FFBEAE90  Mosview",
            ],
            command_rows_bold=[False, False, True],
        ),
    ]

    def fake_cmd_with_extract(line: str, *, timeout: float = 0.0, expand_window: bool = False):
        calls.append((line, expand_window))
        return responses.pop(0)

    monkeypatch.setattr(server._driver, "cmd_with_extract", fake_cmd_with_extract)

    result = server._call_tool("addr_context", {"name": "Mosview"})

    assert calls == [("ADDR Mosview", False), ("ADDR", False)]
    assert result["ok"] is True
    assert result["parsed"] == {"switched_to": "Mosview"}


def test_bp_set_canonicalizes_selector_offset_and_ignores_noisy_output(monkeypatch):
    server = MCPServer()
    calls: list[tuple[str, bool]] = []
    responses = [
        _snap(
            command_rows=[
                "WINICE: Load32 USER32",
                "Windows is active, press CTRL Z to pop up WINICE",
            ]
        ),
        _snap(command_rows=["00) BPX  #0028:7E893010"]),
    ]

    def fake_cmd_with_extract(line: str, *, timeout: float = 0.0, expand_window: bool = False):
        calls.append((line, expand_window))
        return responses.pop(0)

    monkeypatch.setattr(server._driver, "cmd_with_extract", fake_cmd_with_extract)

    result = server._call_tool("bp_set", {"kind": "bpx", "address": "#0028:7E893010"})

    assert calls == [("BPX #0028:7E893010", False), ("BL", False)]
    assert result["ok"] is True
    assert result["parsed"] == {"issued": ["BPX #0028:7E893010"]}


def test_resume_canonicalizes_large_hex_string(monkeypatch):
    server = MCPServer()
    seen: dict[str, object] = {}

    def fake_raw_cmd(line: str, timeout: float = 1.5):
        seen["line"] = line
        seen["timeout"] = timeout
        return {"popped_in": False, "line": line}

    monkeypatch.setattr(server._driver, "raw_cmd", fake_raw_cmd)

    result = server._call_tool("resume", {"address": "7E893010"})

    assert seen == {"line": "G 7E893010", "timeout": 1.0}
    assert result["ok"] is True
    assert result["line"] == "G 7E893010"
