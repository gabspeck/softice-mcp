from __future__ import annotations

from softice_mcp.server import MCPServer


def _register_rows() -> list[str]:
    rows = [" " * 80 for _ in range(25)]
    rows[0] = "EAX=00000001 EBX=00000002".ljust(80)
    rows[1] = "EIP=00401000 ESP=0063FF00".ljust(80)
    rows[2] = "   o  d  I  s  z  a  p  c".ljust(80)
    rows[3] = ("-" * 73 + "PROT32-").ljust(80)
    rows[24] = ":".ljust(80)
    return rows


def _snap(
    *,
    command_rows: list[str] | None = None,
    command_rows_bold: list[bool] | None = None,
    raw_rows: list[str] | None = None,
    popped_in: bool = True,
) -> dict[str, object]:
    return {
        "command_rows": command_rows or [],
        "command_rows_bold": command_rows_bold or [],
        "raw_rows": raw_rows or [],
        "cursor": [24, 0],
        "bounds": [0, 24],
        "popped_in": popped_in,
    }


def test_raw_cmd_does_not_prepend_cls(monkeypatch):
    server = MCPServer()
    calls: list[str] = []

    def fake_cmd_with_extract(line: str, *, timeout: float = 0.0):
        calls.append(line)
        return _snap()

    monkeypatch.setattr(server._driver, "cmd_with_extract", fake_cmd_with_extract)

    result = server._call_tool("raw_cmd", {"line": "VER"})

    assert calls == ["VER"]
    assert result["ok"] is True


def test_addr_context_succeeds_when_switch_command_is_silent(monkeypatch):
    server = MCPServer()
    calls: list[str] = []

    def fake_cmd_with_extract(line: str, *, timeout: float = 0.0):
        calls.append(line)
        if line == "CLS":
            return _snap()
        if line == "ADDR Mosview":
            return _snap(command_rows=[])
        raise AssertionError(line)

    monkeypatch.setattr(server._driver, "cmd_with_extract", fake_cmd_with_extract)

    result = server._call_tool("addr_context", {"name": "Mosview"})

    assert calls == ["CLS", "ADDR Mosview"]
    assert result["ok"] is True
    assert result["parsed"] == {"switched_to": "Mosview"}


def test_addr_context_fails_when_switch_command_prints_output(monkeypatch):
    server = MCPServer()
    calls: list[str] = []

    def fake_cmd_with_extract(line: str, *, timeout: float = 0.0):
        calls.append(line)
        if line == "CLS":
            return _snap()
        if line == "ADDR mosview":
            return _snap(command_rows=["Invalid command"])
        raise AssertionError(line)

    monkeypatch.setattr(server._driver, "cmd_with_extract", fake_cmd_with_extract)

    result = server._call_tool("addr_context", {"name": "mosview"})

    assert calls == ["CLS", "ADDR mosview"]
    assert result["ok"] is False
    assert result["parse_error"] == "switch_failed"
    assert result["parsed"] == {"attempted": "mosview"}
    assert result["note"] == "Invalid command"


def test_bp_set_canonicalizes_selector_offset_and_ignores_noisy_output(monkeypatch):
    server = MCPServer()
    calls: list[str] = []

    def fake_cmd_with_extract(line: str, *, timeout: float = 0.0):
        calls.append(line)
        if line == "CLS":
            return _snap()
        return _snap(
            command_rows=[
                "WINICE: Load32 USER32",
                "Windows is active, press CTRL Z to pop up WINICE",
            ]
        )

    monkeypatch.setattr(server._driver, "cmd_with_extract", fake_cmd_with_extract)

    result = server._call_tool("bp_set", {"kind": "bpx", "address": "#0028:7E893010"})

    assert calls == ["CLS", "BPX #0028:7E893010"]
    assert result["ok"] is True
    assert result["parsed"] == {"issued": ["BPX #0028:7E893010"]}


def test_resume_canonicalizes_large_hex_string(monkeypatch):
    server = MCPServer()
    seen: dict[str, object] = {}

    def fake_resume(line: str):
        seen["line"] = line
        return {"popped_in": False, "line": line}

    monkeypatch.setattr(server._driver, "resume", fake_resume)

    result = server._call_tool("resume", {"address": "7E893010"})

    assert seen == {"line": "G 7E893010"}
    assert result["ok"] is True
    assert result["line"] == "G 7E893010"
    assert result["popped_in"] is False


def test_bp_list_clears_before_bl(monkeypatch):
    server = MCPServer()
    calls: list[str] = []

    def fake_cmd_with_extract(line: str, *, timeout: float = 0.0):
        calls.append(line)
        if line == "CLS":
            return _snap()
        return _snap(command_rows=["00) BPX  #0028:7E893010"])

    monkeypatch.setattr(server._driver, "cmd_with_extract", fake_cmd_with_extract)

    result = server._call_tool("bp_list", {})

    assert calls == ["CLS", "BL"]
    assert result["ok"] is True


def test_bp_mutate_can_return_breakpoints_after_clear(monkeypatch):
    server = MCPServer()
    calls: list[str] = []

    def fake_cmd_with_extract(line: str, *, timeout: float = 0.0):
        calls.append(line)
        if line == "CLS":
            return _snap()
        if line == "BL":
            return _snap(command_rows=["00) BPX  #0028:7E893010"])
        return _snap()

    monkeypatch.setattr(server._driver, "cmd_with_extract", fake_cmd_with_extract)

    result = server._call_tool(
        "bp_mutate", {"op": "clear", "index": "*", "return_breakpoints": True}
    )

    assert calls == ["CLS", "BC *", "CLS", "BL"]
    assert result["ok"] is True
    assert result["parsed"] == {
        "issued": "BC *",
        "breakpoints": [
            {
                "index": 0,
                "enabled": True,
                "kind": "BPX",
                "target": "#0028:7E893010",
                "condition": "",
                "action": "",
            }
        ],
    }


def test_bp_set_rejects_on_explicit_softice_error(monkeypatch):
    server = MCPServer()
    calls: list[str] = []

    def fake_cmd_with_extract(line: str, *, timeout: float = 0.0):
        calls.append(line)
        if line == "CLS":
            return _snap()
        return _snap(command_rows=["Duplicate breakpoint"])

    monkeypatch.setattr(server._driver, "cmd_with_extract", fake_cmd_with_extract)

    result = server._call_tool("bp_set", {"kind": "bpx", "address": "#0028:7E893010"})

    assert calls == ["CLS", "BPX #0028:7E893010"]
    assert result["ok"] is False
    assert result["parse_error"] == "bpx_rejected"


def test_registers_temporarily_shows_and_hides_register_pane(monkeypatch):
    server = MCPServer()
    calls: list[str] = []
    visible = iter([False, True])

    monkeypatch.setattr(server._driver, "ensure_popped", lambda: None)
    monkeypatch.setattr(server._driver, "registers_visible", lambda: next(visible))

    def fake_raw_cmd(line: str, timeout: float = 1.5):
        calls.append(line)
        return _snap(raw_rows=_register_rows())

    def fake_cmd_with_extract(line: str, *, timeout: float = 0.0):
        calls.append(line)
        return _snap(raw_rows=_register_rows())

    monkeypatch.setattr(server._driver, "raw_cmd", fake_raw_cmd)
    monkeypatch.setattr(server._driver, "cmd_with_extract", fake_cmd_with_extract)

    result = server._call_tool("registers", {})

    assert calls == ["WR", "CLS", "WR"]
    assert result["ok"] is True
    assert result["parsed"]["registers"]["EAX"] == 1


def test_step_toggles_register_pane_and_clears_each_command(monkeypatch):
    server = MCPServer()
    calls: list[str] = []
    visible = iter([False, True])

    monkeypatch.setattr(server._driver, "ensure_popped", lambda: None)
    monkeypatch.setattr(server._driver, "registers_visible", lambda: next(visible))

    def fake_raw_cmd(line: str, timeout: float = 1.5):
        calls.append(line)
        return _snap(raw_rows=_register_rows())

    def fake_cmd_with_extract(line: str, *, timeout: float = 0.0):
        calls.append(line)
        return _snap(raw_rows=_register_rows())

    monkeypatch.setattr(server._driver, "raw_cmd", fake_raw_cmd)
    monkeypatch.setattr(server._driver, "cmd_with_extract", fake_cmd_with_extract)

    result = server._call_tool("step", {"count": 2})

    assert calls == ["WR", "CLS", "T", "CLS", "T", "WR"]
    assert result["ok"] is True
    assert result["parsed"]["count"] == 2
    assert result["parsed"]["registers"]["registers"]["EAX"] == 1
