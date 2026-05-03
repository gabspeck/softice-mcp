from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from typing import Any

from .bp_composer import (
    compose_addr_switch,
    compose_bp,
    compose_bp_mutate,
    format_address,
)
from .driver import (
    DEFAULT_SEND_KEYS_DRAIN_TIMEOUT,
    SoftICEDriver,
    SoftICEIOError,
    SoftICEStateError,
)
from .parsers import (
    parse_addr_table,
    parse_breakpoint_list,
    parse_disasm,
    parse_eval_result,
    parse_memory_dump,
    parse_mod_table,
    parse_register_dump,
    parse_status_owner,
)
from .profiling import (
    install as install_profiler,
    span,
    uninstall as uninstall_profiler,
)

SERVER_INFO = {"name": "softice-mcp", "version": "0.1.0"}

REMINDER_RESUME = (
    "Call `resume` before ending your turn — leaving SoftICE popped freezes the VM."
)
REMINDER_ADDR = (
    "For user-range addresses (0x00400000..0x7FFFFFFF) pass `context` so the BP "
    "arms in the correct process space; otherwise it will silently miss."
)
_EXPLICIT_SOFTICE_ERROR_SNIPPETS = (
    "duplicate breakpoint",
    "invalid ",
    "syntax error",
    "value is too large",
    "not found",
    "unknown command",
    "unknown symbol",
    "illegal",
    "bad ",
    "expected ",
    "requires ",
)


def _debug_log(message: str) -> None:
    print(f"[softice-mcp pid={os.getpid()}] {message}", file=sys.stderr, flush=True)


def _encode_raw(raw: bytes) -> str:
    return raw[:512].hex() if raw else ""


def _filtered_command_rows(command_rows: list[str]) -> list[str]:
    out: list[str] = []
    for row in command_rows:
        stripped = row.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if lowered.startswith("winice:"):
            continue
        if "windows is active" in lowered:
            continue
        out.append(stripped)
    return out


def _command_output_message(command_rows: list[str]) -> str:
    """Collapse meaningful command_rows into a single-line message, or ""."""
    return " ".join(_filtered_command_rows(command_rows))


def _command_error_message(command_rows: list[str]) -> str:
    """Return an explicit SoftICE error row, ignoring benign transport noise.

    BPX/BPM/BPIO/BPINT and ADDR <name> are silent on success, so any content
    is suspicious, but not every captured row belongs to the command itself.
    Background WinICE logs and detached-state status lines should not make a
    typed tool fail.
    """
    for stripped in _filtered_command_rows(command_rows):
        lowered = stripped.lower()
        if any(snippet in lowered for snippet in _EXPLICIT_SOFTICE_ERROR_SNIPPETS):
            return stripped
    return ""


def _address_linear_value(value: int | str | None) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        rendered = format_address(value)
    except ValueError:
        return None
    try:
        return int(rendered.split(":")[-1], 16)
    except ValueError:
        return None


def _raw_envelope(
    snapshot: dict[str, Any],
    *,
    parsed: dict[str, Any] | None = None,
    parse_error: str | None = None,
    note: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Full snapshot — raw_rows, raw_hex, cursor, bounds, the lot.

    Used only by the three raw passthrough tools (`screen`, `send_keys`,
    `raw_cmd`) where the unstructured grid IS the value the LLM is asking for.
    Parsed tools must use `_parsed_envelope` instead so callers don't drown in
    the 25-row grid alongside the structured data they actually wanted.
    """
    raw = snapshot.get("raw", b"") or b""
    env: dict[str, Any] = {
        "ok": parse_error is None,
        "parsed": parsed,
        "parse_error": parse_error,
        "command_rows": snapshot.get("command_rows", []),
        "raw_rows": snapshot.get("raw_rows") or snapshot.get("final_rows") or [],
        "raw_hex": _encode_raw(raw if isinstance(raw, (bytes, bytearray)) else b""),
        "cursor": snapshot.get("cursor"),
        "bounds": snapshot.get("bounds"),
        "popped_in": snapshot.get("popped_in"),
        "line": snapshot.get("line"),
    }
    if note:
        env["note"] = note
    if extra:
        env.update(extra)
    return env


def _parsed_envelope(
    snapshot: dict[str, Any],
    *,
    parsed: dict[str, Any] | None,
    parse_error: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Slim shape for tools backed by a structured parser.

    Drops the 25-row grid, raw byte hex, cursor and bounds — the LLM has the
    parsed value, the rest is noise. On parse failure we put `command_rows`
    and `raw_rows` back so the caller has a fallback path. `popped_in` rides
    along so the caller knows whether to resume before ending its turn; only
    targeted `note`s (errors, one-shot warnings) are emitted — the resume
    reminder sits in the tool descriptions, not every response.
    """
    env: dict[str, Any] = {
        "ok": parse_error is None,
        "parsed": parsed,
        "parse_error": parse_error,
        "popped_in": bool(snapshot.get("popped_in")),
    }
    line = snapshot.get("line")
    if line:
        env["line"] = line
    if note:
        env["note"] = note
    if parse_error is not None:
        env["command_rows"] = snapshot.get("command_rows", [])
        env["raw_rows"] = snapshot.get("raw_rows") or snapshot.get("final_rows") or []
    return env


class MCPServer:
    def __init__(self) -> None:
        self._driver = SoftICEDriver()
        self._tools = self._build_tools()
        self._transport_mode: str | None = None
        self._json_buffer = bytearray()

    def serve(self) -> None:
        _debug_log("server loop started")
        while True:
            message = self._read_message()
            if message is None:
                _debug_log("stdin closed")
                return
            self._handle_message(message)

    # ---- JSON-RPC dispatch ---------------------------------------

    def _handle_message(self, message: dict[str, Any]) -> None:
        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params", {}) or {}
        try:
            if method == "initialize":
                self._write_result(
                    request_id,
                    {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": SERVER_INFO,
                    },
                )
                return
            if method in ("notifications/initialized", "notifications/cancelled"):
                return
            if method == "ping":
                self._write_result(request_id, {})
                return
            if method == "tools/list":
                self._write_result(request_id, {"tools": self._tools})
                return
            if method == "resources/list":
                self._write_result(request_id, {"resources": []})
                return
            if method == "resources/templates/list":
                self._write_result(request_id, {"resourceTemplates": []})
                return
            if method == "prompts/list":
                self._write_result(request_id, {"prompts": []})
                return
            if method == "tools/call":
                name = params.get("name")
                arguments = params.get("arguments", {}) or {}
                result = self._call_tool(name, arguments)
                self._write_result(
                    request_id,
                    {
                        "content": [
                            {"type": "text", "text": json.dumps(result, indent=2, sort_keys=True, default=str)}
                        ],
                        "structuredContent": result,
                        "isError": not result.get("ok", True),
                    },
                )
                return
            raise ValueError(f"unsupported method {method!r}")
        except Exception as exc:
            self._write_error(request_id, exc)

    # ---- tool table ----------------------------------------------

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        with span(f"tool.{name}", args_keys=sorted(arguments.keys())):
            if name == "connect":
                return self._tool_connect(arguments)
            if name == "popup":
                return self._tool_popup(arguments)
            if name == "resume":
                return self._tool_resume(arguments)
            if name == "wait_for_popup":
                return self._tool_wait_for_popup(arguments)
            if name == "disconnect":
                return self._tool_disconnect(arguments)
            if name == "screen":
                return self._tool_screen(arguments)
            if name == "raw_cmd":
                return self._tool_raw_cmd(arguments)
            if name == "send_keys":
                return self._tool_send_keys(arguments)
            if name == "step":
                return self._tool_flow("T", arguments, label="step")
            if name == "step_over":
                return self._tool_flow("P", arguments, label="step_over")
            if name == "go_until":
                return self._tool_go_until(arguments)
            if name == "registers":
                return self._tool_registers(arguments)
            if name == "read_memory":
                return self._tool_read_memory(arguments)
            if name == "disassemble":
                return self._tool_disassemble(arguments)
            if name == "eval_expr":
                return self._tool_eval_expr(arguments)
            if name == "addr_context":
                return self._tool_addr_context(arguments)
            if name == "module_info":
                return self._tool_module_info(arguments)
            if name == "bp_set":
                return self._tool_bp_set(arguments)
            if name == "bp_list":
                return self._tool_bp_list(arguments)
            if name == "bp_mutate":
                return self._tool_bp_mutate(arguments)
            raise ValueError(f"unknown tool {name!r}")

    # ---- session / raw -------------------------------------------

    def _tool_connect(self, args: dict[str, Any]) -> dict[str, Any]:
        path = self._require_string(args, "path")
        profile_log = args.get("profile_log")
        note: str | None = None
        if profile_log is not None:
            if not isinstance(profile_log, str) or not profile_log.strip():
                raise ValueError("profile_log must be a non-empty string path")
            _, note = install_profiler(profile_log)
            if note is None:
                note = f"profile_log enabled: {profile_log}"
        else:
            uninstall_profiler()
        result = self._driver.connect(path)
        env: dict[str, Any] = {
            "ok": True,
            "parsed": result,
            "parse_error": None,
            "popped_in": False,
        }
        if note:
            env["note"] = note
        return env

    def _tool_popup(self, args: dict[str, Any]) -> dict[str, Any]:
        timeout = self._optional_float(args, "timeout", 1.5)
        snap = self._driver.popup(timeout=timeout or 1.5)
        return _parsed_envelope(snap, parsed=None)

    def _tool_resume(self, args: dict[str, Any]) -> dict[str, Any]:
        address = self._optional_address(args, "address")
        line = "G" if address is None else f"G {format_address(address)}"
        snap = self._driver.resume(line)
        return _parsed_envelope(snap, parsed={"resumed": True})

    def _tool_wait_for_popup(self, args: dict[str, Any]) -> dict[str, Any]:
        timeout_ms = self._optional_int(args, "timeout_ms", 30000)
        poll_interval_ms = self._optional_int(args, "poll_interval_ms", 100)
        if timeout_ms is None or timeout_ms < 0:
            raise ValueError("timeout_ms must be >= 0")
        if poll_interval_ms is None or poll_interval_ms < 1:
            raise ValueError("poll_interval_ms must be >= 1")
        snap = self._driver.wait_for_popup(
            timeout_ms=timeout_ms,
            poll_interval_ms=poll_interval_ms,
        )
        return _parsed_envelope(
            snap,
            parsed={
                "detected": bool(snap.get("popped_in")) and not bool(snap.get("timed_out")),
                "timed_out": bool(snap.get("timed_out")),
                "elapsed_ms": int(snap.get("elapsed_ms", 0)),
            },
        )

    def _tool_disconnect(self, args: dict[str, Any]) -> dict[str, Any]:
        result = self._driver.disconnect()
        uninstall_profiler()
        return {"ok": True, "parsed": result, "parse_error": None, "popped_in": False}

    def _tool_screen(self, args: dict[str, Any]) -> dict[str, Any]:
        timeout = self._optional_float(args, "timeout", 0.6)
        snap = self._driver.drain(timeout=timeout or 0.6)
        return _raw_envelope(snap)

    def _clear_command_window(self, timeout: float = 1.0) -> dict[str, Any]:
        return self._driver.cmd_with_extract("CLS", timeout=timeout)

    def _typed_cmd_with_extract(self, line: str, *, timeout: float = 1.5) -> dict[str, Any]:
        self._clear_command_window()
        return self._driver.cmd_with_extract(line, timeout=timeout)

    def _prepare_register_pane(self) -> bool:
        self._driver.ensure_popped()
        if self._driver.registers_visible():
            return False
        for _ in range(2):
            self._driver.raw_cmd("WR", timeout=1.0)
            if self._driver.registers_visible():
                return True
        raise SoftICEStateError("Register pane not visible — SoftICE may not be popped in.")

    def _tool_raw_cmd(self, args: dict[str, Any]) -> dict[str, Any]:
        line = self._require_string(args, "line")
        timeout = self._optional_float(args, "timeout", 1.5) or 1.5
        snap = self._driver.cmd_with_extract(line, timeout=timeout)
        return _raw_envelope(snap, parse_error=snap.get("parse_error"))

    def _tool_send_keys(self, args: dict[str, Any]) -> dict[str, Any]:
        keys = self._require_string(args, "keys")
        drain_timeout = self._optional_float(
            args,
            "drain_timeout",
            DEFAULT_SEND_KEYS_DRAIN_TIMEOUT,
        )
        if drain_timeout is None:
            drain_timeout = DEFAULT_SEND_KEYS_DRAIN_TIMEOUT
        decoded = keys.encode("latin-1").decode("unicode_escape")
        snap = self._driver.send_keys(decoded, drain_timeout=drain_timeout)
        return _raw_envelope(snap, parsed={"sent_bytes": len(decoded)})

    # ---- flow control -------------------------------------------

    def _tool_flow(self, cmd: str, args: dict[str, Any], *, label: str) -> dict[str, Any]:
        count = self._optional_int(args, "count", default=1) or 1
        if count < 1:
            raise ValueError("count must be >= 1")
        cleanup_registers = self._prepare_register_pane()
        try:
            last_snap: dict[str, Any] | None = None
            for _ in range(count):
                last_snap = self._typed_cmd_with_extract(cmd, timeout=1.5)
            assert last_snap is not None
            with span("parse.parse_register_dump", rows=len(last_snap["raw_rows"])):
                reg = parse_register_dump(last_snap["raw_rows"])
            return _parsed_envelope(
                last_snap,
                parsed={"label": label, "count": count, "registers": reg["parsed"]},
                parse_error=last_snap.get("parse_error") or reg["parse_error"],
            )
        finally:
            if cleanup_registers:
                self._driver.raw_cmd("WR", timeout=1.0)

    def _tool_go_until(self, args: dict[str, Any]) -> dict[str, Any]:
        address = self._require_address(args, "address")
        line = f"G {format_address(address)}"
        snap = self._typed_cmd_with_extract(line, timeout=5.0)
        return _parsed_envelope(snap, parsed={"issued": line})

    # ---- inspection ---------------------------------------------

    def _tool_registers(self, args: dict[str, Any]) -> dict[str, Any]:
        cleanup_registers = self._prepare_register_pane()
        try:
            snap = self._clear_command_window()
            snap = dict(snap)
            snap["line"] = None
            with span("parse.parse_register_dump", rows=len(snap["raw_rows"])):
                parsed = parse_register_dump(snap["raw_rows"])
            if not parsed["parsed"]:
                raise SoftICEStateError("Register pane not visible — SoftICE may not be popped in.")
            return _parsed_envelope(snap, parsed=parsed["parsed"], parse_error=parsed["parse_error"])
        finally:
            if cleanup_registers:
                self._driver.raw_cmd("WR", timeout=1.0)

    def _tool_read_memory(self, args: dict[str, Any]) -> dict[str, Any]:
        address = self._require_address(args, "address")
        length = self._require_int(args, "length", default=128)
        if length < 1 or length > 4096:
            raise ValueError("length must be in [1, 4096]")
        width = args.get("width", "b")
        if width not in ("b", "w", "d"):
            raise ValueError("width must be b|w|d")
        line = f"D{width.upper()} {format_address(address)} L{length:X}"
        snap = self._typed_cmd_with_extract(line, timeout=2.5)
        with span("parse.parse_memory_dump", rows=len(snap["command_rows"])):
            parsed = parse_memory_dump(snap["command_rows"])
        return _parsed_envelope(snap, parsed=parsed["parsed"], parse_error=parsed["parse_error"])

    def _tool_disassemble(self, args: dict[str, Any]) -> dict[str, Any]:
        address = self._require_address(args, "address")
        count = self._require_int(args, "count", default=8)
        if count < 1 or count > 128:
            raise ValueError("count must be in [1, 128]")
        # SoftICE's `L` is a byte length, not an instruction count. x86
        # instructions are at most 15 bytes; ask for `count * 16` bytes so
        # we're guaranteed at least `count` instructions, then truncate.
        line = f"U {format_address(address)} L{count * 16:X}"
        snap = self._typed_cmd_with_extract(line, timeout=2.0)
        with span("parse.parse_disasm", rows=len(snap["command_rows"])):
            parsed = parse_disasm(snap["command_rows"])
        if parsed["parsed"]:
            parsed["parsed"]["instructions"] = parsed["parsed"]["instructions"][:count]
        return _parsed_envelope(snap, parsed=parsed["parsed"], parse_error=parsed["parse_error"])

    def _tool_eval_expr(self, args: dict[str, Any]) -> dict[str, Any]:
        expr = self._require_string(args, "expr")
        if "\n" in expr or "\r" in expr:
            raise ValueError("expr must not contain newlines")
        snap = self._typed_cmd_with_extract(f"? {expr}", timeout=1.5)
        with span("parse.parse_eval_result", rows=len(snap["command_rows"])):
            parsed = parse_eval_result(snap["command_rows"])
        return _parsed_envelope(snap, parsed=parsed["parsed"], parse_error=parsed["parse_error"])

    def _read_addr_contexts(self, *, timeout: float = 2.0) -> tuple[dict[str, Any], dict[str, Any]]:
        snap = self._typed_cmd_with_extract("ADDR", timeout=timeout)
        status_owner = parse_status_owner(snap.get("raw_rows") or [])
        with span("parse.parse_addr_table", rows=len(snap["command_rows"])):
            parsed = parse_addr_table(
                snap["command_rows"],
                snap.get("command_rows_bold"),
                status_owner=status_owner,
            )
        return snap, parsed

    def _tool_addr_context(self, args: dict[str, Any]) -> dict[str, Any]:
        name = args.get("name")
        if name:
            target = str(name).strip()
            snap = self._typed_cmd_with_extract(f"ADDR {target}", timeout=2.0)
            message = _command_output_message(snap["command_rows"])
            if message:
                return _parsed_envelope(
                    snap,
                    parsed={"attempted": target},
                    parse_error="switch_failed",
                    note=message,
                )
            return _parsed_envelope(snap, parsed={"switched_to": target})
        snap, parsed = self._read_addr_contexts(timeout=2.0)
        return _parsed_envelope(snap, parsed=parsed["parsed"], parse_error=parsed["parse_error"])

    def _tool_module_info(self, args: dict[str, Any]) -> dict[str, Any]:
        pattern = args.get("pattern")
        line = "MOD" if not pattern else f"MOD {str(pattern).strip()}"
        snap = self._typed_cmd_with_extract(line, timeout=3.0)
        with span("parse.parse_mod_table", rows=len(snap["command_rows"])):
            parsed = parse_mod_table(snap["command_rows"])
        return _parsed_envelope(snap, parsed=parsed["parsed"], parse_error=parsed["parse_error"])

    # ---- breakpoints --------------------------------------------

    def _tool_bp_set(self, args: dict[str, Any]) -> dict[str, Any]:
        kind = self._require_string(args, "kind").lower()
        raw_address = args.get("address")
        address: int | str | None = None
        if kind in ("bpx", "bpm"):
            address = self._require_address(args, "address")
        elif raw_address is not None:
            address = self._coerce_address(raw_address, "address")
        actions = args.get("actions")
        if actions is not None and not isinstance(actions, list):
            raise ValueError("actions must be an array of strings")
        bp_line = compose_bp(
            kind,
            address,
            size=args.get("size"),
            verb=args.get("verb"),
            port=args.get("port"),
            intno=args.get("intno"),
            condition=args.get("condition"),
            actions=actions,
        )
        context = args.get("context")
        addr_line: str | None = compose_addr_switch(context) if context else None

        note: str | None = None
        linear_address = _address_linear_value(address)
        if kind in ("bpx", "bpm") and linear_address is not None:
            if 0x00400000 <= linear_address <= 0x7FFFFFFF and not context:
                note = REMINDER_ADDR

        # SoftICE 3.x rejects `ADDR x; BPX y` compound with Invalid Context
        # Handle — switch has to commit before BPX runs. Issue as two commands.
        if addr_line is not None:
            addr_snap = self._typed_cmd_with_extract(addr_line, timeout=2.0)
            addr_msg = _command_error_message(addr_snap["command_rows"])
            if addr_msg:
                return _parsed_envelope(
                    addr_snap,
                    parsed={"issued": [addr_line]},
                    parse_error="addr_switch_failed",
                    note=addr_msg,
                )

        snap = self._typed_cmd_with_extract(bp_line, timeout=2.0)
        bp_msg = _command_error_message(snap["command_rows"])
        issued = [addr_line, bp_line] if addr_line else [bp_line]

        parsed: dict[str, Any] = {"issued": issued}
        if bp_msg:
            return _parsed_envelope(
                snap,
                parsed=parsed,
                parse_error="bpx_rejected",
                note=bp_msg,
            )
        return _parsed_envelope(snap, parsed=parsed, note=note)

    def _tool_bp_list(self, args: dict[str, Any]) -> dict[str, Any]:
        snap = self._typed_cmd_with_extract("BL", timeout=1.5)
        with span("parse.parse_breakpoint_list", rows=len(snap["command_rows"])):
            parsed = parse_breakpoint_list(snap["command_rows"])
        bps = parsed["parsed"]["breakpoints"] if parsed["parsed"] else []
        return _parsed_envelope(snap, parsed={"breakpoints": bps})

    def _tool_bp_mutate(self, args: dict[str, Any]) -> dict[str, Any]:
        op = self._require_string(args, "op")
        idx_raw = args.get("index")
        if isinstance(idx_raw, str):
            s = idx_raw.strip()
            if s == "*":
                index: int | str = "*"
            elif s.lower().startswith("0x"):
                index = int(s, 16)
            elif s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                index = int(s)
            else:
                raise ValueError("index must be an integer or '*'")
        else:
            index = self._require_int(args, "index")
        return_breakpoints = bool(args.get("return_breakpoints", False))
        line = compose_bp_mutate(op, index)
        snap = self._typed_cmd_with_extract(line, timeout=1.5)
        parsed: dict[str, Any] = {"issued": line}
        if return_breakpoints:
            follow = self._typed_cmd_with_extract("BL", timeout=1.5)
            with span("parse.parse_breakpoint_list", rows=len(follow["command_rows"])):
                parsed_bl = parse_breakpoint_list(follow["command_rows"])
            bps = parsed_bl["parsed"]["breakpoints"] if parsed_bl["parsed"] else []
            parsed["breakpoints"] = bps
        return _parsed_envelope(snap, parsed=parsed)

    # ---- transport -----------------------------------------------

    def _read_message(self) -> dict[str, Any] | None:
        if self._transport_mode == "raw-json":
            return self._read_raw_json_message()
        content_length: int | None = None
        while True:
            line = sys.stdin.buffer.readline()
            if not line:
                return None
            if content_length is None and self._transport_mode is None:
                stripped = line.lstrip()
                if stripped.startswith((b"{", b"[")):
                    self._transport_mode = "raw-json"
                    self._json_buffer.extend(line)
                    return self._read_raw_json_message()
            if line in (b"\r\n", b"\n"):
                break
            header = line.decode("ascii").strip()
            if header.lower().startswith("content-length:"):
                content_length = int(header.split(":", 1)[1].strip())
                self._transport_mode = "content-length"
        if content_length is None:
            raise ValueError("missing Content-Length header")
        body = sys.stdin.buffer.read(content_length)
        if len(body) != content_length:
            return None
        return json.loads(body.decode("utf-8"))

    def _read_raw_json_message(self) -> dict[str, Any] | None:
        decoder = json.JSONDecoder()
        while True:
            if self._json_buffer:
                try:
                    text = self._json_buffer.decode("utf-8")
                    obj, end = decoder.raw_decode(text)
                    remainder = text[end:].lstrip()
                    self._json_buffer = bytearray(remainder.encode("utf-8"))
                    return obj
                except json.JSONDecodeError:
                    pass
            chunk = sys.stdin.buffer.read1(65536)
            if not chunk:
                if not self._json_buffer:
                    return None
                raise ValueError("incomplete raw JSON message on stdin")
            self._json_buffer.extend(chunk)

    def _write_result(self, request_id: Any, result: dict[str, Any]) -> None:
        self._write_message({"jsonrpc": "2.0", "id": request_id, "result": result})

    def _write_error(self, request_id: Any, exc: Exception) -> None:
        _debug_log(f"error for id={request_id!r}: {exc.__class__.__name__}: {exc}")
        code = -32000
        if isinstance(exc, ValueError):
            code = -32602
        elif isinstance(exc, SoftICEStateError):
            code = -32002
        elif isinstance(exc, SoftICEIOError):
            code = -32001
        self._write_message(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": code,
                    "message": str(exc),
                    "data": {
                        "type": exc.__class__.__name__,
                        "traceback": traceback.format_exc(),
                    },
                },
            }
        )

    def _write_message(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True, default=str).encode("utf-8")
        if self._transport_mode == "raw-json":
            sys.stdout.buffer.write(body)
            sys.stdout.buffer.write(b"\n")
        else:
            header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            sys.stdout.buffer.write(header)
            sys.stdout.buffer.write(body)
        sys.stdout.buffer.flush()

    # ---- argument helpers ----------------------------------------

    def _require_string(self, arguments: dict[str, Any], key: str) -> str:
        value = arguments.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{key} must be a non-empty string")
        return value

    def _optional_string(self, arguments: dict[str, Any], key: str, default: str = "") -> str:
        value = arguments.get(key, default)
        if not isinstance(value, str):
            raise ValueError(f"{key} must be a string")
        return value

    def _require_int(self, arguments: dict[str, Any], key: str, default: int | None = None) -> int:
        value = arguments.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{key} must be an integer")
        return value

    def _optional_int(self, arguments: dict[str, Any], key: str, default: int | None = None) -> int | None:
        value = arguments.get(key, default)
        if value is None:
            return default
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{key} must be an integer")
        return value

    def _optional_float(self, arguments: dict[str, Any], key: str, default: float | None = None) -> float | None:
        value = arguments.get(key, default)
        if value is None:
            return default
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{key} must be a number")
        return float(value)

    def _coerce_address(self, raw: Any, key: str) -> int | str:
        if isinstance(raw, bool):
            raise ValueError(f"{key} must be int or string")
        if isinstance(raw, int):
            return raw
        if isinstance(raw, str):
            s = raw.strip()
            if not s:
                raise ValueError(f"{key} must be a non-empty string")
            return s
        raise ValueError(f"{key} must be int or string")

    def _require_address(self, arguments: dict[str, Any], key: str) -> int | str:
        if key not in arguments:
            raise ValueError(f"{key} is required")
        return self._coerce_address(arguments[key], key)

    def _optional_address(self, arguments: dict[str, Any], key: str) -> int | str | None:
        if key not in arguments or arguments[key] is None:
            return None
        return self._coerce_address(arguments[key], key)

    # ---- tool schemas -------------------------------------------

    def _tool(self, name: str, description: str, properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
        return {
            "name": name,
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        }

    def _build_tools(self) -> list[dict[str, Any]]:
        addr_schema = {"oneOf": [{"type": "integer"}, {"type": "string"}]}
        resume_hint = " " + REMINDER_RESUME
        addr_hint = " " + REMINDER_ADDR
        return [
            self._tool(
                "connect",
                "Open the SoftICE serial transport. Call this once before any other tool — subsequent commands reuse the connection and auto-pop SoftICE (Ctrl-D) when needed. Use the host-side path of the PTY exposed by 86Box's Virtual Console backend (typically `/tmp/softice_host`, or whatever path 86Box's COM1 config points at). The transport is locked to one MCP process at a time. Calling `connect` again replaces the existing connection.",
                {
                    "path": {
                        "type": "string",
                        "description": "Filesystem path to the SoftICE PTY device exposed by 86Box (e.g. /tmp/softice_host, or a /dev/pts/N device).",
                    },
                    "profile_log": {
                        "type": "string",
                        "description": "Optional filesystem path. When set, write a JSONL profiling log with per-span timings (tool dispatch, transport, pager iterations, parsers) for diagnosing slow tool calls. Truncated each connect. Omit to disable (default).",
                    },
                },
                ["path"],
            ),
            self._tool(
                "popup",
                "Ctrl-D into SoftICE to break over the running VM. Usually unnecessary — structured tools auto-pop on demand. Use this when you want to pop explicitly without issuing a command.",
                {"timeout": {"type": "number"}},
                [],
            ),
            self._tool(
                "resume",
                "Resume execution (G [addr]). Call this before ending your turn — leaving SoftICE popped freezes the VM.",
                {"address": addr_schema},
                [],
            ),
            self._tool(
                "wait_for_popup",
                "Block until SoftICE pops in or the timeout expires. Use this after `resume` when you want to wait for a breakpoint hit while the VM runs. If SoftICE is popped when it returns, call `resume` before ending your turn.",
                {
                    "timeout_ms": {
                        "type": "integer",
                        "default": 30000,
                        "description": "Maximum time to wait before returning a timeout result.",
                    },
                    "poll_interval_ms": {
                        "type": "integer",
                        "default": 100,
                        "description": "Polling interval for passive transport drains while waiting.",
                    },
                },
                [],
            ),
            self._tool(
                "disconnect",
                "Close the transport and forget the path. A fresh `connect` is required before further commands.",
                {},
                [],
            ),
            self._tool(
                "screen",
                "Drain pending bytes and return the current 25-row grid.",
                {"timeout": {"type": "number"}},
                [],
            ),
            self._tool(
                "raw_cmd",
                "Escape hatch: send an arbitrary SoftICE command line (CR appended). Prefer a typed tool (`step`, `read_memory`, `bp_set`, `addr_context`, `module_info`, `eval_expr`, `registers`, etc.) — they parse output into structured fields and enforce known-good discipline (e.g. splitting `ADDR; BPX`). Reach for `raw_cmd` only when no typed tool fits (WHAT, BSTAT, TABLE, exotic chains). State in one sentence why the typed path doesn't work before issuing."
                + resume_hint,
                {
                    "line": {"type": "string"},
                    "timeout": {"type": "number"},
                },
                ["line"],
            ),
            self._tool(
                "send_keys",
                "Escape hatch: write raw bytes to the transport (no CR appended). Escapes supported: \\r \\n \\t \\e \\x04. Use only for byte-level input no other tool can produce — arrow-key navigation (BH list), ESC to dismiss pagers, function keys, chained Ctrl-sequences. For command lines use `raw_cmd`; for structured debugger ops use the typed tools. State in one sentence why no typed tool fits before issuing.",
                {
                    "keys": {"type": "string"},
                    "drain_timeout": {
                        "type": "number",
                        "default": DEFAULT_SEND_KEYS_DRAIN_TIMEOUT,
                        "description": "Seconds to wait for post-key repaint before snapshotting; set to 0 to skip draining.",
                    },
                },
                ["keys"],
            ),
            self._tool(
                "step",
                "Single-step (T) `count` instructions, return final register pane." + resume_hint,
                {"count": {"type": "integer"}},
                [],
            ),
            self._tool(
                "step_over",
                "Step over (P) `count` instructions without descending into calls." + resume_hint,
                {"count": {"type": "integer"}},
                [],
            ),
            self._tool(
                "go_until",
                "G until the given address (one-shot implicit breakpoint)." + resume_hint,
                {"address": addr_schema},
                ["address"],
            ),
            self._tool(
                "registers",
                "Return the Register pane parsed as a dict (eax, ebx, …, flags_set). Temporarily shows the Register pane with `WR` when needed, clears the command window, parses the pane, then restores the maximized-command layout.",
                {},
                [],
            ),
            self._tool(
                "read_memory",
                "Dump up to 4096 bytes via D/DB/DW/DD. Clears the command window first, then returns hex, ASCII, and a per-line breakdown.",
                {
                    "address": addr_schema,
                    "length": {"type": "integer", "default": 128},
                    "width": {"type": "string", "enum": ["b", "w", "d"], "default": "b"},
                },
                ["address"],
            ),
            self._tool(
                "disassemble",
                "U `count` instructions from `address`. Returns parsed mnemonic+operands per line.",
                {
                    "address": addr_schema,
                    "count": {"type": "integer", "default": 8},
                },
                ["address"],
            ),
            self._tool(
                "eval_expr",
                "Evaluate a SoftICE expression (`? <expr>`). Returns hex/dec/ascii. Supports stack/register indirection: `esp->4`, `eax.1c`, `dword(addr)`, etc.",
                {"expr": {"type": "string"}},
                ["expr"],
            ),
            self._tool(
                "addr_context",
                "Show the address-context table (ADDR) or switch to a context (ADDR <target>). `name` accepts either a process name (e.g. `Explorer`) or a hex Handle from the table — use the handle when multiple rows share a name.",
                {"name": {"type": "string"}},
                [],
            ),
            self._tool(
                "module_info",
                "MOD [pattern] — list global modules (Win95). Returns parsed name/base/pe_header/path per module.",
                {"pattern": {"type": "string"}},
                [],
            ),
            self._tool(
                "bp_set",
                "Arm a breakpoint. Composes BPX/BPM[size]/BPIO/BPINT with optional IF/DO. "
                + REMINDER_ADDR
                + " " + REMINDER_RESUME,
                {
                    "kind": {"type": "string", "enum": ["bpx", "bpm", "bpio", "bpint"]},
                    "address": addr_schema,
                    "size": {"type": "string", "enum": ["b", "w", "d"]},
                    "verb": {"type": "string", "enum": ["r", "w", "rw", "x"]},
                    "port": {"type": "integer"},
                    "intno": {"type": "integer"},
                    "condition": {
                        "type": "string",
                        "description": "Optional IF expression. Wrapped in parens if not already. e.g. \"EAX==1\", \"dword(esp->4) != 0\".",
                    },
                    "actions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional DO action list joined with ';'. Actions must not contain raw double-quotes.",
                    },
                    "context": {
                        "type": "string",
                        "description": "Optional process name to prefix as `ADDR <ctx>;`. Required when the address is in 0x00400000..0x7FFFFFFF and loaded in a specific process.",
                    },
                },
                ["kind"],
            ),
            self._tool(
                "bp_list",
                "List current breakpoints (BL), parsed into {index, kind, enabled, target, condition, action}.",
                {},
                [],
            ),
            self._tool(
                "bp_mutate",
                "Clear (BC), enable (BE), or disable (BD) a breakpoint by index, or pass '*' for all. "
                "By default returns only the issued command line; set "
                "`return_breakpoints=true` to also run BL and include the parsed list.",
                {
                    "op": {"type": "string", "enum": ["clear", "enable", "disable"]},
                    "index": {"oneOf": [{"type": "integer"}, {"type": "string", "enum": ["*"]}]},
                    "return_breakpoints": {
                        "type": "boolean",
                        "default": False,
                        "description": "When true, run BL after the mutation and include `breakpoints` in the response. Default false (saves a round-trip).",
                    },
                },
                ["op", "index"],
            ),
        ]


def _run_self_test(path: str) -> int:
    """Smoke-test driver + parsers against a live SoftICE session.

    Requires a VM where SoftICE is configured for VT100-over-serial and 86Box
    exposes the host side of a PTY pair via Virtual Console. Prints a short
    summary and exits 0 on success, non-zero on the first failure.
    """
    driver = SoftICEDriver()
    steps: list[tuple[str, dict[str, Any]]] = []
    try:
        driver.connect(path)
        steps.append(("popup", driver.popup()))
        steps.append(("eval 1+1", driver.cmd_with_extract("? 1+1")))
        driver.raw_cmd("WR")
        steps.append(("registers", driver.drain(timeout=0.3)))
        driver.raw_cmd("WR")
        steps.append(("bl", driver.cmd_with_extract("BL")))
        steps.append(("resume", driver.resume("G")))
    except Exception as exc:
        print(f"self-test FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        driver.disconnect()

    for label, snap in steps:
        preview = snap.get("command_rows") or snap.get("raw_rows") or []
        preview_s = " | ".join(r.strip() for r in preview[:3] if r.strip())
        print(f"[{label}] popped_in={snap.get('popped_in')} rows={len(preview)} {preview_s[:140]}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SoftICE MCP stdio server")
    parser.add_argument(
        "--self-test",
        metavar="PATH",
        default=None,
        help="Run a live smoke test against the given PTY device path and exit "
        "(typically /tmp/softice_host). In normal serve mode the path is supplied "
        "by the MCP client via the `connect` tool.",
    )
    ns = parser.parse_args()
    if ns.self_test:
        return _run_self_test(ns.self_test)
    MCPServer().serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
