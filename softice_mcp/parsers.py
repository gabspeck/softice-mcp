"""Parse SoftICE VT100-rendered grids into structured dicts.

All parsers are pure functions over the pyte-rendered 80x25 grid. They never
raise on malformed input — they return ``{"parsed": ..., "parse_error": ...}``
so the caller can fall back to the raw rows when SoftICE output doesn't fit
the expected shape.
"""

from __future__ import annotations

import re
from typing import Any

from .profiling import span

CommandRows = list[str]
Grid = list[str]
_STATUS_OWNER = re.compile(r"Enter a command \(H for help\)\s+(?P<owner>\S+)\s*$")


# ---- extractor ---------------------------------------------------------


def extract_command_output(
    rows: Grid,
    echo_line: str,
    bounds: tuple[int, int],
    cursor_row: int,
) -> tuple[CommandRows, str | None, list[int]]:
    """Slice the Command window down to just the output of the last command.

    ``rows`` is the pyte 25-row grid. ``bounds`` is the inclusive top/bottom
    row range of the Command window (17..24 for stock layout, 4..24 when the
    Data/Code panes are hidden). ``cursor_row`` is pyte's Y after drain —
    SoftICE parks the cursor on the fresh prompt.

    Returns (command_rows, parse_error, row_indices). command_rows excludes
    the echo row and the new prompt row, trailing blank lines are dropped,
    and row_indices holds the source grid index for each kept row so callers
    can look up sibling attributes (boldness, colour) at the same coords.
    """
    with span("parser.extract_command_output", rows=len(rows)):
        top, bot = bounds
        top = max(0, top)
        bot = min(len(rows) - 1, bot)
        if top > bot:
            return [], "bounds_invalid", []

        # Anchor the prompt at the bottommost terminator. We deliberately ignore
        # `cursor_row`: pyte doesn't reliably park on the bare `:` row, so
        # walking up from the cursor can latch onto a `:COMMAND` echo (`:BL`,
        # `:WD`) and treat it as the prompt — especially in an expanded Command
        # window where prior-command echoes stay visible. Walking up from `bot`
        # picks whatever is actually nearest the bottom of the pane.
        prompt_row: int | None = None
        for r in range(bot, top - 1, -1):
            stripped = rows[r].strip()
            if not stripped:
                continue
            if "Enter a command" in stripped:
                continue
            if "--------" in stripped:
                continue
            if stripped == ":":
                prompt_row = r
                break
            # First non-skippable row isn't a fresh `:` prompt — SoftICE hasn't
            # finished painting yet. Fail loudly instead of silently latching
            # onto a stale echo higher up.
            break
        if prompt_row is None:
            return [], "prompt_not_found", []

        # Echo search walks BACKWARD from the prompt so the most recent `:CMD`
        # echo wins over stale ones. Pass 1 insists on an exact match (with or
        # without the leading `:`) to reject accidental substring hits — a
        # single-letter needle like `"R"` would otherwise false-match a register
        # dump row containing `IDTR`. Pass 2 is the looser substring+`:` check,
        # reached only if Pass 1 found nothing in the whole window.
        echo_row: int | None = None
        needle = echo_line.strip()
        if needle:
            colon_needle = f":{needle}"
            for r in range(prompt_row - 1, top - 1, -1):
                stripped = rows[r].strip()
                if stripped == needle or stripped == colon_needle:
                    echo_row = r
                    break
            if echo_row is None:
                for r in range(prompt_row - 1, top - 1, -1):
                    row = rows[r]
                    idx = row.find(needle)
                    if idx < 0:
                        continue
                    if ":" in row[:idx]:
                        echo_row = r
                        break
        # Fallback (and the continuation-page case): include everything between
        # the last separator row and the prompt. SoftICE's Command window scrolls
        # upward, so output sits above the prompt; the echo often gets overwritten
        # by the result before we snapshot, so matching it fails.
        if echo_row is None:
            echo_row = top - 1
            for r in range(prompt_row - 1, top - 1, -1):
                if _is_separator(rows[r]):
                    echo_row = r
                    break

        indices = list(range(echo_row + 1, prompt_row))
        out = [rows[r].rstrip() for r in indices]
        while out and not out[-1].strip():
            out.pop()
            indices.pop()
        return out, None, indices


def _is_separator(row: str) -> bool:
    """SoftICE divider lines between panes.

    Stock dividers look like ``------…------PROT32-``. Code-pane headers
    additionally prefix the current function name+offset, giving something
    like ``End_Nest_Exec+0074-----------``. We match either shape by
    looking for a run of ≥8 consecutive dashes anywhere on the line (this
    excludes memory-dump ASCII rows, which only ever have single ``-``
    characters between byte pairs).
    """
    return "--------" in row


def detect_command_bounds(rows: Grid, fallback: tuple[int, int]) -> tuple[int, int]:
    """Infer the Command window rows from the rendered grid.

    SoftICE's Command window sits below the last pane separator (the
    ``---…---PROT32-`` / ``---…---KERNEL32-`` style bar) and stops above the
    status bar. We locate the separator; if not present (expanded command
    window with panes hidden) we fall back to the caller's hint.
    """
    with span("parser.detect_command_bounds", rows=len(rows)):
        last_sep = -1
        for i, row in enumerate(rows):
            if _is_separator(row):
                last_sep = i
        if last_sep < 0:
            return fallback
        top = last_sep + 1
        bot = len(rows) - 1
        # The bottom-most row with content (and at most one row above it carrying
        # the "Enter a command (H for help)" or module-name status bar) doesn't
        # belong in the extraction window. Trim a trailing non-prompt row if we
        # see the status-bar pattern.
        while bot > top and not rows[bot].strip():
            bot -= 1
        return top, bot


def detect_popped_in(rows: Grid, bounds: tuple[int, int]) -> bool:
    """True iff SoftICE is currently popped over the VM.

    After a ``G`` the Command window still shows ``:G <addr>`` in the bottom
    half, which fooled the old "any ':' in the lower rows" heuristic. Use
    three signals:
    - ``Windows is active`` on the host status line means detached.
    - ``Enter a command (H for help)`` is SoftICE's Command-window status
      bar — painted only while popped.
    - Fallback: a bare ``:`` at the last non-status Command-window row.
    """
    with span("parser.detect_popped_in", rows=len(rows)):
        if not rows:
            return False
        if any("Windows is active" in r for r in rows):
            return False
        if any("Enter a command" in r for r in rows):
            return True
        top, bot = bounds
        top = max(0, top)
        bot = min(len(rows) - 1, bot)
        for r in range(bot, top - 1, -1):
            stripped = rows[r].strip()
            if not stripped or "--------" in stripped:
                continue
            if "Enter a command" in stripped:
                continue
            return stripped == ":"
        return False


def parse_status_owner(rows: Grid) -> str | None:
    """Extract the trailing status-bar label from SoftICE's command footer."""
    with span("parser.parse_status_owner", rows=len(rows)):
        for row in reversed(rows):
            match = _STATUS_OWNER.search(row.rstrip())
            if match:
                return match.group("owner")
        return None


# ---- register pane (rows 0..2 in default layout) ----------------------

_REG_PAIR = re.compile(r"\b([A-Za-z]{2,3})=([0-9A-Fa-f]+)\b")
_FLAG_TOKEN = re.compile(r"\b(OF|DF|IF|TF|SF|ZF|AF|PF|CF|RF|NT|VM|AC|VIF|VIP|ID)\b")


def parse_register_dump(rows: Grid) -> dict[str, Any]:
    """Extract register values + flag bits from the Register pane (top 3 rows).

    Falls back with ``parse_error: "no_register_pane"`` if the pane isn't
    painted (e.g. SoftICE not popped in).
    """
    with span("parser.parse_register_dump", rows=len(rows)):
        if not rows or "EAX=" not in rows[0]:
            return {"parsed": None, "parse_error": "no_register_pane", "rows": list(rows[:3])}

        regs: dict[str, int] = {}
        flags: dict[str, bool] = {}
        pane = rows[:3]
        for line in pane:
            for name, value in _REG_PAIR.findall(line):
                try:
                    regs[name.upper()] = int(value, 16)
                except ValueError:
                    continue
            for token in _FLAG_TOKEN.findall(line):
                flags[token.upper()] = True

        return {
            "parsed": {"registers": regs, "flags_set": sorted(flags.keys())},
            "parse_error": None,
            "rows": pane,
        }


# ---- expression evaluator ( ? expr ) ----------------------------------

_EVAL_LINE = re.compile(
    r"""
    \s*
    (?P<hex>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)
    \s+
    (?P<dec>-?\d+)
    (?:\s+\"(?P<ascii>.*?)\")?
    """,
    re.VERBOSE,
)


def parse_eval_result(command_rows: CommandRows) -> dict[str, Any]:
    with span("parser.parse_eval_result", rows=len(command_rows)):
        for line in command_rows:
            m = _EVAL_LINE.match(line)
            if not m:
                continue
            hex_str = m.group("hex")
            try:
                hex_val = int(hex_str, 16)
            except ValueError:
                continue
            try:
                dec_val = int(m.group("dec"))
            except (TypeError, ValueError):
                dec_val = None
            return {
                "parsed": {
                    "hex": hex_val,
                    "dec": dec_val,
                    "ascii": m.group("ascii") or "",
                },
                "parse_error": None,
                "rows": list(command_rows),
            }
        return {"parsed": None, "parse_error": "no_eval_row", "rows": list(command_rows)}


# ---- memory dump ( D / DB / DW / DD ) ---------------------------------

_DUMP_LINE = re.compile(
    r"""
    ^\s*
    (?P<addr>(?:[0-9A-Fa-f]+:)?[0-9A-Fa-f]+)
    \s+
    (?P<hex>(?:[0-9A-Fa-f]{2,8}[\s-]+){1,16}[0-9A-Fa-f]{2,8})
    (?:\s{2,}(?P<ascii>.{1,16}))?
    \s*$
    """,
    re.VERBOSE,
)


def _hex_to_bytes(hex_blob: str) -> list[int]:
    """'89 E5 56-57 8B-75' → [0x89, 0xE5, 0x56, 0x57, 0x8B, 0x75]."""
    tokens = re.split(r"[\s-]+", hex_blob.strip())
    out: list[int] = []
    for tok in tokens:
        if not tok:
            continue
        if len(tok) % 2 != 0:
            return out
        try:
            out.extend(int(tok[i : i + 2], 16) for i in range(0, len(tok), 2))
        except ValueError:
            return out
    return out


def parse_memory_dump(command_rows: CommandRows) -> dict[str, Any]:
    with span("parser.parse_memory_dump", rows=len(command_rows)):
        lines: list[dict[str, Any]] = []
        all_bytes: list[int] = []
        first_addr: int | None = None
        for row in command_rows:
            m = _DUMP_LINE.match(row)
            if not m:
                continue
            raw_addr = m.group("addr")
            linear = raw_addr.split(":")[-1]
            try:
                addr = int(linear, 16)
            except ValueError:
                continue
            data = _hex_to_bytes(m.group("hex"))
            if not data:
                continue
            if first_addr is None:
                first_addr = addr
            lines.append(
                {
                    "address": addr,
                    "seg_offset": raw_addr,
                    "bytes": data,
                    "ascii": (m.group("ascii") or "").rstrip(),
                }
            )
            all_bytes.extend(data)
        if not lines:
            return {"parsed": None, "parse_error": "no_dump_rows", "rows": list(command_rows)}
        return {
            "parsed": {
                "address": first_addr,
                "bytes": all_bytes,
                "hex": " ".join(f"{b:02X}" for b in all_bytes),
                "lines": lines,
            },
            "parse_error": None,
            "rows": list(command_rows),
        }


# ---- disassembly ( U ) -------------------------------------------------

_DISASM_LINE = re.compile(
    r"""
    ^\s*
    (?P<addr>(?:[0-9A-Fa-f]+:)?[0-9A-Fa-f]+)
    \s+
    (?:(?P<bytes>[0-9A-Fa-f]{2}(?:[\s-]*[0-9A-Fa-f]{2})*)\s{2,})?
    (?P<mnemonic>[A-Za-z][A-Za-z0-9]*)
    (?:\s+(?P<operands>.+?))?
    \s*$
    """,
    re.VERBOSE,
)


def _split_operands_annotation(operands: str) -> tuple[str, str]:
    """Split operand text from SoftICE's trailing hint.

    SoftICE annotates conditional jumps (``(JUMP)`` / ``(NO JUMP)``) and
    current-EIP memory refs (``DS:00401234=DEADBEEF``) at a fixed rightmost
    column, separated from the real operands by a run of spaces. x86 operand
    syntax only uses single spaces (``DWORD PTR [ESP]``), so a 2+-space gap
    reliably marks the hint boundary.
    """
    parts = re.split(r"\s{2,}", operands.strip(), maxsplit=1)
    if len(parts) == 1:
        return parts[0], ""
    return parts[0].strip(), parts[1].strip()


def parse_disasm(command_rows: CommandRows) -> dict[str, Any]:
    with span("parser.parse_disasm", rows=len(command_rows)):
        out: list[dict[str, Any]] = []
        for row in command_rows:
            m = _DISASM_LINE.match(row)
            if not m:
                continue
            raw_addr = m.group("addr")
            linear = raw_addr.split(":")[-1]
            try:
                addr = int(linear, 16)
            except ValueError:
                continue
            operands, annotation = _split_operands_annotation(m.group("operands") or "")
            out.append(
                {
                    "address": addr,
                    "seg_offset": raw_addr,
                    "bytes": (m.group("bytes") or "").strip(),
                    "mnemonic": m.group("mnemonic").upper(),
                    "operands": operands,
                    "annotation": annotation,
                }
            )
        if not out:
            return {"parsed": None, "parse_error": "no_instructions", "rows": list(command_rows)}
        return {
            "parsed": {"instructions": out},
            "parse_error": None,
            "rows": list(command_rows),
        }


# ---- breakpoint list ( BL ) -------------------------------------------

_BL_LINE = re.compile(
    r"""
    ^\s*
    (?P<index>[0-9A-Fa-f]{1,2})
    \)\s*
    (?P<disabled>\*\s+)?
    (?P<kind>BPX|BPMB|BPMW|BPMD|BPM|BPIO|BPINT|BMSG)
    \s*
    (?P<rest>.*?)
    \s*$
    """,
    re.VERBOSE,
)


def parse_breakpoint_list(command_rows: CommandRows) -> dict[str, Any]:
    with span("parser.parse_breakpoint_list", rows=len(command_rows)):
        out: list[dict[str, Any]] = []
        for row in command_rows:
            m = _BL_LINE.match(row)
            if not m:
                continue
            rest = m.group("rest")
            condition = ""
            action = ""
            if_idx = rest.upper().find(" IF ")
            do_idx = rest.upper().find(" DO ")
            head = rest
            if if_idx >= 0:
                head = rest[:if_idx]
                tail = rest[if_idx + 4 :]
                if do_idx > if_idx:
                    cut = do_idx - if_idx - 4
                    condition = tail[:cut].strip()
                    action = tail[cut + 4 :].strip().strip('"')
                else:
                    condition = tail.strip()
            elif do_idx >= 0:
                head = rest[:do_idx]
                action = rest[do_idx + 4 :].strip().strip('"')
            out.append(
                {
                    "index": int(m.group("index"), 16),
                    "enabled": not bool(m.group("disabled")),
                    "kind": m.group("kind").upper(),
                    "target": head.strip(),
                    "condition": condition,
                    "action": action,
                }
            )
        if not out:
            return {"parsed": None, "parse_error": "no_breakpoints", "rows": list(command_rows)}
        return {
            "parsed": {"breakpoints": out},
            "parse_error": None,
            "rows": list(command_rows),
        }


# ---- address contexts ( ADDR ) ----------------------------------------


def parse_addr_table(
    command_rows: CommandRows,
    command_rows_bold: list[bool] | None = None,
    status_owner: str | None = None,
) -> dict[str, Any]:
    # SoftICE bolds the active row in the ADDR table and only that row.
    # `command_rows_bold[i]` should line up with `command_rows[i]`; when it's
    # missing we just can't identify the active context and everything comes
    # back `active=False, current=None`.
    with span("parser.parse_addr_table", rows=len(command_rows)):
        bold = command_rows_bold or []
        contexts: list[dict[str, Any]] = []
        current: str | None = None
        header_seen = False
        for i, row in enumerate(command_rows):
            stripped = row.strip()
            if not stripped:
                continue
            if not header_seen and ("Handle" in row or "Owner" in row):
                header_seen = True
                continue
            parts = stripped.split()
            if len(parts) < 2:
                continue
            try:
                handle = int(parts[0], 16)
            except ValueError:
                continue
            active = bool(bold[i]) if i < len(bold) else False
            owner = parts[-1]
            if re.fullmatch(r"[0-9A-Fa-f]{6,8}", owner or ""):
                if status_owner:
                    owner = status_owner
                    active = True
                else:
                    continue
            contexts.append(
                {"handle": handle, "owner": owner, "active": active, "raw": stripped}
            )
            if active and current is None:
                current = owner
        if status_owner:
            for ctx in contexts:
                if str(ctx.get("owner") or "").casefold() == status_owner.casefold():
                    for other in contexts:
                        other["active"] = False
                    ctx["active"] = True
                    current = str(ctx["owner"])
                    break
            else:
                current = status_owner
        if contexts and current is None:
            # SoftICE documents that the first listed context is the current
            # one. When bold metadata is unavailable or noisy, fall back to
            # that ordering instead of reporting an unknown current context.
            contexts[0]["active"] = True
            current = contexts[0]["owner"]
        if not contexts:
            return {"parsed": None, "parse_error": "no_contexts", "rows": list(command_rows)}
        return {
            "parsed": {"contexts": contexts, "current": current},
            "parse_error": None,
            "rows": list(command_rows),
        }


# ---- modules ( MOD ) --------------------------------------------------


def parse_mod_table(command_rows: CommandRows) -> dict[str, Any]:
    with span("parser.parse_mod_table", rows=len(command_rows)):
        modules: list[dict[str, Any]] = []
        header_seen = False
        for row in command_rows:
            if not row.strip():
                continue
            if not header_seen and (row.strip().lower().startswith("hmod") or "ModuleName" in row):
                header_seen = True
                continue
            parts = row.split()
            if len(parts) < 3:
                continue
            try:
                hmod = int(parts[0], 16)
                base = int(parts[1], 16)
            except ValueError:
                continue
            pe_header: int | None = None
            name_idx = 2
            if len(parts) >= 4:
                try:
                    pe_header = int(parts[2], 16)
                    name_idx = 3
                except ValueError:
                    pe_header = None
            if name_idx >= len(parts):
                continue
            name = parts[name_idx]
            path = " ".join(parts[name_idx + 1 :]) if name_idx + 1 < len(parts) else ""
            modules.append(
                {
                    "hmod": hmod,
                    "base": base,
                    "pe_header": pe_header,
                    "name": name,
                    "path": path,
                }
            )
        if not modules:
            return {"parsed": None, "parse_error": "no_modules", "rows": list(command_rows)}
        return {"parsed": {"modules": modules}, "parse_error": None, "rows": list(command_rows)}
