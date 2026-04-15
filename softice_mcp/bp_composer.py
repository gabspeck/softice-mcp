"""Build a SoftICE breakpoint command line from structured arguments.

Covers BPX (execution), BPM[size] (memory with size+verb), BPIO (I/O port
R/W/RW), and BPINT (interrupt number). Supports the IF/DO suffix shared by
all four, and an optional ``context`` that prepends ``ADDR <proc>;`` so the
breakpoint arms in the correct address space (see feedback_softice_addr_before_bpx).

Refusal / validation:
- ``actions`` are joined with ``;`` inside ``DO "..."``. Raw double-quotes or
  newlines in any action are rejected rather than silently corrupting the
  wire format (SoftICE's DO-string escaping is under-documented, so we stay
  on the safe side).
- BPM requires ``size`` (b/w/d) and ``verb`` (r/w/rw/x).
- BPIO requires ``port`` (int) and ``verb`` (r/w/rw).
- BPINT requires ``intno`` (int).
"""

from __future__ import annotations

from collections.abc import Iterable

VALID_KINDS = {"bpx", "bpm", "bpio", "bpint"}
VALID_BPM_SIZES = {"b", "w", "d"}
VALID_BPM_VERBS = {"r", "w", "rw", "x"}
VALID_BPIO_VERBS = {"r", "w", "rw"}


def format_address(value: int | str) -> str:
    """Render an address the way SoftICE wants.

    Integers → uppercase hex without ``0x`` prefix (``401234`` not ``0x401234``).
    Strings pass through unchanged so callers can use ``MODULE!symbol``,
    ``cs:eip``, or decimal as needed.
    """
    if isinstance(value, bool):
        raise ValueError("address must be an int or string, not bool")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("address must be non-negative")
        return f"{value:X}"
    if isinstance(value, str):
        s = value.strip()
        if not s:
            raise ValueError("address string must be non-empty")
        if "\n" in s or "\r" in s:
            raise ValueError("address string must not contain newlines")
        return s
    raise ValueError(f"address must be int or str, got {type(value).__name__}")


def _format_actions(actions: Iterable[str] | None) -> str:
    if not actions:
        return ""
    parts: list[str] = []
    for idx, act in enumerate(actions):
        if not isinstance(act, str):
            raise ValueError(f"action[{idx}] must be a string")
        if '"' in act:
            raise ValueError(f"action[{idx}] must not contain raw double-quotes")
        if "\n" in act or "\r" in act:
            raise ValueError(f"action[{idx}] must not contain newlines")
        stripped = act.strip()
        if not stripped:
            raise ValueError(f"action[{idx}] must be non-empty")
        parts.append(stripped)
    return f' DO "{";".join(parts)}"'


def _format_condition(condition: str | None) -> str:
    if condition is None:
        return ""
    if not isinstance(condition, str):
        raise ValueError("condition must be a string")
    cond = condition.strip()
    if not cond:
        return ""
    if "\n" in cond or "\r" in cond:
        raise ValueError("condition must not contain newlines")
    return f" IF ({cond})" if not (cond.startswith("(") and cond.endswith(")")) else f" IF {cond}"


def _prefix_context(context: str | None) -> str:
    if context is None:
        return ""
    if not isinstance(context, str) or not context.strip():
        raise ValueError("context must be a non-empty string")
    ctx = context.strip()
    if any(c in ctx for c in ";\n\r\""):
        raise ValueError("context must not contain separators or quotes")
    return f"ADDR {ctx}; "


def compose_bp(
    kind: str,
    address: int | str | None = None,
    *,
    size: str | None = None,
    verb: str | None = None,
    port: int | None = None,
    intno: int | None = None,
    condition: str | None = None,
    actions: Iterable[str] | None = None,
    context: str | None = None,
) -> str:
    k = kind.lower().strip()
    if k not in VALID_KINDS:
        raise ValueError(f"kind must be one of {sorted(VALID_KINDS)}, got {kind!r}")

    prefix = _prefix_context(context)
    suffix = _format_condition(condition) + _format_actions(actions)

    if k == "bpx":
        if address is None:
            raise ValueError("bpx requires address")
        return f"{prefix}BPX {format_address(address)}{suffix}"

    if k == "bpm":
        if address is None:
            raise ValueError("bpm requires address")
        if size is None or size.lower() not in VALID_BPM_SIZES:
            raise ValueError(f"bpm requires size in {sorted(VALID_BPM_SIZES)}")
        if verb is None or verb.lower() not in VALID_BPM_VERBS:
            raise ValueError(f"bpm requires verb in {sorted(VALID_BPM_VERBS)}")
        return (
            f"{prefix}BPM{size.upper()} {format_address(address)} {verb.upper()}{suffix}"
        )

    if k == "bpio":
        if port is None:
            raise ValueError("bpio requires port")
        if not isinstance(port, int) or isinstance(port, bool) or port < 0 or port > 0xFFFF:
            raise ValueError("bpio port must be an int in [0, 0xFFFF]")
        if verb is None or verb.lower() not in VALID_BPIO_VERBS:
            raise ValueError(f"bpio requires verb in {sorted(VALID_BPIO_VERBS)}")
        return f"{prefix}BPIO {port:X} {verb.upper()}{suffix}"

    # bpint
    if intno is None:
        raise ValueError("bpint requires intno")
    if not isinstance(intno, int) or isinstance(intno, bool) or intno < 0 or intno > 0xFF:
        raise ValueError("bpint intno must be an int in [0, 0xFF]")
    return f"{prefix}BPINT {intno:X}{suffix}"


def compose_bp_mutate(op: str, index: int | str) -> str:
    """BC / BD / BE commands. ``index`` may be an int or '*' for all."""
    op_lower = op.lower().strip()
    if op_lower not in {"clear", "enable", "disable"}:
        raise ValueError("op must be clear|enable|disable")
    cmd = {"clear": "BC", "enable": "BE", "disable": "BD"}[op_lower]
    if isinstance(index, str):
        if index.strip() != "*":
            raise ValueError("index must be an int or '*'")
        return f"{cmd} *"
    if isinstance(index, bool) or not isinstance(index, int):
        raise ValueError("index must be an int or '*'")
    if index < 0:
        raise ValueError("index must be non-negative")
    return f"{cmd} {index}"
