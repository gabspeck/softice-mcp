# softice-mcp

An MCP server that drives SoftICE 3.x (running inside a Win95 86Box VM) over
a VT100 serial PTY bridge, filters the debugger's multi-pane chrome out of
command output, and exposes a set of structured tools to the Claude Code LLM.

## Prerequisites

1. 86Box VM running Windows 95 with SoftICE configured for serial VT100:
   ```
   SERIAL ON 1 115200
   DISPLAY VT100
   ```
2. 86Box COM1 passthrough wired to a host-side PTY via the bridge script:
   ```
   ./start_softice_bridge.sh
   ```
   This creates `/tmp/softice_guest` (used by 86Box) and `/tmp/softice_host`
   (used by this MCP).

## Install

```
git clone https://github.com/gabspeck/softice-mcp.git
cd softice-mcp
uv venv
uv pip install -e .
```

## Register in `~/.claude.json`

Under the relevant project's `mcpServers`:

```json
"softice": {
  "type": "stdio",
  "command": "/path/to/softice-mcp/.venv/bin/python3",
  "args": ["/path/to/softice-mcp/mcp_server.py"]
}
```

The server is connection-less at startup. The MCP client must call the
`connect` tool with the PTY path (typically `/tmp/softice_host`) before any
other tool. `disconnect` closes the PTY and clears the path — a fresh
`connect` is required to resume.

## Smoke test

With the VM running and SoftICE popped out:

```
./.venv/bin/python3 mcp_server.py --self-test /tmp/softice_host
```

## Tool surface

Session / raw: `popup`, `resume`, `wait_for_popup`, `disconnect`, `screen`, `raw_cmd`, `send_keys`.
Flow control: `step`, `step_over`, `go_until`.
Inspection: `registers`, `read_memory`, `disassemble`, `eval_expr`,
`addr_context`, `module_info`.
Breakpoints: `bp_set`, `bp_list`, `bp_mutate`.

Structured tools auto-pop SoftICE (Ctrl-D) on demand, so `popup` is only
needed when you want to break in without issuing a command. `resume` stays
explicit — always call it before ending your turn.

`wait_for_popup` is the polling-based way to block until SoftICE pops back in,
usually because a breakpoint hit while the VM was running. The recommended
pattern is: `bp_set`, `resume`, `wait_for_popup`, inspect with typed tools,
then `resume` again. It does not emit unsolicited MCP notifications.

`raw_cmd` and `send_keys` are escape hatches. `raw_cmd` runs an arbitrary
SoftICE command line; `send_keys` writes raw bytes (arrow keys, ESC, function
keys, chained Ctrl-sequences). Both bypass the typed tools' parsing and
discipline — prefer a typed tool when one fits.

## Discipline

Three rules baked into the tool descriptions:

1. For user-range breakpoint addresses (`0x00400000`–`0x7FFFFFFF`) pass
   `context` to `bp_set` — the tool issues `ADDR <proc>` as its own command
   before `BPX` (the `ADDR x; BPX y` compound is rejected by SoftICE 3.x
   with `Invalid Context Handle`). Skipping `context` arms the BP against
   whatever page table happens to be current.
2. Always call `resume` before ending a turn. Leaving SoftICE popped freezes
   the VM for the next user interaction.
3. Before reaching for `raw_cmd` or `send_keys`, state in one sentence why
   the typed tool doesn't fit. These escape hatches skip structured parsing
   and the discipline enforced by `bp_set`, `addr_context`, `step`, etc. —
   use them for SoftICE commands without a wrapper (WHAT, BSTAT, TABLE) or
   byte-level input (BH arrow-key navigation, pager dismissal), not as a
   shortcut around typed tools.
