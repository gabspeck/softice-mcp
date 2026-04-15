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

Session / raw: `popup`, `resume`, `disconnect`, `screen`, `raw_cmd`, `send_keys`.
Flow control: `step`, `step_over`, `go_until`.
Inspection: `registers`, `read_memory`, `disassemble`, `eval_expr`,
`addr_context`, `module_info`.
Breakpoints: `bp_set`, `bp_list`, `bp_mutate`.

`send_keys` is the unconditional byte-level escape hatch — use it for anything
the typed tools don't cover (arrow-key navigation, pager dismissal, function
keys, chained Ctrl-sequences).

## Discipline

Two rules baked into the tool descriptions:

1. For user-range breakpoint addresses (`0x00400000`–`0x7FFFFFFF`) pass
   `context` to `bp_set` so the composer emits `ADDR <proc>; BPX …` on one
   line — skipping this arms BPs against the wrong page table silently.
2. Always call `resume` before ending a turn. Leaving SoftICE popped freezes
   the VM for the next user interaction.
