#!/usr/bin/env bash
# Legacy helper for the old socat-based PTY bridge.
# Preferred setup now uses 86Box's Named Pipe / UNIX FIFO backend directly.
set -euo pipefail

guest_link="${1:-/tmp/softice_guest}"
host_link="${2:-/tmp/softice_host}"

rm -f "$guest_link" "$host_link"

exec socat -d -d -x -v \
  PTY,link="$guest_link",rawer,echo=0 \
  PTY,link="$host_link",rawer,echo=0
