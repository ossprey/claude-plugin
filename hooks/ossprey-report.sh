#!/bin/sh
# Stop hook: if background manifest scans found malware, block the stop so
# the agent remediates before the session ends.
DIR="${CLAUDE_PLUGIN_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
PY="$(command -v python3 || command -v python || true)"
[ -z "$PY" ] && exit 0
exec "$PY" "$DIR/hooks/ossprey_hook.py" report
