#!/bin/sh
# PostToolUse (Write|Edit|MultiEdit|NotebookEdit) hook: background-scan the
# project when a dependency manifest changes. Fire-and-forget; no output.
DIR="${CLAUDE_PLUGIN_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
PY="$(command -v python3 || command -v python || true)"
[ -z "$PY" ] && exit 0
exec "$PY" "$DIR/hooks/ossprey_hook.py" audit
