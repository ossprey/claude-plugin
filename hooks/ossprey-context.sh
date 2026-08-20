#!/bin/sh
# SessionStart hook: inject rules/ossprey.md as session context. This is the
# stand-in for Cursor's alwaysApply rule — a plugin cannot append to
# CLAUDE.md, so the guidance is handed to the session at start.
DIR="${CLAUDE_PLUGIN_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
PY="$(command -v python3 || command -v python || true)"
[ -z "$PY" ] && exit 0
exec "$PY" "$DIR/hooks/ossprey_hook.py" context
