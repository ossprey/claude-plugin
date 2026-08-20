#!/bin/sh
# PreToolUse (Bash) hook: check install commands with Ossprey before they
# run. Fails open (stays out of the way) if python3 is unavailable.
DIR="${CLAUDE_PLUGIN_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  printf '{"additionalContext":"Ossprey hook skipped: python3 not found, install was NOT checked for malware.","systemMessage":"Ossprey: python3 not found; install not checked for malware."}'
  exit 0
fi
exec "$PY" "$DIR/hooks/ossprey_hook.py" guard
