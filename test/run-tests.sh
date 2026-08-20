#!/bin/sh
# End-to-end tests for the Ossprey Claude Code hooks. No Claude Code and no
# network needed: hook scripts are fed the same JSON payloads Claude Code
# sends on stdin, and the Ossprey CLI is replaced with test/mock/ossprey
# (drive it with MOCK_MODE). Run:  sh test/run-tests.sh
set -u

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
GUARD="$ROOT/hooks/ossprey-guard.sh"
AUDIT="$ROOT/hooks/ossprey-audit.sh"
REPORT="$ROOT/hooks/ossprey-report.sh"
CONTEXT="$ROOT/hooks/ossprey-context.sh"
MOCK="$ROOT/test/mock/ossprey"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export CLAUDE_PLUGIN_ROOT="$ROOT"
export OSSPREY_BIN="$MOCK"
export XDG_CONFIG_HOME="$WORK/xdg-isolated"  # never read the real user config
unset OSSPREY_API_KEY OSSPREY_CONFIG_DIR
export OSSPREY_HOOK_STATE_DIR="$WORK/state"
export OSSPREY_HOOK_DEBOUNCE=0
export MOCK_LOG="$WORK/mock.log"

PASS=0; FAIL=0

reset() { : > "$MOCK_LOG"; }

json_str() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"; }

# run_guard <mode> <shell-command> -> stdout of hook
run_guard() {
  printf '{"session_id":"sess-1","cwd":"/tmp/proj","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command": %s}}' "$(json_str "$2")" \
    | MOCK_MODE="$1" sh "$GUARD"
}

# run_guard_rc <mode> <shell-command> -> exit status of hook
run_guard_rc() {
  printf '{"session_id":"sess-1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command": %s}}' "$(json_str "$2")" \
    | MOCK_MODE="$1" sh "$GUARD" >/dev/null 2>&1
  echo $?
}

# run_report <session-id> [extra-json] -> "stderr<TAB>exit"
run_report() {
  extra="${2:-}"
  out="$(printf '{"session_id":"%s","hook_event_name":"Stop"%s}' "$1" "$extra" \
    | sh "$REPORT" 2>&1)"
  rc=$?
  printf '%s\nexit=%s' "$out" "$rc"
}

check() { # check <name> <haystack> <needle>
  case "$2" in
    *"$3"*) PASS=$((PASS+1)); echo "PASS: $1" ;;
    *) FAIL=$((FAIL+1)); echo "FAIL: $1"; echo "  wanted: $3"; echo "  got:    $2" ;;
  esac
}

check_absent() { # check_absent <name> <haystack> <needle>
  case "$2" in
    *"$3"*) FAIL=$((FAIL+1)); echo "FAIL: $1 (found '$3')"; echo "  got: $2" ;;
    *) PASS=$((PASS+1)); echo "PASS: $1" ;;
  esac
}

echo "== PreToolUse (guard): routing through the forwarder =="

# The guard does not reach a verdict — it rewrites the command so the Ossprey
# CLI's forwarder does the checking inside its own process, before the real
# package manager runs. So these assert on the rewritten command, and that the
# guard ran nothing at all.
#
# The suite points OSSPREY_BIN at the mock, and an explicit OSSPREY_BIN is
# honoured verbatim in the rewrite, so that path is what the commands call.
OSSP="$MOCK"

reset
OUT=$(run_guard safe "npm install left-pad")
check "an install is routed through the forwarder" "$OUT" "\"command\": \"$OSSP npm install left-pad\""
check "the rewrite is reported to the agent" "$OUT" "ossprey npm"
check "the guard runs no CLI of its own" "$(cat "$MOCK_LOG")x" "x"
# Rewriting a command is not a reason to grant it permission: the user's own
# rules still decide, they just see the wrapped command.
check_absent "the guard renders no permission decision" "$OUT" "permissionDecision"
check "the rewrite names the right event" "$OUT" '"hookEventName": "PreToolUse"'

# Every install form the forwarder handles, routed without the hook needing to
# know which of them are installs — that is the CLI's job.
for CMD in "npm install" "npm ci" "npm i left-pad" "npm add left-pad" \
           "npm update" "pnpm install" "pnpm add -w left-pad" "yarn install" \
           "yarn add left-pad" "yarn upgrade" "poetry install" "poetry lock" \
           "poetry add requests" "pip install requests" \
           "pip install -r requirements.txt" "pip3 install requests" \
           "uv sync" "uv add httpx" "uv pip install flask"
do
  reset
  OUT=$(run_guard safe "$CMD")
  check "\`$CMD\` is routed through the forwarder" "$OUT" "$OSSP $CMD"
done

echo "== PreToolUse (guard): the rewrite preserves the command =="

reset
OUT=$(run_guard safe "cd api && npm ci")
check "a leading cd is left alone" "$OUT" "\"command\": \"cd api && $OSSP npm ci\""

reset
OUT=$(run_guard safe "npm install a && npm test")
check "every manager invocation is routed" "$OUT" "$OSSP npm install a && $OSSP npm test"

reset
OUT=$(run_guard safe "sudo pip install requests")
check "ossprey is inserted after sudo" "$OUT" "sudo $OSSP pip install requests"

reset
OUT=$(run_guard safe "CI=1 npm ci")
check "ossprey is inserted after env assignments" "$OUT" "CI=1 $OSSP npm ci"

reset
OUT=$(run_guard safe "if npm ci; then echo ok; fi")
check "ossprey is inserted after a shell keyword" "$OUT" "if $OSSP npm ci; then echo ok; fi"

reset
OUT=$(run_guard safe "npm install x > out.log 2>&1")
check "redirections are preserved" "$OUT" "$OSSP npm install x > out.log 2>&1"

reset
OUT=$(run_guard safe "npm install 'c d' --foo=bar")
check "quoting is preserved byte for byte" "$OUT" "$OSSP npm install 'c d' --foo=bar"

# Separators without surrounding spaces, and newlines, must still start a new
# command. A shlex-based parser missed both: it drops newlines and leaves `;`
# stuck to its neighbour, so the second install went unrouted.
reset
OUT=$(run_guard safe "npm i a;npm i b")
check "an unspaced semicolon starts a new command" "$OUT" "$OSSP npm i a;$OSSP npm i b"

reset
OUT=$(run_guard safe "npm i a&&npm i b")
check "an unspaced && starts a new command" "$OUT" "$OSSP npm i a&&$OSSP npm i b"

reset
# json_str escapes the newline properly; a raw one inside a JSON string would
# make the payload unparseable, which the hook treats as "no command".
NL_CMD="$(printf 'cd api\nnpm install evil')"
OUT=$(run_guard safe "$NL_CMD")
check "an install on the next line is routed" "$OUT" "$OSSP npm install evil"

# updatedInput replaces the entire input object, so dropping a field would
# silently change how the command runs.
reset
OUT=$(printf '{"session_id":"s","cwd":"/tmp/proj","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm ci","description":"install deps","timeout":120000,"run_in_background":false}}' \
  | MOCK_MODE=safe sh "$GUARD")
check "other tool_input fields survive the rewrite" "$OUT" '"description": "install deps"'
check "the timeout survives the rewrite" "$OUT" '"timeout": 120000'
check "run_in_background survives the rewrite" "$OUT" '"run_in_background": false'

# A rewritten command prefers the bare name whenever `ossprey` resolves on
# PATH — readable, and it picks up a `ossprey shim install` shim. The absolute
# path is the fallback for a CLI that is not on PATH at all.
reset
FAKEBIN="$WORK/fakebin"
mkdir -p "$FAKEBIN"
printf '#!/bin/sh\nexit 0\n' > "$FAKEBIN/ossprey"
chmod +x "$FAKEBIN/ossprey"
OUT=$(printf '{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm ci"}}' \
  | (unset OSSPREY_BIN; PATH="$FAKEBIN:$PATH" sh "$GUARD"))
check "a PATH-resolved CLI is called by bare name" "$OUT" '"command": "ossprey npm ci"'

OUT=$(printf '{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm ci"}}' \
  | PATH="$FAKEBIN:$PATH" sh "$GUARD")
check "the bare name wins over OSSPREY_BIN when it resolves" "$OUT" '"command": "ossprey npm ci"'

echo "== PreToolUse (guard): commands left alone =="

reset
OUT=$(run_guard safe "ls -la && git status")
check "a non-manager command exits 0" "$(run_guard_rc safe 'ls -la && git status')" "0"
check_absent "a non-manager command gets no rewrite" "$OUT" "updatedInput"

reset
OUT=$(run_guard safe "ossprey npm install evil-pkg")
check_absent "an already-wrapped install is not double-wrapped" "$OUT" "updatedInput"

reset
OUT=$(run_guard safe "echo npm install")
check_absent "a manager named mid-command is not a command head" "$OUT" "updatedInput"

reset
OUT=$(run_guard safe "git commit -m \"npm install\"")
check_absent "a manager inside a quoted string is left alone" "$OUT" "updatedInput"

echo "== PreToolUse (guard): what cannot be routed is reported =="

# `ossprey <bin>` exists only for the managers the CLI forwards. Wrapping
# anything else would fail with "unknown command", so these are left alone —
# and said out loud rather than passed off as covered.
reset
OUT=$(run_guard safe "bun add left-pad")
check_absent "bun is not wrapped" "$OUT" "updatedInput"
check "bun is reported as unchecked" "$OUT" "no \`ossprey bun\` forwarder"

reset
OUT=$(run_guard safe "pipenv install")
check "pipenv is reported as unchecked" "$OUT" "no \`ossprey pipenv\` forwarder"

reset
OUT=$(run_guard safe "python3 -m pip install requests")
check_absent "python -m pip is not rewritten" "$OUT" "updatedInput"
check "python -m pip is reported as unchecked" "$OUT" "which interpreter installs"

reset
OUT=$(run_guard safe "/usr/local/bin/npm install x")
check_absent "a path-qualified manager is not rewritten" "$OUT" "updatedInput"
check "a path-qualified manager is reported as unchecked" "$OUT" "invoked by full path"

echo "== PreToolUse (guard): fail-open =="

# Rewriting to a CLI that is not installed would turn a working install into
# "ossprey: command not found", so a missing CLI means no rewrite at all.
reset
OUT=$( (OSSPREY_BIN="$WORK/does-not-exist"; export OSSPREY_BIN; run_guard safe "npm install some-pkg") )
check "missing CLI fails open with a warning" "$OUT" "Ossprey CLI not found"
check_absent "missing CLI does not rewrite the command" "$OUT" "updatedInput"
check "missing CLI is flagged to the user" "$OUT" "systemMessage"

reset
OUT=$( (OSSPREY_BIN="$WORK/does-not-exist"; export OSSPREY_BIN; run_guard safe "npm ci") )
check "missing CLI fails open on a manifest install too" "$OUT" "Ossprey CLI not found"


echo "== PostToolUse (audit) + Stop (report) =="

reset
mkdir -p "$WORK/proj"
PAYLOAD=$(printf '{"session_id":"sess-a","hook_event_name":"PostToolUse","tool_name":"Edit","tool_input":{"file_path":"%s/proj/package.json"}}' "$WORK")
echo "$PAYLOAD" | MOCK_MODE=malware sh "$AUDIT"
sleep 1  # background scan
check "manifest edit triggers a scan" "$(cat "$MOCK_LOG")" "scan $WORK/proj"

OUT=$(run_report sess-a)
check "stop blocks on malware findings" "$OUT" "exit=2"
check "stop feedback lists the finding" "$OUT" "contains malware"

OUT=$(run_report sess-a)
check "findings not repeated once reported" "$OUT" "exit=0"

reset
echo '{"session_id":"sess-b","hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{"file_path":"/tmp/proj/src/main.py"}}' \
  | MOCK_MODE=malware sh "$AUDIT"
sleep 1
check "non-manifest edit does not scan" "$(cat "$MOCK_LOG")x" "x"

OUT=$(run_report sess-clean)
check "clean session does not block the stop" "$OUT" "exit=0"

reset
PAYLOAD=$(printf '{"session_id":"sess-c","hook_event_name":"PostToolUse","tool_name":"Edit","tool_input":{"file_path":"%s/proj/package.json"}}' "$WORK")
echo "$PAYLOAD" | MOCK_MODE=auth sh "$AUDIT"
sleep 1  # background scan
OUT=$(run_report sess-c)
check "signed-out scan surfaces at stop" "$OUT" "exit=2"
check "stop feedback steers the agent to ossprey login" "$OUT" "ossprey login"
check_absent "signed-out scan is not reported as malware" "$OUT" "contains malware"

# stop_hook_active means Claude Code already forced one continuation; never
# block again off the back of it.
reset
PAYLOAD=$(printf '{"session_id":"sess-d","hook_event_name":"PostToolUse","tool_name":"Edit","tool_input":{"file_path":"%s/proj/package.json"}}' "$WORK")
echo "$PAYLOAD" | MOCK_MODE=malware sh "$AUDIT"
sleep 1
OUT=$(run_report sess-d ',"stop_hook_active":true')
check "stop_hook_active suppresses the block" "$OUT" "exit=0"

# The followup cap stops a session looping when the agent cannot remediate.
reset
OSSPREY_HOOK_MAX_FOLLOWUPS=1
export OSSPREY_HOOK_MAX_FOLLOWUPS
for i in 1 2; do
  PAYLOAD=$(printf '{"session_id":"sess-e","hook_event_name":"PostToolUse","tool_name":"Edit","tool_input":{"file_path":"%s/proj/package.json"}}' "$WORK")
  echo "$PAYLOAD" | MOCK_MODE=malware sh "$AUDIT"
  sleep 1
  eval "OUT$i=\$(run_report sess-e)"
done
check "first finding blocks the stop" "$OUT1" "exit=2"
check "followup cap releases the stop" "$OUT2" "exit=0"
unset OSSPREY_HOOK_MAX_FOLLOWUPS

echo "== SessionStart (context) =="

OUT=$(printf '{"session_id":"sess-f","hook_event_name":"SessionStart","source":"startup"}' | sh "$CONTEXT")
check "session start injects context" "$OUT" '"hookEventName": "SessionStart"'
check "context carries the rules" "$OUT" "Ossprey dependency safety"
# The guidance must NOT tell the agent to type the wrapper: the hook routes
# installs for it, and typing `ossprey` by hand fails where the CLI is not on
# PATH but OSSPREY_BIN is.
check "context says to install the normal way" "$OUT" "Install packages the normal way"
check_absent "context does not ask the agent to type the wrapper" "$OUT" "prefer wrapping the package manager"
check "context explains how a malware block reads" "$OUT" "contains malware"

echo "== config file fallback =="

# The hooks read ~/.config/ossprey/env so the API key (and any other knob) can
# be set once, instead of in the environment Claude Code inherits. The guard
# runs no CLI now, so the key is asserted where a CLI actually runs: the audit
# hook's background scan.
XDG="$WORK/xdg"
mkdir -p "$XDG/ossprey"
printf 'OSSPREY_API_KEY=test-key-123\n' > "$XDG/ossprey/env"

reset
PAYLOAD=$(printf '{"session_id":"sess-cfg","hook_event_name":"PostToolUse","tool_name":"Edit","tool_input":{"file_path":"%s/proj/package.json"}}' "$WORK")
echo "$PAYLOAD" | XDG_CONFIG_HOME="$XDG" MOCK_MODE=safe sh "$AUDIT"
sleep 1
check "CLI received the key from the config file" "$(cat "$MOCK_LOG")" "key=test-key-123"

reset
echo "$PAYLOAD" | XDG_CONFIG_HOME="$XDG" OSSPREY_API_KEY=env-key MOCK_MODE=safe sh "$AUDIT"
sleep 1
check "env var beats the config file" "$(cat "$MOCK_LOG")" "key=env-key"

# OSSPREY_BIN from the config file is honoured by the guard's rewrite.
XDGB="$WORK/xdg-bin"
mkdir -p "$XDGB/ossprey"
printf 'OSSPREY_BIN=%s\n' "$MOCK" > "$XDGB/ossprey/env"
OUT=$(printf '{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm ci"}}' \
  | (unset OSSPREY_BIN; XDG_CONFIG_HOME="$XDGB" sh "$GUARD"))
check "OSSPREY_BIN from the config file is used in the rewrite" "$OUT" "$MOCK npm ci"

echo "== manifests =="

check "plugin manifest names the plugin" "$(cat "$ROOT/.claude-plugin/plugin.json")" '"name": "ossprey"'
check "marketplace lists the plugin at the repo root" \
  "$(cat "$ROOT/.claude-plugin/marketplace.json")" '"source": "./"'
check "hook wiring uses the plugin root variable" \
  "$(cat "$ROOT/hooks/hooks.json")" 'CLAUDE_PLUGIN_ROOT'
check "no MCP server is registered" \
  "$([ -e "$ROOT/.mcp.json" ] && echo present || echo absent)" "absent"

for f in "$ROOT/.claude-plugin/plugin.json" "$ROOT/.claude-plugin/marketplace.json" \
         "$ROOT/hooks/hooks.json" "$ROOT/hooks/hooks.posix.json" \
         "$ROOT/hooks/hooks.windows.json"; do
  if python3 -m json.tool "$f" >/dev/null 2>&1; then
    PASS=$((PASS+1)); echo "PASS: $(basename "$f") is valid JSON"
  else
    FAIL=$((FAIL+1)); echo "FAIL: $(basename "$f") is not valid JSON"
  fi
done

# The active wiring must be a copy of one of the canonical files, both
# wirings must cover the same events, and every event must map to an
# entrypoint that exists.
python3 - "$ROOT" <<'WIRING'
import json, os, sys
root = sys.argv[1]
load = lambda n: json.load(open(os.path.join(root, "hooks", n)))
active, posix, win = load("hooks.json"), load("hooks.posix.json"), load("hooks.windows.json")
ok = True
if active != posix:
    print("FAIL: hooks.json is not the shipped POSIX wiring (hooks.posix.json)")
    ok = False
else:
    print("PASS: hooks.json is the shipped POSIX wiring")
if set(posix["hooks"]) != set(win["hooks"]):
    print("FAIL: hook wirings cover different events:",
          set(posix["hooks"]) ^ set(win["hooks"]))
    ok = False
else:
    print("PASS: both hook wirings cover the same events")
for name, wiring in (("posix", posix), ("windows", win)):
    for event, entries in wiring["hooks"].items():
        for entry in entries:
            for hook in entry["hooks"]:
                # "${CLAUDE_PLUGIN_ROOT}"/hooks/x.sh  or  "...\hooks\x.cmd" arg
                tail = hook["command"].split("}", 1)[-1].lstrip('"')
                rel = tail.split('"')[0].replace("\\", "/").strip("/")
                if not os.path.exists(os.path.join(root, rel)):
                    print(f"FAIL: {name} {event} entrypoint missing: {rel}")
                    ok = False
                else:
                    print(f"PASS: {name} {event} entrypoint exists ({rel})")
sys.exit(0 if ok else 1)
WIRING
if [ $? -eq 0 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi

echo "== install.sh =="

INSTALL="$ROOT/install.sh"
FAKEBIN="$WORK/bin"
mkdir -p "$FAKEBIN"
# Stand-in for the claude CLI: logs its argv, and fails the calls the real
# CLI fails (adding an already-registered marketplace) when asked to.
cat > "$FAKEBIN/claude" <<'MOCKEOF'
#!/bin/sh
printf '%s\n' "$*" >> "$CLAUDE_LOG"
case "$*" in
  *"marketplace add"*) [ -z "${CLAUDE_ADD_FAILS:-}" ] || exit 1 ;;
  *"plugin install"*) [ -z "${CLAUDE_INSTALL_FAILS:-}" ] || exit 1 ;;
esac
exit 0
MOCKEOF
chmod +x "$FAKEBIN/claude"
export CLAUDE_BIN="$FAKEBIN/claude"
CLAUDE_LOG="$WORK/claude.log"; export CLAUDE_LOG
: > "$CLAUDE_LOG"

OUT=$(sh "$INSTALL")
check "local install adds the checkout as a marketplace" "$(cat "$CLAUDE_LOG")" "marketplace add $ROOT"
check "local install installs the plugin" "$(cat "$CLAUDE_LOG")" "plugin install ossprey@ossprey"
check "local install says where it came from" "$OUT" "local checkout"
check "local install leaves the sh wiring active" \
  "$(cat "$ROOT/hooks/hooks.json")" "ossprey-guard.sh"

# The Windows wiring is reversible: applying it and re-running with the
# default style must restore the shipped hooks.json byte for byte.
cp "$ROOT/hooks/hooks.json" "$WORK/hooks.shipped.json"
OUT=$(OSSPREY_HOOKS_STYLE=windows sh "$INSTALL")
check "windows hook style applies the batch shim" \
  "$(cat "$ROOT/hooks/hooks.json")" "ossprey-hook.cmd"
OUT=$(sh "$INSTALL")
if cmp -s "$ROOT/hooks/hooks.json" "$WORK/hooks.shipped.json"; then
  PASS=$((PASS+1)); echo "PASS: re-running restores the shipped wiring"
else
  FAIL=$((FAIL+1)); echo "FAIL: re-running did not restore the shipped wiring"
fi

: > "$CLAUDE_LOG"
OUT=$(CLAUDE_ADD_FAILS=1 sh "$INSTALL")
check "re-install updates the registered marketplace" "$(cat "$CLAUDE_LOG")" "marketplace update ossprey"
check "re-install still reaches the plugin install" "$(cat "$CLAUDE_LOG")" "plugin install ossprey@ossprey"

: > "$CLAUDE_LOG"
OUT=$(CLAUDE_INSTALL_FAILS=1 sh "$INSTALL")
check "an already-installed plugin falls back to update" "$(cat "$CLAUDE_LOG")" "plugin update ossprey@ossprey"

OUT=$(sh "$INSTALL" --branch foo 2>&1)
check "--branch is rejected in local mode" "$OUT" "only applies to remote installs"

XDGI="$WORK/xdg-install"
OUT=$(XDG_CONFIG_HOME="$XDGI" HOME="$WORK/home" sh "$INSTALL" --key sk-test-456)
check "--key saves the key to the config file" "$(cat "$XDGI/ossprey/env")" "OSSPREY_API_KEY=sk-test-456"
check_absent "saved key silences the sign-in hint" "$OUT" "ossprey login"

OUT=$(XDG_CONFIG_HOME="$XDGI" HOME="$WORK/home" sh "$INSTALL" --key sk-rotated-789)
check "--key rotates the stored key" "$(cat "$XDGI/ossprey/env")" "OSSPREY_API_KEY=sk-rotated-789"
check_absent "old key gone from the config file" "$(cat "$XDGI/ossprey/env")" "sk-test-456"

XDGN="$WORK/xdg-nocreds"
OUT=$(XDG_CONFIG_HOME="$XDGN" HOME="$WORK/home" sh "$INSTALL")
check "no credentials -> installer suggests ossprey login" "$OUT" "ossprey login"

mkdir -p "$XDGN/ossprey" && echo '{}' > "$XDGN/ossprey/credentials.json"
OUT=$(XDG_CONFIG_HOME="$XDGN" HOME="$WORK/home" sh "$INSTALL")
check_absent "a stored login silences the sign-in hint" "$OUT" "ossprey login"

OUT=$(XDG_CONFIG_HOME="$XDGI" sh "$INSTALL" --key x --uninstall 2>&1)
check "--key with --uninstall is rejected" "$OUT" "cannot be combined"

: > "$CLAUDE_LOG"
OUT=$(sh "$INSTALL" --uninstall)
check "uninstall removes the plugin" "$(cat "$CLAUDE_LOG")" "plugin uninstall ossprey@ossprey"
check "uninstall removes the marketplace" "$(cat "$CLAUDE_LOG")" "marketplace remove ossprey"

OUT=$(CLAUDE_BIN="$WORK/no-such-claude" sh "$INSTALL" 2>&1)
check "a missing claude CLI is reported, not ignored" "$OUT" "claude CLI is required"

# The Windows hook entrypoint is a .cmd shim, so it can only be exercised on
# Windows -- test/run-tests.ps1 does that in CI. What is portable is
# install.ps1, so run it here whenever pwsh is available: that keeps the
# installer developable from macOS/Linux and catches PowerShell syntax
# regressions without a Windows box.
echo "== install.ps1 (pwsh) =="

if command -v pwsh >/dev/null 2>&1; then
  : > "$CLAUDE_LOG"
  OUT=$(OSSPREY_HOOKS_STYLE=posix HOME="$WORK/home" \
    pwsh -NoProfile -File "$ROOT/install.ps1")
  check "install.ps1 local install adds the checkout" "$(cat "$CLAUDE_LOG")" "marketplace add $ROOT"
  check "install.ps1 installs the plugin" "$(cat "$CLAUDE_LOG")" "plugin install ossprey@ossprey"
  check "posix hook style leaves the sh wiring" \
    "$(cat "$ROOT/hooks/hooks.json")" "ossprey-guard.sh"

  XDGP="$WORK/xdg-ps"
  OUT=$(XDG_CONFIG_HOME="$XDGP" OSSPREY_HOOKS_STYLE=posix HOME="$WORK/home" \
    pwsh -NoProfile -File "$ROOT/install.ps1" -Key sk-ps-456)
  check "install.ps1 -Key saves the key" "$(cat "$XDGP/ossprey/env")" "OSSPREY_API_KEY=sk-ps-456"
  check_absent "install.ps1 saved key silences the sign-in hint" "$OUT" "ossprey login"

  XDGQ="$WORK/xdg-ps-nocreds"
  OUT=$(XDG_CONFIG_HOME="$XDGQ" OSSPREY_HOOKS_STYLE=posix HOME="$WORK/home" \
    pwsh -NoProfile -File "$ROOT/install.ps1")
  check "install.ps1 no credentials -> suggests ossprey login" "$OUT" "ossprey login"

  OUT=$(HOME="$WORK/home" pwsh -NoProfile -File "$ROOT/install.ps1" -Branch foo 2>&1)
  check "install.ps1 -Branch rejected in local mode" "$OUT" "only applies to remote installs"

  OUT=$(HOME="$WORK/home" pwsh -NoProfile -File "$ROOT/install.ps1" -Key x -Uninstall 2>&1)
  check "install.ps1 -Key with -Uninstall rejected" "$OUT" "cannot be combined"

  : > "$CLAUDE_LOG"
  OUT=$(HOME="$WORK/home" pwsh -NoProfile -File "$ROOT/install.ps1" -Uninstall)
  check "install.ps1 uninstall removes the plugin" "$(cat "$CLAUDE_LOG")" "plugin uninstall ossprey@ossprey"

  OUT=$(CLAUDE_BIN="$WORK/no-such-claude" HOME="$WORK/home" \
    pwsh -NoProfile -File "$ROOT/install.ps1" 2>&1)
  check "install.ps1 reports a missing claude CLI" "$OUT" "claude CLI is required"
else
  echo "SKIP: pwsh not found; install.ps1 tests not run"
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
