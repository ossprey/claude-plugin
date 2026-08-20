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

echo "== PreToolUse (guard) =="

reset
OUT=$(run_guard malware "npm install evil-pkg@1.0.0")
check "malicious npm install is denied" "$OUT" '"permissionDecision": "deny"'
check "deny names the right event" "$OUT" '"hookEventName": "PreToolUse"'
check "deny carries the malware detail" "$OUT" "contains malware"
check "mock got the right check argv" "$(cat "$MOCK_LOG")" "check -e npm evil-pkg@1.0.0"

reset
OUT=$(run_guard safe "npm install lodash react@18.2.0")
check "clean npm install reports the check" "$OUT" "checked 2 package(s)"
check "both packages were checked" "$(cat "$MOCK_LOG")" "check -e npm lodash react@18.2.0"
# A clean verdict must NOT auto-approve the command: an explicit allow would
# bypass the user's own permission rules for that Bash call.
check_absent "clean verdict does not auto-approve" "$OUT" "permissionDecision"

reset
OUT=$(run_guard safe "pip install requests==2.31.0 -r reqs.txt")
check "pip install checked as pypi" "$(cat "$MOCK_LOG")" "check -e pypi requests==2.31.0"
check_absent "-r value not treated as a package" "$(cat "$MOCK_LOG")" "reqs.txt"

reset
OUT=$(run_guard safe "cd /tmp/proj && yarn add left-pad")
check "compound command still checked" "$(cat "$MOCK_LOG")" "check -e npm left-pad"

reset
OUT=$(run_guard safe "uv pip install flask>=2.0")
check "uv pip install checked, range stripped" "$(cat "$MOCK_LOG")" "check -e pypi flask"

reset
OUT=$(run_guard malware "ls -la && git status")
check_absent "non-install command is not denied" "$OUT" "deny"
check "non-install command exits 0" "$(run_guard_rc malware 'ls -la && git status')" "0"
check "non-install command never calls ossprey" "$(cat "$MOCK_LOG")x" "x"

reset
OUT=$(run_guard malware "npm install")
check_absent "bare manifest install is not denied (audit hook covers it)" "$OUT" "deny"
check "bare install never calls ossprey" "$(cat "$MOCK_LOG")x" "x"

reset
OUT=$(run_guard malware "ossprey npm install evil-pkg")
check_absent "forwarder-wrapped install passes through" "$OUT" "deny"

reset
OUT=$(run_guard safe "npm install ./local-pkg ../other git+https://github.com/x/y.git")
check_absent "local/vcs-only install is not denied" "$OUT" "deny"
check "local/vcs targets never checked" "$(cat "$MOCK_LOG")x" "x"

reset
OUT=$(run_guard error "npm install some-pkg")
check_absent "API error fails open" "$OUT" "deny"
check "fail-open is flagged to the agent" "$OUT" "proceeding without a verdict"
check "fail-open is flagged to the user" "$OUT" "systemMessage"

reset
OUT=$(run_guard auth "npm install some-pkg")
check_absent "signed-out check fails open" "$OUT" "deny"
check "signed-out check steers the agent to ossprey login" "$OUT" "ossprey login"
check "signed-out guidance mentions whoami confirmation" "$OUT" "ossprey whoami"

reset
OUT=$( (OSSPREY_BIN="$WORK/does-not-exist"; export OSSPREY_BIN; run_guard safe "npm install some-pkg") )
check "missing CLI fails open with a warning" "$OUT" "Ossprey CLI not found"

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
check "context teaches guarded installs" "$OUT" "ossprey npm install"

echo "== config file fallback =="

XDG="$WORK/xdg"
mkdir -p "$XDG/ossprey"
printf 'OSSPREY_API_KEY=test-key-123\n' > "$XDG/ossprey/env"

reset
OUT=$(printf '{"session_id":"sess-g","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm install lodash"}}' \
  | XDG_CONFIG_HOME="$XDG" MOCK_MODE=safe sh "$GUARD")
check "guard proceeds with a config-file key" "$OUT" "no known malware"
check "CLI received the key from the config file" "$(cat "$MOCK_LOG")" "key=test-key-123"

reset
OUT=$(printf '{"session_id":"sess-h","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm install lodash"}}' \
  | XDG_CONFIG_HOME="$XDG" OSSPREY_API_KEY=env-key MOCK_MODE=safe sh "$GUARD")
check "env var beats the config file" "$(cat "$MOCK_LOG")" "key=env-key"

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
