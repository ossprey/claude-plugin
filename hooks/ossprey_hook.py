#!/usr/bin/env python3
"""Ossprey hook dispatcher for Claude Code plugin hooks.

One script backs all four hook events (see hooks.json):

  guard    PreToolUse (Bash)     Recognise every install command the Ossprey
                                 CLI's forwarder handles. Packages named on the
                                 command line are checked with `ossprey check`;
                                 a manifest install that names none (`npm
                                 install`, `npm ci`, `yarn install`, `poetry
                                 install`, `uv sync`, `pip install -r ...`) is
                                 scanned with `ossprey scan` first. Deny on a
                                 malware verdict.
  audit    PostToolUse (edits)   When a dependency manifest is edited, kick off
                                 a background `ossprey scan` of that directory
                                 and record findings in a per-session state
                                 file.
  report   Stop                  If background scans recorded malware findings,
                                 block the stop so the agent remediates before
                                 the session ends.
  context  SessionStart          Inject rules/ossprey.md as session context —
                                 the always-on dependency-safety guidance.

Design rules:
  * The CLI owns the verdict. The guard hook decides only *where a command
    runs*, never whether a package is malicious — so none of the CLI's
    install-command parsing, flag handling or spec normalisation is
    duplicated here, and none of it can drift out of step with the CLI.
  * Fail open. Without the CLI on PATH the command is left exactly as the
    agent wrote it, with a warning for the agent and the transcript: a
    rewrite to a CLI that is not installed would turn a working install into
    "ossprey: command not found".
  * Render no permission decision. Rewriting a command is not a reason to
    grant it permission, and an explicit `permissionDecision: allow` would
    skip the user's own rules for that command. The user's rules still
    decide; they just see the wrapped command.
  * Never execute the intercepted command, and never run a package manager.
    The guard runs nothing at all; the audit hook runs only `ossprey scan`.

Credentials are the CLI's problem, not ours: a stored `ossprey login`
session or OSSPREY_API_KEY is resolved by the CLI itself on every check and
scan.

Environment:
  OSSPREY_API_KEY            API key, read by the Ossprey CLI itself (not
                             needed after `ossprey login`). When unset,
                             KEY=VALUE lines from $XDG_CONFIG_HOME/ossprey/env
                             (default ~/.config/ossprey/env, written by
                             `install.sh --key`) are loaded as defaults.
  OSSPREY_BIN                Path to the ossprey binary, for the hook's own
                             calls. A rewritten command calls `ossprey` by name
                             when that resolves on PATH, and falls back to this
                             path when it does not (default: from PATH).
  OSSPREY_HOOK_STATE_DIR     Where scan findings are recorded
                             (default: <tmpdir>/ossprey-claude).
  OSSPREY_HOOK_DEBOUNCE      Min seconds between background scans of the same
                             directory (default 30).
  OSSPREY_HOOK_MAX_FOLLOWUPS Max Stop-hook remediation prompts per session
                             (default 2).
  OSSPREY_HOOK_SCAN_ARGS     Extra args appended to the audit hook's
                             `ossprey scan`.
"""

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

MALWARE_RE = re.compile(r"contains malware", re.IGNORECASE)

# The CLI's no-credentials error ("no credentials: run `ossprey login`, or
# set OSSPREY_API_KEY / --api-key"). Handled apart from other errors so the
# agent walks the user through signing in instead of shrugging.
AUTH_RE = re.compile(r"no credentials|not logged in", re.IGNORECASE)

LOGIN_GUIDANCE = (
    "Ossprey is not signed in, so nothing was checked for malware. Help the "
    "user sign in now: offer to run `ossprey login` in the terminal — it "
    "prints a URL and a one-time code, and the user approves it in their "
    "browser while the command waits. Confirm with `ossprey whoami` "
    "afterwards. (Headless alternative: set OSSPREY_API_KEY.)")

# Manifest / lockfile basenames that trigger a background scan on edit.
MANIFEST_FILES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "Pipfile",
    "Pipfile.lock",
    "setup.py",
}

PLUGIN_ROOT = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))


def load_config_env():
    """Fill os.environ from the ossprey config file (KEY=VALUE lines)
    without overriding variables that are already set. Lets users configure
    the API key once via `install.sh --key` instead of exporting variables
    into the environment Claude Code inherits (which, when it is launched
    from a desktop session, is not the shell's)."""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    path = os.path.join(base, "ossprey", "env")
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
                    os.environ.setdefault(key, val.strip().strip("'\""))
    except OSError:
        pass


def emit(obj):
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def proceed(agent_message=None, user_message=None):
    """Let the tool call continue through Claude Code's normal permission
    flow. Deliberately not `permissionDecision: "allow"`: that would
    auto-approve the command and skip the user's own permission rules, which
    a malware check has no business doing. `additionalContext` reaches the
    agent, `systemMessage` shows the user a warning in the transcript."""
    out = {}
    if agent_message:
        out["additionalContext"] = agent_message
    if user_message:
        out["systemMessage"] = user_message
    if out:
        emit(out)
    sys.exit(0)


def state_dir():
    d = os.environ.get("OSSPREY_HOOK_STATE_DIR") or os.path.join(
        tempfile.gettempdir(), "ossprey-claude")
    os.makedirs(d, exist_ok=True)
    return d


def session_key(payload):
    sess = payload.get("session_id") or payload.get("prompt_id") or "session"
    return re.sub(r"[^A-Za-z0-9_-]", "_", str(sess))


def findings_file(payload):
    return os.path.join(state_dir(), session_key(payload) + ".log")


def ossprey_bin():
    override = os.environ.get("OSSPREY_BIN")
    if override:
        return override if os.path.exists(override) else None
    return shutil.which("ossprey")


def tool_input(payload):
    ti = payload.get("tool_input")
    return ti if isinstance(ti, dict) else {}


# ---------------------------------------------------------------------------
# Routing package-manager commands through the Ossprey forwarder.
#
# `ossprey npm install left-pad` checks the named packages — and, for an
# install that names none, scans the project manifest — inside the CLI, before
# it execs the real npm. So the hook does not need to reach a verdict itself:
# it rewrites the agent's command to go through the forwarder and lets the CLI
# decide. Nothing here duplicates the CLI's parsing, which means nothing here
# can drift out of step with it.
#
# `ossprey <bin>` exists for exactly these managers (forward.Managers() in
# ossprey-cli). Wrapping anything else would fail with "unknown command", so
# the list is load-bearing, not decorative.
WRAPPABLE = ("npm", "pnpm", "yarn", "pip3", "pip", "poetry", "uv")

# Managers the CLI has no forwarder for. There is nothing to route them
# through, so they are left alone and reported as unverified.
UNWRAPPABLE = ("bun", "pipenv")

# A command head: start of line, or after a shell separator. Kept textual on
# purpose — see wrap_command.
_SEPARATOR = r"(?:^|\n|;|&&|\|\||\||&|\(|\)|\{|\}|`)"

# `ossprey` is inserted after them, so it runs under the same wrapper the
# agent chose.
# Wrappers, shell keywords, and environment assignments that may sit in front
# of the manager: `sudo npm i x`, `if npm ci; then`, `CI=1 npm ci`.
_PREFIX = (r"(?:(?:sudo|env|command|nice|time"
           r"|if|then|else|elif|do|while|until|!)\s+"
           r"|[A-Za-z_][A-Za-z0-9_]*=(?:[^\s'\"]|'[^']*'|\"[^\"]*\")*\s+)*")

_HEAD_RE = re.compile(
    r"(?P<sep>" + _SEPARATOR + r")(?P<pre>\s*" + _PREFIX + r")"
    r"(?P<bin>" + "|".join(WRAPPABLE + UNWRAPPABLE) + r")(?=\s|$)")

# `python -m pip install ...` and a path-qualified manager (`/usr/bin/pip
# install ...`, `./venv/bin/pip ...`) cannot be routed through the forwarder:
# `ossprey pip` would pick a different interpreter or a different binary than
# the agent asked for. Detected so they can be reported rather than silently
# passed off as covered.
_PYTHON_M_PIP_RE = re.compile(
    r"(?:^|\n|;|&&|\|\||\||&|\(|`)\s*(?:sudo\s+|env\s+)*"
    r"python[0-9.]*\s+-m\s+pip(?=\s|$)")
_QUALIFIED_RE = re.compile(
    r"(?:^|\n|;|&&|\|\||\||&|\(|`)\s*(?:sudo\s+|env\s+)*"
    r"[^\s;&|]*/(?:" + "|".join(WRAPPABLE) + r")(?=\s|$)")


def wrap_command(command, ossprey_cmd):
    """Route every wrappable package-manager invocation in a shell command
    through the Ossprey forwarder.

    Returns (new_command, wrapped, unverified) where `wrapped` names the
    managers that were routed and `unverified` describes invocations that
    could not be. `ossprey_cmd` of None reports without rewriting.

    The rewrite is textual — `ossprey ` is inserted in front of the manager
    token and every other byte of the command is left exactly as the agent
    wrote it. Re-serialising a parsed token list would have to reproduce the
    original quoting, globs, redirections and here-docs, and any difference
    there changes what the command does."""
    wrapped, unverified = [], []

    def repl(m):
        bin_name = m.group("bin")
        if bin_name in UNWRAPPABLE:
            unverified.append(
                f"`{bin_name}` has no `ossprey {bin_name}` forwarder, so this "
                f"install was not checked")
            return m.group(0)
        wrapped.append(bin_name)
        if ossprey_cmd is None:
            return m.group(0)
        return m.group("sep") + m.group("pre") + ossprey_cmd + " " + bin_name

    new_command = _HEAD_RE.sub(repl, command)

    if _PYTHON_M_PIP_RE.search(command):
        unverified.append(
            "`python -m pip` cannot be routed through the forwarder without "
            "changing which interpreter installs, so it was not checked — "
            "prefer `ossprey pip install ...`")
    if _QUALIFIED_RE.search(command):
        unverified.append(
            "a package manager invoked by full path cannot be routed through "
            "the forwarder, so it was not checked")

    return new_command, wrapped, unverified


def already_wrapped(command, wrapped):
    """True when the rewrite changed nothing because the command already runs
    through the forwarder (or a PATH shim, which is the same thing)."""
    return not wrapped


FORWARDER_NOTE = (
    "Ossprey routed this through `ossprey {managers}`, which checks the "
    "packages — or scans the project manifest, for an install that names none "
    "— before the real package manager runs. If it exits non-zero reporting "
    "that a package \"contains malware\", that is a confirmed malicious "
    "package: do NOT retry, bypass, or fetch it another way (no version pin, "
    "no direct download, no alternate registry, no vendored tarball). Choose "
    "a safe alternative or ask the user how to proceed.")


def forwarder_command(binary):
    """How a rewritten command should call the CLI.

    Prefer the bare name: it keeps the command readable, and it resolves on
    the agent shell's own PATH, which is where the CLI's installer puts it.
    The hook cannot see that shell's PATH, so fall back to the absolute path
    when `ossprey` does not resolve here — that is what routes an
    OSSPREY_BIN-only install."""
    if shutil.which("ossprey"):
        return "ossprey"
    return shlex.quote(binary)


def hook_guard(payload):
    ti = tool_input(payload)
    command = ti.get("command") or ""
    if not command:
        sys.exit(0)

    binary = ossprey_bin()

    # Report-only pass first: the command has to be inspected either way, and
    # rewriting to a CLI that is not installed would turn a working install
    # into "ossprey: command not found".
    _, wrapped, unverified = wrap_command(command, None)
    if not wrapped and not unverified:
        sys.exit(0)  # nothing to do with this command

    if not binary:
        if wrapped:
            proceed(
                "Ossprey CLI not found, so this install was NOT checked for "
                "malware. Install it "
                "(https://github.com/ossprey/ossprey-cli) or review the "
                "packages manually before relying on them.",
                "Ossprey: CLI not found; install not checked for malware.")
        proceed(" ".join(unverified))

    new_command, wrapped, unverified = wrap_command(
        command, forwarder_command(binary))

    if already_wrapped(command, wrapped):
        # Already routed through the forwarder (or a PATH shim): it
        # self-checks, so there is nothing to add but the caveats.
        proceed(" ".join(unverified) if unverified else None)

    note = FORWARDER_NOTE.format(managers="`, `ossprey ".join(
        sorted(set(wrapped))))
    if unverified:
        note += " Not covered by that: " + " ".join(unverified) + "."

    updated = dict(ti)
    updated["command"] = new_command
    emit({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            # No permissionDecision: rewriting the command is not a reason to
            # grant it permission. The user's own rules still decide, they
            # just see the wrapped command.
            "updatedInput": updated,
            "additionalContext": note,
        }
    })
    sys.exit(0)


def hook_audit(payload):
    ti = tool_input(payload)
    file_path = ti.get("file_path") or ti.get("notebook_path") or ""
    if os.path.basename(file_path) not in MANIFEST_FILES:
        sys.exit(0)

    binary = ossprey_bin()
    if not binary:
        sys.exit(0)

    scan_dir = os.path.dirname(os.path.abspath(file_path)) or "."

    # Debounce repeated edits to the same directory.
    debounce = float(os.environ.get("OSSPREY_HOOK_DEBOUNCE", "30"))
    marker = os.path.join(
        state_dir(),
        "scan-" + hashlib.sha1(scan_dir.encode()).hexdigest()[:16] + ".t")
    now = time.time()
    try:
        if debounce > 0 and now - os.path.getmtime(marker) < debounce:
            sys.exit(0)
    except OSError:
        pass
    with open(marker, "w") as fh:
        fh.write(str(now))

    extra = shlex.split(os.environ.get("OSSPREY_HOOK_SCAN_ARGS", ""))
    cmd = [binary, "scan"] + extra + [scan_dir]
    log = open(findings_file(payload), "ab")
    log.write(f"--- ossprey scan {scan_dir} ({file_path}) ---\n".encode())
    log.flush()
    # Detached: PostToolUse must not stall the agent loop and a scan can take
    # a while. start_new_session is POSIX-only (silently ignored on Windows),
    # so use creationflags there to detach without flashing a console window.
    if os.name == "nt":
        detach = {"creationflags": subprocess.DETACHED_PROCESS
                  | subprocess.CREATE_NEW_PROCESS_GROUP}
    else:
        detach = {"start_new_session": True}
    subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, **detach)
    sys.exit(0)


def block_stop(reason):
    """Stop the session from ending and hand the agent a reason. Exit 2 is
    Claude Code's blocking status: stderr becomes the feedback the agent
    acts on."""
    sys.stderr.write(reason)
    sys.stderr.flush()
    sys.exit(2)


def hook_report(payload):
    # Claude Code sets this once a Stop hook has already forced a
    # continuation; never block a second time off the same block.
    if payload.get("stop_hook_active"):
        sys.exit(0)

    path = findings_file(payload)
    try:
        with open(path, "r", errors="replace") as fh:
            content = fh.read()
    except OSError:
        sys.exit(0)

    lines = sorted({l.strip() for l in content.splitlines()
                    if MALWARE_RE.search(l)})
    needs_login = not lines and AUTH_RE.search(content)
    if not lines and not needs_login:
        sys.exit(0)

    # Don't loop forever if the agent cannot remediate.
    max_followups = int(os.environ.get("OSSPREY_HOOK_MAX_FOLLOWUPS", "2"))
    counter = path + ".followups"
    try:
        with open(counter) as fh:
            count = int(fh.read().strip() or "0")
    except (OSError, ValueError):
        count = 0
    if count >= max_followups:
        sys.exit(0)
    with open(counter, "w") as fh:
        fh.write(str(count + 1))

    # Reset findings; a remediation edit re-triggers the audit scan.
    try:
        os.truncate(path, 0)
    except OSError:
        pass

    if needs_login:
        block_stop(
            "Dependency manifests were edited this session, but Ossprey "
            "could not scan them for malware: " + LOGIN_GUIDANCE +
            " Then re-run `ossprey scan .` to verify the project.")

    block_stop(
        "Ossprey scanned dependency manifests edited in this session "
        "and found known malware:\n" + "\n".join(lines) +
        "\nRemove or replace these packages now, update the lockfile, "
        "and re-run `ossprey scan .` to confirm the project is clean.")


def hook_context(payload):
    """Inject the always-on dependency-safety guidance. This is the Claude
    Code equivalent of Cursor's `alwaysApply: true` rule: a plugin cannot
    add to CLAUDE.md, so the same text is handed to the session as
    SessionStart context."""
    try:
        with open(os.path.join(PLUGIN_ROOT, "rules", "ossprey.md"),
                  encoding="utf-8") as fh:
            rules = fh.read().strip()
    except OSError:
        sys.exit(0)
    if not rules:
        sys.exit(0)
    emit({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": rules,
        }
    })
    sys.exit(0)


def main():
    load_config_env()
    event = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    try:
        if event == "guard":
            hook_guard(payload)
        elif event == "audit":
            hook_audit(payload)
        elif event == "report":
            hook_report(payload)
        elif event == "context":
            hook_context(payload)
    except SystemExit:
        raise
    except Exception as exc:  # fail open, never break the agent loop
        if event == "guard":
            proceed(f"Ossprey hook error ({exc}); command not checked for "
                    "malware.")
    sys.exit(0)


if __name__ == "__main__":
    main()
