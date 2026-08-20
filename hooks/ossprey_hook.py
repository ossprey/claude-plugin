#!/usr/bin/env python3
"""Ossprey hook dispatcher for Claude Code plugin hooks.

One script backs all four hook events (see hooks.json):

  guard    PreToolUse (Bash)     Check packages named in npm/pip-style install
                                 commands against the Ossprey API before the
                                 command runs. Deny on a malware verdict.
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
  * Fail open. A missing CLI, missing credentials, network error, or timeout
    must never block the developer — the hook stays silent about the decision
    and attaches a warning for the agent and the transcript.
  * Deny only on an explicit malware verdict from the Ossprey CLI.
  * Never `permissionDecision: allow`. In Claude Code an explicit "allow"
    bypasses the user's own permission rules for that command, so a clean
    verdict must leave the normal permission flow untouched: we emit context
    only. Denying is the one decision this hook makes.
  * Never execute the intercepted command ourselves; only `ossprey check`
    (packages named on the command line) and `ossprey scan` (manifests) run.

Credentials are the CLI's problem, not ours: a stored `ossprey login`
session or OSSPREY_API_KEY is resolved by the CLI itself on every check and
scan.

Environment:
  OSSPREY_API_KEY            API key, read by the Ossprey CLI itself (not
                             needed after `ossprey login`). When unset,
                             KEY=VALUE lines from $XDG_CONFIG_HOME/ossprey/env
                             (default ~/.config/ossprey/env, written by
                             `install.sh --key`) are loaded as defaults.
  OSSPREY_BIN                Path to the ossprey binary (default: from PATH).
  OSSPREY_HOOK_TIMEOUT       Seconds to wait for `ossprey check` (default 60).
  OSSPREY_HOOK_STATE_DIR     Where scan findings are recorded
                             (default: <tmpdir>/ossprey-claude).
  OSSPREY_HOOK_DEBOUNCE      Min seconds between background scans of the same
                             directory (default 30).
  OSSPREY_HOOK_MAX_FOLLOWUPS Max Stop-hook remediation prompts per session
                             (default 2).
  OSSPREY_HOOK_CHECK_ARGS    Extra args appended to `ossprey check`
                             (e.g. --dry-run-malicious for testing).
  OSSPREY_HOOK_SCAN_ARGS     Extra args appended to `ossprey scan`.
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

# package manager -> (install subcommands, ecosystem)
MANAGERS = {
    "npm": ({"install", "i", "add"}, "npm"),
    "pnpm": ({"install", "i", "add"}, "npm"),
    "yarn": ({"add"}, "npm"),
    "bun": ({"install", "i", "add"}, "npm"),
    "pip": ({"install"}, "pypi"),
    "pip3": ({"install"}, "pypi"),
    "pipenv": ({"install"}, "pypi"),
    "poetry": ({"add"}, "pypi"),
    "uv": ({"add"}, "pypi"),  # `uv pip install` handled separately
}

# Flags that consume the next token as a value, per ecosystem family.
VALUE_FLAGS = {
    "npm": {"--registry", "--tag", "--prefix", "--workspace", "-w",
            "--loglevel", "--omit", "--include", "--location",
            "--script-shell"},
    "pypi": {"-r", "--requirement", "-c", "--constraint", "-e", "--editable",
             "-i", "--index-url", "--extra-index-url", "-f", "--find-links",
             "-t", "--target", "--prefix", "--root", "--src", "--platform",
             "--python", "--python-version", "--implementation", "--abi",
             "--proxy", "--retries", "--timeout", "--cache-dir", "--log",
             "--group", "-G", "--source", "-E", "--extras", "--directory",
             "-C", "--project", "--index", "--default-index", "-p"},
}

SHELL_OPERATORS = {"&&", "||", ";", "|", "&"}
ARCHIVE_SUFFIXES = (".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2")

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


def deny(reason):
    emit({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    })
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


def is_package_token(tok):
    """True if a bare CLI arg looks like a registry package spec (not a
    path, URL, VCS ref, or archive)."""
    if not tok or tok.startswith("-"):
        return False
    if "://" in tok or tok.startswith(("git+", "file:", "./", "../", "~")):
        return False
    if tok.startswith("/") or tok.endswith(ARCHIVE_SUFFIXES):
        return False
    # Windows-style paths
    if re.match(r"^[A-Za-z]:[\\/]", tok):
        return False
    return True


def normalize_spec(tok, eco):
    """Reduce a command-line package spec to a form `ossprey check` accepts:
    name, name@version (npm) or name==version (pypi). Ranges and extras are
    stripped; an unresolvable version falls back to name-only (the CLI then
    resolves the latest published version)."""
    tok = re.sub(r"\[[^\]]*\]", "", tok)  # strip pip extras: name[extra]
    if eco == "pypi":
        m = re.match(r"^([A-Za-z0-9._-]+)==([A-Za-z0-9.!+*_-]+)$", tok)
        if m:
            return f"{m.group(1)}=={m.group(2)}"
        # name>=1.0, name~=1.0, bare name, or anything else version-fuzzy
        m = re.match(r"^([A-Za-z0-9._-]+)", tok)
        return m.group(1) if m else None
    # npm: @scope/name@version or name@version; version may carry ^ / ~
    m = re.match(r"^(@?[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?)(?:@(.+))?$", tok)
    if not m:
        return None
    name, ver = m.group(1), m.group(2)
    if ver:
        ver = ver.lstrip("^~=v")
        if re.match(r"^\d+(\.\d+){0,2}([.-][A-Za-z0-9.]+)?$", ver):
            return f"{name}@{ver}"
    return name


def split_segments(tokens):
    """Split a shell token list on command separators."""
    seg = []
    for tok in tokens:
        if tok in SHELL_OPERATORS:
            if seg:
                yield seg
            seg = []
        else:
            seg.append(tok)
    if seg:
        yield seg


def extract_packages(command):
    """Parse a shell command string; return {ecosystem: [specs]} for every
    package named in an install-style invocation. Returns {} when nothing
    checkable is found (non-install command, bare manifest install, local
    paths only, or a command already wrapped by the ossprey forwarder)."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return {}

    found = {}
    for seg in split_segments(tokens):
        # Drop wrappers and env assignments: sudo, env, VAR=value
        while seg and (seg[0] in ("sudo", "env", "command")
                       or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[0])):
            seg = seg[1:]
        if not seg:
            continue
        head = os.path.basename(seg[0])

        # Already routed through the ossprey forwarder: it self-checks.
        if head == "ossprey":
            continue

        # `python -m pip install ...`
        if head in ("python", "python3") and seg[1:3] == ["-m", "pip"]:
            head, seg = "pip", seg[2:]

        if head not in MANAGERS:
            continue
        subcommands, eco = MANAGERS[head]
        rest = seg[1:]

        # `uv pip install ...`
        if head == "uv" and rest[:2] == ["pip", "install"]:
            rest = rest[2:]
        else:
            if not rest or rest[0] not in subcommands:
                continue
            rest = rest[1:]

        value_flags = VALUE_FLAGS[eco]
        skip_next = False
        for tok in rest:
            if skip_next:
                skip_next = False
                continue
            if tok.startswith("-"):
                if tok in value_flags:
                    skip_next = True
                continue
            if not is_package_token(tok):
                continue
            spec = normalize_spec(tok, eco)
            if spec:
                found.setdefault(eco, []).append(spec)
    return found


def run_check(binary, eco, specs):
    """Run `ossprey check`; return (verdict, output) where verdict is one of
    'clean', 'malware', 'auth', 'error'."""
    timeout = float(os.environ.get("OSSPREY_HOOK_TIMEOUT", "60"))
    extra = shlex.split(os.environ.get("OSSPREY_HOOK_CHECK_ARGS", ""))
    cmd = [binary, "check", "-e", eco] + extra + specs
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return "error", str(exc)
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode == 0:
        return "clean", output
    if MALWARE_RE.search(output):
        return "malware", output
    if AUTH_RE.search(output):
        return "auth", output
    return "error", output


def hook_guard(payload):
    command = tool_input(payload).get("command") or ""
    packages = extract_packages(command)
    if not packages:
        sys.exit(0)

    binary = ossprey_bin()
    if not binary:
        proceed(
            "Ossprey CLI not found, so this install was NOT checked for "
            "malware. Install it (https://github.com/ossprey/ossprey-cli) "
            "or review the packages manually before relying on them.",
            "Ossprey: CLI not found; install not checked for malware.")

    checked, warnings = 0, []
    for eco, specs in packages.items():
        verdict, output = run_check(binary, eco, specs)
        if verdict == "malware":
            lines = [l.strip() for l in output.splitlines()
                     if MALWARE_RE.search(l)]
            detail = "\n".join(lines) or output.strip()
            deny(
                "Ossprey blocked this command because at least one package "
                "is known malware:\n" + detail + "\nDo NOT retry, bypass, or "
                "fetch these packages another way (no version pin, no direct "
                "download, no alternate registry, no vendored tarball). "
                "Choose a safe alternative or ask the user how to proceed.")
        if verdict == "auth":
            # Same credentials for every ecosystem; no point checking more.
            proceed(LOGIN_GUIDANCE + " Re-run the install afterwards so the "
                    "packages actually get checked.",
                    "Ossprey: not signed in; install not checked for malware.")
        if verdict == "error":
            warnings.append(
                f"Ossprey check errored for {eco} packages "
                f"({', '.join(specs)}); proceeding without a verdict.")
        else:
            checked += len(specs)

    if warnings:
        proceed(" ".join(warnings),
                "Ossprey: check failed; install not verified.")
    proceed(f"Ossprey: checked {checked} package(s), no known malware.")


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
