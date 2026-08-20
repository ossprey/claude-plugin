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
  OSSPREY_HOOK_SCAN_TIMEOUT  Seconds to wait for the guard's blocking
                             `ossprey scan` of a manifest install (default 180).
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


# ---------------------------------------------------------------------------
# Install-command recognition, ported from internal/forward in ossprey-cli.
#
# `ossprey npm install ...` (the CLI's forwarder) is the reference for what
# counts as an install and what gets checked. This hook has to recognise the
# same commands when the agent runs them *unwrapped*, so the manager registry,
# verb lists, flag tables and token classification below are a port of
# internal/forward/forward.go. Keep them in step with it.
#
# manager -> (ecosystem, install verbs). `uv` is special-cased below: its
# install forms are `uv add`, `uv sync` and `uv pip install`.
MANAGERS = {
    "npm": ("npm", ("install", "i", "add", "ci", "update", "up")),
    "pnpm": ("npm", ("install", "i", "add", "update", "up")),
    "yarn": ("npm", ("add", "install", "upgrade", "up")),
    "pip": ("pypi", ("install",)),
    "pip3": ("pypi", ("install",)),
    "poetry": ("pypi", ("add", "install", "update", "lock")),
    "uv": ("pypi", ()),
    # Beyond the CLI forwarder's list: there is no `ossprey bun` or
    # `ossprey pipenv`, but `ossprey check` is manager-agnostic, so keeping
    # these costs nothing and dropping them would lose coverage the hook
    # already had. Their flag tables are deliberately thin — the structural
    # is_non_package_token check is the backstop.
    "bun": ("npm", ("install", "i", "add", "update")),
    "pipenv": ("pypi", ("install", "sync", "update", "lock")),
}

# Flags valid *before* the verb whose following token is a value rather than
# the verb itself: `npm --prefix /tmp install x`, `pnpm --filter web add x`.
# Reading only the first token classified those as "not an install".
#
# Bias, as in the CLI: when in doubt leave a flag out. Omitting a value-taking
# flag makes its value read as the verb, which matches nothing and forwards
# unchecked — the same fail-open behaviour as not having this table. Wrongly
# listing a *boolean* flag would swallow the real verb and hide an install.
GLOBAL_VALUE_FLAGS = {
    "npm": {"--prefix", "-C", "--loglevel", "--registry", "--userconfig",
            "--globalconfig", "--cache", "-w", "--workspace", "--omit",
            "--include"},
    "pnpm": {"--filter", "-F", "--filter-prod", "--dir", "-C", "--loglevel",
             "--reporter", "--store-dir", "--virtual-store-dir",
             "--resolution-mode", "--use-node-version",
             "--package-import-method", "--workspace-concurrency",
             "--network-concurrency", "--registry"},
    "yarn": {"--cwd", "--registry", "--cache-folder", "--modules-folder"},
    "pip": {"--log", "--proxy", "--timeout", "--retries", "--cache-dir",
            "--python", "-i", "--index-url"},
    "poetry": {"-C", "--directory", "--project", "-P"},
    "uv": {"--directory", "--project", "--cache-dir", "--python", "-p",
           "--config-file", "--color"},
    "bun": {"--cwd", "--config", "-c"},
    "pipenv": {"--python", "--site-packages"},
}

# Flags *after* the verb whose following argument is a value, not a package.
# Per-manager, never shared: pnpm's -w is boolean (--workspace-root) where
# npm's -w takes a value, and pnpm inheriting npm's list is what hid
# `pnpm add -w <pkg>` in the CLI (OSS-1577).
#
# The asymmetry bites harder here than for the global table: omitting a
# value-taking flag makes its value read as a package, checking something that
# is not being installed (noisy, safe), while wrongly listing a boolean flag
# swallows the package name and skips its check entirely (silent, unsafe).
VALUE_FLAGS = {
    "npm": {"--registry", "--prefix", "-C", "--cache", "--userconfig",
            "--globalconfig", "--tag", "--otp", "-w", "--workspace", "--omit",
            "--include"},
    "pnpm": {"--filter", "-F", "--filter-prod", "--dir", "-C", "--registry",
             "--store-dir", "--virtual-store-dir", "--cache-dir",
             "--loglevel", "--reporter", "--resolution-mode",
             "--use-node-version", "--package-import-method",
             "--workspace-concurrency", "--network-concurrency"},
    "yarn": {"--registry", "--cache-folder", "--modules-folder", "--cwd"},
    "pip": {"-t", "--target", "-e", "--editable", "-i", "--index-url",
            "--extra-index-url", "-f", "--find-links", "-c", "--constraint",
            "--prefix", "--root", "--src", "--python", "--cache-dir", "--log",
            "--no-binary", "--only-binary", "--platform", "--python-version",
            "--implementation", "--abi", "--progress-bar", "--report"},
    "poetry": {"--source", "-G", "--group", "--python", "-P", "--project",
               "-C"},
    "uv": {"-i", "--index-url", "--extra-index-url", "--index",
           "--default-index", "-f", "--find-links", "--cache-dir", "-p",
           "--python", "--project", "-c", "--constraint", "-o", "--override",
           "--group", "--index-strategy", "-t", "--target", "--prefix", "-e",
           "--editable", "--optional", "--extra"},
    "bun": {"--registry", "--cwd", "--config", "-c", "--backend"},
    "pipenv": {"--python", "--extra-pip-args"},
}

# Flags whose value is a requirements/constraints file. Its packages live in
# the file, not on the command line, so naming one makes this a manifest
# install: the project gets scanned instead of parsed here.
REQUIREMENT_FILE_FLAGS = {
    "pip": {"-r", "--requirement"},
    "uv": {"-r", "--requirement"},
    "pipenv": {"-r", "--requirements"},
}

# pip3 is pip under another name, so it shares every table (as in the CLI).
for _table in (GLOBAL_VALUE_FLAGS, VALUE_FLAGS, REQUIREMENT_FILE_FLAGS):
    _table["pip3"] = _table["pip"]

SHELL_OPERATORS = {"&&", "||", ";", "|", "&"}

# Install targets that cannot be resolved against a package registry.
ARCHIVE_SUFFIXES = (".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar", ".tbz2",
                    ".whl", ".zip")
URL_PREFIXES = ("git+", "git:", "http:", "https:", "file:", "ssh:")


def split_flag_value(arg):
    """Split "--flag=value" into ("--flag", "value", True). A flag with no
    inline value returns (flag, "", False)."""
    eq = arg.find("=")
    if eq >= 0:
        return arg[:eq], arg[eq + 1:], True
    return arg, "", False


def verb_index(bin_name, args):
    """Index of the subcommand verb, skipping global flags that precede it, or
    -1. Only the first non-flag token is considered: it is the verb or nothing
    is. Never scan ahead for a verb-shaped token — `pnpm run add` must stay a
    script run, not an install of a package called "add"."""
    global_flags = GLOBAL_VALUE_FLAGS.get(bin_name, frozenset())
    i = 0
    while i < len(args):
        arg = args[i]
        if not arg:
            i += 1
            continue
        if not arg.startswith("-"):
            return i
        if arg == "--":  # ends option parsing; the verb cannot follow it
            return -1
        flag, _, has_inline = split_flag_value(arg)
        if flag in global_flags and not has_inline:
            i += 1  # this flag's value is the next token, not the verb
        i += 1
    return -1


def install_at(bin_name, args):
    """Return (index where package specs begin, True) when args is an install
    command for bin_name, else (0, False)."""
    idx = verb_index(bin_name, args)
    if idx < 0 or idx >= len(args):
        return 0, False
    if bin_name == "uv":
        rest = args[idx:]
        if rest[0] in ("add", "sync"):
            return idx + 1, True
        if len(rest) >= 2 and rest[0] == "pip" and rest[1] == "install":
            return idx + 2, True
        return 0, False
    if args[idx] in MANAGERS[bin_name][1]:
        return idx + 1, True
    return 0, False


def is_non_package_token(token):
    """True for an install target that cannot be resolved against a registry:
    a local path, a local archive, a URL, or a VCS ref."""
    if "://" in token:
        return True
    if token.startswith(URL_PREFIXES):
        return True
    if token in (".", ".."):
        return True
    if token.startswith(("./", "../", ".\\", "..\\", "/", "~")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", token):  # Windows drive path
        return True
    return token.endswith(ARCHIVE_SUFFIXES)


def split_npm(token):
    """Parse "name@version" / "@scope/name@version" / "name". The delimiter is
    the last '@'; a leading '@' (scoped package) is not a delimiter."""
    at = token.rfind("@")
    if at <= 0:
        return token, ""
    return token[:at], token[at + 1:]


def split_pypi(token):
    """Parse a pip requirement: "name==version" pins, other ranges reduce to a
    bare name (the CLI resolves latest), "name@version" is the friendly form —
    ignored when what follows '@' looks like a URL or VCS ref."""
    m = re.search(r"[=<>~!]", token)
    if m:
        name = token[:m.start()]
        rest = token[m.start():]
        return name, rest[2:] if rest.startswith("==") else ""
    at = token.rfind("@")
    if at > 0:
        rest = token[at + 1:]
        if rest and not re.search(r"[/:]", rest):
            return token[:at], rest
    return token, ""


def normalize_spec(token, eco):
    """Reduce a command-line package spec to a form `ossprey check` accepts:
    name, name@version (npm) or name==version (pypi), or None if it is not a
    package spec at all.

    Version handling deliberately differs from the CLI forwarder: a range or
    tag (`foo@^1.2.3`, `foo@latest`) becomes a bare name so `ossprey check`
    resolves and checks the latest published version, rather than submitting a
    range as if it were a version. Extras are stripped (`name[extra]`)."""
    token = re.sub(r"\[[^\]]*\]", "", token)
    if not token:
        return None
    if eco == "pypi":
        name, ver = split_pypi(token)
        if not name:
            return None
        return f"{name}=={ver}" if ver else name
    name, ver = split_npm(token)
    if not name:
        return None
    if ver:
        ver = ver.lstrip("^~=v")
        if re.match(r"^\d+(\.\d+){0,2}([.-][A-Za-z0-9.]+)?$", ver):
            return f"{name}@{ver}"
    return name


def parse_specs(bin_name, eco, args):
    """Classify an install command's arguments (everything after the verb).

    A real-world install interleaves package names with flags, flag values,
    paths and URLs -- `pip install requests -r extra.txt -t ./vendor flask
    ./local.whl` -- so treating every non-flag token as a package produces
    bogus specs. Returns (specs, non_packages, req_files)."""
    val_flags = VALUE_FLAGS.get(bin_name, frozenset())
    req_flags = REQUIREMENT_FILE_FLAGS.get(bin_name, frozenset())
    specs, non_packages, req_files = [], [], []

    i = 0
    while i < len(args):
        arg = args[i]
        if not arg:
            i += 1
            continue
        if arg.startswith("-"):
            flag, inline, has_inline = split_flag_value(arg)
            if flag in req_flags:
                if has_inline:
                    req_files.append(inline)
                elif i + 1 < len(args):
                    req_files.append(args[i + 1])
                    i += 1
            elif flag in val_flags and not has_inline and i + 1 < len(args):
                i += 1  # consume the value so it is not read as a package
            i += 1
            continue
        if is_non_package_token(arg):
            non_packages.append(arg)
            i += 1
            continue
        spec = normalize_spec(arg, eco)
        if spec:
            specs.append(spec)
        else:
            non_packages.append(arg)
        i += 1
    return specs, non_packages, req_files


def is_manifest_install(specs, non_packages, req_files):
    """True when an install that names no packages pulls them from the project
    manifest/lockfile -- a bare install (`npm install`, `npm ci`, `yarn
    install`, `poetry install`, `uv sync`) or one driven by a requirements
    file. An install whose only targets are local paths or URLs is not."""
    if specs:
        return False
    return bool(req_files) or not non_packages


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


def strip_prefixes(seg):
    """Drop wrappers and env assignments: sudo, env, command, VAR=value."""
    while seg and (seg[0] in ("sudo", "env", "command")
                   or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[0])):
        seg = seg[1:]
    return seg


def segment_cwd(seg, cwd):
    """New working directory after a `cd <dir>` segment, else cwd. The CLI
    forwarder scans "." because it *is* the installing process; the hook sees
    the whole command line, so `cd proj && npm install` must scan proj."""
    if len(seg) >= 2 and seg[0] == "cd" and not seg[1].startswith("-"):
        return os.path.normpath(os.path.join(cwd, os.path.expanduser(seg[1])))
    return cwd


def plan_command(command, cwd="."):
    """Parse a shell command string and return the work the guard must do:
    a list of actions, in command order, each one of

        ("check", ecosystem, [specs], label)   check these named packages
        ("scan",  directory,  None,   label)   scan the project first

    plus a list of install targets that could not be checked at all. An empty
    action list means nothing checkable was found: a non-install command, an
    install of only local paths or URLs, or a command already routed through
    the `ossprey` forwarder (which self-checks)."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return [], []

    actions, unchecked, scanned = [], [], set()
    checks = {}  # ecosystem -> specs, merged across segments

    for seg in split_segments(tokens):
        cwd = segment_cwd(seg, cwd)
        seg = strip_prefixes(seg)
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
        eco = MANAGERS[head][0]

        start, ok = install_at(head, seg[1:])
        if not ok:
            continue

        specs, non_packages, req_files = parse_specs(
            head, eco, seg[1:][start:])

        if specs:
            for spec in specs:
                if spec not in checks.setdefault(eco, []):
                    checks[eco].append(spec)
            unchecked.extend(non_packages + req_files)
        elif is_manifest_install(specs, non_packages, req_files):
            target = cwd or "."
            if target not in scanned:
                scanned.add(target)
                actions.append(("scan", target, None,
                                f"{head} {' '.join(seg[1:])}".strip()))
        else:
            # Only un-checkable explicit targets (local paths, archives, URLs,
            # VCS refs). Nothing to verify against a registry.
            unchecked.extend(non_packages)

    # Named packages are checked in one call per ecosystem, before any scan:
    # it is much faster and it is the more common case.
    for eco, specs in checks.items():
        actions.insert(0, ("check", eco, specs, ", ".join(specs)))

    return actions, unchecked


def verdict_of(proc_returncode, output):
    """Map a CLI exit code plus its output to one of 'clean', 'malware',
    'auth', 'error'. Shared by check and scan so their verdict wording cannot
    drift apart."""
    if proc_returncode == 0:
        return "clean"
    if MALWARE_RE.search(output):
        return "malware"
    if AUTH_RE.search(output):
        return "auth"
    return "error"


def run_cli(binary, args, timeout):
    """Run the Ossprey CLI; return (verdict, output)."""
    try:
        proc = subprocess.run([binary] + args, capture_output=True, text=True,
                              timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return "error", str(exc)
    output = (proc.stdout or "") + (proc.stderr or "")
    return verdict_of(proc.returncode, output), output


def run_check(binary, eco, specs):
    """Check named packages: `ossprey check -e <eco> <specs...>`."""
    timeout = float(os.environ.get("OSSPREY_HOOK_TIMEOUT", "60"))
    extra = shlex.split(os.environ.get("OSSPREY_HOOK_CHECK_ARGS", ""))
    return run_cli(binary, ["check", "-e", eco] + extra + specs, timeout)


def run_scan(binary, directory):
    """Scan a project before a manifest install: `ossprey scan <dir>`.

    Blocking, unlike the audit hook's background scan — the whole point is to
    get a verdict before the install runs. The longer default timeout reflects
    that cataloguing a lockfile takes more than checking a name."""
    timeout = float(os.environ.get("OSSPREY_HOOK_SCAN_TIMEOUT", "180"))
    extra = shlex.split(os.environ.get("OSSPREY_HOOK_SCAN_ARGS", ""))
    return run_cli(binary, ["scan"] + extra + [directory], timeout)


def malware_detail(output):
    lines = [l.strip() for l in output.splitlines() if MALWARE_RE.search(l)]
    return "\n".join(lines) or output.strip()


def unchecked_note(targets):
    """Mirrors the CLI forwarder's warning: these targets cannot be resolved
    against a package registry, so nothing about them was verified."""
    return ("Ossprey did not check these non-registry install targets: "
            + ", ".join(sorted(set(targets)))
            + " — run `ossprey scan .` after the install for full coverage.")


DENY_TAIL = (
    "\nDo NOT retry, bypass, or fetch these packages another way (no version "
    "pin, no direct download, no alternate registry, no vendored tarball). "
    "Remove or replace the package, or ask the user how to proceed.")


def hook_guard(payload):
    command = tool_input(payload).get("command") or ""
    cwd = payload.get("cwd") or "."
    actions, unchecked = plan_command(command, cwd)
    if not actions:
        # An install whose only targets are local paths, archives or URLs:
        # nothing to verify against a registry, but say so rather than let it
        # read as a clean bill of health.
        if unchecked:
            proceed(unchecked_note(unchecked))
        sys.exit(0)

    binary = ossprey_bin()
    if not binary:
        proceed(
            "Ossprey CLI not found, so this install was NOT checked for "
            "malware. Install it (https://github.com/ossprey/ossprey-cli) "
            "or review the packages manually before relying on them.",
            "Ossprey: CLI not found; install not checked for malware.")

    notes, warnings = [], []
    for kind, target, specs, label in actions:
        if kind == "check":
            verdict, output = run_check(binary, target, specs)
            what = f"{len(specs)} {target} package(s)"
            failed = (f"Ossprey could not check the {target} packages "
                      f"({label})")
        else:
            verdict, output = run_scan(binary, target)
            what = f"the project in {target}"
            failed = f"Ossprey could not scan {target} before `{label}`"

        if verdict == "malware":
            if kind == "check":
                deny("Ossprey blocked this command because at least one "
                     "package named on it is known malware:\n"
                     + malware_detail(output) + DENY_TAIL)
            deny(
                f"This install takes its packages from the project manifest, "
                f"so Ossprey scanned {target} first and found known malware "
                f"in the dependency tree:\n" + malware_detail(output)
                + DENY_TAIL + " Then re-run the install.")

        if verdict == "auth":
            # Same credentials for every call; no point trying the rest.
            proceed(LOGIN_GUIDANCE + " Re-run the install afterwards so it "
                    "actually gets checked.",
                    "Ossprey: not signed in; install not checked for malware.")

        if verdict == "error":
            warnings.append(f"{failed}; proceeding without a verdict.")
        else:
            notes.append(f"checked {what}")

    if unchecked:
        warnings.append(unchecked_note(unchecked))

    if warnings:
        proceed(" ".join(warnings), "Ossprey: install not fully verified.")
    proceed("Ossprey: " + ", ".join(notes) + "; no known malware.")


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
