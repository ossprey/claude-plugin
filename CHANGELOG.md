# Changelog

## Unreleased

- **The guard hook now covers every install path the Ossprey CLI's forwarder
  handles.** It is a port of `internal/forward` in ossprey-cli — the code
  behind `ossprey npm install …` — so a command is treated the same way
  whether the agent wraps it or not. What this adds over 0.1.0:
  - **Manifest installs are scanned instead of waved through.** A bare
    `npm install`, `npm ci`, `yarn install`, `pnpm install`,
    `poetry install`, `poetry lock`, `uv sync`, or `pip install -r req.txt`
    names no packages, so there was nothing for `ossprey check` to look at
    and the command went unchecked. The hook now runs a blocking
    `ossprey scan` of the project it is installing into and denies on a
    malware verdict (`OSSPREY_HOOK_SCAN_TIMEOUT`, default 180s, then fails
    open). A leading `cd` is followed, so `cd api && npm ci` scans `api`.
  - **Install verbs beyond the obvious ones**: `npm i/add/ci/update/up`,
    `pnpm update/up`, `yarn install/upgrade/up`, `poetry install/update/lock`,
    `uv sync`. Previously only `install`/`i`/`add` (and `poetry add`,
    `uv add`) were recognised, so `npm ci` and `yarn upgrade` were invisible.
  - **Global flags before the verb**: `npm --prefix /tmp install x`,
    `pnpm --filter web add x`, `pip --quiet install x`. Reading only the first
    token classified these as "not an install" — and pnpm workspaces write
    them as a matter of course.
  - **Per-manager flag tables, never shared.** `pnpm -w` is boolean
    (`--workspace-root`) where `npm -w` takes a value; one shared table per
    ecosystem is what hid `pnpm add -w <pkg>` in the CLI (OSS-1577). Also
    handles `--flag=value` inline values and `--` ending option parsing.
  - **Un-checkable targets are reported, not ignored.** An install of only
    local paths, archives, URLs or VCS refs now tells the agent what went
    unverified instead of exiting silently, matching the CLI's warning.
  - Spec parsing follows the CLI's `ParseSpec` (last `@` for npm, so
    `@scope/name@1.2.3` splits correctly). One deliberate difference: a range
    or tag (`foo@^1.2.3`, `foo@latest`) reduces to a bare name so
    `ossprey check` resolves and checks the latest published version, rather
    than submitting a range as if it were a version.
- **Docs point at `ossprey shim install`** for the installs the hook cannot
  see — Makefiles, CI steps, another terminal. The two overlap harmlessly: a
  shimmed install looks `ossprey`-wrapped to the hook, so it is not
  double-checked.
- Test suites grew to cover each manager's verbs, the flag-parsing cases, the
  manifest-scan path, and the deny wording for both (139 assertions POSIX).

## 0.1.0

Initial release: the Claude Code counterpart of the
[Ossprey plugin for Cursor](https://github.com/ossprey/cursor). Same Ossprey
CLI, same fail-open design, same `hooks/ossprey_hook.py` core; the wiring,
manifests, and decision protocol are Claude Code's.

- **`PreToolUse` (Bash) hook** blocks installs of known-malicious npm/PyPI
  packages via `ossprey check` (npm, pnpm, yarn, bun, pip, pipenv, poetry, uv
  supported, including `python -m pip`, `uv pip install`, and compound
  `a && b` commands). Fail-open on a missing CLI, missing credentials,
  network error, or timeout.
- **A clean verdict never returns `permissionDecision: "allow"`.** An
  explicit allow in Claude Code bypasses the user's own permission rules for
  that command, so a clean check emits `additionalContext` and leaves the
  normal permission flow alone. Denying is the only decision the hook makes.
- **`PostToolUse` (Write/Edit/MultiEdit/NotebookEdit) hook**
  background-scans a project when dependency manifests or lockfiles change;
  the **`Stop` hook** blocks the stop (exit 2, feedback on stderr) so the
  agent remediates findings before the session ends. Capped at
  `OSSPREY_HOOK_MAX_FOLLOWUPS` blocks per session and stands down on
  `stop_hook_active`, so an unremediable finding cannot trap a session.
- **`SessionStart` hook** injects `rules/ossprey.md` as session context —
  the stand-in for Cursor's `alwaysApply: true` rule, since a plugin cannot
  append to `CLAUDE.md`.
- **`ossprey-malware-scan` skill** for on-demand scanning workflows and
  reading verdicts, plus **`/ossprey:scan`, `/ossprey:check`, and
  `/ossprey:login`** commands over the same CLI.
- **This repository is its own marketplace** (`.claude-plugin/marketplace.json`
  with `"source": "./"`), so `/plugin marketplace add ossprey/claude-plugin`
  followed by `/plugin install ossprey@ossprey` is the whole install.
- **`install.sh` / `install.ps1`** wrap those two `claude plugin` commands
  and add the parts the CLI does not do: `--key` / `-Key` stores an API key
  in `~/.config/ossprey/env` (read by the hooks when `OSSPREY_API_KEY` is
  unset, so no shell-profile or launchd/systemd environment setup is needed),
  `--branch` installs a pre-release ref, a checkout installs itself for
  testing a branch, `--uninstall` removes plugin and marketplace, and
  `-InstallCli` installs the Ossprey CLI on Windows.
- **`ossprey login` is the recommended auth.** The CLI's browser-based OAuth
  sign-in; the hooks pick it up automatically because the CLI resolves its
  own credentials. API keys remain supported for headless setups. A "no
  credentials" error is treated as its own case, not a generic failure: the
  hooks instruct the agent to offer running `ossprey login`, confirm with
  `ossprey whoami`, and re-run the unchecked install or scan.
- **No MCP server.** Everything — checking, scanning, guarded installs —
  goes through the Ossprey CLI.
- **Windows support.** Claude Code runs shell-form hooks through Git Bash on
  Windows, so the `.sh` entrypoints are the default wiring there too;
  `hooks/hooks.windows.json` covers the PowerShell fallback via
  `hooks/ossprey-hook.cmd` (a batch shim, so Python inherits the stdin
  payload untouched — a PowerShell wrapper loses it). `hooks/hooks.json` is
  always written from `hooks.posix.json` or `hooks.windows.json`, so the
  choice is idempotent and reversible.
- **Offline test suites** (`test/run-tests.sh`, `test/run-tests.ps1`) with a
  mock CLI, run in CI on `ubuntu-latest` and `windows-latest` behind an
  aggregate `hooks` check, plus a working-tree-clean assertion so the
  installer tests cannot leave the wiring swapped.
