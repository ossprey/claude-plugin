# Changelog

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
