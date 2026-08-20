# Changelog

## Unreleased

- **The guard hook routes commands through the CLI instead of adjudicating
  them.** `ossprey npm install left-pad` already checks the named packages —
  and, for an install that names none, scans the project manifest — inside
  the CLI before it execs the real npm. So the hook stopped calling
  `ossprey check` / `ossprey scan` to reach its own verdict and now rewrites
  the agent's command (`npm ci` → `ossprey npm ci`) via `updatedInput` on
  `PreToolUse`, letting the CLI decide.

  This deleted every copy of the CLI's install-command logic from the plugin:
  no manager verb lists, no per-manager flag tables, no spec normalisation,
  no manifest-install detection, no `--flag=value` handling. There is nothing
  left to keep in step with the CLI and nothing that can drift, and coverage
  now follows the CLI automatically — including install forms added to it
  later. `hooks/ossprey_hook.py` lost ~210 lines.

  Consequences worth knowing:
  - **Every invocation of a routed manager is rewritten, not just installs.**
    `npm run build` runs as `ossprey npm run build`; the forwarder execs
    non-install commands straight through. That is what removes the need for
    a list of install verbs. Cost is one extra process.
  - **Permission rules see the rewritten command.** A rule for
    `Bash(npm install:*)` no longer matches — allowlist `Bash(ossprey:*)`.
  - **The verdict arrives as a failed command**, not as a hook denial: the
    CLI exits non-zero with the malware report and never runs the package
    manager. The hook attaches guidance so the agent treats it as a
    confirmed malicious package rather than a flake to retry.
  - **The rewrite is textual.** `ossprey ` is inserted in front of the
    manager token and every other byte is left as written, so quoting,
    globs, redirections and here-docs survive. It goes after wrappers and
    assignments: `sudo npm i x` → `sudo ossprey npm i x`, `CI=1 npm ci` →
    `CI=1 ossprey npm ci`, `if npm ci; then` → `if ossprey npm ci; then`.
  - **A missing CLI means no rewrite at all**, rather than rewriting to a
    command that would fail with `ossprey: command not found`.
  - **`bun` and `pipenv` lost coverage.** The CLI has no `ossprey bun` /
    `ossprey pipenv` forwarder, so there is nothing to route them through;
    they are now reported to the agent as unverified. Same for
    `python -m pip install …` (routing it would change which interpreter
    installs) and a manager invoked by full path.
  - `OSSPREY_HOOK_TIMEOUT`, `OSSPREY_HOOK_SCAN_TIMEOUT` and
    `OSSPREY_HOOK_CHECK_ARGS` are gone: the guard runs nothing, so it has
    nothing to time out or pass flags to. `OSSPREY_HOOK_SCAN_ARGS` still
    applies to the audit hook's background scan.
- **The plugin's scope is the agent's own commands only.** An earlier draft
  pointed users at the CLI's PATH shims (`ossprey shim install`) to cover
  Makefiles, CI steps and their own terminal; that is out of scope for a
  Claude Code plugin, which should not reconfigure the whole environment to
  do its job. `ossprey scan .` remains the way to verify a project after an
  install the plugin never saw.
- **The session guidance stopped telling the agent to type `ossprey`.**
  Installs are routed for it now, and typing the wrapper by hand fails on
  setups where the CLI is not on `PATH` but `OSSPREY_BIN` is set.
- Verified in a real Claude Code session with `ossprey` deliberately off
  `PATH`, so only the hook's rewrite could reach the CLI: the model typed a
  bare `npm install left-pad@1.3.0 --dry-run` and the CLI received
  `npm install left-pad@1.3.0 --dry-run` as its arguments.

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
