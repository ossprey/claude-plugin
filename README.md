# Ossprey plugin for Claude Code

Supply-chain malware protection for [Claude Code](https://claude.com/claude-code).
The plugin watches what the agent installs and edits, checks open-source
packages against the [Ossprey](https://ossprey.com) known-malware platform,
and blocks malicious packages **before** they reach the machine.

This is the Claude Code counterpart of the
[Ossprey plugin for Cursor](https://github.com/ossprey/cursor); same CLI, same
fail-open design, wired to Claude Code's hook events and plugin format.

## What it does

| Component | Behaviour |
|-----------|-----------|
| `PreToolUse` hook (Bash) | Rewrites package-manager commands to run through the Ossprey CLI's forwarder — `npm install left-pad` becomes `ossprey npm install left-pad` — which checks the packages, or scans the project manifest for an install that names none, and refuses to run the real manager on a malware verdict. See [How the check happens](#how-the-check-happens). |
| `PostToolUse` hook (edits) | When the agent edits a dependency manifest or lockfile (`package.json`, `requirements.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock`, …) it kicks off a background `ossprey scan` of that directory. |
| `Stop` hook | If a background scan found malware, the stop is blocked and the agent is told to remediate before the session ends. |
| `SessionStart` hook | Injects `rules/ossprey.md` as session context: prefer `ossprey <manager> install …` wrapped installs, run `ossprey scan .` after dependency changes, never bypass a malware block. |
| Skill | `ossprey-malware-scan` — on-demand reference for scanning workflows and interpreting results. |
| Commands | `/ossprey:scan`, `/ossprey:check`, `/ossprey:login` — the CLI's three everyday operations as slash commands. |

Everything goes through the [Ossprey CLI](https://github.com/ossprey/ossprey-cli)
— the hooks shell out to `ossprey check` and `ossprey scan`, and the CLI
handles authentication and talking to the Ossprey API. The plugin registers
no MCP server.

### How the check happens

The hook does not decide whether a package is malicious. `ossprey npm install
left-pad` already checks the named packages — and, for an install that names
none, scans the project manifest — inside the CLI, before it execs the real
npm. So the hook's whole job is to make the agent's command go through that
path:

```
agent runs:   npm ci
hook rewrites: ossprey npm ci
ossprey:      scans the project, blocks on malware, else execs the real npm
```

It rewrites via `updatedInput` on the `PreToolUse` hook, which replaces a
tool's arguments before it runs. The rewrite is textual — `ossprey ` is
inserted in front of the manager and every other byte is left as the agent
wrote it, so quoting, globs, redirections and here-docs are untouched.
`ossprey` goes *after* any wrapper or assignment, so `sudo npm i x` becomes
`sudo ossprey npm i x` and `CI=1 npm ci` becomes `CI=1 ossprey npm ci`.

**Nothing here duplicates the CLI's parsing**, which is the point: no install
verbs, no per-manager flag tables, no spec normalisation, no manifest-install
detection. There is nothing to keep in step and nothing that can drift.

`npm`, `pnpm`, `yarn`, `pip`, `pip3`, `poetry` and `uv` are routed — exactly
the managers `ossprey <bin>` exists for (`forward.Managers()` in the CLI).
Every invocation of one is routed, not just installs, so there is no list of
install verbs to keep in step with the CLI: the forwarder execs a non-install
command straight through. `npm run build` runs as `ossprey npm run build` and
behaves identically, at the cost of one extra process.

Three things can't be routed, and are reported to the agent as unverified
rather than passed off as covered:

| Not routed | Why |
|------------|-----|
| `bun`, `pipenv` | The CLI has no `ossprey bun` / `ossprey pipenv` forwarder, so there is nothing to route them through |
| `python -m pip install …` | `ossprey pip` would install with a different interpreter than the agent asked for |
| `/usr/local/bin/npm install …` | The forwarder takes a manager name, not a path, so it would resolve a different binary |

A command already wrapped in `ossprey …` is left alone — it self-checks.
So is anything that isn't a package manager, and a manager name that isn't a
command head (`echo npm install`, `git commit -m "npm install"`).

The plugin's scope is the agent's own commands, deliberately: it covers what
Claude Code runs through its Bash tool and changes nothing about the rest of
your environment. Installs from a Makefile, a CI step, or your own terminal
are outside it — `ossprey scan .` is the way to verify a project after one.

#### One thing to know about permission rules

The command your permission rules see is the rewritten one. A rule for
`Bash(npm install:*)` no longer matches, because the command is now
`ossprey npm install …`. Allowlist `Bash(ossprey:*)` instead if you want
installs to run without a prompt.

### Fail-open by design

The hooks never block development on infrastructure problems. Without the
CLI on `PATH` the command is left exactly as the agent wrote it, with a
warning for the agent and the transcript — a rewrite to a CLI that is not
installed would turn a working install into `ossprey: command not found`.
Missing credentials, a network error, or a timeout are the CLI's own
fail-open paths, and it forwards to the real package manager rather than
blocking on them.

The only thing that stops an install is an explicit malware verdict, and it
stops inside the CLI, before the real package manager is exec'd. That holds
even if the agent ignores the session guidance entirely: the routing is done
by the hook, not by the agent choosing to type `ossprey`.

The hook renders **no permission decision** — not even on a clean command.
Rewriting a command is not a reason to grant it permission, and an explicit
`permissionDecision: "allow"` would skip your own rules for that command.
Your rules still decide; they just see the wrapped command.

When the CLI reports it has no credentials, the hooks go one step further
than a warning: they tell the agent to offer to run `ossprey login` in the
terminal on your behalf — the device flow prints a URL and one-time code,
you approve it in the browser, and the command stores the session — then
confirm with `ossprey whoami` and re-run whatever went unchecked.

## Requirements

| Dependency | Needed for | If it's missing |
|------------|-----------|-----------------|
| **Claude Code**, recent enough for plugins and `${CLAUDE_PLUGIN_ROOT}` in hook commands | Loading the plugin at all | The plugin never runs |
| **Python 3** (3.8+), on `PATH` as `python3` / `python`, or the `py` launcher on Windows | The hook logic (`hooks/ossprey_hook.py`) — the `.sh` / `.cmd` entrypoints are thin wrappers around it | Hooks **fail open**: installs proceed, nothing is checked, and the agent is warned |
| **[Ossprey CLI](https://github.com/ossprey/ossprey-cli)** on `PATH` as `ossprey` | Every verdict — the hooks shell out to `ossprey check` and `ossprey scan` | Hooks **fail open** with a warning telling the agent the install was not checked |
| **Ossprey credentials** — an `ossprey login` session or `OSSPREY_API_KEY` ([free account](https://ossprey.com)) | Talking to the Ossprey API | Hooks **fail open** and steer the agent to run `ossprey login` for you |
| **`git`** | Installing from the marketplace (Claude Code clones this repo) | Install from a local checkout instead |
| **POSIX `sh`**, or **Git Bash** on Windows | Running the hook entrypoints | Windows without Git Bash: apply the batch wiring (see [Platform support](#platform-support)) |

Nothing else: no Node, no MCP server, no extension, and no Ossprey daemon.
Network access to `api.ossprey.com` is needed for verdicts, and `github.com`
for installs and updates.

Note the pattern in the table — every dependency except Claude Code itself
degrades to **fail open** rather than breaking your workflow. That is
deliberate (see [Fail-open by design](#fail-open-by-design)), but it also
means a broken setup is quiet: if you want to confirm the plugin is really
protecting you, run the [live end-to-end test](#testing) below.

## Setup

1. **Install the Ossprey CLI** (the hooks shell out to it):

   ```sh
   curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh | sudo sh
   ```

   Windows: `irm https://github.com/ossprey/ossprey-cli/releases/latest/download/install.ps1 | iex`,
   or let the plugin installer do it with `install.ps1 -InstallCli`.

2. **Sign in to Ossprey** (free account at [ossprey.com](https://ossprey.com)):

   ```sh
   ossprey login
   ```

   A browser opens, you confirm a one-time code, and the CLI stores the
   tokens locally. Tokens refresh automatically; `ossprey whoami` shows the
   session and `ossprey logout` removes it. No key to create, copy, or
   rotate — and nothing to configure in the environment Claude Code runs in,
   because the hooks shell out to the CLI, which finds the login itself.

3. **Install the plugin.** This repository is both the plugin and its
   marketplace, so from inside Claude Code:

   ```
   /plugin marketplace add ossprey/claude-plugin
   /plugin install ossprey@ossprey
   ```

   or from a terminal:

   ```sh
   claude plugin marketplace add ossprey/claude-plugin
   claude plugin install ossprey@ossprey
   ```

   The installer scripts wrap exactly those two commands and add the API-key
   plumbing:

   ```sh
   curl -fsSL https://raw.githubusercontent.com/ossprey/claude-plugin/main/install.sh | sh
   ```

   ```powershell
   irm https://raw.githubusercontent.com/ossprey/claude-plugin/main/install.ps1 | iex
   ```

   Re-run either any time to update, pass `--uninstall` / `-Uninstall` to
   remove the plugin and its marketplace. From inside a checkout,
   `sh install.sh` registers **that working tree** as the marketplace instead
   — handy for testing a branch before release. `--branch <ref>` does the
   same for a remote ref.

   For headless setups where a browser login is impractical, use an API key
   instead (create one at
   [dashboard.ossprey.com](https://dashboard.ossprey.com)): either export
   `OSSPREY_API_KEY` in the environment Claude Code runs in, or let the
   installer save it where the hooks pick it up:

   ```sh
   curl -fsSL https://raw.githubusercontent.com/ossprey/claude-plugin/main/install.sh \
     | sh -s -- --key YOUR_API_KEY
   ```

   Note: a stored `ossprey login` session takes precedence over an API key,
   so `ossprey logout` first if you want to force key auth.

4. **Start a new session** (or run `/plugin` in a running one) so the hooks,
   skill, and commands load.

### Platform support

macOS, Linux, and Windows are supported, and all three are covered by CI.
The hooks are thin wrappers around `hooks/ossprey_hook.py`.

Claude Code runs shell-form hook commands through `sh` on macOS and Linux and
through **Git Bash on Windows**, falling back to PowerShell when Git Bash is
not installed. The shipped wiring (`hooks/hooks.json`, a copy of
`hooks/hooks.posix.json`) uses the `.sh` entrypoints, which covers all three
of those cases except the PowerShell fallback. For that case
`hooks/hooks.windows.json` wires the same events through
`hooks/ossprey-hook.cmd`; a local install applies it automatically on Windows,
and `OSSPREY_HOOKS_STYLE=posix|windows` forces either wiring. Because
`hooks/hooks.json` is always written from one of the two canonical files, the
choice is reversible — re-running the installer restores the other.

The Windows entrypoint is a `.cmd` rather than a PowerShell script for a
specific reason: Claude Code delivers the hook payload on stdin, and
`cmd.exe` lets the Python child inherit that handle untouched, the same way
`exec` does in the `sh` entrypoints. A PowerShell wrapper has to read stdin
and re-write it to the child, and Windows PowerShell exposes a `-File`
script's redirected stdin through neither `$input` nor `[Console]::In` — so
the payload vanishes and every hook silently checks nothing.

## Configuration

All knobs are environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `OSSPREY_API_KEY` | from `~/.config/ossprey/env` | API key (only needed without `ossprey login`) |
| `OSSPREY_BIN` | `ossprey` on `PATH` | CLI binary override, for the hooks' own calls. A rewritten command calls `ossprey` by name when that resolves on `PATH`, and falls back to this path when it doesn't |
| `OSSPREY_HOOK_DEBOUNCE` | `30` | Min seconds between background rescans of a directory |
| `OSSPREY_HOOK_MAX_FOLLOWUPS` | `2` | Max Stop-hook remediation prompts per session |
| `OSSPREY_HOOK_STATE_DIR` | `<tmpdir>/ossprey-claude` | Where background scan findings are recorded |
| `OSSPREY_HOOK_SCAN_ARGS` | — | Extra args for the audit hook's `ossprey scan` (e.g. `--url` for a staging API) |
| `OSSPREY_HOOKS_STYLE` | `windows` on Windows, else `posix` | Which hook wiring a local install applies |

The hooks read any `KEY=VALUE` lines in `~/.config/ossprey/env`
(`install.sh --key` / `install.ps1 -Key` write it; on Windows that is
`%USERPROFILE%\.config\ossprey\env`) as defaults, so every variable above
can be set there instead of in Claude Code's process environment. Real
environment variables win over the file.

The guard hook takes no options because it runs nothing: it rewrites the
command and the CLI's own configuration (`OSSPREY_API_URL`,
`OSSPREY_API_KEY`) takes over from there.

The Stop hook is capped at `OSSPREY_HOOK_MAX_FOLLOWUPS` blocks per session
and stands down as soon as Claude Code reports `stop_hook_active`, so a
finding the agent cannot remediate never traps a session in a loop.

## Testing

The hook suite runs without Claude Code and without network access — payloads
are piped into the hook scripts exactly as Claude Code sends them, and the
CLI is replaced by `test/mock/ossprey`:

```sh
sh test/run-tests.sh          # macOS / Linux
```

```powershell
pwsh -NoProfile -File test\run-tests.ps1    # Windows
```

The POSIX suite covers the `sh` entrypoints and `install.sh`, plus
`install.ps1` when `pwsh` is on the `PATH`. The PowerShell suite covers the
same hook behaviour driven through the Windows entrypoint and the `.cmd`
mock CLI; those parts need Windows and are skipped elsewhere, so running it
on macOS/Linux exercises `install.ps1` only. Both suites run in CI, on
`ubuntu-latest` and `windows-latest`.

For a live end-to-end test inside Claude Code, install the plugin and ask the
agent to install [`@ossprey/test-package`](https://www.npmjs.com/package/@ossprey/test-package)
— our harmless npm package that the Ossprey platform always flags as
malicious (think EICAR for supply-chain malware):

```sh
npm install @ossprey/test-package
```

The install must be denied with a malware message. The package contains no
malicious code, so nothing bad happens even if a blocking layer is
misconfigured and it does get installed.

The install must fail with a malware message, and the transcript should show
the command as `ossprey npm install @ossprey/test-package` — that is the hook
doing its job. (The CLI's `--dry-run-malicious` flag works on
`ossprey check`, not on the forwarder, so there is no hook-side dry run to
set: the forwarder passes every argument through to the package manager.)

## Repository layout

```
.claude-plugin/plugin.json      plugin manifest
.claude-plugin/marketplace.json marketplace catalogue (this repo is its own marketplace)
install.sh                      install / update / uninstall via the claude CLI (macOS/Linux)
install.ps1                     same for Windows; -InstallCli also installs the Ossprey CLI
hooks/hooks.json                active hook wiring (a copy of hooks.posix.json)
hooks/hooks.posix.json          POSIX wiring (sh entrypoints)
hooks/hooks.windows.json        Windows wiring (batch shim, for the PowerShell fallback)
hooks/ossprey_hook.py           guard / audit / report / context logic
hooks/ossprey-*.sh              thin sh entrypoints (fail open without python3)
hooks/ossprey-hook.cmd          Windows entrypoint (fails open without Python 3)
rules/ossprey.md                always-on agent guidance, injected at SessionStart
skills/ossprey/SKILL.md         scanning workflow reference
commands/*.md                   /ossprey:scan, /ossprey:check, /ossprey:login
test/run-tests.sh               POSIX hook + install.sh suite
test/run-tests.ps1              PowerShell hook + install.ps1 suite
test/mock/ossprey[.cmd]         mock CLI (sh script + Windows .cmd sibling)
```

## Support

- Docs: [docs.ossprey.com](https://docs.ossprey.com)
- Issues: [github.com/ossprey/claude-plugin/issues](https://github.com/ossprey/claude-plugin/issues)
- Email: support@ossprey.com
