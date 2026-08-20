---
name: ossprey-malware-scan
description: Scan open-source dependencies for known malware with Ossprey. Use when installing or updating npm/PyPI packages, auditing a project's dependency tree, or checking whether a specific package version is malicious.
---

# Ossprey malware scanning

Ossprey checks open-source packages against a live database of known
supply-chain malware. Everything goes through the **`ossprey` CLI**:
checking packages, scanning projects, and guarded installs. The plugin's
`/ossprey:check`, `/ossprey:scan`, and `/ossprey:login` commands and its
hooks all shell out to the same CLI.

## Prerequisites

- The CLI is installed via:
  `curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh | sudo sh`
- Credentials, either of:
  - `ossprey login` — interactive browser sign-in, stored locally, tokens
    refresh automatically (`ossprey whoami` shows the session,
    `ossprey logout` removes it); or
  - `OSSPREY_API_KEY` set in the environment or saved to
    `~/.config/ossprey/env` via `install.sh --key` (create a key at
    https://dashboard.ossprey.com) — for headless / CI setups.

## Signing the user in

On a "no credentials" error, run the login on the user's behalf:

```sh
ossprey login    # prints a URL + one-time code, waits for browser approval
ossprey whoami   # confirm who is signed in
```

Tell the user to open the URL (or check the browser tab that opens) and
approve the code. The command blocks until they do, then stores the tokens;
every later check and scan picks them up automatically. Re-run whatever
failed once `whoami` succeeds.

## Check specific packages (fast, before install)

```sh
ossprey check -e npm lodash@4.17.21 react@18.2.0
ossprey check -e pypi requests==2.31.0
```

Exit code `0` means no malware; `1` means malware found or the check failed
(read the output — malware verdicts contain "contains malware").

## Guarded installs

Wrap the package manager so malicious packages are blocked before install:

```sh
ossprey npm install <pkg>     # also: yarn add, pip install, poetry add,
ossprey uv pip install <pkg>  # uv sync, npm ci, ...
```

If packages are named, each is checked; a bare manifest install (`npm ci`,
`yarn install`, `poetry install`, `uv sync`, `pip install -r req.txt`) scans
the project first. On a malware verdict the real package manager never runs.

To cover installs that don't go through the wrapper at all -- Makefiles, CI
steps, another terminal -- install the CLI's PATH shims once:

```sh
ossprey shim install          # ossprey shim status / uninstall
```

They put `ossprey` ahead of npm/pnpm/yarn/pip/pip3/poetry/uv on PATH, so a
plain `npm install` is checked too. Inside Claude Code the plugin's hook
already does this for the agent's own commands.

## Scan a whole project

```sh
ossprey scan .          # catalogues manifests/lockfiles, submits, verdict
ossprey scan . -o sbom.json   # also write the OSSBOM
```

Covers Python (requirements.txt, poetry.lock, uv.lock, pyproject.toml, ...)
and JavaScript (package.json, package-lock.json, yarn.lock, pnpm-lock.yaml).
Use a lockfile for full transitive coverage.

## Interpreting results

- "No malware found" — clean, proceed.
- "WARNING: <pkg>:<ver> contains malware. Remediate this immediately" —
  confirmed malicious. Remove the package, choose an alternative, and never
  bypass the block by fetching the package another way.
- Other non-zero failures (auth, network, quota) are errors, not verdicts;
  fix the cause (usually missing credentials — run `ossprey login` or set
  `OSSPREY_API_KEY`) and re-run.

## Testing the pipeline

`@ossprey/test-package` (npm) is Ossprey's harmless test package that the
platform always flags as malicious — use it to verify that checks, guarded
installs, and the PreToolUse hook are actually blocking:

```sh
ossprey check -e npm @ossprey/test-package
```

Expect a malware verdict and exit code `1`. The package itself is safe; a
verdict on it means the pipeline works, not that anything needs remediating.
