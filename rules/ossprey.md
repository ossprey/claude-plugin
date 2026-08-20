# Ossprey dependency safety

This workspace is protected by Ossprey, which checks open-source packages
for known malware before they are installed.

- **Install packages the normal way.** Run `npm install <pkg>`,
  `pip install <pkg>`, `yarn add <pkg>`, `npm ci`, `uv sync` and so on as you
  normally would. A hook routes them through the Ossprey CLI automatically —
  you do not need to type `ossprey` in front of anything, and doing so by
  hand can fail on setups where the CLI is not on `PATH`.
- If an install fails with a message that a package "contains malware", treat
  it as a confirmed malicious package. Do NOT retry the install, pin a
  different version blindly, download the package directly, switch
  registries, or vendor the tarball. Pick a safe alternative package or ask
  the user how to proceed.
- An install that names no packages (`npm ci`, `yarn install`,
  `poetry install`, `uv sync`, `pip install -r ...`) is verified by scanning
  the project manifest first, so expect it to take a few seconds longer than
  the install alone, and read the verdict before assuming the tree is clean.
- Some things cannot be routed and are therefore unverified: `bun` and
  `pipenv` (no Ossprey forwarder exists for them), `python -m pip install`,
  and a package manager invoked by full path. Prefer `pip install ...` over
  `python -m pip install ...`, and run `ossprey scan .` afterwards when you
  had to use one of the others.
- After changing dependency manifests or lockfiles, run `ossprey scan .` to
  verify the full dependency tree, and fix anything it reports.
- Scans need credentials: either a stored `ossprey login` session or
  `OSSPREY_API_KEY` in the environment. If a check or scan fails with a
  "no credentials" error, do not silently skip scanning and do not tell the
  user to go set up an API key — offer to run `ossprey login` in the
  terminal for them. It prints a URL and a one-time code, waits while the
  user approves it in their browser, and stores the session. Confirm with
  `ossprey whoami`, then re-run the check or scan that failed.
  (`OSSPREY_API_KEY` from https://dashboard.ossprey.com remains the
  fallback for headless environments.)
- All checking, scanning, and installing goes through the `ossprey` CLI;
  there is no other Ossprey surface in this workspace. The `/ossprey:check`,
  `/ossprey:scan`, and `/ossprey:login` commands and the
  `ossprey-malware-scan` skill are shortcuts to that CLI, not a second
  implementation.
