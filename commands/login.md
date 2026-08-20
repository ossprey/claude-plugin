---
description: Sign in to Ossprey so the malware hooks can get verdicts
allowed-tools: Bash(ossprey whoami:*), Bash(ossprey login:*)
---

Make sure Ossprey has credentials — without them the hooks fail open and
nothing is checked for malware.

1. Run `ossprey whoami`. If it reports a session, say who is signed in and
   stop.
2. Otherwise run `ossprey login` in the terminal. It prints a URL and a
   one-time code, then waits while the user approves it in their browser.
   Tell the user to open the URL (or check the browser tab that opened) and
   approve the code.
3. Confirm with `ossprey whoami`, then re-run whatever check or scan went
   unverified earlier in the session.

If the CLI is not installed, point at the installer instead:
`curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh | sudo sh`
(Windows: `irm https://github.com/ossprey/ossprey-cli/releases/latest/download/install.ps1 | iex`).

For headless setups where a browser login is impractical, `OSSPREY_API_KEY`
from https://dashboard.ossprey.com is the alternative — the plugin's
installer can store it with `install.sh --key YOUR_API_KEY`.
