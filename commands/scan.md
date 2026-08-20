---
description: Scan this project's dependency tree for known malware with Ossprey
argument-hint: "[path] (default: .)"
allowed-tools: Bash(ossprey scan:*), Bash(ossprey whoami:*), Bash(ossprey login:*)
---

Scan the dependency tree for known supply-chain malware.

Run `ossprey scan $1` and report the verdict — scan `.` if no path was
given.

- "No malware found" — say so and stop.
- A `contains malware` line — name the offending package and version, remove
  or replace it, update the lockfile, and re-run the scan to confirm the
  project is clean. Never work around the verdict by fetching the package
  another way.
- A "no credentials" error — offer to run `ossprey login` for the user (it
  prints a URL and a one-time code and waits for browser approval), confirm
  with `ossprey whoami`, then re-run the scan.
- Any other failure (network, quota) is an error, not a verdict: report it
  rather than implying the project is clean.

Lockfiles give full transitive coverage; note it if only a top-level
manifest was available.
