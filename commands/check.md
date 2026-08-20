---
description: Check specific npm or PyPI package versions for known malware before installing
argument-hint: <package>[@version] ... (npm unless the specs look like PyPI)
allowed-tools: Bash(ossprey check:*), Bash(ossprey whoami:*), Bash(ossprey login:*)
---

Check these packages for known malware before anything installs them:
$ARGUMENTS

Pick the ecosystem from the specs — `-e npm` for `name@version` or scoped
`@scope/name`, `-e pypi` for `name==version` — and run one `ossprey check`
per ecosystem:

```sh
ossprey check -e npm <specs...>
ossprey check -e pypi <specs...>
```

Exit code `0` means no malware. Exit code `1` with a `contains malware` line
is a confirmed malicious package: report it and do not install it. Any other
non-zero exit is an error, not a clean verdict — on "no credentials", offer
to run `ossprey login`, confirm with `ossprey whoami`, and re-run the check.

If no packages were named, ask which ones to check.
