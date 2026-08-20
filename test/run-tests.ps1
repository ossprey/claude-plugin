# Windows-native test suite for the Ossprey Claude Code plugin. No Claude
# Code and no network needed: hook payloads are piped into the Windows
# entrypoint exactly as Claude Code sends them, and the Ossprey CLI is
# replaced by the mock in test/mock (drive it with MOCK_MODE). Run:
#
#   pwsh -NoProfile -File test/run-tests.ps1
#   powershell -ExecutionPolicy Bypass -File test\run-tests.ps1
#
# This is the Windows counterpart of test/run-tests.sh, which needs a POSIX
# shell. The hook-entrypoint tests only run on Windows, because the entrypoint
# is a .cmd shim; on macOS/Linux the same hook logic is covered by
# run-tests.sh through the sh entrypoints, and this suite still exercises
# install.ps1 so the installer can be developed off Windows.

# Native commands write to stderr on the error-mode tests, and the report
# hook exits 2 on purpose; don't let either abort the run.
$ErrorActionPreference = 'Continue'

# Windows PowerShell 5.1 pipes to native commands as ASCII by default; the
# hook payloads carry file paths, so keep the pipe UTF-8 in both hosts.
$OutputEncoding = New-Object System.Text.UTF8Encoding $false

$Root = Split-Path -Parent $PSScriptRoot
$Hook = Join-Path $Root 'hooks/ossprey-hook.cmd'
$Install = Join-Path $Root 'install.ps1'
$OnWindows = if ($PSVersionTable.PSVersion.Major -ge 6) { $IsWindows } else { $true }
# $(...) is required here: `if` is a statement, so plain parentheses in
# argument position would not evaluate it.
$Mock = Join-Path $Root $(if ($OnWindows) { 'test/mock/ossprey.cmd' } else { 'test/mock/ossprey' })

# install.ps1 runs under Windows PowerShell 5.1 where it exists, so the host
# most Windows users will invoke it with is the one under test. Resolve to an
# absolute path: one test empties PATH, and the shell still has to launch.
$Shell = $null
if ($OnWindows) { $Shell = (Get-Command powershell -ErrorAction SilentlyContinue).Source }
if (-not $Shell) { $Shell = (Get-Command pwsh -ErrorAction SilentlyContinue).Source }
if (-not $Shell) { $Shell = (Get-Process -Id $PID).Path }

$Work = Join-Path ([IO.Path]::GetTempPath()) ("ossprey-tests-" + [IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $Work | Out-Null

$MockLog = Join-Path $Work 'mock.log'
$env:OSSPREY_BIN = $Mock
$env:OSSPREY_HOOK_STATE_DIR = Join-Path $Work 'state'
$env:OSSPREY_HOOK_DEBOUNCE = '0'
$env:MOCK_LOG = $MockLog
# Never read the real user config, and keep the credential probes pointed at
# throwaway directories.
$env:XDG_CONFIG_HOME = Join-Path $Work 'xdg-isolated'
$env:APPDATA = Join-Path $Work 'appdata'
Remove-Item Env:OSSPREY_API_KEY, Env:OSSPREY_CONFIG_DIR -ErrorAction SilentlyContinue

$script:Pass = 0
$script:Fail = 0

function Reset-Log { Set-Content -Path $MockLog -Value '' -NoNewline }

function Get-Log {
    # Get-Content -Raw yields $null for an empty file; callers want a string.
    if (-not (Test-Path $MockLog)) { return '' }
    $raw = Get-Content $MockLog -Raw
    if ($null -eq $raw) { return '' }
    return $raw
}

function Check([string]$Name, [string]$Haystack, [string]$Needle) {
    if ($Haystack -and $Haystack.Contains($Needle)) {
        $script:Pass++; Write-Host "PASS: $Name"
    } else {
        $script:Fail++
        Write-Host "FAIL: $Name"
        Write-Host "  wanted: $Needle"
        Write-Host "  got:    $Haystack"
    }
}

function Check-Absent([string]$Name, [string]$Haystack, [string]$Needle) {
    if ($Haystack -and $Haystack.Contains($Needle)) {
        $script:Fail++
        Write-Host "FAIL: $Name (found '$Needle')"
        Write-Host "  got: $Haystack"
    } else {
        $script:Pass++; Write-Host "PASS: $Name"
    }
}

function New-Payload([hashtable]$Fields) {
    # ConvertTo-Json escapes Windows path separators correctly. Depth covers
    # the nested tool_input object Claude Code sends.
    ($Fields | ConvertTo-Json -Compress -Depth 5)
}

function Use-Env([hashtable]$Overrides, [scriptblock]$Body) {
    $saved = @{}
    foreach ($k in $Overrides.Keys) {
        $saved[$k] = [Environment]::GetEnvironmentVariable($k)
        [Environment]::SetEnvironmentVariable($k, $Overrides[$k])
    }
    try { & $Body } finally {
        foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }
    }
}

function Invoke-Hook {
    param([string]$Event, [string]$Payload, [string]$Mode = 'safe', [hashtable]$Env = @{})
    Use-Env $Env {
        $env:MOCK_MODE = $Mode
        try {
            # Piped exactly the way Claude Code delivers the payload. The exit
            # code is part of the contract (the report hook blocks with 2), so
            # append it to the captured text.
            $out = $Payload | & $Hook $Event 2>&1
            return ((@($out) -join "`n") + "`nexit=$LASTEXITCODE")
        } finally {
            Remove-Item Env:MOCK_MODE -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-Guard([string]$Command, [string]$Mode = 'safe', [hashtable]$Env = @{}) {
    Invoke-Hook -Event 'guard' -Mode $Mode -Env $Env -Payload (New-Payload @{
        session_id = 'sess-1'
        hook_event_name = 'PreToolUse'
        tool_name = 'Bash'
        tool_input = @{ command = $Command }
    })
}

function Invoke-Install {
    param([string[]]$Arguments = @(), [hashtable]$Env = @{})
    Use-Env $Env {
        $out = & $Shell -NoProfile -ExecutionPolicy Bypass -File $Install @Arguments 2>&1
        return (@($out) -join "`n")
    }
}

# Wait for the detached background scan to land in the findings log.
function Wait-ForLog([string]$Needle, [int]$TimeoutSeconds = 20) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ((Get-Log).Contains($Needle)) { return $true }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

Write-Host "== environment =="
Write-Host "  shell: $Shell"
Write-Host "  hook:  $Hook"
Write-Host "  mock:  $Mock"

if (-not $OnWindows) {
    Write-Host ''
    Write-Host 'SKIP: hook entrypoint tests need Windows (the entrypoint is a .cmd shim).'
    Write-Host '      test/run-tests.sh covers the same hook logic via the sh entrypoints.'
    Write-Host ''
}

if ($OnWindows) {

Write-Host "== stdin plumbing =="

# The entrypoint's whole job is to hand Claude Code's JSON payload to Python.
# Getting that wrong fails silently — an empty payload looks like "no command
# to check", so the hook stays quiet and reports success having checked
# nothing. A PowerShell entrypoint did exactly that (Windows PowerShell
# exposes a -File script's redirected stdin through neither $input nor
# [Console]::In), which is why the entrypoint is a batch shim that lets
# Python inherit the handle. Assert the payload actually arrives, so a
# regression here can never be silent again.
Reset-Log
$plumbing = Invoke-Guard 'npm install plumbing-probe' 'safe'
Check 'the entrypoint forwards the payload to the hook script' $plumbing 'ossprey npm install plumbing-probe'
Check 'a delivered payload produces a verdict, not silence' $plumbing 'additionalContext'

Write-Host "== PreToolUse (guard): routing through the forwarder =="

# The guard does not reach a verdict — it rewrites the command so the Ossprey
# CLI's forwarder does the checking inside its own process, before the real
# package manager runs. So these assert on the rewritten command, and that the
# guard ran nothing at all.
#
# A rewritten command prefers the bare name whenever `ossprey` resolves on
# PATH, so put a stub there: the assertions then read the same on every
# platform, instead of carrying a JSON-escaped Windows path.
$stubDir = Join-Path $Work 'stub'
New-Item -ItemType Directory -Force -Path $stubDir | Out-Null
[IO.File]::WriteAllText((Join-Path $stubDir 'ossprey.cmd'), "@echo off`r`nexit /b 0`r`n")
$pathWithoutStub = $env:PATH
$env:PATH = "$stubDir$([IO.Path]::PathSeparator)$env:PATH"

Reset-Log
$out = Invoke-Guard 'npm install left-pad' 'safe'
Check 'an install is routed through the forwarder' $out '"command": "ossprey npm install left-pad"'
Check 'the rewrite is reported to the agent' $out 'ossprey npm'
Check-Absent 'the guard runs no CLI of its own' (Get-Log) 'check'
# Rewriting a command is not a reason to grant it permission: the user's own
# rules still decide, they just see the wrapped command.
Check-Absent 'the guard renders no permission decision' $out 'permissionDecision'
Check 'the rewrite names the right event' $out '"hookEventName": "PreToolUse"'

# Every install form the forwarder handles, routed without the hook needing to
# know which of them are installs — that is the CLI's job.
foreach ($cmd in @('npm install', 'npm ci', 'npm i left-pad', 'npm add left-pad',
                   'npm update', 'pnpm install', 'pnpm add -w left-pad',
                   'yarn install', 'yarn add left-pad', 'yarn upgrade',
                   'poetry install', 'poetry lock', 'poetry add requests',
                   'pip install requests', 'pip install -r requirements.txt',
                   'pip3 install requests', 'uv sync', 'uv add httpx',
                   'uv pip install flask')) {
    Reset-Log
    $out = Invoke-Guard $cmd 'safe'
    Check "``$cmd`` is routed through the forwarder" $out "ossprey $cmd"
}

Write-Host "== PreToolUse (guard): the rewrite preserves the command =="

Reset-Log
$out = Invoke-Guard 'cd api && npm ci' 'safe'
Check 'a leading cd is left alone' $out '"command": "cd api && ossprey npm ci"'

Reset-Log
$out = Invoke-Guard 'npm install a && npm test' 'safe'
Check 'every manager invocation is routed' $out 'ossprey npm install a && ossprey npm test'

Reset-Log
$out = Invoke-Guard 'CI=1 npm ci' 'safe'
Check 'ossprey is inserted after env assignments' $out 'CI=1 ossprey npm ci'

Reset-Log
$out = Invoke-Guard 'if npm ci; then echo ok; fi' 'safe'
Check 'ossprey is inserted after a shell keyword' $out 'if ossprey npm ci; then echo ok; fi'

Reset-Log
$out = Invoke-Guard 'npm install x > out.log 2>&1' 'safe'
Check 'redirections are preserved' $out 'ossprey npm install x > out.log 2>&1'

# updatedInput replaces the entire input object, so dropping a field would
# silently change how the command runs.
Reset-Log
$out = Invoke-Hook -Event 'guard' -Mode 'safe' -Payload (New-Payload @{
    session_id = 's'
    hook_event_name = 'PreToolUse'
    tool_name = 'Bash'
    tool_input = @{ command = 'npm ci'; description = 'install deps'; timeout = 120000 }
})
Check 'other tool_input fields survive the rewrite' $out '"description": "install deps"'
Check 'the timeout survives the rewrite' $out '"timeout": 120000'

Write-Host "== PreToolUse (guard): commands left alone =="

Reset-Log
$out = Invoke-Guard 'ls -la && git status' 'safe'
Check 'a non-manager command exits 0' $out 'exit=0'
Check-Absent 'a non-manager command gets no rewrite' $out 'updatedInput'

Reset-Log
$out = Invoke-Guard 'ossprey npm install evil-pkg' 'safe'
Check-Absent 'an already-wrapped install is not double-wrapped' $out 'updatedInput'

Reset-Log
$out = Invoke-Guard 'echo npm install' 'safe'
Check-Absent 'a manager named mid-command is not a command head' $out 'updatedInput'

Write-Host "== PreToolUse (guard): what cannot be routed is reported =="

# `ossprey <bin>` exists only for the managers the CLI forwards. Wrapping
# anything else would fail with "unknown command", so these are left alone —
# and said out loud rather than passed off as covered.
Reset-Log
$out = Invoke-Guard 'bun add left-pad' 'safe'
Check-Absent 'bun is not wrapped' $out 'updatedInput'
Check 'bun is reported as unchecked' $out 'forwarder'

Reset-Log
$out = Invoke-Guard 'python3 -m pip install requests' 'safe'
Check-Absent 'python -m pip is not rewritten' $out 'updatedInput'
Check 'python -m pip is reported as unchecked' $out 'which interpreter installs'

Write-Host "== PreToolUse (guard): fail-open =="

# Rewriting to a CLI that is not installed would turn a working install into
# "ossprey: command not found", so a missing CLI means no rewrite at all. The
# PATH stub has to go for this one, or the bare name would still resolve.
Reset-Log
$out = Invoke-Guard 'npm install some-pkg' 'safe' @{
    OSSPREY_BIN = (Join-Path $Work 'does-not-exist')
    PATH = $pathWithoutStub   # drops the stub, keeps Python
}
Check 'missing CLI fails open with a warning' $out 'Ossprey CLI not found'
Check-Absent 'missing CLI does not rewrite the command' $out 'updatedInput'
Check 'missing CLI is flagged to the user' $out 'systemMessage'

# The entrypoint must fail open when no Python 3 is on PATH, exactly like the
# sh entrypoints do. Keep System32 on PATH so cmd.exe still resolves; the
# Python launcher lives in C:\Windows, so this is still a Python-less PATH.
$noPython = Join-Path $env:SystemRoot 'System32'
$out = Invoke-Guard 'npm install x' 'safe' @{ PATH = $noPython }
Check 'guard fails open without Python' $out 'NOT checked for malware'
$out = Invoke-Hook -Event 'audit' -Payload '{}' -Env @{ PATH = $noPython }
Check 'audit is silent without Python' $out 'exit=0'


Write-Host "== PostToolUse (audit) + Stop (report) =="

Reset-Log
$proj = Join-Path $Work 'proj'
New-Item -ItemType Directory -Force -Path $proj | Out-Null
$manifest = Join-Path $proj 'package.json'
Set-Content -Path $manifest -Value '{}'
$out = Invoke-Hook -Event 'audit' -Mode 'malware' -Payload (New-Payload @{
    session_id = 'sess-a'
    hook_event_name = 'PostToolUse'
    tool_name = 'Edit'
    tool_input = @{ file_path = $manifest }
})
Wait-ForLog 'scan' | Out-Null
Check 'manifest edit triggers a scan' (Get-Log) 'scan'

$stopA = New-Payload @{ session_id = 'sess-a'; hook_event_name = 'Stop' }
$out = Invoke-Hook -Event 'report' -Payload $stopA
Check 'stop blocks on malware findings' $out 'exit=2'
Check 'stop feedback lists the finding' $out 'contains malware'

$out = Invoke-Hook -Event 'report' -Payload $stopA
Check 'findings not repeated once reported' $out 'exit=0'

Reset-Log
$out = Invoke-Hook -Event 'audit' -Mode 'malware' -Payload (New-Payload @{
    session_id = 'sess-b'
    hook_event_name = 'PostToolUse'
    tool_name = 'Write'
    tool_input = @{ file_path = (Join-Path $proj 'main.py') }
})
Start-Sleep -Seconds 1
Check-Absent 'non-manifest edit does not scan' (Get-Log) 'scan'

$out = Invoke-Hook -Event 'report' -Payload (New-Payload @{
    session_id = 'sess-clean'; hook_event_name = 'Stop'
})
Check 'clean session does not block the stop' $out 'exit=0'

Reset-Log
$out = Invoke-Hook -Event 'audit' -Mode 'auth' -Payload (New-Payload @{
    session_id = 'sess-c'
    hook_event_name = 'PostToolUse'
    tool_name = 'Edit'
    tool_input = @{ file_path = $manifest }
})
Wait-ForLog 'no credentials' | Out-Null
$out = Invoke-Hook -Event 'report' -Payload (New-Payload @{
    session_id = 'sess-c'; hook_event_name = 'Stop'
})
Check 'signed-out scan surfaces at stop' $out 'exit=2'
Check 'stop feedback steers the agent to ossprey login' $out 'ossprey login'
Check-Absent 'signed-out scan is not reported as malware' $out 'contains malware'

# stop_hook_active means Claude Code already forced one continuation; never
# block again off the back of it.
Reset-Log
$out = Invoke-Hook -Event 'audit' -Mode 'malware' -Payload (New-Payload @{
    session_id = 'sess-d'
    hook_event_name = 'PostToolUse'
    tool_name = 'Edit'
    tool_input = @{ file_path = $manifest }
})
Wait-ForLog 'scan' | Out-Null
$out = Invoke-Hook -Event 'report' -Payload (New-Payload @{
    session_id = 'sess-d'; hook_event_name = 'Stop'; stop_hook_active = $true
})
Check 'stop_hook_active suppresses the block' $out 'exit=0'

Write-Host "== SessionStart (context) =="

$out = Invoke-Hook -Event 'context' -Payload (New-Payload @{
    session_id = 'sess-f'; hook_event_name = 'SessionStart'; source = 'startup'
})
Check 'session start injects context' $out '"hookEventName": "SessionStart"'
Check 'context carries the rules' $out 'Ossprey dependency safety'

Write-Host "== config file fallback =="

# The hooks read ~/.config/ossprey/env so the API key (and any other knob) can
# be set once, instead of in the environment Claude Code inherits. The guard
# runs no CLI now, so the key is asserted where a CLI actually runs: the audit
# hook's background scan.
$xdg = Join-Path $Work 'xdg'
New-Item -ItemType Directory -Force -Path (Join-Path $xdg 'ossprey') | Out-Null
Set-Content -Path (Join-Path $xdg 'ossprey/env') -Value 'OSSPREY_API_KEY=test-key-123'

Reset-Log
$auditPayload = New-Payload @{
    session_id = 'sess-cfg'
    hook_event_name = 'PostToolUse'
    tool_name = 'Edit'
    tool_input = @{ file_path = $manifest }
}
$out = Invoke-Hook -Event 'audit' -Mode 'safe' -Payload $auditPayload -Env @{ XDG_CONFIG_HOME = $xdg }
Wait-ForLog 'key=test-key-123' | Out-Null
Check 'CLI received the key from the config file' (Get-Log) 'key=test-key-123'

Reset-Log
$out = Invoke-Hook -Event 'audit' -Mode 'safe' -Payload $auditPayload -Env @{ XDG_CONFIG_HOME = $xdg; OSSPREY_API_KEY = 'env-key' }
Wait-ForLog 'key=env-key' | Out-Null
Check 'env var beats the config file' (Get-Log) 'key=env-key'

}  # end Windows-only hook tests

Write-Host "== install.ps1 =="

$homeDir = Join-Path $Work 'home'
# Create it: PowerShell derives $HOME from USERPROFILE at startup and a
# missing home directory makes the child host complain.
New-Item -ItemType Directory -Force -Path $homeDir | Out-Null

# Stand-in for the claude CLI: logs its argv, and fails the calls the real
# CLI fails (adding an already-registered marketplace) when asked to.
$claudeLog = Join-Path $Work 'claude.log'
Set-Content -Path $claudeLog -Value '' -NoNewline
if ($OnWindows) {
    $claudeBin = Join-Path $Work 'claude.cmd'
    # CRLF: cmd.exe mis-parses labels and `goto` in LF-only files.
    $lines = @(
        '@echo off',
        'echo %* >> "%CLAUDE_LOG%"',
        'echo %*| find "marketplace add" >nul && if defined CLAUDE_ADD_FAILS exit /b 1',
        'echo %*| find "plugin install" >nul && if defined CLAUDE_INSTALL_FAILS exit /b 1',
        'exit /b 0'
    )
    [IO.File]::WriteAllText($claudeBin, ($lines -join "`r`n") + "`r`n")
} else {
    $claudeBin = Join-Path $Work 'claude'
    $lines = @(
        '#!/bin/sh',
        'printf ''%s\n'' "$*" >> "$CLAUDE_LOG"',
        'case "$*" in',
        '  *"marketplace add"*) [ -z "${CLAUDE_ADD_FAILS:-}" ] || exit 1 ;;',
        '  *"plugin install"*) [ -z "${CLAUDE_INSTALL_FAILS:-}" ] || exit 1 ;;',
        'esac',
        'exit 0'
    )
    [IO.File]::WriteAllText($claudeBin, ($lines -join "`n") + "`n")
    & chmod +x $claudeBin
}

$baseEnv = @{
    HOME = $homeDir
    USERPROFILE = $homeDir
    CLAUDE_BIN = $claudeBin
    CLAUDE_LOG = $claudeLog
}

function With-Env([hashtable]$Extra) {
    $merged = @{}
    foreach ($k in $baseEnv.Keys) { $merged[$k] = $baseEnv[$k] }
    foreach ($k in $Extra.Keys) { $merged[$k] = $Extra[$k] }
    return $merged
}

function Get-ClaudeLog {
    if (-not (Test-Path $claudeLog)) { return '' }
    $raw = Get-Content $claudeLog -Raw
    if ($null -eq $raw) { return '' }
    return $raw
}

function Reset-ClaudeLog { Set-Content -Path $claudeLog -Value '' -NoNewline }

# A local install rewrites hooks/hooks.json in the checkout; keep the shipped
# copy so the working tree is restored no matter how the suite ends.
$ActiveHooks = Join-Path $Root 'hooks/hooks.json'
$ShippedHooks = Join-Path $Work 'hooks.shipped.json'
Copy-Item $ActiveHooks $ShippedHooks -Force

Reset-ClaudeLog
$out = Invoke-Install -Env (With-Env @{ OSSPREY_HOOKS_STYLE = 'windows' })
Check 'local install adds the checkout as a marketplace' (Get-ClaudeLog) 'marketplace add'
Check 'local install installs the plugin' (Get-ClaudeLog) 'plugin install ossprey@ossprey'
Check 'local install says where it came from' $out 'local checkout'
Check 'Windows hook wiring applied' `
    (Get-Content $ActiveHooks -Raw) 'ossprey-hook.cmd'

# Reversible: re-running with the POSIX style must restore the shipped wiring
# byte for byte, so a Windows install never leaves the checkout stranded.
$out = Invoke-Install -Env (With-Env @{ OSSPREY_HOOKS_STYLE = 'posix' })
Check 'posix hook style restores the sh wiring' `
    (Get-Content $ActiveHooks -Raw) 'ossprey-guard.sh'
Check 'restored wiring matches the shipped file' `
    $(if ((Get-FileHash $ActiveHooks).Hash -eq (Get-FileHash $ShippedHooks).Hash) { 'same' } else { 'different' }) 'same'

Reset-ClaudeLog
$out = Invoke-Install -Env (With-Env @{ OSSPREY_HOOKS_STYLE = 'posix'; CLAUDE_ADD_FAILS = '1' })
Check 're-install updates the registered marketplace' (Get-ClaudeLog) 'marketplace update ossprey'
Check 're-install still reaches the plugin install' (Get-ClaudeLog) 'plugin install ossprey@ossprey'

Reset-ClaudeLog
$out = Invoke-Install -Env (With-Env @{ OSSPREY_HOOKS_STYLE = 'posix'; CLAUDE_INSTALL_FAILS = '1' })
Check 'an already-installed plugin falls back to update' (Get-ClaudeLog) 'plugin update ossprey@ossprey'

Check 'no .mcp.json is shipped' `
    $(if (Test-Path (Join-Path $Root '.mcp.json')) { 'present' } else { 'absent' }) 'absent'

$xdgi = Join-Path $Work 'xdg-install'
$out = Invoke-Install -Arguments @('-Key', 'sk-test-456') -Env (With-Env @{ XDG_CONFIG_HOME = $xdgi; OSSPREY_HOOKS_STYLE = 'posix' })
Check '-Key saves the key to the config file' `
    (Get-Content (Join-Path $xdgi 'ossprey/env') -Raw) 'OSSPREY_API_KEY=sk-test-456'
Check-Absent 'saved key silences the sign-in hint' $out 'ossprey login'

$out = Invoke-Install -Arguments @('-Key', 'sk-rotated-789') -Env (With-Env @{ XDG_CONFIG_HOME = $xdgi; OSSPREY_HOOKS_STYLE = 'posix' })
Check '-Key rotates the stored key' `
    (Get-Content (Join-Path $xdgi 'ossprey/env') -Raw) 'OSSPREY_API_KEY=sk-rotated-789'
Check-Absent 'old key gone from the config file' `
    (Get-Content (Join-Path $xdgi 'ossprey/env') -Raw) 'sk-test-456'

$xdgn = Join-Path $Work 'xdg-nocreds'
$out = Invoke-Install -Env (With-Env @{ XDG_CONFIG_HOME = $xdgn; OSSPREY_HOOKS_STYLE = 'posix' })
Check 'no credentials -> installer suggests ossprey login' $out 'ossprey login'

New-Item -ItemType Directory -Force -Path (Join-Path $xdgn 'ossprey') | Out-Null
Set-Content -Path (Join-Path $xdgn 'ossprey/credentials.json') -Value '{}'
$out = Invoke-Install -Env (With-Env @{ XDG_CONFIG_HOME = $xdgn; OSSPREY_HOOKS_STYLE = 'posix' })
Check-Absent 'a stored login silences the sign-in hint' $out 'ossprey login'

$out = Invoke-Install -Arguments @('-Branch', 'foo') -Env (With-Env @{})
Check '-Branch is rejected in local mode' $out 'only applies to remote installs'

$out = Invoke-Install -Arguments @('-Key', 'x', '-Uninstall') -Env (With-Env @{})
Check '-Key with -Uninstall is rejected' $out 'cannot be combined'

Reset-ClaudeLog
$out = Invoke-Install -Arguments @('-Uninstall') -Env (With-Env @{})
Check 'uninstall removes the plugin' (Get-ClaudeLog) 'plugin uninstall ossprey@ossprey'
Check 'uninstall removes the marketplace' (Get-ClaudeLog) 'marketplace remove ossprey'

$out = Invoke-Install -Env (With-Env @{ CLAUDE_BIN = (Join-Path $Work 'no-such-claude') })
Check 'a missing claude CLI is reported, not ignored' $out 'claude CLI is required'

# Leave the checkout as it was found: the hook-style tests rewrite
# hooks/hooks.json in place.
Copy-Item $ShippedHooks $ActiveHooks -Force

Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue

Write-Host ''
Write-Host "$($script:Pass) passed, $($script:Fail) failed"
if ($script:Fail -gt 0) { exit 1 }
exit 0
