# Install the Ossprey plugin for Claude Code on Windows.
#
# Remote install (PowerShell 5.1+ or pwsh):
#   irm https://raw.githubusercontent.com/ossprey/claude-plugin/main/install.ps1 | iex
#
# Remote install with options (plugin + Ossprey CLI in one go):
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/ossprey/claude-plugin/main/install.ps1))) -InstallCli
#
# Auth: run `ossprey login` once (browser sign-in, no key to manage), or pass
# -Key YOUR_API_KEY for headless setups.
#
# From a checkout (installs that working tree, e.g. a feature branch):
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# Options:
#   -Key <key>       save an Ossprey API key to ~\.config\ossprey\env
#                    (read by the hooks, which pass it to the CLI);
#                    unnecessary after `ossprey login`
#   -Branch <ref>    add the marketplace at this branch or tag (remote mode)
#   -InstallCli      also install the Ossprey CLI by running its official
#                    Windows installer from the ossprey-cli GitHub releases
#                    (sha256-verified, installs to
#                    %LOCALAPPDATA%\Programs\ossprey, added to user PATH)
#   -Uninstall       remove the plugin and its marketplace
#
# Env overrides: OSSPREY_PLUGIN_REPO (marketplace source), CLAUDE_BIN (path
# to the claude CLI), OSSPREY_HOOKS_STYLE (posix|windows, see below),
# OSSPREY_VERSION / OSSPREY_INSTALL_DIR (CLI tag and location, honored by the
# CLI's installer during -InstallCli).
#
# This repository is both the plugin and its marketplace, so the installer
# drives Claude Code's own plugin CLI (`claude plugin marketplace add` +
# `claude plugin install`). In a checkout the marketplace is added from that
# directory, so the working tree you have is what gets installed.
#
# Hook wiring: Claude Code runs shell-form hooks through Git Bash on Windows,
# falling back to PowerShell when Git Bash is not installed. The .sh
# entrypoints work under Git Bash, so the default wiring is left alone. For
# the PowerShell fallback, a local install rewrites the checkout's
# hooks/hooks.json from hooks/hooks.windows.json so the hooks run through a
# batch shim instead. Set OSSPREY_HOOKS_STYLE=posix to keep the .sh wiring,
# or =windows to force the shim.
param(
    [string]$Key = '',
    [string]$Branch = '',
    [switch]$InstallCli,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

$Repo = if ($env:OSSPREY_PLUGIN_REPO) { $env:OSSPREY_PLUGIN_REPO } else { 'ossprey/claude-plugin' }
$Marketplace = if ($env:OSSPREY_MARKETPLACE_NAME) { $env:OSSPREY_MARKETPLACE_NAME } else { 'ossprey' }
$Plugin = 'ossprey'
$ClaudeBin = if ($env:CLAUDE_BIN) { $env:CLAUDE_BIN } else { 'claude' }
$ManifestRel = '.claude-plugin/plugin.json'
$ConfBase = if ($env:XDG_CONFIG_HOME) { $env:XDG_CONFIG_HOME } else { Join-Path $HOME '.config' }
$ConfDir = Join-Path $ConfBase 'ossprey'
$Conf = Join-Path $ConfDir 'env'
$CliRepo = 'ossprey/ossprey-cli'

# Windows PowerShell 5.1 has no $IsWindows automatic variable (it only runs
# on Windows); pwsh 6+ sets it on every platform.
$OnWindows = if ($PSVersionTable.PSVersion.Major -ge 6) { $IsWindows } else { $true }

function Info([string]$Message) { Write-Host $Message }
function Die([string]$Message) { [Console]::Error.WriteLine("error: $Message"); exit 1 }

function Test-OsspreyPlugin([string]$Dir) {
    $manifest = Join-Path $Dir $ManifestRel
    (Test-Path $manifest) -and
        ((Get-Content $manifest -Raw) -match '"name"\s*:\s*"ossprey"')
}

function Get-SavedKey {
    if (-not (Test-Path $Conf)) { return '' }
    $match = Get-Content $Conf | Where-Object { $_ -match '^OSSPREY_API_KEY=' } | Select-Object -Last 1
    if ($match) { return ($match -replace '^OSSPREY_API_KEY=', '') }
    return ''
}

function Save-Key([string]$NewKey) {
    New-Item -ItemType Directory -Force -Path $ConfDir | Out-Null
    $lines = @()
    if (Test-Path $Conf) {
        $lines = @(Get-Content $Conf | Where-Object { $_ -notmatch '^OSSPREY_API_KEY=' })
    }
    $lines += "OSSPREY_API_KEY=$NewKey"
    Set-Content -Path $Conf -Value $lines
    Info "Saved API key to $Conf"
}

function Test-Credentials {
    # A stored `ossprey login` session or an API key, anywhere the CLI or
    # the hooks look for one. On Windows the CLI's user config dir
    # (Go os.UserConfigDir) is %APPDATA%.
    if ($env:OSSPREY_API_KEY) { return $true }
    if (Get-SavedKey) { return $true }
    if ($env:OSSPREY_CONFIG_DIR -and (Test-Path (Join-Path $env:OSSPREY_CONFIG_DIR 'credentials.json'))) { return $true }
    if ($env:APPDATA -and (Test-Path (Join-Path $env:APPDATA 'ossprey/credentials.json'))) { return $true }
    if (Test-Path (Join-Path $ConfDir 'credentials.json')) { return $true }
    return $false
}

function Find-Python {
    foreach ($cand in @(@{ Exe = 'py'; Args = @('-3') },
                        @{ Exe = 'python3'; Args = @() },
                        @{ Exe = 'python'; Args = @() })) {
        if (-not (Get-Command $cand.Exe -ErrorAction SilentlyContinue)) { continue }
        try {
            & $cand.Exe @($cand.Args) '-c' 'import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)' 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { return $true }
        } catch { }
    }
    return $false
}

function Set-HookWiring([string]$Dir) {
    # Claude Code runs shell-form hooks through Git Bash on Windows, which can
    # execute the .sh entrypoints; the batch shim is for the PowerShell
    # fallback when Git Bash is not installed. hooks/hooks.json is the active
    # wiring and is always written from one of the two canonical files, so the
    # swap is idempotent and reversible: OSSPREY_HOOKS_STYLE=posix restores
    # the .sh wiring, =windows forces the shim.
    $style = $env:OSSPREY_HOOKS_STYLE
    if (-not $style) { $style = if ($OnWindows) { 'windows' } else { 'posix' } }
    $name = if ($style -eq 'windows') { 'hooks.windows.json' } else { 'hooks.posix.json' }
    $src = Join-Path $Dir "hooks/$name"
    if (-not (Test-Path $src)) { return }
    Copy-Item $src (Join-Path $Dir 'hooks/hooks.json') -Force
    Info "Applied $style hook wiring (hooks/$name -> hooks/hooks.json)."
}

function Invoke-Claude {
    # Run the claude CLI, swallowing its output; returns $true on exit 0.
    param([string[]]$Arguments)
    try {
        & $ClaudeBin @Arguments 2>&1 | Out-Null
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

function Test-ClaudeCli {
    [bool](Get-Command $ClaudeBin -ErrorAction SilentlyContinue)
}

function Install-OsspreyCli {
    if (-not $OnWindows) { Die '-InstallCli is only supported on Windows; use the install.sh one-liner instead.' }
    # Delegate to the CLI's official Windows installer, attached to its
    # releases: it detects the arch, verifies the binary's sha256, installs
    # to %LOCALAPPDATA%\Programs\ossprey (override: OSSPREY_INSTALL_DIR;
    # pin a tag with OSSPREY_VERSION), and adds it to the user PATH.
    $url = "https://github.com/$CliRepo/releases/latest/download/install.ps1"
    # Windows PowerShell 5.1 defaults to TLS 1.0; GitHub requires 1.2+.
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Info "Running the Ossprey CLI installer ($url)"
    try {
        Invoke-Expression (Invoke-RestMethod -UseBasicParsing -Uri $url)
    } catch {
        Die "Ossprey CLI install failed: $($_.Exception.Message)"
    }
}

if ($Uninstall) {
    if ($Key) { Die '-Key cannot be combined with -Uninstall' }
    if (-not (Test-ClaudeCli)) { Die "the claude CLI is not on PATH; nothing to uninstall from." }
    if (-not (Invoke-Claude @('plugin', 'uninstall', "$Plugin@$Marketplace"))) {
        Info "Plugin $Plugin@$Marketplace was not installed."
    }
    if (-not (Invoke-Claude @('plugin', 'marketplace', 'remove', $Marketplace))) {
        Info "Marketplace $Marketplace was not registered."
    }
    Info "Removed $Plugin@$Marketplace. It unloads on the next Claude Code session."
    exit 0
}

if ($Key) { Save-Key $Key }
if ($InstallCli) { Install-OsspreyCli }

# Local mode: if this script sits inside a plugin checkout, install that
# working tree (branch and all). $PSScriptRoot is empty when piped via iex.
$Src = ''
if ($PSScriptRoot -and (Test-OsspreyPlugin $PSScriptRoot)) {
    $Src = $PSScriptRoot
}

if ($Src -and $Branch) {
    Die "-Branch only applies to remote installs; check out the branch in $Src instead."
}

if (-not (Test-ClaudeCli)) {
    Die "the claude CLI is required: https://code.claude.com/docs/en/quickstart
(then re-run this installer, or add the marketplace by hand with
'/plugin marketplace add $Repo' inside Claude Code)."
}

if ($Src) {
    Set-HookWiring $Src
    $Source = $Src
} elseif ($Branch) {
    $Source = "$Repo@$Branch"
} else {
    $Source = $Repo
}

# `marketplace add` fails when the name is already registered; `update`
# refreshes it in place, which is also what re-running the installer means.
if (Invoke-Claude @('plugin', 'marketplace', 'add', $Source)) {
    Info "Added marketplace $Source"
} elseif (Invoke-Claude @('plugin', 'marketplace', 'update', $Marketplace)) {
    Info "Updated marketplace $Marketplace ($Source)"
} else {
    Die "could not add or update the marketplace $Source.
Try it by hand: $ClaudeBin plugin marketplace add $Source"
}

if (Invoke-Claude @('plugin', 'install', "$Plugin@$Marketplace", '--yes')) {
    Info "Installed $Plugin@$Marketplace"
} elseif (Invoke-Claude @('plugin', 'update', "$Plugin@$Marketplace")) {
    Info "Updated $Plugin@$Marketplace"
} else {
    Die "could not install $Plugin@$Marketplace.
Try it by hand: $ClaudeBin plugin install $Plugin@$Marketplace"
}

if ($Src) {
    Info "Installed from the local checkout $Src."
    Info 'Re-run this script after local changes so Claude Code picks them up.'
}

Info ''
Info 'Next steps:'
Info "  1. Start a new Claude Code session (or run '/plugin' in a running one) so the plugin loads."
$osspreyBin = if ($env:OSSPREY_BIN) { $env:OSSPREY_BIN } else { 'ossprey' }
if (-not (Get-Command $osspreyBin -ErrorAction SilentlyContinue)) {
    Info '  2. Install the Ossprey CLI (hooks fail open without it):'
    Info '     irm https://github.com/ossprey/ossprey-cli/releases/latest/download/install.ps1 | iex'
    Info '     (re-running this installer with -InstallCli does the same)'
}
if (-not (Test-Credentials)) {
    Info '  3. Sign in so the hooks can get malware verdicts:'
    Info '     ossprey login'
    Info '     (or re-run this installer with -Key YOUR_API_KEY for headless setups;'
    Info '     create a key at https://dashboard.ossprey.com)'
    Info '     Without credentials the hooks fail open and nothing is checked for malware.'
}
if ($OnWindows -and -not (Find-Python)) {
    Info '  Note: the hooks need Python 3 and none was found; they fail open (no'
    Info '  malware checks) until you install it: winget install Python.Python.3.12'
}
