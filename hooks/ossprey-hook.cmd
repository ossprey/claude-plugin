@echo off
REM Windows hook entrypoint: runs ossprey_hook.py for the event named in the
REM first argument (guard | audit | report | context). Wired up by
REM hooks/hooks.windows.json, which install.ps1 applies as hooks/hooks.json
REM when the plugin is installed from a local checkout on Windows.
REM
REM Only needed when Claude Code cannot run the .sh entrypoints. Claude Code
REM runs shell-form hooks through `sh` on macOS/Linux and Git Bash on
REM Windows, falling back to PowerShell when Git Bash is not installed --
REM that fallback is what this shim covers.
REM
REM A batch shim rather than a PowerShell script, on purpose. Claude Code
REM delivers the hook payload on stdin, and cmd.exe lets the Python child
REM inherit that handle untouched -- the same thing the POSIX entrypoints get
REM from `exec`. A PowerShell wrapper would have to read stdin and re-write
REM it to the child, and Windows PowerShell exposes redirected stdin to a
REM -File script through neither $input nor [Console]::In, so the payload was
REM silently lost. That failure is invisible in production: an empty payload
REM parses as "no install command", so the guard stays quiet and reports
REM success having checked nothing.
REM
REM Fails open like the sh entrypoints when no Python 3 is available. The
REM probes use -c, which never reads stdin, so the payload stays intact.
REM
REM The exit code is propagated: the report hook exits 2 to block a stop.
setlocal EnableExtensions

py -3 -c "import sys" >nul 2>&1
if not errorlevel 1 (set "PY=py -3" & goto :run)

python3 -c "import sys" >nul 2>&1
if not errorlevel 1 (set "PY=python3" & goto :run)

python -c "import sys" >nul 2>&1
if not errorlevel 1 (set "PY=python" & goto :run)

goto :failopen

:run
%PY% "%~dp0ossprey_hook.py" %1
exit /b %ERRORLEVEL%

:failopen
if /i "%~1"=="guard" echo {"additionalContext":"Ossprey hook skipped: Python 3 not found, install was NOT checked for malware.","systemMessage":"Ossprey: Python 3 not found; install not checked for malware."}
exit /b 0
