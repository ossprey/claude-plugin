@echo off
REM Windows mock Ossprey CLI for the hook tests — the .cmd sibling of
REM test/mock/ossprey, which Windows cannot execute (Python's subprocess
REM runs .cmd/.bat through cmd.exe, but not a shebang script).
REM
REM Mirrors the real CLI's contract:
REM   exit 0 + "No malware found"                    on a clean verdict
REM   exit 1 + "... contains malware. Remediate ..." on a malware verdict
REM   exit 1 + error text on stderr                  on API/auth errors
REM   exit 1 + "no credentials: ..." on stderr       when signed out
REM Behaviour is selected with MOCK_MODE=safe|malware|error|auth (default
REM safe). Every invocation's argv is appended to MOCK_LOG when set.
setlocal EnableExtensions

if not defined MOCK_LOG goto :verdict
REM Expand into plain variables first: %VAR% inside a parenthesised block
REM is substituted when the block is parsed, not when it runs.
set "ARGS=%*"
set "KEY=%OSSPREY_API_KEY%"
>>"%MOCK_LOG%" echo.%ARGS%
>>"%MOCK_LOG%" echo.key=%KEY%

:verdict
if /i "%MOCK_MODE%"=="malware" goto :malware
if /i "%MOCK_MODE%"=="error" goto :error
if /i "%MOCK_MODE%"=="auth" goto :auth
echo No malware found
exit /b 0

:malware
echo Error: WARNING: evil-pkg:1.0.0 contains malware. Remediate this immediately
exit /b 1

:error
>&2 echo Error: Post "https://api.ossprey.com/public/v1/scans": dial tcp: no route to host
exit /b 1

:auth
>&2 echo Error: no credentials: run `ossprey login`, or set OSSPREY_API_KEY / --api-key
exit /b 1
