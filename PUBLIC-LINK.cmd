@echo off
REM ===========================================================================
REM  NEXUS CYBER DEFENSE - show / create the public link (Cloudflare Quick Tunnel)
REM  Usage: PUBLIC-LINK.cmd             reuse the running tunnel or start one
REM         PUBLIC-LINK.cmd -Restart    force a new public URL
REM ===========================================================================
setlocal
set "SCRIPT_DIR=%~dp0"
powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%SCRIPT_DIR%scripts\tunnel.ps1" %*
if errorlevel 1 pause
exit /b %ERRORLEVEL%
