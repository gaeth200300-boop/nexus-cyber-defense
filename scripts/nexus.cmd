@echo off
REM ===========================================================================
REM  NEXUS CYBER DEFENSE - launcher wrapper (Windows 10 / 11)
REM  This wrapper bypasses the PowerShell execution policy for THIS process only
REM  so the platform can start even when scripts are disabled system-wide.
REM ===========================================================================
setlocal
set "SCRIPT_DIR=%~dp0"
powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%SCRIPT_DIR%nexus.ps1" %*
exit /b %ERRORLEVEL%
