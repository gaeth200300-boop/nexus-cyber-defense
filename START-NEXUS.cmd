@echo off
cd /d "%~dp0"
call scripts\nexus.cmd launch
if errorlevel 1 pause
