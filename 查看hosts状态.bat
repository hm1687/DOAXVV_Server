@echo off
rem [STATUS] show hosts state
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0hosts_switch.ps1" status

echo.
pause