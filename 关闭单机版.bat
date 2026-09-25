@echo off
rem [DISABLE] private server -> real
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0hosts_switch.ps1" off
