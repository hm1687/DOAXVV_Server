@echo off
rem [ENABLE] standalone -> local
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0hosts_switch.ps1" on
