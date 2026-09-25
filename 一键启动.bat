@echo off
chcp 65001 >nul
set "PYTHONUTF8=1"
cd /d "%~dp0"
rem DOAXVV one-click start: launch tray app via pythonw (no console window), works from any cwd
rem   tray app runs server+probe(hidden)+hosts in background, hides to system tray
start "" pythonw "%~dp0tray_app.py"
