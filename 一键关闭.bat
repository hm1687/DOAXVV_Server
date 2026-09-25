@echo off
chcp 65001 >nul
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
cd /d "%~dp0"
rem DOAXVV one-click stop: kill tray+server+probe+hosts+offset, works from any cwd
python "%~dp0stop_all.py"
pause
