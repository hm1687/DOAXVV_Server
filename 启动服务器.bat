@echo off
chcp 65001 >nul
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
cd /d "%~dp0"
rem === Pure server start (NO time clamp / NO probe) - 19:00 white-screen server-side fix test ===
rem Close this window to stop the server. If 443 is in use, close the other server first.
"C:\Program Files\Python312\python.exe" -u "%~dp0local_server\local_server_v2.py"
pause
