@echo off
setlocal
chcp 65001 >nul
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
pushd "%~dp0"

rem === Server-only start (no tray / clamp / probe). ===
rem === For full auto start, use the one-click script instead. ===
rem Keep this window open while playing; closing it stops the server.

call "%~dp0_python_env.bat"
if not defined PY_EXE (
    echo [ERROR] No usable Python found.
    echo         Need Python 3.10+ with the "cryptography" package.
    echo         Tried: .venv, %ProgramFiles%\Python312, and every python on PATH.
    echo         Fix:  "%ProgramFiles%\Python312\python.exe" -m pip install cryptography
    echo.
    pause
    popd
    exit /b 1
)
echo [*] Python: %PY_EXE%

netstat -ano | findstr /C:"LISTENING" | findstr /C:":443 " >nul 2>&1
if not errorlevel 1 (
    echo [WARN] Port 443 is already in use.
    echo        Close the other server first, or press any key to try anyway.
    echo.
    pause >nul
)

"%PY_EXE%" -u "%~dp0local_server\local_server_v2.py"

echo.
echo [Server exited] - press any key to close this window.
pause >nul
popd
endlocal
