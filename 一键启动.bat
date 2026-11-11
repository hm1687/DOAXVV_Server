@echo off
setlocal
chcp 65001 >nul
set "PYTHONUTF8=1"
pushd "%~dp0"

rem DOAXVV one-click start: launch tray app via pythonw (no console window).
rem The tray app does two jobs: hijack hosts, then start the local server.

call "%~dp0_python_env.bat"
if not defined PY_EXE (
    echo [ERROR] No usable Python found.
    echo         Need Python 3.10+ with the "cryptography" package.
    echo         Fix:  "%ProgramFiles%\Python312\python.exe" -m pip install cryptography
    echo.
    pause
    popd
    exit /b 1
)

start "" "%PYW_EXE%" "%~dp0tray_app.py"
popd
endlocal
