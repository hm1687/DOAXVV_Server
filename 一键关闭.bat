@echo off
setlocal
chcp 65001 >nul
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
pushd "%~dp0"

rem DOAXVV one-click stop: kill tray + server, restore hosts.
rem No keypress on success (double-click closes by itself); pause only on error.

call "%~dp0_python_env.bat"
if not defined PY_EXE (
    echo [ERROR] No usable Python found, cannot run stop_all.py.
    pause
    popd
    exit /b 1
)

"%PY_EXE%" "%~dp0stop_all.py" %*
if errorlevel 1 pause
popd
endlocal
