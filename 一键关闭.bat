@echo off
setlocal
chcp 65001 >nul
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
pushd "%~dp0"

rem DOAXVV one-click stop: kill tray + server, restore hosts.
rem Arg "quiet" = do not wait for a keypress (used by the VBS launcher).

call "%~dp0_python_env.bat"
if not defined PY_EXE (
    echo [ERROR] No usable Python found, cannot run stop_all.py.
    if /i not "%~1"=="quiet" pause
    popd
    exit /b 1
)

"%PY_EXE%" "%~dp0stop_all.py" %2 %3
if /i not "%~1"=="quiet" pause
popd
endlocal
