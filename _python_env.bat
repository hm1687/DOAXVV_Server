@echo off
rem ============================================================
rem  Resolve a Python interpreter that can import this project's
rem  dependencies (cryptography etc.), because the first "python"
rem  on PATH may be another bundled runtime without them.
rem
rem  Usage (from a bat that already did "setlocal"):
rem      call "%~dp0_python_env.bat"
rem      "%PY_EXE%" -u "%~dp0local_server\local_server_v2.py"
rem
rem  Sets: PY_EXE  (console interpreter)
rem        PYW_EXE (windowless interpreter, for background launch)
rem  NOTE: no setlocal here on purpose - vars must reach the caller.
rem ============================================================

set "PY_EXE="
set "PYW_EXE="

call :try "%~dp0.venv\Scripts\python.exe"
if defined PY_EXE goto :eof

call :try "%ProgramFiles%\Python312\python.exe"
if defined PY_EXE goto :eof

call :try "%ProgramFiles%\Python311\python.exe"
if defined PY_EXE goto :eof

call :try "%ProgramFiles%\Python310\python.exe"
if defined PY_EXE goto :eof

for /f "delims=" %%P in ('where python 2^>nul') do (
    if not defined PY_EXE call :try "%%P"
)
goto :eof

:try
if "%~1"=="" goto :eof
if not exist "%~1" goto :eof
"%~1" -c "import cryptography" >nul 2>&1
if errorlevel 1 goto :eof
set "PY_EXE=%~1"
set "PYW_EXE=%~dp1pythonw.exe"
if not exist "%PYW_EXE%" set "PYW_EXE=%~1"
goto :eof
