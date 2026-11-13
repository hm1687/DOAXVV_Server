@echo off
setlocal EnableDelayedExpansion
title DOAXVV server status / switch

rem ============================================================
rem  DOAXVV server switch - status + start/stop in ONE script
rem    1 = start server (local_server_v2.py in its OWN window)
rem    2 = stop server  (kill local_server_v2 + port 443 listener)
rem    No choice within 15s -> switch to the OPPOSITE state.
rem    Closing the window while waiting -> keep the current state.
rem    After the switch, this window closes within 5 seconds.
rem  Scope: SERVER ONLY. Does NOT touch tray / hosts / time offset.
rem    For a full shutdown use the one-click stop bat (stop_all.py).
rem  Backend: _python_env.bat (interpreter) + local_server_v2.py.
rem  Colors: status line via Write-Host, no ANSI / VT needed.
rem ============================================================

set "PY_ENV=%~dp0_python_env.bat"
set "ENTRY=%~dp0local_server\local_server_v2.py"

echo === server state ===
rem ---- 1. detect current state by port 443 listener ----
call :PROBE
set "CUR=STOPPED"
set "DEF=1"
if defined PID443 (
    set "CUR=RUNNING"
    set "DEF=2"
)

rem RUNNING = cyan line / green "running"; STOPPED = yellow line / red "stopped"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s='%CUR%'; if($s -eq 'RUNNING'){Write-Host -NoNewline '[RUNNING] server listening on 127.0.0.1:443 -> ' -ForegroundColor Cyan; Write-Host 'running' -ForegroundColor Green} else {Write-Host -NoNewline '[STOPPED] no listener on 127.0.0.1:443 -> ' -ForegroundColor Yellow; Write-Host 'stopped' -ForegroundColor Red}; [Console]::ResetColor()"
if not errorlevel 1 goto PS_OK
if "%CUR%"=="RUNNING" echo [RUNNING] server listening on 127.0.0.1:443 -^> running
if "%CUR%"=="STOPPED" echo [STOPPED] no listener on 127.0.0.1:443 -^> stopped
:PS_OK
if defined PID443 echo     PID: !PID443! ^(close the server window, or choose 2 to stop^)

echo === server switch ===
echo 1.start server
echo 2.stop server
echo If no selection is made within 15 seconds, it will switch to the opposite state; closing the window will keep the current state.
echo Select 1 or 2 ^(auto in 15s, default: %DEF%^):

rem ---- 2. wait; /D is the opposite of the current state ----
choice /C 12 /N /T 15 /D %DEF% >nul
if errorlevel 2 (
    set "ACT=stop"
    set "WANT=STOPPED"
) else (
    set "ACT=start"
    set "WANT=RUNNING"
)
echo.
echo ^>^> switching to %ACT% ...

rem ---- 3. apply ----
if "%ACT%"=="start" goto DO_START
goto DO_STOP

:DO_START
call :PROBE
if defined PID443 (
    echo     Server already running ^(PID !PID443!^); nothing to start.
    goto VERIFY
)
if not exist "%PY_ENV%" (
    echo [ERROR] _python_env.bat not found next to this script.
    goto VERIFY
)
call "%PY_ENV%"
if not defined PY_EXE (
    echo [ERROR] No usable Python found ^(need 3.10+ with cryptography^).
    goto VERIFY
)
echo     Python: !PY_EXE!
start "DOAXVV Server" /D "%~dp0" "!PY_EXE!" -u "%ENTRY%"
echo     Server window opened; close that window to stop the server.
echo     Waiting for port 443 ^(up to 10s^)...
set "TRIES=0"
:WAIT_LOOP
ping -n 2 127.0.0.1 >nul
call :PROBE
if defined PID443 goto VERIFY
set /a TRIES+=1
if !TRIES! GEQ 10 goto VERIFY
echo     waiting... !TRIES!/10
goto WAIT_LOOP

:DO_STOP
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'python' -and $_.CommandLine -match 'local_server_v2' } | ForEach-Object { taskkill /F /PID $_.ProcessId 2>$null }; Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { taskkill /F /PID $_.OwningProcess 2>$null }"
ping -n 3 127.0.0.1 >nul
goto VERIFY

rem ---- 4. verify by probing port 443 again ----
:VERIFY
call :PROBE
set "NOW=STOPPED"
if defined PID443 set "NOW=RUNNING"
if "!NOW!"=="!WANT!" (
    echo [OK] server state is now: !NOW!
) else (
    echo [FAILED] server state unchanged ^(see messages above^); state: !NOW!
)

rem ---- 5. close within 5s (any key closes sooner) ----
echo.
echo This window will close in 5 seconds ^(press any key to close now^)...
timeout /t 5 >nul 2>&1
exit /b 0

rem ---- subroutine: probe port 443 listener, sets PID443 (empty = none) ----
:PROBE
set "PID443="
for /f "tokens=5" %%a in ('netstat -ano ^| findstr /C:"LISTENING" ^| findstr /C:":443 "') do (
    if "!PID443!"=="" set "PID443=%%a"
)
goto :eof
