@echo off
setlocal enabledelayedexpansion
rem ============================================
rem  DOAXVV GM Panel - one-click start
rem  Starts game server (if not running) + opens GM panel
rem  Location: DOAXVV_Server\GM\
rem  Portable: all paths relative to this bat file
rem ============================================
cd /d "%~dp0"
set "PY=C:\Program Files\Python312\python.exe"
if not exist "!PY!" (
    echo [*] Python not found, trying python from PATH...
    set "PY=python"
)

echo [*] Checking game server on port 443...
netstat -ano | findstr "LISTENING" | findstr ":443" >nul 2>&1
if !errorlevel! neq 0 (
    echo [*] Game server not running, starting...
    start "" "!PY!" -u "%~dp0..\local_server\local_server_v2.py"
    echo [*] Waiting for server to be ready...
    set "READY=0"
    for /l %%i in (1,1,10) do (
        timeout /t 1 /nobreak >nul
        netstat -ano | findstr "LISTENING" | findstr ":443" >nul 2>&1
        if !errorlevel! equ 0 (
            echo [*] Server is listening [waited %%i s]
            set "READY=1"
            goto :ready
        )
        echo [*] Still waiting... %%i/10
    )
    if "!READY!"=="0" (
        echo.
        echo [ERROR] Server failed to start within 10 seconds.
        echo [*] Possible causes:
        echo     - Port 443 already in use by another program
        echo     - Python or dependencies not installed
        echo     - server_state.json or server_response_db.json missing
        echo.
        echo [*] Try starting the server manually:
        echo     !PY! "%~dp0..\local_server\local_server_v2.py"
        echo.
        pause
        exit /b 1
    )
) else (
    echo [*] Game server already running.
)

:ready
echo [*] Opening GM panel in browser...
powershell -NoProfile -Command "Start-Process 'https://127.0.0.1/gm/'"

echo.
echo ========================================
echo  GM Panel: https://127.0.0.1/gm/
echo  If certificate warning appears:
echo    Click Advanced then Proceed
echo  Or use https://api.doaxvv.com/gm/
echo  (requires hosts hijack active)
echo ========================================
echo  To close: run the close bat in this folder
echo.
pause
