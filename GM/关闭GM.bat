@echo off
rem ============================================
rem  DOAXVV GM Panel - close and cleanup
rem  Stops game server (port 443) + kills python
rem  Location: DOAXVV_Server\GM\
rem ============================================
cd /d "%~dp0"

echo [*] Stopping DOAXVV game server...

rem 1. Kill process listening on 443
set "KILLED=0"
for /f "tokens=5" %%a in ('netstat -ano ^| findstr "LISTENING" ^| findstr ":443"') do (
    echo    found server PID: %%a
    taskkill /f /pid %%a >nul 2>&1
    set "KILLED=1"
)

rem 2. Kill any python running local_server_v2
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'python' -and $_.CommandLine -match 'local_server_v2' } | ForEach-Object { Write-Host ('    killing python PID: ' + $_.ProcessId); taskkill /f /pid $_.ProcessId | Out-Null }"

timeout /t 2 /nobreak >nul

rem 3. Verify port is free
netstat -ano | findstr "LISTENING" | findstr ":443" >nul 2>&1
if errorlevel 1 (
    echo.
    echo [OK] Game server fully stopped.
    echo [*] Port 443 is now free.
) else (
    echo.
    echo [WARN] Port 443 still in use - may need manual taskkill
)

echo.
echo [*] Please close the GM browser tab manually.
echo [*] To restart: run the start bat in this folder
echo.
pause
