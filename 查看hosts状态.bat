@echo off
setlocal EnableDelayedExpansion
title DOAXVV hosts switch

rem ============================================================
rem  DOAXVV hosts switch - status + on/off in ONE script
rem    1 = switch to local  (hijack)
rem    2 = switch to real   (restore)
rem    No choice within 15s -> switch to the OPPOSITE state.
rem    Closing the window while waiting -> keep the current state.
rem    After the switch, this window closes within 5 seconds.
rem  Backend: hosts_switch.ps1 (UAC / backup / DNS flush / status
rem  for tray_app.py and stop_all.py). Do not remove that file.
rem  Colors: the status line is printed with Write-Host, so the two
rem  states and the local / real keywords have different colors.
rem  No ANSI / VT escape sequences needed (works on any Windows console).
rem ============================================================

set "HOSTS=%windir%\System32\drivers\etc\hosts"
set "PS1=%~dp0hosts_switch.ps1"

if not exist "%PS1%" (
    echo [ERROR] hosts_switch.ps1 not found next to this script.
    echo This window will close in 5 seconds...
    timeout /t 5 /nobreak >nul 2>&1
    exit /b 1
)

rem ---- 1. detect current state (same rule as hosts_switch.ps1) ----
set "CUR=REAL"
set "DEF=1"
findstr /i /c:"doaxvv.com" "%HOSTS%" >nul 2>&1
if not errorlevel 1 (
    set "CUR=LOCAL"
    set "DEF=2"
)

echo === hosts state ===
rem HIJACKED = yellow line / red "local"; PASS-THROUGH = cyan line / green "real"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s='%CUR%'; if($s -eq 'LOCAL'){Write-Host -NoNewline '[HIJACKED] standalone -> ' -ForegroundColor Yellow; Write-Host 'local' -ForegroundColor Red} else {Write-Host -NoNewline '[PASS-THROUGH] private server -> ' -ForegroundColor Cyan; Write-Host 'real' -ForegroundColor Green}; [Console]::ResetColor()"
if not errorlevel 1 goto PS_OK
if "%CUR%"=="LOCAL" echo [HIJACKED] standalone -^> local
if "%CUR%"=="REAL" echo [PASS-THROUGH] private server -^> real
:PS_OK
if "%CUR%"=="REAL" goto SHOW_DONE
for /f "delims=" %%L in ('findstr /i /c:"doaxvv.com" "%HOSTS%"') do echo %%L
:SHOW_DONE
echo === hosts switch ===
echo 1.switch to local
echo 2.switch to real
echo If no selection is made within 15 seconds, it will switch to the opposite state; closing the window will keep the current state.
echo Select 1 or 2 ^(auto in 15s, default: %DEF%^):

rem ---- 2. wait; /D is the opposite of the current state ----
choice /C 12 /N /T 15 /D %DEF% >nul
if errorlevel 2 (
    set "ACT=off"
    set "WANT=REAL"
) else (
    set "ACT=on"
    set "WANT=LOCAL"
)
echo.
echo ^>^> switching to %ACT% ...

rem ---- 3. apply (UAC is requested here, after the choice only) ----
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" !ACT!

rem ---- 4. verify by reading hosts again ----
set "NOW=REAL"
findstr /i /c:"doaxvv.com" "%HOSTS%" >nul 2>&1
if not errorlevel 1 set "NOW=LOCAL"
if "!NOW!"=="!WANT!" (
    echo [OK] hosts state is now: !NOW!
) else (
    echo [FAILED] hosts unchanged ^(UAC cancelled or write denied^); state: !NOW!
)

rem ---- 5. close within 5s (any key closes sooner) ----
echo.
echo This window will close in 5 seconds ^(press any key to close now^)...
timeout /t 5 >nul 2>&1
exit /b 0
