@echo off
cd /d "%~dp0"
echo [*] Stopping DOAXVV server...

rem 1. Kill local_server_v2.py
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'python' -and $_.CommandLine -match 'local_server_v2' } | ForEach-Object { taskkill /F /PID $_.ProcessId 2>$null }; Write-Host '  Server process: stopped'"

rem 2. Kill 443 listener
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { taskkill /F /PID $_.OwningProcess 2>$null }; Write-Host '  Port 443: released'"

timeout /t 2 >nul
echo [OK] Server stopped
