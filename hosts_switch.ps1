# ============================================================
#  DOAXVV hosts switch (unified manager)
#  Usage:
#    powershell -ExecutionPolicy Bypass -File hosts_switch.ps1 on     enable hijack (standalone -> local)
#    powershell -ExecutionPolicy Bypass -File hosts_switch.ps1 off    disable hijack (private server -> real)
#    powershell -ExecutionPolicy Bypass -File hosts_switch.ps1 status show current state
# ============================================================
param([string]$Action = "status")

$HOSTS = "C:\Windows\System32\drivers\etc\hosts"
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$BACKUP_DIR = Join-Path $SCRIPT_DIR "hosts_backup"

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin) -and ($Action -eq "on" -or $Action -eq "off")) {
    Write-Host "[Requesting admin rights - click YES on the UAC prompt]" -ForegroundColor Yellow
    $argList = "-ExecutionPolicy Bypass -File `"$PSCommandPath`" -Action $Action"
    try {
        Start-Process powershell -ArgumentList $argList -Verb RunAs -Wait -WindowStyle Hidden
    } catch {
        Write-Host "[Elevation failed or cancelled]" -ForegroundColor Red
        exit 1
    }
    exit 0
}

function Get-HostsLines {
    return [System.IO.File]::ReadAllLines($HOSTS)
}

function Set-HostsLines([string[]]$lines) {
    [System.IO.File]::WriteAllLines($HOSTS, $lines, [System.Text.Encoding]::ASCII)
}

function Backup-Hosts {
    if (-not (Test-Path $BACKUP_DIR)) { New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null }
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $dst = Join-Path $BACKUP_DIR "hosts_$ts.bak"
    Copy-Item $HOSTS $dst -Force
    Write-Host "  [hosts backed up -> $dst]" -ForegroundColor DarkGray
}

function Flush-Dns {
    ipconfig /flushdns | Out-Null
}

function Get-CurrentState {
    $content = Get-Content $HOSTS -ErrorAction SilentlyContinue
    $hijacked = $content | Where-Object { $_ -match "api\.doaxvv\.com|game\.doaxvv\.com|api01\.doaxvv\.com" }
    if ($hijacked) { return @{ Active = $true; Lines = @($hijacked) } }
    else { return @{ Active = $false; Lines = @() } }
}

switch ($Action.ToLower()) {
    "on" {
        Write-Host "=== ENABLE hijack: standalone -> local server ===" -ForegroundColor Cyan
        # 2026-09-10: 劫持列表扩展 — 补上启动器后端 api01.doaxvv.com (维护/版本检查)
        $required = @("api.doaxvv.com", "game.doaxvv.com", "api01.doaxvv.com")
        $content = Get-Content $HOSTS -ErrorAction SilentlyContinue
        $missing = @($required | Where-Object {
            $h = $_
            -not ($content | Where-Object { $_ -match ("^\s*127\.0\.0\.1\s+" + [regex]::Escape($h) + "\s*$") })
        })
        if ($missing.Count -eq 0) {
            Write-Host "  [Already hijacked, nothing to do]" -ForegroundColor Yellow
        } else {
            Backup-Hosts
            $lines = @(Get-HostsLines | Where-Object { $_ -notmatch "doaxvv\.com" })
            $lines += "127.0.0.1 api.doaxvv.com"
            $lines += "127.0.0.1 game.doaxvv.com"
            $lines += "127.0.0.1 api01.doaxvv.com"
            Set-HostsLines $lines
            Flush-Dns
            Write-Host "  [OK] Enabled: 127.0.0.1 api.doaxvv.com" -ForegroundColor Green
            Write-Host "  [OK] Enabled: 127.0.0.1 game.doaxvv.com" -ForegroundColor Green
            Write-Host "  [OK] Enabled: 127.0.0.1 api01.doaxvv.com  (launcher backend)" -ForegroundColor Green
            Write-Host "  Now start the STANDALONE game -> goes to local server" -ForegroundColor White
        }
    }
    "off" {
        Write-Host "=== DISABLE hijack: private server -> real server ===" -ForegroundColor Cyan
        $st = Get-CurrentState
        if (-not $st.Active) {
            Write-Host "  [Not hijacked, nothing to do]" -ForegroundColor Yellow
        } else {
            Backup-Hosts
            $lines = @(Get-HostsLines | Where-Object { $_ -notmatch "doaxvv\.com" })
            Set-HostsLines $lines
            Flush-Dns
            Write-Host "  [OK] Removed doaxvv hijack, hosts restored" -ForegroundColor Green
            Write-Host "  Private server can now connect to the real server" -ForegroundColor White
        }
    }
    "status" {
        Write-Host "=== hosts state ===" -ForegroundColor Cyan
        $st = Get-CurrentState
        if ($st.Active) {
            Write-Host "  [HIJACKED] standalone -> local" -ForegroundColor Yellow
            $st.Lines | ForEach-Object { Write-Host "     $_" }
        } else {
            Write-Host "  [PASS-THROUGH] private server -> real" -ForegroundColor Green
        }
    }
    default {
        Write-Host "Usage: hosts_switch.ps1 [on|off|status]" -ForegroundColor Yellow
    }
}