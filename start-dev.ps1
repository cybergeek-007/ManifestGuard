param(
    [switch]$Detached
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$frontend = Join-Path $root "frontend"
$npmCmd = "C:\Program Files\nodejs\npm.cmd"

if (-not (Test-Path $npmCmd)) {
    throw "npm.cmd was not found at $npmCmd"
}

Write-Host "ManifestGuard v2 dev launcher" -ForegroundColor Cyan
Write-Host "Backend:  http://127.0.0.1:8000" -ForegroundColor DarkGray
Write-Host "Frontend: http://127.0.0.1:5173" -ForegroundColor DarkGray

if ($Detached) {
    & (Join-Path $root "start-backend.ps1") -Detached -WaitForHealth
    Start-Process powershell -WorkingDirectory $frontend -ArgumentList "-NoExit", "-Command", "& '$npmCmd' run dev"
    Write-Host "Started backend and frontend in separate PowerShell windows." -ForegroundColor Green
    exit 0
}

Write-Host ""
Write-Host "Run these in separate terminals:" -ForegroundColor Yellow
Write-Host "  1. cd $root ; .\start-backend.ps1"
Write-Host "  2. cd $frontend ; & '$npmCmd' run dev"
