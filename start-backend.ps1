param(
    [switch]$Detached,
    [switch]$WaitForHealth,
    [string]$Host = "127.0.0.1",
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$healthUrl = "http://${Host}:${Port}/api/health"
$command = "python -m backend.serve --host $Host --port $Port"

function Wait-ForHealth {
    param([string]$Url)

    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-RestMethod -Uri $Url -Method Get -TimeoutSec 2
            if ($response.status -eq "ok") {
                Write-Host "Backend healthy at $Url" -ForegroundColor Green
                return
            }
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }

    throw "Backend did not become healthy within 20 seconds: $Url"
}

Set-Location $root

if ($Detached) {
    Start-Process powershell -WorkingDirectory $root -ArgumentList "-NoExit", "-Command", $command | Out-Null
    if ($WaitForHealth) {
        Wait-ForHealth -Url $healthUrl
    } else {
        Write-Host "Started backend in a separate PowerShell window." -ForegroundColor Green
    }
    exit 0
}

if ($WaitForHealth) {
    $job = Start-Job -ScriptBlock {
        param($WorkingDirectory, $Cmd)
        Set-Location $WorkingDirectory
        Invoke-Expression $Cmd
    } -ArgumentList $root, $command
    try {
        Wait-ForHealth -Url $healthUrl
        Write-Host "Backend is running in job $($job.Id)." -ForegroundColor Green
        Write-Host "Stop it with: Stop-Job -Id $($job.Id); Remove-Job -Id $($job.Id)" -ForegroundColor Yellow
        Wait-Job -Id $job.Id | Out-Null
        Receive-Job -Id $job.Id
    } finally {
        if ($job.State -ne "Running") {
            Receive-Job -Id $job.Id -ErrorAction SilentlyContinue | Out-Null
            Remove-Job -Id $job.Id -Force -ErrorAction SilentlyContinue
        }
    }
    exit 0
}

Invoke-Expression $command
