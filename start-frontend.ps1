$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$frontend = Join-Path $root "frontend"
$npmCmd = "C:\Program Files\nodejs\npm.cmd"

if (-not (Test-Path $npmCmd)) {
    throw "npm.cmd was not found at $npmCmd"
}

Set-Location $frontend
& $npmCmd run dev
