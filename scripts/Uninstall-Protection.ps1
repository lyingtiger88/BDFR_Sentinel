$ErrorActionPreference = "Continue"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session."
    }
}

Assert-Admin

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$serviceExe = Join-Path $root "bdfr-sentinel-service.exe"

Write-Host "Stopping minifilter if present..."
fltmc.exe unload BDFRSentinelFilter 2>$null | Out-Host

if (Test-Path $serviceExe) {
    Write-Host "Stopping BDFR Sentinel service..."
    & $serviceExe stop 2>$null

    Write-Host "Removing BDFR Sentinel service..."
    & $serviceExe uninstall
}

Write-Host "BDFR Sentinel protection components removed."
