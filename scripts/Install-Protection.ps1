param(
    [switch]$SkipDriver
)

$ErrorActionPreference = "Stop"

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

if (-not (Test-Path $serviceExe)) {
    throw "bdfr-sentinel-service.exe was not found next to this installer."
}

Write-Host "Installing BDFR Sentinel protection service..."
& $serviceExe install

Write-Host "Starting BDFR Sentinel protection service..."
try {
    & $serviceExe start
} catch {
    Write-Warning "Service start failed: $($_.Exception.Message)"
}

if (-not $SkipDriver) {
    $driverDir = Join-Path $root "minifilter"
    $sys = Join-Path $driverDir "BDFRSentinelFilter.sys"
    $inf = Join-Path $driverDir "BDFRSentinelFilter.inf"

    if ((Test-Path $sys) -and (Test-Path $inf)) {
        Write-Host "Installing minifilter driver package..."
        pnputil.exe /add-driver $inf /install | Out-Host

        Write-Host "Starting minifilter..."
        fltmc.exe load BDFRSentinelFilter | Out-Host
    }
    else {
        Write-Warning "No signed/test-signed BDFRSentinelFilter.sys is included. User-mode protection is active; pre-execution kernel blocking remains unavailable until the driver is built and signed."
    }
}

Write-Host ""
Write-Host "BDFR Sentinel protection installation complete."
Write-Host "Open bdfr-sentinel-gui.exe and press Refresh on the dashboard."
