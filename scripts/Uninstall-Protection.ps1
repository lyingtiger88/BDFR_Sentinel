param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles "BDFR Sentinel"),
    [switch]$KeepData
)

$ErrorActionPreference = "Continue"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session."
    }
}

Assert-Admin

$sourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$installedService = Join-Path $InstallDir "bdfr-sentinel-service.exe"
$fallbackService = Join-Path $sourceRoot "bdfr-sentinel-service.exe"
$serviceExe = if (Test-Path $installedService) { $installedService } else { $fallbackService }

Write-Host "Stopping minifilter if present..."
fltmc.exe unload BDFRSentinelFilter 2>$null | Out-Host

Write-Host "Removing BDFR Sentinel network firewall rules..."
for ($i = 0; $i -lt 64; $i++) {
    netsh.exe advfirewall firewall delete rule name="BDFR Sentinel Network Block v4-$i" 2>$null | Out-Null
    netsh.exe advfirewall firewall delete rule name="BDFR Sentinel Network Block v6-$i" 2>$null | Out-Null
}


if (Test-Path $serviceExe) {
    Write-Host "Stopping BDFR Sentinel service..."
    & $serviceExe stop 2>$null

    Write-Host "Removing BDFR Sentinel service..."
    & $serviceExe uninstall 2>$null
}
else {
    sc.exe stop BDFRSentinel 2>$null | Out-Null
    sc.exe delete BDFRSentinel 2>$null | Out-Null
}

$shortcut = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\BDFR Sentinel.lnk"
Remove-Item $shortcut -Force -ErrorAction SilentlyContinue

if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not $KeepData) {
    $programData = Join-Path $env:ProgramData "BDFR\Sentinel"
    if (Test-Path $programData) {
        # Restore administrator ownership/access before deleting hardened data.
        takeown.exe /F $programData /R /D Y | Out-Null
        icacls.exe $programData /grant "Administrators:(OI)(CI)F" /T /C | Out-Null
        Remove-Item $programData -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "BDFR Sentinel protection components removed."
