param(
    [switch]$SkipDriver,
    [string]$InstallDir = (Join-Path $env:ProgramFiles "BDFR Sentinel")
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session."
    }
}

function Grant-ReadExecuteToUsers([string]$Path) {
    icacls.exe $Path /inheritance:r | Out-Null
    icacls.exe $Path /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" | Out-Null
}

Assert-Admin

$sourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourceService = Join-Path $sourceRoot "bdfr-sentinel-service.exe"
$sourceGui = Join-Path $sourceRoot "bdfr-sentinel-gui.exe"
$sourceCli = Join-Path $sourceRoot "bdfr-sentinel.exe"

if (-not (Test-Path $sourceService)) {
    throw "bdfr-sentinel-service.exe was not found next to this installer."
}

$existingService = Get-Service -Name "BDFRSentinel" -ErrorAction SilentlyContinue
if ($existingService) {
    $existingBinary = (Get-CimInstance Win32_Service -Filter "Name='BDFRSentinel'").PathName.Trim('"')
    if (Test-Path $existingBinary) {
        try { & $existingBinary stop 2>$null } catch {}
        try { & $existingBinary uninstall 2>$null } catch {}
    }
}

Write-Host "Installing application files to $InstallDir ..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $sourceService (Join-Path $InstallDir "bdfr-sentinel-service.exe") -Force
if (Test-Path $sourceGui) { Copy-Item $sourceGui (Join-Path $InstallDir "bdfr-sentinel-gui.exe") -Force }
if (Test-Path $sourceCli) { Copy-Item $sourceCli (Join-Path $InstallDir "bdfr-sentinel.exe") -Force }

$sourceDefinitions = Join-Path $sourceRoot "Definitions"
if (Test-Path $sourceDefinitions) {
    Copy-Item $sourceDefinitions (Join-Path $InstallDir "Definitions") -Recurse -Force
}

Grant-ReadExecuteToUsers $InstallDir

$programData = Join-Path $env:ProgramData "BDFR\Sentinel"
New-Item -ItemType Directory -Force -Path $programData | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $programData "Definitions") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $programData "Quarantine") | Out-Null
Grant-ReadExecuteToUsers $programData

# SYSTEM and Administrators retain write control. The service runs as LocalSystem.
icacls.exe (Join-Path $programData "Quarantine") /inheritance:r | Out-Null
icacls.exe (Join-Path $programData "Quarantine") /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

if (Test-Path (Join-Path $InstallDir "Definitions")) {
    Copy-Item (Join-Path $InstallDir "Definitions\*") (Join-Path $programData "Definitions") -Recurse -Force
}

$serviceExe = Join-Path $InstallDir "bdfr-sentinel-service.exe"
Write-Host "Installing BDFR Sentinel protection service..."
& $serviceExe install

Write-Host "Starting BDFR Sentinel protection service..."
& $serviceExe start

$startMenu = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
$shortcutPath = Join-Path $startMenu "BDFR Sentinel.lnk"
if (Test-Path (Join-Path $InstallDir "bdfr-sentinel-gui.exe")) {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = Join-Path $InstallDir "bdfr-sentinel-gui.exe"
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.Description = "BDFR Sentinel Endpoint Security"
    $shortcut.Save()
}

if (-not $SkipDriver) {
    $driverDir = Join-Path $sourceRoot "minifilter"
    $sys = Join-Path $driverDir "BDFRSentinelFilter.sys"
    $inf = Join-Path $driverDir "BDFRSentinelFilter.inf"

    if ((Test-Path $sys) -and (Test-Path $inf)) {
        Write-Host "Installing minifilter driver package..."
        pnputil.exe /add-driver $inf /install | Out-Host
        Write-Host "Starting minifilter..."
        fltmc.exe load BDFRSentinelFilter | Out-Host
    }
    else {
        Write-Warning "No signed/test-signed BDFRSentinelFilter.sys is included. User-mode protection remains active."
    }
}

Write-Host ""
Write-Host "BDFR Sentinel installation complete."
Write-Host "Installed path: $InstallDir"
Write-Host "Open BDFR Sentinel from the Start menu."
