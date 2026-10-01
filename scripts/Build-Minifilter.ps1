param(
    [ValidateSet("Release","Debug")]
    [string]$Configuration = "Release",
    [ValidateSet("x64")]
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$driverDir = Join-Path $repo "drivers\minifilter"
$project = Join-Path $driverDir "BDFRSentinelFilter.vcxproj"
$packagesConfig = Join-Path $driverDir "packages.config"
$packagesDir = Join-Path $driverDir "packages"

if (-not (Test-Path $project)) {
    throw "Minifilter project not found: $project"
}

$msbuild = Get-Command msbuild.exe -ErrorAction SilentlyContinue
if (-not $msbuild) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $install = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($install) {
            $candidate = Join-Path $install "MSBuild\Current\Bin\MSBuild.exe"
            if (Test-Path $candidate) {
                $msbuild = Get-Item $candidate
            }
        }
    }
}

if (-not $msbuild) {
    throw "MSBuild was not found. Install Visual Studio 2022 with the Desktop C++ workload."
}

if (Test-Path $packagesConfig) {
    $nuget = Get-Command nuget.exe -ErrorAction SilentlyContinue
    if (-not $nuget) {
        throw "nuget.exe was not found. Install NuGet or restore the WDK packages manually."
    }

    Write-Host "Restoring pinned WDK/SDK packages..."
    & $nuget.Source restore $packagesConfig -PackagesDirectory $packagesDir -NonInteractive
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "Building BDFR Sentinel minifilter ($Configuration/$Platform)..."
& $msbuild.FullName $project /m /p:Configuration=$Configuration /p:Platform=$Platform

$driver = Get-ChildItem (Split-Path $project) -Filter BDFRSentinelFilter.sys -Recurse |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $driver) {
    throw "Build completed but BDFRSentinelFilter.sys was not found."
}

Write-Host "Driver built: $($driver.FullName)"
Write-Warning "Windows will not load this driver unless it is appropriately test-signed or production-signed."
