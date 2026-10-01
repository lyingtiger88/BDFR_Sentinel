# BDFR Sentinel System Protection

## Protection stack

The Windows protection stack is split between a user-mode Windows service and an optional File System Minifilter.

### Always-on Windows service

`bdfr-sentinel-service.exe` installs as the **BDFR Sentinel Protection Service** with automatic startup.

The service currently integrates:

- real-time file create/modify/rename monitoring;
- the core multi-engine file scanner;
- automatic encrypted quarantine for confirmed malicious verdicts;
- Windows AMSI scanning for script content;
- process start/exit telemetry;
- ETW process-start telemetry with a polling fallback;
- registry Run/RunOnce persistence monitoring;
- executable+writable (RWX) memory-region inspection;
- behavior-signal correlation;
- signed/staged definition update activation;
- optional Minifilter broker communication.

### Pre-execution Minifilter

The source in `drivers/minifilter/` registers a File System Minifilter pre-create callback. For user-mode `FILE_EXECUTE` requests it sends a versioned request to the Sentinel service through:

```text
\BDFRSentinelPort
```

The service scans the requested image and replies Allow/Block.

The kernel path is deliberately **fail-open**. If the service is unavailable, communication fails, the protocol is invalid, or the synchronous request times out, the driver allows the operation. This prevents a protection-engine failure from making Windows unusable.

## Installing the test protection stack

From an elevated PowerShell prompt in the extracted test-build folder:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-Protection.ps1
```

The script installs the Windows service and starts it.

If a built and appropriately signed `BDFRSentinelFilter.sys` exists next to the packaged INF in the `minifilter` folder, the installer also attempts to install and load the Minifilter.

## Driver build

The repository includes:

```powershell
.\scripts\Build-Minifilter.ps1
```

Building the kernel driver requires Visual Studio C++ plus a compatible Windows Driver Kit (WDK). Microsoft documents WDK installation through WinGet and WDK NuGet packages for automated builds.

## Driver signing and altitude

A public production Minifilter cannot simply ship with the development INF unchanged.

Production deployment requires external Microsoft/Windows ecosystem steps, including:

- an appropriate signed driver package;
- normal current Windows driver-signing requirements;
- a Microsoft-assigned Minifilter altitude rather than the development placeholder.

These are distribution/signing prerequisites rather than missing scanner logic. The repository already contains the kernel callback, communication protocol, user-mode broker, scan policy and fail-open enforcement path.

## Status reporting

The protection service writes its current component state to:

```text
%ProgramData%\BDFR\Sentinel\status.json
```

The GUI reads this file and displays the actual status of:

- file monitoring;
- process telemetry;
- registry telemetry;
- memory telemetry;
- AMSI;
- ETW;
- Minifilter connectivity.

## Security policy

BDFR Sentinel is an anti-malware product, not anti-piracy software. Crack or license-bypass classifications alone are non-actionable under the default detection policy. Independent malware findings remain actionable.
