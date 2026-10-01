# BDFR Sentinel Minifilter

This directory contains the Windows File System Minifilter used for pre-execution policy enforcement.

## Current policy path

```text
Process requests FILE_EXECUTE
        |
        v
BDFRSentinelFilter (pre-create)
        |
        v
\BDFRSentinelPort
        |
        v
BDFR Sentinel Windows service
        |
        +--> hash definitions
        +--> PE/static analysis
        +--> policy
        |
        v
Allow / Block
```

The kernel path is intentionally **fail-open**. If the user-mode service is unavailable, the port disconnects, a reply times out, or the protocol is invalid, file access is allowed. This avoids making the machine unusable because of a protection-engine failure.

The synchronous policy timeout is currently 2 seconds.

## Build requirements

- Visual Studio with Desktop C++ workload
- Windows Driver Kit (WDK)
- x64 Windows target

Create a Windows Kernel Mode Driver / Minifilter project and compile `BDFRSentinelFilter.c` with `FltMgr.lib`.

## Signing

Development machines can use Windows test signing for local driver testing. Public/production distribution requires normal Windows driver signing requirements and a Microsoft-assigned minifilter altitude.

The altitude in the included INF is a development placeholder and must not be treated as a production allocation.
