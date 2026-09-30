# BDFR Sentinel MVP

The first tangible MVP is the `bdfr-sentinel.exe` Windows command-line application.

## Commands

### Status

```powershell
bdfr-sentinel.exe status
```

### Scan a file

```powershell
bdfr-sentinel.exe scan C:\Samples\file.exe
```

### Scan a directory

```powershell
bdfr-sentinel.exe scan C:\Downloads
```

### Add ClamAV-compatible hash definitions

```powershell
bdfr-sentinel.exe scan C:\Downloads --hdb .\definitions\main.hdb --hsb .\definitions\main.hsb
```

### Scan and quarantine confirmed malware

```powershell
bdfr-sentinel.exe scan C:\Downloads --hsb .\definitions\main.hsb --quarantine-dir C:\ProgramData\BDFR\Sentinel\Quarantine --quarantine-malware
```

Only a final `Malicious` verdict is auto-quarantined by this command. Crack and license-bypass classifications are non-actionable by the default policy and do not trigger quarantine by themselves.

### Manual quarantine

```powershell
bdfr-sentinel.exe quarantine C:\Samples\file.exe --store C:\ProgramData\BDFR\Sentinel\Quarantine
```

### Restore

```powershell
bdfr-sentinel.exe restore <UUID> --store C:\ProgramData\BDFR\Sentinel\Quarantine
```

## MVP scan pipeline

```text
File / Directory
     |
     +--> SHA-256 metadata
     |
     +--> PE structural analyzer
     |
     +--> HDB / HSB hash definition engine
     |
     +--> Detection policy
     |
     +--> Clean / Suspicious / Malicious
     |
     +--> Optional encrypted quarantine
```

The Windows artifact workflow builds a release executable and performs a `status` smoke test before packaging it.
