# BDFR Sentinel

BDFR Sentinel is a modular Windows endpoint security platform written primarily in Rust.

## Goals

- Real-time file monitoring
- YARA-based detection
- Secure quarantine
- Behavioral analysis
- PE/static analysis
- Signed update pipeline
- Windows service integration
- Future Minifilter, ETW and AMSI integrations

## Workspace

```text
crates/
  sentinel-core/
  sentinel-realtime/
  sentinel-quarantine/
  sentinel-updater/
  sentinel-yara/
  sentinel-pe/
docs/
```

## Status

Early bootstrap / architecture phase.

## Build

```powershell
cargo build --workspace
cargo test --workspace
```

## Security

This project is experimental and not yet suitable for production endpoint protection.
