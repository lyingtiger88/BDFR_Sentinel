# Soban

**Soban (سوبان)** is a cross-platform endpoint-security product developed around a shared Rust detection and policy core with native Windows, Debian GNU/Linux and Android integrations.

The product name is Soban. Internal Rust crate names and the GitHub repository name remain unchanged for now to avoid breaking imports, package references, automation and repository history.

## Supported targets
- **Windows:** reference implementation and current feature baseline.
- **Debian GNU/Linux:** native service, filesystem, process and network integrations.
- **Android:** Kotlin application with a shared Rust engine through JNI and Android-scoped file access.

All three targets are developed in parallel. Every new feature or change is evaluated against all three platforms. Shared behavior and security policy remain consistent wherever operating-system permissions allow.

## Core capabilities
- On-demand and real-time file scanning, subject to platform scope.
- Hash and YARA-based detection.
- Secure quarantine and recovery.
- Behavioral and ransomware signals.
- Network protection through native platform backends.
- Signed definition updates and rollback protection.
- Platform-specific service/app lifecycle and diagnostics.

## Workspace
```text
crates/
  sentinel-core/
  sentinel-realtime/
  sentinel-quarantine/
  sentinel-updater/
  sentinel-yara/
  sentinel-definitions/
  sentinel-network/
  sentinel-linux/
  sentinel-android-ffi/
platforms/
  debian/
  android/
docs/
  PLATFORM_PARITY.md
  THREE_PLATFORM_DEVELOPMENT.md
```

## Development policy
See [Three-Platform Development Contract](docs/THREE_PLATFORM_DEVELOPMENT.md) and [Platform Parity](docs/PLATFORM_PARITY.md).

A feature is not complete merely because it exists on one operating system. Platform limitations must be explicit, and UI status must never imply protection that is not active.

## Project status
Experimental development. Not suitable for production endpoint protection until security review, builds, tests and runtime validation are completed.

## Build and validation
Builds, tests, packaging and CI workflows are run only when explicitly authorized by the project owner.
