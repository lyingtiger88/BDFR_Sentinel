# Three-Platform Development Contract

## Product rule

BDFR Sentinel is developed as one product with three first-class targets:
- Windows — existing reference implementation and compatibility baseline.
- Debian GNU/Linux — native Linux implementation.
- Android — native mobile implementation.

From this point forward, every new feature request and every change to an existing feature is a **three-platform change**. A request first defines the shared user-visible behavior and security contract, then implements or explicitly tracks the native implementation on all three platforms in the same development cycle. Do not silently implement a requested feature on only the platform where it was first mentioned.

## What must stay consistent

Across Windows, Debian and Android, keep these aligned wherever the operating system permits:
1. User-facing feature purpose, terminology, navigation and status semantics.
2. Detection policy, verdict severity, event/report schema and false-positive handling.
3. Definition format, signature verification rules, version/rollback policy and update status.
4. Quarantine semantics: identity, integrity, metadata, restore safety and audit events.
5. Settings, exclusions, schedules, notification meaning and user consent.
6. License/entitlement checks and feature availability semantics.
7. Error categories and diagnostics, including permission-denied and unsupported states.

## What must be native

Do not force one OS implementation onto another. Use platform adapters behind shared contracts:
- Windows: Windows service, filesystem/process telemetry, WFP and Windows security APIs.
- Debian: systemd, inotify/fanotify, procfs, nftables, udev and Linux capabilities.
- Android: Kotlin lifecycle, Storage Access Framework/MediaStore, JNI/Rust engine, Android Keystore and optional user-consented VPNService.

An Android limitation must not be represented as a fully active desktop-style feature. Debian features requiring root or kernel support must disclose that requirement. The Windows implementation remains intact and must not lose capability merely to make a portable abstraction compile.

## Required workflow for every feature request

1. **Capture the shared contract:** define behavior, settings, permissions, threat model, UI states, API/report shape and acceptance criteria once.
2. **Map all three targets:** identify shared-core work and Windows/Debian/Android adapters. Record any OS-specific limitation explicitly.
3. **Implement in parallel:** update shared Rust crates and all three platform adapters in the same feature branch/series. Keep platform-specific code gated and isolated.
4. **Update parity tracking:** update `docs/PLATFORM_PARITY.md` and the feature matrix with one of: Implemented, Limited, Planned, Unsupported, or Needs validation for each platform.
5. **Review regressions:** inspect the impact on all three platforms, including existing Windows behavior. Add tests for shared contracts and platform-specific behavior.
6. **Report honestly:** list files/areas changed, parity status per OS, known limitations, and any validation not performed.
7. **Build gate:** do not run builds, tests, packaging, or workflows until the user explicitly authorizes a build. Source review and static inspection are allowed.

## Completion rule

A feature request is not complete merely because one platform works. It is complete when:
- all three implementations meet the shared contract; or
- an explicit platform limitation is documented, the UI reports the correct Limited/Unavailable state, and the remaining work is tracked.

Never claim parity based only on matching screens or compiling shared code.

## Feature status vocabulary

- **Implemented:** native backend exists and its behavior has been validated.
- **Limited:** works only within documented OS permissions/capabilities or a reduced scope.
- **Planned:** contract and implementation path exist, but the backend is not implemented.
- **Unsupported:** technically or policy-incompatible with the platform; explain why and provide the closest safe alternative.
- **Needs validation:** source exists but has not been built/tested or runtime-verified.

## Branch and release discipline

- Continue platform work on feature branches; do not change `main` or merge without authorization.
- Do not delete or replace working Windows code while porting.
- Keep commits scoped and descriptive; do not mark unvalidated code as release-ready.
- No build/test/package/CI execution until explicitly requested by the user.
