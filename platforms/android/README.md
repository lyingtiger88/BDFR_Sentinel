# BDFR Sentinel for Android

Android is a companion endpoint-security app backed by the shared Rust detection core. It is not a device-wide antivirus: scoped storage, app sandboxing and background execution limits define coverage.

Initial surfaces: protection dashboard with accurate permission/coverage state; user-initiated SAF scan; results/history; app-private quarantine and restore; signed definition status; settings and About.

Native boundary:
- Kotlin owns lifecycle, permissions, document URIs, notifications and UI.
- Rust owns byte scanning, detection policy, hash/YARA engines and signed definition verification.
- JNI calls are bounded, cancellation-aware and return structured errors.
- Pass file descriptors or bounded byte streams; never guess filesystem paths from content URIs.
- Scan off the main thread.

Out of scope: root-only device scanning, silent access to other apps' private data, TLS interception, accessibility-service abuse and automatic deletion based only on heuristics.

The Android project skeleton is separate from the Windows GUI and service.
