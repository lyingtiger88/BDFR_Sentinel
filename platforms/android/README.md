# soban for Android

Android is a companion endpoint-security app backed by the shared Rust detection core. It is not a device-wide antivirus: scoped storage, app sandboxing and background execution limits define coverage.

Initial surfaces: protection dashboard with accurate permission/coverage state; user-initiated SAF scan; results/history; app-private quarantine and restore; signed definition status; settings and About.

Native boundary:
- Kotlin owns lifecycle, permissions, document URIs, notifications and UI.
- Rust owns byte scanning, detection policy, hash/YARA engines and signed definition verification.
- JNI calls are bounded, cancellation-aware and return structured errors.
- Pass file descriptors or bounded byte streams; never guess filesystem paths from content URIs.
- Scan off the main thread.

Out of scope: root-only device scanning, silent access to other apps' private data, TLS interception, accessibility-service abuse and automatic deletion based only on heuristics.

The Android project skeleton and JNI scanner entry point are separate from the Windows GUI and service. The Rust JNI bridge accepts bounded byte arrays supplied by the SAF host and refuses to return a clean verdict unless usable definitions are installed in the app-private verified-definitions directory. The current app disables scanning until the ABI-matched native library is packaged. The JNI bridge assumes the app updater has already verified the definitions; signature verification is not implemented in the Android app yet, so unverified files must not be placed in that directory. ABI packaging (for example, via cargo-ndk into app/src/main/jniLibs), signed-definition installation/verification, full dashboard/history/settings UI, Android Keystore-backed quarantine, scheduled/background scans and VPNService remain open. No Android build has been run.


## Branding, themes and languages

The Android shell uses the product display name **Soban**. It offers five visual presets (Soban Default, Obsidian, Arctic, Graphite and High Contrast) that alter the surface palette and guardian mark, not only an accent swatch. Language choice is persisted across launches: English, Persian, Balochi, Kurdish Sorani, Arabic, German, French and Spanish. RTL direction is enabled for Persian, Sorani Kurdish and Arabic. Balochi and Sorani wording is provisional and needs native-speaker review. Translation coverage currently focuses on the scan entry screen; full screen/dialog coverage remains open.
