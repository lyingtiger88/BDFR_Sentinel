# soban — Debian and Android Platform Parity

## Goal
Keep Windows as the reference implementation and bring Debian GNU/Linux and Android forward against the same versioned security-core contracts. Platform ports must not pretend to have kernel privileges or visibility that the operating system does not grant.

## Repository baseline inspected
- The workspace is Rust and already has portable candidates: sentinel-core, sentinel-definitions, sentinel-updater, sentinel-quarantine, sentinel-realtime and sentinel-network.
- sentinel-realtime uses notify, which can use inotify on Linux; it is event-driven observation, not pre-execution kernel interception.
- sentinel-network currently implements kernel enforcement only under cfg(windows) (WFP). Its non-Windows connection query currently returns an empty list; this must be replaced by a real Linux backend before reporting network protection as active.
- The existing GUI and Windows service contain Windows-specific paths, APIs and service-control code. They must remain Windows-specific rather than being made to compile by weakening protections.
- Windows remains the feature reference. This branch does not change the Windows release pipeline.

## Target architecture
```
                  sentinel-core contracts
  scan / verdict / policy / definitions / update verification
             / quarantine metadata / events
                         |
          +--------------+----------------+
          |              |                |
      Windows         Debian           Android
      WFP/ETW/       systemd +         Android app
      AMSI/NTFS      inotify/fanotify   scoped storage
      service        procfs/udev       SAF + JNI
          |              |                |
          +-------- shared signed definitions --------+
```

## Feature contract
| Capability | Windows reference | Debian target | Android target |
|---|---|---|---|
| On-demand scan | Full local scan | Accessible filesystem scan, privilege-aware roots | User-selected files/media via Storage Access Framework |
| Realtime files | Windows watcher + minifilter integration | inotify initially; fanotify permission events only after privileged helper review | App-scoped imports/downloads/media; no cross-app surveillance |
| Detection | Hashes, YARA-X, PE and behavior engines | Shared hashes/YARA-X; ELF/script/package metadata | Shared hashes/YARA-X where ABI and memory budgets permit; APK/DEX/ELF metadata |
| Quarantine | Protected store | Root-owned store, atomic move, metadata and restore | App-private encrypted store; user-directed export/restore |
| Ransomware defense | Windows behavior signals and hooks | Change-burst heuristics, /proc attribution; optional fanotify deny path after safety review | Detect suspicious changes only within accessible scope |
| Process telemetry | ETW/process APIs | /proc, proc connector where available; eBPF optional and capability-gated | Own-process telemetry and permitted APIs only |
| Network | WFP | nftables backend, explicit opt-in and rollback-safe rules | Optional VPNService; metadata-level filtering only |
| Removable media | Windows removable-device integration | udev/mount monitoring | USB Host API for explicitly attached devices |
| Updates | Signed manifest and staged update | Same Ed25519 verification and staged atomic update | Same signed definitions; app binaries via Android package manager |

## Debian implementation plan
1. Keep scanner, policy, definitions, updater and quarantine contracts shared. Add Linux adapters separately; never pull Windows service/WFP APIs into Linux builds.
2. systemd unit with least privilege, dedicated bdfr-sentinel account, explicit capabilities, hardened filesystem settings and journald logging.
3. inotify-backed watch roots with event coalescing, bounded queues, exclusions and backpressure. Add fanotify permission mode only after failure-mode, deadlock and fail-open/fail-closed review.
4. /proc attribution, file-change burst scoring and safe response policy. Never kill processes solely from a heuristic score.
5. nftables backend with a Sentinel-owned table/chain namespace, transactional apply, dry-run, backup and timed rollback; never flush user firewall tables.
6. Debian package metadata, systemd unit, tmpfiles/sysusers, uninstall/rollback scripts and signed repository metadata.
7. Static analysis, unit/integration tests, package lint, service sandbox review and Debian stable validation. No build/test until authorized.

## Android implementation plan
1. Kotlin owns lifecycle, permissions, document URIs, notifications and UI. Rust owns byte scanning, shared policy, hash/YARA engines and signed definition verification through a narrow JNI interface.
2. Dashboard, manual scan, history, quarantine, definitions/update status, settings and About; offline-first.
3. Use Storage Access Framework and MediaStore. Persist URI grants only after explicit user choice. Never request broad storage access as a shortcut.
4. Scan user-selected files and app-controlled imports. UI must state scoped coverage; Android is not a device-wide desktop antivirus.
5. App-private quarantine, integrity metadata and reversible restore. Destructive deletion requires confirmation.
6. Optional VPNService is opt-in and initially handles domain/IP/reputation metadata only. No TLS decryption or inspection of other apps' private data.
7. Android signing and app updates remain under the package manager/distribution channel; signed malware definitions use the shared updater.

## Security invariants
- A feature is Active only after its backend reports successful initialization and real enforcement/monitoring.
- Permission denial, unsupported kernels, missing capabilities, SELinux restrictions and unavailable APIs produce Limited/Unavailable, never a green status.
- Definition updates require Ed25519 verification, hash validation, version/rollback checks and atomic activation.
- Quarantine must resist symlink/path traversal, be integrity-checked and recoverable.
- No silent firewall replacement, blanket privilege escalation, root requirement on Android, or automatic destructive response based only on heuristics.
- Windows-only crates remain gated; Linux and Android get native adapters.
- No parity claim until feature matrix, tests and threat-model review support it.

## Current branch scope
This branch now includes: a Linux scan/watch CLI using the shared hash and YARA-X engines; conservative Linux capability discovery; an opt-in nftables blocklist isolated to the bdfr_sentinel table; explicit encrypted quarantine/restore commands with owner-only key storage and no-replace restore semantics; an Android Kotlin SAF shell; a Rust JNI buffer-scanning bridge; and a shared bounded in-memory scan API. Neither port is yet at full Windows parity. Debian still needs systemd lifecycle, signed updater wiring, full process/ransomware telemetry, broader firewall policy and packaging. Android still needs native ABI packaging, signed-definition installation/verification, Android Keystore quarantine, full UI/history/settings and background/VPN integrations.


## Three-platform feature parity tracker

This matrix is the source of truth for feature requests that must be carried across all three targets. Statuses describe source implementation only; no runtime validation is implied where builds/tests have not been authorized.

| Feature area | Windows | Debian | Android |
|---|---|---|---|
| Shared scan/verdict contracts | Implemented | Implemented via shared core | Implemented via bounded JNI buffer API; integration needs validation |
| On-demand scan | Reference implementation | Implemented in CLI; needs validation | Limited; SAF flow and JNI source exist, native ABI not packaged |
| Hash/YARA detection | Reference implementation | Implemented against shared engines; needs validation | Bridge loads shared engines; definitions installation/verification integration pending |
| Realtime file protection | Windows-specific implementation | Limited to post-write watcher; no pre-execution blocking | Planned/limited to app-scoped access |
| Quarantine/restore | Reference implementation | CLI integration and Linux key adapter implemented; needs validation | Planned; Android Keystore adapter pending |
| Network protection | WFP reference implementation | Initial isolated nftables blocklist backend; needs validation | Planned; optional VPNService integration pending |
| Process/behavior telemetry | Reference implementation | Planned; procfs/eBPF integrations pending | Limited by Android sandbox; own-app scope initially |
| Ransomware protection | Reference implementation | Planned | Limited/planned |
| Signed definition updates | Shared updater reference | Integration pending | Integration pending |
| Service/app lifecycle | Windows service | systemd service pending | Android lifecycle shell present; full background work pending |
| UI and history | Soban desktop UI: theme/language selector and themed artwork updated; full localization pending | CLI only; locale catalog present, desktop UI pending | SAF scan screen with theme/language selectors and localized scan entry; full dashboard/history pending |
| License/entitlement | Reference behavior | Integration pending | Integration pending |

### Mandatory propagation checklist

For every subsequent feature request, update all three columns in the same work cycle. If a feature cannot be provided on one platform, document the OS reason, expose a Limited/Unavailable state and track the closest safe alternative. Never silently omit a platform.

## Build policy
Do not run cargo build, cargo test, Gradle build, APK packaging, Debian packaging or any GitHub Actions workflow until the user explicitly authorizes a build. Source inspection and non-build review are permitted.


## Soban visual themes and localization

- Product display name: **Soban** (English) and **سوبان** (Persian).
- Windows/desktop egui theme model now supports wallpaper style, icon stroke style, illustration style, typography scale and control scale in addition to color palette.
- Android includes selectable visual presets that change the surface palette and guardian mark, plus persistent language selection.
- Language packs are supplied for English, Persian, Balochi, Kurdish Sorani, Arabic, German, French and Spanish.
- Current translation coverage is an initial UI slice (navigation, appearance/language labels and Android scan entry screen), not yet every dialog, alert, report and settings field.
- Balochi and Kurdish Sorani strings are first drafts and require native-speaker review before production release. Kurdish is Sorani (ckb); Balochi is represented by a generic Latin/Arabic script draft and needs dialect/script selection review.
- Debian currently has a CLI rather than a completed desktop interface; the locale packs are present but CLI-wide localization is not yet wired.
