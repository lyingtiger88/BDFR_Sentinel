# BDFR Sentinel Roadmap

## Phase 0 — Bootstrap
- [x] Cargo workspace
- [x] Core module skeletons
- [x] CI build/test workflow
- [ ] Architecture decision records
- [ ] Threat model

## Phase 1 — Safe MVP
- [x] Core scan orchestration
- [x] YARA engine abstraction
- [x] Real-time filesystem monitor
- [x] Secure quarantine
- [x] Signed update manifests
- [ ] PE metadata analyzer
- [ ] Windows service host
- [ ] Structured logging
- [x] Detection policy separating malware from crack/license-bypass classifications
- [x] Multi-source definition provider architecture

## Phase 2 — Endpoint Telemetry
- [ ] ETW event ingestion
- [ ] Process tree tracking
- [ ] Registry telemetry
- [ ] Persistence detection
- [ ] AMSI integration

## Phase 3 — Kernel Protection
- [ ] Windows Minifilter prototype
- [ ] Pre-create / pre-execute policy path
- [ ] User-mode scan broker
- [ ] Driver signing/release workflow
- [ ] Anti-tamper controls

## Phase 4 — Detection Platform
- [ ] Event correlation engine
- [ ] Reputation service abstraction
- [ ] Ransomware heuristics
- [ ] Memory scan interfaces
- [ ] Rule packs and update channels
- [ ] Additional licensed/open definition adapters

## Phase 5 — Productization
- [ ] Tauri UI
- [ ] Installer
- [ ] Self-update
- [ ] Accessibility
- [ ] Internationalization
- [ ] Performance benchmarks
