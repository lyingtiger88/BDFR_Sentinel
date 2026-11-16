# BDFR Sentinel for Debian

Debian packaging and service boundary for the shared Rust security core.

Planned package contents:
- bdfr-sentinel-service: systemd-managed daemon, least privilege by default.
- bdfr-sentinel: desktop console sharing Sentinel UI and policy contracts.
- /etc/bdfr-sentinel/: administrator configuration.
- /var/lib/bdfr-sentinel/: definitions, quarantine metadata and service state.
- Service logs go to journald.

Security requirements:
- Dedicated service user and group.
- systemd hardening: NoNewPrivileges, ProtectSystem, ProtectHome, PrivateTmp and restrictive device access.
- No blanket CAP_SYS_ADMIN; each optional integration documents its exact capability.
- Firewall rules live only in a Sentinel-owned nftables table and support dry-run and rollback.
- Installer/uninstaller preserves existing firewall rules and configuration backups.

The Linux port currently has a definition-backed CLI for on-demand file/directory scanning and post-write realtime watch events, plus conservative host capability discovery. The shared quarantine crate has Linux owner-only key-file support. This is not yet a complete service: systemd lifecycle, nftables enforcement, safe quarantine orchestration, signed updater wiring and Debian package scripts remain open.
