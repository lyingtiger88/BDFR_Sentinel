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

The Linux daemon is not yet a complete antivirus service. The native adapter crate currently provides capability discovery and path conventions only. Realtime orchestration, nftables enforcement, quarantine operations, updater wiring and Debian package scripts remain implementation tasks.
