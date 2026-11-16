# soban for Debian

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

The Linux port currently has a definition-backed CLI for on-demand file/directory scanning and post-write realtime watch events, conservative host capability discovery, explicit encrypted quarantine/restore commands, and an opt-in nftables backend that only creates/removes the dedicated bdfr_sentinel table. Linux quarantine keys are owner-only and restores use no-replace rename semantics. Firewall changes require root and are never applied automatically. This is not yet a complete service: systemd lifecycle, signed updater wiring, richer process/ransomware telemetry, full Debian packaging and the desktop GUI remain open.
