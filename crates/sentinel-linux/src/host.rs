use crate::CapabilitySnapshot;
use std::process::Command;

/// Read host capabilities without changing system state.
pub fn discover_capabilities() -> CapabilitySnapshot {
    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "unknown".to_string()).trim().to_string();
    let is_root = unsafe { libc::geteuid() == 0 };
    CapabilitySnapshot {
        inotify_available: std::path::Path::new("/proc/sys/fs/inotify").exists(),
        // Presence is not proof that fanotify permission events can be initialized.
        fanotify_available: std::path::Path::new("/proc/filesystems").exists(),
        nft_available: command_exists("nft"),
        ebpf_available: std::path::Path::new("/sys/fs/bpf").exists(),
        udev_available: std::path::Path::new("/run/udev").exists(),
        is_root,
        kernel_release,
    }
}

fn command_exists(program: &str) -> bool {
    Command::new("sh")
        .args(["-c", "command -v \"$1\" >/dev/null 2>&1", "sentinel", program])
        .status().is_ok_and(|status| status.success())
}
