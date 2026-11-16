use crate::CapabilitySnapshot;
use std::path::Path;
use std::process::Command;

/// Read host capabilities without changing system state.
pub fn discover_capabilities() -> CapabilitySnapshot {
    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();
    let is_root = unsafe { libc::geteuid() == 0 };

    CapabilitySnapshot {
        inotify_available: Path::new("/proc/sys/fs/inotify").exists(),
        // Conservative: kernel/API support is not inferred from the presence of procfs.
        // A future fanotify adapter must probe initialization and permission events directly.
        fanotify_available: Path::new("/proc/sys/fs/fanotify").exists(),
        nft_available: command_exists("nft"),
        ebpf_available: Path::new("/sys/fs/bpf").exists(),
        udev_available: Path::new("/run/udev").exists(),
        is_root,
        kernel_release,
    }
}

fn command_exists(program: &str) -> bool {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .any(|directory| {
            let candidate = directory.join(program);
            candidate.is_file()
        })
}

/// Run a read-only version query for a known system utility.
pub fn nft_version() -> Option<String> {
    let output = Command::new("nft").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
