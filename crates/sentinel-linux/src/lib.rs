//! Linux-specific platform discovery and service integration primitives.
//! A feature is never reported active merely because an API exists.

#[cfg(target_os = "linux")]
pub mod host;
#[cfg(target_os = "linux")]
pub mod firewall;
#[cfg(target_os = "linux")]
pub mod paths;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendState { Active, Limited, Unavailable }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CapabilitySnapshot {
    pub inotify_available: bool,
    pub fanotify_available: bool,
    pub nft_available: bool,
    pub ebpf_available: bool,
    pub udev_available: bool,
    pub is_root: bool,
    pub kernel_release: String,
}
