use std::path::PathBuf;

/// XDG-aware per-user configuration location.
pub fn user_config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from).map(|home| home.join(".config")))
        .unwrap_or_else(|| PathBuf::from("/etc"))
        .join("BDFR").join("Sentinel")
}

/// Root-owned service state location. Installer creates it with restrictive permissions.
pub fn system_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/bdfr-sentinel")
}
