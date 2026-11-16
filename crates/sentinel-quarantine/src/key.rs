use crate::QuarantineError;
use std::fs;
use std::path::Path;

#[cfg(windows)]
const KEY_FILE: &str = ".sentinel-key.dpapi";

#[cfg(windows)]
pub fn load_or_create_key(root: &Path) -> Result<[u8; 32], QuarantineError> {
    use aes_gcm::aead::OsRng;
    use aes_gcm::{Aes256Gcm, KeyInit};
    use windows_dpapi::{decrypt_data, encrypt_data, Scope};

    let path = root.join(KEY_FILE);
    if path.exists() {
        let protected = fs::read(path)?;
        let unprotected = decrypt_data(&protected, Scope::Machine, None)
            .map_err(|err| QuarantineError::KeyProtection(err.to_string()))?;
        return unprotected.as_slice().try_into()
            .map_err(|_| QuarantineError::KeyProtection("invalid key length".to_string()));
    }

    let key = Aes256Gcm::generate_key(&mut OsRng);
    let protected = encrypt_data(key.as_slice(), Scope::Machine, None)
        .map_err(|err| QuarantineError::KeyProtection(err.to_string()))?;
    let temp = root.join(format!("{KEY_FILE}.tmp"));
    fs::write(&temp, protected)?;
    fs::rename(temp, &path)?;
    key.as_slice().try_into()
        .map_err(|_| QuarantineError::KeyProtection("invalid key length".to_string()))
}

#[cfg(target_os = "linux")]
pub fn load_or_create_key(root: &Path) -> Result<[u8; 32], QuarantineError> {
    use aes_gcm::aead::OsRng;
    use aes_gcm::{Aes256Gcm, KeyInit};
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    const KEY_FILE: &str = ".sentinel-key";
    let path = root.join(KEY_FILE);

    let read_existing = |path: &Path| -> Result<[u8; 32], QuarantineError> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(QuarantineError::KeyProtection(
                "quarantine key must be a regular file accessible only by its owner".to_string(),
            ));
        }
        let mut file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        bytes.try_into().map_err(|_| QuarantineError::KeyProtection("invalid key length".to_string()))
    };

    if path.exists() {
        return read_existing(&path);
    }

    let key = Aes256Gcm::generate_key(&mut OsRng);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW);
    match options.open(&path) {
        Ok(mut file) => {
            file.write_all(key.as_slice())?;
            file.sync_all()?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            Ok(key.as_slice().try_into().map_err(|_| {
                QuarantineError::KeyProtection("invalid key length".to_string())
            })?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read_existing(&path),
        Err(error) => Err(QuarantineError::Io(error)),
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn load_or_create_key(_root: &Path) -> Result<[u8; 32], QuarantineError> {
    Err(QuarantineError::KeyProtection(
        "platform key protection adapter is not available".to_string(),
    ))
}
