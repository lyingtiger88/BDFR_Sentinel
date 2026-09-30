use crate::QuarantineError;
use std::fs;
use std::path::Path;

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

        return unprotected
            .as_slice()
            .try_into()
            .map_err(|_| QuarantineError::KeyProtection("invalid key length".to_string()));
    }

    let key = Aes256Gcm::generate_key(&mut OsRng);
    let protected = encrypt_data(key.as_slice(), Scope::Machine, None)
        .map_err(|err| QuarantineError::KeyProtection(err.to_string()))?;

    let temp = root.join(format!("{KEY_FILE}.tmp"));
    fs::write(&temp, protected)?;
    fs::rename(temp, &path)?;

    key.as_slice()
        .try_into()
        .map_err(|_| QuarantineError::KeyProtection("invalid key length".to_string()))
}

#[cfg(not(windows))]
pub fn load_or_create_key(_root: &Path) -> Result<[u8; 32], QuarantineError> {
    Err(QuarantineError::KeyProtection(
        "BDFR Sentinel quarantine key protection currently requires Windows DPAPI".to_string(),
    ))
}
