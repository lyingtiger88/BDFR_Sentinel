mod key;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

const MAGIC: &[u8; 8] = b"BDFRSQ01";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineId(pub Uuid);

impl QuarantineId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for QuarantineId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: QuarantineId,
    pub original_path: PathBuf,
    pub original_size: u64,
    pub original_sha256: String,
    pub reason: String,
}

#[derive(Debug, Error)]
pub enum QuarantineError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("cryptographic operation failed")]
    Crypto,

    #[error("invalid quarantine blob")]
    InvalidBlob,

    #[error("quarantine entry hash verification failed")]
    HashMismatch,

    #[error("key protection error: {0}")]
    KeyProtection(String),

    #[error("metadata error: {0}")]
    Metadata(#[from] serde_json::Error),
}

pub struct QuarantineStore {
    root: PathBuf,
    cipher: Aes256Gcm,
}

impl QuarantineStore {
    pub fn open<P: AsRef<Path>>(root: P) -> Result<Self, QuarantineError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;

        let key = key::load_or_create_key(&root)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| QuarantineError::Crypto)?;

        Ok(Self { root, cipher })
    }

    pub fn quarantine_file<P: AsRef<Path>>(
        &self,
        source: P,
        reason: impl Into<String>,
    ) -> Result<QuarantineEntry, QuarantineError> {
        let source = source.as_ref();
        let data = fs::read(source)?;
        let metadata = fs::metadata(source)?;

        let id = QuarantineId::new();
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let encrypted = self
            .cipher
            .encrypt(&nonce, data.as_ref())
            .map_err(|_| QuarantineError::Crypto)?;

        let mut blob = Vec::with_capacity(MAGIC.len() + nonce.len() + encrypted.len());
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&encrypted);

        let entry = QuarantineEntry {
            id,
            original_path: source.to_path_buf(),
            original_size: metadata.len(),
            original_sha256: sha256_hex(&data),
            reason: reason.into(),
        };

        self.atomic_write(&self.blob_path(id), &blob)?;
        let encoded = serde_json::to_vec_pretty(&entry)?;
        self.atomic_write(&self.metadata_path(id), &encoded)?;

        if let Err(err) = fs::remove_file(source) {
            let _ = fs::remove_file(self.blob_path(id));
            let _ = fs::remove_file(self.metadata_path(id));
            return Err(QuarantineError::Io(err));
        }

        Ok(entry)
    }

    pub fn restore(&self, id: QuarantineId) -> Result<QuarantineEntry, QuarantineError> {
        let entry = self.read_entry(id)?;
        let blob = fs::read(self.blob_path(id))?;
        let data = self.decrypt_blob(&blob)?;

        if sha256_hex(&data) != entry.original_sha256 {
            return Err(QuarantineError::HashMismatch);
        }

        if let Some(parent) = entry.original_path.parent() {
            fs::create_dir_all(parent)?;
        }

        self.atomic_write(&entry.original_path, &data)?;
        fs::remove_file(self.blob_path(id))?;
        fs::remove_file(self.metadata_path(id))?;

        Ok(entry)
    }

    pub fn delete(&self, id: QuarantineId) -> Result<(), QuarantineError> {
        remove_if_exists(&self.blob_path(id))?;
        remove_if_exists(&self.metadata_path(id))?;
        Ok(())
    }

    pub fn read_entry(&self, id: QuarantineId) -> Result<QuarantineEntry, QuarantineError> {
        let encoded = fs::read(self.metadata_path(id))?;
        Ok(serde_json::from_slice(&encoded)?)
    }

    fn decrypt_blob(&self, blob: &[u8]) -> Result<Vec<u8>, QuarantineError> {
        if blob.len() <= MAGIC.len() + 12 || &blob[..MAGIC.len()] != MAGIC {
            return Err(QuarantineError::InvalidBlob);
        }

        let nonce_start = MAGIC.len();
        let nonce_end = nonce_start + 12;
        let nonce = Nonce::from_slice(&blob[nonce_start..nonce_end]);

        self.cipher
            .decrypt(nonce, &blob[nonce_end..])
            .map_err(|_| QuarantineError::Crypto)
    }

    fn blob_path(&self, id: QuarantineId) -> PathBuf {
        self.root.join(format!("{}.qbin", id.0))
    }

    fn metadata_path(&self, id: QuarantineId) -> PathBuf {
        self.root.join(format!("{}.json", id.0))
    }

    fn atomic_write(&self, path: &Path, data: &[u8]) -> Result<(), io::Error> {
        let temp = path.with_extension(format!(
            "{}.tmp",
            path.extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("sentinel")
        ));
        fs::write(&temp, data)?;
        fs::rename(temp, path)
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn remove_if_exists(path: &Path) -> Result<(), io::Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn quarantine_round_trip() {
        let base =
            std::env::temp_dir().join(format!("bdfr-sentinel-quarantine-{}", Uuid::new_v4()));
        let source = base.join("sample.bin");
        let store_dir = base.join("store");

        fs::create_dir_all(&base).unwrap();
        fs::write(&source, b"sentinel quarantine test").unwrap();

        let store = QuarantineStore::open(&store_dir).unwrap();
        let entry = store.quarantine_file(&source, "unit-test").unwrap();

        assert!(!source.exists());

        let restored = store.restore(entry.id).unwrap();
        assert_eq!(restored.original_sha256, entry.original_sha256);
        assert_eq!(fs::read(&source).unwrap(), b"sentinel quarantine test");

        let _ = fs::remove_dir_all(base);
    }
}
