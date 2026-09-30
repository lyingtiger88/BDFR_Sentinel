use crate::UpdateManifest;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StagingError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("missing staged file: {0}")]
    MissingFile(String),

    #[error("size mismatch for {path}: expected {expected}, got {actual}")]
    SizeMismatch {
        path: String,
        expected: u64,
        actual: u64,
    },

    #[error("hash mismatch for staged file: {0}")]
    HashMismatch(String),

    #[error("unsafe relative path in manifest: {0}")]
    UnsafePath(String),
}

#[derive(Debug, Clone)]
pub struct StagingUpdater {
    pub staging_dir: PathBuf,
    pub live_dir: PathBuf,
    pub backup_dir: PathBuf,
}

impl StagingUpdater {
    pub fn verify_staging(&self, manifest: &UpdateManifest) -> Result<(), StagingError> {
        for file in &manifest.files {
            let relative = safe_relative_path(&file.path)?;
            let path = self.staging_dir.join(relative);

            if !path.is_file() {
                return Err(StagingError::MissingFile(file.path.clone()));
            }

            let metadata = fs::metadata(&path)?;
            if metadata.len() != file.size {
                return Err(StagingError::SizeMismatch {
                    path: file.path.clone(),
                    expected: file.size,
                    actual: metadata.len(),
                });
            }

            let data = fs::read(&path)?;
            if sha256_hex(&data) != file.sha256.to_ascii_lowercase() {
                return Err(StagingError::HashMismatch(file.path.clone()));
            }
        }

        Ok(())
    }

    pub fn activate_verified(&self, manifest: &UpdateManifest) -> Result<(), StagingError> {
        self.verify_staging(manifest)?;

        if self.backup_dir.exists() {
            fs::remove_dir_all(&self.backup_dir)?;
        }

        if self.live_dir.exists() {
            fs::rename(&self.live_dir, &self.backup_dir)?;
        }

        if let Err(err) = fs::rename(&self.staging_dir, &self.live_dir) {
            if self.backup_dir.exists() && !self.live_dir.exists() {
                let _ = fs::rename(&self.backup_dir, &self.live_dir);
            }
            return Err(StagingError::Io(err));
        }

        Ok(())
    }
}

fn safe_relative_path(input: &str) -> Result<PathBuf, StagingError> {
    let path = Path::new(input);

    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(StagingError::UnsafePath(input.to_string()));
    }

    Ok(path.to_path_buf())
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_parent_directory_paths() {
        let result = safe_relative_path("../escape.yar");
        assert!(matches!(result, Err(StagingError::UnsafePath(_))));
    }
}
