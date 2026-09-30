mod manifest;
mod staging;

pub use manifest::{is_newer, UpdateFile, UpdateManifest, UpdateVerifier, VerifyError};
pub use staging::{StagingError, StagingUpdater};
