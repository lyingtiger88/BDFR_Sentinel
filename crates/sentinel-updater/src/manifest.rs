use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub schema_version: u32,
    pub version: Version,
    pub channel: String,
    pub files: Vec<UpdateFile>,
    pub signature: String,
}

impl UpdateManifest {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = format!(
            "schema_version={}
version={}
channel={}
",
            self.schema_version, self.version, self.channel
        );

        for file in &self.files {
            out.push_str(&format!(
                "file={}|{}|{}
",
                file.path, file.sha256, file.size
            ));
        }

        out.into_bytes()
    }
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,

    #[error("signature verification failed")]
    SignatureVerification,
}

pub struct UpdateVerifier {
    key: VerifyingKey,
}

impl UpdateVerifier {
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
        let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| VerifyError::InvalidPublicKey)?;
        let key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|_| VerifyError::InvalidPublicKey)?;
        Ok(Self { key })
    }

    pub fn verify_manifest(&self, manifest: &UpdateManifest) -> Result<(), VerifyError> {
        let raw = BASE64
            .decode(&manifest.signature)
            .map_err(|_| VerifyError::InvalidSignatureEncoding)?;
        let signature =
            Signature::from_slice(&raw).map_err(|_| VerifyError::InvalidSignatureEncoding)?;

        self.key
            .verify(&manifest.signing_bytes(), &signature)
            .map_err(|_| VerifyError::SignatureVerification)
    }
}

pub fn is_newer(current: &Version, available: &Version) -> bool {
    available > current
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn semver_ordering_is_correct() {
        let current = Version::parse("1.9.0").unwrap();
        let available = Version::parse("1.10.0").unwrap();
        assert!(is_newer(&current, &available));
    }

    #[test]
    fn verifies_signed_manifest() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let verifier = UpdateVerifier::from_public_key_bytes(
            signing.verifying_key().as_bytes(),
        )
        .unwrap();

        let mut manifest = UpdateManifest {
            schema_version: 1,
            version: Version::parse("0.2.0").unwrap(),
            channel: "stable".to_string(),
            files: vec![UpdateFile {
                path: "rules/main.yar".to_string(),
                sha256: "abc".to_string(),
                size: 42,
            }],
            signature: String::new(),
        };

        let signature = signing.sign(&manifest.signing_bytes());
        manifest.signature = BASE64.encode(signature.to_bytes());

        verifier.verify_manifest(&manifest).unwrap();
    }
}
