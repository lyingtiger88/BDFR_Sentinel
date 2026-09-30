use sentinel_core::{DetectionCategory, ThreatLevel};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClamHashEntry {
    pub hash: String,
    pub size: Option<u64>,
    pub name: String,
    pub category: DetectionCategory,
    pub level: ThreatLevel,
}

#[derive(Debug, Default)]
pub struct ClamHashDatabase {
    entries: HashMap<String, ClamHashEntry>,
}

#[derive(Debug, Error)]
pub enum ClamHashError {
    #[error("invalid hash database line: {0}")]
    InvalidLine(String),
}

impl ClamHashDatabase {
    pub fn parse_hdb(input: &str) -> Result<Self, ClamHashError> {
        Self::parse_hash_db(input, 32)
    }

    pub fn parse_hsb(input: &str) -> Result<Self, ClamHashError> {
        Self::parse_hash_db(input, 64)
    }

    fn parse_hash_db(input: &str, expected_hash_len: usize) -> Result<Self, ClamHashError> {
        let mut db = Self::default();

        for raw in input.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let mut parts = line.splitn(3, ':');
            let hash = parts.next().unwrap_or_default().trim();
            let size = parts
                .next()
                .ok_or_else(|| ClamHashError::InvalidLine(line.to_string()))?
                .parse::<u64>()
                .map_err(|_| ClamHashError::InvalidLine(line.to_string()))?;
            let name = parts
                .next()
                .ok_or_else(|| ClamHashError::InvalidLine(line.to_string()))?
                .trim();

            if hash.len() != expected_hash_len
                || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                || name.is_empty()
            {
                return Err(ClamHashError::InvalidLine(line.to_string()));
            }

            let category = classify_name(name);
            let entry = ClamHashEntry {
                hash: hash.to_ascii_lowercase(),
                size: Some(size),
                name: name.to_string(),
                category,
                level: if matches!(
                    category,
                    DetectionCategory::Crack | DetectionCategory::LicenseBypass
                ) {
                    ThreatLevel::Suspicious
                } else {
                    ThreatLevel::Malicious
                },
            };

            db.entries.insert(entry.hash.clone(), entry);
        }

        Ok(db)
    }

    pub fn lookup_hash(&self, hash_hex: &str) -> Option<&ClamHashEntry> {
        self.entries.get(&hash_hex.to_ascii_lowercase())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn classify_name(name: &str) -> DetectionCategory {
    let n = name.to_ascii_lowercase();

    if n.contains("ransom") {
        DetectionCategory::Ransomware
    } else if n.contains("trojan") {
        DetectionCategory::Trojan
    } else if n.contains("worm") {
        DetectionCategory::Worm
    } else if n.contains("backdoor") {
        DetectionCategory::Backdoor
    } else if n.contains("rootkit") {
        DetectionCategory::Rootkit
    } else if n.contains("spyware") {
        DetectionCategory::Spyware
    } else if n.contains("adware") {
        DetectionCategory::Adware
    } else if n.contains("hacktool") {
        DetectionCategory::HackTool
    } else if n.contains("keygen") || n.contains("crack") {
        DetectionCategory::Crack
    } else if n.contains("license") || n.contains("activator") {
        DetectionCategory::LicenseBypass
    } else if n.contains("pua") || n.contains("pup") {
        DetectionCategory::PotentiallyUnwanted
    } else {
        DetectionCategory::Malware
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hdb_and_classifies_crack_names() {
        let db = ClamHashDatabase::parse_hdb(
            "0123456789abcdef0123456789abcdef:1234:Win.Tool.Keygen.Test",
        )
        .unwrap();

        assert_eq!(db.len(), 1);
        let entry = db
            .lookup_hash("0123456789abcdef0123456789abcdef")
            .unwrap();
        assert_eq!(entry.category, DetectionCategory::Crack);
    }

    #[test]
    fn parses_hsb_sha256_database() {
        let hash = "a".repeat(64);
        let db = ClamHashDatabase::parse_hsb(&format!("{hash}:42:Trojan.Unit.Test")).unwrap();
        assert_eq!(
            db.lookup_hash(&hash).unwrap().category,
            DetectionCategory::Trojan
        );
    }
}
