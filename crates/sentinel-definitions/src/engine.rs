use crate::ClamHashDatabase;
use md5::{Digest, Md5};
use sentinel_core::{Detection, DetectionKind, ScanEngine, ScanError};
use sha2::Sha256;

#[derive(Debug, Default)]
pub struct HashDefinitionEngine {
    hdb: Option<ClamHashDatabase>,
    hsb: Option<ClamHashDatabase>,
}

impl HashDefinitionEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_hdb(mut self, db: ClamHashDatabase) -> Self {
        self.hdb = Some(db);
        self
    }

    pub fn with_hsb(mut self, db: ClamHashDatabase) -> Self {
        self.hsb = Some(db);
        self
    }

    pub fn has_definitions(&self) -> bool {
        self.hdb.as_ref().is_some_and(|db| !db.is_empty())
            || self.hsb.as_ref().is_some_and(|db| !db.is_empty())
    }
}

impl ScanEngine for HashDefinitionEngine {
    fn name(&self) -> &'static str {
        "hash-definitions"
    }

    fn scan_bytes(&self, data: &[u8]) -> Result<Vec<Detection>, ScanError> {
        let mut detections = Vec::new();

        if let Some(db) = &self.hdb {
            let mut hasher = Md5::new();
            hasher.update(data);
            let hash = format!("{:x}", hasher.finalize());

            if let Some(entry) = db.lookup_hash(&hash) {
                detections.push(Detection {
                    engine: self.name().to_string(),
                    rule_id: Some(entry.name.clone()),
                    kind: DetectionKind::Signature,
                    category: entry.category,
                    level: entry.level,
                    title: format!("Hash definition matched: {}", entry.name),
                    details: Some(format!("md5={hash}")),
                });
            }
        }

        if let Some(db) = &self.hsb {
            let mut hasher = Sha256::new();
            hasher.update(data);
            let hash = format!("{:x}", hasher.finalize());

            if let Some(entry) = db.lookup_hash(&hash) {
                detections.push(Detection {
                    engine: self.name().to_string(),
                    rule_id: Some(entry.name.clone()),
                    kind: DetectionKind::Signature,
                    category: entry.category,
                    level: entry.level,
                    title: format!("Hash definition matched: {}", entry.name),
                    details: Some(format!("sha256={hash}")),
                });
            }
        }

        Ok(detections)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::{DetectionCategory, ThreatLevel};

    #[test]
    fn hsb_match_becomes_detection() {
        let data = b"known malicious sample";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = format!("{:x}", hasher.finalize());

        let db =
            ClamHashDatabase::parse_hsb(&format!("{hash}:{}:Trojan.Test", data.len())).unwrap();
        let engine = HashDefinitionEngine::new().with_hsb(db);
        let detections = engine.scan_bytes(data).unwrap();

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].category, DetectionCategory::Trojan);
        assert_eq!(detections[0].level, ThreatLevel::Malicious);
    }
}
