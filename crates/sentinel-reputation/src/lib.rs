use sentinel_core::{
    Detection, DetectionCategory, DetectionKind, ScanContext, ScanEngine, ScanError, ThreatLevel,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReputationState {
    Trusted,
    Malicious,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationRecord {
    pub sha256: String,
    pub state: ReputationState,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Default)]
pub struct ReputationDatabase {
    by_hash: HashMap<String, ReputationRecord>,
}

impl ReputationDatabase {
    pub fn load_jsonl(path: &Path) -> Result<Self, std::io::Error> {
        if !path.is_file() {
            return Ok(Self::default());
        }

        let text = fs::read_to_string(path)?;
        let mut by_hash = HashMap::new();
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            let Ok(record) = serde_json::from_str::<ReputationRecord>(line) else {
                continue;
            };
            by_hash.insert(record.sha256.to_ascii_lowercase(), record);
        }

        Ok(Self { by_hash })
    }

    pub fn lookup(&self, sha256: &str) -> ReputationState {
        self.by_hash
            .get(&sha256.to_ascii_lowercase())
            .map(|record| record.state.clone())
            .unwrap_or(ReputationState::Unknown)
    }

    pub fn record(&self, sha256: &str) -> Option<&ReputationRecord> {
        self.by_hash.get(&sha256.to_ascii_lowercase())
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }
}

pub struct ReputationEngine {
    db: ReputationDatabase,
}

impl ReputationEngine {
    pub fn new(db: ReputationDatabase) -> Self {
        Self { db }
    }

    pub fn database(&self) -> &ReputationDatabase {
        &self.db
    }
}

impl ScanEngine for ReputationEngine {
    fn name(&self) -> &'static str {
        "reputation"
    }

    fn scan_bytes(&self, _data: &[u8]) -> Result<Vec<Detection>, ScanError> {
        Ok(Vec::new())
    }

    fn scan_context(&self, context: &ScanContext<'_>) -> Result<Vec<Detection>, ScanError> {
        let Some(record) = self.db.record(context.sha256) else {
            return Ok(Vec::new());
        };

        if record.state != ReputationState::Malicious {
            return Ok(Vec::new());
        }

        Ok(vec![Detection {
            engine: self.name().to_string(),
            rule_id: Some(format!("REP:{}", &context.sha256[..16.min(context.sha256.len())])),
            kind: DetectionKind::Reputation,
            category: DetectionCategory::Malware,
            level: ThreatLevel::Malicious,
            title: record
                .family
                .as_ref()
                .map(|family| format!("Known malicious reputation: {family}"))
                .unwrap_or_else(|| "Known malicious reputation".to_string()),
            details: Some(format!(
                "sha256={}, source={}",
                context.sha256,
                record.source.as_deref().unwrap_or("local")
            )),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malicious_reputation_becomes_detection() {
        let mut db = ReputationDatabase::default();
        let hash = "a".repeat(64);
        db.by_hash.insert(
            hash.clone(),
            ReputationRecord {
                sha256: hash.clone(),
                state: ReputationState::Malicious,
                family: Some("Trojan.Test".to_string()),
                source: Some("unit-test".to_string()),
            },
        );

        let engine = ReputationEngine::new(db);
        let detections = engine
            .scan_context(&ScanContext {
                data: b"x",
                sha256: &hash,
            })
            .unwrap();

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].level, ThreatLevel::Malicious);
    }
}
