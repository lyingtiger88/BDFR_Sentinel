use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionKind {
    Signature,
    Heuristic,
    StaticAnalysis,
    Reputation,
    Behavior,
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionCategory {
    Malware,
    Ransomware,
    Trojan,
    Worm,
    Backdoor,
    Rootkit,
    Spyware,
    Adware,
    PotentiallyUnwanted,
    Riskware,
    HackTool,
    Crack,
    LicenseBypass,
    Test,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    pub engine: String,
    pub rule_id: Option<String>,
    pub kind: DetectionKind,
    pub category: DetectionCategory,
    pub level: ThreatLevel,
    pub title: String,
    pub details: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetadata {
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanVerdict {
    pub level: ThreatLevel,
    pub detections: Vec<Detection>,
}

impl ScanVerdict {
    pub fn clean() -> Self {
        Self {
            level: ThreatLevel::Clean,
            detections: Vec::new(),
        }
    }

    pub fn from_detections(detections: Vec<Detection>) -> Self {
        let level = detections
            .iter()
            .map(|d| d.level)
            .max()
            .unwrap_or(ThreatLevel::Clean);

        Self { level, detections }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub path: String,
    pub metadata: FileMetadata,
    pub verdict: ScanVerdict,
}
