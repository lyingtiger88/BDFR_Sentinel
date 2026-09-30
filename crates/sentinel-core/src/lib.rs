use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanVerdict {
    pub level: ThreatLevel,
    pub engine: String,
    pub reason: String,
}

pub trait ScanEngine: Send + Sync {
    fn name(&self) -> &'static str;
    fn scan_bytes(&self, data: &[u8]) -> ScanVerdict;
}
