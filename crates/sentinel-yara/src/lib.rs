use sentinel_core::{ScanEngine, ScanVerdict, ThreatLevel};

#[derive(Debug, Default)]
pub struct YaraEngine;

impl ScanEngine for YaraEngine {
    fn name(&self) -> &'static str {
        "yara"
    }

    fn scan_bytes(&self, _data: &[u8]) -> ScanVerdict {
        ScanVerdict {
            level: ThreatLevel::Clean,
            engine: self.name().to_string(),
            reason: "No rules loaded in bootstrap build".to_string(),
        }
    }
}
