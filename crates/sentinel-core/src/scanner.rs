use crate::{DetectionPolicy, EngineRegistry, FileMetadata, ScanError, ScanReport};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub max_file_size: u64,
    pub policy: DetectionPolicy,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_file_size: 128 * 1024 * 1024,
            policy: DetectionPolicy::default(),
        }
    }
}

pub struct FileScanner {
    config: ScannerConfig,
    engines: EngineRegistry,
}

impl FileScanner {
    pub fn new(config: ScannerConfig, engines: EngineRegistry) -> Self {
        Self { config, engines }
    }

    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<ScanReport, ScanError> {
        let path = path.as_ref();
        let metadata = fs::metadata(path)?;

        if metadata.len() > self.config.max_file_size {
            return Err(ScanError::FileTooLarge {
                actual: metadata.len(),
                max: self.config.max_file_size,
            });
        }

        let data = fs::read(path)?;
        let sha256 = hex_sha256(&data);

        let mut detections = Vec::new();
        for engine in self.engines.engines() {
            let mut engine_detections =
                engine.scan_bytes(&data).map_err(|err| ScanError::Engine {
                    engine: engine.name().to_string(),
                    message: err.to_string(),
                })?;
            detections.append(&mut engine_detections);
        }

        Ok(ScanReport {
            path: path.display().to_string(),
            metadata: FileMetadata {
                size: metadata.len(),
                sha256,
            },
            verdict: self.config.policy.evaluate(detections),
        })
    }
}

fn hex_sha256(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Detection, DetectionCategory, DetectionKind, ScanEngine, ThreatLevel};
    use std::io::Write;

    struct TestEngine;

    impl ScanEngine for TestEngine {
        fn name(&self) -> &'static str {
            "test"
        }

        fn scan_bytes(&self, data: &[u8]) -> Result<Vec<Detection>, ScanError> {
            if data.windows(4).any(|w| w == b"EVIL") {
                Ok(vec![Detection {
                    engine: self.name().to_string(),
                    rule_id: Some("TEST-001".to_string()),
                    kind: DetectionKind::Signature,
                    category: DetectionCategory::Malware,
                    level: ThreatLevel::Malicious,
                    title: "Synthetic test detection".to_string(),
                    details: None,
                }])
            } else {
                Ok(Vec::new())
            }
        }
    }

    #[test]
    fn aggregates_engine_detections_and_hashes_file() {
        let temp =
            std::env::temp_dir().join(format!("bdfr-sentinel-test-{}.bin", std::process::id()));

        {
            let mut f = fs::File::create(&temp).unwrap();
            f.write_all(b"hello EVIL world").unwrap();
        }

        let mut registry = EngineRegistry::new();
        registry.register(TestEngine);

        let scanner = FileScanner::new(ScannerConfig::default(), registry);
        let report = scanner.scan_file(&temp).unwrap();

        let _ = fs::remove_file(&temp);

        assert_eq!(report.verdict.level, ThreatLevel::Malicious);
        assert_eq!(report.verdict.detections.len(), 1);
        assert_eq!(report.metadata.size, 16);
        assert_eq!(report.metadata.sha256.len(), 64);
    }
}
