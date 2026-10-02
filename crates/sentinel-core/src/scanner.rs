use crate::{DetectionPolicy, EngineRegistry, FileMetadata, ScanContext, ScanError, ScanReport};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub max_file_size: u64,
    pub policy: DetectionPolicy,
    pub cache_capacity: usize,
    pub cache_ttl: Duration,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_file_size: 128 * 1024 * 1024,
            policy: DetectionPolicy::default(),
            cache_capacity: 4096,
            cache_ttl: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone)]
struct CachedScan {
    len: u64,
    modified: Option<SystemTime>,
    cached_at: Instant,
    report: ScanReport,
}

pub struct FileScanner {
    config: ScannerConfig,
    engines: EngineRegistry,
    cache: Mutex<HashMap<PathBuf, CachedScan>>,
}

impl FileScanner {
    pub fn new(config: ScannerConfig, engines: EngineRegistry) -> Self {
        Self {
            config,
            engines,
            cache: Mutex::new(HashMap::new()),
        }
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

        let modified = metadata.modified().ok();
        let cache_key = path.to_path_buf();

        if self.config.cache_capacity > 0 {
            if let Ok(cache) = self.cache.lock() {
                if let Some(cached) = cache.get(&cache_key) {
                    if cached.len == metadata.len()
                        && cached.modified == modified
                        && cached.cached_at.elapsed() <= self.config.cache_ttl
                    {
                        return Ok(cached.report.clone());
                    }
                }
            }
        }

        let data = fs::read(path)?;
        let sha256 = hex_sha256(&data);

        let context = ScanContext {
            data: &data,
            sha256: &sha256,
        };

        let mut detections = Vec::new();
        for engine in self.engines.engines() {
            let mut engine_detections =
                engine.scan_context(&context).map_err(|err| ScanError::Engine {
                    engine: engine.name().to_string(),
                    message: err.to_string(),
                })?;
            detections.append(&mut engine_detections);
        }

        let report = ScanReport {
            path: path.display().to_string(),
            metadata: FileMetadata {
                size: metadata.len(),
                sha256,
            },
            verdict: self.config.policy.evaluate(detections),
        };

        if self.config.cache_capacity > 0 {
            if let Ok(mut cache) = self.cache.lock() {
                if cache.len() >= self.config.cache_capacity {
                    cache.clear();
                }
                cache.insert(
                    cache_key,
                    CachedScan {
                        len: metadata.len(),
                        modified,
                        cached_at: Instant::now(),
                        report: report.clone(),
                    },
                );
            }
        }

        Ok(report)
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

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

    #[test]
    fn cache_avoids_duplicate_engine_execution() {
        struct CountingEngine(Arc<AtomicUsize>);

        impl ScanEngine for CountingEngine {
            fn name(&self) -> &'static str {
                "counting"
            }

            fn scan_bytes(&self, _data: &[u8]) -> Result<Vec<Detection>, ScanError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            }
        }

        let temp = std::env::temp_dir().join(format!(
            "bdfr-sentinel-cache-count-test-{}.bin",
            std::process::id()
        ));
        fs::write(&temp, b"same file").unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let mut registry = EngineRegistry::new();
        registry.register(CountingEngine(Arc::clone(&calls)));

        let scanner = FileScanner::new(ScannerConfig::default(), registry);
        scanner.scan_file(&temp).unwrap();
        scanner.scan_file(&temp).unwrap();

        let _ = fs::remove_file(&temp);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn repeated_unchanged_scan_uses_cached_report() {
        let temp = std::env::temp_dir().join(format!(
            "bdfr-sentinel-cache-test-{}.bin",
            std::process::id()
        ));
        fs::write(&temp, b"cache me").unwrap();

        let scanner = FileScanner::new(ScannerConfig::default(), EngineRegistry::new());
        let first = scanner.scan_file(&temp).unwrap();
        let second = scanner.scan_file(&temp).unwrap();

        let _ = fs::remove_file(&temp);
        assert_eq!(first, second);
    }
}
