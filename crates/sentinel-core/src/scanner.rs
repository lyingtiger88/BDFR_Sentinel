use crate::{
    Detection, DetectionCategory, DetectionKind, DetectionPolicy, EngineRegistry, FileMetadata,
    ScanContext, ScanError, ScanReport, ThreatLevel,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub max_file_size: u64,
    pub policy: DetectionPolicy,
    pub cache_capacity: usize,
    pub cache_ttl: Duration,
    pub archive_scan_enabled: bool,
    pub archive_max_depth: usize,
    pub archive_max_entries: usize,
    pub archive_max_entry_size: u64,
    pub archive_max_total_size: u64,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_file_size: 128 * 1024 * 1024,
            policy: DetectionPolicy::default(),
            cache_capacity: 4096,
            cache_ttl: Duration::from_secs(30),
            archive_scan_enabled: true,
            archive_max_depth: 3,
            archive_max_entries: 512,
            archive_max_entry_size: 64 * 1024 * 1024,
            archive_max_total_size: 256 * 1024 * 1024,
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
        let detections = self.scan_bytes_recursive(&data, 0, path.display().to_string())?;

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

    fn scan_bytes_recursive(
        &self,
        data: &[u8],
        depth: usize,
        label: String,
    ) -> Result<Vec<Detection>, ScanError> {
        let sha256 = hex_sha256(data);
        let context = ScanContext {
            data,
            sha256: &sha256,
        };

        let mut detections = Vec::new();
        for engine in self.engines.engines() {
            let mut engine_detections =
                engine
                    .scan_context(&context)
                    .map_err(|err| ScanError::Engine {
                        engine: engine.name().to_string(),
                        message: err.to_string(),
                    })?;
            detections.append(&mut engine_detections);
        }

        if !self.config.archive_scan_enabled
            || depth >= self.config.archive_max_depth
            || !looks_like_zip(data)
        {
            return Ok(detections);
        }

        let cursor = Cursor::new(data);
        let Ok(mut archive) = zip::ZipArchive::new(cursor) else {
            return Ok(detections);
        };

        if archive.len() > self.config.archive_max_entries {
            detections.push(archive_limit_detection(
                "ARCHIVE-ENTRIES-001",
                format!(
                    "archive entry limit exceeded: {} > {} ({label})",
                    archive.len(),
                    self.config.archive_max_entries
                ),
            ));
            return Ok(detections);
        }

        if archive
            .decompressed_size()
            .is_some_and(|size| size > self.config.archive_max_total_size as u128)
        {
            detections.push(archive_limit_detection(
                "ARCHIVE-SIZE-001",
                format!(
                    "archive expanded-size limit exceeded: > {} bytes ({label})",
                    self.config.archive_max_total_size
                ),
            ));
            return Ok(detections);
        }

        let mut expanded_total = 0u64;

        for index in 0..archive.len() {
            let Ok(mut entry) = archive.by_index(index) else {
                continue;
            };

            let entry_name = entry.name().to_string();
            if entry_name.ends_with('/') {
                continue;
            }

            let declared_size = entry.size();
            if declared_size > self.config.archive_max_entry_size {
                detections.push(archive_limit_detection(
                    "ARCHIVE-ENTRY-SIZE-001",
                    format!("archive entry too large: {entry_name} ({declared_size} bytes)"),
                ));
                continue;
            }

            expanded_total = expanded_total.saturating_add(declared_size);
            if expanded_total > self.config.archive_max_total_size {
                detections.push(archive_limit_detection(
                    "ARCHIVE-TOTAL-SIZE-001",
                    format!("archive expanded-size budget exceeded while reading {entry_name}"),
                ));
                break;
            }

            let mut entry_data = Vec::with_capacity(declared_size.min(1024 * 1024) as usize);
            let mut limited = entry
                .by_ref()
                .take(self.config.archive_max_entry_size.saturating_add(1));
            if limited.read_to_end(&mut entry_data).is_err()
                || entry_data.len() as u64 > self.config.archive_max_entry_size
            {
                continue;
            }

            let nested_label = format!("{label}!{entry_name}");
            let mut nested = self.scan_bytes_recursive(&entry_data, depth + 1, nested_label)?;
            for detection in &mut nested {
                let prefix = format!("archive_entry={entry_name}");
                detection.details = Some(match detection.details.take() {
                    Some(details) => format!("{prefix}; {details}"),
                    None => prefix,
                });
            }
            detections.append(&mut nested);
        }

        Ok(detections)
    }
}

fn looks_like_zip(data: &[u8]) -> bool {
    data.len() >= 4 && matches!(&data[..4], b"PK\x03\x04" | b"PK\x05\x06" | b"PK\x07\x08")
}

fn archive_limit_detection(rule_id: &str, details: String) -> Detection {
    Detection {
        engine: "archive-scanner".to_string(),
        rule_id: Some(rule_id.to_string()),
        kind: DetectionKind::Heuristic,
        category: DetectionCategory::Unknown,
        level: ThreatLevel::Suspicious,
        title: "Archive safety limit reached".to_string(),
        details: Some(details),
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
    use crate::ScanEngine;
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
    fn scans_payload_inside_zip_archive() {
        let temp = std::env::temp_dir().join(format!(
            "bdfr-sentinel-archive-test-{}.zip",
            std::process::id()
        ));

        {
            let file = fs::File::create(&temp).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            writer
                .start_file("payload.bin", zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"inside EVIL payload").unwrap();
            writer.finish().unwrap();
        }

        let mut registry = EngineRegistry::new();
        registry.register(TestEngine);
        let scanner = FileScanner::new(ScannerConfig::default(), registry);
        let report = scanner.scan_file(&temp).unwrap();

        let _ = fs::remove_file(&temp);
        assert_eq!(report.verdict.level, ThreatLevel::Malicious);
        assert!(report.verdict.detections.iter().any(|d| d
            .details
            .as_deref()
            .is_some_and(|v| v.contains("payload.bin"))));
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
