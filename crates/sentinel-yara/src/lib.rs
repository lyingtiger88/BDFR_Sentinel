use sentinel_core::{
    Detection, DetectionCategory, DetectionKind, ScanEngine, ScanError, ThreatLevel,
};
use std::fs;
use std::path::Path;
use std::time::Duration;

pub trait YaraBackend: Send + Sync {
    fn scan(&self, data: &[u8]) -> Result<Vec<YaraMatch>, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraMatch {
    pub rule_id: String,
    pub namespace: Option<String>,
    pub tags: Vec<String>,
    pub category: DetectionCategory,
    pub level: ThreatLevel,
    pub details: Option<String>,
}

pub struct YaraEngine<B> {
    backend: B,
}

impl<B> YaraEngine<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }
}

impl<B> ScanEngine for YaraEngine<B>
where
    B: YaraBackend,
{
    fn name(&self) -> &'static str {
        "yara"
    }

    fn scan_bytes(&self, data: &[u8]) -> Result<Vec<Detection>, ScanError> {
        let matches = self
            .backend
            .scan(data)
            .map_err(|message| ScanError::Engine {
                engine: self.name().to_string(),
                message,
            })?;

        Ok(matches
            .into_iter()
            .map(|m| Detection {
                engine: self.name().to_string(),
                rule_id: Some(m.rule_id.clone()),
                kind: DetectionKind::Signature,
                category: m.category,
                level: m.level,
                title: format!("YARA rule matched: {}", m.rule_id),
                details: m.details.or_else(|| {
                    if m.tags.is_empty() && m.namespace.is_none() {
                        None
                    } else {
                        Some(format!(
                            "namespace={}, tags={}",
                            m.namespace.unwrap_or_else(|| "default".to_string()),
                            m.tags.join(",")
                        ))
                    }
                }),
            })
            .collect())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopYaraBackend;

impl YaraBackend for NoopYaraBackend {
    fn scan(&self, _data: &[u8]) -> Result<Vec<YaraMatch>, String> {
        Ok(Vec::new())
    }
}

pub type BootstrapYaraEngine = YaraEngine<NoopYaraBackend>;

pub struct YaraXBackend {
    rules: yara_x::Rules,
    timeout: Duration,
}

impl YaraXBackend {
    pub fn compile_directory(path: &Path) -> Result<Option<Self>, String> {
        if !path.is_dir() {
            return Ok(None);
        }

        let mut sources = Vec::new();
        let entries = fs::read_dir(path).map_err(|err| err.to_string())?;
        for entry in entries {
            let entry = entry.map_err(|err| err.to_string())?;
            let file_type = entry.file_type().map_err(|err| err.to_string())?;
            if !file_type.is_file() {
                continue;
            }

            let path = entry.path();
            let supported = path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| matches!(ext.to_ascii_lowercase().as_str(), "yar" | "yara"))
                .unwrap_or(false);
            if !supported {
                continue;
            }

            let source = fs::read_to_string(&path)
                .map_err(|err| format!("{}: {err}", path.display()))?;
            sources.push((path, source));
        }

        if sources.is_empty() {
            return Ok(None);
        }

        let mut compiler = yara_x::Compiler::new();
        for (path, source) in &sources {
            compiler
                .add_source(source.as_str())
                .map_err(|err| format!("{}: {err}", path.display()))?;
        }

        Ok(Some(Self {
            rules: compiler.build(),
            timeout: Duration::from_millis(500),
        }))
    }

    pub fn rule_count(&self) -> usize {
        self.rules.iter().len()
    }
}

impl YaraBackend for YaraXBackend {
    fn scan(&self, data: &[u8]) -> Result<Vec<YaraMatch>, String> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        scanner.set_timeout(self.timeout).fast_scan(true);
        let results = scanner.scan(data).map_err(|err| err.to_string())?;

        let mut matches = Vec::new();
        for rule in results.matching_rules() {
            let rule_id = rule.identifier().to_string();
            let namespace = match rule.namespace() {
                "" | "default" => None,
                value => Some(value.to_string()),
            };
            let lower = rule_id.to_ascii_lowercase();
            let category = if lower.contains("ransom") {
                DetectionCategory::Ransomware
            } else if lower.contains("trojan") {
                DetectionCategory::Trojan
            } else if lower.contains("backdoor") {
                DetectionCategory::Backdoor
            } else if lower.contains("spy") {
                DetectionCategory::Spyware
            } else if lower.contains("rootkit") {
                DetectionCategory::Rootkit
            } else if lower.contains("worm") {
                DetectionCategory::Worm
            } else if lower.contains("pua") || lower.contains("adware") {
                DetectionCategory::PotentiallyUnwanted
            } else {
                DetectionCategory::Malware
            };

            matches.push(YaraMatch {
                rule_id,
                namespace,
                tags: Vec::new(),
                category,
                level: ThreatLevel::Malicious,
                details: Some("matched by YARA-X".to_string()),
            });
        }

        Ok(matches)
    }
}

pub type YaraXEngine = YaraEngine<YaraXBackend>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct MockBackend;

    impl YaraBackend for MockBackend {
        fn scan(&self, data: &[u8]) -> Result<Vec<YaraMatch>, String> {
            if data.windows(5).any(|w| w == b"EICAR") {
                Ok(vec![YaraMatch {
                    rule_id: "EICAR_TEST".to_string(),
                    namespace: Some("tests".to_string()),
                    tags: vec!["test".to_string()],
                    category: DetectionCategory::Test,
                    level: ThreatLevel::Malicious,
                    details: None,
                }])
            } else {
                Ok(Vec::new())
            }
        }
    }

    #[test]
    fn converts_backend_matches_into_core_detections() {
        let engine = YaraEngine::new(MockBackend);
        let detections = engine.scan_bytes(b"prefix EICAR suffix").unwrap();

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].rule_id.as_deref(), Some("EICAR_TEST"));
        assert_eq!(detections[0].category, DetectionCategory::Test);
        assert_eq!(detections[0].level, ThreatLevel::Malicious);
    }

    #[test]
    fn compiles_and_scans_real_yara_x_rules() {
        let root = std::env::temp_dir().join(format!(
            "bdfr-yarax-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("test.yar"),
            r#"
rule Trojan_BDFR_Test {
  strings:
    $a = "BDFR_YARA_X_MARKER"
  condition:
    $a
}
"#,
        )
        .unwrap();

        let backend = YaraXBackend::compile_directory(&root)
            .unwrap()
            .expect("rules should compile");
        assert_eq!(backend.rule_count(), 1);

        let engine = YaraEngine::new(backend);
        let detections = engine.scan_bytes(b"xx BDFR_YARA_X_MARKER yy").unwrap();

        let _ = fs::remove_dir_all(root);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].category, DetectionCategory::Trojan);
    }
}
