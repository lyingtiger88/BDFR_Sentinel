use sentinel_core::{Detection, DetectionKind, ScanEngine, ScanError, ThreatLevel};

pub trait YaraBackend: Send + Sync {
    fn scan(&self, data: &[u8]) -> Result<Vec<YaraMatch>, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraMatch {
    pub rule_id: String,
    pub namespace: Option<String>,
    pub tags: Vec<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBackend;

    impl YaraBackend for MockBackend {
        fn scan(&self, data: &[u8]) -> Result<Vec<YaraMatch>, String> {
            if data.windows(5).any(|w| w == b"EICAR") {
                Ok(vec![YaraMatch {
                    rule_id: "EICAR_TEST".to_string(),
                    namespace: Some("tests".to_string()),
                    tags: vec!["test".to_string()],
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
        assert_eq!(detections[0].level, ThreatLevel::Malicious);
    }
}
