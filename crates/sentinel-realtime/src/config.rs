use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RealtimeConfig {
    pub paths: Vec<PathBuf>,
    pub recursive: bool,
    pub debounce: Duration,
    pub extensions: Vec<String>,
    pub max_file_size: u64,
}

impl Default for RealtimeConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            recursive: true,
            debounce: Duration::from_millis(350),
            extensions: vec![
                "exe".to_string(),
                "dll".to_string(),
                "sys".to_string(),
                "msi".to_string(),
                "ps1".to_string(),
                "bat".to_string(),
                "cmd".to_string(),
                "js".to_string(),
                "vbs".to_string(),
                "scr".to_string(),
            ],
            max_file_size: 128 * 1024 * 1024,
        }
    }
}

impl RealtimeConfig {
    pub fn accepts_extension(&self, path: &std::path::Path) -> bool {
        if self.extensions.is_empty() {
            return true;
        }

        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| {
                self.extensions
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(ext))
            })
            .unwrap_or(false)
    }
}
