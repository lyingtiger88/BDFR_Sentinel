use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareAssessment {
    pub suspicious: bool,
    pub malicious: bool,
    pub recent_changes: usize,
    pub unique_directories: usize,
    pub unique_extensions: usize,
}

#[derive(Debug)]
struct ChangeEvent {
    at: Instant,
    path: PathBuf,
}

#[derive(Debug)]
pub struct RansomwareShield {
    window: Duration,
    suspicious_change_threshold: usize,
    malicious_change_threshold: usize,
    events: VecDeque<ChangeEvent>,
    canary_hits: HashMap<PathBuf, Instant>,
}

impl Default for RansomwareShield {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(10),
            suspicious_change_threshold: 40,
            malicious_change_threshold: 120,
            events: VecDeque::new(),
            canary_hits: HashMap::new(),
        }
    }
}

impl RansomwareShield {
    pub fn observe_path(&mut self, path: &Path) -> RansomwareAssessment {
        let now = Instant::now();
        self.events.push_back(ChangeEvent {
            at: now,
            path: path.to_path_buf(),
        });

        while self
            .events
            .front()
            .is_some_and(|event| now.duration_since(event.at) > self.window)
        {
            self.events.pop_front();
        }

        let mut directories = HashSet::new();
        let mut extensions = HashSet::new();
        for event in &self.events {
            if let Some(parent) = event.path.parent() {
                directories.insert(parent.to_path_buf());
            }
            if let Some(ext) = event.path.extension().and_then(|ext| ext.to_str()) {
                extensions.insert(ext.to_ascii_lowercase());
            }
        }

        let recent_changes = self.events.len();
        let unique_directories = directories.len();
        let unique_extensions = extensions.len();

        let suspicious = recent_changes >= self.suspicious_change_threshold
            && unique_directories >= 2;
        let malicious = recent_changes >= self.malicious_change_threshold
            && unique_directories >= 3
            && unique_extensions >= 3;

        RansomwareAssessment {
            suspicious,
            malicious,
            recent_changes,
            unique_directories,
            unique_extensions,
        }
    }

    pub fn observe_canary(&mut self, path: &Path) -> bool {
        let now = Instant::now();
        let duplicate = self
            .canary_hits
            .get(path)
            .is_some_and(|previous| now.duration_since(*previous) < Duration::from_secs(5));
        self.canary_hits.insert(path.to_path_buf(), now);
        !duplicate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mass_changes_raise_risk() {
        let mut shield = RansomwareShield {
            suspicious_change_threshold: 3,
            malicious_change_threshold: 5,
            ..RansomwareShield::default()
        };

        for i in 0..5 {
            let path = PathBuf::from(format!(r"C:\Users\A\Dir{}\file{}.ext{}", i % 3, i, i % 3));
            let assessment = shield.observe_path(&path);
            if i < 4 {
                assert!(!assessment.malicious);
            }
        }

        let final_assessment = shield.observe_path(Path::new(r"C:\Users\A\Dir4\last.zzz"));
        assert!(final_assessment.malicious);
    }
}
