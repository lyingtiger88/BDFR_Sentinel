use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareAssessment {
    pub suspicious: bool,
    pub malicious: bool,
    pub recent_changes: usize,
    pub unique_directories: usize,
    pub unique_extensions: usize,
    pub risk_score: u8,
    pub aggressive_mode: bool,
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
    aggressive_mode: bool,
}

impl Default for RansomwareShield {
    fn default() -> Self {
        Self::with_aggressive_mode(false)
    }
}

impl RansomwareShield {
    pub fn with_aggressive_mode(aggressive_mode: bool) -> Self {
        let (window, suspicious_change_threshold, malicious_change_threshold) = if aggressive_mode {
            (Duration::from_secs(8), 18, 60)
        } else {
            (Duration::from_secs(10), 40, 120)
        };

        Self {
            window,
            suspicious_change_threshold,
            malicious_change_threshold,
            events: VecDeque::new(),
            canary_hits: HashMap::new(),
            aggressive_mode,
        }
    }

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

        let threshold_progress =
            ((recent_changes.saturating_mul(60)) / self.suspicious_change_threshold.max(1)).min(60);
        let directory_score = unique_directories.saturating_mul(8).min(24);
        let extension_score = unique_extensions.saturating_mul(4).min(16);
        let risk_score = (threshold_progress + directory_score + extension_score).min(100) as u8;

        let suspicious =
            recent_changes >= self.suspicious_change_threshold && unique_directories >= 2;
        let malicious = (recent_changes >= self.malicious_change_threshold
            && unique_directories >= 3
            && unique_extensions >= 3)
            || (risk_score >= 90 && unique_directories >= 4);

        RansomwareAssessment {
            suspicious,
            malicious,
            recent_changes,
            unique_directories,
            unique_extensions,
            risk_score,
            aggressive_mode: self.aggressive_mode,
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

pub struct RansomwareMonitor {
    _watcher: RecommendedWatcher,
}

impl RansomwareMonitor {
    pub fn start<F>(
        paths: &[PathBuf],
        excluded_paths: Vec<PathBuf>,
        aggressive_mode: bool,
        on_alert: F,
    ) -> Result<Self, notify::Error>
    where
        F: Fn(PathBuf, RansomwareAssessment) + Send + Sync + 'static,
    {
        let shield = Arc::new(Mutex::new(RansomwareShield::with_aggressive_mode(
            aggressive_mode,
        )));
        let callback = Arc::new(on_alert);
        let shield_for_callback = Arc::clone(&shield);
        let callback_for_events = Arc::clone(&callback);

        let mut watcher =
            notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
                let event = match event {
                    Ok(event) => event,
                    Err(err) => {
                        warn!(error = %err, "ransomware filesystem watcher error");
                        return;
                    }
                };

                if !matches!(
                    event.kind,
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                ) {
                    return;
                }

                for path in event.paths {
                    if excluded_paths
                        .iter()
                        .any(|excluded| path.starts_with(excluded))
                        || path.is_dir()
                    {
                        continue;
                    }

                    let assessment = match shield_for_callback.lock() {
                        Ok(mut shield) => shield.observe_path(&path),
                        Err(_) => continue,
                    };

                    if assessment.suspicious {
                        callback_for_events(path, assessment);
                    }
                }
            })?;

        for path in paths {
            if path.exists() {
                watcher.watch(path, RecursiveMode::Recursive)?;
            }
        }

        Ok(Self { _watcher: watcher })
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

        let mut final_assessment = None;
        for i in 0..6 {
            let path = PathBuf::from(format!(r"C:\Users\A\Dir{}\file{}.ext{}", i % 4, i, i % 4));
            final_assessment = Some(shield.observe_path(&path));
        }

        let final_assessment = final_assessment.unwrap();
        assert!(final_assessment.malicious);
        assert!(final_assessment.risk_score >= 90);
    }

    #[test]
    fn aggressive_mode_uses_lower_thresholds() {
        let normal = RansomwareShield::with_aggressive_mode(false);
        let aggressive = RansomwareShield::with_aggressive_mode(true);

        assert!(aggressive.suspicious_change_threshold < normal.suspicious_change_threshold);
        assert!(aggressive.malicious_change_threshold < normal.malicious_change_threshold);
    }
}
