use crate::{RealtimeConfig, RealtimeError};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use sentinel_core::{FileScanner, ScanReport};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Instant;
use tracing::{debug, error, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MonitorState {
    Stopped = 0,
    Running = 1,
    Paused = 2,
}

impl MonitorState {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Running,
            2 => Self::Paused,
            _ => Self::Stopped,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorEventKind {
    Created,
    Modified,
    Renamed,
}

#[derive(Debug, Clone)]
pub struct MonitorEvent {
    pub path: PathBuf,
    pub kind: MonitorEventKind,
    pub report: Option<ScanReport>,
}

pub struct RealtimeMonitor {
    config: RealtimeConfig,
    scanner: Arc<FileScanner>,
    state: Arc<AtomicU8>,
    stop: Arc<AtomicBool>,
    watcher: Option<RecommendedWatcher>,
}

impl RealtimeMonitor {
    pub fn new(config: RealtimeConfig, scanner: Arc<FileScanner>) -> Result<Self, RealtimeError> {
        if config.paths.is_empty() {
            return Err(RealtimeError::NoWatchPaths);
        }

        for path in &config.paths {
            if !path.exists() {
                return Err(RealtimeError::MissingPath(path.display().to_string()));
            }
        }

        Ok(Self {
            config,
            scanner,
            state: Arc::new(AtomicU8::new(MonitorState::Stopped as u8)),
            stop: Arc::new(AtomicBool::new(false)),
            watcher: None,
        })
    }

    pub fn state(&self) -> MonitorState {
        MonitorState::from_u8(self.state.load(Ordering::Relaxed))
    }

    pub fn pause(&self) {
        self.state
            .store(MonitorState::Paused as u8, Ordering::Relaxed);
    }

    pub fn resume(&self) {
        self.state
            .store(MonitorState::Running as u8, Ordering::Relaxed);
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.state
            .store(MonitorState::Stopped as u8, Ordering::Relaxed);
        self.watcher.take();
    }

    pub fn start<F>(&mut self, on_event: F) -> Result<(), RealtimeError>
    where
        F: Fn(MonitorEvent) + Send + Sync + 'static,
    {
        if self.state() == MonitorState::Running {
            return Err(RealtimeError::AlreadyRunning);
        }

        self.stop.store(false, Ordering::Relaxed);

        let (tx, rx) = mpsc::channel::<notify::Result<Event>>();
        let mut watcher = notify::recommended_watcher(tx)?;

        let mode = if self.config.recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };

        for path in &self.config.paths {
            watcher.watch(path, mode)?;
        }

        let config = self.config.clone();
        let scanner = Arc::clone(&self.scanner);
        let state = Arc::clone(&self.state);
        let stop = Arc::clone(&self.stop);
        let callback = Arc::new(on_event);

        thread::Builder::new()
            .name("bdfr-sentinel-realtime".to_string())
            .spawn(move || {
                let mut last_seen: HashMap<PathBuf, Instant> = HashMap::new();

                while !stop.load(Ordering::Relaxed) {
                    let event = match rx.recv_timeout(std::time::Duration::from_millis(200)) {
                        Ok(Ok(event)) => event,
                        Ok(Err(err)) => {
                            error!(error = %err, "filesystem watcher error");
                            continue;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };

                    if MonitorState::from_u8(state.load(Ordering::Relaxed)) != MonitorState::Running {
                        continue;
                    }

                    let kind = match classify_event(&event.kind) {
                        Some(kind) => kind,
                        None => continue,
                    };

                    for path in event.paths {
                        if !should_scan(&config, &path) {
                            continue;
                        }

                        let now = Instant::now();
                        if let Some(previous) = last_seen.get(&path) {
                            if now.duration_since(*previous) < config.debounce {
                                debug!(path = %path.display(), "debounced filesystem event");
                                continue;
                            }
                        }
                        last_seen.insert(path.clone(), now);

                        let report = match scanner.scan_file(&path) {
                            Ok(report) => Some(report),
                            Err(err) => {
                                warn!(path = %path.display(), error = %err, "realtime scan skipped");
                                None
                            }
                        };

                        callback(MonitorEvent {
                            path,
                            kind,
                            report,
                        });
                    }
                }
            })
            .map_err(|err| RealtimeError::ThreadStart(err.to_string()))?;

        self.watcher = Some(watcher);
        self.state
            .store(MonitorState::Running as u8, Ordering::Relaxed);

        Ok(())
    }
}

impl Drop for RealtimeMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

fn classify_event(kind: &EventKind) -> Option<MonitorEventKind> {
    match kind {
        EventKind::Create(_) => Some(MonitorEventKind::Created),
        EventKind::Modify(notify::event::ModifyKind::Name(_)) => Some(MonitorEventKind::Renamed),
        EventKind::Modify(_) => Some(MonitorEventKind::Modified),
        _ => None,
    }
}

fn should_scan(config: &RealtimeConfig, path: &Path) -> bool {
    if !path.is_file() || !config.accepts_extension(path) {
        return false;
    }

    match path.metadata() {
        Ok(metadata) => metadata.len() <= config.max_file_size,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::{EngineRegistry, ScannerConfig};

    #[test]
    fn event_classification_ignores_remove_events() {
        assert_eq!(
            classify_event(&EventKind::Remove(notify::event::RemoveKind::Any)),
            None
        );
    }

    #[test]
    fn extension_filter_is_case_insensitive() {
        let config = RealtimeConfig::default();
        assert!(config.accepts_extension(Path::new("sample.EXE")));
        assert!(!config.accepts_extension(Path::new("sample.txt")));
    }

    #[test]
    fn rejects_empty_watch_configuration() {
        let scanner = Arc::new(FileScanner::new(
            ScannerConfig::default(),
            EngineRegistry::new(),
        ));

        let result = RealtimeMonitor::new(RealtimeConfig::default(), scanner);
        assert!(matches!(result, Err(RealtimeError::NoWatchPaths)));
    }
}
