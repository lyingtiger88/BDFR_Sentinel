use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::warn;

const WATCH_KEYS: &[&str] = &[
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryEventKind {
    Added,
    Modified,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEvent {
    pub kind: RegistryEventKind,
    pub key: String,
    pub name: String,
    pub value: Option<String>,
}

pub struct RegistryTelemetry {
    stop: Arc<AtomicBool>,
}

impl RegistryTelemetry {
    pub fn start<F>(poll_interval: Duration, on_event: F) -> Self
    where
        F: Fn(RegistryEvent) + Send + Sync + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_worker = Arc::clone(&stop);
        let callback = Arc::new(on_event);

        thread::Builder::new()
            .name("bdfr-sentinel-registry-telemetry".to_string())
            .spawn(move || {
                let mut known = snapshot_all();

                while !stop_worker.load(Ordering::Relaxed) {
                    thread::sleep(poll_interval);
                    let current = snapshot_all();

                    for (identity, value) in &current {
                        match known.get(identity) {
                            None => callback(RegistryEvent {
                                kind: RegistryEventKind::Added,
                                key: identity.0.clone(),
                                name: identity.1.clone(),
                                value: Some(value.clone()),
                            }),
                            Some(previous) if previous != value => callback(RegistryEvent {
                                kind: RegistryEventKind::Modified,
                                key: identity.0.clone(),
                                name: identity.1.clone(),
                                value: Some(value.clone()),
                            }),
                            _ => {}
                        }
                    }

                    for identity in known.keys() {
                        if !current.contains_key(identity) {
                            callback(RegistryEvent {
                                kind: RegistryEventKind::Removed,
                                key: identity.0.clone(),
                                name: identity.1.clone(),
                                value: None,
                            });
                        }
                    }

                    known = current;
                }
            })
            .unwrap_or_else(|err| {
                warn!(error = %err, "failed to start registry telemetry worker");
                panic!("failed to start registry telemetry worker: {err}");
            });

        Self { stop }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for RegistryTelemetry {
    fn drop(&mut self) {
        self.stop();
    }
}

fn snapshot_all() -> HashMap<(String, String), String> {
    let mut values = HashMap::new();
    for key in WATCH_KEYS {
        if let Ok(entries) = query_values(key) {
            for (name, value) in entries {
                values.insert(((*key).to_string(), name), value);
            }
        }
    }
    values
}

fn query_values(key: &str) -> Result<Vec<(String, String)>, std::io::Error> {
    let mut command = Command::new("reg.exe");
    command.args(["query", key]);

    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    let output = command.output()?;
    if !output.status.success() {
        return Ok(Vec::new());
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut entries = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("HKEY_") || trimmed.starts_with("HKLM") {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let type_index = parts
            .iter()
            .position(|part| part.starts_with("REG_"))
            .unwrap_or(1);

        if type_index == 0 || type_index + 1 >= parts.len() {
            continue;
        }

        let name = parts[..type_index].join(" ");
        let value = parts[type_index + 1..].join(" ");
        entries.push((name, value));
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watched_keys_include_run_and_runonce() {
        assert!(WATCH_KEYS.iter().any(|key| key.ends_with(r"\Run")));
        assert!(WATCH_KEYS.iter().any(|key| key.ends_with(r"\RunOnce")));
    }
}
