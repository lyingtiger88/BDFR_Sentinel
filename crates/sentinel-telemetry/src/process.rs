use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use sysinfo::{Pid, ProcessesToUpdate, System};
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessEventKind {
    Started,
    Exited,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub executable: Option<PathBuf>,
    pub command_line: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub kind: ProcessEventKind,
    pub process: ProcessSnapshot,
}

pub struct ProcessTelemetry {
    stop: Arc<AtomicBool>,
}

impl ProcessTelemetry {
    pub fn start<F>(poll_interval: Duration, on_event: F) -> Self
    where
        F: Fn(ProcessEvent) + Send + Sync + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_worker = Arc::clone(&stop);
        let callback = Arc::new(on_event);

        thread::Builder::new()
            .name("bdfr-sentinel-process-telemetry".to_string())
            .spawn(move || {
                let mut system = System::new_all();
                let mut known: HashMap<Pid, ProcessSnapshot> = HashMap::new();

                system.refresh_processes(ProcessesToUpdate::All, true);
                for (pid, process) in system.processes() {
                    known.insert(*pid, snapshot(*pid, process));
                }

                while !stop_worker.load(Ordering::Relaxed) {
                    thread::sleep(poll_interval);
                    system.refresh_processes(ProcessesToUpdate::All, true);

                    let mut current = HashMap::new();

                    for (pid, process) in system.processes() {
                        let snap = snapshot(*pid, process);
                        if !known.contains_key(pid) {
                            callback(ProcessEvent {
                                kind: ProcessEventKind::Started,
                                process: snap.clone(),
                            });
                        }
                        current.insert(*pid, snap);
                    }

                    for (pid, process) in &known {
                        if !current.contains_key(pid) {
                            callback(ProcessEvent {
                                kind: ProcessEventKind::Exited,
                                process: process.clone(),
                            });
                        }
                    }

                    known = current;
                }
            })
            .unwrap_or_else(|err| {
                warn!(error = %err, "failed to start process telemetry worker");
                panic!("failed to start process telemetry worker: {err}");
            });

        Self { stop }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for ProcessTelemetry {
    fn drop(&mut self) {
        self.stop();
    }
}

fn snapshot(pid: Pid, process: &sysinfo::Process) -> ProcessSnapshot {
    ProcessSnapshot {
        pid: pid.as_u32(),
        parent_pid: process.parent().map(|pid| pid.as_u32()),
        name: process.name().to_string_lossy().into_owned(),
        executable: process.exe().map(PathBuf::from),
        command_line: process
            .cmd()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_types_are_distinct() {
        assert_ne!(ProcessEventKind::Started, ProcessEventKind::Exited);
    }
}
