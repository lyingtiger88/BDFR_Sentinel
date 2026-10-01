use sentinel_core::ThreatLevel;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BehaviorSignalKind {
    ScriptInterpreter,
    SuspiciousParentChild,
    TempExecutable,
    PersistenceChange,
    RemoteThread,
    RwxMemory,
    MassFileModification,
    CredentialAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorSignal {
    pub pid: u32,
    pub kind: BehaviorSignalKind,
    pub weight: u32,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct BehaviorAssessment {
    pub pid: u32,
    pub score: u32,
    pub level: ThreatLevel,
    pub distinct_signal_kinds: usize,
    pub signals: Vec<BehaviorSignal>,
}

impl BehaviorAssessment {
    pub fn is_actionable_malicious(&self) -> bool {
        self.level == ThreatLevel::Malicious && self.distinct_signal_kinds >= 3
    }
}

#[derive(Debug)]
struct TimedSignal {
    at: Instant,
    signal: BehaviorSignal,
}

#[derive(Debug)]
pub struct BehaviorEngine {
    window: Duration,
    suspicious_threshold: u32,
    malicious_threshold: u32,
    by_pid: HashMap<u32, VecDeque<TimedSignal>>,
}

impl Default for BehaviorEngine {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(30),
            suspicious_threshold: 40,
            malicious_threshold: 80,
            by_pid: HashMap::new(),
        }
    }
}

impl BehaviorEngine {
    pub fn with_thresholds(
        window: Duration,
        suspicious_threshold: u32,
        malicious_threshold: u32,
    ) -> Self {
        Self {
            window,
            suspicious_threshold,
            malicious_threshold,
            by_pid: HashMap::new(),
        }
    }

    pub fn observe(&mut self, signal: BehaviorSignal) -> BehaviorAssessment {
        let now = Instant::now();
        let queue = self.by_pid.entry(signal.pid).or_default();
        queue.push_back(TimedSignal { at: now, signal });

        while queue
            .front()
            .is_some_and(|item| now.duration_since(item.at) > self.window)
        {
            queue.pop_front();
        }

        let mut score = 0;
        let mut signals = Vec::with_capacity(queue.len());
        let mut distinct_kinds = HashSet::new();
        for item in queue.iter() {
            score += item.signal.weight;
            distinct_kinds.insert(item.signal.kind);
            signals.push(item.signal.clone());
        }

        let level = if score >= self.malicious_threshold {
            ThreatLevel::Malicious
        } else if score >= self.suspicious_threshold {
            ThreatLevel::Suspicious
        } else {
            ThreatLevel::Clean
        };

        BehaviorAssessment {
            pid: signals.first().map(|s| s.pid).unwrap_or_default(),
            score,
            level,
            distinct_signal_kinds: distinct_kinds.len(),
            signals,
        }
    }

    pub fn forget_process(&mut self, pid: u32) {
        self.by_pid.remove(&pid);
    }
}

pub fn process_start_signals(
    pid: u32,
    parent_name: Option<&str>,
    process_name: &str,
    executable: Option<&std::path::Path>,
    command_line: &[String],
) -> Vec<BehaviorSignal> {
    let mut out = Vec::new();
    let name = process_name.to_ascii_lowercase();
    let parent = parent_name.unwrap_or_default().to_ascii_lowercase();
    let command = command_line.join(" ").to_ascii_lowercase();

    if matches!(
        name.as_str(),
        "powershell.exe" | "pwsh.exe" | "wscript.exe" | "cscript.exe" | "mshta.exe"
    ) {
        out.push(BehaviorSignal {
            pid,
            kind: BehaviorSignalKind::ScriptInterpreter,
            weight: 15,
            details: format!("script interpreter started: {process_name}"),
        });
    }

    if matches!(
        parent.as_str(),
        "winword.exe" | "excel.exe" | "powerpnt.exe" | "outlook.exe"
    ) && matches!(
        name.as_str(),
        "powershell.exe" | "cmd.exe" | "wscript.exe" | "cscript.exe" | "mshta.exe"
    ) {
        out.push(BehaviorSignal {
            pid,
            kind: BehaviorSignalKind::SuspiciousParentChild,
            weight: 35,
            details: format!("{parent} spawned {name}"),
        });
    }

    if let Some(path) = executable {
        let lower = path.to_string_lossy().to_ascii_lowercase();
        if lower.contains(r"\temp\") || lower.contains(r"\appdata\local\temp\") {
            out.push(BehaviorSignal {
                pid,
                kind: BehaviorSignalKind::TempExecutable,
                weight: 20,
                details: format!(
                    "process image launched from temporary directory: {}",
                    path.display()
                ),
            });
        }
    }

    if command.contains("-enc ")
        || command.contains("-encodedcommand")
        || command.contains("frombase64string")
    {
        out.push(BehaviorSignal {
            pid,
            kind: BehaviorSignalKind::ScriptInterpreter,
            weight: 30,
            details: "encoded script command line".to_string(),
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiple_signals_raise_level() {
        let mut engine = BehaviorEngine::default();
        let first = engine.observe(BehaviorSignal {
            pid: 10,
            kind: BehaviorSignalKind::ScriptInterpreter,
            weight: 15,
            details: "one".to_string(),
        });
        assert_eq!(first.level, ThreatLevel::Clean);

        let second = engine.observe(BehaviorSignal {
            pid: 10,
            kind: BehaviorSignalKind::SuspiciousParentChild,
            weight: 35,
            details: "two".to_string(),
        });
        assert_eq!(second.level, ThreatLevel::Suspicious);
    }

    #[test]
    fn actionable_malicious_requires_three_distinct_signal_kinds() {
        let mut engine = BehaviorEngine::with_thresholds(Duration::from_secs(30), 40, 80);

        let first = engine.observe(BehaviorSignal {
            pid: 42,
            kind: BehaviorSignalKind::ScriptInterpreter,
            weight: 45,
            details: "script".to_string(),
        });
        assert!(!first.is_actionable_malicious());

        let second = engine.observe(BehaviorSignal {
            pid: 42,
            kind: BehaviorSignalKind::SuspiciousParentChild,
            weight: 45,
            details: "parent-child".to_string(),
        });
        assert_eq!(second.level, ThreatLevel::Malicious);
        assert!(!second.is_actionable_malicious());

        let third = engine.observe(BehaviorSignal {
            pid: 42,
            kind: BehaviorSignalKind::RwxMemory,
            weight: 45,
            details: "rwx".to_string(),
        });
        assert!(third.is_actionable_malicious());
        assert_eq!(third.distinct_signal_kinds, 3);
    }

    #[test]
    fn common_script_host_alone_is_not_malware() {
        let signals = process_start_signals(
            100,
            Some("explorer.exe"),
            "powershell.exe",
            None,
            &["powershell.exe".to_string()],
        );
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].weight, 15);
    }
}
