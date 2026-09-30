#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorState {
    Stopped,
    Running,
    Paused,
}

#[derive(Debug)]
pub struct RealtimeMonitor {
    state: MonitorState,
}

impl Default for RealtimeMonitor {
    fn default() -> Self {
        Self {
            state: MonitorState::Stopped,
        }
    }
}

impl RealtimeMonitor {
    pub fn state(&self) -> MonitorState {
        self.state
    }
}
