use thiserror::Error;

#[derive(Debug, Error)]
pub enum RealtimeError {
    #[error("no watch paths configured")]
    NoWatchPaths,

    #[error("watch path does not exist: {0}")]
    MissingPath(String),

    #[error("notify error: {0}")]
    Notify(#[from] notify::Error),

    #[error("monitor is already running")]
    AlreadyRunning,

    #[error("monitor worker thread failed to start: {0}")]
    ThreadStart(String),
}
