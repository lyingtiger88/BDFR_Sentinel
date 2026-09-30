mod engine;
mod error;
mod model;
mod scanner;

pub use engine::{EngineRegistry, ScanEngine};
pub use error::ScanError;
pub use model::{
    Detection, DetectionKind, FileMetadata, ScanReport, ScanVerdict, ThreatLevel,
};
pub use scanner::{FileScanner, ScannerConfig};
