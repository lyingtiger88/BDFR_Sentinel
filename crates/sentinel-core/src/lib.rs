mod engine;
mod error;
mod model;
mod policy;
mod scanner;

pub use engine::{EngineRegistry, ScanEngine};
pub use error::ScanError;
pub use model::{
    Detection, DetectionCategory, DetectionKind, FileMetadata, ScanReport, ScanVerdict, ThreatLevel,
};
pub use policy::DetectionPolicy;
pub use scanner::{FileScanner, ScannerConfig};
