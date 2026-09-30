use crate::{Detection, ScanError};

pub trait ScanEngine: Send + Sync {
    fn name(&self) -> &'static str;
    fn scan_bytes(&self, data: &[u8]) -> Result<Vec<Detection>, ScanError>;
}

#[derive(Default)]
pub struct EngineRegistry {
    engines: Vec<Box<dyn ScanEngine>>,
}

impl EngineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<E>(&mut self, engine: E)
    where
        E: ScanEngine + 'static,
    {
        self.engines.push(Box::new(engine));
    }

    pub fn engines(&self) -> &[Box<dyn ScanEngine>] {
        &self.engines
    }

    pub fn len(&self) -> usize {
        self.engines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.engines.is_empty()
    }
}
