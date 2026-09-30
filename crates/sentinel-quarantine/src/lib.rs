use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineId(pub Uuid);

impl QuarantineId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for QuarantineId {
    fn default() -> Self {
        Self::new()
    }
}
