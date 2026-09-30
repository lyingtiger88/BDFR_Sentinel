use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSummary {
    pub is_pe: bool,
    pub machine: Option<String>,
    pub section_count: Option<u16>,
}

pub fn inspect_header(data: &[u8]) -> PeSummary {
    let is_pe = data.len() >= 2 && &data[..2] == b"MZ";
    PeSummary {
        is_pe,
        machine: None,
        section_count: None,
    }
}
