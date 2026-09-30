use sentinel_core::{
    Detection, DetectionCategory, DetectionKind, ScanEngine, ScanError, ThreatLevel,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSummary {
    pub is_pe: bool,
    pub machine: Option<String>,
    pub section_count: Option<u16>,
    pub pe_offset: Option<u32>,
    pub characteristics: Option<u16>,
}

pub fn inspect_header(data: &[u8]) -> PeSummary {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return PeSummary {
            is_pe: false,
            machine: None,
            section_count: None,
            pe_offset: None,
            characteristics: None,
        };
    }

    let pe_offset = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]);
    let offset = pe_offset as usize;

    if offset.checked_add(24).is_none() || offset + 24 > data.len() {
        return PeSummary {
            is_pe: false,
            machine: None,
            section_count: None,
            pe_offset: Some(pe_offset),
            characteristics: None,
        };
    }

    if &data[offset..offset + 4] != b"PE\0\0" {
        return PeSummary {
            is_pe: false,
            machine: None,
            section_count: None,
            pe_offset: Some(pe_offset),
            characteristics: None,
        };
    }

    let machine_raw = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
    let section_count = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);
    let characteristics = u16::from_le_bytes([data[offset + 22], data[offset + 23]]);

    PeSummary {
        is_pe: true,
        machine: Some(machine_name(machine_raw).to_string()),
        section_count: Some(section_count),
        pe_offset: Some(pe_offset),
        characteristics: Some(characteristics),
    }
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014c => "x86",
        0x8664 => "x86_64",
        0xaa64 => "arm64",
        0x01c0 => "arm",
        _ => "unknown",
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PeAnalyzerEngine;

impl ScanEngine for PeAnalyzerEngine {
    fn name(&self) -> &'static str {
        "pe-analyzer"
    }

    fn scan_bytes(&self, data: &[u8]) -> Result<Vec<Detection>, ScanError> {
        if data.len() < 2 || &data[..2] != b"MZ" {
            return Ok(Vec::new());
        }

        let summary = inspect_header(data);

        if !summary.is_pe {
            return Ok(vec![Detection {
                engine: self.name().to_string(),
                rule_id: Some("PE-MALFORMED-001".to_string()),
                kind: DetectionKind::StaticAnalysis,
                category: DetectionCategory::Unknown,
                level: ThreatLevel::Suspicious,
                title: "Malformed PE structure".to_string(),
                details: summary
                    .pe_offset
                    .map(|offset| format!("PE header offset: {offset}")),
            }]);
        }

        let mut detections = Vec::new();

        if summary.section_count.unwrap_or_default() > 16 {
            detections.push(Detection {
                engine: self.name().to_string(),
                rule_id: Some("PE-SECTIONS-001".to_string()),
                kind: DetectionKind::Heuristic,
                category: DetectionCategory::Unknown,
                level: ThreatLevel::Suspicious,
                title: "Unusually high PE section count".to_string(),
                details: summary
                    .section_count
                    .map(|count| format!("section_count={count}")),
            });
        }

        Ok(detections)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe_input() {
        let summary = inspect_header(b"hello world");
        assert!(!summary.is_pe);
    }

    #[test]
    fn parses_minimal_pe_header() {
        let mut data = vec![0u8; 0x100];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data[0x84..0x86].copy_from_slice(&(0x8664u16).to_le_bytes());
        data[0x86..0x88].copy_from_slice(&(3u16).to_le_bytes());

        let summary = inspect_header(&data);
        assert!(summary.is_pe);
        assert_eq!(summary.machine.as_deref(), Some("x86_64"));
        assert_eq!(summary.section_count, Some(3));
    }
}
