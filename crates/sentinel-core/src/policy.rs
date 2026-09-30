use crate::{Detection, DetectionCategory, ScanVerdict, ThreatLevel};

#[derive(Debug, Clone)]
pub struct DetectionPolicy {
    pub ignore_crack_only: bool,
    pub ignore_license_bypass_only: bool,
    pub ignore_pua_only: bool,
}

impl Default for DetectionPolicy {
    fn default() -> Self {
        Self {
            ignore_crack_only: true,
            ignore_license_bypass_only: true,
            ignore_pua_only: false,
        }
    }
}

impl DetectionPolicy {
    pub fn evaluate(&self, detections: Vec<Detection>) -> ScanVerdict {
        let actionable: Vec<Detection> = detections
            .into_iter()
            .filter(|d| !self.is_ignored_category(d.category))
            .collect();

        let level = actionable
            .iter()
            .map(|d| d.level)
            .max()
            .unwrap_or(ThreatLevel::Clean);

        ScanVerdict {
            level,
            detections: actionable,
        }
    }

    fn is_ignored_category(&self, category: DetectionCategory) -> bool {
        match category {
            DetectionCategory::Crack => self.ignore_crack_only,
            DetectionCategory::LicenseBypass => self.ignore_license_bypass_only,
            DetectionCategory::PotentiallyUnwanted => self.ignore_pua_only,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DetectionKind, ThreatLevel};

    fn detection(category: DetectionCategory, level: ThreatLevel) -> Detection {
        Detection {
            engine: "test".to_string(),
            rule_id: None,
            kind: DetectionKind::Signature,
            category,
            level,
            title: "test".to_string(),
            details: None,
        }
    }

    #[test]
    fn ignores_crack_only_by_default() {
        let verdict = DetectionPolicy::default().evaluate(vec![detection(
            DetectionCategory::Crack,
            ThreatLevel::Malicious,
        )]);
        assert_eq!(verdict.level, ThreatLevel::Clean);
    }

    #[test]
    fn malware_still_wins_if_file_is_also_a_crack() {
        let verdict = DetectionPolicy::default().evaluate(vec![
            detection(DetectionCategory::Crack, ThreatLevel::Malicious),
            detection(DetectionCategory::Trojan, ThreatLevel::Malicious),
        ]);
        assert_eq!(verdict.level, ThreatLevel::Malicious);
        assert_eq!(verdict.detections.len(), 1);
        assert_eq!(verdict.detections[0].category, DetectionCategory::Trojan);
    }
}
