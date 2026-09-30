use semver::Version;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub version: Version,
    pub channel: String,
}

pub fn is_newer(current: &Version, available: &Version) -> bool {
    available > current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_ordering_is_correct() {
        let current = Version::parse("1.9.0").unwrap();
        let available = Version::parse("1.10.0").unwrap();
        assert!(is_newer(&current, &available));
    }
}
