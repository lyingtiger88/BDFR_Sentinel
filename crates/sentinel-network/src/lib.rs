use ipnet::IpNet;
use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::warn;

const RULE_PREFIX: &str = "BDFR Sentinel Network Block";
const MAX_RULE_CHUNKS: usize = 64;
const ADDRESSES_PER_RULE: usize = 128;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkBlocklist {
    entries: Vec<IpNet>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkProtectionReport {
    pub loaded_entries: usize,
    pub applied_rules: usize,
}

impl NetworkBlocklist {
    pub fn load(path: &Path) -> Result<Self, std::io::Error> {
        if !path.is_file() {
            return Ok(Self::default());
        }

        let text = fs::read_to_string(path)?;
        let mut entries = Vec::new();

        for line in text.lines() {
            let value = line.split('#').next().unwrap_or_default().trim();
            if value.is_empty() {
                continue;
            }

            if let Ok(network) = value.parse::<IpNet>() {
                if !entries.contains(&network) {
                    entries.push(network);
                }
            } else if let Ok(address) = value.parse::<std::net::IpAddr>() {
                entries.push(IpNet::from(address));
            }
        }

        Ok(Self { entries })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, address: std::net::IpAddr) -> bool {
        self.entries.iter().any(|network| network.contains(&address))
    }

    pub fn entries(&self) -> &[IpNet] {
        &self.entries
    }
}

#[cfg(windows)]
pub fn apply_windows_firewall_blocklist(
    blocklist: &NetworkBlocklist,
) -> NetworkProtectionReport {
    for family in ["v4", "v6"] {
        for index in 0..MAX_RULE_CHUNKS {
            let name = format!("{RULE_PREFIX} {family}-{index}");
            let _ = Command::new("netsh.exe")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={name}"),
                ])
                .output();
        }
    }

    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for network in blocklist.entries() {
        match network {
            IpNet::V4(_) => v4.push(network.to_string()),
            IpNet::V6(_) => v6.push(network.to_string()),
        }
    }

    let mut applied_rules = 0;
    for (family, entries) in [("v4", v4), ("v6", v6)] {
        for (index, chunk) in entries.chunks(ADDRESSES_PER_RULE).enumerate() {
            if index >= MAX_RULE_CHUNKS {
                warn!(
                    family,
                    max_rules = MAX_RULE_CHUNKS,
                    "network blocklist truncated because rule limit was reached"
                );
                break;
            }

            let name = format!("{RULE_PREFIX} {family}-{index}");
            let remote = chunk.join(",");
            let status = Command::new("netsh.exe")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={name}"),
                    "dir=out",
                    "action=block",
                    &format!("remoteip={remote}"),
                    "enable=yes",
                    "profile=any",
                ])
                .status();

            match status {
                Ok(status) if status.success() => applied_rules += 1,
                Ok(_) => warn!(rule = %name, "Windows Firewall rejected network block rule"),
                Err(err) => warn!(rule = %name, error = %err, "could not invoke Windows Firewall"),
            }
        }
    }

    NetworkProtectionReport {
        loaded_entries: blocklist.len(),
        applied_rules,
    }
}

#[cfg(not(windows))]
pub fn apply_windows_firewall_blocklist(
    blocklist: &NetworkBlocklist,
) -> NetworkProtectionReport {
    NetworkProtectionReport {
        loaded_entries: blocklist.len(),
        applied_rules: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_ipv4_and_cidr_entries() {
        let blocklist = NetworkBlocklist {
            entries: vec![
                "203.0.113.0/24".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
            ],
        };

        assert!(blocklist.contains("203.0.113.8".parse().unwrap()));
        assert!(!blocklist.contains("198.51.100.8".parse().unwrap()));
        assert!(blocklist.contains("2001:db8::10".parse().unwrap()));
    }
}
