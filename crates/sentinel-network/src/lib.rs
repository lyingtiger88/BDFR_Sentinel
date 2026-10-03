use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallMode {
    #[default]
    Smart,
    Whitelist,
    BlockAll,
    AllowAll,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallDirection {
    #[default]
    Outbound,
    Inbound,
    Both,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallAction {
    #[default]
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallProtocol {
    #[default]
    Any,
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationRule {
    pub application: PathBuf,
    #[serde(default)]
    pub direction: FirewallDirection,
    #[serde(default)]
    pub action: FirewallAction,
    #[serde(default)]
    pub protocol: FirewallProtocol,
    #[serde(default)]
    pub remote_ports: Vec<u16>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallPolicy {
    #[serde(default)]
    pub mode: FirewallMode,
    #[serde(default)]
    pub application_rules: Vec<ApplicationRule>,
    #[serde(default = "default_true")]
    pub allow_loopback: bool,
}

impl Default for FirewallPolicy {
    fn default() -> Self {
        Self {
            mode: FirewallMode::Smart,
            application_rules: Vec::new(),
            allow_loopback: true,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkBlocklist {
    entries: Vec<IpNet>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkProtectionReport {
    pub loaded_entries: usize,
    pub applied_filters: usize,
    pub application_rules: usize,
    pub mode: FirewallMode,
    pub backend: String,
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

            let network = value
                .parse::<IpNet>()
                .or_else(|_| value.parse::<std::net::IpAddr>().map(IpNet::from));

            if let Ok(network) = network {
                if !entries.contains(&network) {
                    entries.push(network);
                }
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
        self.entries
            .iter()
            .any(|network| network.contains(&address))
    }

    pub fn entries(&self) -> &[IpNet] {
        &self.entries
    }
}

#[cfg(windows)]
mod kernel {
    use super::*;
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;
    use wfp::{
        ActionType, AppIdConditionBuilder, FilterBuilder, FilterEngine, FilterEngineBuilder,
        FilterWeight, IpAddressConditionBuilder, Layer, PortConditionBuilder,
        ProtocolConditionBuilder, SubLayerBuilder, Transaction,
    };

    const SUBLAYER_GUID: wfp::GUID = wfp::GUID::from_u128(0x7d56a933_10b8_4b0f_a22c_0b90f4ae5101);

    const WEIGHT_LOOPBACK: u64 = 10_000;
    const WEIGHT_BLOCKLIST: u64 = 9_500;
    const WEIGHT_APP_BLOCK: u64 = 9_200;
    const WEIGHT_APP_ALLOW: u64 = 9_000;
    const WEIGHT_DEFAULT_BLOCK: u64 = 100;

    pub struct KernelFirewall {
        _engine: FilterEngine,
        report: NetworkProtectionReport,
    }

    impl KernelFirewall {
        pub fn install(blocklist: &NetworkBlocklist, policy: &FirewallPolicy) -> io::Result<Self> {
            let mut engine = FilterEngineBuilder::default()
                .dynamic()
                .transaction_timeout(Duration::from_secs(5))
                .open()?;

            let transaction = Transaction::new(&mut engine)?;

            SubLayerBuilder::default()
                .name("BDFR Sentinel Kernel Firewall")
                .description("BDFR Sentinel WFP/ALE kernel-enforced firewall policy")
                .guid(SUBLAYER_GUID)
                .weight(0x7f00)
                .add(&transaction)?;

            let mut applied_filters = 0usize;
            let mut application_rules = 0usize;

            if policy.allow_loopback {
                applied_filters += add_loopback_filters(&transaction)?;
            }

            match policy.mode {
                FirewallMode::AllowAll => {}
                FirewallMode::BlockAll => {
                    applied_filters += add_default_block_filters(&transaction)?;
                }
                FirewallMode::Smart | FirewallMode::Whitelist => {
                    for network in blocklist.entries() {
                        applied_filters += add_blocklist_network(&transaction, network)?;
                    }

                    for rule in policy.application_rules.iter().filter(|rule| rule.enabled) {
                        let added = add_application_rule(&transaction, rule)?;
                        applied_filters += added;
                        if added > 0 {
                            application_rules += 1;
                        }
                    }

                    if policy.mode == FirewallMode::Whitelist {
                        applied_filters += add_default_block_filters(&transaction)?;
                    }
                }
            }

            transaction.commit()?;

            let report = NetworkProtectionReport {
                loaded_entries: blocklist.len(),
                applied_filters,
                application_rules,
                mode: policy.mode,
                backend: "wfp-ale-kernel".to_string(),
            };

            Ok(Self {
                _engine: engine,
                report,
            })
        }

        pub fn report(&self) -> &NetworkProtectionReport {
            &self.report
        }
    }

    fn add_loopback_filters(transaction: &Transaction<'_>) -> io::Result<usize> {
        let mut count = 0;

        let v4 = IpAddressConditionBuilder::remote()
            .subnet_v4(Ipv4Addr::new(127, 0, 0, 0), 8)
            .build();
        for layer in [Layer::ConnectV4, Layer::AcceptV4] {
            add_filter(
                transaction,
                "BDFR Sentinel Allow IPv4 Loopback",
                "Keep local IPv4 IPC traffic available",
                ActionType::Permit,
                layer,
                WEIGHT_LOOPBACK,
                vec![v4.clone()],
            )?;
            count += 1;
        }

        let v6 = IpAddressConditionBuilder::remote()
            .subnet_v6(Ipv6Addr::LOCALHOST, 128)
            .build();
        for layer in [Layer::ConnectV6, Layer::AcceptV6] {
            add_filter(
                transaction,
                "BDFR Sentinel Allow IPv6 Loopback",
                "Keep local IPv6 IPC traffic available",
                ActionType::Permit,
                layer,
                WEIGHT_LOOPBACK,
                vec![v6.clone()],
            )?;
            count += 1;
        }

        Ok(count)
    }

    fn add_default_block_filters(transaction: &Transaction<'_>) -> io::Result<usize> {
        let mut count = 0;
        for layer in [
            Layer::ConnectV4,
            Layer::ConnectV6,
            Layer::AcceptV4,
            Layer::AcceptV6,
        ] {
            add_filter(
                transaction,
                "BDFR Sentinel Default Deny",
                "Default-deny WFP policy for connections without an explicit allow rule",
                ActionType::Block,
                layer,
                WEIGHT_DEFAULT_BLOCK,
                Vec::new(),
            )?;
            count += 1;
        }
        Ok(count)
    }

    fn add_blocklist_network(transaction: &Transaction<'_>, network: &IpNet) -> io::Result<usize> {
        let (condition, layers): (_, &[Layer]) = match network {
            IpNet::V4(network) => (
                IpAddressConditionBuilder::remote()
                    .subnet_v4(network.network(), network.prefix_len())
                    .build(),
                &[Layer::ConnectV4, Layer::AcceptV4],
            ),
            IpNet::V6(network) => (
                IpAddressConditionBuilder::remote()
                    .subnet_v6(network.network(), network.prefix_len())
                    .build(),
                &[Layer::ConnectV6, Layer::AcceptV6],
            ),
        };

        let mut count = 0;
        for layer in layers {
            add_filter(
                transaction,
                "BDFR Sentinel Threat Block",
                "Block a remote address from the Sentinel network reputation list",
                ActionType::Block,
                *layer,
                WEIGHT_BLOCKLIST,
                vec![condition.clone()],
            )?;
            count += 1;
        }
        Ok(count)
    }

    fn add_application_rule(
        transaction: &Transaction<'_>,
        rule: &ApplicationRule,
    ) -> io::Result<usize> {
        if !rule.application.is_file() {
            return Ok(0);
        }

        let action = match rule.action {
            FirewallAction::Allow => ActionType::Permit,
            FirewallAction::Block => ActionType::Block,
        };
        let weight = match rule.action {
            FirewallAction::Allow => WEIGHT_APP_ALLOW,
            FirewallAction::Block => WEIGHT_APP_BLOCK,
        };

        let mut count = 0;
        let ports: Vec<Option<u16>> = if rule.remote_ports.is_empty() {
            vec![None]
        } else {
            rule.remote_ports.iter().copied().map(Some).collect()
        };

        for ipv6 in [false, true] {
            for layer in layers_for(rule.direction, ipv6) {
                for port in &ports {
                    let app_condition = AppIdConditionBuilder::new()
                        .equal(&rule.application)?
                        .build();

                    let mut conditions = vec![app_condition];
                    if let Some(port) = port {
                        conditions.push(PortConditionBuilder::remote().equal(*port).build());
                    }

                    match rule.protocol {
                        FirewallProtocol::Any => {}
                        FirewallProtocol::Tcp => {
                            conditions.push(ProtocolConditionBuilder::tcp().build())
                        }
                        FirewallProtocol::Udp => {
                            conditions.push(ProtocolConditionBuilder::udp().build())
                        }
                    }

                    add_filter(
                        transaction,
                        "BDFR Sentinel Application Rule",
                        "Per-application WFP policy",
                        action,
                        layer,
                        weight,
                        conditions,
                    )?;
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    fn layers_for(direction: FirewallDirection, ipv6: bool) -> Vec<Layer> {
        let outbound = if ipv6 {
            Layer::ConnectV6
        } else {
            Layer::ConnectV4
        };
        let inbound = if ipv6 {
            Layer::AcceptV6
        } else {
            Layer::AcceptV4
        };

        match direction {
            FirewallDirection::Outbound => vec![outbound],
            FirewallDirection::Inbound => vec![inbound],
            FirewallDirection::Both => vec![outbound, inbound],
        }
    }

    fn add_filter(
        transaction: &Transaction<'_>,
        name: &str,
        description: &str,
        action: ActionType,
        layer: Layer,
        weight: u64,
        conditions: Vec<wfp::Condition>,
    ) -> io::Result<()> {
        let mut builder = FilterBuilder::default()
            .name(name)
            .description(description)
            .action(action)
            .layer(layer)
            .sublayer(SUBLAYER_GUID)
            .weight(FilterWeight::Exact(weight));

        for condition in conditions {
            builder = builder.condition(condition);
        }

        builder.add(transaction)?;
        Ok(())
    }
}

#[cfg(windows)]
pub use kernel::KernelFirewall;

#[cfg(not(windows))]
pub struct KernelFirewall {
    report: NetworkProtectionReport,
}

#[cfg(not(windows))]
impl KernelFirewall {
    pub fn install(
        blocklist: &NetworkBlocklist,
        policy: &FirewallPolicy,
    ) -> Result<Self, std::io::Error> {
        Ok(Self {
            report: NetworkProtectionReport {
                loaded_entries: blocklist.len(),
                applied_filters: 0,
                application_rules: 0,
                mode: policy.mode,
                backend: "unsupported".to_string(),
            },
        })
    }

    pub fn report(&self) -> &NetworkProtectionReport {
        &self.report
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

    #[test]
    fn default_policy_is_smart_and_loopback_safe() {
        let policy = FirewallPolicy::default();
        assert_eq!(policy.mode, FirewallMode::Smart);
        assert!(policy.allow_loopback);
        assert!(policy.application_rules.is_empty());
    }

    #[test]
    fn duplicate_blocklist_entries_are_collapsed() {
        let path =
            std::env::temp_dir().join(format!("bdfr-sentinel-network-{}.txt", std::process::id()));
        fs::write(&path, "203.0.113.0/24\n203.0.113.0/24\n198.51.100.10\n").unwrap();

        let list = NetworkBlocklist::load(&path).unwrap();
        let _ = fs::remove_file(path);

        assert_eq!(list.len(), 2);
    }
}
