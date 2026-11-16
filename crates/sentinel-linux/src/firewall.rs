use ipnet::IpNet;
use sentinel_network::{FirewallMode, NetworkBlocklist, NetworkProtectionReport};
use std::io::{self, Write};
use std::process::{Command, Stdio};

const TABLE: &str = "bdfr_sentinel";

/// Install an outbound IP blocklist in a Sentinel-owned nftables table.
///
/// The operation is one nftables transaction. It does not flush, edit or
/// replace any pre-existing user tables, chains or rules.
pub fn install_blocklist(blocklist: &NetworkBlocklist) -> io::Result<NetworkProtectionReport> {
    require_root()?;

    let mut script = format!(
        "add table inet {TABLE}\n         add set inet {TABLE} blocked_v4 {{ type ipv4_addr; flags interval; }}\n         add set inet {TABLE} blocked_v6 {{ type ipv6_addr; flags interval; }}\n         add chain inet {TABLE} output {{ type filter hook output priority filter; policy accept; }}\n         add rule inet {TABLE} output ip daddr @blocked_v4 drop\n         add rule inet {TABLE} output ip6 daddr @blocked_v6 drop\n"
    );

    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for network in blocklist.entries() {
        match network {
            IpNet::V4(value) => ipv4.push(value.to_string()),
            IpNet::V6(value) => ipv6.push(value.to_string()),
        }
    }

    if !ipv4.is_empty() {
        script.push_str(&format!(
            "add element inet {TABLE} blocked_v4 {{ {} }}\n",
            ipv4.join(", ")
        ));
    }
    if !ipv6.is_empty() {
        script.push_str(&format!(
            "add element inet {TABLE} blocked_v6 {{ {} }}\n",
            ipv6.join(", ")
        ));
    }

    apply_transaction(&script)?;
    Ok(NetworkProtectionReport {
        loaded_entries: blocklist.len(),
        applied_filters: 2,
        application_rules: 0,
        mode: FirewallMode::Smart,
        backend: "nftables".to_string(),
        kernel_enforced: true,
        ipv6_enabled: true,
    })
}

/// Remove only the BDFR Sentinel table. Other firewall configuration is untouched.
pub fn remove_sentinel_table() -> io::Result<()> {
    require_root()?;
    apply_transaction(&format!("delete table inet {TABLE}\n"))
}

fn require_root() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "nftables policy changes require root; rerun with sudo",
        ));
    }
    Ok(())
}

fn apply_transaction(script: &str) -> io::Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    child.stdin.take()
        .ok_or_else(|| io::Error::other("failed to open nftables stdin"))?
        .write_all(script.as_bytes())?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "nftables transaction failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}
