use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use sentinel_core::{EngineRegistry, FileScanner, ScannerConfig, ThreatLevel};
use sentinel_definitions::{ClamHashDatabase, HashDefinitionEngine};
use sentinel_realtime::{RealtimeConfig, RealtimeMonitor};
use sentinel_yara::{YaraEngine, YaraXBackend};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use walkdir::WalkDir;

#[derive(Debug, Parser)]
#[command(name = "bdfr-sentinel-linux", version, about = "BDFR Sentinel Debian scanner")]
struct Cli {
    #[arg(long, default_value = "/var/lib/bdfr-sentinel/definitions")]
    definitions_dir: PathBuf,
    #[arg(long, default_value = "/var/lib/bdfr-sentinel/definitions/yara")]
    rules_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan a file or directory visible to the current user.
    Scan { path: PathBuf },
    /// Monitor a directory and scan changed files after filesystem events.
    Watch { path: PathBuf },
    /// Print detected Linux integration capabilities without changing system state.
    Capabilities,
    /// Install outbound IP block rules in the isolated Sentinel nftables table.
    FirewallInstall { blocklist: PathBuf },
    /// Remove only the Sentinel-owned nftables table.
    FirewallRemove,
    /// Encrypt and move a suspicious file into the protected quarantine.
    Quarantine { path: PathBuf, #[arg(long, default_value = "user initiated")] reason: String },
    /// Restore a quarantined item by its UUID, without overwriting an existing path.
    Restore { id: String },
    /// List encrypted quarantine entries.
    QuarantineList,
}

fn build_scanner(definitions_dir: &Path, rules_dir: &Path) -> Result<Arc<FileScanner>> {
    let mut registry = EngineRegistry::new();
    let mut hashes = HashDefinitionEngine::new();

    let hdb = definitions_dir.join("main.hdb");
    if hdb.is_file() {
        let data = std::fs::read_to_string(&hdb)
            .with_context(|| format!("cannot read {}", hdb.display()))?;
        hashes = hashes.with_hdb(ClamHashDatabase::parse_hdb(&data)
            .context("invalid HDB definition file")?);
    }

    let hsb = definitions_dir.join("main.hsb");
    if hsb.is_file() {
        let data = std::fs::read_to_string(&hsb)
            .with_context(|| format!("cannot read {}", hsb.display()))?;
        hashes = hashes.with_hsb(ClamHashDatabase::parse_hsb(&data)
            .context("invalid HSB definition file")?);
    }

    if hashes.has_definitions() {
        registry.register(hashes);
    }

    if let Some(yara) = YaraXBackend::compile_directory(rules_dir)
        .context("failed to compile YARA-X definitions")?
    {
        registry.register(YaraEngine::new(yara));
    }

    if registry.is_empty() {
        bail!(
            "no usable malware definitions loaded; refusing to label files clean. Install definitions already verified by the trusted updater under {} and YARA rules under {}",
            definitions_dir.display(),
            rules_dir.display()
        );
    }

    Ok(Arc::new(FileScanner::new(ScannerConfig::default(), registry)))
}

fn scan_path(scanner: &FileScanner, path: &Path) -> Result<(usize, usize, usize)> {
    if path.is_file() {
        let report = scanner.scan_file(path)
            .with_context(|| format!("scan failed for {}", path.display()))?;
        println!("{}", serde_json::to_string(&report)?);
        let suspicious = usize::from(report.verdict.level == ThreatLevel::Suspicious);
        let malicious = usize::from(report.verdict.level == ThreatLevel::Malicious);
        return Ok((1, suspicious, malicious));
    }

    if !path.is_dir() {
        bail!("scan target does not exist or is not a regular file/directory: {}", path.display());
    }

    let mut scanned = 0usize;
    let mut suspicious = 0usize;
    let mut malicious = 0usize;
    for entry in WalkDir::new(path).follow_links(false).into_iter().filter_map(|entry| entry.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        match scanner.scan_file(entry.path()) {
            Ok(report) => {
                scanned += 1;
                suspicious += usize::from(report.verdict.level == ThreatLevel::Suspicious);
                malicious += usize::from(report.verdict.level == ThreatLevel::Malicious);
                println!("{}", serde_json::to_string(&report)?);
            }
            Err(error) => eprintln!("SKIPPED {}: {error}", entry.path().display()),
        }
    }
    Ok((scanned, suspicious, malicious))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Capabilities => {
            #[cfg(target_os = "linux")]
            {
                let capabilities = sentinel_linux::host::discover_capabilities();
                println!("{}", serde_json::to_string_pretty(&capabilities)?);
            }
            #[cfg(not(target_os = "linux"))]
            bail!("capability discovery is available only on Linux");
        }
        Command::FirewallInstall { blocklist } => {
            #[cfg(target_os = "linux")]
            {
                use sentinel_network::NetworkBlocklist;
                let blocklist = NetworkBlocklist::load(&blocklist)
                    .with_context(|| format!("cannot read blocklist {}", blocklist.display()))?;
                if blocklist.is_empty() {
                    bail!("blocklist is empty; refusing to install an empty firewall policy");
                }
                let report = sentinel_linux::firewall::install_blocklist(&blocklist)?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = &blocklist;
                bail!("nftables integration is available only on Linux");
            }
        }
        Command::FirewallRemove => {
            #[cfg(target_os = "linux")]
            sentinel_linux::firewall::remove_sentinel_table()?;
            #[cfg(not(target_os = "linux"))]
            bail!("nftables integration is available only on Linux");
        }
        Command::Quarantine { path, reason } => {
            #[cfg(target_os = "linux")]
            {
                let metadata = std::fs::symlink_metadata(&path)?;
                if !metadata.file_type().is_file() {
                    bail!("quarantine accepts regular files only; symlinks and special files are rejected");
                }
                let store = open_quarantine_store()?;
                let entry = store.quarantine_file(&path, reason)?;
                println!("{}", serde_json::to_string_pretty(&entry)?);
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (&path, &reason);
                bail!("Linux quarantine command is available only on Linux");
            }
        }
        Command::Restore { id } => {
            #[cfg(target_os = "linux")]
            {
                let uuid = uuid::Uuid::parse_str(&id).context("invalid quarantine UUID")?;
                let store = open_quarantine_store()?;
                let entry = store.read_entry(sentinel_quarantine::QuarantineId(uuid))?;
                if std::fs::symlink_metadata(&entry.original_path).is_ok() {
                    bail!("restore target already exists; move it first to avoid overwriting data");
                }
                let restored = store.restore(sentinel_quarantine::QuarantineId(uuid))?;
                println!("{}", serde_json::to_string_pretty(&restored)?);
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = &id;
                bail!("Linux quarantine command is available only on Linux");
            }
        }
        Command::QuarantineList => {
            #[cfg(target_os = "linux")]
            {
                let store = open_quarantine_store()?;
                println!("{}", serde_json::to_string_pretty(&store.list_entries()?)?);
            }
            #[cfg(not(target_os = "linux"))]
            bail!("Linux quarantine command is available only on Linux");
        }
        Command::Scan { path } => {
            let scanner = build_scanner(&cli.definitions_dir, &cli.rules_dir)?;
            let (scanned, suspicious, malicious) = scan_path(&scanner, &path)?;
            eprintln!("Scanned: {scanned}; suspicious: {suspicious}; malicious: {malicious}");
        }
        Command::Watch { path } => {
            if !path.is_dir() {
                bail!("watch target must be an existing directory: {}", path.display());
            }
            let scanner = build_scanner(&cli.definitions_dir, &cli.rules_dir)?;
            let mut config = RealtimeConfig::default();
            config.paths = vec![path.clone()];
            config.recursive = true;
            config.extensions.clear();
            config.debounce = Duration::from_millis(500);

            let mut monitor = RealtimeMonitor::new(config, scanner)?;
            monitor.start(|event| {
                if let Some(report) = event.report {
                    if report.verdict.level != ThreatLevel::Clean {
                        eprintln!(
                            "ALERT {:?}: {} ({:?})",
                            report.verdict.level, event.path.display(), report.verdict.detections
                        );
                    }
                }
            })?;
            eprintln!("Monitoring {} (post-write event scanning; not pre-execution blocking). Press Ctrl+C to stop.", path.display());
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_quarantine_store() -> Result<sentinel_quarantine::QuarantineStore> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if unsafe { libc::geteuid() } != 0 {
        bail!("quarantine operations require root privileges; rerun with sudo");
    }
    let root = PathBuf::from("/var/lib/bdfr-sentinel/quarantine");
    std::fs::create_dir_all(&root)?;
    let metadata = std::fs::symlink_metadata(&root)?;
    if !metadata.file_type().is_dir() || metadata.uid() != 0 {
        bail!("quarantine directory must be a real directory owned by root");
    }
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    Ok(sentinel_quarantine::QuarantineStore::open(root)?)
}
