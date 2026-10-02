use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sentinel_core::{EngineRegistry, FileScanner, ScannerConfig, ThreatLevel};
use sentinel_definitions::{ClamHashDatabase, HashDefinitionEngine};
use sentinel_pe::PeAnalyzerEngine;
use sentinel_quarantine::{QuarantineId, QuarantineStore};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use walkdir::WalkDir;

#[derive(Debug, Parser)]
#[command(name = "bdfr-sentinel", version, about = "BDFR Sentinel antivirus MVP")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Scan {
        path: PathBuf,
        #[arg(long)]
        hdb: Option<PathBuf>,
        #[arg(long)]
        hsb: Option<PathBuf>,
        #[arg(long)]
        quarantine_dir: Option<PathBuf>,
        #[arg(long)]
        quarantine_malware: bool,
        #[arg(long)]
        json: bool,
    },
    Status,
    PerfSmoke {
        #[arg(long, default_value_t = 16)]
        size_mb: usize,
        #[arg(long, default_value_t = 3)]
        iterations: usize,
    },
    Quarantine {
        path: PathBuf,
        #[arg(long)]
        store: PathBuf,
        #[arg(long, default_value = "manual quarantine")]
        reason: String,
    },
    Restore {
        id: String,
        #[arg(long)]
        store: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            path,
            hdb,
            hsb,
            quarantine_dir,
            quarantine_malware,
            json,
        } => scan_command(
            &path,
            hdb.as_deref(),
            hsb.as_deref(),
            quarantine_dir.as_deref(),
            quarantine_malware,
            json,
        ),
        Command::Status => {
            println!("BDFR Sentinel {}", env!("CARGO_PKG_VERSION"));
            println!("Core scanner: ready");
            println!("PE analyzer: ready");
            println!("Hash definitions: HDB/HSB supported");
            println!("Quarantine: AES-256-GCM + Windows DPAPI");
            println!("Policy: crack/license-bypass are non-actionable by default");
            Ok(())
        }
        Command::PerfSmoke {
            size_mb,
            iterations,
        } => perf_smoke(size_mb, iterations),
        Command::Quarantine {
            path,
            store,
            reason,
        } => {
            let quarantine = QuarantineStore::open(&store)?;
            let entry = quarantine.quarantine_file(&path, reason)?;
            println!("Quarantined: {}", entry.id.0);
            println!("Original: {}", entry.original_path.display());
            Ok(())
        }
        Command::Restore { id, store } => {
            let uuid = Uuid::parse_str(&id).context("invalid quarantine UUID")?;
            let quarantine = QuarantineStore::open(&store)?;
            let entry = quarantine.restore(QuarantineId(uuid))?;
            println!("Restored: {}", entry.original_path.display());
            Ok(())
        }
    }
}

fn perf_smoke(size_mb: usize, iterations: usize) -> Result<()> {
    use std::time::Instant;

    let size_mb = size_mb.clamp(1, 256);
    let iterations = iterations.clamp(1, 20);
    let bytes = size_mb * 1024 * 1024;
    let path = std::env::temp_dir().join(format!(
        "bdfr-sentinel-perf-{}-{}mb.bin",
        std::process::id(),
        size_mb
    ));

    let mut data = vec![0u8; bytes];
    for (index, byte) in data.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(31).wrapping_add(17);
    }
    fs::write(&path, &data)?;
    drop(data);

    let mut registry = EngineRegistry::new();
    registry.register(PeAnalyzerEngine);

    let cold_config = ScannerConfig {
        cache_capacity: 0,
        ..ScannerConfig::default()
    };
    let cold_scanner = FileScanner::new(cold_config, registry);

    let cold_start = Instant::now();
    for _ in 0..iterations {
        cold_scanner.scan_file(&path)?;
    }
    let cold_elapsed = cold_start.elapsed();
    let total_mb = (size_mb * iterations) as f64;
    let cold_mbps = total_mb / cold_elapsed.as_secs_f64().max(0.000_001);

    let mut cached_registry = EngineRegistry::new();
    cached_registry.register(PeAnalyzerEngine);
    let cached_scanner = FileScanner::new(ScannerConfig::default(), cached_registry);
    cached_scanner.scan_file(&path)?;

    let cached_start = Instant::now();
    for _ in 0..iterations {
        cached_scanner.scan_file(&path)?;
    }
    let cached_elapsed = cached_start.elapsed();
    let cached_avg_us = cached_elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64;

    let _ = fs::remove_file(&path);

    println!("BDFR Sentinel performance smoke test");
    println!("file_size_mb={size_mb}");
    println!("iterations={iterations}");
    println!("cold_scan_throughput_mb_s={cold_mbps:.2}");
    println!("cached_scan_average_us={cached_avg_us:.2}");
    Ok(())
}

fn scan_command(
    target: &Path,
    hdb_path: Option<&Path>,
    hsb_path: Option<&Path>,
    quarantine_dir: Option<&Path>,
    quarantine_malware: bool,
    json: bool,
) -> Result<()> {
    let mut registry = EngineRegistry::new();
    registry.register(PeAnalyzerEngine);

    let mut hash_engine = HashDefinitionEngine::new();

    if let Some(path) = hdb_path {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read HDB {}", path.display()))?;
        hash_engine = hash_engine.with_hdb(ClamHashDatabase::parse_hdb(&text)?);
    }

    if let Some(path) = hsb_path {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read HSB {}", path.display()))?;
        hash_engine = hash_engine.with_hsb(ClamHashDatabase::parse_hsb(&text)?);
    }

    if hash_engine.has_definitions() {
        registry.register(hash_engine);
    }

    let scanner = FileScanner::new(ScannerConfig::default(), registry);
    let quarantine = quarantine_dir.map(QuarantineStore::open).transpose()?;

    if target.is_file() {
        scan_one(
            &scanner,
            target,
            quarantine.as_ref(),
            quarantine_malware,
            json,
        )?;
        return Ok(());
    }

    if target.is_dir() {
        for entry in WalkDir::new(target).follow_links(false) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    eprintln!("walk error: {err}");
                    continue;
                }
            };

            if entry.file_type().is_file() {
                if let Err(err) = scan_one(
                    &scanner,
                    entry.path(),
                    quarantine.as_ref(),
                    quarantine_malware,
                    json,
                ) {
                    eprintln!("scan error {}: {err}", entry.path().display());
                }
            }
        }
        return Ok(());
    }

    anyhow::bail!("target does not exist: {}", target.display())
}

fn scan_one(
    scanner: &FileScanner,
    path: &Path,
    quarantine: Option<&QuarantineStore>,
    quarantine_malware: bool,
    json: bool,
) -> Result<()> {
    let report = scanner.scan_file(path)?;

    if json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!(
            "[{:?}] {}  sha256={}",
            report.verdict.level, report.path, report.metadata.sha256
        );

        for detection in &report.verdict.detections {
            println!(
                "  - {:?}/{:?}: {}",
                detection.category, detection.level, detection.title
            );
        }
    }

    if quarantine_malware && report.verdict.level == ThreatLevel::Malicious {
        if let Some(store) = quarantine {
            let entry = store.quarantine_file(path, "malware detected by BDFR Sentinel")?;
            println!("  quarantined as {}", entry.id.0);
        }
    }

    Ok(())
}
