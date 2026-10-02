use anyhow::{Context, Result};
use sentinel_amsi::{AmsiScanner, AmsiVerdict};
use sentinel_behavior::{
    process_start_signals, BehaviorEngine, BehaviorSignal, BehaviorSignalKind,
};
use sentinel_core::{EngineRegistry, FileScanner, ScannerConfig, ThreatLevel};
use sentinel_definitions::{ClamHashDatabase, HashDefinitionEngine};
use sentinel_etw::EtwProcessTelemetry;
use sentinel_memory::executable_writable_regions;
use sentinel_minifilter_client::{MinifilterBroker, MinifilterDecision};
use sentinel_pe::PeAnalyzerEngine;
use sentinel_quarantine::QuarantineStore;
use sentinel_realtime::{RealtimeConfig, RealtimeMonitor};
use sentinel_telemetry::{
    ProcessEventKind, ProcessTelemetry, RegistryEventKind, RegistryTelemetry,
};
use sentinel_updater::{StagingUpdater, UpdateManifest, UpdateVerifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tracing::{error, info, warn};
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const SERVICE_NAME: &str = "BDFRSentinel";
const SERVICE_DISPLAY_NAME: &str = "BDFR Sentinel Protection Service";

define_windows_service!(ffi_service_main, service_main);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceConfig {
    watch_paths: Vec<PathBuf>,
    recursive: bool,
    auto_quarantine: bool,
    hdb_path: Option<PathBuf>,
    hsb_path: Option<PathBuf>,
    quarantine_dir: PathBuf,
    #[serde(default)]
    definition_update_public_key: Option<PathBuf>,
    #[serde(default = "default_definition_update_interval_minutes")]
    definition_update_interval_minutes: u64,
    #[serde(default = "default_true")]
    enable_realtime_file_monitor: bool,
    #[serde(default = "default_true")]
    enable_process_telemetry: bool,
    #[serde(default = "default_true")]
    enable_registry_telemetry: bool,
    #[serde(default = "default_true")]
    enable_memory_telemetry: bool,
    #[serde(default = "default_true")]
    enable_amsi: bool,
    #[serde(default = "default_true")]
    enable_etw: bool,
    #[serde(default = "default_true")]
    enable_minifilter: bool,
    #[serde(default = "default_true")]
    enable_definition_updates: bool,
}

fn default_definition_update_interval_minutes() -> u64 {
    30
}

fn default_true() -> bool {
    true
}

impl ServiceConfig {
    fn defaults() -> Self {
        let program_data = program_data_dir();
        let users = PathBuf::from(r"C:\Users");
        let watch_paths = if users.exists() {
            vec![users]
        } else {
            vec![std::env::temp_dir()]
        };

        Self {
            watch_paths,
            recursive: true,
            auto_quarantine: true,
            hdb_path: Some(program_data.join("Definitions").join("main.hdb")),
            hsb_path: Some(program_data.join("Definitions").join("main.hsb")),
            quarantine_dir: program_data.join("Quarantine"),
            definition_update_public_key: Some(
                program_data
                    .join("Definitions")
                    .join("update-public-key.bin"),
            ),
            definition_update_interval_minutes: 30,
            enable_realtime_file_monitor: true,
            enable_process_telemetry: true,
            enable_registry_telemetry: true,
            enable_memory_telemetry: true,
            enable_amsi: true,
            enable_etw: true,
            enable_minifilter: true,
            enable_definition_updates: true,
        }
    }
}

#[derive(Debug, Serialize)]
struct ThreatEventRecord {
    unix_time: u64,
    source: &'static str,
    action: &'static str,
    path: String,
    details: String,
}

#[derive(Debug, Serialize)]
struct StatusSnapshot {
    service: &'static str,
    protection: &'static str,
    watch_paths: Vec<PathBuf>,
    auto_quarantine: bool,
    realtime_file_monitor: bool,
    process_telemetry: bool,
    registry_telemetry: bool,
    memory_telemetry: bool,
    amsi_active: bool,
    etw_active: bool,
    minifilter_connected: bool,
    behavior_active: bool,
    definition_updates_active: bool,
}

#[derive(Debug, Serialize)]
struct SelfTestReport {
    hash_detection: bool,
    realtime_detection: bool,
    quarantine_round_trip: bool,
    amsi_available: bool,
    memory_inspection_available: bool,
    behavior_correlation: bool,
    passed: bool,
}

fn main() -> Result<()> {
    init_logging();

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("install") => install_service(),
        Some("uninstall") => uninstall_service(),
        Some("start") => start_service(),
        Some("stop") => stop_service(),
        Some("status") => print_status(),
        Some("diagnostics") => print_diagnostics(),
        Some("self-test") => run_self_test(),
        Some("config") => config_command(args.collect()),
        Some("console") => run_protection_loop(),
        Some(other) => anyhow::bail!("unknown command: {other}"),
        None => service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .context("failed to connect to Windows Service Control Manager"),
    }
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}

fn install_service() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;

    if let Ok(service) = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG,
    ) {
        service.set_description(
            "BDFR Sentinel always-on real-time file protection and quarantine service.",
        )?;
        ensure_config_exists()?;
        configure_service_recovery();
        println!("{SERVICE_DISPLAY_NAME} is already installed");
        return Ok(());
    }

    let executable = std::env::current_exe()?;
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let service = manager.create_service(
        &service_info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_STATUS,
    )?;
    service.set_description(
        "BDFR Sentinel always-on real-time file protection and quarantine service.",
    )?;

    ensure_config_exists()?;
    configure_service_recovery();
    println!("Installed {SERVICE_DISPLAY_NAME}");
    Ok(())
}

fn configure_service_recovery() {
    let failure = Command::new("sc.exe")
        .args([
            "failure",
            SERVICE_NAME,
            "reset=",
            "86400",
            "actions=",
            "restart/5000/restart/15000/restart/60000",
        ])
        .status();

    if let Ok(status) = failure {
        if !status.success() {
            warn!("could not configure Windows service restart actions");
        }
    } else {
        warn!("sc.exe was unavailable while configuring service recovery");
    }

    let failure_flag = Command::new("sc.exe")
        .args(["failureflag", SERVICE_NAME, "1"])
        .status();

    if let Ok(status) = failure_flag {
        if !status.success() {
            warn!("could not enable service failure actions for non-crash exits");
        }
    }
}

fn uninstall_service() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;

    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        for _ in 0..30 {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    service.delete()?;
    println!("Uninstalled {SERVICE_DISPLAY_NAME}");
    Ok(())
}

fn start_service() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::START | ServiceAccess::QUERY_STATUS,
    )?;
    service.start(&[] as &[&str])?;
    println!("Start requested");
    Ok(())
}

fn stop_service() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
    )?;
    service.stop()?;
    println!("Stop requested");
    Ok(())
}

fn print_status() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)?;
    let status = service.query_status()?;
    println!("{:?}", status.current_state);
    Ok(())
}

fn print_diagnostics() -> Result<()> {
    ensure_config_exists()?;
    let config = load_config()?;

    #[derive(Serialize)]
    struct Diagnostics {
        service_installed: bool,
        service_state: String,
        config_path: String,
        status_path: String,
        quarantine_dir: String,
        hdb_exists: bool,
        hsb_exists: bool,
        update_public_key_exists: bool,
        status_snapshot_exists: bool,
    }

    let (service_installed, service_state) =
        match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .and_then(|manager| manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS))
        {
            Ok(service) => match service.query_status() {
                Ok(status) => (true, format!("{:?}", status.current_state)),
                Err(_) => (true, "Unknown".to_string()),
            },
            Err(_) => (false, "NotInstalled".to_string()),
        };

    let diagnostics = Diagnostics {
        service_installed,
        service_state,
        config_path: config_path().display().to_string(),
        status_path: status_path().display().to_string(),
        quarantine_dir: config.quarantine_dir.display().to_string(),
        hdb_exists: config.hdb_path.as_deref().is_some_and(Path::is_file),
        hsb_exists: config.hsb_path.as_deref().is_some_and(Path::is_file),
        update_public_key_exists: config
            .definition_update_public_key
            .as_deref()
            .is_some_and(Path::is_file),
        status_snapshot_exists: status_path().is_file(),
    };

    println!("{}", serde_json::to_string_pretty(&diagnostics)?);
    Ok(())
}

fn run_self_test() -> Result<()> {
    let marker = b"BDFR_SENTINEL_SELF_TEST_MARKER_v1";
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(marker);
        format!("{:x}", hasher.finalize())
    };

    let hsb = format!("{hash}:{}:Trojan.BDFR.SelfTest", marker.len());
    let db = ClamHashDatabase::parse_hsb(&hsb)?;
    let hashes = HashDefinitionEngine::new().with_hsb(db);

    let mut registry = EngineRegistry::new();
    registry.register(PeAnalyzerEngine);
    registry.register(hashes);
    let scanner = Arc::new(FileScanner::new(ScannerConfig::default(), registry));

    let root = std::env::temp_dir().join(format!(
        "bdfr-sentinel-self-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    ));
    let watched = root.join("watched");
    let quarantine_dir = root.join("quarantine");
    fs::create_dir_all(&watched)?;

    let sample = watched.join("self-test.exe");
    fs::write(&sample, marker)?;

    let hash_detection = scanner
        .scan_file(&sample)
        .map(|report| report.verdict.level == ThreatLevel::Malicious)
        .unwrap_or(false);

    let (tx, rx) = std::sync::mpsc::channel();
    let mut realtime = RealtimeMonitor::new(
        RealtimeConfig {
            paths: vec![watched.clone()],
            recursive: true,
            debounce: Duration::from_millis(50),
            ..RealtimeConfig::default()
        },
        Arc::clone(&scanner),
    )?;

    realtime.start(move |event| {
        if let Some(report) = event.report {
            let _ = tx.send(report.verdict.level);
        }
    })?;

    let realtime_sample = watched.join("realtime-self-test.exe");
    fs::write(&realtime_sample, marker)?;

    let realtime_detection = rx
        .recv_timeout(Duration::from_secs(5))
        .map(|level| level == ThreatLevel::Malicious)
        .unwrap_or(false);

    realtime.stop();

    let quarantine_round_trip = (|| -> Result<bool> {
        let store = QuarantineStore::open(&quarantine_dir)?;
        let entry = store.quarantine_file(&sample, "BDFR Sentinel self-test")?;
        if sample.exists() {
            return Ok(false);
        }

        let restored = store.restore(entry.id)?;
        Ok(restored.original_path == sample && fs::read(&sample)? == marker)
    })()
    .unwrap_or(false);

    let amsi_available = AmsiScanner::new().is_ok();
    let memory_inspection_available = executable_writable_regions(std::process::id()).is_ok();

    let behavior_correlation = {
        let mut engine = BehaviorEngine::default();
        let _ = engine.observe(BehaviorSignal {
            pid: 4242,
            kind: BehaviorSignalKind::ScriptInterpreter,
            weight: 45,
            details: "self-test script interpreter".to_string(),
        });
        let _ = engine.observe(BehaviorSignal {
            pid: 4242,
            kind: BehaviorSignalKind::SuspiciousParentChild,
            weight: 45,
            details: "self-test parent-child".to_string(),
        });
        engine
            .observe(BehaviorSignal {
                pid: 4242,
                kind: BehaviorSignalKind::RwxMemory,
                weight: 45,
                details: "self-test rwx memory".to_string(),
            })
            .is_actionable_malicious()
    };

    let passed = hash_detection
        && realtime_detection
        && quarantine_round_trip
        && amsi_available
        && memory_inspection_available
        && behavior_correlation;

    let report = SelfTestReport {
        hash_detection,
        realtime_detection,
        quarantine_round_trip,
        amsi_available,
        memory_inspection_available,
        behavior_correlation,
        passed,
    };

    println!("{}", serde_json::to_string_pretty(&report)?);
    let _ = fs::remove_dir_all(&root);

    if !passed {
        anyhow::bail!("BDFR Sentinel protection self-test failed");
    }

    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(err) = run_service() {
        error!(error = %err, "service terminated with error");
    }
}

fn run_service() -> Result<()> {
    let stopped = Arc::new(AtomicBool::new(false));
    let stopped_for_handler = Arc::clone(&stopped);

    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stopped_for_handler.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    })?;

    ensure_config_exists()?;
    let config = load_config()?;
    let scanner = Arc::new(build_scanner(
        config.hdb_path.as_deref(),
        config.hsb_path.as_deref(),
    )?);

    let realtime_config = RealtimeConfig {
        paths: config.watch_paths.clone(),
        recursive: config.recursive,
        ..RealtimeConfig::default()
    };

    let quarantine_dir = config.quarantine_dir.clone();
    let auto_quarantine = config.auto_quarantine;
    let amsi = Arc::new(Mutex::new(if config.enable_amsi {
        AmsiScanner::new().ok()
    } else {
        None
    }));
    let amsi_for_files = Arc::clone(&amsi);

    let mut monitor = if config.enable_realtime_file_monitor {
        let mut monitor = RealtimeMonitor::new(realtime_config, Arc::clone(&scanner))?;
        monitor.start(move |event| {
            let mut quarantined_by_amsi = false;

            if is_script_path(&event.path) {
                if let Ok(guard) = amsi_for_files.lock() {
                    if let Some(scanner) = guard.as_ref() {
                        match scanner.scan_file(&event.path) {
                            Ok(AmsiVerdict::Malicious) => {
                                warn!(
                                    path = %event.path.display(),
                                    "AMSI reported malicious script content"
                                );

                                if auto_quarantine {
                                    match QuarantineStore::open(&quarantine_dir).and_then(|store| {
                                        store.quarantine_file(
                                            &event.path,
                                            "malicious script detected by Windows AMSI",
                                        )
                                    }) {
                                        Ok(entry) => {
                                            quarantined_by_amsi = true;
                                            record_threat_event(
                                                "amsi",
                                                "quarantine",
                                                &event.path,
                                                format!("quarantine_id={}", entry.id.0),
                                            );
                                            warn!(
                                                path = %event.path.display(),
                                                quarantine_id = %entry.id.0,
                                                "AMSI detection quarantined"
                                            );
                                        }
                                        Err(err) => {
                                            error!(
                                                path = %event.path.display(),
                                                error = %err,
                                                "failed to quarantine AMSI detection"
                                            );
                                        }
                                    }
                                }
                            }
                            Ok(AmsiVerdict::Suspicious) => {
                                warn!(
                                    path = %event.path.display(),
                                    "AMSI returned a suspicious or policy-blocked result"
                                );
                            }
                            Ok(AmsiVerdict::Clean) => {}
                            Err(err) => {
                                warn!(
                                    path = %event.path.display(),
                                    error = %err,
                                    "AMSI scan failed; continuing with Sentinel engines"
                                );
                            }
                        }
                    }
                }
            }

            if let Some(report) = event.report {
                if report.verdict.level == ThreatLevel::Malicious
                    && auto_quarantine
                    && !quarantined_by_amsi
                {
                    match QuarantineStore::open(&quarantine_dir).and_then(|store| {
                        store.quarantine_file(
                            &event.path,
                            "malware detected by BDFR Sentinel real-time protection",
                        )
                    }) {
                        Ok(entry) => {
                            record_threat_event(
                                "realtime-file",
                                "quarantine",
                                &event.path,
                                format!("quarantine_id={}", entry.id.0),
                            );
                            warn!(
                                path = %event.path.display(),
                                quarantine_id = %entry.id.0,
                                "malware quarantined by real-time protection"
                            );
                        }
                        Err(err) => {
                            error!(
                                path = %event.path.display(),
                                error = %err,
                                "failed to quarantine real-time detection"
                            );
                        }
                    }
                }
            }
        })?;
        Some(monitor)
    } else {
        None
    };

    let policy_scanner = Arc::clone(&scanner);
    let policy_quarantine = config.quarantine_dir.clone();
    let policy_auto_quarantine = config.auto_quarantine;

    let mut minifilter_broker = if config.enable_minifilter {
        match MinifilterBroker::start(move |request| {
            match policy_scanner.scan_file(&request.path) {
                Ok(report) if report.verdict.level == ThreatLevel::Malicious => {
                    record_threat_event(
                        "minifilter",
                        "block",
                        &request.path,
                        format!("pid={}", request.process_id),
                    );
                    warn!(
                        pid = request.process_id,
                        path = %request.path.display(),
                        "pre-execution policy blocked malicious image"
                    );

                    if policy_auto_quarantine {
                        let path = request.path.clone();
                        let quarantine_dir = policy_quarantine.clone();
                        let _ = thread::Builder::new()
                            .name("bdfr-sentinel-preexec-quarantine".to_string())
                            .spawn(move || {
                                let _ = QuarantineStore::open(&quarantine_dir).and_then(|store| {
                                    store.quarantine_file(
                                        &path,
                                        "malware blocked by BDFR Sentinel pre-execution policy",
                                    )
                                });
                            });
                    }

                    MinifilterDecision::Block
                }
                Ok(_) => MinifilterDecision::Allow,
                Err(err) => {
                    warn!(
                        pid = request.process_id,
                        path = %request.path.display(),
                        error = %err,
                        "pre-execution scan failed; allowing by fail-open policy"
                    );
                    MinifilterDecision::Allow
                }
            }
        }) {
            Ok(broker) => {
                info!("connected to BDFR Sentinel minifilter policy port");
                Some(broker)
            }
            Err(err) => {
                info!(error = %err, "minifilter unavailable; continuing with user-mode protection");
                None
            }
        }
    } else {
        None
    };

    let process_scanner = Arc::clone(&scanner);
    let behavior = Arc::new(Mutex::new(BehaviorEngine::default()));

    let etw_behavior = Arc::clone(&behavior);
    let etw_process_names = Arc::new(Mutex::new(HashMap::<u32, String>::new()));
    let etw_names_for_callback = Arc::clone(&etw_process_names);
    let etw_scanner = Arc::clone(&scanner);
    let etw_quarantine = config.quarantine_dir.clone();
    let etw_auto_quarantine = config.auto_quarantine;
    let etw_memory_enabled = config.enable_memory_telemetry;

    let mut etw_process = if config.enable_etw {
        match EtwProcessTelemetry::start(move |event| {
            let parent_name = etw_names_for_callback
                .lock()
                .ok()
                .and_then(|names| names.get(&event.parent_process_id).cloned());

            if let Ok(mut names) = etw_names_for_callback.lock() {
                if names.len() >= 8192 {
                    names.clear();
                }
                names.insert(event.process_id, event.image_name.clone());
            }

            let executable = process_image_path(event.process_id);
            let mut signals = process_start_signals(
                event.process_id,
                parent_name.as_deref(),
                &event.image_name,
                executable.as_deref(),
                &[],
            );

            if etw_memory_enabled {
                if let Ok(regions) = executable_writable_regions(event.process_id) {
                    for region in regions.into_iter().take(4) {
                        signals.push(BehaviorSignal {
                            pid: event.process_id,
                            kind: BehaviorSignalKind::RwxMemory,
                            weight: 45,
                            details: format!(
                                "executable+writable memory region at 0x{:x}, {} bytes",
                                region.base_address, region.region_size
                            ),
                        });
                    }
                }
            }

            let mut behavior_actionable = false;
            if let Ok(mut engine) = etw_behavior.lock() {
                for signal in signals {
                    let assessment = engine.observe(signal);
                    behavior_actionable |= assessment.is_actionable_malicious();
                    if assessment.level != ThreatLevel::Clean {
                        warn!(
                            pid = assessment.pid,
                            score = assessment.score,
                            distinct_signals = assessment.distinct_signal_kinds,
                            level = ?assessment.level,
                            "ETW process behavior raised risk"
                        );
                    }
                }
            }

            let Some(executable) = executable else {
                return;
            };

            match etw_scanner.scan_file(&executable) {
                Ok(report) if report.verdict.level == ThreatLevel::Malicious => {
                    remediate_malicious_process(
                        "etw-process",
                        event.process_id,
                        &executable,
                        &etw_quarantine,
                        etw_auto_quarantine,
                        "malware detected from ETW process telemetry",
                    );
                }
                Ok(_) if behavior_actionable => {
                    remediate_malicious_process(
                        "behavior",
                        event.process_id,
                        &executable,
                        &etw_quarantine,
                        etw_auto_quarantine,
                        "malicious behavior correlation detected from ETW telemetry",
                    );
                }
                Ok(_) => {}
                Err(err) => {
                    warn!(
                        pid = event.process_id,
                        path = %executable.display(),
                        error = %err,
                        "ETW process image scan failed"
                    );
                }
            }
        }) {
            Ok(trace) => {
                info!("ETW process telemetry active");
                Some(trace)
            }
            Err(err) => {
                warn!(error = %err, "ETW unavailable; polling process telemetry remains active");
                None
            }
        }
    } else {
        None
    };

    let process_quarantine = config.quarantine_dir.clone();
    let process_auto_quarantine = config.auto_quarantine;
    let memory_telemetry_enabled = config.enable_memory_telemetry;
    let process_behavior = Arc::clone(&behavior);
    let process_telemetry = if config.enable_process_telemetry && etw_process.is_none() {
        info!("ETW unavailable or disabled; enabling low-frequency process polling fallback");
        Some(ProcessTelemetry::start(
            Duration::from_secs(2),
            move |event| {
                if event.kind != ProcessEventKind::Started {
                    return;
                }

                let mut signals = process_start_signals(
                    event.process.pid,
                    None,
                    &event.process.name,
                    event.process.executable.as_deref(),
                    &event.process.command_line,
                );

                if memory_telemetry_enabled {
                    if let Ok(regions) = executable_writable_regions(event.process.pid) {
                        for region in regions.into_iter().take(4) {
                            signals.push(BehaviorSignal {
                                pid: event.process.pid,
                                kind: BehaviorSignalKind::RwxMemory,
                                weight: 45,
                                details: format!(
                                    "executable+writable memory region at 0x{:x}, {} bytes",
                                    region.base_address, region.region_size
                                ),
                            });
                        }
                    }
                }

                let mut behavior_actionable = false;
                if let Ok(mut engine) = process_behavior.lock() {
                    for signal in signals {
                        let assessment = engine.observe(signal);
                        behavior_actionable |= assessment.is_actionable_malicious();
                        if assessment.level != ThreatLevel::Clean {
                            warn!(
                                pid = assessment.pid,
                                score = assessment.score,
                                distinct_signals = assessment.distinct_signal_kinds,
                                level = ?assessment.level,
                                "behavior correlation raised process risk"
                            );
                        }
                    }
                }

                let Some(executable) = event.process.executable.as_deref() else {
                    return;
                };

                match process_scanner.scan_file(executable) {
                    Ok(report) if report.verdict.level == ThreatLevel::Malicious => {
                        remediate_malicious_process(
                            "process",
                            event.process.pid,
                            executable,
                            &process_quarantine,
                            process_auto_quarantine,
                            "malware detected from process telemetry",
                        );
                    }
                    Ok(_) if behavior_actionable => {
                        remediate_malicious_process(
                            "behavior",
                            event.process.pid,
                            executable,
                            &process_quarantine,
                            process_auto_quarantine,
                            "malicious behavior correlation detected from process telemetry",
                        );
                    }
                    Ok(_) => {}
                    Err(err) => {
                        warn!(
                            pid = event.process.pid,
                            path = %executable.display(),
                            error = %err,
                            "process image scan failed"
                        );
                    }
                }
            },
        ))
    } else {
        None
    };

    let registry_behavior = Arc::clone(&behavior);
    let registry_telemetry = if config.enable_registry_telemetry {
        Some(RegistryTelemetry::start(
            Duration::from_secs(10),
            move |event| {
                if matches!(
                    event.kind,
                    RegistryEventKind::Added | RegistryEventKind::Modified
                ) {
                    warn!(
                        key = %event.key,
                        name = %event.name,
                        value = ?event.value,
                        "persistence registry value changed"
                    );

                    if let Ok(mut engine) = registry_behavior.lock() {
                        let assessment = engine.observe(BehaviorSignal {
                            pid: 0,
                            kind: BehaviorSignalKind::PersistenceChange,
                            weight: 45,
                            details: format!(
                                "{}\\{} = {}",
                                event.key,
                                event.name,
                                event.value.as_deref().unwrap_or_default()
                            ),
                        });

                        if assessment.level != ThreatLevel::Clean {
                            warn!(
                                score = assessment.score,
                                level = ?assessment.level,
                                "registry persistence behavior raised system risk"
                            );
                        }
                    }
                }
            },
        ))
    } else {
        None
    };

    let update_stop = Arc::new(AtomicBool::new(false));
    let update_stop_worker = Arc::clone(&update_stop);
    let update_config = config.clone();
    let update_thread = if config.enable_definition_updates {
        thread::Builder::new()
            .name("bdfr-sentinel-definition-updater".to_string())
            .spawn(move || {
                let interval = Duration::from_secs(
                    update_config
                        .definition_update_interval_minutes
                        .max(1)
                        .saturating_mul(60),
                );

                while !update_stop_worker.load(Ordering::Relaxed) {
                    if let Err(err) = try_activate_definition_update(&update_config) {
                        warn!(error = %err, "definition update check failed");
                    }

                    let mut slept = Duration::ZERO;
                    while slept < interval && !update_stop_worker.load(Ordering::Relaxed) {
                        let slice = Duration::from_secs(1).min(interval - slept);
                        thread::sleep(slice);
                        slept += slice;
                    }
                }
            })
            .ok()
    } else {
        None
    };

    let amsi_active = amsi
        .lock()
        .map(|scanner| scanner.is_some())
        .unwrap_or(false);
    write_status_snapshot(
        &config,
        "running",
        monitor.is_some(),
        process_telemetry.is_some(),
        registry_telemetry.is_some(),
        config.enable_memory_telemetry && process_telemetry.is_some(),
        amsi_active,
        etw_process.is_some(),
        minifilter_broker.is_some(),
        process_telemetry.is_some() || registry_telemetry.is_some() || etw_process.is_some(),
        update_thread.is_some(),
    );

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    info!("BDFR Sentinel real-time protection service started");

    while !stopped.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(1));
    }

    update_stop.store(true, Ordering::Relaxed);
    if let Some(handle) = update_thread {
        let _ = handle.join();
    }

    if let Some(broker) = minifilter_broker.as_mut() {
        broker.stop();
    }
    if let Some(etw) = etw_process.as_mut() {
        etw.stop();
    }
    if let Some(registry) = registry_telemetry.as_ref() {
        registry.stop();
    }
    if let Some(process) = process_telemetry.as_ref() {
        process.stop();
    }
    if let Some(monitor) = monitor.as_mut() {
        monitor.stop();
    }
    write_status_snapshot(
        &config, "stopped", false, false, false, false, false, false, false, false, false,
    );

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

fn run_protection_loop() -> Result<()> {
    ensure_config_exists()?;
    let config = load_config()?;
    let scanner = Arc::new(build_scanner(
        config.hdb_path.as_deref(),
        config.hsb_path.as_deref(),
    )?);
    let quarantine_dir = config.quarantine_dir.clone();
    let auto_quarantine = config.auto_quarantine;

    let realtime_config = RealtimeConfig {
        paths: config.watch_paths.clone(),
        recursive: config.recursive,
        ..RealtimeConfig::default()
    };

    let mut monitor = RealtimeMonitor::new(realtime_config, scanner)?;
    monitor.start(move |event| {
        if let Some(report) = event.report {
            println!("[{:?}] {}", report.verdict.level, event.path.display());

            if report.verdict.level == ThreatLevel::Malicious && auto_quarantine {
                let _ = QuarantineStore::open(&quarantine_dir).and_then(|store| {
                    store.quarantine_file(
                        &event.path,
                        "malware detected by BDFR Sentinel real-time protection",
                    )
                });
            }
        }
    })?;

    println!("Real-time protection running. Press Ctrl+C to terminate.");
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn try_activate_definition_update(config: &ServiceConfig) -> Result<()> {
    let definitions_dir = program_data_dir().join("Definitions");
    let staging_dir = definitions_dir.join("staging");
    let manifest_path = staging_dir.join("manifest.json");

    if !manifest_path.is_file() {
        return Ok(());
    }

    let Some(public_key_path) = config.definition_update_public_key.as_deref() else {
        return Ok(());
    };

    if !public_key_path.is_file() {
        anyhow::bail!(
            "definition update public key not found: {}",
            public_key_path.display()
        );
    }

    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest: UpdateManifest = serde_json::from_slice(&manifest_bytes)?;
    let public_key = fs::read(public_key_path)?;
    let verifier = UpdateVerifier::from_public_key_bytes(&public_key)
        .context("invalid definition update public key")?;
    verifier
        .verify_manifest(&manifest)
        .context("definition manifest signature verification failed")?;

    let live_dir = definitions_dir.join("active");
    let backup_dir = definitions_dir.join("backup");
    let updater = StagingUpdater {
        staging_dir: staging_dir.clone(),
        live_dir,
        backup_dir,
    };

    updater
        .activate_verified(&manifest)
        .context("failed to activate verified definition update")?;

    info!(version = %manifest.version, "activated signed definition update");
    Ok(())
}

fn is_script_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "ps1" | "psm1" | "psd1" | "js" | "jse" | "vbs" | "vbe" | "bat" | "cmd" | "hta"
            )
        })
        .unwrap_or(false)
}

fn build_scanner(hdb_path: Option<&Path>, hsb_path: Option<&Path>) -> Result<FileScanner> {
    let mut registry = EngineRegistry::new();
    registry.register(PeAnalyzerEngine);

    let mut hashes = HashDefinitionEngine::new();

    if let Some(path) = hdb_path {
        if path.is_file() {
            let text = fs::read_to_string(path)?;
            hashes = hashes.with_hdb(ClamHashDatabase::parse_hdb(&text)?);
        }
    }

    if let Some(path) = hsb_path {
        if path.is_file() {
            let text = fs::read_to_string(path)?;
            hashes = hashes.with_hsb(ClamHashDatabase::parse_hsb(&text)?);
        }
    }

    if hashes.has_definitions() {
        registry.register(hashes);
    }

    Ok(FileScanner::new(ScannerConfig::default(), registry))
}

#[cfg(windows)]
fn process_image_path(pid: u32) -> Option<PathBuf> {
    use std::ffi::c_void;

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> *mut c_void;
        fn QueryFullProcessImageNameW(
            process: *mut c_void,
            flags: u32,
            exe_name: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }

    let mut buffer = vec![0u16; 32768];
    let mut len = buffer.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut len) };
    unsafe {
        CloseHandle(handle);
    }

    if ok == 0 || len == 0 {
        return None;
    }

    Some(PathBuf::from(String::from_utf16_lossy(
        &buffer[..len as usize],
    )))
}

#[cfg(not(windows))]
fn process_image_path(_pid: u32) -> Option<PathBuf> {
    None
}

fn remediate_malicious_process(
    source: &'static str,
    pid: u32,
    executable: &Path,
    quarantine_dir: &Path,
    auto_quarantine: bool,
    reason: &str,
) {
    record_threat_event(source, "detect", executable, format!("pid={pid}"));
    warn!(
        pid,
        path = %executable.display(),
        source,
        "confirmed malicious process"
    );

    match terminate_process_for_malware(pid) {
        Ok(()) => {
            record_threat_event(source, "terminate", executable, format!("pid={pid}"));
            warn!(pid, path = %executable.display(), "terminated malicious process");
            thread::sleep(Duration::from_millis(150));
        }
        Err(err) => {
            warn!(
                pid,
                path = %executable.display(),
                error = %err,
                "could not terminate malicious process"
            );
        }
    }

    if auto_quarantine {
        match QuarantineStore::open(quarantine_dir)
            .and_then(|store| store.quarantine_file(executable, reason))
        {
            Ok(entry) => {
                record_threat_event(
                    source,
                    "quarantine",
                    executable,
                    format!("pid={pid}; quarantine_id={}", entry.id.0),
                );
            }
            Err(err) => {
                error!(
                    pid,
                    path = %executable.display(),
                    error = %err,
                    "failed to quarantine malicious process image"
                );
            }
        }
    }
}

#[cfg(windows)]
fn terminate_process_for_malware(pid: u32) -> Result<()> {
    use std::ffi::c_void;

    const PROCESS_TERMINATE: u32 = 0x0001;

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> *mut c_void;
        fn TerminateProcess(process: *mut c_void, exit_code: u32) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if handle.is_null() {
        anyhow::bail!("failed to open process {pid} for termination");
    }

    let terminated = unsafe { TerminateProcess(handle, 0xDEAD) };
    unsafe {
        CloseHandle(handle);
    }

    if terminated == 0 {
        anyhow::bail!("TerminateProcess failed for pid {pid}");
    }

    Ok(())
}

#[cfg(not(windows))]
fn terminate_process_for_malware(_pid: u32) -> Result<()> {
    anyhow::bail!("process termination is only available on Windows")
}

fn threat_events_path() -> PathBuf {
    sentinel_dir().join("events.jsonl")
}

fn record_threat_event(
    source: &'static str,
    action: &'static str,
    path: &Path,
    details: impl Into<String>,
) {
    use std::io::Write as _;

    let unix_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();

    let record = ThreatEventRecord {
        unix_time,
        source,
        action,
        path: path.display().to_string(),
        details: details.into(),
    };

    let Ok(line) = serde_json::to_string(&record) else {
        return;
    };

    let path = threat_events_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line}");
    }
}

fn sentinel_dir() -> PathBuf {
    program_data_dir()
}

fn program_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("BDFR")
        .join("Sentinel")
}

fn config_path() -> PathBuf {
    sentinel_dir().join("service.json")
}

fn status_path() -> PathBuf {
    sentinel_dir().join("status.json")
}

fn ensure_config_exists() -> Result<()> {
    let path = config_path();
    if path.exists() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let defaults = ServiceConfig::defaults();
    fs::write(&path, serde_json::to_vec_pretty(&defaults)?)?;
    Ok(())
}

fn load_config() -> Result<ServiceConfig> {
    let path = config_path();
    let bytes = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn save_config(config: &ServiceConfig) -> Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, serde_json::to_vec_pretty(config)?)?;
    Ok(())
}

fn parse_config_bool(value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" | "enable" | "enabled" => Ok(true),
        "0" | "false" | "off" | "no" | "disable" | "disabled" => Ok(false),
        _ => anyhow::bail!("invalid boolean value: {value}"),
    }
}

fn apply_config_setting(config: &mut ServiceConfig, key: &str, enabled: bool) -> Result<()> {
    match key {
        "realtime_file_monitor" => config.enable_realtime_file_monitor = enabled,
        "process_telemetry" => config.enable_process_telemetry = enabled,
        "registry_telemetry" => config.enable_registry_telemetry = enabled,
        "memory_telemetry" => config.enable_memory_telemetry = enabled,
        "amsi" => config.enable_amsi = enabled,
        "etw" => config.enable_etw = enabled,
        "minifilter" => config.enable_minifilter = enabled,
        "definition_updates" => config.enable_definition_updates = enabled,
        "auto_quarantine" => config.auto_quarantine = enabled,
        _ => anyhow::bail!("unknown protection setting: {key}"),
    }
    Ok(())
}

fn config_command(args: Vec<String>) -> Result<()> {
    ensure_config_exists()?;

    match args.as_slice() {
        [command] if command == "show" => {
            let config = load_config()?;
            println!("{}", serde_json::to_string_pretty(&config)?);
            Ok(())
        }
        [command] if command == "reset" => {
            let config = ServiceConfig::defaults();
            save_config(&config)?;
            println!("Protection configuration reset to defaults");
            Ok(())
        }
        [command, key, value] if command == "set" => {
            let enabled = parse_config_bool(value)?;
            let mut config = load_config()?;
            apply_config_setting(&mut config, key, enabled)?;
            save_config(&config)?;
            println!("Updated {key}={enabled}. Restart the protection service to apply.");
            Ok(())
        }
        [command, settings @ ..] if command == "apply" && !settings.is_empty() => {
            let mut config = load_config()?;

            for item in settings {
                let Some((key, value)) = item.split_once('=') else {
                    anyhow::bail!("invalid setting assignment: {item}");
                };
                let enabled = parse_config_bool(value)?;
                apply_config_setting(&mut config, key, enabled)?;
            }

            save_config(&config)?;
            println!("Protection configuration updated. Restart the service to apply.");
            Ok(())
        }
        [command, settings @ ..] if command == "apply-restart" && !settings.is_empty() => {
            let mut config = load_config()?;

            for item in settings {
                let Some((key, value)) = item.split_once('=') else {
                    anyhow::bail!("invalid setting assignment: {item}");
                };
                let enabled = parse_config_bool(value)?;
                apply_config_setting(&mut config, key, enabled)?;
            }

            save_config(&config)?;

            let manager =
                ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
            let service = manager.open_service(
                SERVICE_NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::START,
            );

            if let Ok(service) = service {
                let was_running = service.query_status()?.current_state != ServiceState::Stopped;

                if was_running {
                    let _ = service.stop();
                    for _ in 0..40 {
                        if service.query_status()?.current_state == ServiceState::Stopped {
                            break;
                        }
                        thread::sleep(Duration::from_millis(250));
                    }

                    service.start(&[] as &[&str])?;
                }
            }

            println!("Protection configuration updated and service restart requested.");
            Ok(())
        }
        _ => anyhow::bail!(
            "usage: bdfr-sentinel-service config show | reset | set <setting> <true|false> | apply <setting=true>... | apply-restart <setting=true>..."
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn write_status_snapshot(
    config: &ServiceConfig,
    state: &'static str,
    realtime_file_monitor: bool,
    process_telemetry: bool,
    registry_telemetry: bool,
    memory_telemetry: bool,
    amsi_active: bool,
    etw_active: bool,
    minifilter_connected: bool,
    behavior_active: bool,
    definition_updates_active: bool,
) {
    let snapshot = StatusSnapshot {
        service: SERVICE_NAME,
        protection: state,
        watch_paths: config.watch_paths.clone(),
        auto_quarantine: config.auto_quarantine,
        realtime_file_monitor,
        process_telemetry,
        registry_telemetry,
        memory_telemetry,
        amsi_active,
        etw_active,
        minifilter_connected,
        behavior_active,
        definition_updates_active,
    };

    if let Ok(bytes) = serde_json::to_vec_pretty(&snapshot) {
        let _ = fs::write(status_path(), bytes);
    }
}
