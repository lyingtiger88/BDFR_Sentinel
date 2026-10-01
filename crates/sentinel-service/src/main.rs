#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::{Context, Result};
use sentinel_behavior::{
    process_start_signals, BehaviorEngine, BehaviorSignal, BehaviorSignalKind,
};
use sentinel_core::{EngineRegistry, FileScanner, ScannerConfig, ThreatLevel};
use sentinel_definitions::{ClamHashDatabase, HashDefinitionEngine};
use sentinel_pe::PeAnalyzerEngine;
use sentinel_quarantine::QuarantineStore;
use sentinel_realtime::{RealtimeConfig, RealtimeMonitor};
use sentinel_telemetry::{
    ProcessEventKind, ProcessTelemetry, RegistryEventKind, RegistryTelemetry,
};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
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
        }
    }
}

#[derive(Debug, Serialize)]
struct StatusSnapshot {
    service: &'static str,
    protection: &'static str,
    watch_paths: Vec<PathBuf>,
    auto_quarantine: bool,
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

    let service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    service.set_description(
        "BDFR Sentinel always-on real-time file protection and quarantine service.",
    )?;

    ensure_config_exists()?;
    println!("Installed {SERVICE_DISPLAY_NAME}");
    Ok(())
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

    let mut monitor = RealtimeMonitor::new(realtime_config, scanner)?;
    monitor.start(move |event| {
        if let Some(report) = event.report {
            if report.verdict.level == ThreatLevel::Malicious && auto_quarantine {
                match QuarantineStore::open(&quarantine_dir).and_then(|store| {
                    store.quarantine_file(
                        &event.path,
                        "malware detected by BDFR Sentinel real-time protection",
                    )
                }) {
                    Ok(entry) => {
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

    let process_scanner = Arc::clone(&scanner);
    let behavior = Arc::new(Mutex::new(BehaviorEngine::default()));
    let process_quarantine = config.quarantine_dir.clone();
    let process_auto_quarantine = config.auto_quarantine;
    let process_telemetry = ProcessTelemetry::start(Duration::from_millis(750), move |event| {
        if event.kind != ProcessEventKind::Started {
            return;
        }

        let signals = process_start_signals(
            event.process.pid,
            None,
            &event.process.name,
            event.process.executable.as_deref(),
            &event.process.command_line,
        );

        if let Ok(mut engine) = behavior.lock() {
            for signal in signals {
                let assessment = engine.observe(signal);
                if assessment.level != ThreatLevel::Clean {
                    warn!(
                        pid = assessment.pid,
                        score = assessment.score,
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
                warn!(
                    pid = event.process.pid,
                    path = %executable.display(),
                    "malicious process image detected"
                );

                if process_auto_quarantine {
                    if let Err(err) = QuarantineStore::open(&process_quarantine).and_then(|store| {
                        store.quarantine_file(executable, "malware detected from process telemetry")
                    }) {
                        error!(
                            pid = event.process.pid,
                            path = %executable.display(),
                            error = %err,
                            "failed to quarantine malicious process image"
                        );
                    }
                }
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
    });

    let registry_behavior = Arc::clone(&behavior);
    let registry_telemetry = RegistryTelemetry::start(Duration::from_secs(2), move |event| {
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
    });

    write_status_snapshot(&config, "running");

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
        thread::sleep(Duration::from_millis(250));
    }

    registry_telemetry.stop();
    process_telemetry.stop();
    monitor.stop();
    write_status_snapshot(&config, "stopped");

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

fn write_status_snapshot(config: &ServiceConfig, state: &'static str) {
    let snapshot = StatusSnapshot {
        service: SERVICE_NAME,
        protection: state,
        watch_paths: config.watch_paths.clone(),
        auto_quarantine: config.auto_quarantine,
    };

    if let Ok(bytes) = serde_json::to_vec_pretty(&snapshot) {
        let _ = fs::write(status_path(), bytes);
    }
}
