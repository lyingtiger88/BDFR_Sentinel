#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::{Context, Result};
use eframe::egui;
use sentinel_core::{EngineRegistry, FileScanner, ScanReport, ScannerConfig, ThreatLevel};
use sentinel_definitions::{ClamHashDatabase, HashDefinitionEngine};
use sentinel_pe::PeAnalyzerEngine;
use sentinel_quarantine::{QuarantineEntry, QuarantineStore};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::System;
use walkdir::WalkDir;

const GOOD: egui::Color32 = egui::Color32::from_rgb(60, 170, 75);
const WARN: egui::Color32 = egui::Color32::from_rgb(230, 145, 0);
const BAD: egui::Color32 = egui::Color32::from_rgb(210, 55, 45);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThemeMode {
    System,
    Dark,
    Light,
}

impl ThemeMode {
    fn label(self) -> &'static str {
        match self {
            Self::System => "System default",
            Self::Dark => "Dark",
            Self::Light => "Light",
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("BDFR Sentinel")
            .with_inner_size([1240.0, 800.0])
            .with_min_inner_size([980.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        "BDFR Sentinel",
        options,
        Box::new(|cc| Ok(Box::new(SentinelApp::new(&cc.egui_ctx)))),
    )
}

fn resolved_theme(ctx: &egui::Context, mode: ThemeMode) -> egui::Theme {
    match mode {
        ThemeMode::Dark => egui::Theme::Dark,
        ThemeMode::Light => egui::Theme::Light,
        ThemeMode::System => ctx.system_theme().unwrap_or(egui::Theme::Dark),
    }
}

fn configure_style(ctx: &egui::Context, mode: ThemeMode) {
    let theme = resolved_theme(ctx, mode);
    ctx.set_theme(theme);

    let dark = theme == egui::Theme::Dark;
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(16.0, 10.0);
    style.spacing.indent = 18.0;
    style.visuals = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };

    let panel = if dark {
        egui::Color32::from_rgb(38, 38, 38)
    } else {
        egui::Color32::from_rgb(250, 250, 250)
    };
    let panel_hover = if dark {
        egui::Color32::from_rgb(50, 50, 50)
    } else {
        egui::Color32::from_rgb(238, 238, 238)
    };
    let background = if dark {
        egui::Color32::from_rgb(31, 31, 31)
    } else {
        egui::Color32::from_rgb(243, 243, 243)
    };
    let sidebar = if dark {
        egui::Color32::from_rgb(27, 27, 27)
    } else {
        egui::Color32::from_rgb(248, 248, 248)
    };
    let text = if dark {
        egui::Color32::from_rgb(245, 245, 245)
    } else {
        egui::Color32::from_rgb(28, 28, 28)
    };
    let accent = if dark {
        egui::Color32::from_rgb(96, 205, 255)
    } else {
        egui::Color32::from_rgb(0, 95, 184)
    };

    style.visuals.panel_fill = background;
    style.visuals.window_fill = panel;
    style.visuals.extreme_bg_color = sidebar;
    style.visuals.faint_bg_color = panel;
    style.visuals.override_text_color = Some(text);
    style.visuals.widgets.noninteractive.bg_fill = panel;
    style.visuals.widgets.noninteractive.fg_stroke.color = text;
    style.visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::same(8);
    style.visuals.widgets.inactive.bg_fill = panel;
    style.visuals.widgets.inactive.weak_bg_fill = panel;
    style.visuals.widgets.inactive.fg_stroke.color = text;
    style.visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(8);
    style.visuals.widgets.hovered.bg_fill = panel_hover;
    style.visuals.widgets.hovered.weak_bg_fill = panel_hover;
    style.visuals.widgets.hovered.fg_stroke.color = text;
    style.visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(8);
    style.visuals.widgets.active.bg_fill = panel_hover;
    style.visuals.widgets.active.fg_stroke.color = text;
    style.visuals.widgets.active.corner_radius = egui::CornerRadius::same(8);
    style.visuals.selection.bg_fill = accent;
    style.visuals.hyperlink_color = accent;

    ctx.set_style(style);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Dashboard,
    Scan,
    Quarantine,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GaugeKind {
    Cpu,
    Memory,
}

struct GaugeCardResponse {
    drag: egui::Response,
    rect: egui::Rect,
}

enum WorkerMessage {
    Started(usize),
    Current(PathBuf),
    Report(ScanReport),
    Error(String),
    Finished { cancelled: bool },
}

#[derive(Debug, Clone)]
struct ScanSummary {
    target: String,
    scanned: usize,
    clean: usize,
    suspicious: usize,
    malicious: usize,
    total: usize,
    cancelled: bool,
    duration: Duration,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ProtectionSnapshot {
    #[serde(default)]
    realtime_file_monitor: bool,
    #[serde(default)]
    process_telemetry: bool,
    #[serde(default)]
    registry_telemetry: bool,
    #[serde(default)]
    memory_telemetry: bool,
    #[serde(default)]
    amsi_active: bool,
    #[serde(default)]
    etw_active: bool,
    #[serde(default)]
    minifilter_connected: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
struct ProtectionPreferences {
    #[serde(default = "default_enabled")]
    enable_realtime_file_monitor: bool,
    #[serde(default = "default_enabled")]
    enable_process_telemetry: bool,
    #[serde(default = "default_enabled")]
    enable_registry_telemetry: bool,
    #[serde(default = "default_enabled")]
    enable_memory_telemetry: bool,
    #[serde(default = "default_enabled")]
    enable_amsi: bool,
    #[serde(default = "default_enabled")]
    enable_etw: bool,
    #[serde(default = "default_enabled")]
    enable_minifilter: bool,
    #[serde(default = "default_enabled")]
    enable_definition_updates: bool,
    #[serde(default = "default_enabled")]
    auto_quarantine: bool,
}

impl Default for ProtectionPreferences {
    fn default() -> Self {
        Self {
            enable_realtime_file_monitor: true,
            enable_process_telemetry: true,
            enable_registry_telemetry: true,
            enable_memory_telemetry: true,
            enable_amsi: true,
            enable_etw: true,
            enable_minifilter: true,
            enable_definition_updates: true,
            auto_quarantine: true,
        }
    }
}

struct SentinelApp {
    page: Page,
    target: Option<PathBuf>,
    hdb_path: Option<PathBuf>,
    hsb_path: Option<PathBuf>,
    quarantine_dir: PathBuf,
    reports: Vec<ScanReport>,
    quarantine_entries: Vec<QuarantineEntry>,
    scan_rx: Option<mpsc::Receiver<WorkerMessage>>,
    cancel_flag: Option<Arc<AtomicBool>>,
    scanning: bool,
    total_files: usize,
    current_file: Option<PathBuf>,
    scanned_count: usize,
    clean_count: usize,
    suspicious_count: usize,
    malicious_count: usize,
    status_text: String,
    auto_quarantine: bool,
    scan_started: Option<Instant>,
    last_summary: Option<ScanSummary>,
    show_report: bool,
    system: System,
    last_metrics_refresh: Instant,
    cpu_usage: f32,
    memory_usage: f32,
    memory_used_gb: f64,
    memory_total_gb: f64,
    theme_mode: ThemeMode,
    applied_theme: egui::Theme,
    gauge_order: [GaugeKind; 2],
    dragging_gauge: Option<GaugeKind>,
    service_state: String,
    protection_snapshot: ProtectionSnapshot,
    protection_preferences: ProtectionPreferences,
    protection_preferences_loaded: bool,
    last_service_refresh: Instant,
}

impl SentinelApp {
    fn new(ctx: &egui::Context) -> Self {
        let quarantine_dir = default_quarantine_dir();
        let theme_mode = ThemeMode::System;
        configure_style(ctx, theme_mode);
        let applied_theme = resolved_theme(ctx, theme_mode);
        let mut system = System::new_all();
        system.refresh_cpu_usage();
        system.refresh_memory();

        let mut app = Self {
            page: Page::Dashboard,
            target: None,
            hdb_path: None,
            hsb_path: None,
            quarantine_dir,
            reports: Vec::new(),
            quarantine_entries: Vec::new(),
            scan_rx: None,
            cancel_flag: None,
            scanning: false,
            total_files: 0,
            current_file: None,
            scanned_count: 0,
            clean_count: 0,
            suspicious_count: 0,
            malicious_count: 0,
            status_text: "Protection engine ready".to_string(),
            auto_quarantine: false,
            scan_started: None,
            last_summary: None,
            show_report: false,
            system,
            last_metrics_refresh: Instant::now(),
            cpu_usage: 0.0,
            memory_usage: 0.0,
            memory_used_gb: 0.0,
            memory_total_gb: 0.0,
            theme_mode,
            applied_theme,
            gauge_order: [GaugeKind::Cpu, GaugeKind::Memory],
            dragging_gauge: None,
            service_state: "Checking…".to_string(),
            protection_snapshot: ProtectionSnapshot::default(),
            protection_preferences: ProtectionPreferences::default(),
            protection_preferences_loaded: false,
            last_service_refresh: Instant::now() - Duration::from_secs(10),
        };
        app.refresh_quarantine();
        app.refresh_metrics();
        app.refresh_service_state();
        app.load_service_preferences();
        app
    }

    fn refresh_theme(&mut self, ctx: &egui::Context) {
        let resolved = resolved_theme(ctx, self.theme_mode);
        if resolved != self.applied_theme {
            configure_style(ctx, self.theme_mode);
            self.applied_theme = resolved;
        }
    }

    fn refresh_service_state(&mut self) {
        if self.last_service_refresh.elapsed() < Duration::from_secs(2) {
            return;
        }

        let exe = service_executable_path();
        self.service_state = if !exe.is_file() {
            "Service binary missing".to_string()
        } else {
            match Command::new(&exe).arg("status").output() {
                Ok(output) if output.status.success() => {
                    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if text.is_empty() {
                        "Unknown".to_string()
                    } else {
                        text
                    }
                }
                Ok(_) => "Not installed".to_string(),
                Err(_) => "Unavailable".to_string(),
            }
        };

        self.protection_snapshot = fs::read(service_status_path())
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ProtectionSnapshot>(&bytes).ok())
            .unwrap_or_default();

        self.last_service_refresh = Instant::now();
    }

    fn invoke_service_command(&mut self, command: &str) {
        let exe = service_executable_path();
        if !exe.is_file() {
            self.status_text = "Protection service executable was not found.".to_string();
            return;
        }

        let escaped = exe.display().to_string().replace('\'', "''");
        let script = format!(
            "Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs -Wait",
            escaped, command
        );

        match Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", &script])
            .status()
        {
            Ok(status) if status.success() => {
                self.last_service_refresh = Instant::now() - Duration::from_secs(10);
                self.refresh_service_state();
                self.status_text = format!("Protection service command completed: {command}");
            }
            Ok(_) => {
                self.status_text = format!("Protection service command failed: {command}");
            }
            Err(err) => {
                self.status_text = format!("Could not run protection service command: {err}");
            }
        }
    }

    fn load_service_preferences(&mut self) {
        let exe = service_executable_path();
        if !exe.is_file() {
            return;
        }

        match Command::new(&exe).args(["config", "show"]).output() {
            Ok(output) if output.status.success() => {
                if let Ok(preferences) =
                    serde_json::from_slice::<ProtectionPreferences>(&output.stdout)
                {
                    self.protection_preferences = preferences;
                    self.protection_preferences_loaded = true;
                }
            }
            _ => {}
        }
    }

    fn apply_protection_preferences(&mut self) {
        let exe = service_executable_path();
        if !exe.is_file() {
            self.status_text = "Protection service executable was not found.".to_string();
            return;
        }

        let assignments = vec![
            format!(
                "realtime_file_monitor={}",
                self.protection_preferences.enable_realtime_file_monitor
            ),
            format!(
                "process_telemetry={}",
                self.protection_preferences.enable_process_telemetry
            ),
            format!(
                "registry_telemetry={}",
                self.protection_preferences.enable_registry_telemetry
            ),
            format!(
                "memory_telemetry={}",
                self.protection_preferences.enable_memory_telemetry
            ),
            format!("amsi={}", self.protection_preferences.enable_amsi),
            format!("etw={}", self.protection_preferences.enable_etw),
            format!(
                "minifilter={}",
                self.protection_preferences.enable_minifilter
            ),
            format!(
                "definition_updates={}",
                self.protection_preferences.enable_definition_updates
            ),
            format!(
                "auto_quarantine={}",
                self.protection_preferences.auto_quarantine
            ),
        ];

        let escaped_exe = exe.display().to_string().replace('\'', "''");
        let mut argument_literals = vec!["'config'".to_string(), "'apply-restart'".to_string()];
        argument_literals.extend(
            assignments
                .iter()
                .map(|value| format!("'{}'", value.replace('\'', "''"))),
        );

        let script = format!(
            "Start-Process -FilePath '{}' -ArgumentList @({}) -Verb RunAs -Wait",
            escaped_exe,
            argument_literals.join(",")
        );

        match Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", &script])
            .status()
        {
            Ok(status) if status.success() => {
                self.status_text =
                    "Protection settings applied; service restart requested.".to_string();
                self.last_service_refresh = Instant::now() - Duration::from_secs(10);
                self.refresh_service_state();
                self.load_service_preferences();
            }
            Ok(_) => {
                self.status_text = "Failed to apply protection settings.".to_string();
            }
            Err(err) => {
                self.status_text = format!("Could not apply protection settings: {err}");
            }
        }
    }

    fn refresh_metrics(&mut self) {
        if self.last_metrics_refresh.elapsed() < Duration::from_millis(900) {
            return;
        }

        self.system.refresh_cpu_usage();
        self.system.refresh_memory();

        self.cpu_usage = self.system.global_cpu_usage().clamp(0.0, 100.0);
        let total = self.system.total_memory();
        let used = self.system.used_memory();
        self.memory_usage = if total == 0 {
            0.0
        } else {
            ((used as f64 / total as f64) * 100.0) as f32
        };
        self.memory_used_gb = used as f64 / 1024.0 / 1024.0 / 1024.0;
        self.memory_total_gb = total as f64 / 1024.0 / 1024.0 / 1024.0;
        self.last_metrics_refresh = Instant::now();
    }

    fn start_scan(&mut self) {
        let Some(target) = self.target.clone() else {
            self.status_text = "Select a file or folder first".to_string();
            return;
        };

        self.reports.clear();
        self.scanned_count = 0;
        self.clean_count = 0;
        self.suspicious_count = 0;
        self.malicious_count = 0;
        self.total_files = 0;
        self.current_file = None;
        self.scanning = true;
        self.show_report = false;
        self.scan_started = Some(Instant::now());
        self.status_text = format!("Preparing scan for {}", target.display());

        let hdb = self.hdb_path.clone();
        let hsb = self.hsb_path.clone();
        let quarantine_dir = self.quarantine_dir.clone();
        let auto_quarantine = self.auto_quarantine;
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel_flag = Some(Arc::clone(&cancel));

        let (tx, rx) = mpsc::channel();
        self.scan_rx = Some(rx);

        thread::spawn(move || {
            let scanner = match build_scanner(hdb.as_deref(), hsb.as_deref()) {
                Ok(scanner) => scanner,
                Err(err) => {
                    let _ = tx.send(WorkerMessage::Error(err.to_string()));
                    let _ = tx.send(WorkerMessage::Finished { cancelled: false });
                    return;
                }
            };

            let quarantine = if auto_quarantine {
                QuarantineStore::open(&quarantine_dir).ok()
            } else {
                None
            };

            let files = collect_scan_targets(&target, &cancel);
            let cancelled_before_scan = cancel.load(Ordering::Relaxed);
            let _ = tx.send(WorkerMessage::Started(files.len()));

            if cancelled_before_scan {
                let _ = tx.send(WorkerMessage::Finished { cancelled: true });
                return;
            }

            for path in files {
                if cancel.load(Ordering::Relaxed) {
                    let _ = tx.send(WorkerMessage::Finished { cancelled: true });
                    return;
                }

                let _ = tx.send(WorkerMessage::Current(path.clone()));
                scan_and_send(&scanner, &path, quarantine.as_ref(), auto_quarantine, &tx);
            }

            let _ = tx.send(WorkerMessage::Finished {
                cancelled: cancel.load(Ordering::Relaxed),
            });
        });
    }

    fn cancel_scan(&mut self) {
        if let Some(flag) = &self.cancel_flag {
            flag.store(true, Ordering::Relaxed);
            self.status_text = "Cancelling scan…".to_string();
        }
    }

    fn poll_scan(&mut self) {
        let Some(rx) = self.scan_rx.take() else {
            return;
        };

        let mut finished = false;

        while let Ok(message) = rx.try_recv() {
            match message {
                WorkerMessage::Started(total) => {
                    self.total_files = total;
                    self.status_text = format!("Scanning {total} file(s)");
                }
                WorkerMessage::Current(path) => {
                    self.current_file = Some(path);
                }
                WorkerMessage::Report(report) => {
                    self.scanned_count += 1;
                    match report.verdict.level {
                        ThreatLevel::Clean => self.clean_count += 1,
                        ThreatLevel::Suspicious => self.suspicious_count += 1,
                        ThreatLevel::Malicious => self.malicious_count += 1,
                    }
                    self.reports.push(report);
                }
                WorkerMessage::Error(err) => {
                    self.status_text = err;
                }
                WorkerMessage::Finished { cancelled } => {
                    self.scanning = false;
                    self.current_file = None;
                    self.cancel_flag = None;
                    let duration = self
                        .scan_started
                        .take()
                        .map(|start| start.elapsed())
                        .unwrap_or_default();

                    let target = self
                        .target
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "Unknown".to_string());

                    self.last_summary = Some(ScanSummary {
                        target,
                        scanned: self.scanned_count,
                        clean: self.clean_count,
                        suspicious: self.suspicious_count,
                        malicious: self.malicious_count,
                        total: self.total_files,
                        cancelled,
                        duration,
                    });

                    if cancelled {
                        self.status_text = format!(
                            "Scan cancelled after {} of {} file(s)",
                            self.scanned_count, self.total_files
                        );
                    } else {
                        self.status_text = format!(
                            "Scan complete — {} file(s), {} malicious, {} suspicious",
                            self.scanned_count, self.malicious_count, self.suspicious_count
                        );
                    }

                    self.refresh_quarantine();
                    self.show_report = true;
                    finished = true;
                }
            }
        }

        if !finished {
            self.scan_rx = Some(rx);
        }
    }

    fn refresh_quarantine(&mut self) {
        self.quarantine_entries = QuarantineStore::open(&self.quarantine_dir)
            .and_then(|store| store.list_entries())
            .unwrap_or_default();
    }

    fn restore_entry(&mut self, entry: &QuarantineEntry) {
        match QuarantineStore::open(&self.quarantine_dir).and_then(|store| store.restore(entry.id))
        {
            Ok(restored) => {
                self.status_text = format!("Restored {}", restored.original_path.display());
                self.refresh_quarantine();
            }
            Err(err) => self.status_text = format!("Restore failed: {err}"),
        }
    }

    fn delete_entry(&mut self, entry: &QuarantineEntry) {
        match QuarantineStore::open(&self.quarantine_dir).and_then(|store| store.delete(entry.id)) {
            Ok(()) => {
                self.status_text = "Quarantine entry deleted".to_string();
                self.refresh_quarantine();
            }
            Err(err) => self.status_text = format!("Delete failed: {err}"),
        }
    }

    fn save_report(&mut self) {
        let Some(summary) = &self.last_summary else {
            return;
        };

        let Some(path) = rfd::FileDialog::new()
            .set_file_name("BDFR-Sentinel-Scan-Report.txt")
            .save_file()
        else {
            return;
        };

        let mut body = String::new();
        body.push_str("BDFR Sentinel Scan Report\n");
        body.push_str("=========================\n\n");
        body.push_str(&format!("Target: {}\n", summary.target));
        body.push_str(&format!(
            "Status: {}\n",
            if summary.cancelled {
                "Cancelled"
            } else {
                "Completed"
            }
        ));
        body.push_str(&format!(
            "Duration: {:.2}s\n",
            summary.duration.as_secs_f64()
        ));
        body.push_str(&format!(
            "Scanned: {} / {}\n",
            summary.scanned, summary.total
        ));
        body.push_str(&format!("Clean: {}\n", summary.clean));
        body.push_str(&format!("Suspicious: {}\n", summary.suspicious));
        body.push_str(&format!("Malicious: {}\n\n", summary.malicious));

        for report in &self.reports {
            if report.verdict.level == ThreatLevel::Clean {
                continue;
            }
            body.push_str(&format!("[{:?}] {}\n", report.verdict.level, report.path));
            body.push_str(&format!("SHA-256: {}\n", report.metadata.sha256));
            for detection in &report.verdict.detections {
                body.push_str(&format!(
                    "  - {:?} / {:?}: {}\n",
                    detection.category, detection.level, detection.title
                ));
                if let Some(details) = &detection.details {
                    body.push_str(&format!("    {}\n", details));
                }
            }
            body.push('\n');
        }

        match fs::write(&path, body) {
            Ok(()) => self.status_text = format!("Report saved to {}", path.display()),
            Err(err) => self.status_text = format!("Could not save report: {err}"),
        }
    }

    fn nav_button(&mut self, ui: &mut egui::Ui, page: Page, icon: &str, label: &str) {
        let selected = self.page == page;
        let text = egui::RichText::new(format!("{icon}   {label}"))
            .size(17.0)
            .color(ui.visuals().text_color());

        let button = egui::Button::new(text)
            .fill(if selected {
                ui.visuals().widgets.active.bg_fill
            } else {
                egui::Color32::TRANSPARENT
            })
            .stroke(egui::Stroke::NONE)
            .corner_radius(8.0)
            .min_size(egui::vec2(210.0, 50.0));

        if ui.add(button).clicked() {
            self.page = page;
        }

        if selected {
            let rect = ui.min_rect();
            let painter = ui.painter();
            let x = rect.left() + 2.0;
            painter.line_segment(
                [
                    egui::pos2(x, rect.bottom() - 45.0),
                    egui::pos2(x, rect.bottom() - 9.0),
                ],
                egui::Stroke::new(3.0_f32, ui.visuals().hyperlink_color),
            );
        }
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("◈")
                    .size(28.0)
                    .color(ui.visuals().hyperlink_color),
            );
            ui.vertical(|ui| {
                ui.label(egui::RichText::new("BDFR Sentinel").size(19.0).strong());
                ui.label(
                    egui::RichText::new("Endpoint Security")
                        .size(12.0)
                        .color(ui.visuals().weak_text_color()),
                );
            });
        });
        ui.add_space(28.0);

        self.nav_button(ui, Page::Dashboard, "⌂", "Dashboard");
        self.nav_button(ui, Page::Scan, "⌕", "Scan");
        self.nav_button(ui, Page::Quarantine, "▣", "Quarantine");
        self.nav_button(ui, Page::Settings, "⚙", "Settings");

        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION")))
                    .size(11.0)
                    .color(ui.visuals().weak_text_color()),
            );
            ui.label(
                egui::RichText::new("Crack/license-bypass ignored by default")
                    .size(11.0)
                    .color(ui.visuals().weak_text_color()),
            );
        });
    }

    fn dashboard(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Security dashboard",
            "A quick view of protection, scan activity and system load.",
        );

        let realtime_running = self.service_state.contains("Running");

        egui::Frame::new()
            .fill(ui.visuals().faint_bg_color)
            .corner_radius(12.0)
            .inner_margin(20.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(if realtime_running { "✓" } else { "!" })
                            .size(36.0)
                            .color(if realtime_running { GOOD } else { WARN }),
                    );
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(if realtime_running {
                                "Real-time protection is on"
                            } else {
                                "Real-time protection needs attention"
                            })
                            .size(21.0)
                            .strong(),
                        );
                        ui.label(
                            egui::RichText::new(format!(
                                "Windows protection service: {}",
                                self.service_state
                            ))
                            .color(ui.visuals().weak_text_color()),
                        );
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if realtime_running {
                            if fluent_button(ui, "Stop", true).clicked() {
                                self.invoke_service_command("stop");
                            }
                        } else {
                            if fluent_button(ui, "Start", false).clicked() {
                                self.invoke_service_command("start");
                            }
                            if self.service_state.contains("Not installed")
                                && fluent_button(ui, "Install", false).clicked()
                            {
                                self.invoke_service_command("install");
                                self.invoke_service_command("start");
                            }
                        }

                        if fluent_button(ui, "Refresh", false).clicked() {
                            self.last_service_refresh = Instant::now() - Duration::from_secs(10);
                            self.refresh_service_state();
                        }
                    });
                });
            });

        ui.add_space(14.0);

        ui.horizontal_wrapped(|ui| {
            metric_card(
                ui,
                "Scanned",
                self.scanned_count,
                ui.visuals().hyperlink_color,
            );
            metric_card(ui, "Clean", self.clean_count, GOOD);
            metric_card(ui, "Suspicious", self.suspicious_count, WARN);
            metric_card(ui, "Malicious", self.malicious_count, BAD);
            metric_card(
                ui,
                "Quarantine",
                self.quarantine_entries.len(),
                ui.visuals().hyperlink_color,
            );
        });

        ui.add_space(14.0);
        ui.label(
            egui::RichText::new("Drag the gauge cards to reorder them")
                .size(11.0)
                .color(ui.visuals().weak_text_color()),
        );
        ui.add_space(4.0);

        let gauge_order = self.gauge_order;
        let mut card_responses: [Option<GaugeCardResponse>; 2] = [None, None];

        ui.columns(2, |columns| {
            for index in 0..2 {
                let response = match gauge_order[index] {
                    GaugeKind::Cpu => {
                        let accent = columns[index].visuals().hyperlink_color;
                        resource_card(
                            &mut columns[index],
                            "CPU",
                            self.cpu_usage,
                            format!("{:.0}% in use", self.cpu_usage),
                            accent,
                        )
                    }
                    GaugeKind::Memory => resource_card(
                        &mut columns[index],
                        "Memory",
                        self.memory_usage,
                        format!(
                            "{:.1} / {:.1} GB",
                            self.memory_used_gb, self.memory_total_gb
                        ),
                        egui::Color32::from_rgb(177, 113, 255),
                    ),
                };

                if response.drag.drag_started() {
                    self.dragging_gauge = Some(gauge_order[index]);
                }

                card_responses[index] = Some(response);
            }
        });

        if ui.input(|input| input.pointer.any_released()) {
            if let (Some(dragging), Some(pointer)) = (
                self.dragging_gauge,
                ui.input(|input| input.pointer.hover_pos()),
            ) {
                let source_index = gauge_order.iter().position(|kind| *kind == dragging);
                let target_index = card_responses.iter().position(|response| {
                    response
                        .as_ref()
                        .is_some_and(|response| response.rect.contains(pointer))
                });

                if let (Some(source), Some(target)) = (source_index, target_index) {
                    if source != target {
                        self.gauge_order.swap(source, target);
                    }
                }
            }
            self.dragging_gauge = None;
        }

        ui.add_space(14.0);
        settings_card(ui, "Protection components", |ui| {
            status_row(ui, "Core scanner", "Ready", GOOD);
            status_row(ui, "PE analyzer", "Ready", GOOD);
            status_row(
                ui,
                "Hash definitions",
                "HDB / HSB",
                ui.visuals().hyperlink_color,
            );
            status_row(ui, "Encrypted quarantine", "AES-256-GCM + DPAPI", GOOD);
            status_row(
                ui,
                "Real-time protection",
                &self.service_state,
                if realtime_running { GOOD } else { WARN },
            );
            status_row(
                ui,
                "File monitor",
                component_label(self.protection_snapshot.realtime_file_monitor),
                component_color(self.protection_snapshot.realtime_file_monitor),
            );
            status_row(
                ui,
                "Process telemetry",
                component_label(self.protection_snapshot.process_telemetry),
                component_color(self.protection_snapshot.process_telemetry),
            );
            status_row(
                ui,
                "Registry persistence",
                component_label(self.protection_snapshot.registry_telemetry),
                component_color(self.protection_snapshot.registry_telemetry),
            );
            status_row(
                ui,
                "Memory telemetry",
                component_label(self.protection_snapshot.memory_telemetry),
                component_color(self.protection_snapshot.memory_telemetry),
            );
            status_row(
                ui,
                "Windows AMSI",
                component_label(self.protection_snapshot.amsi_active),
                component_color(self.protection_snapshot.amsi_active),
            );
            status_row(
                ui,
                "ETW process trace",
                component_label(self.protection_snapshot.etw_active),
                component_color(self.protection_snapshot.etw_active),
            );
            status_row(
                ui,
                "Pre-execution Minifilter",
                if self.protection_snapshot.minifilter_connected {
                    "Connected"
                } else {
                    "Not connected"
                },
                component_color(self.protection_snapshot.minifilter_connected),
            );
        });

        if let Some(summary) = &self.last_summary {
            ui.add_space(14.0);
            settings_card(ui, "Last scan", |ui| {
                ui.horizontal(|ui| {
                    ui.label(format!(
                        "{} files • {} malicious • {} suspicious • {:.1}s",
                        summary.scanned,
                        summary.malicious,
                        summary.suspicious,
                        summary.duration.as_secs_f64()
                    ));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("View report").clicked() {
                            self.show_report = true;
                        }
                    });
                });
            });
        }
    }

    fn scan_page(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Scan",
            "Choose a file or folder and inspect it with the active detection engines.",
        );

        settings_card(ui, "Scan target", |ui| {
            ui.horizontal_wrapped(|ui| {
                if fluent_button(ui, "Choose file", false).clicked() {
                    self.target = rfd::FileDialog::new().pick_file();
                }
                if fluent_button(ui, "Choose folder", false).clicked() {
                    self.target = rfd::FileDialog::new().pick_folder();
                }

                if self.scanning {
                    if fluent_button(ui, "Cancel scan", true).clicked() {
                        self.cancel_scan();
                    }
                } else if ui
                    .add_enabled(
                        self.target.is_some(),
                        egui::Button::new(egui::RichText::new("Start scan").size(15.0))
                            .fill(egui::Color32::from_rgb(0, 95, 184))
                            .corner_radius(8.0)
                            .min_size(egui::vec2(120.0, 42.0)),
                    )
                    .clicked()
                {
                    self.start_scan();
                }
            });

            if let Some(target) = &self.target {
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(target.display().to_string())
                        .color(ui.visuals().weak_text_color()),
                );
            }

            ui.checkbox(
                &mut self.auto_quarantine,
                "Automatically quarantine confirmed malicious verdicts",
            );
        });

        if self.scanning {
            ui.add_space(14.0);
            settings_card(ui, "Scan progress", |ui| {
                let progress = if self.total_files == 0 {
                    0.0
                } else {
                    self.scanned_count as f32 / self.total_files as f32
                };

                ui.add(
                    egui::ProgressBar::new(progress.clamp(0.0, 1.0))
                        .animate(true)
                        .desired_width(f32::INFINITY)
                        .text(format!(
                            "{} / {} files",
                            self.scanned_count, self.total_files
                        )),
                );

                if let Some(current) = &self.current_file {
                    ui.label(
                        egui::RichText::new(format!("Scanning: {}", current.display()))
                            .size(12.0)
                            .color(ui.visuals().weak_text_color()),
                    );
                }

                ui.horizontal(|ui| {
                    ui.label(format!("Clean: {}", self.clean_count));
                    ui.separator();
                    ui.label(format!("Suspicious: {}", self.suspicious_count));
                    ui.separator();
                    ui.label(format!("Malicious: {}", self.malicious_count));
                });
            });
        }

        ui.add_space(14.0);
        settings_card(ui, "Results", |ui| {
            egui::ScrollArea::vertical()
                .max_height(ui.available_height().max(240.0))
                .show(ui, |ui| {
                    if self.reports.is_empty() {
                        ui.label(
                            egui::RichText::new("No scan results yet.")
                                .color(ui.visuals().weak_text_color()),
                        );
                    }

                    for report in self.reports.iter().rev().take(700) {
                        let level_color = match report.verdict.level {
                            ThreatLevel::Clean => GOOD,
                            ThreatLevel::Suspicious => WARN,
                            ThreatLevel::Malicious => BAD,
                        };

                        egui::CollapsingHeader::new(
                            egui::RichText::new(format!(
                                "{:?}   {}   {} bytes",
                                report.verdict.level, report.path, report.metadata.size
                            ))
                            .color(level_color),
                        )
                        .default_open(report.verdict.level != ThreatLevel::Clean)
                        .show(ui, |ui| {
                            ui.monospace(format!("SHA-256: {}", report.metadata.sha256));
                            if report.verdict.detections.is_empty() {
                                ui.label("No detections");
                            } else {
                                for detection in &report.verdict.detections {
                                    ui.label(format!(
                                        "{:?} / {:?} — {}",
                                        detection.category, detection.level, detection.title
                                    ));
                                    if let Some(details) = &detection.details {
                                        ui.label(
                                            egui::RichText::new(details)
                                                .small()
                                                .color(ui.visuals().weak_text_color()),
                                        );
                                    }
                                }
                            }
                        });
                    }
                });
        });
    }

    fn quarantine_page(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Quarantine",
            "Review isolated files, restore trusted items or remove them permanently.",
        );

        settings_card(ui, "Quarantine store", |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(self.quarantine_dir.display().to_string())
                        .color(ui.visuals().weak_text_color()),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if fluent_button(ui, "Refresh", false).clicked() {
                        self.refresh_quarantine();
                    }
                });
            });
        });

        ui.add_space(14.0);
        let entries = self.quarantine_entries.clone();

        egui::ScrollArea::vertical().show(ui, |ui| {
            if entries.is_empty() {
                settings_card(ui, "No quarantined items", |ui| {
                    ui.label(
                        egui::RichText::new("The quarantine store is empty.")
                            .color(ui.visuals().weak_text_color()),
                    );
                });
            }

            for entry in entries {
                egui::Frame::new()
                    .fill(ui.visuals().faint_bg_color)
                    .corner_radius(10.0)
                    .inner_margin(16.0)
                    .outer_margin(egui::Margin::symmetric(0, 5))
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(entry.original_path.display().to_string()).strong(),
                        );
                        ui.label(
                            egui::RichText::new(format!(
                                "{} bytes • SHA-256 {}",
                                entry.original_size, entry.original_sha256
                            ))
                            .size(11.0)
                            .color(ui.visuals().weak_text_color()),
                        );
                        ui.label(
                            egui::RichText::new(&entry.reason)
                                .color(ui.visuals().weak_text_color()),
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if fluent_button(ui, "Restore", false).clicked() {
                                self.restore_entry(&entry);
                            }
                            if fluent_button(ui, "Delete", true).clicked() {
                                self.delete_entry(&entry);
                            }
                        });
                    });
            }
        });
    }

    fn settings_page(&mut self, ui: &mut egui::Ui) {
        let hdb_current = self.hdb_path.clone();
        let hsb_current = self.hsb_path.clone();

        page_header(
            ui,
            "Settings",
            "Configure definition sources and detection behavior.",
        );

        settings_card(ui, "Appearance", |ui| {
            ui.label(
                egui::RichText::new("Choose how BDFR Sentinel should look.")
                    .color(ui.visuals().weak_text_color()),
            );
            ui.add_space(6.0);

            let mut selected = self.theme_mode;
            egui::ComboBox::from_id_salt("theme_mode")
                .selected_text(selected.label())
                .width(180.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut selected,
                        ThemeMode::System,
                        ThemeMode::System.label(),
                    );
                    ui.selectable_value(&mut selected, ThemeMode::Dark, ThemeMode::Dark.label());
                    ui.selectable_value(&mut selected, ThemeMode::Light, ThemeMode::Light.label());
                });

            if selected != self.theme_mode {
                self.theme_mode = selected;
            }

            ui.label(
                egui::RichText::new(match self.theme_mode {
                    ThemeMode::System => "Follows the current Windows light/dark appearance.",
                    ThemeMode::Dark => "Uses the dark Fluent palette.",
                    ThemeMode::Light => "Uses the light Fluent palette.",
                })
                .size(11.0)
                .color(ui.visuals().weak_text_color()),
            );
        });

        ui.add_space(14.0);

        settings_card(ui, "Protection controls", |ui| {
            ui.label(
                egui::RichText::new(
                    "Choose which always-on protection subsystems should run in the Windows service.",
                )
                .color(ui.visuals().weak_text_color()),
            );
            ui.add_space(8.0);

            if !self.protection_preferences_loaded {
                ui.label(
                    egui::RichText::new(
                        "Service configuration is unavailable until the protection service is installed.",
                    )
                    .color(WARN),
                );
            }

            ui.checkbox(
                &mut self.protection_preferences.enable_realtime_file_monitor,
                "Real-time file monitoring",
            );
            ui.checkbox(
                &mut self.protection_preferences.enable_process_telemetry,
                "Process telemetry and process-image scanning",
            );
            ui.checkbox(
                &mut self.protection_preferences.enable_registry_telemetry,
                "Registry persistence monitoring",
            );
            ui.checkbox(
                &mut self.protection_preferences.enable_memory_telemetry,
                "Executable/writable memory telemetry",
            );
            ui.checkbox(
                &mut self.protection_preferences.enable_amsi,
                "Windows AMSI script scanning",
            );
            ui.checkbox(
                &mut self.protection_preferences.enable_etw,
                "ETW process telemetry",
            );
            ui.checkbox(
                &mut self.protection_preferences.enable_minifilter,
                "Kernel Minifilter broker / pre-execution policy",
            );
            ui.checkbox(
                &mut self.protection_preferences.enable_definition_updates,
                "Signed definition update activation",
            );
            ui.checkbox(
                &mut self.protection_preferences.auto_quarantine,
                "Automatically quarantine confirmed malware",
            );

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        self.protection_preferences_loaded,
                        egui::Button::new("Apply & restart protection"),
                    )
                    .clicked()
                {
                    self.apply_protection_preferences();
                }

                if fluent_button(ui, "Reload", false).clicked() {
                    self.load_service_preferences();
                }
            });

            ui.label(
                egui::RichText::new(
                    "Minifilter can only become Active when a built and appropriately signed driver is installed.",
                )
                .size(11.0)
                .color(ui.visuals().weak_text_color()),
            );
        });

        ui.add_space(14.0);

        settings_card(ui, "Definition sources", |ui| {
            setting_picker(
                ui,
                "ClamAV HDB",
                "MD5-based signature database",
                hdb_current.as_ref(),
                || {
                    rfd::FileDialog::new()
                        .add_filter("ClamAV HDB", &["hdb"])
                        .pick_file()
                },
                &mut self.hdb_path,
            );

            ui.separator();

            setting_picker(
                ui,
                "ClamAV HSB",
                "SHA-256 signature database",
                hsb_current.as_ref(),
                || {
                    rfd::FileDialog::new()
                        .add_filter("ClamAV HSB", &["hsb"])
                        .pick_file()
                },
                &mut self.hsb_path,
            );
        });

        ui.add_space(14.0);
        settings_card(ui, "Detection policy", |ui| {
            ui.label(
                "Malware, ransomware, trojans, backdoors and similar threats remain actionable.",
            );
            ui.label(
                egui::RichText::new(
                    "Crack and license-bypass classifications are ignored by default.",
                )
                .color(ui.visuals().weak_text_color()),
            );
            ui.label(egui::RichText::new("A cracked file is still detected if it independently matches malware indicators.").color(ui.visuals().weak_text_color()));
        });

        ui.add_space(14.0);
        settings_card(ui, "System", |ui| {
            status_row(
                ui,
                "CPU usage",
                &format!("{:.0}%", self.cpu_usage),
                ui.visuals().hyperlink_color,
            );
            status_row(
                ui,
                "Memory usage",
                &format!(
                    "{:.0}% ({:.1}/{:.1} GB)",
                    self.memory_usage, self.memory_used_gb, self.memory_total_gb
                ),
                egui::Color32::from_rgb(177, 113, 255),
            );
        });
    }

    fn report_window(&mut self, ctx: &egui::Context) {
        if !self.show_report {
            return;
        }

        let Some(summary) = self.last_summary.clone() else {
            self.show_report = false;
            return;
        };

        let mut open = self.show_report;
        egui::Window::new("Scan report")
            .open(&mut open)
            .resizable(true)
            .default_width(620.0)
            .default_height(520.0)
            .show(ctx, |ui| {
                ui.heading(if summary.cancelled {
                    "Scan cancelled"
                } else {
                    "Scan completed"
                });
                ui.label(
                    egui::RichText::new(&summary.target).color(ui.visuals().weak_text_color()),
                );
                ui.add_space(12.0);

                ui.horizontal_wrapped(|ui| {
                    metric_card(ui, "Scanned", summary.scanned, ui.visuals().hyperlink_color);
                    metric_card(ui, "Clean", summary.clean, GOOD);
                    metric_card(ui, "Suspicious", summary.suspicious, WARN);
                    metric_card(ui, "Malicious", summary.malicious, BAD);
                });

                ui.add_space(10.0);
                ui.label(format!(
                    "Duration: {:.2} seconds • Progress: {} / {}",
                    summary.duration.as_secs_f64(),
                    summary.scanned,
                    summary.total
                ));

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if fluent_button(ui, "Save report", false).clicked() {
                        self.save_report();
                    }
                    if fluent_button(ui, "Close", false).clicked() {
                        self.show_report = false;
                    }
                });

                ui.separator();
                ui.label(egui::RichText::new("Detections").strong());
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let mut any = false;
                    for report in &self.reports {
                        if report.verdict.level == ThreatLevel::Clean {
                            continue;
                        }
                        any = true;
                        ui.label(
                            egui::RichText::new(format!(
                                "{:?} — {}",
                                report.verdict.level, report.path
                            ))
                            .strong(),
                        );
                        for detection in &report.verdict.detections {
                            ui.label(format!(
                                "• {:?} / {:?}: {}",
                                detection.category, detection.level, detection.title
                            ));
                        }
                        ui.add_space(8.0);
                    }
                    if !any {
                        ui.label(
                            egui::RichText::new("No suspicious or malicious detections.")
                                .color(GOOD),
                        );
                    }
                });
            });

        self.show_report = open && self.show_report;
    }
}

impl eframe::App for SentinelApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_scan();
        self.refresh_theme(ctx);
        self.refresh_metrics();
        self.refresh_service_state();

        if self.scanning {
            ctx.request_repaint_after(Duration::from_millis(100));
        } else {
            ctx.request_repaint_after(Duration::from_millis(900));
        }

        let visuals = ctx.style().visuals.clone();

        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(250.0)
            .frame(
                egui::Frame::new()
                    .fill(visuals.extreme_bg_color)
                    .inner_margin(16.0),
            )
            .show(ctx, |ui| self.sidebar(ui));

        egui::TopBottomPanel::bottom("status")
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(visuals.extreme_bg_color)
                    .inner_margin(egui::Margin::symmetric(18, 8)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if self.scanning {
                        ui.spinner();
                    } else {
                        ui.label(egui::RichText::new("●").color(GOOD));
                    }
                    ui.label(
                        egui::RichText::new(&self.status_text)
                            .size(12.0)
                            .color(ui.visuals().weak_text_color()),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new(format!("RAM {:.0}%", self.memory_usage))
                                .size(11.0)
                                .color(ui.visuals().weak_text_color()),
                        );
                        ui.label(
                            egui::RichText::new(format!("CPU {:.0}%", self.cpu_usage))
                                .size(11.0)
                                .color(ui.visuals().weak_text_color()),
                        );
                    });
                });
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(visuals.panel_fill)
                    .inner_margin(egui::Margin::same(28)),
            )
            .show(ctx, |ui| match self.page {
                Page::Dashboard => self.dashboard(ui),
                Page::Scan => self.scan_page(ui),
                Page::Quarantine => self.quarantine_page(ui),
                Page::Settings => self.settings_page(ui),
            });

        self.report_window(ctx);
    }
}

fn collect_scan_targets(target: &Path, cancel: &AtomicBool) -> Vec<PathBuf> {
    if target.is_file() {
        return vec![target.to_path_buf()];
    }

    if !target.is_dir() {
        return Vec::new();
    }

    let mut files = Vec::new();
    for entry in WalkDir::new(target).follow_links(false) {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if let Ok(entry) = entry {
            if entry.file_type().is_file() {
                files.push(entry.into_path());
            }
        }
    }
    files
}

fn page_header(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(egui::RichText::new(title).size(30.0).strong());
    ui.label(
        egui::RichText::new(subtitle)
            .size(13.0)
            .color(ui.visuals().weak_text_color()),
    );
    ui.add_space(18.0);
}

fn metric_card(ui: &mut egui::Ui, title: &str, value: usize, color: egui::Color32) {
    egui::Frame::new()
        .fill(ui.visuals().faint_bg_color)
        .corner_radius(10.0)
        .inner_margin(16.0)
        .show(ui, |ui| {
            ui.set_min_width(125.0);
            ui.label(
                egui::RichText::new(value.to_string())
                    .size(25.0)
                    .strong()
                    .color(color),
            );
            ui.label(
                egui::RichText::new(title)
                    .size(12.0)
                    .color(ui.visuals().weak_text_color()),
            );
        });
}

fn resource_card(
    ui: &mut egui::Ui,
    title: &str,
    percentage: f32,
    detail: String,
    color: egui::Color32,
) -> GaugeCardResponse {
    let shown = egui::Frame::new()
        .fill(ui.visuals().faint_bg_color)
        .corner_radius(10.0)
        .inner_margin(18.0)
        .show(ui, |ui| {
            let drag = ui
                .add(
                    egui::Label::new(
                        egui::RichText::new("⠿  Drag")
                            .size(11.0)
                            .color(ui.visuals().weak_text_color()),
                    )
                    .sense(egui::Sense::drag()),
                )
                .on_hover_cursor(egui::CursorIcon::Grab);

            if drag.dragged() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::Grabbing);
            }

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let (response, painter) =
                    ui.allocate_painter(egui::vec2(96.0, 96.0), egui::Sense::hover());
                let center = response.rect.center();
                let radius = 38.0;
                let background = if ui.visuals().dark_mode {
                    egui::Color32::from_rgb(63, 63, 63)
                } else {
                    egui::Color32::from_rgb(210, 210, 210)
                };

                painter.circle_stroke(center, radius, egui::Stroke::new(8.0_f32, background));

                let fraction = (percentage / 100.0).clamp(0.0, 1.0);
                let start = -std::f32::consts::FRAC_PI_2;
                let end = start + std::f32::consts::TAU * fraction;
                let segments = 64;
                let mut points = Vec::with_capacity(segments + 1);
                for i in 0..=segments {
                    let t = i as f32 / segments as f32;
                    let angle = start + (end - start) * t;
                    points.push(egui::pos2(
                        center.x + angle.cos() * radius,
                        center.y + angle.sin() * radius,
                    ));
                }
                if points.len() > 1 {
                    painter.line(points, egui::Stroke::new(8.0_f32, color));
                }

                painter.text(
                    center,
                    egui::Align2::CENTER_CENTER,
                    format!("{:.0}%", percentage),
                    egui::FontId::proportional(21.0),
                    ui.visuals().text_color(),
                );

                ui.add_space(10.0);
                ui.vertical(|ui| {
                    ui.add_space(15.0);
                    ui.label(egui::RichText::new(title).size(17.0).strong());
                    ui.label(
                        egui::RichText::new(detail)
                            .size(12.0)
                            .color(ui.visuals().weak_text_color()),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new("Live system usage")
                            .size(11.0)
                            .color(color),
                    );
                });
            });

            drag
        });

    GaugeCardResponse {
        drag: shown.inner,
        rect: shown.response.rect,
    }
}

fn settings_card(ui: &mut egui::Ui, title: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(ui.visuals().faint_bg_color)
        .corner_radius(10.0)
        .inner_margin(18.0)
        .show(ui, |ui| {
            ui.label(egui::RichText::new(title).size(16.0).strong());
            ui.add_space(7.0);
            add_contents(ui);
        });
}

fn status_row(ui: &mut egui::Ui, name: &str, status: &str, color: egui::Color32) {
    ui.horizontal(|ui| {
        ui.label(name);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(status).color(color));
        });
    });
}

fn fluent_button(ui: &mut egui::Ui, label: &str, destructive: bool) -> egui::Response {
    let fill = if destructive {
        if ui.visuals().dark_mode {
            egui::Color32::from_rgb(92, 35, 35)
        } else {
            egui::Color32::from_rgb(252, 225, 223)
        }
    } else {
        ui.visuals().widgets.inactive.bg_fill
    };

    let text_color = if destructive {
        if ui.visuals().dark_mode {
            egui::Color32::from_rgb(255, 205, 201)
        } else {
            egui::Color32::from_rgb(130, 25, 20)
        }
    } else {
        ui.visuals().text_color()
    };

    ui.add(
        egui::Button::new(egui::RichText::new(label).size(14.0).color(text_color))
            .fill(fill)
            .corner_radius(8.0)
            .min_size(egui::vec2(104.0, 40.0)),
    )
}

fn setting_picker(
    ui: &mut egui::Ui,
    title: &str,
    subtitle: &str,
    current: Option<&PathBuf>,
    picker: impl FnOnce() -> Option<PathBuf>,
    destination: &mut Option<PathBuf>,
) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(egui::RichText::new(title).strong());
            ui.label(
                egui::RichText::new(subtitle)
                    .size(11.0)
                    .color(ui.visuals().weak_text_color()),
            );
            if let Some(path) = current {
                ui.label(
                    egui::RichText::new(path.display().to_string())
                        .size(11.0)
                        .color(ui.visuals().hyperlink_color),
                );
            }
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if fluent_button(ui, "Browse", false).clicked() {
                *destination = picker();
            }
        });
    });
}

fn component_label(active: bool) -> &'static str {
    if active {
        "Active"
    } else {
        "Inactive"
    }
}

fn component_color(active: bool) -> egui::Color32 {
    if active {
        GOOD
    } else {
        WARN
    }
}

fn service_status_path() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("BDFR")
        .join("Sentinel")
        .join("status.json")
}

fn service_executable_path() -> PathBuf {
    let current = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    current
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("bdfr-sentinel-service.exe")
}

fn default_quarantine_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("BDFR").join("Sentinel").join("Quarantine")
}

fn build_scanner(hdb_path: Option<&Path>, hsb_path: Option<&Path>) -> Result<Arc<FileScanner>> {
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

    Ok(Arc::new(FileScanner::new(
        ScannerConfig::default(),
        registry,
    )))
}

fn scan_and_send(
    scanner: &FileScanner,
    path: &Path,
    quarantine: Option<&QuarantineStore>,
    auto_quarantine: bool,
    tx: &mpsc::Sender<WorkerMessage>,
) {
    match scanner.scan_file(path) {
        Ok(report) => {
            let malicious = report.verdict.level == ThreatLevel::Malicious;
            if tx.send(WorkerMessage::Report(report)).is_err() {
                return;
            }

            if auto_quarantine && malicious {
                if let Some(store) = quarantine {
                    if let Err(err) =
                        store.quarantine_file(path, "malware detected by BDFR Sentinel GUI")
                    {
                        let _ = tx.send(WorkerMessage::Error(format!(
                            "Quarantine failed for {}: {err}",
                            path.display()
                        )));
                    }
                }
            }
        }
        Err(err) => {
            let _ = tx.send(WorkerMessage::Error(format!(
                "Scan failed for {}: {err}",
                path.display()
            )));
        }
    }
}
