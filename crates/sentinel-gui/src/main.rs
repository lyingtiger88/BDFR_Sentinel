#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::{Context, Result};
use eframe::egui;
use sentinel_core::{EngineRegistry, FileScanner, ScanReport, ScannerConfig, ThreatLevel};
use sentinel_definitions::{ClamHashDatabase, HashDefinitionEngine};
use sentinel_pe::PeAnalyzerEngine;
use sentinel_quarantine::{QuarantineEntry, QuarantineStore};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread;
use walkdir::WalkDir;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("BDFR Sentinel")
            .with_inner_size([1120.0, 720.0])
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "BDFR Sentinel",
        options,
        Box::new(|_cc| Ok(Box::new(SentinelApp::new()))),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Dashboard,
    Scan,
    Quarantine,
    Settings,
}

enum WorkerMessage {
    Report(ScanReport),
    Error(String),
    Finished,
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
    scanning: bool,
    scanned_count: usize,
    clean_count: usize,
    suspicious_count: usize,
    malicious_count: usize,
    status_text: String,
    auto_quarantine: bool,
}

impl SentinelApp {
    fn new() -> Self {
        let quarantine_dir = default_quarantine_dir();
        let mut app = Self {
            page: Page::Dashboard,
            target: None,
            hdb_path: None,
            hsb_path: None,
            quarantine_dir,
            reports: Vec::new(),
            quarantine_entries: Vec::new(),
            scan_rx: None,
            scanning: false,
            scanned_count: 0,
            clean_count: 0,
            suspicious_count: 0,
            malicious_count: 0,
            status_text: "Protection engine ready".to_string(),
            auto_quarantine: false,
        };
        app.refresh_quarantine();
        app
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
        self.scanning = true;
        self.status_text = format!("Scanning {}", target.display());

        let hdb = self.hdb_path.clone();
        let hsb = self.hsb_path.clone();
        let quarantine_dir = self.quarantine_dir.clone();
        let auto_quarantine = self.auto_quarantine;
        let (tx, rx) = mpsc::channel();
        self.scan_rx = Some(rx);

        thread::spawn(move || {
            let scanner = match build_scanner(hdb.as_deref(), hsb.as_deref()) {
                Ok(scanner) => scanner,
                Err(err) => {
                    let _ = tx.send(WorkerMessage::Error(err.to_string()));
                    let _ = tx.send(WorkerMessage::Finished);
                    return;
                }
            };

            let quarantine = if auto_quarantine {
                QuarantineStore::open(&quarantine_dir).ok()
            } else {
                None
            };

            if target.is_file() {
                scan_and_send(&scanner, &target, quarantine.as_ref(), auto_quarantine, &tx);
            } else if target.is_dir() {
                for entry in WalkDir::new(&target).follow_links(false) {
                    match entry {
                        Ok(entry) if entry.file_type().is_file() => {
                            scan_and_send(
                                &scanner,
                                entry.path(),
                                quarantine.as_ref(),
                                auto_quarantine,
                                &tx,
                            );
                        }
                        Ok(_) => {}
                        Err(err) => {
                            let _ = tx.send(WorkerMessage::Error(err.to_string()));
                        }
                    }
                }
            } else {
                let _ = tx.send(WorkerMessage::Error(format!(
                    "Target does not exist: {}",
                    target.display()
                )));
            }

            let _ = tx.send(WorkerMessage::Finished);
        });
    }

    fn poll_scan(&mut self) {
        let Some(rx) = self.scan_rx.take() else {
            return;
        };

        let mut finished = false;
        while let Ok(message) = rx.try_recv() {
            match message {
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
                WorkerMessage::Finished => {
                    self.scanning = false;
                    self.status_text = format!(
                        "Scan finished: {} files, {} malicious, {} suspicious",
                        self.scanned_count, self.malicious_count, self.suspicious_count
                    );
                    self.refresh_quarantine();
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
        match QuarantineStore::open(&self.quarantine_dir)
            .and_then(|store| store.restore(entry.id))
        {
            Ok(restored) => {
                self.status_text = format!("Restored {}", restored.original_path.display());
                self.refresh_quarantine();
            }
            Err(err) => self.status_text = format!("Restore failed: {err}"),
        }
    }

    fn delete_entry(&mut self, entry: &QuarantineEntry) {
        match QuarantineStore::open(&self.quarantine_dir)
            .and_then(|store| store.delete(entry.id))
        {
            Ok(()) => {
                self.status_text = "Quarantine entry deleted".to_string();
                self.refresh_quarantine();
            }
            Err(err) => self.status_text = format!("Delete failed: {err}"),
        }
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.heading("BDFR Sentinel");
        ui.label("Endpoint Security");
        ui.add_space(18.0);

        for (page, label) in [
            (Page::Dashboard, "Dashboard"),
            (Page::Scan, "Scan"),
            (Page::Quarantine, "Quarantine"),
            (Page::Settings, "Settings"),
        ] {
            if ui.selectable_label(self.page == page, label).clicked() {
                self.page = page;
            }
        }

        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            ui.small(format!("v{}", env!("CARGO_PKG_VERSION")));
            ui.small("Crack/license-bypass: ignored by default");
        });
    }

    fn dashboard(&mut self, ui: &mut egui::Ui) {
        ui.heading("Security dashboard");
        ui.add_space(10.0);

        ui.horizontal_wrapped(|ui| {
            metric(ui, "Scanned", self.scanned_count.to_string());
            metric(ui, "Clean", self.clean_count.to_string());
            metric(ui, "Suspicious", self.suspicious_count.to_string());
            metric(ui, "Malicious", self.malicious_count.to_string());
            metric(ui, "Quarantine", self.quarantine_entries.len().to_string());
        });

        ui.add_space(18.0);
        ui.group(|ui| {
            ui.heading("Protection status");
            ui.label("Core scanner: Ready");
            ui.label("PE analyzer: Ready");
            ui.label("Hash definitions: HDB / HSB");
            ui.label("Encrypted quarantine: AES-256-GCM + DPAPI");
            ui.label("Real-time monitor: Core module available");
        });

        ui.add_space(14.0);
        ui.label(&self.status_text);
    }

    fn scan_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scan");
        ui.add_space(10.0);

        ui.horizontal(|ui| {
            if ui.button("Select file").clicked() {
                self.target = rfd::FileDialog::new().pick_file();
            }
            if ui.button("Select folder").clicked() {
                self.target = rfd::FileDialog::new().pick_folder();
            }
            if ui
                .add_enabled(!self.scanning && self.target.is_some(), egui::Button::new("Start scan"))
                .clicked()
            {
                self.start_scan();
            }
        });

        if let Some(target) = &self.target {
            ui.label(format!("Target: {}", target.display()));
        }

        ui.checkbox(
            &mut self.auto_quarantine,
            "Automatically quarantine malicious verdicts",
        );

        if self.scanning {
            ui.add(egui::ProgressBar::new(0.5).animate(true).text("Scanning..."));
        }

        ui.separator();
        egui::ScrollArea::vertical().show(ui, |ui| {
            for report in self.reports.iter().rev().take(500) {
                let summary = format!(
                    "{:?}  {}  {} bytes",
                    report.verdict.level, report.path, report.metadata.size
                );
                egui::CollapsingHeader::new(summary)
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
                                    ui.small(details);
                                }
                            }
                        }
                    });
            }
        });
    }

    fn quarantine_page(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Quarantine");
            if ui.button("Refresh").clicked() {
                self.refresh_quarantine();
            }
        });

        ui.label(format!("Store: {}", self.quarantine_dir.display()));
        ui.separator();

        let entries = self.quarantine_entries.clone();
        egui::ScrollArea::vertical().show(ui, |ui| {
            for entry in entries {
                ui.group(|ui| {
                    ui.label(entry.original_path.display().to_string());
                    ui.small(format!(
                        "{} bytes • SHA-256 {}",
                        entry.original_size, entry.original_sha256
                    ));
                    ui.small(&entry.reason);
                    ui.horizontal(|ui| {
                        if ui.button("Restore").clicked() {
                            self.restore_entry(&entry);
                        }
                        if ui.button("Delete").clicked() {
                            self.delete_entry(&entry);
                        }
                    });
                });
            }
        });
    }

    fn settings_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.heading("Definition sources");

            ui.horizontal(|ui| {
                if ui.button("Choose HDB").clicked() {
                    self.hdb_path = rfd::FileDialog::new()
                        .add_filter("ClamAV HDB", &["hdb"])
                        .pick_file();
                }
                ui.label(
                    self.hdb_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "Not configured".to_string()),
                );
            });

            ui.horizontal(|ui| {
                if ui.button("Choose HSB").clicked() {
                    self.hsb_path = rfd::FileDialog::new()
                        .add_filter("ClamAV HSB", &["hsb"])
                        .pick_file();
                }
                ui.label(
                    self.hsb_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "Not configured".to_string()),
                );
            });
        });

        ui.add_space(12.0);
        ui.group(|ui| {
            ui.heading("Detection policy");
            ui.label("Malware, ransomware, trojans, backdoors and similar threats remain actionable.");
            ui.label("Crack and license-bypass classifications are ignored by default.");
            ui.label("A cracked file is still detected if it independently matches malware indicators.");
        });
    }
}

impl eframe::App for SentinelApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_scan();
        if self.scanning {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        egui::SidePanel::left("sidebar")
            .resizable(false)
            .default_width(190.0)
            .show(ctx, |ui| self.sidebar(ui));

        egui::TopBottomPanel::bottom("status")
            .resizable(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(&self.status_text);
                    if self.scanning {
                        ui.spinner();
                    }
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| match self.page {
            Page::Dashboard => self.dashboard(ui),
            Page::Scan => self.scan_page(ui),
            Page::Quarantine => self.quarantine_page(ui),
            Page::Settings => self.settings_page(ui),
        });
    }
}

fn metric(ui: &mut egui::Ui, title: &str, value: String) {
    ui.group(|ui| {
        ui.set_min_width(140.0);
        ui.heading(value);
        ui.label(title);
    });
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
