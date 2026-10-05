#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use eframe::egui;
use sentinel_core::{EngineRegistry, FileScanner, ScanReport, ScannerConfig, ThreatLevel};
use sentinel_definitions::{ClamHashDatabase, HashDefinitionEngine};
use sentinel_network::{
    ApplicationRule, FirewallAction, FirewallDirection, FirewallMode, FirewallProtocol,
};
use sentinel_pe::PeAnalyzerEngine;
use sentinel_quarantine::{QuarantineEntry, QuarantineStore};
use serde::{Deserialize, Serialize};
use std::fs;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{ProcessesToUpdate, System};
use walkdir::WalkDir;

const GOOD: egui::Color32 = egui::Color32::from_rgb(60, 170, 75);
const WARN: egui::Color32 = egui::Color32::from_rgb(230, 145, 0);
const BAD: egui::Color32 = egui::Color32::from_rgb(210, 55, 45);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UiSkin {
    name: String,
    mode: ThemeMode,
    accent: [u8; 3],
    background: [u8; 3],
    sidebar: [u8; 3],
    panel: [u8; 3],
    panel_hover: [u8; 3],
    text: [u8; 3],
    #[serde(default = "default_skin_corner_radius")]
    corner_radius: u8,
    #[serde(default)]
    compact: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UiPreferences {
    selected_skin: String,
}

fn default_skin_corner_radius() -> u8 {
    10
}

fn rgb(value: [u8; 3]) -> egui::Color32 {
    egui::Color32::from_rgb(value[0], value[1], value[2])
}

fn built_in_skins() -> Vec<UiSkin> {
    vec![
        UiSkin {
            name: "Sentinel Default".to_string(),
            mode: ThemeMode::Dark,
            accent: [96, 205, 255],
            background: [20, 27, 36],
            sidebar: [16, 23, 32],
            panel: [29, 36, 46],
            panel_hover: [39, 51, 65],
            text: [245, 245, 245],
            corner_radius: 10,
            compact: false,
        },
        UiSkin {
            name: "Obsidian".to_string(),
            mode: ThemeMode::Dark,
            accent: [55, 150, 255],
            background: [10, 13, 18],
            sidebar: [7, 10, 15],
            panel: [20, 25, 33],
            panel_hover: [29, 37, 49],
            text: [238, 243, 250],
            corner_radius: 12,
            compact: false,
        },
        UiSkin {
            name: "Arctic".to_string(),
            mode: ThemeMode::Light,
            accent: [0, 105, 180],
            background: [239, 247, 252],
            sidebar: [225, 239, 248],
            panel: [250, 253, 255],
            panel_hover: [219, 237, 247],
            text: [24, 43, 56],
            corner_radius: 12,
            compact: false,
        },
        UiSkin {
            name: "Graphite".to_string(),
            mode: ThemeMode::Dark,
            accent: [174, 186, 198],
            background: [26, 28, 31],
            sidebar: [20, 22, 25],
            panel: [37, 40, 44],
            panel_hover: [50, 54, 59],
            text: [240, 240, 240],
            corner_radius: 8,
            compact: true,
        },
        UiSkin {
            name: "High Contrast".to_string(),
            mode: ThemeMode::Dark,
            accent: [0, 220, 255],
            background: [0, 0, 0],
            sidebar: [0, 0, 0],
            panel: [18, 18, 18],
            panel_hover: [38, 38, 38],
            text: [255, 255, 255],
            corner_radius: 4,
            compact: true,
        },
    ]
}

fn ui_preferences_path() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("BDFR")
        .join("Sentinel")
        .join("ui-preferences.json")
}

fn user_skin_dir() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("BDFR").join("Sentinel").join("Themes")
}

fn bundled_skin_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|parent| parent.join("themes")))
}

fn load_skin_file(path: &Path) -> Option<UiSkin> {
    let bytes = fs::read(path).ok()?;
    let mut skin = serde_json::from_slice::<UiSkin>(&bytes).ok()?;
    skin.name = skin.name.trim().to_string();
    if skin.name.is_empty() {
        return None;
    }
    skin.corner_radius = skin.corner_radius.clamp(0, 24);
    Some(skin)
}

fn load_available_skins() -> Vec<UiSkin> {
    let mut skins = built_in_skins();

    let mut roots = Vec::new();
    if let Some(path) = bundled_skin_dir() {
        roots.push(path);
    }
    roots.push(user_skin_dir());

    for root in roots {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Some(skin) = load_skin_file(&path) else {
                continue;
            };

            if let Some(existing) = skins.iter_mut().find(|item| item.name == skin.name) {
                *existing = skin;
            } else {
                skins.push(skin);
            }
        }
    }

    skins
}

fn load_ui_preferences() -> UiPreferences {
    fs::read(ui_preferences_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(UiPreferences {
            selected_skin: "Sentinel Default".to_string(),
        })
}

fn save_ui_preferences(selected_skin: &str) {
    let path = ui_preferences_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let preferences = UiPreferences {
        selected_skin: selected_skin.to_string(),
    };
    if let Ok(bytes) = serde_json::to_vec_pretty(&preferences) {
        let _ = fs::write(path, bytes);
    }
}

fn skin_file_name(name: &str) -> String {
    let sanitized = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_ascii_lowercase();
    format!(
        "{}.json",
        if sanitized.is_empty() {
            "custom-skin"
        } else {
            &sanitized
        }
    )
}

#[cfg(windows)]
fn run_elevated_hidden(executable: &Path, args: &[String]) -> Result<()> {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: *mut c_void,
            operation: *const u16,
            file: *const u16,
            parameters: *const u16,
            directory: *const u16,
            show_cmd: i32,
        ) -> isize;
    }

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn quote_arg(value: &str) -> String {
        if value.chars().any(|ch| matches!(ch, ' ' | '\t' | '"')) {
            format!("\"{}\"", value.replace('"', "\\\""))
        } else {
            value.to_string()
        }
    }

    let operation = wide(OsStr::new("runas"));
    let file = wide(executable.as_os_str());
    let parameters_text = args
        .iter()
        .map(|arg| quote_arg(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let parameters = wide(OsStr::new(&parameters_text));

    // SW_HIDE=0. Elevation still presents the single Windows UAC consent dialog,
    // while the elevated console executable itself remains hidden.
    let result = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            operation.as_ptr(),
            file.as_ptr(),
            parameters.as_ptr(),
            ptr::null(),
            0,
        )
    };

    if result <= 32 {
        anyhow::bail!("Windows elevation request failed with code {result}");
    }

    Ok(())
}

#[cfg(not(windows))]
fn run_elevated_hidden(_executable: &Path, _args: &[String]) -> Result<()> {
    anyhow::bail!("elevated service commands are only supported on Windows")
}

fn hidden_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);

    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    command
}

#[cfg(windows)]
struct SingleInstanceGuard(*mut std::ffi::c_void);

#[cfg(windows)]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        #[link(name = "kernel32")]
        extern "system" {
            fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
        }

        if !self.0.is_null() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
fn focus_existing_instance() {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    #[link(name = "user32")]
    extern "system" {
        fn FindWindowW(class_name: *const u16, window_name: *const u16) -> *mut std::ffi::c_void;
        fn ShowWindow(window: *mut std::ffi::c_void, command: i32) -> i32;
        fn SetForegroundWindow(window: *mut std::ffi::c_void) -> i32;
    }

    const SW_RESTORE: i32 = 9;
    let title: Vec<u16> = OsStr::new("BDFR Sentinel")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let window = FindWindowW(ptr::null(), title.as_ptr());
        if !window.is_null() {
            let _ = ShowWindow(window, SW_RESTORE);
            let _ = SetForegroundWindow(window);
        }
    }
}

#[cfg(windows)]
fn acquire_single_instance() -> std::io::Result<Option<SingleInstanceGuard>> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateMutexW(
            security_attributes: *const std::ffi::c_void,
            initial_owner: i32,
            name: *const u16,
        ) -> *mut std::ffi::c_void;
        fn GetLastError() -> u32;
        fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
    }

    const ERROR_ALREADY_EXISTS: u32 = 183;
    let name: Vec<u16> =
        OsStr::new("Local\\BDFR_Sentinel_GUI_91F8715A_71D5_4D49_90A4_7D83F2D7B2D4")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

    unsafe {
        let handle = CreateMutexW(ptr::null(), 0, name.as_ptr());
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        if GetLastError() == ERROR_ALREADY_EXISTS {
            let _ = CloseHandle(handle);
            focus_existing_instance();
            return Ok(None);
        }

        Ok(Some(SingleInstanceGuard(handle)))
    }
}

fn main() -> eframe::Result<()> {
    #[cfg(windows)]
    let _single_instance_guard = match acquire_single_instance() {
        Ok(Some(guard)) => Some(guard),
        Ok(None) => return Ok(()),
        Err(_) => None,
    };

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

fn configure_style(ctx: &egui::Context, skin: &UiSkin) {
    let theme = resolved_theme(ctx, skin.mode);
    ctx.set_theme(theme);

    let mut style = (*ctx.style()).clone();
    let spacing = if skin.compact { 8.0 } else { 12.0 };
    let button_x = if skin.compact { 13.0 } else { 18.0 };
    let button_y = if skin.compact { 8.0 } else { 11.0 };
    style.spacing.item_spacing = egui::vec2(spacing, spacing);
    style.spacing.button_padding = egui::vec2(button_x, button_y);
    style.spacing.indent = if skin.compact { 14.0 } else { 20.0 };
    style.visuals = if theme == egui::Theme::Dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };

    let panel = rgb(skin.panel);
    let panel_hover = rgb(skin.panel_hover);
    let background = rgb(skin.background);
    let sidebar = rgb(skin.sidebar);
    let text = rgb(skin.text);
    let accent = rgb(skin.accent);
    let radius = egui::CornerRadius::same(skin.corner_radius);

    style.visuals.panel_fill = background;
    style.visuals.window_fill = panel;
    style.visuals.extreme_bg_color = sidebar;
    style.visuals.faint_bg_color = panel;
    style.visuals.override_text_color = Some(text);
    style.visuals.widgets.noninteractive.bg_fill = panel;
    style.visuals.widgets.noninteractive.fg_stroke.color = text;
    style.visuals.widgets.noninteractive.corner_radius = radius;
    style.visuals.widgets.inactive.bg_fill = panel;
    style.visuals.widgets.inactive.weak_bg_fill = panel;
    style.visuals.widgets.inactive.fg_stroke.color = text;
    style.visuals.widgets.inactive.corner_radius = radius;
    style.visuals.widgets.hovered.bg_fill = panel_hover;
    style.visuals.widgets.hovered.weak_bg_fill = panel_hover;
    style.visuals.widgets.hovered.fg_stroke.color = text;
    style.visuals.widgets.hovered.corner_radius = radius;
    style.visuals.widgets.active.bg_fill = panel_hover;
    style.visuals.widgets.active.fg_stroke.color = text;
    style.visuals.widgets.active.corner_radius = radius;
    style.visuals.selection.bg_fill = accent;
    style.visuals.hyperlink_color = accent;

    ctx.set_style(style);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Dashboard,
    Scan,
    Quarantine,
    History,
    Settings,
    About,
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

#[derive(Debug, Clone)]
struct ScanDriveOption {
    path: PathBuf,
    selected: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ProtectionSnapshot {
    #[serde(default)]
    protection: String,
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
    #[serde(default)]
    behavior_active: bool,
    #[serde(default)]
    definition_updates_active: bool,
    #[serde(default)]
    yara_active: bool,
    #[serde(default)]
    reputation_active: bool,
    #[serde(default)]
    ransomware_active: bool,
    #[serde(default)]
    scheduled_scan_active: bool,
    #[serde(default)]
    usb_protection_active: bool,
    #[serde(default)]
    network_protection_active: bool,
    #[serde(default)]
    game_mode_active: bool,
    #[serde(default)]
    ransomware_aggressive: bool,
    #[serde(default)]
    firewall_mode: FirewallMode,
}

#[derive(Debug, Clone, Deserialize)]
struct ThreatEventView {
    unix_time: u64,
    source: String,
    action: String,
    path: String,
    details: String,
}

fn default_enabled() -> bool {
    true
}

fn default_scheduled_scan_interval_minutes() -> u64 {
    24 * 60
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    enable_ransomware_shield: bool,
    #[serde(default = "default_enabled")]
    enable_usb_protection: bool,
    #[serde(default = "default_enabled")]
    enable_network_protection: bool,
    #[serde(default)]
    firewall_mode: FirewallMode,
    #[serde(default)]
    firewall_application_rules: Vec<ApplicationRule>,
    #[serde(default)]
    enable_scheduled_scan: bool,
    #[serde(default = "default_enabled")]
    auto_quarantine: bool,
    #[serde(default = "default_scheduled_scan_interval_minutes")]
    scheduled_scan_interval_minutes: u64,
    #[serde(default)]
    enable_game_mode: bool,
    #[serde(default)]
    ransomware_aggressive: bool,
    #[serde(default)]
    ransomware_protected_paths: Vec<PathBuf>,
    #[serde(default)]
    excluded_paths: Vec<PathBuf>,
    #[serde(default)]
    excluded_extensions: Vec<String>,
    #[serde(default)]
    excluded_processes: Vec<String>,
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
            enable_ransomware_shield: true,
            enable_usb_protection: true,
            enable_network_protection: true,
            firewall_mode: FirewallMode::Smart,
            firewall_application_rules: Vec::new(),
            enable_scheduled_scan: false,
            auto_quarantine: true,
            scheduled_scan_interval_minutes: 24 * 60,
            enable_game_mode: false,
            ransomware_aggressive: false,
            ransomware_protected_paths: Vec::new(),
            excluded_paths: Vec::new(),
            excluded_extensions: Vec::new(),
            excluded_processes: Vec::new(),
        }
    }
}

struct SentinelApp {
    page: Page,
    target: Option<PathBuf>,
    available_drives: Vec<ScanDriveOption>,
    scan_target_label: String,
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
    sentinel_cpu_usage: f32,
    sentinel_memory_mb: f64,
    sentinel_process_count: usize,
    skins: Vec<UiSkin>,
    selected_skin_index: usize,
    applied_skin_name: String,
    applied_theme: egui::Theme,
    gauge_order: [GaugeKind; 2],
    dragging_gauge: Option<GaugeKind>,
    service_state: String,
    protection_snapshot: ProtectionSnapshot,
    protection_preferences: ProtectionPreferences,
    protection_preferences_loaded: bool,
    last_service_refresh: Instant,
    show_self_test: bool,
    self_test_output: String,
    threat_events: Vec<ThreatEventView>,
    last_event_refresh: Instant,
    new_excluded_extension: String,
    new_excluded_process: String,
    pending_realtime_target: Option<bool>,
    pending_realtime_started: Option<Instant>,
}

impl SentinelApp {
    fn new(ctx: &egui::Context) -> Self {
        let quarantine_dir = default_quarantine_dir();
        let skins = load_available_skins();
        let ui_preferences = load_ui_preferences();
        let selected_skin_index = skins
            .iter()
            .position(|skin| skin.name == ui_preferences.selected_skin)
            .unwrap_or(0);
        let initial_skin = skins
            .get(selected_skin_index)
            .cloned()
            .unwrap_or_else(|| built_in_skins().remove(0));
        configure_style(ctx, &initial_skin);
        let applied_theme = resolved_theme(ctx, initial_skin.mode);
        let applied_skin_name = initial_skin.name.clone();
        let mut system = System::new_all();
        system.refresh_cpu_usage();
        system.refresh_memory();

        let mut app = Self {
            page: Page::Dashboard,
            target: None,
            available_drives: enumerate_scan_drives(),
            scan_target_label: "Unknown".to_string(),
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
            sentinel_cpu_usage: 0.0,
            sentinel_memory_mb: 0.0,
            sentinel_process_count: 0,
            skins,
            selected_skin_index,
            applied_skin_name,
            applied_theme,
            gauge_order: [GaugeKind::Cpu, GaugeKind::Memory],
            dragging_gauge: None,
            service_state: "Checking…".to_string(),
            protection_snapshot: ProtectionSnapshot::default(),
            protection_preferences: ProtectionPreferences::default(),
            protection_preferences_loaded: false,
            last_service_refresh: Instant::now() - Duration::from_secs(10),
            show_self_test: false,
            self_test_output: String::new(),
            threat_events: Vec::new(),
            last_event_refresh: Instant::now() - Duration::from_secs(10),
            new_excluded_extension: String::new(),
            new_excluded_process: String::new(),
            pending_realtime_target: None,
            pending_realtime_started: None,
        };
        app.refresh_quarantine();
        app.refresh_metrics();
        app.refresh_service_state();
        app.load_service_preferences();
        app.refresh_threat_events();
        app
    }

    fn refresh_theme(&mut self, ctx: &egui::Context) {
        let Some(skin) = self.skins.get(self.selected_skin_index) else {
            return;
        };
        let resolved = resolved_theme(ctx, skin.mode);
        if resolved != self.applied_theme || skin.name != self.applied_skin_name {
            configure_style(ctx, skin);
            self.applied_theme = resolved;
            self.applied_skin_name = skin.name.clone();
            save_ui_preferences(&skin.name);
        }
    }

    fn select_skin_by_name(&mut self, name: &str) {
        if let Some(index) = self.skins.iter().position(|skin| skin.name == name) {
            self.selected_skin_index = index;
        }
    }

    fn import_skin(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("BDFR Sentinel Skin", &["json"])
            .pick_file()
        else {
            return;
        };

        let Some(skin) = load_skin_file(&path) else {
            self.status_text = "The selected skin file is not a valid Sentinel skin.".to_string();
            return;
        };

        let dir = user_skin_dir();
        if fs::create_dir_all(&dir).is_err() {
            self.status_text = "Could not create the user theme directory.".to_string();
            return;
        }

        let destination = dir.join(skin_file_name(&skin.name));
        let Ok(bytes) = serde_json::to_vec_pretty(&skin) else {
            self.status_text = "Could not serialize the imported skin.".to_string();
            return;
        };
        if let Err(err) = fs::write(&destination, bytes) {
            self.status_text = format!("Could not save imported skin: {err}");
            return;
        }

        if let Some(existing) = self.skins.iter_mut().find(|item| item.name == skin.name) {
            *existing = skin.clone();
        } else {
            self.skins.push(skin.clone());
        }
        self.select_skin_by_name(&skin.name);
        self.status_text = format!("Imported skin: {}", skin.name);
    }

    fn refresh_service_state(&mut self) {
        if self.last_service_refresh.elapsed() < Duration::from_secs(2) {
            return;
        }

        let exe = service_executable_path();
        self.protection_snapshot = fs::read(service_status_path())
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ProtectionSnapshot>(&bytes).ok())
            .unwrap_or_default();

        self.service_state = if !exe.is_file() {
            "Service binary missing".to_string()
        } else if self
            .protection_snapshot
            .protection
            .eq_ignore_ascii_case("running")
        {
            "Running".to_string()
        } else if self
            .protection_snapshot
            .protection
            .eq_ignore_ascii_case("stopped")
        {
            "Stopped".to_string()
        } else if service_status_path().is_file() {
            "Unknown".to_string()
        } else {
            "Not installed".to_string()
        };

        if let Some(target) = self.pending_realtime_target {
            let reached_target = self.service_state.contains("Running")
                && self.protection_snapshot.realtime_file_monitor == target;

            if reached_target {
                self.pending_realtime_target = None;
                self.pending_realtime_started = None;
                self.protection_preferences.enable_realtime_file_monitor = target;
                self.status_text = if target {
                    "Real-time protection enabled.".to_string()
                } else {
                    "Real-time protection disabled; protection service remains running.".to_string()
                };
            } else if self
                .pending_realtime_started
                .is_some_and(|started| started.elapsed() > Duration::from_secs(20))
            {
                self.pending_realtime_target = None;
                self.pending_realtime_started = None;
                self.status_text =
                    "Real-time protection change timed out; refresh status and try again."
                        .to_string();
            }
        }

        self.last_service_refresh = Instant::now();
    }

    fn set_realtime_protection(&mut self, enabled: bool) {
        let exe = service_executable_path();
        if !exe.is_file() {
            self.status_text = "Protection service executable was not found.".to_string();
            return;
        }

        let args = vec![
            "config".to_string(),
            "apply-restart".to_string(),
            format!("realtime_file_monitor={enabled}"),
        ];

        match run_elevated_hidden(&exe, &args) {
            Ok(()) => {
                self.pending_realtime_target = Some(enabled);
                self.pending_realtime_started = Some(Instant::now());
                self.last_service_refresh = Instant::now() - Duration::from_secs(10);
                self.status_text = if enabled {
                    "Enabling real-time protection…".to_string()
                } else {
                    "Disabling real-time protection…".to_string()
                };
            }
            Err(err) => {
                self.status_text = format!("Could not change real-time protection: {err}");
            }
        }
    }

    fn invoke_service_command(&mut self, command: &str) {
        let exe = service_executable_path();
        if !exe.is_file() {
            self.status_text = "Protection service executable was not found.".to_string();
            return;
        }

        match run_elevated_hidden(&exe, &[command.to_string()]) {
            Ok(()) => {
                self.last_service_refresh = Instant::now() - Duration::from_secs(10);
                self.status_text = format!("Protection service command requested: {command}");
            }
            Err(err) => {
                self.status_text = format!("Could not run protection service command: {err}");
            }
        }
    }

    fn load_service_preferences(&mut self) {
        if let Ok(bytes) = fs::read(service_config_path()) {
            if let Ok(preferences) = serde_json::from_slice::<ProtectionPreferences>(&bytes) {
                self.protection_preferences = preferences;
                self.protection_preferences_loaded = true;
            }
        }
    }

    fn apply_protection_preferences(&mut self) {
        let exe = service_executable_path();
        if !exe.is_file() {
            self.status_text = "Protection service executable was not found.".to_string();
            return;
        }

        let payload_json = match serde_json::to_vec(&self.protection_preferences) {
            Ok(payload) => payload,
            Err(err) => {
                self.status_text = format!("Could not serialize protection settings: {err}");
                return;
            }
        };
        let payload = BASE64.encode(payload_json);
        let args = vec!["config".to_string(), "apply-ui".to_string(), payload];

        match run_elevated_hidden(&exe, &args) {
            Ok(()) => {
                self.status_text =
                    "Protection settings submitted; waiting for service restart…".to_string();
                self.last_service_refresh = Instant::now() - Duration::from_secs(10);
            }
            Err(err) => {
                self.status_text = format!("Could not apply protection settings: {err}");
            }
        }
    }

    fn run_protection_self_test(&mut self) {
        let exe = service_executable_path();
        if !exe.is_file() {
            self.status_text = "Protection service executable was not found.".to_string();
            return;
        }

        self.status_text = "Running protection self-test…".to_string();

        match hidden_command(&exe).arg("self-test").output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

                self.self_test_output = if stdout.is_empty() {
                    stderr
                } else if stderr.is_empty() {
                    stdout
                } else {
                    format!("{stdout}\n\n{stderr}")
                };

                if output.status.success() {
                    self.status_text = "Protection self-test passed.".to_string();
                } else {
                    self.status_text = "Protection self-test failed.".to_string();
                }

                self.show_self_test = true;
            }
            Err(err) => {
                self.self_test_output = format!("Could not run self-test: {err}");
                self.status_text = "Protection self-test could not start.".to_string();
                self.show_self_test = true;
            }
        }
    }

    fn refresh_threat_events(&mut self) {
        if self.last_event_refresh.elapsed() < Duration::from_secs(2) {
            return;
        }

        let path = threat_events_path();
        let mut events = Vec::new();

        if let Ok(text) = fs::read_to_string(path) {
            for line in text.lines().rev().take(500) {
                if let Ok(event) = serde_json::from_str::<ThreatEventView>(line) {
                    events.push(event);
                }
            }
        }

        self.threat_events = events;
        self.last_event_refresh = Instant::now();
    }

    fn refresh_metrics(&mut self) {
        let refresh_interval = if self.protection_snapshot.game_mode_active {
            Duration::from_secs(4)
        } else {
            Duration::from_millis(900)
        };
        if self.last_metrics_refresh.elapsed() < refresh_interval {
            return;
        }

        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        self.system.refresh_processes(ProcessesToUpdate::All, true);

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

        let mut sentinel_cpu = 0.0_f32;
        let mut sentinel_memory = 0_u64;
        let mut sentinel_processes = 0_usize;

        for process in self.system.processes().values() {
            let name = process.name().to_string_lossy().to_ascii_lowercase();
            if name.starts_with("bdfr-sentinel") {
                sentinel_cpu += process.cpu_usage();
                sentinel_memory = sentinel_memory.saturating_add(process.memory());
                sentinel_processes += 1;
            }
        }

        self.sentinel_cpu_usage = sentinel_cpu.max(0.0);
        self.sentinel_memory_mb = sentinel_memory as f64 / 1024.0 / 1024.0;
        self.sentinel_process_count = sentinel_processes;
        self.last_metrics_refresh = Instant::now();
    }

    fn refresh_scan_drives(&mut self) {
        let selected: Vec<PathBuf> = self
            .available_drives
            .iter()
            .filter(|drive| drive.selected)
            .map(|drive| drive.path.clone())
            .collect();
        self.available_drives = enumerate_scan_drives();
        for drive in &mut self.available_drives {
            drive.selected = selected.iter().any(|path| path == &drive.path);
        }
    }

    fn set_game_mode(&mut self, enabled: bool) {
        let exe = service_executable_path();
        if !exe.is_file() {
            self.status_text = "Protection service executable was not found.".to_string();
            return;
        }

        let args = vec![
            "config".to_string(),
            "apply-restart".to_string(),
            format!("game_mode={enabled}"),
        ];

        match run_elevated_hidden(&exe, &args) {
            Ok(()) => {
                self.protection_preferences.enable_game_mode = enabled;
                self.last_service_refresh = Instant::now() - Duration::from_secs(10);
                self.status_text = if enabled {
                    "Game Mode requested — background protection is being reduced.".to_string()
                } else {
                    "Game Mode disabled — full background protection is being restored.".to_string()
                };
            }
            Err(err) => {
                self.status_text = format!("Could not change Game Mode: {err}");
            }
        }
    }

    fn start_scan(&mut self) {
        let mut targets: Vec<PathBuf> = self
            .available_drives
            .iter()
            .filter(|drive| drive.selected)
            .map(|drive| drive.path.clone())
            .collect();
        if let Some(target) = self.target.clone() {
            targets.push(target);
        }
        targets.sort();
        targets.dedup();

        if targets.is_empty() {
            self.status_text =
                "Select a file, folder, or at least one system drive first".to_string();
            return;
        }

        self.scan_target_label = if targets.len() == 1 {
            targets[0].display().to_string()
        } else {
            format!("{} selected targets", targets.len())
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
        self.status_text = format!("Preparing scan for {}", self.scan_target_label);

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

            let mut files = Vec::new();
            for target in &targets {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                files.extend(collect_scan_targets(target, &cancel));
            }
            files.sort();
            files.dedup();

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

                    let target = self.scan_target_label.clone();

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

    fn nav_button(&mut self, ui: &mut egui::Ui, page: Page, label: &str) {
        let selected = self.page == page;
        let desired = egui::vec2(210.0, 50.0);
        let (rect, response) = ui.allocate_exact_size(desired, egui::Sense::click());

        let fill = if selected {
            ui.visuals().widgets.active.bg_fill
        } else if response.hovered() {
            ui.visuals().widgets.hovered.bg_fill
        } else {
            egui::Color32::TRANSPARENT
        };

        ui.painter().rect_filled(rect, 8.0, fill);

        if selected {
            ui.painter().rect_filled(
                egui::Rect::from_min_max(
                    egui::pos2(rect.left() + 1.0, rect.top() + 8.0),
                    egui::pos2(rect.left() + 4.0, rect.bottom() - 8.0),
                ),
                2.0,
                ui.visuals().hyperlink_color,
            );
        }

        let icon_rect = egui::Rect::from_center_size(
            egui::pos2(rect.left() + 24.0, rect.center().y),
            egui::vec2(22.0, 22.0),
        );
        draw_page_icon(
            ui.painter(),
            page,
            icon_rect,
            if selected {
                ui.visuals().hyperlink_color
            } else {
                ui.visuals().text_color()
            },
        );

        ui.painter().text(
            egui::pos2(rect.left() + 46.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            label,
            egui::FontId::proportional(17.0),
            ui.visuals().text_color(),
        );

        if response.clicked() {
            self.page = page;
        }

        response.on_hover_cursor(egui::CursorIcon::PointingHand);
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

        self.nav_button(ui, Page::Dashboard, "Dashboard");
        self.nav_button(ui, Page::Scan, "Scan");
        self.nav_button(ui, Page::Quarantine, "Quarantine");
        self.nav_button(ui, Page::History, "History");
        self.nav_button(ui, Page::Settings, "Settings");
        self.nav_button(ui, Page::About, "About");

        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION")))
                    .size(11.0)
                    .color(ui.visuals().weak_text_color()),
            );
            ui.label(
                egui::RichText::new("BDFR Sentinel • Endpoint Security")
                    .size(11.0)
                    .color(ui.visuals().weak_text_color()),
            );
        });
    }

    fn dashboard(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            Page::Dashboard,
            "Security dashboard",
            "A quick view of protection, scan activity and system load.",
        );

        let service_running = self.service_state.contains("Running");
        let realtime_running = service_running && self.protection_snapshot.realtime_file_monitor;
        let realtime_changing = self.pending_realtime_target.is_some();

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
                            egui::RichText::new(if realtime_changing {
                                "Real-time protection is changing"
                            } else if realtime_running {
                                "Real-time protection is on"
                            } else if service_running {
                                "Real-time protection is off"
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
                        if realtime_changing {
                            ui.spinner();
                            ui.label(
                                egui::RichText::new("Changing…")
                                    .size(12.0)
                                    .color(ui.visuals().weak_text_color()),
                            );
                        } else if service_running {
                            if realtime_running {
                                if fluent_button(ui, "Turn off", true).clicked() {
                                    self.set_realtime_protection(false);
                                }
                            } else if fluent_button(ui, "Turn on", false).clicked() {
                                self.set_realtime_protection(true);
                            }
                        } else {
                            if fluent_button(ui, "Start service", false).clicked() {
                                self.invoke_service_command("start");
                            }
                            if self.service_state.contains("Not installed")
                                && fluent_button(ui, "Install", false).clicked()
                            {
                                self.invoke_service_command("install");
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

        ui.columns(2, |columns| {
            settings_card(&mut columns[0], "Game Mode", |ui| {
                let active = self.protection_snapshot.game_mode_active;
                ui.label(
                    egui::RichText::new(if active {
                        "Gaming optimization is active"
                    } else {
                        "Full protection performance profile"
                    })
                    .strong()
                    .color(if active { GOOD } else { ui.visuals().text_color() }),
                );
                ui.label(
                    egui::RichText::new(
                        "Keeps essential real-time, firewall and ransomware defenses while reducing background work.",
                    )
                    .size(11.0)
                    .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(6.0);
                if fluent_button(
                    ui,
                    if active { "Disable Game Mode" } else { "Enable Game Mode" },
                    false,
                )
                .clicked()
                {
                    self.set_game_mode(!active);
                }
            });

            settings_card(&mut columns[1], "Advanced Anti-Ransomware", |ui| {
                let active = self.protection_snapshot.ransomware_active;
                ui.label(
                    egui::RichText::new(if active {
                        "Protected"
                    } else {
                        "Protection disabled"
                    })
                    .strong()
                    .color(if active { GOOD } else { WARN }),
                );
                ui.label(format!(
                    "{} protected folder(s) • {} heuristics",
                    self.protection_preferences.ransomware_protected_paths.len(),
                    if self.protection_snapshot.ransomware_aggressive {
                        "Aggressive"
                    } else {
                        "Balanced"
                    }
                ));
                ui.label(
                    egui::RichText::new(
                        "Monitors rapid create/modify/delete bursts across protected folders and scores ransomware-like behavior.",
                    )
                    .size(11.0)
                    .color(ui.visuals().weak_text_color()),
                );
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
                            format!("{:.0}% total system", self.cpu_usage),
                            format!(
                                "Sentinel: {:.1}% CPU • {} process{}",
                                self.sentinel_cpu_usage,
                                self.sentinel_process_count,
                                if self.sentinel_process_count == 1 {
                                    ""
                                } else {
                                    "es"
                                }
                            ),
                            accent,
                        )
                    }
                    GaugeKind::Memory => resource_card(
                        &mut columns[index],
                        "Memory",
                        self.memory_usage,
                        format!(
                            "{:.1} / {:.1} GB system",
                            self.memory_used_gb, self.memory_total_gb
                        ),
                        format!("Sentinel: {:.1} MB RAM", self.sentinel_memory_mb),
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
            status_row(
                ui,
                "Behavior correlation",
                component_label(self.protection_snapshot.behavior_active),
                component_color(self.protection_snapshot.behavior_active),
            );
            status_row(
                ui,
                "Definition updater",
                component_label(self.protection_snapshot.definition_updates_active),
                component_color(self.protection_snapshot.definition_updates_active),
            );
            status_row(
                ui,
                "YARA-X rules",
                component_label(self.protection_snapshot.yara_active),
                component_color(self.protection_snapshot.yara_active),
            );
            status_row(
                ui,
                "Local reputation",
                component_label(self.protection_snapshot.reputation_active),
                component_color(self.protection_snapshot.reputation_active),
            );
            status_row(
                ui,
                "Ransomware Shield",
                component_label(self.protection_snapshot.ransomware_active),
                component_color(self.protection_snapshot.ransomware_active),
            );
            status_row(
                ui,
                "Scheduled scan",
                component_label(self.protection_snapshot.scheduled_scan_active),
                component_color(self.protection_snapshot.scheduled_scan_active),
            );
            status_row(
                ui,
                "USB protection",
                component_label(self.protection_snapshot.usb_protection_active),
                component_color(self.protection_snapshot.usb_protection_active),
            );
            let firewall_status = if self.protection_snapshot.network_protection_active {
                match self.protection_snapshot.firewall_mode {
                    FirewallMode::Smart => "Active • Smart",
                    FirewallMode::Whitelist => "Active • Whitelist",
                    FirewallMode::BlockAll => "Active • Block all",
                    FirewallMode::AllowAll => "Active • Allow all",
                }
            } else {
                "Inactive"
            };
            status_row(
                ui,
                "Kernel WFP firewall",
                firewall_status,
                component_color(self.protection_snapshot.network_protection_active),
            );

            ui.add_space(8.0);
            if fluent_button(ui, "Run protection self-test", false).clicked() {
                self.run_protection_self_test();
            }
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
            Page::Scan,
            "Scan center",
            "Scan a custom target or select one or more system drives for a broader inspection.",
        );

        settings_card(ui, "Custom target", |ui| {
            ui.horizontal_wrapped(|ui| {
                if fluent_button(ui, "Choose file", false).clicked() {
                    self.target = rfd::FileDialog::new().pick_file();
                }
                if fluent_button(ui, "Choose folder", false).clicked() {
                    self.target = rfd::FileDialog::new().pick_folder();
                }
                if self.target.is_some()
                    && fluent_button(ui, "Clear custom target", false).clicked()
                {
                    self.target = None;
                }
            });

            if let Some(target) = &self.target {
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(format!("Selected: {}", target.display()))
                        .strong()
                        .color(ui.visuals().hyperlink_color),
                );
            } else {
                ui.label(
                    egui::RichText::new("No custom file or folder selected.")
                        .color(ui.visuals().weak_text_color()),
                );
            }
        });

        ui.add_space(12.0);
        settings_card(ui, "System drives", |ui| {
            ui.horizontal_wrapped(|ui| {
                if fluent_button(ui, "Refresh drives", false).clicked() {
                    self.refresh_scan_drives();
                }
                if fluent_button(ui, "Select all", false).clicked() {
                    for drive in &mut self.available_drives {
                        drive.selected = true;
                    }
                }
                if fluent_button(ui, "Clear", false).clicked() {
                    for drive in &mut self.available_drives {
                        drive.selected = false;
                    }
                }
            });
            ui.add_space(8.0);

            if self.available_drives.is_empty() {
                ui.label(egui::RichText::new("No mounted drive roots were detected.").color(WARN));
            } else {
                ui.horizontal_wrapped(|ui| {
                    for drive in &mut self.available_drives {
                        let label = format!("{}  Drive", drive.path.display());
                        ui.add(
                            egui::Checkbox::new(&mut drive.selected, label).indeterminate(false),
                        );
                        ui.add_space(8.0);
                    }
                });
            }

            ui.label(
                egui::RichText::new(
                    "Selected drives are scanned together with the custom target. Duplicate files are de-duplicated before scanning.",
                )
                .size(11.0)
                .color(ui.visuals().weak_text_color()),
            );
        });

        ui.add_space(12.0);
        settings_card(ui, "Scan controls", |ui| {
            let has_target =
                self.target.is_some() || self.available_drives.iter().any(|drive| drive.selected);

            ui.horizontal_wrapped(|ui| {
                if self.scanning {
                    if fluent_button(ui, "Cancel scan", true).clicked() {
                        self.cancel_scan();
                    }
                } else if ui
                    .add_enabled(
                        has_target,
                        egui::Button::new(egui::RichText::new("Start scan").size(15.0).strong())
                            .fill(ui.visuals().hyperlink_color)
                            .corner_radius(9.0)
                            .min_size(egui::vec2(140.0, 44.0)),
                    )
                    .clicked()
                {
                    self.start_scan();
                }

                ui.checkbox(
                    &mut self.auto_quarantine,
                    "Automatically quarantine confirmed malicious verdicts",
                );
            });

            let drive_count = self
                .available_drives
                .iter()
                .filter(|drive| drive.selected)
                .count();
            ui.label(
                egui::RichText::new(format!(
                    "{} drive target(s) selected{}",
                    drive_count,
                    if self.target.is_some() {
                        " + custom target"
                    } else {
                        ""
                    }
                ))
                .size(11.0)
                .color(ui.visuals().weak_text_color()),
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
            Page::Quarantine,
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

    fn history_page(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            Page::History,
            "Threat history",
            "Review blocks, quarantines and protection events recorded by the service.",
        );

        ui.horizontal(|ui| {
            ui.label(format!("{} recent event(s)", self.threat_events.len()));
            if fluent_button(ui, "Refresh", false).clicked() {
                self.last_event_refresh = Instant::now() - Duration::from_secs(10);
                self.refresh_threat_events();
            }
        });

        ui.add_space(12.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            if self.threat_events.is_empty() {
                settings_card(ui, "No recorded threat events", |ui| {
                    ui.label(
                        egui::RichText::new(
                            "Protection events will appear here when Sentinel blocks or quarantines a threat.",
                        )
                        .color(ui.visuals().weak_text_color()),
                    );
                });
                return;
            }

            for event in &self.threat_events {
                egui::Frame::new()
                    .fill(ui.visuals().faint_bg_color)
                    .corner_radius(10.0)
                    .inner_margin(16.0)
                    .outer_margin(egui::Margin::symmetric(0, 5))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(event.action.to_ascii_uppercase())
                                    .strong()
                                    .color(if event.action.eq_ignore_ascii_case("block") {
                                        BAD
                                    } else {
                                        WARN
                                    }),
                            );
                            ui.label(
                                egui::RichText::new(format!("via {}", event.source))
                                    .color(ui.visuals().hyperlink_color),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        egui::RichText::new(format!("Unix {}", event.unix_time))
                                            .size(11.0)
                                            .color(ui.visuals().weak_text_color()),
                                    );
                                },
                            );
                        });

                        ui.label(egui::RichText::new(&event.path).strong());
                        if !event.details.is_empty() {
                            ui.label(
                                egui::RichText::new(&event.details)
                                    .size(11.0)
                                    .color(ui.visuals().weak_text_color()),
                            );
                        }
                    });
            }
        });
    }

    fn settings_page(&mut self, ui: &mut egui::Ui) {
        let hdb_current = self.hdb_path.clone();
        let hsb_current = self.hsb_path.clone();

        page_header(
            ui,
            Page::Settings,
            "Settings",
            "Customize Sentinel appearance, protection engines and detection behavior.",
        );

        settings_card(ui, "Appearance & skins", |ui| {
            ui.label(
                egui::RichText::new(
                    "Switch the entire Sentinel presentation layer instantly. Imported JSON skins are stored per user.",
                )
                .color(ui.visuals().weak_text_color()),
            );
            ui.add_space(8.0);

            let current_name = self
                .skins
                .get(self.selected_skin_index)
                .map(|skin| skin.name.clone())
                .unwrap_or_else(|| "Sentinel Default".to_string());
            let mut selected_name = current_name.clone();

            ui.horizontal_wrapped(|ui| {
                ui.label("Skin:");
                egui::ComboBox::from_id_salt("skin_picker")
                    .selected_text(&current_name)
                    .width(210.0)
                    .show_ui(ui, |ui| {
                        for skin in &self.skins {
                            ui.selectable_value(&mut selected_name, skin.name.clone(), &skin.name);
                        }
                    });

                if fluent_button(ui, "Import skin…", false).clicked() {
                    self.import_skin();
                }
                if fluent_button(ui, "Reset default", false).clicked() {
                    selected_name = "Sentinel Default".to_string();
                }
            });

            if selected_name != current_name {
                self.select_skin_by_name(&selected_name);
            }

            if let Some(skin) = self.skins.get(self.selected_skin_index) {
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    for (label, color) in [
                        ("Accent", skin.accent),
                        ("Background", skin.background),
                        ("Panel", skin.panel),
                        ("Hover", skin.panel_hover),
                    ] {
                        egui::Frame::new()
                            .fill(rgb(color))
                            .stroke(egui::Stroke::new(
                                1.0_f32,
                                ui.visuals().widgets.noninteractive.bg_stroke.color,
                            ))
                            .corner_radius(6.0)
                            .inner_margin(egui::Margin::symmetric(8, 5))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(label).size(11.0));
                            });
                    }
                });

                ui.label(
                    egui::RichText::new(format!(
                        "{} palette • {} density • {} px control radius",
                        skin.mode.label(),
                        if skin.compact {
                            "Compact"
                        } else {
                            "Comfortable"
                        },
                        skin.corner_radius
                    ))
                    .size(11.0)
                    .color(ui.visuals().weak_text_color()),
                );
            }
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
                &mut self.protection_preferences.enable_ransomware_shield,
                "Advanced Anti-Ransomware / mass file-change protection",
            );
            ui.checkbox(
                &mut self.protection_preferences.ransomware_aggressive,
                "Aggressive ransomware heuristics (faster response, higher sensitivity)",
            );
            ui.checkbox(
                &mut self.protection_preferences.enable_game_mode,
                "Game Mode — minimize Sentinel background CPU activity while gaming",
            );
            ui.label(
                egui::RichText::new(
                    "Game Mode keeps real-time file protection, WFP firewall and Anti-Ransomware active while pausing heavier telemetry, updates and scheduled scans.",
                )
                .size(11.0)
                .color(ui.visuals().weak_text_color()),
            );

            ui.add_space(8.0);
            ui.label(egui::RichText::new("Ransomware protected folders").strong());
            ui.horizontal_wrapped(|ui| {
                if fluent_button(ui, "Add protected folder", false).clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        if !self
                            .protection_preferences
                            .ransomware_protected_paths
                            .iter()
                            .any(|item| item == &path)
                        {
                            self.protection_preferences
                                .ransomware_protected_paths
                                .push(path);
                        }
                    }
                }
            });
            let mut remove_ransomware_path = None;
            for (index, path) in self
                .protection_preferences
                .ransomware_protected_paths
                .iter()
                .enumerate()
            {
                ui.horizontal(|ui| {
                    ui.label(path.display().to_string());
                    if ui.small_button("Remove").clicked() {
                        remove_ransomware_path = Some(index);
                    }
                });
            }
            if let Some(index) = remove_ransomware_path {
                self.protection_preferences
                    .ransomware_protected_paths
                    .remove(index);
            }

            ui.checkbox(
                &mut self.protection_preferences.enable_usb_protection,
                "USB / removable drive quick protection",
            );
            ui.checkbox(
                &mut self.protection_preferences.enable_network_protection,
                "Kernel network firewall (Windows Filtering Platform)",
            );
            ui.horizontal(|ui| {
                ui.label("Firewall mode:");
                egui::ComboBox::from_id_salt("firewall_mode")
                    .selected_text(match self.protection_preferences.firewall_mode {
                        FirewallMode::Smart => "Smart",
                        FirewallMode::Whitelist => "Whitelist / TinyWall-style",
                        FirewallMode::BlockAll => "Block all",
                        FirewallMode::AllowAll => "Allow all",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.protection_preferences.firewall_mode,
                            FirewallMode::Smart,
                            "Smart",
                        );
                        ui.selectable_value(
                            &mut self.protection_preferences.firewall_mode,
                            FirewallMode::Whitelist,
                            "Whitelist / TinyWall-style",
                        );
                        ui.selectable_value(
                            &mut self.protection_preferences.firewall_mode,
                            FirewallMode::BlockAll,
                            "Block all",
                        );
                        ui.selectable_value(
                            &mut self.protection_preferences.firewall_mode,
                            FirewallMode::AllowAll,
                            "Allow all",
                        );
                    });
            });
            ui.label(
                egui::RichText::new(
                    "Smart blocks known-bad IP/CIDR targets and explicit app rules. Whitelist blocks connections unless an app rule permits them.",
                )
                .size(11.0)
                .color(ui.visuals().weak_text_color()),
            );

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if fluent_button(ui, "Allow application", false).clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Executable", &["exe"])
                        .pick_file()
                    {
                        if !self
                            .protection_preferences
                            .firewall_application_rules
                            .iter()
                            .any(|rule| rule.application == path)
                        {
                            self.protection_preferences.firewall_application_rules.push(
                                ApplicationRule {
                                    application: path,
                                    direction: FirewallDirection::Outbound,
                                    action: FirewallAction::Allow,
                                    protocol: FirewallProtocol::Any,
                                    remote_ports: Vec::new(),
                                    enabled: true,
                                },
                            );
                        }
                    }
                }

                if fluent_button(ui, "Block application", true).clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Executable", &["exe"])
                        .pick_file()
                    {
                        if !self
                            .protection_preferences
                            .firewall_application_rules
                            .iter()
                            .any(|rule| rule.application == path)
                        {
                            self.protection_preferences.firewall_application_rules.push(
                                ApplicationRule {
                                    application: path,
                                    direction: FirewallDirection::Both,
                                    action: FirewallAction::Block,
                                    protocol: FirewallProtocol::Any,
                                    remote_ports: Vec::new(),
                                    enabled: true,
                                },
                            );
                        }
                    }
                }
            });

            let mut remove_rule = None;
            for (index, rule) in self
                .protection_preferences
                .firewall_application_rules
                .iter_mut()
                .enumerate()
            {
                egui::Frame::new()
                    .fill(ui.visuals().faint_bg_color)
                    .corner_radius(8.0)
                    .inner_margin(10.0)
                    .outer_margin(egui::Margin::symmetric(0, 4))
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.checkbox(&mut rule.enabled, "");
                            ui.label(
                                egui::RichText::new(
                                    rule.application
                                        .file_name()
                                        .and_then(|name| name.to_str())
                                        .unwrap_or("application"),
                                )
                                .strong(),
                            );

                            egui::ComboBox::from_id_salt(("fw_action", index))
                                .selected_text(match rule.action {
                                    FirewallAction::Allow => "Allow",
                                    FirewallAction::Block => "Block",
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut rule.action,
                                        FirewallAction::Allow,
                                        "Allow",
                                    );
                                    ui.selectable_value(
                                        &mut rule.action,
                                        FirewallAction::Block,
                                        "Block",
                                    );
                                });

                            egui::ComboBox::from_id_salt(("fw_direction", index))
                                .selected_text(match rule.direction {
                                    FirewallDirection::Outbound => "Outbound",
                                    FirewallDirection::Inbound => "Inbound",
                                    FirewallDirection::Both => "Both",
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut rule.direction,
                                        FirewallDirection::Outbound,
                                        "Outbound",
                                    );
                                    ui.selectable_value(
                                        &mut rule.direction,
                                        FirewallDirection::Inbound,
                                        "Inbound",
                                    );
                                    ui.selectable_value(
                                        &mut rule.direction,
                                        FirewallDirection::Both,
                                        "Both",
                                    );
                                });

                            egui::ComboBox::from_id_salt(("fw_protocol", index))
                                .selected_text(match rule.protocol {
                                    FirewallProtocol::Any => "Any protocol",
                                    FirewallProtocol::Tcp => "TCP",
                                    FirewallProtocol::Udp => "UDP",
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut rule.protocol,
                                        FirewallProtocol::Any,
                                        "Any protocol",
                                    );
                                    ui.selectable_value(
                                        &mut rule.protocol,
                                        FirewallProtocol::Tcp,
                                        "TCP",
                                    );
                                    ui.selectable_value(
                                        &mut rule.protocol,
                                        FirewallProtocol::Udp,
                                        "UDP",
                                    );
                                });

                            if ui.small_button("Remove").clicked() {
                                remove_rule = Some(index);
                            }
                        });
                        ui.label(
                            egui::RichText::new(rule.application.display().to_string())
                                .size(10.0)
                                .color(ui.visuals().weak_text_color()),
                        );
                    });
            }

            if let Some(index) = remove_rule {
                self.protection_preferences
                    .firewall_application_rules
                    .remove(index);
            }
            ui.checkbox(
                &mut self.protection_preferences.enable_scheduled_scan,
                "Scheduled background scan",
            );
            ui.horizontal(|ui| {
                ui.label("Scheduled scan interval:");
                ui.add(
                    egui::DragValue::new(
                        &mut self.protection_preferences.scheduled_scan_interval_minutes,
                    )
                    .range(15..=10080)
                    .suffix(" min"),
                );
            });
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

        settings_card(ui, "Exclusions", |ui| {
            ui.label(
                egui::RichText::new(
                    "Excluded paths, extensions and processes are ignored by real-time and behavior protection.",
                )
                .color(ui.visuals().weak_text_color()),
            );
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                if fluent_button(ui, "Add folder exclusion", false).clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        if !self
                            .protection_preferences
                            .excluded_paths
                            .iter()
                            .any(|item| item == &path)
                        {
                            self.protection_preferences.excluded_paths.push(path);
                        }
                    }
                }
            });

            let mut remove_path = None;
            for (index, path) in self
                .protection_preferences
                .excluded_paths
                .iter()
                .enumerate()
            {
                ui.horizontal(|ui| {
                    ui.label(path.display().to_string());
                    if ui.small_button("Remove").clicked() {
                        remove_path = Some(index);
                    }
                });
            }
            if let Some(index) = remove_path {
                self.protection_preferences.excluded_paths.remove(index);
            }

            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Extension:");
                ui.text_edit_singleline(&mut self.new_excluded_extension);
                if ui.button("Add").clicked() {
                    let ext = self
                        .new_excluded_extension
                        .trim()
                        .trim_start_matches('.')
                        .to_ascii_lowercase();
                    if !ext.is_empty()
                        && !self
                            .protection_preferences
                            .excluded_extensions
                            .iter()
                            .any(|item| item.eq_ignore_ascii_case(&ext))
                    {
                        self.protection_preferences.excluded_extensions.push(ext);
                    }
                    self.new_excluded_extension.clear();
                }
            });

            let mut remove_ext = None;
            for (index, ext) in self
                .protection_preferences
                .excluded_extensions
                .iter()
                .enumerate()
            {
                ui.horizontal(|ui| {
                    ui.label(format!(".{ext}"));
                    if ui.small_button("Remove").clicked() {
                        remove_ext = Some(index);
                    }
                });
            }
            if let Some(index) = remove_ext {
                self.protection_preferences
                    .excluded_extensions
                    .remove(index);
            }

            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Process:");
                ui.text_edit_singleline(&mut self.new_excluded_process);
                if ui.button("Add").clicked() {
                    let process = self.new_excluded_process.trim().to_ascii_lowercase();
                    if !process.is_empty()
                        && !self
                            .protection_preferences
                            .excluded_processes
                            .iter()
                            .any(|item| item.eq_ignore_ascii_case(&process))
                    {
                        self.protection_preferences.excluded_processes.push(process);
                    }
                    self.new_excluded_process.clear();
                }
            });

            let mut remove_process = None;
            for (index, process) in self
                .protection_preferences
                .excluded_processes
                .iter()
                .enumerate()
            {
                ui.horizontal(|ui| {
                    ui.label(process);
                    if ui.small_button("Remove").clicked() {
                        remove_process = Some(index);
                    }
                });
            }
            if let Some(index) = remove_process {
                self.protection_preferences.excluded_processes.remove(index);
            }

            ui.label(
                egui::RichText::new(
                    "Exclusions are applied only after pressing Apply & restart protection above.",
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

    fn about_page(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            Page::About,
            "About BDFR Sentinel",
            "A modular Windows endpoint-security platform built around low-overhead, layered protection.",
        );

        settings_card(ui, "BDFR Sentinel", |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("◉")
                        .size(54.0)
                        .color(ui.visuals().hyperlink_color),
                );
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("BDFR Sentinel").size(26.0).strong());
                    ui.label(
                        egui::RichText::new("Endpoint Security Platform")
                            .size(15.0)
                            .color(ui.visuals().weak_text_color()),
                    );
                    ui.label(format!("Version {}", env!("CARGO_PKG_VERSION")));
                });
            });
        });

        ui.add_space(14.0);
        ui.columns(2, |columns| {
            settings_card(&mut columns[0], "Protection stack", |ui| {
                for item in [
                    "Real-time Protection",
                    "Advanced Malware Detection",
                    "Behavior Protection",
                    "Network Firewall",
                    "Advanced Anti-Ransomware",
                    "USB Protection",
                    "Encrypted Quarantine",
                    "Game Mode",
                ] {
                    ui.label(format!("✓ {item}"));
                }
            });

            settings_card(&mut columns[1], "Runtime", |ui| {
                status_row(
                    ui,
                    "Protection service",
                    &self.service_state,
                    if self.service_state.contains("Running") {
                        GOOD
                    } else {
                        WARN
                    },
                );
                status_row(
                    ui,
                    "Game Mode",
                    if self.protection_snapshot.game_mode_active {
                        "Active"
                    } else {
                        "Off"
                    },
                    if self.protection_snapshot.game_mode_active {
                        GOOD
                    } else {
                        ui.visuals().weak_text_color()
                    },
                );
                status_row(
                    ui,
                    "Anti-Ransomware",
                    if self.protection_snapshot.ransomware_active {
                        "Active"
                    } else {
                        "Off"
                    },
                    if self.protection_snapshot.ransomware_active {
                        GOOD
                    } else {
                        WARN
                    },
                );
            });
        });

        ui.add_space(14.0);
        settings_card(ui, "Project", |ui| {
            ui.label("Publisher: BDFR");
            ui.label("License: GPL-2.0");
            ui.hyperlink_to(
                "Open BDFR Sentinel repository",
                "https://github.com/lyingtiger88/BDFR_Sentinel",
            );
            ui.label(
                egui::RichText::new(
                    "Designed for layered protection with a Windows-native service, event-driven telemetry and kernel-backed network enforcement.",
                )
                .color(ui.visuals().weak_text_color()),
            );
        });
    }

    fn self_test_window(&mut self, ctx: &egui::Context) {
        if !self.show_self_test {
            return;
        }

        let mut open = self.show_self_test;
        egui::Window::new("Protection self-test")
            .open(&mut open)
            .resizable(true)
            .default_width(560.0)
            .default_height(420.0)
            .show(ctx, |ui| {
                let passed = self.status_text.contains("passed");
                ui.label(
                    egui::RichText::new(if passed {
                        "Protection self-test passed"
                    } else {
                        "Protection self-test result"
                    })
                    .size(20.0)
                    .strong()
                    .color(if passed { GOOD } else { WARN }),
                );
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(
                        "This validates hash detection, real-time monitoring, encrypted quarantine/restore, AMSI availability and memory inspection.",
                    )
                    .color(ui.visuals().weak_text_color()),
                );
                ui.separator();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.monospace(&self.self_test_output);
                });
            });

        self.show_self_test = open;
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

        if self.scanning || self.pending_realtime_target.is_some() {
            ctx.request_repaint_after(Duration::from_millis(200));
        } else if self.protection_snapshot.game_mode_active {
            ctx.request_repaint_after(Duration::from_millis(2500));
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
                Page::History => self.history_page(ui),
                Page::Settings => self.settings_page(ui),
                Page::About => self.about_page(ui),
            });

        self.report_window(ctx);
        self.self_test_window(ctx);
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

fn page_header(ui: &mut egui::Ui, page: Page, title: &str, subtitle: &str) {
    let width = ui.available_width().max(240.0);
    let header_height = 62.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, header_height), egui::Sense::hover());

    let icon_rect = egui::Rect::from_center_size(
        egui::pos2(rect.left() + 25.0, rect.top() + 25.0),
        egui::vec2(44.0, 44.0),
    );

    ui.painter().rect_filled(
        icon_rect,
        11.0,
        ui.visuals().widgets.active.bg_fill,
    );
    draw_page_icon(
        ui.painter(),
        page,
        icon_rect.shrink(10.0),
        ui.visuals().hyperlink_color,
    );

    let text_left = icon_rect.right() + 14.0;
    ui.painter().text(
        egui::pos2(text_left, rect.top() + 8.0),
        egui::Align2::LEFT_TOP,
        title,
        egui::FontId::proportional(30.0),
        ui.visuals().text_color(),
    );
    ui.painter().text(
        egui::pos2(text_left, rect.top() + 43.0),
        egui::Align2::LEFT_TOP,
        subtitle,
        egui::FontId::proportional(13.0),
        ui.visuals().weak_text_color(),
    );

    ui.add_space(10.0);
}

fn draw_page_icon(
    painter: &egui::Painter,
    page: Page,
    rect: egui::Rect,
    color: egui::Color32,
) {
    let stroke = egui::Stroke::new(1.8_f32, color);
    let c = rect.center();
    let w = rect.width();
    let h = rect.height();

    match page {
        Page::Dashboard => {
            let gap = w * 0.14;
            let cell = (w - gap) * 0.5;
            for row in 0..2 {
                for col in 0..2 {
                    let min = egui::pos2(
                        rect.left() + col as f32 * (cell + gap),
                        rect.top() + row as f32 * (cell + gap),
                    );
                    painter.rect_stroke(
                        egui::Rect::from_min_size(min, egui::vec2(cell, cell)),
                        2.0,
                        stroke,
                        egui::StrokeKind::Inside,
                    );
                }
            }
        }
        Page::Scan => {
            let radius = w.min(h) * 0.30;
            let center = egui::pos2(c.x - w * 0.08, c.y - h * 0.08);
            painter.circle_stroke(center, radius, stroke);
            let start = center + egui::vec2(radius * 0.72, radius * 0.72);
            let end = start + egui::vec2(w * 0.28, h * 0.28);
            painter.line_segment([start, end], stroke);
        }
        Page::Quarantine => {
            let top = egui::pos2(c.x, rect.top());
            let left = egui::pos2(rect.left() + w * 0.12, rect.top() + h * 0.22);
            let right = egui::pos2(rect.right() - w * 0.12, rect.top() + h * 0.22);
            let bottom = egui::pos2(c.x, rect.bottom());
            painter.add(egui::Shape::closed_line(
                vec![top, right, egui::pos2(rect.right() - w * 0.18, c.y + h * 0.18), bottom,
                     egui::pos2(rect.left() + w * 0.18, c.y + h * 0.18), left],
                stroke,
            ));
            painter.line_segment(
                [
                    egui::pos2(c.x - w * 0.14, c.y),
                    egui::pos2(c.x - w * 0.02, c.y + h * 0.12),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(c.x - w * 0.02, c.y + h * 0.12),
                    egui::pos2(c.x + w * 0.18, c.y - h * 0.14),
                ],
                stroke,
            );
        }
        Page::History => {
            painter.circle_stroke(c, w.min(h) * 0.43, stroke);
            painter.line_segment([c, egui::pos2(c.x, rect.top() + h * 0.22)], stroke);
            painter.line_segment([c, egui::pos2(c.x + w * 0.22, c.y)], stroke);
        }
        Page::Settings => {
            painter.circle_stroke(c, w.min(h) * 0.18, stroke);
            for i in 0..8 {
                let angle = i as f32 * std::f32::consts::TAU / 8.0;
                let dir = egui::vec2(angle.cos(), angle.sin());
                let a = c + dir * (w * 0.30);
                let b = c + dir * (w * 0.46);
                painter.line_segment([a, b], stroke);
            }
        }
        Page::About => {
            painter.circle_stroke(c, w.min(h) * 0.43, stroke);
            painter.circle_filled(egui::pos2(c.x, c.y - h * 0.18), w * 0.045, color);
            painter.line_segment(
                [
                    egui::pos2(c.x, c.y - h * 0.02),
                    egui::pos2(c.x, c.y + h * 0.22),
                ],
                stroke,
            );
        }
    }
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
    sentinel_detail: String,
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
                    ui.add_space(5.0);
                    ui.label(
                        egui::RichText::new(sentinel_detail)
                            .size(12.0)
                            .strong()
                            .color(color),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new("Live system + BDFR Sentinel usage")
                            .size(11.0)
                            .color(ui.visuals().weak_text_color()),
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

fn threat_events_path() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("BDFR")
        .join("Sentinel")
        .join("events.jsonl")
}

fn service_config_path() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("BDFR")
        .join("Sentinel")
        .join("service.json")
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

fn enumerate_scan_drives() -> Vec<ScanDriveOption> {
    #[cfg(windows)]
    {
        let mut drives = Vec::new();
        for letter in b'A'..=b'Z' {
            let path = PathBuf::from(format!("{}:\\", letter as char));
            if path.exists() {
                drives.push(ScanDriveOption {
                    path,
                    selected: false,
                });
            }
        }
        drives
    }

    #[cfg(not(windows))]
    {
        vec![ScanDriveOption {
            path: PathBuf::from("/"),
            selected: false,
        }]
    }
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
