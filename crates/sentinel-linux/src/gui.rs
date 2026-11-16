use eframe::egui;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page { Overview, Scan, Firewall, System, Settings }

struct SobanLinuxApp {
    page: Page,
    selected_path: Option<PathBuf>,
    scan_output: String,
    status: String,
    capabilities: sentinel_linux::CapabilitySnapshot,
    dark_mode: bool,
    accent: egui::Color32,
}

impl SobanLinuxApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = Self {
            page: Page::Overview,
            selected_path: None,
            scan_output: String::new(),
            status: "Soban is ready. Protection status depends on installed definitions and system permissions.".into(),
            capabilities: sentinel_linux::host::discover_capabilities(),
            dark_mode: true,
            accent: egui::Color32::from_rgb(63, 184, 211),
        };
        app.apply_theme(&cc.egui_ctx);
        app
    }

    fn apply_theme(&self, ctx: &egui::Context) {
        let mut visuals = if self.dark_mode { egui::Visuals::dark() } else { egui::Visuals::light() };
        visuals.widgets.noninteractive.corner_radius = 8.into();
        visuals.widgets.inactive.corner_radius = 8.into();
        visuals.widgets.hovered.corner_radius = 8.into();
        visuals.widgets.active.corner_radius = 8.into();
        visuals.selection.bg_fill = self.accent;
        visuals.hyperlink_color = self.accent;
        visuals.window_corner_radius = 12.into();
        visuals.panel_fill = if self.dark_mode { egui::Color32::from_rgb(17, 25, 36) } else { egui::Color32::from_rgb(244, 247, 250) };
        ctx.set_visuals(visuals);
    }

    fn run_scan(&mut self) {
        let Some(path) = self.selected_path.clone() else {
            self.status = "Select a file or folder before starting a scan.".into();
            return;
        };
        let executable = std::env::current_exe().ok().map(|p| p.with_file_name("bdfr-sentinel-linux"));
        let Some(executable) = executable.filter(|p| p.is_file()) else {
            self.status = "Scanner CLI was not found beside the Soban desktop application.".into();
            return;
        };
        self.status = format!("Scanning {}…", path.display());
        match Command::new(executable).arg("scan").arg(&path).output() {
            Ok(output) => {
                self.scan_output = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                self.status = if output.status.success() {
                    if stderr.is_empty() { "Scan completed.".into() } else { stderr }
                } else {
                    format!("Scan did not complete: {}", if stderr.is_empty() { "scanner returned an error".into() } else { stderr })
                };
            }
            Err(error) => self.status = format!("Could not start scanner: {error}"),
        }
    }

    fn nav_button(ui: &mut egui::Ui, selected: bool, label: &str) -> bool {
        let fill = if selected { ui.visuals().selection.bg_fill.linear_multiply(0.22) } else { egui::Color32::TRANSPARENT };
        ui.add_sized([190.0, 42.0], egui::Button::new(egui::RichText::new(label).size(14.0).strong()).fill(fill).stroke(egui::Stroke::NONE)).clicked()
    }

    fn stat_card(ui: &mut egui::Ui, title: &str, value: &str, detail: &str, accent: egui::Color32) {
        egui::Frame::group(ui.style()).inner_margin(16.0).show(ui, |ui| {
            ui.label(egui::RichText::new(title).size(12.0).color(ui.visuals().weak_text_color()));
            ui.add_space(5.0);
            ui.label(egui::RichText::new(value).size(25.0).strong().color(accent));
            ui.label(egui::RichText::new(detail).size(11.0).color(ui.visuals().weak_text_color()));
        });
    }

    fn page_content(&mut self, ui: &mut egui::Ui) {
        match self.page {
            Page::Overview => {
                ui.heading("Security overview");
                ui.label("A clear view of Soban protection and Linux host readiness.");
                ui.add_space(18.0);
                ui.horizontal(|ui| {
                    Self::stat_card(ui, "PRODUCT", "Soban", "Linux desktop edition", self.accent);
                    Self::stat_card(ui, "FIREWALL", if self.capabilities.nft_available { "Available" } else { "Unavailable" }, "nftables integration detected", self.accent);
                    Self::stat_card(ui, "PRIVILEGES", if self.capabilities.is_root { "Root" } else { "User" }, "Current process privilege", self.accent);
                });
                ui.add_space(20.0);
                egui::Frame::group(ui.style()).inner_margin(18.0).show(ui, |ui| {
                    ui.heading("Protection status");
                    ui.add_space(6.0);
                    ui.label("Soban does not claim real-time or kernel protection unless the relevant Linux backend is installed and confirmed active.");
                    ui.label(egui::RichText::new(&self.status).color(self.accent));
                    ui.add_space(8.0);
                    if ui.button("Refresh system status").clicked() {
                        self.capabilities = sentinel_linux::host::discover_capabilities();
                        self.status = "Linux capabilities refreshed.".into();
                    }
                });
                ui.add_space(14.0);
                ui.heading("Quick actions");
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Choose file to scan").clicked() { self.page = Page::Scan; self.selected_path = rfd::FileDialog::new().pick_file(); }
                    if ui.button("Choose folder to scan").clicked() { self.page = Page::Scan; self.selected_path = rfd::FileDialog::new().pick_folder(); }
                    if ui.button("View firewall").clicked() { self.page = Page::Firewall; }
                });
            }
            Page::Scan => {
                ui.heading("Malware scan");
                ui.label("Scan files and folders you are authorized to access.");
                ui.add_space(16.0);
                egui::Frame::group(ui.style()).inner_margin(18.0).show(ui, |ui| {
                    ui.label("Scan target");
                    ui.horizontal_wrapped(|ui| {
                        let label = self.selected_path.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "No file or folder selected".into());
                        ui.label(egui::RichText::new(label).monospace());
                        if ui.button("Browse file").clicked() { self.selected_path = rfd::FileDialog::new().pick_file(); }
                        if ui.button("Browse folder").clicked() { self.selected_path = rfd::FileDialog::new().pick_folder(); }
                    });
                    ui.add_space(10.0);
                    if ui.add_enabled(self.selected_path.is_some(), egui::Button::new("Start scan")).clicked() { self.run_scan(); }
                });
                ui.add_space(14.0);
                ui.heading("Scan output");
                egui::ScrollArea::vertical().max_height(330.0).show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut self.scan_output).desired_rows(12).code_editor().desired_width(f32::INFINITY));
                });
            }
            Page::Firewall => {
                ui.heading("Network firewall");
                ui.label("Linux enforcement uses an isolated Soban-owned nftables table. Existing user firewall tables are not modified.");
                ui.add_space(14.0);
                egui::Frame::group(ui.style()).inner_margin(18.0).show(ui, |ui| {
                    ui.label(format!("nftables executable: {}", if self.capabilities.nft_available { "detected" } else { "not detected" }));
                    ui.label(format!("Administrative privileges: {}", if self.capabilities.is_root { "available" } else { "not available — firewall changes require sudo" }));
                    ui.label("Current backend: outbound IP/CIDR blocklist. Per-application Linux rules and live socket controls are not yet available in this build.");
                    ui.add_space(8.0);
                    if ui.button("Refresh firewall prerequisites").clicked() {
                        self.capabilities = sentinel_linux::host::discover_capabilities();
                        self.status = "Firewall prerequisites refreshed.".into();
                    }
                });
                ui.add_space(10.0);
                ui.label("Rule editor parity with Windows is planned: application identity, inbound/outbound direction, protocol, local/remote ports, rule priority and event history.");
            }
            Page::System => {
                ui.heading("Linux system capabilities");
                egui::Grid::new("soban-linux-capabilities").striped(true).show(ui, |ui| {
                    ui.label("Kernel release"); ui.label(&self.capabilities.kernel_release); ui.end_row();
                    ui.label("inotify"); ui.label(if self.capabilities.inotify_available { "Available" } else { "Unavailable" }); ui.end_row();
                    ui.label("fanotify"); ui.label(if self.capabilities.fanotify_available { "Available" } else { "Not confirmed" }); ui.end_row();
                    ui.label("nftables"); ui.label(if self.capabilities.nft_available { "Available" } else { "Unavailable" }); ui.end_row();
                    ui.label("eBPF filesystem"); ui.label(if self.capabilities.ebpf_available { "Available" } else { "Unavailable" }); ui.end_row();
                    ui.label("udev"); ui.label(if self.capabilities.udev_available { "Available" } else { "Unavailable" }); ui.end_row();
                    ui.label("Root privileges"); ui.label(if self.capabilities.is_root { "Yes" } else { "No" }); ui.end_row();
                });
            }
            Page::Settings => {
                ui.heading("Appearance");
                ui.checkbox(&mut self.dark_mode, "Dark appearance");
                ui.horizontal(|ui| {
                    ui.label("Accent");
                    for color in [egui::Color32::from_rgb(63,184,211), egui::Color32::from_rgb(91,154,255), egui::Color32::from_rgb(90,190,135), egui::Color32::from_rgb(190,135,230)] {
                        if ui.add(egui::Button::new("  ").fill(color).stroke(egui::Stroke::new(1.0, ui.visuals().widgets.noninteractive.fg_stroke.color))).clicked() { self.accent = color; }
                    }
                });
                ui.label("Appearance changes apply to the complete desktop surface, cards, navigation and status indicators.");
                self.apply_theme(ui.ctx());
            }
        }
    }
}

impl eframe::App for SobanLinuxApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::SidePanel::left("soban-sidebar").exact_width(224.0).resizable(false).show(ctx, |ui| {
            ui.add_space(18.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("⬡").size(30.0).color(self.accent).strong());
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("SOBAN").size(20.0).strong());
                    ui.label(egui::RichText::new("LINUX SECURITY").size(9.0).color(ui.visuals().weak_text_color()));
                });
            });
            ui.add_space(26.0);
            for (page, label) in [
                (Page::Overview, "◈  Overview"),
                (Page::Scan, "⌕  Scan"),
                (Page::Firewall, "▣  Firewall"),
                (Page::System, "▤  System status"),
                (Page::Settings, "⚙  Settings"),
            ] {
                if Self::nav_button(ui, self.page == page, label) { self.page = page; }
                ui.add_space(4.0);
            }
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                ui.separator();
                ui.label(egui::RichText::new("Soban • Debian edition").size(10.0).color(ui.visuals().weak_text_color()));
                ui.label(egui::RichText::new("Protection state is evidence-based").size(9.0).color(ui.visuals().weak_text_color()));
            });
        });
        egui::TopBottomPanel::top("soban-topbar").exact_height(52.0).show(ctx, |ui| {
            ui.horizontal_centered(|ui| {
                ui.label(egui::RichText::new(match self.page {
                    Page::Overview => "Overview", Page::Scan => "Malware scan", Page::Firewall => "Network firewall",
                    Page::System => "System status", Page::Settings => "Settings",
                }).size(16.0).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new("●  Linux endpoint").size(11.0).color(self.accent));
                });
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.add_space(16.0);
                self.page_content(ui);
                ui.add_space(24.0);
            });
        });
        egui::TopBottomPanel::bottom("soban-statusbar").exact_height(28.0).show(ctx, |ui| {
            ui.horizontal_centered(|ui| {
                ui.label(egui::RichText::new(&self.status).size(10.0).color(ui.visuals().weak_text_color()));
            });
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 760.0])
            .with_min_inner_size([860.0, 600.0])
            .with_icon(eframe::icon_data::from_png_bytes(include_bytes!("../../../assets/soban-icon.png")).unwrap_or_default()),
        ..Default::default()
    };
    eframe::run_native("Soban", options, Box::new(|cc| Ok(Box::new(SobanLinuxApp::new(cc)))))
}
