// desktop-ui: M0 smoke test. Opens an egui window showing core::hello().
// Real dashboard UX (Principle 3) lands in M3+M4 once the core protocol
// (M1) and daemon (M2) exist for it to talk to.
//
// Errors from eframe::run_native are surfaced via Result, not unwrapped
// (Principle 2).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([320.0, 160.0])
            .with_title("wake-my-pc"),
        ..Default::default()
    };
    eframe::run_native(
        "wake-my-pc",
        options,
        Box::new(|_cc| Ok(Box::<App>::default())),
    )
}

#[derive(Default, Debug)]
struct App;

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading(wake_my_pc_core::hello());
                ui.label("M0 smoke test — dashboard UX arrives in M4.");
            });
        });
    }
}
