//! SelfLock Windows GUI (eframe/egui).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod elevate;
mod format;
mod prefs;

use app::App;
use selflock_core::{logging, paths};

fn main() {
    // A single executable serves both the GUI and the hidden CLI mode used for
    // elevation and the scheduled auto-clear (invoked with `--cli`).
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--cli") {
        std::process::exit(selflock_cli::run(args) as i32);
    }

    // Only one GUI instance may run at a time. CLI mode is exempt so the elevated
    // helper and the auto-clear task can run alongside the GUI.
    let _guard = match selflock_core::instance::SingleInstance::try_acquire("SelfLock") {
        Some(guard) => guard,
        None => {
            notify_already_running();
            return;
        }
    };

    if let Err(e) = run_gui() {
        eprintln!("selflock: {e}");
        std::process::exit(1);
    }
}

/// Tell the user (via a native dialog on Windows) that an instance is already up.
fn notify_already_running() {
    selflock_core::platform::message_box("SelfLock", "SelfLock is already running.");
}

fn run_gui() -> eframe::Result<()> {
    logging::init_default(Some(paths::user_log_file()), cfg!(debug_assertions));
    log::info!(
        "=== selflock-gui starting (log: {}) ===",
        paths::user_log_file().display()
    );
    if cfg!(debug_assertions) {
        log::debug!("verbose logging enabled (development build)");
    }

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([560.0, 660.0])
            .with_min_inner_size([440.0, 520.0])
            .with_title("SelfLock"),
        ..Default::default()
    };

    eframe::run_native(
        "SelfLock",
        native_options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
