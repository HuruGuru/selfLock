//! The eframe application: a Windows reimagining of SelfLock's main and timer
//! windows.
//!
//! Privileged work (firewall/hosts edits) runs on a background thread so the UI
//! thread never blocks on `netsh`; a corrupt settings file disables block starting
//! instead of silently pretending no block is running.

use crate::{elevate, format, prefs::UiPrefs};
use chrono::{DateTime, Local, Utc};
use eframe::egui;
use selflock_core::apps;
use selflock_core::blocklist_file::{self, BlocklistFile};
use selflock_core::cleaner::clean_blocklist_entry;
use selflock_core::manager::BlockManager;
use selflock_core::paths;
use selflock_core::scheduler;
use selflock_core::settings::Settings;
use selflock_core::{cache, logging};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::{self, TryRecvError};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockAction {
    Start,
    Clear,
    Add,
}

/// On Windows the scheduled task clears the block at the end time without any
/// prompt, so give it a minute before asking for elevation ourselves.
const AUTO_CLEAR_GRACE: Duration = Duration::from_secs(60);

/// If the block expired longer ago than this, the scheduled task clearly missed
/// its run (the machine was asleep or off), so waiting for it is pointless.
const AUTO_CLEAR_STALE: Duration = Duration::from_secs(90);

/// After a declined elevation prompt, wait this long before opening one again on
/// our own. The "Clear expired block" button always retries immediately.
const AUTO_CLEAR_RETRY: Duration = Duration::from_secs(300);

struct ElevationJob {
    rx: mpsc::Receiver<Result<i32, String>>,
    action: BlockAction,
    started: Instant,
}

/// Result of an in-process (already-elevated) block start/clear/add.
enum DirectOutcome {
    Started {
        firewall: usize,
        hosts: usize,
        apps: usize,
    },
    StartDenied,
    StartFailed(String),
    Cleared(bool),
    Added {
        entries: usize,
    },
    AppendFailed(String),
}

struct DirectJob {
    rx: mpsc::Receiver<DirectOutcome>,
    action: BlockAction,
}

pub struct App {
    prefs: UiPrefs,
    settings: Settings,
    /// Set when the settings file exists but could not be read/parsed. While set we
    /// refuse to start a block (fail closed).
    settings_error: Option<String>,
    status: Option<(String, bool)>,
    elevation: Option<ElevationJob>,
    direct: Option<DirectJob>,
    log_lines: Vec<String>,
    log_last_refresh: Instant,
    state_last_check: Instant,
    expired_since: Option<Instant>,
    /// Instant before which we must not open another elevation prompt for the
    /// expired block (set after the user declined it once).
    clear_retry_at: Option<Instant>,
    /// Contents of the "Add to block" input (not persisted).
    add_entry_text: String,
    /// `active_blocklist` length before the in-flight add, used to confirm success.
    add_baseline: Option<usize>,
    /// Entries requested by the in-flight add (kept for the completion message and
    /// to remember them in the editor).
    add_pending: Vec<String>,
    show_log: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let prefs = UiPrefs::load();

        let mut app = App {
            prefs,
            settings: Settings::default(),
            settings_error: None,
            status: None,
            elevation: None,
            direct: None,
            log_lines: Vec::new(),
            log_last_refresh: Instant::now(),
            state_last_check: Instant::now(),
            expired_since: None,
            clear_retry_at: None,
            add_entry_text: String::new(),
            add_baseline: None,
            add_pending: Vec::new(),
            show_log: false,
        };

        app.reload_settings();

        if app.prefs.blocklist_text.trim().is_empty()
            && app.prefs.app_blocklist_text.trim().is_empty()
        {
            if let Ok(file) = blocklist_file::read_from_path(paths::blocklist_file()) {
                app.load_saved_entries(&file.blocklist, file.block_as_whitelist);
            } else if !app.settings.active_blocklist.is_empty() {
                let entries = app.settings.active_blocklist.clone();
                let allowlist = app.settings.active_block_as_whitelist;
                app.load_saved_entries(&entries, allowlist);
            }
        }

        log::info!(
            "gui: started (elevated={}), settings block_is_running={}, settings_error={}",
            elevate::is_elevated(),
            app.settings.block_is_running,
            app.settings_error.is_some()
        );

        app.log_lines = read_log_tail(&logging::default_log_path(), 300);
        app
    }

    /// Split a saved blocklist into ordinary site entries and `app:` entries, so
    /// the GUI can show applications in their own optional field.
    fn load_saved_entries(&mut self, entries: &[String], allowlist: bool) {
        let mut sites = Vec::new();
        let mut apps = Vec::new();
        for entry in entries {
            match apps::strip_prefix(entry) {
                Some(spec) => apps.push(spec.to_string()),
                None => sites.push(entry.clone()),
            }
        }
        self.prefs.blocklist_text = sites.join("\n");
        // Allowlist blocks are a development-only feature.
        self.prefs.is_allowlist = cfg!(debug_assertions) && allowlist;
        if !apps.is_empty() {
            self.prefs.app_blocklist_text = apps.join("\n");
            self.prefs.app_blocking_enabled = true;
        }
    }

    /// Clean, deduplicate and flatten the editor contents into block entries.
    ///
    /// Application entries are only included when the "Application blocking"
    /// checkbox is on; that is what makes the feature optional.
    fn entries(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for line in self.prefs.blocklist_text.lines() {
            for cleaned in clean_blocklist_entry(line) {
                // The checkbox is the master switch for application blocking: with
                // it off, even an explicit `app:` line in the site box is ignored.
                if !self.prefs.app_blocking_enabled && apps::strip_prefix(&cleaned).is_some() {
                    continue;
                }
                if seen.insert(cleaned.clone()) {
                    out.push(cleaned);
                }
            }
        }
        if self.prefs.app_blocking_enabled {
            for line in self.prefs.app_blocklist_text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                // Accept both `firefox.exe` and a pasted `app:firefox.exe` without
                // doubling the prefix.
                let spec = apps::strip_prefix(line).unwrap_or(line);
                for cleaned in clean_blocklist_entry(&format!("app:{spec}")) {
                    if seen.insert(cleaned.clone()) {
                        out.push(cleaned);
                    }
                }
            }
        }
        out
    }

    fn set_status(&mut self, msg: impl Into<String>, is_error: bool) {
        let msg = msg.into();
        // Status is re-set every frame (e.g. the "clearing…" countdown); only log and
        // store it when it actually changes, to avoid flooding the log file.
        if let Some((current, current_is_error)) = &self.status {
            if *current == msg && *current_is_error == is_error {
                return;
            }
        }
        log::info!("status: {msg}");
        self.status = Some((msg, is_error));
    }

    fn busy(&self) -> bool {
        self.elevation.is_some() || self.direct.is_some()
    }

    /// Reload settings, keeping the previous snapshot (and latching an error) when
    /// the file cannot be read. Failing closed avoids treating a corrupt file as
    /// "no block is running".
    fn reload_settings(&mut self) {
        match Settings::load() {
            Ok(s) => {
                self.settings = s;
                self.settings_error = None;
            }
            Err(e) => {
                log::error!("could not load settings: {e}");
                self.settings_error = Some(e.to_string());
            }
        }
    }

    fn try_start(&mut self) {
        if self.settings_error.is_some() {
            self.set_status(
                "Cannot start a block while the settings file is unreadable.",
                true,
            );
            return;
        }
        let max = self.settings.max_block_minutes();
        if self.prefs.duration_minutes > max {
            self.prefs.duration_minutes = max;
            self.set_status(
                format!("Duration capped to the maximum block length ({max} min)."),
                false,
            );
        }
        let entries = self.entries();
        if entries.is_empty() && !self.prefs.is_allowlist {
            self.set_status("Add at least one site or IP to block.", true);
            return;
        }
        log::info!(
            "gui: Start Block clicked ({} entries, allowlist={}, duration={}min)",
            entries.len(),
            self.prefs.is_allowlist,
            self.prefs.duration_minutes
        );
        self.prefs.save();

        let end = Utc::now() + chrono::Duration::minutes(self.prefs.duration_minutes.max(1) as i64);

        if elevate::is_elevated() {
            self.start_direct(&entries, end);
        } else {
            self.start_elevated(&entries, end);
        }
    }

    fn apply_prefs_to_settings(&mut self) {
        self.settings.evaluate_common_subdomains = self.prefs.evaluate_common_subdomains;
        self.settings.include_linked_domains = self.prefs.include_linked_domains;
        self.settings.clear_caches = self.prefs.clear_caches;
        self.settings.allow_local_networks = self.prefs.allow_local_networks;
        self.settings.block_duration = self.prefs.duration_minutes;
    }

    fn start_direct(&mut self, entries: &[String], end: DateTime<Utc>) {
        self.apply_prefs_to_settings();
        self.settings
            .begin_block(entries.to_vec(), self.prefs.is_allowlist, end);
        let settings = self.settings.clone();

        let entries = entries.to_vec();
        let allowlist = self.prefs.is_allowlist;
        let allow_local = self.prefs.allow_local_networks;
        let common = self.prefs.evaluate_common_subdomains;
        let linked = self.prefs.include_linked_domains;
        let exe = elevate::self_exe();
        let log_path = logging::default_log_path();

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut manager = BlockManager::new(allowlist, allow_local, common, linked);
            let outcome = match manager.start_block_from_strings(&entries) {
                Ok(()) => {
                    if let Err(e) = settings.save() {
                        log::warn!("could not persist settings after start: {e}");
                    }
                    match exe {
                        Some(exe) => {
                            let args = vec![
                                "--cli".to_string(),
                                "remove".to_string(),
                                "--force".to_string(),
                                "--log-file".to_string(),
                                log_path.display().to_string(),
                            ];
                            if let Err(e) = scheduler::schedule_clear(&exe, &args, end) {
                                log::warn!("could not schedule automatic clear: {e}");
                            }
                        }
                        None => log::warn!(
                            "could not determine the app path; the block will not auto-clear while the app is closed"
                        ),
                    }
                    DirectOutcome::Started {
                        firewall: manager.firewall_rule_count(),
                        hosts: manager.hosts_rule_count(),
                        apps: manager.app_rule_count(),
                    }
                }
                Err(e) => {
                    log::error!("gui: start failed: {e}");
                    if e.is_permission_denied() {
                        DirectOutcome::StartDenied
                    } else {
                        DirectOutcome::StartFailed(e.to_string())
                    }
                }
            };
            let _ = tx.send(outcome);
        });

        self.direct = Some(DirectJob {
            rx,
            action: BlockAction::Start,
        });
        self.set_status("Starting block…", false);
    }

    fn start_elevated(&mut self, entries: &[String], end: DateTime<Utc>) {
        let Some(exe) = elevate::self_exe() else {
            self.set_status(
                "Administrator privileges are required, but the app could not locate its own executable.",
                true,
            );
            return;
        };

        let dir = paths::user_config_dir();
        let _ = std::fs::create_dir_all(&dir);
        let blocklist_path = dir.join("pending.selflock");
        if let Err(e) = blocklist_file::write_to_path(
            &blocklist_path,
            &BlocklistFile::new(entries.to_vec(), self.prefs.is_allowlist),
        ) {
            self.set_status(format!("Could not write temporary blocklist: {e}"), true);
            return;
        }

        let settings_path = dir.join("pending-settings.json");
        let settings_json = serde_json::json!({
            "AllowLocalNetworks": self.prefs.allow_local_networks,
            "EvaluateCommonSubdomains": self.prefs.evaluate_common_subdomains,
            "IncludeLinkedDomains": self.prefs.include_linked_domains,
            "MaxBlockLength": self.settings.max_block_minutes(),
        })
        .to_string();
        if let Err(e) = std::fs::write(&settings_path, &settings_json) {
            self.set_status(format!("Could not write temporary settings: {e}"), true);
            return;
        }

        let args = vec![
            "--cli".to_string(),
            "start".to_string(),
            "--blocklist".to_string(),
            blocklist_path.display().to_string(),
            "--enddate".to_string(),
            end.to_rfc3339(),
            "--settings-file".to_string(),
            settings_path.display().to_string(),
            "--log-file".to_string(),
            logging::default_log_path().display().to_string(),
        ];

        self.spawn_elevation(exe, args, BlockAction::Start);
    }

    fn request_clear(&mut self) {
        log::info!("gui: clearing block");
        if elevate::is_elevated() {
            let allowlist = self.settings.active_block_as_whitelist;
            let allow_local = self.settings.allow_local_networks;
            let common = self.settings.evaluate_common_subdomains;
            let linked = self.settings.include_linked_domains;
            let mut settings = self.settings.clone();

            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let mut manager = BlockManager::new(allowlist, allow_local, common, linked);
                let ok = manager.clear_block(false);
                let _ = scheduler::cancel_clear();
                settings.remove_block_from_settings();
                if let Err(e) = settings.save() {
                    log::warn!("could not persist settings after clear: {e}");
                }
                let _ = tx.send(DirectOutcome::Cleared(ok));
            });
            self.direct = Some(DirectJob {
                rx,
                action: BlockAction::Clear,
            });
            self.set_status("Clearing block…", false);
        } else if let Some(exe) = elevate::self_exe() {
            let args = vec![
                "--cli".to_string(),
                "remove".to_string(),
                "--force".to_string(),
                "--log-file".to_string(),
                logging::default_log_path().display().to_string(),
            ];
            self.spawn_elevation(exe, args, BlockAction::Clear);
        } else {
            self.set_status(
                "Could not locate the app executable to clear the block.",
                true,
            );
        }
    }

    /// Add entries to the running block ("Add to block", like the original's sheet).
    ///
    /// The block is never stopped or rebuilt: only new hosts lines and new firewall
    /// rules are appended, so the network is not opened even for a moment and the
    /// end date does not change.
    fn request_add(&mut self) {
        let active: HashSet<String> = self.settings.active_blocklist.iter().cloned().collect();
        let entries: Vec<String> = self
            .pending_add_entries()
            .into_iter()
            .filter(|entry| !active.contains(entry))
            .collect();
        if entries.is_empty() {
            self.set_status(
                "Nothing to add — the block already covers these entries (or the field is empty).",
                true,
            );
            return;
        }
        if self.settings.active_block_as_whitelist {
            self.set_status("Entries cannot be added to an allowlist block.", true);
            return;
        }
        if self.settings.seconds_remaining() < 30 {
            self.set_status(
                "The block ends too soon to add entries; try again earlier.",
                true,
            );
            return;
        }

        log::info!(
            "gui: adding {} entr(y/ies) to the active block: {:?}",
            entries.len(),
            entries
        );
        self.add_baseline = Some(self.settings.active_blocklist.len());
        self.add_pending = entries.clone();

        if elevate::is_elevated() {
            let allow_local = self.settings.allow_local_networks;
            let common = self.settings.evaluate_common_subdomains;
            let linked = self.settings.include_linked_domains;
            let mut settings = self.settings.clone();
            let to_add = entries;
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let mut manager = BlockManager::new(false, allow_local, common, linked);
                manager.seed_blocked(&settings.active_blocklist);
                let outcome = match manager.append_block_from_strings(&to_add) {
                    Ok(_) => {
                        settings.active_blocklist.extend(to_add.iter().cloned());
                        if let Err(e) = settings.save() {
                            log::warn!("could not persist settings after add: {e}");
                        }
                        DirectOutcome::Added {
                            entries: to_add.len(),
                        }
                    }
                    Err(e) => DirectOutcome::AppendFailed(e.to_string()),
                };
                let _ = tx.send(outcome);
            });
            self.direct = Some(DirectJob {
                rx,
                action: BlockAction::Add,
            });
            self.set_status("Adding to the block…", false);
        } else if let Some(exe) = elevate::self_exe() {
            let dir = paths::user_config_dir();
            let _ = std::fs::create_dir_all(&dir);
            let blocklist_path = dir.join("pending-add.selflock");
            if let Err(e) =
                blocklist_file::write_to_path(&blocklist_path, &BlocklistFile::new(entries, false))
            {
                self.set_status(
                    format!("Could not write the temporary blocklist: {e}"),
                    true,
                );
                self.add_baseline = None;
                self.add_pending.clear();
                return;
            }
            let args = vec![
                "--cli".to_string(),
                "add".to_string(),
                "--blocklist".to_string(),
                blocklist_path.display().to_string(),
                "--log-file".to_string(),
                logging::default_log_path().display().to_string(),
            ];
            self.spawn_elevation(exe, args, BlockAction::Add);
        } else {
            self.set_status("Could not locate the app executable to add entries.", true);
            self.add_baseline = None;
            self.add_pending.clear();
        }
    }

    /// Parse the "Add to block" field into cleaned, de-duplicated entries.
    fn pending_add_entries(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for line in self.add_entry_text.lines() {
            for cleaned in clean_blocklist_entry(line) {
                if seen.insert(cleaned.clone()) {
                    out.push(cleaned);
                }
            }
        }
        out
    }

    /// Remember successfully added entries in the editor, so the next block includes
    /// them without retyping.
    fn remember_added_prefs(&mut self) {
        let entries = std::mem::take(&mut self.add_pending);
        for entry in entries {
            match apps::strip_prefix(&entry) {
                Some(spec) => {
                    self.prefs.app_blocking_enabled = true;
                    if !self
                        .prefs
                        .app_blocklist_text
                        .lines()
                        .any(|l| l.trim() == spec)
                    {
                        if !self.prefs.app_blocklist_text.is_empty()
                            && !self.prefs.app_blocklist_text.ends_with('\n')
                        {
                            self.prefs.app_blocklist_text.push('\n');
                        }
                        self.prefs.app_blocklist_text.push_str(spec);
                        self.prefs.app_blocklist_text.push('\n');
                    }
                }
                None => {
                    if !self.prefs.blocklist_text.lines().any(|l| l.trim() == entry) {
                        if !self.prefs.blocklist_text.is_empty()
                            && !self.prefs.blocklist_text.ends_with('\n')
                        {
                            self.prefs.blocklist_text.push('\n');
                        }
                        self.prefs.blocklist_text.push_str(&entry);
                        self.prefs.blocklist_text.push('\n');
                    }
                }
            }
        }
        self.prefs.save();
        self.add_entry_text.clear();
    }

    /// Clear browser/DNS caches from the (unprivileged) GUI process, off the UI
    /// thread. The elevated helper no longer touches the user's profile.
    fn spawn_cache_clear(&mut self) {
        log::info!("gui: clearing browser/DNS caches");
        std::thread::spawn(cache::clear_caches);
    }

    fn spawn_elevation(&mut self, cli: PathBuf, args: Vec<String>, action: BlockAction) {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = elevate::run_elevated(&cli, &args);
            let _ = tx.send(result);
        });
        self.elevation = Some(ElevationJob {
            rx,
            action,
            started: Instant::now(),
        });
        self.set_status(
            "Requesting administrator privileges — approve the prompt to continue…",
            false,
        );
    }

    fn poll_elevation(&mut self, ctx: &egui::Context) {
        let Some(job) = self.elevation.as_ref() else {
            return;
        };
        match job.rx.try_recv() {
            Ok(result) => {
                let action = job.action;
                self.elevation = None;
                self.handle_elevation_result(action, result);
            }
            Err(TryRecvError::Empty) => {
                if job.started.elapsed() > Duration::from_secs(300) {
                    self.elevation = None;
                    self.set_status("Timed out waiting for the elevated process.", true);
                } else {
                    ctx.request_repaint_after(Duration::from_millis(200));
                }
            }
            Err(TryRecvError::Disconnected) => {
                self.elevation = None;
                self.set_status("The elevated process handle was lost unexpectedly.", true);
            }
        }
    }

    fn poll_direct(&mut self, ctx: &egui::Context) {
        let Some(job) = self.direct.as_ref() else {
            return;
        };
        match job.rx.try_recv() {
            Ok(outcome) => {
                let action = job.action;
                self.direct = None;
                self.handle_direct_result(action, outcome);
            }
            Err(TryRecvError::Empty) => {
                ctx.request_repaint_after(Duration::from_millis(200));
            }
            Err(TryRecvError::Disconnected) => {
                self.direct = None;
                self.set_status("The block process handle was lost unexpectedly.", true);
            }
        }
    }

    fn handle_elevation_result(&mut self, action: BlockAction, result: Result<i32, String>) {
        self.reload_settings();
        self.refresh_log();

        match result {
            Err(e) => {
                log::warn!("elevation failed: {e}");
                self.set_status(format!("Elevation failed: {e}"), true);
                match action {
                    BlockAction::Clear => self.defer_next_auto_clear(),
                    BlockAction::Add => {
                        self.add_baseline = None;
                        self.add_pending.clear();
                    }
                    BlockAction::Start => {}
                }
            }
            Ok(code) => {
                log::info!("elevated process finished with exit code {code}");
                match action {
                    BlockAction::Start => {
                        if self.settings.block_is_running {
                            self.set_status("Block started.", false);
                            if self.prefs.clear_caches {
                                self.spawn_cache_clear();
                            }
                        } else {
                            // The elevated helper cannot show a console, so the real
                            // reason (netsh output, AppNotFound, …) only exists in the
                            // log. Surface the last failure line instead of just the
                            // exit code.
                            let hint = self
                                .log_lines
                                .iter()
                                .rev()
                                .find(|line| {
                                    line.contains("failed to start block")
                                        || line.contains("netsh: batch failed")
                                })
                                .map(|line| line.trim().to_string());
                            let message = match hint {
                                Some(detail) => format!(
                                    "The elevated process exited (code {code}) and no block is running. {detail}"
                                ),
                                None => format!(
                                    "The elevated process exited (code {code}) but no block is running. See the log: {}",
                                    logging::default_log_path().display()
                                ),
                            };
                            self.set_status(message, true);
                            self.show_log = true;
                        }
                    }
                    BlockAction::Clear => {
                        if self.settings.block_is_running {
                            self.set_status("Block is still running — clearing failed.", true);
                            self.show_log = true;
                            self.defer_next_auto_clear();
                        } else {
                            self.set_status("Block cleared.", false);
                        }
                    }
                    BlockAction::Add => {
                        let baseline = self.add_baseline.take().unwrap_or(0);
                        let now = self.settings.active_blocklist.len();
                        if !self.settings.block_is_running {
                            self.add_pending.clear();
                            self.set_status(
                                "The block ended before the entries could be added.",
                                true,
                            );
                        } else if now > baseline {
                            self.remember_added_prefs();
                            self.set_status(
                                format!("Added {} entr(y/ies) to the block.", now - baseline),
                                false,
                            );
                            if self.prefs.clear_caches {
                                self.spawn_cache_clear();
                            }
                        } else {
                            self.add_pending.clear();
                            // The elevated helper cannot print to a console; surface
                            // the reason from the log instead of just the exit code.
                            let hint = self
                                .log_lines
                                .iter()
                                .rev()
                                .find(|line| {
                                    line.contains("add: failed")
                                        || line.contains("Failed to add entries")
                                })
                                .map(|line| line.trim().to_string());
                            let message = match hint {
                                Some(detail) => {
                                    format!("Could not add entries (code {code}). {detail}")
                                }
                                None => format!(
                                    "Could not add entries (code {code}). See the log: {}",
                                    logging::default_log_path().display()
                                ),
                            };
                            self.set_status(message, true);
                            self.show_log = true;
                        }
                    }
                }
            }
        }
    }

    fn handle_direct_result(&mut self, action: BlockAction, outcome: DirectOutcome) {
        match (action, outcome) {
            (
                BlockAction::Start,
                DirectOutcome::Started {
                    firewall,
                    hosts,
                    apps,
                },
            ) => {
                self.reload_settings();
                self.set_status(
                    format!(
                        "Block started ({firewall} firewall rules, {hosts} hosts rules, {apps} application rules)."
                    ),
                    false,
                );
                if self.prefs.clear_caches {
                    self.spawn_cache_clear();
                }
            }
            (BlockAction::Start, DirectOutcome::StartDenied) => {
                self.settings.remove_block_from_settings();
                self.set_status(
                    "Permission denied — run SelfLock as administrator to start a block.",
                    true,
                );
                self.show_log = true;
            }
            (BlockAction::Start, DirectOutcome::StartFailed(e)) => {
                self.settings.remove_block_from_settings();
                self.set_status(format!("Could not start block: {e}."), true);
                self.show_log = true;
            }
            (BlockAction::Clear, DirectOutcome::Cleared(true)) => {
                self.reload_settings();
                self.set_status("Block cleared.", false);
            }
            (BlockAction::Clear, DirectOutcome::Cleared(false)) => {
                self.reload_settings();
                self.set_status("Block may not have cleared fully.", true);
                self.show_log = true;
                self.defer_next_auto_clear();
            }
            (BlockAction::Add, DirectOutcome::Added { entries }) => {
                self.reload_settings();
                self.add_baseline = None;
                self.remember_added_prefs();
                self.set_status(format!("Added {entries} entr(y/ies) to the block."), false);
                if self.prefs.clear_caches {
                    self.spawn_cache_clear();
                }
            }
            (BlockAction::Add, DirectOutcome::AppendFailed(e)) => {
                self.add_baseline = None;
                self.add_pending.clear();
                self.set_status(format!("Could not add entries: {e}."), true);
                self.show_log = true;
            }
            // Mismatched action/outcome should not happen.
            (_, DirectOutcome::Started { .. })
            | (_, DirectOutcome::StartDenied)
            | (_, DirectOutcome::StartFailed(_))
            | (_, DirectOutcome::Cleared(_))
            | (_, DirectOutcome::Added { .. })
            | (_, DirectOutcome::AppendFailed(_)) => {}
        }
        self.refresh_log();
    }

    fn auto_expire(&mut self, ctx: &egui::Context) {
        // Leave the timers alone while a privileged operation is in flight.
        if self.busy() {
            return;
        }
        if !self.settings.block_is_running || !self.settings.current_block_is_expired() {
            self.expired_since = None;
            self.clear_retry_at = None;
            return;
        }

        // A declined UAC prompt wins over the grace period: do not claim to be
        // "clearing" while we are actually waiting for the user.
        if let Some(at) = self.clear_retry_at {
            if Instant::now() < at {
                self.set_status(
                    "Block expired — administrator approval is required. Use “Clear expired block”.",
                    true,
                );
                return;
            }
            self.clear_retry_at = None;
        }

        // A scheduled task clears the block at the end time without any prompt, so
        // we wait for it (picking up the result via the periodic settings reload)
        // instead of spawning our own elevated request. Exception: when the block
        // expired long before this session noticed it, the task missed its run
        // (machine asleep/off) and waiting is pointless.
        let overdue = self
            .settings
            .block_end_date
            .map(|end| (Utc::now() - end).num_seconds())
            .unwrap_or(i64::MAX);
        let since = *self.expired_since.get_or_insert_with(Instant::now);
        if overdue < AUTO_CLEAR_STALE.as_secs() as i64 && since.elapsed() < AUTO_CLEAR_GRACE {
            self.set_status("Block expired — clearing…", false);
            return;
        }
        // Fallback: the task didn't clear it in time, so elevate ourselves.

        self.set_status("Block expired — clearing rules…", false);
        // A UAC prompt that stays behind the window is easy to miss; flash the
        // taskbar before asking for it.
        ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
            egui::UserAttentionType::Critical,
        ));
        self.request_clear();
    }

    /// Back off after a failed or unapproved clear instead of re-opening the UAC
    /// prompt on every tick.
    fn defer_next_auto_clear(&mut self) {
        self.clear_retry_at = Some(Instant::now() + AUTO_CLEAR_RETRY);
        log::info!(
            "gui: next automatic clear attempt deferred by {}s",
            AUTO_CLEAR_RETRY.as_secs()
        );
    }

    /// Reload the on-disk settings while a block is running so the UI reflects a
    /// clear performed by the scheduled task (or another process).
    fn sync_settings(&mut self) {
        if !self.settings.block_is_running
            || self.state_last_check.elapsed() < Duration::from_secs(1)
        {
            return;
        }
        self.state_last_check = Instant::now();
        let was_running = self.settings.block_is_running;
        match Settings::load() {
            Ok(fresh) => {
                let cleared = was_running && !fresh.block_is_running;
                self.settings = fresh;
                self.settings_error = None;
                if cleared {
                    self.set_status("Block cleared.", false);
                    self.refresh_log();
                }
            }
            Err(e) => {
                log::error!("could not reload settings: {e}");
                self.settings_error = Some(e.to_string());
            }
        }
    }

    fn refresh_log(&mut self) {
        self.log_lines = read_log_tail(&logging::default_log_path(), 300);
        self.log_last_refresh = Instant::now();
    }

    fn start_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("SelfLock");
        ui.label("Block your access to these sites until the timer runs out.");
        ui.add_space(6.0);

        if let Some(err) = self.settings_error.clone() {
            ui.colored_label(
                egui::Color32::from_rgb(230, 110, 110),
                format!(
                    "Settings could not be read ({err}). Starting is disabled until this is fixed."
                ),
            );
            ui.add_space(6.0);
        }

        ui.label("Sites, IPs or CIDR ranges (one per line):");
        ui.add(
            egui::TextEdit::multiline(&mut self.prefs.blocklist_text)
                .desired_rows(10)
                .desired_width(f32::INFINITY)
                .hint_text("facebook.com\ntwitter.com\n93.184.216.0/24"),
        );

        let all_entries = self.entries();
        let count = all_entries.len();
        let app_count = all_entries
            .iter()
            .filter(|entry| apps::strip_prefix(entry).is_some())
            .count();
        if app_count > 0 {
            ui.label(
                egui::RichText::new(format!("{count} entries ({app_count} applications)")).weak(),
            );
        } else {
            ui.label(egui::RichText::new(format!("{count} entries")).weak());
        }
        ui.add_space(6.0);

        // Optional application blocking (Windows Firewall `program=` rules).
        ui.checkbox(&mut self.prefs.app_blocking_enabled, "Application blocking");
        if self.prefs.app_blocking_enabled {
            ui.label("Applications (one per line; image name or full path):");
            ui.add(
                egui::TextEdit::multiline(&mut self.prefs.app_blocklist_text)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY)
                    .hint_text("firefox.exe\nC:\\Program Files\\Mozilla Firefox\\firefox.exe"),
            );
        }
        ui.add_space(6.0);

        let max_minutes = self.settings.max_block_minutes();
        ui.horizontal(|ui| {
            ui.label("Duration:");
            ui.add(
                egui::DragValue::new(&mut self.prefs.duration_minutes)
                    .range(1..=max_minutes)
                    .suffix(" min"),
            );
            ui.label(
                egui::RichText::new(format!(
                    "({})",
                    format::format_minutes(self.prefs.duration_minutes)
                ))
                .weak(),
            );
        });
        // Three rows by unit: minutes, hours, days.
        let rows: [(&str, &[u32]); 3] = [
            ("Minutes:", &[5, 15, 30]),
            ("Hours:", &[60, 120, 240, 480, 720]),
            ("Days:", &[1440, 4320, 7200, 8640]),
        ];
        for (label, presets) in rows {
            ui.horizontal(|ui| {
                ui.add_sized(
                    [58.0, 18.0],
                    egui::Label::new(egui::RichText::new(label).weak()),
                );
                for &minutes in presets {
                    let enabled = minutes <= max_minutes;
                    if ui
                        .add_enabled(enabled, egui::Button::new(format::format_minutes(minutes)))
                        .clicked()
                    {
                        self.prefs.duration_minutes = minutes;
                    }
                }
            });
        }
        if max_minutes < 8640 {
            ui.label(
                egui::RichText::new(format!(
                    "Max block length: {} — longer presets are disabled (raise MaxBlockLength in settings.json to enable them)",
                    format::format_minutes(max_minutes)
                ))
                .weak()
                .small(),
            );
        }
        ui.add_space(4.0);

        // Allowlist blocks are only exposed in development builds.
        #[cfg(debug_assertions)]
        {
            ui.checkbox(
                &mut self.prefs.is_allowlist,
                "Block as allowlist (only allow these sites)",
            );
        }

        ui.collapsing("Advanced options", |ui| {
            ui.checkbox(
                &mut self.prefs.evaluate_common_subdomains,
                "Also block common subdomains (www, m, …)",
            );
            #[cfg(debug_assertions)]
            {
                ui.checkbox(
                    &mut self.prefs.include_linked_domains,
                    "Also allowlist linked domains (allowlist blocks only)",
                );
            }
            ui.checkbox(&mut self.prefs.clear_caches, "Clear browser/DNS caches");
            ui.checkbox(
                &mut self.prefs.allow_local_networks,
                "Allow local network access",
            );
        });

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let can_start = !self.busy() && self.settings_error.is_none();
            // The primary action is deliberately red: it starts an irreversible block.
            let fill = if can_start {
                egui::Color32::from_rgb(190, 45, 45)
            } else {
                egui::Color32::from_rgb(95, 60, 60)
            };
            let start = egui::Button::new(egui::RichText::new("Start Block").strong())
                .fill(fill)
                .min_size(egui::vec2(110.0, 28.0));
            if ui.add_enabled(can_start, start).clicked() {
                self.try_start();
            }
            if ui.button("Reload state").clicked() {
                self.reload_settings();
                self.set_status("Reloaded.", false);
            }
        });
    }

    fn running_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading(if self.settings.active_block_as_whitelist {
            "Allowlist block active"
        } else {
            "Block active"
        });

        let remaining = self.settings.seconds_remaining();
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new(format::format_duration(remaining))
                .size(48.0)
                .strong(),
        );

        if let Some(end) = self.settings.block_end_date {
            let local = end.with_timezone(&Local);
            ui.label(format!("Ends at {}", local.format("%Y-%m-%d %H:%M:%S")));
        }

        if self.settings.current_block_is_expired() {
            ui.add_space(8.0);
            ui.colored_label(
                egui::Color32::from_rgb(230, 180, 90),
                "This block has expired, but its rules are still applied. \
                 Removing them needs administrator approval.",
            );
            if ui
                .add_enabled(!self.busy(), egui::Button::new("Clear expired block"))
                .clicked()
            {
                self.clear_retry_at = None;
                self.request_clear();
            }
        }

        ui.add_space(8.0);
        ui.label("Blocked entries:");
        egui::ScrollArea::vertical()
            .max_height(240.0)
            .show(ui, |ui| {
                for entry in &self.settings.active_blocklist {
                    match apps::strip_prefix(entry) {
                        Some(spec) => ui.label(format!("app: {spec}")),
                        None => ui.label(entry),
                    };
                }
            });

        // "Add to block": the end date cannot be shortened, but new entries can be
        // applied to a running block (the original's Add to Block sheet).
        ui.add_space(10.0);
        ui.separator();
        if self.settings.active_block_as_whitelist {
            ui.label(egui::RichText::new("Entries cannot be added to an allowlist block.").weak());
        } else {
            ui.label("Add to block (site, IP or app: entry):");
            ui.horizontal(|ui| {
                let can_add = !self.busy() && self.settings.seconds_remaining() >= 30;
                let response = ui.add_enabled(
                    can_add,
                    egui::TextEdit::singleline(&mut self.add_entry_text)
                        .desired_width(300.0)
                        .hint_text("example.com or app:firefox.exe"),
                );
                let entered =
                    response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.add_enabled(can_add, egui::Button::new("Add")).clicked()
                    || (can_add && entered)
                {
                    self.request_add();
                }
            });
            if self.busy() {
                ui.label(egui::RichText::new("Adding…").weak());
            } else if self.settings.seconds_remaining() < 30 {
                ui.label(
                    egui::RichText::new("Too close to the end of the block to add entries.").weak(),
                );
            }
        }

        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("There is no way to end the block early. That is the point.")
                .weak(),
        );
    }

    fn log_ui(&mut self, ui: &mut egui::Ui) {
        let path = logging::default_log_path();
        ui.horizontal(|ui| {
            ui.label("Log file:");
            ui.label(egui::RichText::new(path.display().to_string()).weak());
            if ui.small_button("Open").clicked() {
                open_path(&path);
            }
            if ui.small_button("Refresh").clicked() {
                self.refresh_log();
            }
        });
        egui::ScrollArea::vertical()
            .max_height(220.0)
            .stick_to_bottom(true)
            .id_salt("log_view")
            .show(ui, |ui| {
                if self.log_lines.is_empty() {
                    ui.label(egui::RichText::new("(log is empty)").weak());
                }
                for line in &self.log_lines {
                    ui.monospace(line);
                }
            });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_elevation(ctx);
        self.poll_direct(ctx);
        self.sync_settings();
        self.auto_expire(ctx);

        if self.busy() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }

        if cfg!(debug_assertions)
            && self.show_log
            && self.log_last_refresh.elapsed() > Duration::from_millis(800)
        {
            self.refresh_log();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                if self.settings.block_is_running {
                    self.running_ui(ui);
                } else {
                    self.start_ui(ui);
                }

                if let Some((msg, is_error)) = &self.status {
                    ui.add_space(10.0);
                    let color = if *is_error {
                        egui::Color32::from_rgb(230, 110, 110)
                    } else {
                        egui::Color32::from_rgb(120, 200, 140)
                    };
                    ui.colored_label(color, msg);
                }

                // Logging (and the log viewer) is a debug-build tool; release
                // binaries do not write a log file.
                if cfg!(debug_assertions) {
                    ui.add_space(8.0);
                    ui.separator();
                    ui.checkbox(&mut self.show_log, "Show log");
                    if self.show_log {
                        self.log_ui(ui);
                    }
                }
            });
        });

        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

/// Read the last `max` lines of a text file (best-effort, empty on error).
fn read_log_tail(path: &std::path::Path, max: usize) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
            if lines.len() > max {
                lines.drain(0..lines.len() - max);
            }
            lines
        }
        Err(_) => Vec::new(),
    }
}

/// Open a path/file with the OS default handler.
fn open_path(path: &std::path::Path) {
    // `.log` files frequently have no file association, in which case
    // `cmd /c start` silently does nothing. Notepad is always present and
    // reliably shows the text; fall back to revealing the file in Explorer.
    match std::process::Command::new("notepad.exe").arg(path).spawn() {
        Ok(_) => {}
        Err(e) => {
            log::warn!("could not launch notepad: {e}");
            if let Err(e) = std::process::Command::new("explorer.exe")
                .arg(format!("/select,{}", path.display()))
                .spawn()
            {
                log::warn!("could not launch explorer: {e}");
            }
        }
    }
}
