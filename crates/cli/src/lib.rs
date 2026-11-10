//! `selflock-cli` logic, shared between the standalone CLI binary and the GUI
//! executable's hidden CLI mode (used for elevation and the auto-clear task).
//!
//! A port of `cli-main.m`.

use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand};
use selflock_core::blocklist_file;
use selflock_core::cleaner::{clean_blocklist, clean_blocklist_entry};
use selflock_core::elevation::is_elevated;
use selflock_core::manager::BlockManager;
use selflock_core::scheduler;
use selflock_core::security;
use selflock_core::settings::Settings;
use selflock_core::{logging, paths, Error, VERSION};
use std::collections::HashSet;
use std::path::PathBuf;

// sysexits.h-style exit codes, matching the original CLI.
const EX_USAGE: u8 = 64;
const EX_SOFTWARE: u8 = 70;
const EX_UNAVAILABLE: u8 = 69;
const EX_IOERR: u8 = 74;
const EX_CONFIG: u8 = 78;

/// Parsed block source: `(blocklist, is_allowlist, end_date)`.
type BlockSource = Result<(Vec<String>, bool, Option<DateTime<Utc>>), u8>;

/// An `add` is refused when the block has less than this left, so the request and
/// the scheduled auto-clear cannot race over the same rules.
const MIN_REMAINING_SECONDS: i64 = 30;

/// A scheduled trigger can fire a fraction of a second early because Task
/// Scheduler stores whole seconds, so treat "about to expire" as expired.
const EXPIRY_TOLERANCE_SECONDS: i64 = 2;

/// Clean the requested entries and drop any that the active block already covers.
fn new_entries(active: &[String], requested: &[String]) -> Vec<String> {
    let mut seen: HashSet<String> = active.iter().cloned().collect();
    let mut out = Vec::new();
    for raw in requested {
        for cleaned in clean_blocklist_entry(raw) {
            if seen.insert(cleaned.clone()) {
                out.push(cleaned);
            }
        }
    }
    out
}

/// What a `remove` request should do, decided before touching the firewall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RemovalDecision {
    /// The block is over, or `--if-expired` was not requested: clear it.
    Clear,
    /// `--if-expired` was given and the block still has time left: do nothing.
    NotExpired,
    /// `--if-expired` was given and no block is running: drop a stale task.
    NoBlock,
}

/// Apply the `--if-expired` guard to the stored block state.
fn removal_decision(settings: &Settings, if_expired: bool) -> RemovalDecision {
    if !if_expired {
        return RemovalDecision::Clear;
    }
    if !settings.block_is_running {
        return RemovalDecision::NoBlock;
    }
    if settings.block_is_expired_within(Duration::seconds(EXPIRY_TOLERANCE_SECONDS)) {
        RemovalDecision::Clear
    } else {
        RemovalDecision::NotExpired
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "selflock-cli",
    version = VERSION,
    about = "SelfLock CLI — start and inspect self-enforced blocks"
)]
struct Cli {
    /// Write diagnostics to this file instead of the default user log.
    #[arg(long = "log-file", global = true)]
    log_file: Option<PathBuf>,

    /// Internal marker: set when the CLI runs inside the GUI executable. Ignored.
    #[arg(long = "cli", hide = true, global = true)]
    cli_mode: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start a SelfLock block.
    #[command(alias = "install")]
    Start(StartArgs),
    /// Print YES if a block is currently running, NO otherwise.
    #[command(name = "is-running", alias = "isrunning")]
    IsRunning,
    /// Print the current secured settings (for debugging).
    #[command(name = "print-settings", alias = "printsettings")]
    PrintSettings,
    /// Print the CLI version.
    #[command(name = "version")]
    Version,
    /// Attempt to remove a block (generally refused; requires `--force`).
    Remove(RemoveArgs),
    /// Add entries to a block that is already running.
    Add(AddArgs),
}

#[derive(Parser, Debug)]
struct StartArgs {
    /// Path to a saved `.selflock` blocklist file.
    #[arg(long, short = 'b')]
    blocklist: Option<PathBuf>,

    /// Block end date in ISO-8601 / RFC-3339 format (e.g. 2026-10-18T22:00:00Z).
    #[arg(long, short = 'd')]
    enddate: Option<String>,

    /// Other block settings, as a JSON object string.
    #[arg(long, short = 's')]
    settings: Option<String>,

    /// Other block settings, read from a JSON file (used by the GUI to avoid
    /// shell-quoting issues).
    #[arg(long = "settings-file", hide = true)]
    settings_file: Option<PathBuf>,

    /// Block an application (image name or full path) with a Windows Firewall
    /// `program=` rule. Repeat for several applications.
    #[arg(long = "app", value_name = "EXE")]
    app: Vec<String>,
}

#[derive(Parser, Debug)]
struct RemoveArgs {
    /// Force-remove the block even if it hasn't expired (dangerous).
    #[arg(long)]
    force: bool,

    /// Only clear the block if its end date has already passed.
    ///
    /// The scheduled auto-clear always passes this, so its repeated / logon
    /// triggers can never lift a block that is still supposed to be running.
    #[arg(long = "if-expired")]
    if_expired: bool,
}

#[derive(Parser, Debug)]
struct AddArgs {
    /// Path to a saved `.selflock` blocklist file with the entries to add.
    #[arg(long, short = 'b')]
    blocklist: Option<PathBuf>,

    /// Add an application (image name or full path) to the block. Repeat for
    /// several applications.
    #[arg(long = "app", value_name = "EXE")]
    app: Vec<String>,
}

/// Run the CLI using the current process arguments.
pub fn run_from_env() -> u8 {
    run(std::env::args().collect())
}

/// Run the CLI with an explicit argument list (including argv[0]).
pub fn run(args: Vec<String>) -> u8 {
    // Do this first so any console window disappears before it draws.
    selflock_core::platform::hide_private_console();

    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return EX_USAGE;
        }
    };
    let _ = cli.cli_mode;

    let log_path = logging::resolve_log_path(cli.log_file.clone());
    // An explicit `--log-file` opts into logging even in a release build: the
    // scheduled auto-clear passes one, so its invisible runs still leave a trace.
    logging::init_with_force(
        &log_path,
        log::LevelFilter::Info,
        true,
        cli.log_file.is_some(),
    );
    log::info!(
        "=== selflock {} CLI mode started (elevated={}) ===",
        VERSION,
        is_elevated()
    );
    log::info!("args: {:?}", args);
    log::info!("log file: {}", log_path.display());
    if cfg!(debug_assertions) {
        log::debug!("verbose logging enabled (development build)");
    }

    match cli.command {
        Some(Commands::Start(args)) => cmd_start(args, &log_path),
        Some(Commands::IsRunning) => cmd_is_running(),
        Some(Commands::PrintSettings) => cmd_print_settings(),
        Some(Commands::Version) => {
            println!("{VERSION}");
            0
        }
        Some(Commands::Remove(args)) => cmd_remove(args, &log_path),
        Some(Commands::Add(args)) => cmd_add(args, &log_path),
        None => {
            print_help();
            0
        }
    }
}

fn cmd_start(args: StartArgs, log_path: &std::path::Path) -> u8 {
    let mut settings = match Settings::load() {
        Ok(s) => s,
        Err(e) => return fail("could not load settings", e),
    };

    if settings.any_block_is_running() {
        eprintln!("ERROR: Block is already running");
        return EX_CONFIG;
    }

    // Determine blocklist / end date / allowlist.
    let (mut blocklist, is_allowlist, end_date) = match resolve_block_source(&args, &settings) {
        Ok(v) => v,
        Err(code) => return code,
    };
    // Allowlist blocks are a development-only feature. Refuse them loudly instead
    // of silently turning "allow only X" into "block X".
    if is_allowlist && !cfg!(debug_assertions) {
        eprintln!("ERROR: allowlist blocks are not supported in release builds.");
        log::error!("start: allowlist requested in a release build");
        return EX_CONFIG;
    }

    // `--app` entries are additive and use the same `app:` syntax as the GUI and
    // saved blocklists. They are cleaned here (not by the hostname sanitizer).
    for spec in &args.app {
        for cleaned in clean_blocklist_entry(&format!("app:{spec}")) {
            if !blocklist.contains(&cleaned) {
                blocklist.push(cleaned);
            }
        }
    }

    let end_date = match end_date {
        Some(d) if d > Utc::now() => d,
        _ => {
            eprintln!("ERROR: Block end date must be in the future");
            return EX_CONFIG;
        }
    };

    if blocklist.is_empty() && !is_allowlist {
        eprintln!("ERROR: Blocklist is empty");
        return EX_CONFIG;
    }

    // Apply JSON settings overrides on top of the defaults.
    let settings_json = match read_settings_override(&args) {
        Ok(v) => v,
        Err(code) => return code,
    };
    // Snapshot before applying this invocation's overrides, so the update below can
    // tell our changes apart from a concurrent process's changes.
    let baseline = settings.clone();
    if let Some(json) = &settings_json {
        if let Err(e) = apply_settings_json(&mut settings, json) {
            eprintln!("ERROR: Failed to parse JSON settings: {e}");
            log::error!("failed to parse JSON settings: {e}");
            return EX_USAGE;
        }
    }

    // Enforce the configured maximum block length.
    let max_minutes = settings.max_block_minutes() as i64;
    let requested_minutes = (end_date - Utc::now()).num_minutes();
    if requested_minutes > max_minutes {
        eprintln!(
            "ERROR: Block length ({requested_minutes} min) exceeds the configured maximum ({max_minutes} min)."
        );
        return EX_CONFIG;
    }

    // Never write privileged state into a location a non-administrator can modify.
    if let Err(e) = security::ensure_secure_dir(&paths::config_dir()) {
        eprintln!("ERROR: refusing to use the secured settings directory: {e}");
        log::error!("secured settings directory is not secure: {e}");
        return EX_CONFIG;
    }

    if !is_elevated() {
        eprintln!(
            "WARNING: not running with administrator privileges; firewall and hosts edits will likely fail."
        );
    }

    log::info!(
        "start: allowlist={is_allowlist}, entries={}, end_date={}, settings={:?}",
        blocklist.len(),
        end_date.to_rfc3339(),
        settings_json
    );
    // The effective list is what the manager will parse; `app:` entries in it are
    // the usual cause of an otherwise mysterious start failure.
    log::info!("start: blocklist = {blocklist:?}");

    // Persist the block state *before* touching the system. If the process dies
    // during the firewall/hosts work, the block is still tracked and can be
    // removed (fail closed), rather than leaving untracked rules behind.
    //
    // The check-and-set happens under the settings lock so two concurrent starts
    // cannot both believe the machine is idle.
    let mut desired = settings.clone();
    desired.begin_block(blocklist.clone(), is_allowlist, end_date);
    settings = match Settings::update(|current| {
        if current.block_is_running {
            return Err(Error::other("block is already running"));
        }
        current.merge_block_start(&baseline, &desired);
        Ok(())
    }) {
        Ok(updated) => updated,
        Err(e) => {
            eprintln!("ERROR: could not persist settings: {e}");
            log::error!("could not persist settings before start: {e}");
            return EX_SOFTWARE;
        }
    };

    let mut manager = BlockManager::new(
        is_allowlist,
        settings.allow_local_networks,
        settings.evaluate_common_subdomains,
        settings.include_linked_domains,
    );

    println!("Adding firewall rules...");
    if let Err(e) = manager.start_block_from_strings(&blocklist) {
        log::error!("failed to start block: {e}");
        if manager.block_is_active() {
            // Rollback was incomplete: keep the persisted state so the GUI and the
            // scheduled task can still clear the partial block.
            log::error!("start failed but rules are still active; keeping block state");
        } else {
            settings.remove_block_from_settings();
            if let Err(save_err) = settings.save() {
                log::error!("could not roll back settings after failed start: {save_err}");
            }
        }
        if e.is_permission_denied() {
            eprintln!("ERROR: Permission denied. Re-run with administrator privileges.");
        } else {
            eprintln!("ERROR: Failed to start block: {e}");
        }
        eprintln!("See log for details: {}", log_path.display());
        return EX_SOFTWARE;
    }

    // Browser/DNS cache clearing is intentionally NOT done here: this runs as a
    // privileged process, and caches live in the unprivileged user profile. The GUI
    // clears them itself after a successful start.

    // Register the automatic clear so the block lifts even if nothing is running.
    if let Ok(cli_path) = std::env::current_exe() {
        // `--cli` makes the shipped GUI executable run in CLI mode rather than
        // opening a second window.
        let args = vec![
            "--cli".to_string(),
            "remove".to_string(),
            "--force".to_string(),
            "--if-expired".to_string(),
            "--log-file".to_string(),
            log_path.display().to_string(),
        ];
        if let Err(e) = scheduler::schedule_clear(&cli_path, &args, end_date) {
            log::warn!("could not schedule automatic clear: {e}");
        }
    }

    log::info!(
        "start: SUCCESS ({} firewall rules, {} hosts rules)",
        manager.firewall_rule_count(),
        manager.hosts_rule_count()
    );
    println!(
        "INFO: Block successfully added ({} firewall rules, {} hosts rules, {} application rules). Ends at {}.",
        manager.firewall_rule_count(),
        manager.hosts_rule_count(),
        manager.app_rule_count(),
        end_date.to_rfc3339()
    );
    0
}

/// Add entries to an already-running block (the CLI half of the GUI's "Add to
/// block" panel).
///
/// This is the Windows equivalent of the original's `updateBlocklist`: the block
/// end date does not change, allowlist blocks are refused, and only new entries are
/// applied. It never rebuilds the block, so the network is not opened even briefly
/// and the original hosts backup is preserved.
fn cmd_add(args: AddArgs, log_path: &std::path::Path) -> u8 {
    if !is_elevated() {
        eprintln!("ERROR: adding entries to a block requires administrator privileges.");
        return EX_UNAVAILABLE;
    }

    let settings = match Settings::load() {
        Ok(s) => s,
        Err(e) => return fail("could not load settings", e),
    };

    if !settings.block_is_running {
        eprintln!("ERROR: No block is running.");
        return EX_CONFIG;
    }
    if settings.active_block_as_whitelist {
        eprintln!("ERROR: Entries cannot be added to an allowlist block.");
        return EX_CONFIG;
    }
    if settings.current_block_is_expired() {
        eprintln!("ERROR: The block has already expired and is being cleared.");
        return EX_CONFIG;
    }
    if let Some(end) = settings.block_end_date {
        let remaining = (end - Utc::now()).num_seconds();
        if remaining < MIN_REMAINING_SECONDS {
            eprintln!(
                "ERROR: The block ends in {remaining}s; too close to the end to add entries."
            );
            return EX_CONFIG;
        }
    }

    let mut requested: Vec<String> = Vec::new();
    if let Some(path) = &args.blocklist {
        match blocklist_file::read_from_path(path) {
            Ok(file) => requested.extend(file.blocklist),
            Err(e) => return fail("could not read the blocklist", e),
        }
    }
    for spec in &args.app {
        requested.push(format!("app:{spec}"));
    }

    let new = new_entries(&settings.active_blocklist, &requested);
    if new.is_empty() {
        println!("INFO: Nothing to add; the block already covers these entries.");
        return 0;
    }

    if let Err(e) = security::ensure_secure_dir(&paths::config_dir()) {
        eprintln!("ERROR: refusing to use the secured settings directory: {e}");
        log::error!("secured settings directory is not secure: {e}");
        return EX_CONFIG;
    }

    log::info!("add: adding {} entr(y/ies): {:?}", new.len(), new);

    let mut manager = BlockManager::new(
        false,
        settings.allow_local_networks,
        settings.evaluate_common_subdomains,
        settings.include_linked_domains,
    );
    // Entries already covered by the block (including common subdomains) must not
    // be written twice.
    manager.seed_blocked(&settings.active_blocklist);

    let report = match manager.append_block_from_strings(&new) {
        Ok(r) => r,
        Err(e) => {
            log::error!("add: failed to add entries: {e}");
            eprintln!("ERROR: Failed to add entries: {e}");
            eprintln!("See log for details: {}", log_path.display());
            return EX_SOFTWARE;
        }
    };

    // Re-read under the settings lock and append, so a concurrent add/clear cannot
    // be overwritten by this process's older snapshot.
    if let Err(e) = Settings::update(|current| {
        if !current.block_is_running {
            return Err(Error::other(
                "block is no longer running; not persisting the added entries",
            ));
        }
        current.active_blocklist.extend(new.iter().cloned());
        Ok(())
    }) {
        eprintln!("WARNING: entries were applied but could not be persisted: {e}");
        log::warn!("add: could not persist settings: {e}");
    }

    println!(
        "INFO: Added {} entr(y/ies) to the block ({} firewall rules, {} hosts rules, {} application rules).",
        new.len(),
        report.firewall_rules,
        report.hosts_rules,
        report.app_rules
    );
    0
}

/// Read block-setting overrides from `--settings-file` (preferred) or `--settings`.
fn read_settings_override(args: &StartArgs) -> Result<Option<String>, u8> {
    if let Some(path) = &args.settings_file {
        match std::fs::read_to_string(path) {
            Ok(text) => return Ok(Some(text)),
            Err(e) => {
                eprintln!(
                    "ERROR: could not read settings file {}: {e}",
                    path.display()
                );
                log::error!("could not read settings file {}: {e}", path.display());
                return Err(EX_IOERR);
            }
        }
    }
    Ok(args.settings.clone())
}

/// Return `(blocklist, is_allowlist, end_date_or_none)`.
fn resolve_block_source(args: &StartArgs, settings: &Settings) -> BlockSource {
    let end_date = args.enddate.as_deref().and_then(parse_date);

    if let Some(path) = &args.blocklist {
        match blocklist_file::read_from_path(path) {
            Ok(file) => {
                return Ok((
                    clean_blocklist(&file.blocklist),
                    file.block_as_whitelist,
                    end_date,
                ));
            }
            Err(_) => {
                eprintln!(
                    "ERROR: Block could not be read from file {}",
                    path.display()
                );
                return Err(EX_IOERR);
            }
        }
    }

    // Fall back to defaults stored in settings (legacy behaviour).
    let list = clean_blocklist(&settings.active_blocklist);
    let duration = Duration::minutes(settings.block_duration as i64);
    let end = end_date.or_else(|| Some(Utc::now() + duration.max(Duration::seconds(1))));
    Ok((list, settings.active_block_as_whitelist, end))
}

fn parse_date(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

fn apply_settings_json(settings: &mut Settings, json: &str) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let obj = value.as_object().ok_or("settings must be a JSON object")?;
    for (key, val) in obj {
        match key.as_str() {
            "ClearCaches" => settings.clear_caches = val.as_bool().unwrap_or(settings.clear_caches),
            "AllowLocalNetworks" => {
                settings.allow_local_networks =
                    val.as_bool().unwrap_or(settings.allow_local_networks)
            }
            "EvaluateCommonSubdomains" => {
                settings.evaluate_common_subdomains =
                    val.as_bool().unwrap_or(settings.evaluate_common_subdomains)
            }
            "IncludeLinkedDomains" => {
                settings.include_linked_domains =
                    val.as_bool().unwrap_or(settings.include_linked_domains)
            }
            "MaxBlockLength" => {
                settings.max_block_length =
                    val.as_u64().unwrap_or(settings.max_block_length as u64) as u32
            }
            _ => {}
        }
    }
    Ok(())
}

fn cmd_is_running() -> u8 {
    match Settings::load() {
        Ok(s) => {
            println!(
                "{}",
                if s.any_block_is_running() {
                    "YES"
                } else {
                    "NO"
                }
            );
            0
        }
        Err(e) => fail("could not load settings", e),
    }
}

fn cmd_print_settings() -> u8 {
    match Settings::load() {
        Ok(s) => {
            println!(" - Printing SelfLock secured settings for debug: - ");
            match serde_json::to_string_pretty(&s) {
                Ok(json) => {
                    println!("{json}");
                    0
                }
                Err(e) => fail("could not serialize settings", e),
            }
        }
        Err(e) => fail("could not load settings", e),
    }
}

fn cmd_remove(args: RemoveArgs, _log_path: &std::path::Path) -> u8 {
    if !args.force {
        // The original deliberately refuses removal while a block is running.
        println!("INFO: Nice try.");
        return EX_UNAVAILABLE;
    }

    // Force-removal edits the firewall and hosts file, which needs elevation. We
    // refuse otherwise so the block cannot be lifted by a casual unprivileged call
    // (`selflock --cli remove --force`). The scheduled auto-clear and the GUI's
    // elevation helper both run this elevated.
    if !is_elevated() {
        eprintln!("ERROR: removing a block requires administrator privileges.");
        return EX_UNAVAILABLE;
    }

    // Clearing must not depend on a readable settings file: a corrupt or missing
    // file is exactly when the user most needs a way out. Keep the error only for
    // logging and carry on with defaults.
    let (mut settings, settings_unreadable) = match Settings::load() {
        Ok(s) => (s, false),
        Err(e) => {
            log::error!(
                "remove: settings unreadable ({e}); continuing with defaults — clearing must not depend on readable settings"
            );
            (Settings::default(), true)
        }
    };

    if let Err(e) = security::ensure_secure_dir(&paths::config_dir()) {
        eprintln!("ERROR: refusing to use the secured settings directory: {e}");
        log::error!("secured settings directory is not secure: {e}");
        return EX_CONFIG;
    }

    // The scheduled auto-clear fires on a repeating timer, at logon, and possibly
    // again after a resume. Only an actually expired block may be lifted. If the
    // settings file was unreadable we cannot know the end date, so the explicit
    // elevated removal is allowed to clear the rules.
    if !settings_unreadable {
        match removal_decision(&settings, args.if_expired) {
            RemovalDecision::Clear => {}
            RemovalDecision::NotExpired => {
                log::info!(
                    "remove: --if-expired, block still runs until {:?}; nothing to do",
                    settings.block_end_date
                );
                println!("INFO: The block has not expired yet; leaving it in place.");
                return 0;
            }
            RemovalDecision::NoBlock => {
                // Settings can be stale. Check the actual system state before
                // declaring that there is nothing to clear.
                let mut manager = BlockManager::new(
                    settings.active_block_as_whitelist,
                    settings.allow_local_networks,
                    settings.evaluate_common_subdomains,
                    settings.include_linked_domains,
                );
                if manager.block_is_active() {
                    log::warn!("remove: settings claim no block, but rules are present; clearing");
                    if !manager.clear_block(true) {
                        eprintln!(
                            "ERROR: Block could not be fully cleared. Retry or inspect the log."
                        );
                        return EX_SOFTWARE;
                    }
                    settings.remove_block_from_settings();
                    if let Err(e) = settings.save() {
                        eprintln!("WARNING: could not persist settings: {e}");
                    }
                }
                // A task left over from a block that was cleared some other way
                // would otherwise keep firing every few minutes until its
                // repetition window ends. Only drop it once the rules are gone.
                log::info!(
                    "remove: --if-expired and no block is running; dropping stale auto-clear"
                );
                if let Err(e) = scheduler::cancel_clear() {
                    log::warn!("could not remove stale auto-clear task: {e}");
                }
                println!("INFO: No block is running.");
                return 0;
            }
        }
    }

    log::info!("remove: force-clearing block");
    let mut manager = BlockManager::new(
        settings.active_block_as_whitelist,
        settings.allow_local_networks,
        settings.evaluate_common_subdomains,
        settings.include_linked_domains,
    );
    let cleared = manager.clear_block(true);
    if !cleared {
        // Keep both the state and the auto-clear task: the block is still visible
        // and a later run can retry instead of pretending everything is fine.
        eprintln!("ERROR: Block could not be fully cleared. Retry or inspect the log.");
        log::error!("remove: clear_block failed; keeping block state and auto-clear task");
        return EX_SOFTWARE;
    }

    // Drop our own auto-clear task only after the rules are actually gone.
    if let Err(e) = scheduler::cancel_clear() {
        log::warn!("could not cancel auto-clear task: {e}");
    }

    settings.remove_block_from_settings();
    if let Err(e) = settings.save() {
        eprintln!("WARNING: could not persist settings: {e}");
    }

    println!("INFO: Block cleared.");
    0
}

fn fail(context: &str, err: impl std::fmt::Display) -> u8 {
    eprintln!("ERROR: {context}: {err}");
    log::error!("{context}: {err}");
    EX_SOFTWARE
}

fn print_help() {
    println!("SelfLock CLI Tool v{VERSION}");
    println!("Usage: selflock-cli <command> [<args>]");
    println!();
    println!("Valid commands:");
    println!();
    println!("    start --> starts a SelfLock block");
    println!("        --blocklist <path to saved blocklist file>");
    println!("        --enddate <end date for block in ISO8601 format>");
    println!("        --settings <other block settings in JSON format>");
    println!("        --app <exe name or full path> (repeatable)");
    println!();
    println!("    is-running --> prints YES if a block is running, NO otherwise");
    println!();
    println!("    print-settings --> prints the current secured settings");
    println!();
    println!("    version --> prints the version of the SelfLock CLI tool");
    println!();
    println!("    remove [--force] [--if-expired] --> attempts to remove the active block");
    println!();
    println!("    add [--blocklist <path>] [--app <exe>] --> add entries to a running block");
    println!();
    println!(
        "Example: selflock-cli start --blocklist /path/to/blocklist.selflock --enddate 2026-10-18T22:00:00Z"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(running: bool, end: Option<DateTime<Utc>>) -> Settings {
        Settings {
            block_is_running: running,
            block_end_date: end,
            ..Settings::default()
        }
    }

    #[test]
    fn without_if_expired_a_block_is_always_cleared() {
        let future = Utc::now() + Duration::minutes(30);
        assert_eq!(
            removal_decision(&settings(true, Some(future)), false),
            RemovalDecision::Clear
        );
        assert_eq!(
            removal_decision(&settings(false, None), false),
            RemovalDecision::Clear
        );
    }

    #[test]
    fn if_expired_leaves_a_live_block_alone() {
        let future = Utc::now() + Duration::minutes(30);
        assert_eq!(
            removal_decision(&settings(true, Some(future)), true),
            RemovalDecision::NotExpired
        );
    }

    #[test]
    fn if_expired_clears_an_expired_block() {
        let past = Utc::now() - Duration::minutes(1);
        assert_eq!(
            removal_decision(&settings(true, Some(past)), true),
            RemovalDecision::Clear
        );
        // A running block with no end date is treated as expired (fail open only
        // to clearing, never to blocking).
        assert_eq!(
            removal_decision(&settings(true, None), true),
            RemovalDecision::Clear
        );
    }

    #[test]
    fn if_expired_without_a_block_cleans_up() {
        assert_eq!(
            removal_decision(&settings(false, None), true),
            RemovalDecision::NoBlock
        );
    }

    #[test]
    fn new_entries_cleans_and_dedupes_against_the_active_block() {
        let active = vec!["youtube.com".to_string(), "app:firefox.exe".to_string()];
        let requested = vec![
            " YouTube.com ".to_string(),
            "twitch.tv".to_string(),
            "https://twitch.tv/path".to_string(),
            "app:firefox.exe".to_string(),
            "app:chrome.exe".to_string(),
        ];
        assert_eq!(
            new_entries(&active, &requested),
            vec!["twitch.tv".to_string(), "app:chrome.exe".to_string()]
        );
    }

    #[test]
    fn new_entries_is_empty_for_duplicates_only() {
        let active = vec!["a.example".to_string()];
        assert!(new_entries(&active, &["a.example".to_string()]).is_empty());
        assert!(new_entries(&[], &["   ".to_string()]).is_empty());
    }
}
