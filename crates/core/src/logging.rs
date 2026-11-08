//! Minimal file + stderr logger shared by the CLI and GUI.
//!
//! The elevated CLI runs without a usable console (its window closes or is
//! suppressed), so every diagnostic must land in a file the GUI can show. This
//! logger writes the same formatted line to an append-only log file and,
//! optionally, to stderr.

use log::{LevelFilter, Log, Metadata, Record};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

struct FileLogger {
    file: Mutex<Option<std::fs::File>>,
    stderr: bool,
    level: LevelFilter,
}

impl Log for FileLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let line = format!(
            "{ts} {:<5} [{}] {}\n",
            record.level(),
            record.target(),
            record.args()
        );
        if self.stderr {
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
        if let Ok(mut guard) = self.file.lock() {
            if let Some(file) = guard.as_mut() {
                // `File` writes go straight to the OS; no per-line flush needed.
                let _ = file.write_all(line.as_bytes());
            }
        }
    }

    fn flush(&self) {
        if let Ok(mut guard) = self.file.lock() {
            if let Some(file) = guard.as_mut() {
                let _ = file.flush();
            }
        }
    }
}

/// Parse a level name (`error`/`warn`/`info`/`debug`/`trace`/`off`).
pub fn parse_level(value: &str) -> LevelFilter {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => LevelFilter::Off,
        "error" => LevelFilter::Error,
        "warn" | "warning" => LevelFilter::Warn,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    }
}

/// Resolve the log file: explicit path, then `$SELFLOCK_LOG_FILE`, then the
/// per-user default.
pub fn resolve_log_path(explicit: Option<PathBuf>) -> PathBuf {
    explicit
        .or_else(|| std::env::var_os("SELFLOCK_LOG_FILE").map(PathBuf::from))
        .unwrap_or_else(crate::paths::user_log_file)
}

/// The effective log file path for the current process (no side effects).
pub fn default_log_path() -> PathBuf {
    resolve_log_path(None)
}

/// Maximum log size before it is truncated on startup (1 MiB).
const MAX_LOG_BYTES: u64 = 1 << 20;

/// Initialize the global logger. Safe to call multiple times; only the first call
/// installs a logger.
pub fn init(path: &Path, level: LevelFilter, stderr: bool) {
    init_with_force(path, level, stderr, false);
}

/// Like [`init`], but `force` enables logging in a release build even when
/// `SELFLOCK_LOG` is unset.
///
/// The CLI sets it when `--log-file` was passed explicitly: the scheduled
/// auto-clear runs with no visible window, so without a log an invisible run would
/// leave no trace at all. The GUI does not force it, so a release GUI stays quiet.
pub fn init_with_force(path: &Path, level: LevelFilter, stderr: bool, force: bool) {
    // Release binaries do not log by default: no log file is created and nothing is
    // written to stderr. Setting `SELFLOCK_LOG=<level>` (e.g. `debug`) opts back in.
    let level = match std::env::var("SELFLOCK_LOG").ok().map(|v| parse_level(&v)) {
        Some(explicit) => explicit,
        // Development builds are for diagnosis: always log at least debug, even if
        // the caller asked for info. `SELFLOCK_LOG=off` still wins if set.
        None if cfg!(debug_assertions) => level.max(LevelFilter::Debug),
        None if force => level,
        None => LevelFilter::Off,
    };
    if level == LevelFilter::Off {
        log::set_max_level(LevelFilter::Off);
        return;
    }

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Keep the log from growing without bound across runs: rotate the previous log
    // to `<name>.1` (one generation) instead of silently wiping it.
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_LOG_BYTES {
            let rotated = path.with_extension("log.1");
            let _ = std::fs::remove_file(&rotated);
            let _ = std::fs::rename(path, &rotated);
        }
    }
    let file = OpenOptions::new().create(true).append(true).open(path).ok();
    let logger = FileLogger {
        file: Mutex::new(file),
        stderr,
        level,
    };
    if log::set_boxed_logger(Box::new(logger)).is_ok() {
        log::set_max_level(level);
    }
}

/// Convenience initializer with an info-level default.
pub fn init_default(explicit: Option<PathBuf>, stderr: bool) {
    let path = resolve_log_path(explicit);
    init(&path, LevelFilter::Info, stderr);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_parsing() {
        assert_eq!(parse_level("DEBUG"), LevelFilter::Debug);
        assert_eq!(parse_level(" nonsense "), LevelFilter::Info);
        assert_eq!(parse_level("off"), LevelFilter::Off);
    }
}
