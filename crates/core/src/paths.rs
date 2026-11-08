//! Windows locations for the secured settings store and per-user data.
//!
//! Mirrors the original protected settings store, but uses the standard Windows
//! directories (`%ProgramData%` and `%APPDATA%`).

use std::path::PathBuf;

/// Directory holding the secured settings file (requires elevation to write).
pub fn config_dir() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    PathBuf::from(base).join("SelfLock")
}

/// Path to the secured settings file.
pub fn settings_file() -> PathBuf {
    config_dir().join("settings.json")
}

/// Path to the current (editable) blocklist file.
pub fn blocklist_file() -> PathBuf {
    config_dir().join("blocklist.selflock")
}

/// Path to the cross-process lock guarding the secured settings file.
pub fn settings_lock_file() -> PathBuf {
    config_dir().join("settings.lock")
}

/// Path to the user-writable log file. Used by the GUI and CLI so that both the
/// unprivileged and the elevated process write to the same, readable file.
pub fn user_log_file() -> PathBuf {
    user_config_dir().join("selflock.log")
}

/// A user-writable directory for GUI preferences and saved blocklists (does not
/// require elevation).
pub fn user_config_dir() -> PathBuf {
    let base = std::env::var("APPDATA")
        .unwrap_or_else(|_| std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into()));
    PathBuf::from(base).join("SelfLock")
}

/// Path to the user's saved GUI preferences.
pub fn user_prefs_file() -> PathBuf {
    user_config_dir().join("prefs.json")
}
