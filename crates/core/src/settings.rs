//! Port of `SCSettings` — the block state + preferences, persisted to disk.
//!
//! The original keeps this in a root-owned plist with cross-process change
//! propagation. Here we store a JSON file in a protected directory, guarded by a
//! cross-process lock, and we *fail closed*: if the file exists but cannot be read
//! or parsed we refuse to pretend no block is running.

use crate::error::{Error, Result};
use crate::lock::FileLock;
use crate::paths;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn default_block_duration() -> u32 {
    60
}
fn default_max_block_length() -> u32 {
    // Seven days. The original defaults to 1440 (one day); this port allows a full
    // week so the day presets are usable out of the box.
    10080
}
fn default_schema_version() -> u32 {
    1
}

/// Settings + active block state. Field names/values mirror the original plist keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// On-disk format version, so future migrations can detect old files.
    pub schema_version: u32,

    // --- active block state ---
    pub block_end_date: Option<DateTime<Utc>>,
    pub active_blocklist: Vec<String>,
    pub active_block_as_whitelist: bool,
    pub block_is_running: bool,

    // --- block options (copied from defaults when a block starts) ---
    pub evaluate_common_subdomains: bool,
    pub include_linked_domains: bool,
    pub clear_caches: bool,
    pub allow_local_networks: bool,

    // --- user defaults (GUI) ---
    pub block_duration: u32,
    /// Maximum block length in minutes. Enforced when starting a block.
    pub max_block_length: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            schema_version: default_schema_version(),

            block_end_date: None,
            active_blocklist: Vec::new(),
            active_block_as_whitelist: false,
            block_is_running: false,

            evaluate_common_subdomains: true,
            include_linked_domains: true,
            clear_caches: true,
            allow_local_networks: true,

            block_duration: default_block_duration(),
            max_block_length: default_max_block_length(),
        }
    }
}

impl Settings {
    pub fn path() -> PathBuf {
        paths::settings_file()
    }

    /// Load settings from the default location.
    ///
    /// * A missing file is not an error (first run) and yields defaults.
    /// * A file that exists but cannot be read (permissions, I/O) is an error.
    /// * A file that exists but is not valid JSON is moved aside and reported as
    ///   [`Error::CorruptSettings`] rather than silently treated as "no block".
    pub fn load() -> Result<Self> {
        Self::load_from(Self::path())
    }

    pub fn load_from(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Settings::default()),
            Err(e) => return Err(e.into()),
        };
        match serde_json::from_str::<Settings>(&text) {
            Ok(s) => {
                log::trace!(
                    "settings: loaded {} (block_is_running={}, end_date={:?})",
                    path.display(),
                    s.block_is_running,
                    s.block_end_date
                );
                Ok(s)
            }
            Err(e) => {
                log::error!(
                    "settings: {} is not valid JSON ({e}); quarantining it",
                    path.display()
                );
                let quarantine = path.with_extension("json.corrupt");
                let _ = std::fs::rename(path, &quarantine);
                Err(Error::CorruptSettings(path.to_path_buf()))
            }
        }
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(Self::path())
    }

    pub fn save_to(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        // Wait for the cross-process lock instead of silently proceeding without it.
        let _lock = FileLock::acquire(paths::settings_lock_file(), Duration::from_secs(10))?;
        self.save_locked(path)
    }

    /// Read, mutate and write the settings while holding the cross-process lock.
    ///
    /// Use this instead of `load()` + `save()` for read-modify-write operations so
    /// two processes cannot overwrite each other's updates.
    pub fn update<F>(mutate: F) -> Result<Self>
    where
        F: FnOnce(&mut Self) -> Result<()>,
    {
        Self::update_at(Self::path(), mutate)
    }

    pub fn update_at<F>(path: impl AsRef<Path>, mutate: F) -> Result<Self>
    where
        F: FnOnce(&mut Self) -> Result<()>,
    {
        let path = path.as_ref();
        let _lock = FileLock::acquire(paths::settings_lock_file(), Duration::from_secs(10))?;
        let mut settings = Self::load_from(path)?;
        mutate(&mut settings)?;
        settings.save_locked(path)?;
        Ok(settings)
    }

    fn save_locked(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| crate::error::Error::other(e.to_string()))?;
        let result = crate::hosts::write_atomic(path, text.as_bytes());
        match &result {
            Ok(()) => log::info!(
                "settings: saved {} (block_is_running={}, entries={})",
                path.display(),
                self.block_is_running,
                self.active_blocklist.len()
            ),
            Err(e) => log::error!("settings: failed to save {}: {e}", path.display()),
        }
        result
    }

    /// True when a block is (to our knowledge) currently running.
    pub fn any_block_is_running(&self) -> bool {
        self.block_is_running
    }

    /// True when the stored block end date is in the past.
    pub fn current_block_is_expired(&self) -> bool {
        match self.block_end_date {
            Some(end) => end <= Utc::now(),
            None => true,
        }
    }

    /// Like [`Self::current_block_is_expired`], but with `tolerance` of slack.
    ///
    /// Task Scheduler stores whole seconds, so the auto-clear task can fire up to a
    /// second before the exact end; treating "about to end" as ended keeps that
    /// near-miss from delaying the clear by a whole repetition interval.
    pub fn block_is_expired_within(&self, tolerance: chrono::Duration) -> bool {
        match self.block_end_date {
            Some(end) => end <= Utc::now() + tolerance,
            None => true,
        }
    }

    /// Seconds remaining on the active block (0 when none/expired).
    pub fn seconds_remaining(&self) -> i64 {
        match self.block_end_date {
            Some(end) => (end - Utc::now()).num_seconds().max(0),
            None => 0,
        }
    }

    /// The maximum allowed block length in minutes (always at least 1).
    pub fn max_block_minutes(&self) -> u32 {
        self.max_block_length.max(1)
    }

    /// Clear the active-block fields (port of `+[SCBlockUtilities removeBlockFromSettings]`).
    pub fn remove_block_from_settings(&mut self) {
        self.block_is_running = false;
        self.block_end_date = None;
        self.active_blocklist.clear();
        self.active_block_as_whitelist = false;
    }

    /// Start a block, setting the fields the engine cares about.
    pub fn begin_block(
        &mut self,
        blocklist: Vec<String>,
        is_allowlist: bool,
        end_date: DateTime<Utc>,
    ) {
        self.active_blocklist = blocklist;
        self.active_block_as_whitelist = is_allowlist;
        self.block_end_date = Some(end_date);
        self.block_is_running = true;
    }

    /// Merge a block-start snapshot into the current on-disk settings.
    ///
    /// Block fields are always taken from `desired`. Other options are copied only
    /// when they have not changed since `baseline`, so an option edited by another
    /// process while this start was in flight is not overwritten with stale data.
    pub fn merge_block_start(&mut self, baseline: &Self, desired: &Self) {
        self.active_blocklist = desired.active_blocklist.clone();
        self.active_block_as_whitelist = desired.active_block_as_whitelist;
        self.block_end_date = desired.block_end_date;
        self.block_is_running = desired.block_is_running;

        if self.evaluate_common_subdomains == baseline.evaluate_common_subdomains {
            self.evaluate_common_subdomains = desired.evaluate_common_subdomains;
        }
        if self.include_linked_domains == baseline.include_linked_domains {
            self.include_linked_domains = desired.include_linked_domains;
        }
        if self.clear_caches == baseline.clear_caches {
            self.clear_caches = desired.clear_caches;
        }
        if self.allow_local_networks == baseline.allow_local_networks {
            self.allow_local_networks = desired.allow_local_networks;
        }
        if self.block_duration == baseline.block_duration {
            self.block_duration = desired.block_duration;
        }
        if self.max_block_length == baseline.max_block_length {
            self.max_block_length = desired.max_block_length;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sl-settings-{tag}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn defaults_round_trip() {
        let s = Settings::default();
        let json = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert!(back.evaluate_common_subdomains);
        assert_eq!(back.max_block_length, 10080);
    }

    #[test]
    fn missing_fields_fall_back_to_defaults() {
        let s: Settings = serde_json::from_str("{\"block_is_running\": true}").unwrap();
        assert!(s.block_is_running);
        assert!(s.evaluate_common_subdomains);
        assert!(s.clear_caches);
    }

    #[test]
    fn missing_file_is_default() {
        let path = temp_path("missing");
        let s = Settings::load_from(&path).unwrap();
        assert!(!s.block_is_running);
    }

    #[test]
    fn corrupt_file_is_quarantined_and_errors() {
        let path = temp_path("corrupt");
        std::fs::write(&path, "{ not json").unwrap();
        let err = Settings::load_from(&path).unwrap_err();
        assert!(matches!(err, Error::CorruptSettings(_)));
        assert!(!path.exists(), "corrupt file was not moved aside");
        assert!(path.with_extension("json.corrupt").exists());
        let _ = std::fs::remove_file(path.with_extension("json.corrupt"));
    }

    #[test]
    fn expired_when_no_end_date() {
        let s = Settings::default();
        assert!(s.current_block_is_expired());
    }

    #[test]
    fn expiry_tolerance_covers_an_early_trigger() {
        let mut s = Settings::default();
        // The auto-clear task can fire ~0.5 s early because Task Scheduler drops
        // sub-second precision; the tolerance must accept that but not a live block.
        s.begin_block(
            vec!["example.com".into()],
            false,
            Utc::now() + Duration::milliseconds(500),
        );
        assert!(!s.current_block_is_expired());
        assert!(s.block_is_expired_within(Duration::seconds(2)));

        s.begin_block(
            vec!["example.com".into()],
            false,
            Utc::now() + Duration::minutes(10),
        );
        assert!(!s.block_is_expired_within(Duration::seconds(2)));
    }

    #[test]
    fn merge_block_start_keeps_concurrent_option_changes() {
        let baseline = Settings::default();
        let mut desired = baseline.clone();
        desired.begin_block(
            vec!["example.com".into()],
            false,
            Utc::now() + Duration::minutes(10),
        );
        desired.evaluate_common_subdomains = false;

        // Another process changed include_linked_domains after our baseline.
        let mut current = baseline.clone();
        current.include_linked_domains = false;

        current.merge_block_start(&baseline, &desired);

        assert_eq!(current.active_blocklist, vec!["example.com".to_string()]);
        assert!(current.block_is_running);
        // Our unchanged option is merged...
        assert!(!current.evaluate_common_subdomains);
        // ...but the concurrent change is not overwritten.
        assert!(!current.include_linked_domains);
    }

    #[test]
    fn max_block_minutes_is_at_least_one() {
        let zero = Settings {
            max_block_length: 0,
            ..Settings::default()
        };
        assert_eq!(zero.max_block_minutes(), 1);
        let full = Settings {
            max_block_length: 1440,
            ..Settings::default()
        };
        assert_eq!(full.max_block_minutes(), 1440);
    }

    #[test]
    fn used_within_a_day() {
        let mut s = Settings::default();
        let now = Utc::now();
        s.begin_block(vec!["example.com".into()], false, now + Duration::hours(3));
        assert!(s.any_block_is_running());
        s.remove_block_from_settings();
        assert!(!s.any_block_is_running());
    }
}
