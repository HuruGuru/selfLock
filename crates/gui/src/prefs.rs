//! User-editable GUI preferences, stored in a user-writable location.

use selflock_core::paths;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct UiPrefs {
    pub blocklist_text: String,
    pub duration_minutes: u32,
    pub is_allowlist: bool,
    pub evaluate_common_subdomains: bool,
    pub include_linked_domains: bool,
    pub clear_caches: bool,
    pub allow_local_networks: bool,
    /// Optional application blocking (Windows Firewall `program=` rules).
    pub app_blocking_enabled: bool,
    pub app_blocklist_text: String,
}

impl Default for UiPrefs {
    fn default() -> Self {
        UiPrefs {
            blocklist_text: String::new(),
            duration_minutes: 60,
            is_allowlist: false,
            evaluate_common_subdomains: true,
            include_linked_domains: true,
            clear_caches: true,
            allow_local_networks: true,
            app_blocking_enabled: false,
            app_blocklist_text: String::new(),
        }
    }
}

impl UiPrefs {
    pub fn load() -> Self {
        let mut prefs: UiPrefs = std::fs::read_to_string(paths::user_prefs_file())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        // Allowlist blocks are a development-only feature.
        if !cfg!(debug_assertions) {
            prefs.is_allowlist = false;
        }
        prefs
    }

    pub fn save(&self) {
        let path = paths::user_prefs_file();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_string_pretty(self) {
            let _ = selflock_core::hosts::write_atomic(&path, text.as_bytes());
        }
    }
}
