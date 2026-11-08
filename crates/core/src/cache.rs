//! Cache / DNS flushing, ported from the cache-clearing part of the daemon.
//!
//! The original daemon flushes the DNS cache and deletes browser cache folders
//! after installing a block so that already-cached pages become unreachable. This
//! is best-effort: every step logs what it did and never fails the block itself.

use crate::process::hidden_command;
use std::path::PathBuf;

/// Flush the OS DNS cache and clear known browser caches.
pub fn clear_caches() {
    log::info!("clearing DNS and browser caches");
    clear_dns_cache();
    clear_browser_caches();
}

fn run(program: &str, args: &[&str]) {
    log::info!("cache exec: {} {}", program, args.join(" "));
    match hidden_command(program).args(args).output() {
        Ok(output) if output.status.success() => {
            let out = String::from_utf8_lossy(&output.stdout);
            let out = out.trim();
            if out.is_empty() {
                log::info!("cache exec: {} -> ok", program);
            } else {
                log::info!("cache exec: {} -> ok: {}", program, out);
            }
        }
        Ok(output) => {
            let err = String::from_utf8_lossy(&output.stderr);
            log::warn!(
                "cache exec: {} exited {:?}: {}",
                program,
                output.status.code(),
                err.trim()
            );
        }
        Err(e) => log::warn!("cache exec: could not run {program}: {e}"),
    }
}

/// Flush the Windows resolver cache.
pub fn clear_dns_cache() {
    run("ipconfig", &["/flushdns"]);
}

fn remove_dir(path: &PathBuf) {
    if !path.exists() {
        return;
    }
    log::info!("cache: removing {}", path.display());
    match std::fs::remove_dir_all(path) {
        Ok(()) => log::info!("cache: removed {}", path.display()),
        Err(e) => log::warn!("cache: could not remove {}: {e}", path.display()),
    }
}

/// Delete the cache folders of common browsers for the current user.
pub fn clear_browser_caches() {
    if let Some(local) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
        for browser in [
            "Google\\Chrome",
            "Microsoft\\Edge",
            "BraveSoftware\\Brave-Browser",
            "Chromium",
        ] {
            let base = local.join(browser).join("User Data");
            // Only caches. `Default\Network` holds cookies / Local Storage —
            // deleting it would log the user out of every site.
            remove_dir(&base.join("Default").join("Cache"));
            remove_dir(&base.join("Default").join("Code Cache"));
        }
        let firefox = local.join("Mozilla\\Firefox\\Profiles");
        remove_firefox_profiles(&firefox);
    }
}

fn remove_firefox_profiles(profiles: &PathBuf) {
    if let Ok(entries) = std::fs::read_dir(profiles) {
        for entry in entries.flatten() {
            remove_dir(&entry.path().join("cache2"));
        }
    }
}
