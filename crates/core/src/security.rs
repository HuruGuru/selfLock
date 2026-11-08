//! Hardening of the privileged state directory.
//!
//! The secured settings and firewall state live in a shared location
//! (`%ProgramData%\SelfLock`). On a stock system that directory can be created
//! by an ordinary user before the app ever runs, which would let them plant files
//! the elevated process later trusts. Before we write anything there we make sure
//! only administrators can modify it.

use crate::error::{Error, Result};
use crate::process::hidden_command;
use std::path::Path;

/// Create `dir` if needed and restrict it so non-administrators cannot modify its
/// contents. Returns [`Error::InsecureDirectory`] if that cannot be guaranteed.
pub fn ensure_secure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    harden_windows(dir)
}

/// Re-ACL a directory so only SYSTEM and Administrators can write it, and ordinary
/// users get read-only access (the unprivileged GUI still needs to read the
/// settings). Inherited permissions from `%ProgramData%` are removed.
fn harden_windows(dir: &Path) -> Result<()> {
    // Well-known SIDs, so this works regardless of the display language.
    const SYSTEM: &str = "*S-1-5-18:(OI)(CI)F";
    const ADMINISTRATORS: &str = "*S-1-5-32-544:(OI)(CI)F";
    const USERS_READ: &str = "*S-1-5-32-545:(OI)(CI)R";

    let output = hidden_command("icacls")
        .arg(dir)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(SYSTEM)
        .arg(ADMINISTRATORS)
        .arg(USERS_READ)
        .output();

    match output {
        Ok(out) if out.status.success() => {
            log::info!("security: hardened ACL on {}", dir.display());
            Ok(())
        }
        Ok(out) => {
            let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
            log::warn!("security: could not harden {}: {msg}", dir.display());
            // We could not prove the directory is safe. Refuse to continue rather
            // than write sensitive state into a world-writable location.
            Err(Error::InsecureDirectory(dir.to_path_buf()))
        }
        Err(e) => {
            log::warn!("security: could not run icacls: {e}");
            Err(Error::InsecureDirectory(dir.to_path_buf()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_directory() {
        let dir = std::env::temp_dir().join(format!(
            "sl-secure-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        ensure_secure_dir(&dir).unwrap();
        assert!(dir.is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
