//! A small cross-process advisory file lock.
//!
//! Several processes (the GUI, the elevated CLI helper, the scheduled auto-clear
//! task) read and write the same settings file without any coordination. This lock
//! serializes access so a read-modify-write can't interleave.

use crate::error::{Error, Result};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

/// An exclusive lock held for as long as the value is alive.
///
/// The handle is kept only to hold the OS lock (it is never otherwise read), so it
/// is deliberately not exposed.
pub struct FileLock {
    #[allow(dead_code)]
    file: fs::File,
}

impl FileLock {
    /// Try to take the lock at `path`, returning `None` if another process holds it.
    pub fn try_acquire(path: impl AsRef<Path>) -> Option<Self> {
        use std::os::windows::fs::OpenOptionsExt;

        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut opts = fs::OpenOptions::new();
        opts.create(true).write(true).truncate(false);
        // A share mode of 0 means no other process may open the file while we
        // hold this handle — an OS-enforced exclusive lock.
        opts.share_mode(0);
        let file = opts.open(path).ok()?;
        Some(FileLock { file })
    }

    /// Acquire the lock, waiting up to `timeout` for another process to release it.
    ///
    /// Unlike [`try_acquire`], this never silently continues without the lock: a
    /// timeout is returned to the caller as an error.
    pub fn acquire(path: impl AsRef<Path>, timeout: Duration) -> Result<Self> {
        let path = path.as_ref();
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(lock) = Self::try_acquire(path) {
                return Ok(lock);
            }
            if Instant::now() >= deadline {
                return Err(Error::other(format!(
                    "timed out waiting for the lock at {}",
                    path.display()
                )));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_fails_while_held() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "sl-lock-{}-{}.lock",
            std::process::id(),
            rand_suffix()
        ));
        let lock = FileLock::try_acquire(&path).expect("first acquire");
        assert!(
            FileLock::try_acquire(&path).is_none(),
            "lock was not exclusive"
        );
        drop(lock);
        assert!(
            FileLock::try_acquire(&path).is_some(),
            "lock not released on drop"
        );
        let _ = fs::remove_file(&path);
    }

    fn rand_suffix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}
