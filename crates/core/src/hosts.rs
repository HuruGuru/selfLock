//! Port of `HostFileBlocker` — manages the self-controlled region of the system
//! hosts file between `# BEGIN SELFLOCK BLOCK` / `# END SELFLOCK BLOCK`.

use crate::error::{Error, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const SELF_LOCK_HEADER: &str = "# BEGIN SELFLOCK BLOCK";
pub const SELF_LOCK_FOOTER: &str = "# END SELFLOCK BLOCK";

const WINDOWS_DEFAULT_HOSTS: &str = "# Copyright (c) 1993-2009 Microsoft Corp.\n\
#\n\
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\n\
#\n\
127.0.0.1       localhost\n\
::1             localhost\n";

/// Default contents for the Windows hosts file (used only when the file is
/// missing).
pub fn default_hosts_contents() -> &'static str {
    WINDOWS_DEFAULT_HOSTS
}

/// The path to the system hosts file on Windows.
pub fn system_hosts_path() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    PathBuf::from(root).join("System32\\drivers\\etc\\hosts")
}

/// Pure, file-agnostic manipulation of hosts file contents.
#[derive(Clone, Debug)]
pub struct HostsContents {
    text: String,
}

impl HostsContents {
    pub fn from_string(text: impl Into<String>) -> Self {
        HostsContents { text: text.into() }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn into_string(self) -> String {
        self.text
    }

    fn chars(&self) -> Vec<char> {
        self.text.chars().collect()
    }

    fn from_chars(chars: &[char]) -> String {
        chars.iter().collect()
    }

    pub fn contains_block(&self) -> bool {
        self.text.contains(SELF_LOCK_HEADER)
    }

    pub fn add_header(&mut self) {
        self.text.push('\n');
        self.text.push_str(SELF_LOCK_HEADER);
        self.text.push('\n');
    }

    pub fn add_footer(&mut self) {
        self.text.push_str(SELF_LOCK_FOOTER);
        self.text.push('\n');
    }

    fn rule_strings_to_block_domain(domain: &str) -> [String; 2] {
        [format!("0.0.0.0\t{domain}\n"), format!("::\t{domain}\n")]
    }

    pub fn add_rule_blocking_domain(&mut self, domain: &str) {
        // While a block is already active the footer is in place, and new rules must
        // land *before* it: `remove_block` deletes the header..footer range, so
        // anything appended after the footer would survive the clear as an orphan
        // entry. During a fresh start there is no footer yet, so this appends.
        //
        // The footer must be searched only *after* our header. A stray footer above
        // the block (left by another tool or an older damaged file) must not become
        // the insertion point: the rule would be placed outside the block and would
        // survive every clear.
        let insert_at = match self.text.find(SELF_LOCK_HEADER) {
            Some(header) => self.text[header..]
                .find(SELF_LOCK_FOOTER)
                .map_or(self.text.len(), |offset| header + offset),
            None => self.text.len(),
        };
        let mut rules = String::new();
        for rule in Self::rule_strings_to_block_domain(domain) {
            rules.push_str(&rule);
        }
        self.text.insert_str(insert_at, &rules);
    }

    /// Newline-aware removal of the block, mirroring the original byte-for-byte
    /// (but operating on Unicode scalar values instead of UTF-16 code units).
    pub fn remove_block(&mut self) {
        if !self.contains_block() {
            return;
        }

        let chars = self.chars();
        let header_chars: Vec<char> = SELF_LOCK_HEADER.chars().collect();
        let footer_chars: Vec<char> = SELF_LOCK_FOOTER.chars().collect();

        let Some(start) = find_subslice(&chars, &header_chars) else {
            return;
        };

        // Only look for the footer *after* the header. A stray/damaged footer above
        // the header (pre-seeded hosts, leftovers from another tool) must never be
        // used, otherwise the subtraction below underflows and — in release builds —
        // wraps to a huge `usize` that deletes everything from the header to EOF.
        let end = find_subslice(&chars[start..], &footer_chars).map(|off| start + off);

        let mut delete_start = start;
        if delete_start > 0 {
            let prev = chars[delete_start - 1];
            if is_newline(prev) {
                delete_start -= 1;
            }
        }

        let max_delete_len = chars.len() - delete_start;
        let delete_len = match end {
            None => max_delete_len,
            Some(end_idx) => {
                debug_assert!(end_idx >= delete_start);
                let raw = (end_idx + footer_chars.len()).saturating_sub(delete_start);
                let mut len = std::cmp::min(max_delete_len, raw);
                if len < max_delete_len {
                    let next = chars[delete_start + len];
                    if is_newline(next) {
                        len += 1;
                    }
                }
                len
            }
        };

        let mut kept: Vec<char> = Vec::with_capacity(chars.len());
        kept.extend_from_slice(&chars[..delete_start]);
        kept.extend_from_slice(&chars[delete_start + delete_len..]);
        self.text = Self::from_chars(&kept);
    }
}

fn is_newline(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{0085}' | '\u{2028}' | '\u{2029}')
}

/// Find the starting char index of `needle` within `haystack`.
fn find_subslice(haystack: &[char], needle: &[char]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A `HostsContents` bound to a file on disk, with backup support.
#[derive(Debug)]
pub struct HostFileBlocker {
    path: PathBuf,
    contents: HostsContents,
    /// Non-`NotFound` error from the last read. While set, the in-memory contents
    /// are not a trustworthy view of the file and writing is refused.
    load_error: Option<String>,
}

impl HostFileBlocker {
    /// Create a blocker for the given path, loading existing contents (falling back
    /// to the platform default only when the file is missing).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let (text, load_error) = match fs::read_to_string(&path) {
            Ok(text) => (text, None),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                (default_hosts_contents().to_string(), None)
            }
            Err(e) => {
                log::error!("hosts: cannot read {}: {e}", path.display());
                (String::new(), Some(e.to_string()))
            }
        };
        HostFileBlocker {
            path,
            contents: HostsContents::from_string(text),
            load_error,
        }
    }

    pub fn for_system() -> Self {
        Self::new(system_hosts_path())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn contents(&self) -> &HostsContents {
        &self.contents
    }

    pub fn contains_block(&self) -> bool {
        self.contents.contains_block()
    }

    pub fn add_header(&mut self) {
        self.contents.add_header();
    }

    pub fn add_footer(&mut self) {
        self.contents.add_footer();
    }

    pub fn add_rule_blocking_domain(&mut self, domain: &str) {
        self.contents.add_rule_blocking_domain(domain);
    }

    pub fn remove_block(&mut self) {
        self.contents.remove_block();
    }

    pub fn backup_path(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".bak");
        PathBuf::from(p)
    }

    pub fn revert_to_disk(&mut self) {
        match fs::read_to_string(&self.path) {
            Ok(text) => {
                self.contents = HostsContents::from_string(text);
                self.load_error = None;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.contents = HostsContents::from_string(default_hosts_contents());
                self.load_error = None;
            }
            Err(e) => {
                // Keep the previous in-memory contents: replacing them with the
                // default would make the next write clobber the real hosts file.
                log::error!("hosts: cannot re-read {}: {e}", self.path.display());
                self.load_error = Some(e.to_string());
            }
        }
    }

    pub fn write_new_file_contents(&self) -> Result<()> {
        if let Some(error) = &self.load_error {
            return Err(Error::other(format!(
                "hosts file is unreadable; refusing to overwrite {}: {error}",
                self.path.display()
            )));
        }
        write_atomic(&self.path, self.contents.as_str().as_bytes())
    }

    pub fn create_backup(&self) -> Result<bool> {
        self.delete_backup()?;
        if !self.path.exists() {
            write_atomic(&self.path, default_hosts_contents().as_bytes())?;
        }
        let backup = self.backup_path();
        if backup.exists() {
            return Ok(false);
        }
        fs::copy(&self.path, &backup)?;
        log::info!(
            "hosts: backed up {} -> {}",
            self.path.display(),
            backup.display()
        );
        Ok(true)
    }

    pub fn delete_backup(&self) -> Result<bool> {
        let backup = self.backup_path();
        if backup.exists() {
            fs::remove_file(&backup)?;
            log::info!("hosts: deleted backup {}", backup.display());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn restore_backup(&self) -> Result<bool> {
        let backup = self.backup_path();
        if !backup.exists() {
            return Ok(false);
        }
        fs::copy(&backup, &self.path)?;
        log::info!("hosts: restored {} from backup", self.path.display());
        Ok(true)
    }
}

/// Write a file atomically (write to a sibling temp file, then rename over the
/// target). The temp file is created with `O_EXCL` and a unique name so a
/// concurrent writer (or a guessable-name attacker) can't redirect the write, and
/// it is removed on failure.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let unique = format!(
        "{}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let mut tmp = dir.to_path_buf();
    tmp.push(format!(".{name}.{unique}.tmp"));

    let write_result = (|| -> std::io::Result<()> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }

    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }

    log::debug!("wrote {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_remove_block_is_clean() {
        let base = "127.0.0.1 localhost\n";
        let mut c = HostsContents::from_string(base);
        c.add_header();
        c.add_rule_blocking_domain("example.com");
        c.add_footer();
        assert!(c.contains_block());
        assert!(c.as_str().contains("0.0.0.0\texample.com"));
        c.remove_block();
        assert!(!c.contains_block());
        assert_eq!(c.as_str(), base);
    }

    #[test]
    fn remove_without_prior_block_is_noop() {
        let base = "127.0.0.1 localhost\n";
        let mut c = HostsContents::from_string(base);
        c.remove_block();
        assert_eq!(c.as_str(), base);
    }

    #[test]
    fn remove_ignores_footer_before_header() {
        // A footer above the header must not be used to compute the delete range,
        // and must not underflow into deleting the rest of the file.
        let base = "# a comment\n\
                    # END SELFLOCK BLOCK\n\
                    127.0.0.1\tlocalhost\n\
                    10.0.0.5\tintranet.corp\n";
        let mut c = HostsContents::from_string(base);
        c.add_header();
        c.add_rule_blocking_domain("evil.test");
        c.add_footer();
        c.remove_block();
        assert!(!c.contains_block());
        let s = c.as_str();
        assert!(
            s.contains("intranet.corp"),
            "unrelated hosts entry was deleted: {s:?}"
        );
        assert!(
            s.contains("# END SELFLOCK BLOCK\n127.0.0.1"),
            "pre-existing footer lost: {s:?}"
        );
    }

    #[test]
    fn add_rule_ignores_footer_before_header() {
        // A stray footer above our block must not become the insertion point.
        let base = "# END SELFLOCK BLOCK\n127.0.0.1\tlocalhost\n";
        let mut c = HostsContents::from_string(base);
        c.add_header();
        c.add_rule_blocking_domain("evil.test");
        c.add_footer();
        c.remove_block();

        assert!(
            !c.as_str().contains("evil.test"),
            "rule outside the block survived the clear: {:?}",
            c.as_str()
        );
        assert!(c.as_str().contains("# END SELFLOCK BLOCK\n127.0.0.1"));
    }

    #[test]
    fn unreadable_hosts_is_not_overwritten() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "sl-hosts-unreadable-{}-{}.txt",
            std::process::id(),
            rand_suffix()
        ));
        // Invalid UTF-8: read_to_string fails, but write_atomic would succeed.
        let original = b"127.0.0.1\tlocalhost\n\xFF\xFE\n";
        std::fs::write(&path, original).unwrap();

        let blocker = HostFileBlocker::new(&path);
        assert!(blocker.write_new_file_contents().is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn remove_handles_missing_footer() {
        let base = "127.0.0.1 localhost\n";
        let mut c = HostsContents::from_string(base);
        c.add_header();
        c.add_rule_blocking_domain("example.com");
        // No footer added.
        c.remove_block();
        assert_eq!(c.as_str(), base);
    }

    #[test]
    fn add_rule_inserts_before_an_existing_footer() {
        let base = "127.0.0.1 localhost\n";
        let mut c = HostsContents::from_string(base);
        c.add_header();
        c.add_rule_blocking_domain("old.example");
        c.add_footer();
        // Simulates "add to block" while the block is running.
        c.add_rule_blocking_domain("new.example");

        let s = c.as_str();
        let old_pos = s.find("0.0.0.0\told.example").unwrap();
        let new_pos = s.find("0.0.0.0\tnew.example").unwrap();
        let footer_pos = s.find(SELF_LOCK_FOOTER).unwrap();
        assert!(old_pos < new_pos);
        assert!(
            new_pos < footer_pos,
            "new rule landed after the footer: {s:?}"
        );
        assert_eq!(
            s.matches("0.0.0.0\tnew.example").count(),
            1,
            "duplicate rule written"
        );

        // A later clear must remove the appended rules too.
        c.remove_block();
        assert_eq!(c.as_str(), base);
    }

    #[test]
    fn add_rule_appends_when_there_is_no_footer_yet() {
        let mut c = HostsContents::from_string("127.0.0.1 localhost\n");
        c.add_header();
        c.add_rule_blocking_domain("a.example");
        assert!(c.as_str().ends_with("::\ta.example\n"));
    }

    #[test]
    fn write_atomic_replaces_contents() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "sl-atomic-{}-{}.txt",
            std::process::id(),
            rand_suffix()
        ));
        write_atomic(&path, b"one").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two");
        // No stray temp files left behind.
        let leftovers = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name().to_string_lossy().starts_with(&format!(
                    ".{}-",
                    path.file_name().unwrap().to_string_lossy()
                ))
            })
            .count();
        assert_eq!(leftovers, 0);
        let _ = std::fs::remove_file(&path);
    }

    fn rand_suffix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}
