//! Port of `BlockManager` — coordinates hosts-file blocking and firewall rules.
//!
//! The original parallelizes work with an `NSOperationQueue`; this version parses
//! everything up front, resolves domains in parallel, then applies the results
//! deterministically.

use crate::apps;
use crate::common_subdomains::common_subdomains_for_hostname;
use crate::entry::{BlockEntry, EntryKind};
use crate::error::{Error, Result};
use crate::firewall::{default_backend, FirewallBackend, FirewallRule};
use crate::google::{domain_is_google, GOOGLE_IPS};
use crate::hosts::HostFileBlocker;
use crate::resolve::resolve_many;
use crate::scraper;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// Pluggable DNS resolver so tests (and callers) can override resolution.
type Resolver = dyn Fn(&str) -> Vec<IpAddr> + Send + Sync;

/// What [`BlockManager::append_block_from_strings`] actually added.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AppendReport {
    pub firewall_rules: usize,
    pub hosts_rules: usize,
    pub app_rules: usize,
}

pub struct BlockManager {
    is_allowlist: bool,
    allow_local: bool,
    include_common_subdomains: bool,
    include_linked_domains: bool,
    hosts: Option<HostFileBlocker>,
    firewall: Box<dyn FirewallBackend>,
    added: HashSet<BlockEntry>,
    hosts_blocking_enabled: bool,
    resolver: Option<Arc<Resolver>>,
    firewall_rule_count: usize,
    hosts_rule_count: usize,
    app_rule_count: usize,
    unresolved_apps: Vec<String>,
}

impl BlockManager {
    /// Production constructor: uses the system hosts file and the platform firewall.
    pub fn new(
        is_allowlist: bool,
        allow_local: bool,
        include_common_subdomains: bool,
        include_linked_domains: bool,
    ) -> Self {
        BlockManager {
            is_allowlist,
            allow_local,
            include_common_subdomains,
            include_linked_domains,
            hosts: Some(HostFileBlocker::for_system()),
            firewall: default_backend(),
            added: HashSet::new(),
            hosts_blocking_enabled: false,
            resolver: None,
            firewall_rule_count: 0,
            hosts_rule_count: 0,
            app_rule_count: 0,
            unresolved_apps: Vec::new(),
        }
    }

    /// Test/dependency-injection constructor.
    pub fn with_parts(
        is_allowlist: bool,
        allow_local: bool,
        include_common_subdomains: bool,
        include_linked_domains: bool,
        hosts_path: PathBuf,
        firewall: Box<dyn FirewallBackend>,
    ) -> Self {
        BlockManager {
            is_allowlist,
            allow_local,
            include_common_subdomains,
            include_linked_domains,
            hosts: Some(HostFileBlocker::new(hosts_path)),
            firewall,
            added: HashSet::new(),
            hosts_blocking_enabled: false,
            resolver: None,
            firewall_rule_count: 0,
            hosts_rule_count: 0,
            app_rule_count: 0,
            unresolved_apps: Vec::new(),
        }
    }

    pub fn firewall(&self) -> &dyn FirewallBackend {
        self.firewall.as_ref()
    }

    /// Number of firewall rules queued/applied so far.
    pub fn firewall_rule_count(&self) -> usize {
        self.firewall_rule_count
    }

    /// Number of hosts-file rules written so far.
    pub fn hosts_rule_count(&self) -> usize {
        self.hosts_rule_count
    }

    /// Number of application (`program=`) firewall rules queued so far.
    pub fn app_rule_count(&self) -> usize {
        self.app_rule_count
    }

    /// Whether local-network traffic should be permitted in an allowlist block.
    pub fn allow_local(&self) -> bool {
        self.allow_local
    }

    /// Override DNS resolution (used by tests to stay offline/deterministic).
    pub fn set_resolver<F>(&mut self, resolver: F)
    where
        F: Fn(&str) -> Vec<IpAddr> + Send + Sync + 'static,
    {
        self.resolver = Some(Arc::new(resolver));
    }

    /// Mark entries the running block already covers, so an append does not write
    /// duplicate hosts lines or firewall rules for them (for example when adding
    /// `www.youtube.com` while `youtube.com` and its common subdomains are blocked).
    pub fn seed_blocked(&mut self, entries: &[String]) {
        for raw in entries {
            if let Some(entry) = BlockEntry::parse(raw) {
                self.added.insert(entry);
            }
        }
    }

    /// Port of `-[BlockManager prepareToAddBlock]`.
    pub fn prepare_to_add_block(&mut self) -> Result<()> {
        log::info!(
            "manager: prepare_to_add_block (allowlist={}, hosts={})",
            self.is_allowlist,
            self.hosts
                .as_ref()
                .map(|h| h.path().display().to_string())
                .unwrap_or_else(|| "none".into())
        );
        if let Some(h) = self.hosts.as_mut() {
            if h.contains_block() {
                log::info!("manager: removing pre-existing hosts block first");
                h.remove_block();
                h.write_new_file_contents()?;
            }
        }

        if !self.is_allowlist {
            if let Some(h) = self.hosts.as_mut() {
                h.create_backup()?;
                h.add_header();
            }
            self.hosts_blocking_enabled = true;
        } else {
            self.hosts_blocking_enabled = false;
        }
        log::info!(
            "manager: hosts blocking {}",
            if self.hosts_blocking_enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        Ok(())
    }

    /// Port of `-[BlockManager finalizeBlock]`.
    pub fn finalize_block(&mut self) -> Result<()> {
        if self.hosts_blocking_enabled {
            if let Some(h) = self.hosts.as_mut() {
                h.add_footer();
                h.write_new_file_contents()?;
            }
        }
        log::info!(
            "manager: finalize — applying {} firewall rule(s) via '{}'",
            self.firewall_rule_count,
            self.firewall.name()
        );
        self.firewall.start_block(self.is_allowlist)?;
        log::info!(
            "manager: block finalized ({} firewall rules, {} hosts rules)",
            self.firewall_rule_count,
            self.hosts_rule_count
        );
        Ok(())
    }

    /// Port of `-[BlockManager clearBlock]` / `forceClearBlock`.
    pub fn clear_block(&mut self, force: bool) -> bool {
        log::info!("manager: clear_block (force={force})");
        let _ = self.firewall.stop_block(force);
        let firewall_success = !self.firewall.contains_block();

        let mut host_success = true;
        let mut backup_existed = false;
        if let Some(h) = self.hosts.as_mut() {
            backup_existed = h.backup_path().exists();
            h.remove_block();
            host_success = h.write_new_file_contents().is_ok();
            h.revert_to_disk();
            host_success = host_success && !h.contains_block();
        }

        let mut cleared = host_success && firewall_success;
        let mut backup_restored = false;

        if !cleared {
            if !firewall_success {
                let _ = self.firewall.stop_block(true);
            }
            if !host_success {
                if let Some(h) = self.hosts.as_ref() {
                    backup_restored = h.restore_backup().unwrap_or(false);
                }
            }
            cleared = !self.block_is_active();
        }

        // Only discard our sole recovery copy once the pre-block hosts contents are
        // safely back in place. Deleting it after a failed restore would destroy the
        // user's original hosts file permanently.
        if let Some(h) = self.hosts.as_ref() {
            if host_success || backup_restored || !backup_existed {
                let _ = h.delete_backup();
            } else {
                log::error!(
                    "manager: clear failed and hosts could not be restored; keeping backup at {}",
                    h.backup_path().display()
                );
            }
        }

        log::info!("manager: clear_block result cleared={cleared} (firewall_ok={firewall_success}, hosts_ok={host_success}, backup_restored={backup_restored})");
        cleared
    }

    /// Port of `-[BlockManager blockIsActive]`.
    pub fn block_is_active(&self) -> bool {
        self.hosts
            .as_ref()
            .map(|h| h.contains_block())
            .unwrap_or(false)
            || self.firewall.contains_block()
    }

    /// Convenience: prepare + add + finalize (port of `+installBlockRulesFromSettings`).
    pub fn start_block_from_strings(&mut self, list: &[String]) -> Result<()> {
        log::info!(
            "manager: starting block from {} raw entr(y/ies) [allowlist={}, subdomains={}, linked={}]",
            list.len(),
            self.is_allowlist,
            self.include_common_subdomains,
            self.include_linked_domains,
        );
        self.prepare_to_add_block()?;
        if let Err(e) = self.add_entries_from_strings(list) {
            // Nothing has been written to the firewall yet, but the hosts file may
            // already be in the in-memory "blocking" state. Roll it back so a
            // mistyped application path cannot leave a half-started block.
            log::error!("manager: adding entries failed ({e}); rolling back hosts changes");
            self.clear_block(true);
            return Err(e);
        }
        match self.finalize_block() {
            Ok(()) => Ok(()),
            Err(e) => {
                // finalize_block writes the hosts file before configuring the
                // firewall; if the firewall step fails we must undo the hosts change
                // so we don't leave a half-applied, untracked block behind.
                log::error!("manager: finalize failed ({e}); rolling back hosts changes");
                self.clear_block(true);
                Err(e)
            }
        }
    }

    /// Port of `-[BlockManager addBlockEntriesFromStrings:]`.
    pub fn add_entries_from_strings(&mut self, list: &[String]) -> Result<()> {
        for raw in list {
            log::debug!("manager: raw entry {:?}", raw);
        }
        let expanded = self.expand_entries(list);
        log::info!(
            "manager: {} raw entr(y/ies) expanded to {} entr(y/ies)",
            list.len(),
            expanded.len()
        );
        self.apply_entries(expanded)
    }

    /// Port of `-[BlockManager enterAppendMode]` + `finishAppending`: add entries to
    /// a block that is already active.
    ///
    /// Unlike [`BlockManager::start_block_from_strings`] this never touches the
    /// hosts backup, the firewall policy or the existing rules. New hosts entries
    /// are inserted before the block footer, and new firewall rules are appended
    /// with fresh names, so the original block keeps running throughout (the network
    /// is never opened even for a moment).
    ///
    /// The hosts file is written back and the in-memory view restored if the
    /// firewall step fails, so a failed add leaves the running block unchanged.
    pub fn append_block_from_strings(&mut self, list: &[String]) -> Result<AppendReport> {
        if self.is_allowlist {
            return Err(Error::Unsupported(
                "entries cannot be added to an allowlist block".into(),
            ));
        }
        let Some(hosts) = self.hosts.as_ref() else {
            return Err(Error::other("no hosts file to extend"));
        };
        if !hosts.contains_block() {
            return Err(Error::other(
                "no active hosts block to extend; the block may already be cleared",
            ));
        }
        // Snapshot for rollback if the firewall step fails.
        let previous_hosts = hosts.contents().as_str().to_string();
        self.hosts_blocking_enabled = true;
        let before = (
            self.firewall_rule_count,
            self.hosts_rule_count,
            self.app_rule_count,
        );

        log::info!(
            "manager: appending {} raw entr(y/ies) to the active block",
            list.len()
        );
        let expanded = self.expand_entries(list);
        log::info!("manager: append expanded to {} entr(y/ies)", expanded.len());
        if let Err(e) = self.apply_entries(expanded) {
            // Nothing has been written to disk yet.
            self.restore_hosts(&previous_hosts, false);
            return Err(e);
        }

        if let Some(h) = self.hosts.as_mut() {
            if let Err(e) = h.write_new_file_contents() {
                self.restore_hosts(&previous_hosts, false);
                return Err(e);
            }
        }

        if let Err(e) = self.firewall.append_rules(self.is_allowlist) {
            log::error!(
                "manager: appending firewall rules failed ({e}); rolling back hosts changes"
            );
            self.restore_hosts(&previous_hosts, true);
            return Err(e);
        }

        let report = AppendReport {
            firewall_rules: self.firewall_rule_count - before.0,
            hosts_rules: self.hosts_rule_count - before.1,
            app_rules: self.app_rule_count - before.2,
        };
        log::info!(
            "manager: appended {} firewall rule(s) ({} hosts, {} application)",
            report.firewall_rules,
            report.hosts_rules,
            report.app_rules
        );
        Ok(report)
    }

    /// Restore the hosts file to `text` after a failed append.
    ///
    /// `write` also puts the text back on disk (used after the file was written but
    /// the firewall step failed); otherwise the disk still holds the original and
    /// only the in-memory view needs to be refreshed.
    fn restore_hosts(&mut self, text: &str, write: bool) {
        if let Some(h) = self.hosts.as_mut() {
            if write {
                if let Err(e) = crate::hosts::write_atomic(h.path(), text.as_bytes()) {
                    log::error!("manager: could not roll back hosts file: {e}");
                }
            }
            h.revert_to_disk();
        }
    }

    /// Parse strings, expand related entries (subdomains + scraped links), dedupe.
    fn expand_entries(&self, list: &[String]) -> Vec<BlockEntry> {
        let mut seen: HashSet<BlockEntry> = HashSet::new();
        let mut out: Vec<BlockEntry> = Vec::new();
        let mut push = |e: BlockEntry, out: &mut Vec<BlockEntry>| {
            if seen.insert(e.clone()) {
                out.push(e);
            }
        };

        for raw in list {
            let Some(entry) = BlockEntry::parse(raw) else {
                continue;
            };
            for related in self.related_block_entries(&entry) {
                push(related, &mut out);
            }
            push(entry, &mut out);
        }
        out
    }

    /// Port of `-[BlockManager relatedBlockEntriesForEntry:]`.
    pub fn related_block_entries(&self, entry: &BlockEntry) -> Vec<BlockEntry> {
        // Application entries are not hostnames: never scrape them or add
        // "common subdomains" of an executable path.
        if entry.kind == EntryKind::App {
            return Vec::new();
        }

        let mut related = Vec::new();

        if self.is_allowlist && self.include_linked_domains && !entry.is_ip() {
            for scraped in scraper::related_block_entries(&entry.hostname) {
                related.push(scraped);
            }
        }

        if !entry.is_ip() && self.include_common_subdomains {
            for sub in common_subdomains_for_hostname(&entry.hostname) {
                if let Some(e) = BlockEntry::parse(&sub) {
                    related.push(e);
                }
            }
        }

        related
    }

    /// Resolve all domains in parallel, then apply every entry.
    fn apply_entries(&mut self, entries: Vec<BlockEntry>) -> Result<()> {
        let mut to_resolve: Vec<String> = Vec::new();
        let mut seen_hosts: HashSet<String> = HashSet::new();
        for e in &entries {
            if e.kind != EntryKind::App
                && !e.is_ip()
                && e.hostname != "*"
                && !domain_is_google(&e.hostname)
                && seen_hosts.insert(e.hostname.clone())
            {
                to_resolve.push(e.hostname.clone());
            }
        }
        log::info!("manager: resolving {} domain(s)", to_resolve.len());
        let resolved: HashMap<String, Vec<IpAddr>> = match &self.resolver {
            Some(resolver) => to_resolve
                .iter()
                .map(|h| (h.clone(), resolver(h)))
                .collect(),
            None => resolve_many(&to_resolve).into_iter().collect(),
        };
        let with_addrs = resolved.values().filter(|v| !v.is_empty()).count();
        log::info!(
            "manager: {} of {} domain(s) resolved to an address",
            with_addrs,
            to_resolve.len()
        );
        for (host, ips) in &resolved {
            if ips.is_empty() {
                log::warn!("manager: {host} did not resolve to any address");
            } else {
                log::debug!("manager: {host} -> {:?}", ips);
            }
        }

        for entry in entries {
            self.apply_entry(&entry, &resolved)?;
        }

        if !self.unresolved_apps.is_empty() {
            return Err(Error::AppNotFound(self.unresolved_apps.join(", ")));
        }
        Ok(())
    }

    /// Queue a firewall rule, keeping a running count for reporting.
    fn queue_rule(&mut self, rule: FirewallRule) {
        log::debug!("manager: queuing firewall rule {rule:?}");
        self.firewall.add_rule(rule);
        self.firewall_rule_count += 1;
    }

    /// Queue Windows Firewall `program=` rules for an application entry.
    ///
    /// A bare image name (`firefox.exe`) may resolve to more than one installed
    /// copy; every match is blocked. If nothing is found the whole block fails
    /// instead of silently doing nothing.
    fn apply_app_entry(&mut self, entry: &BlockEntry) -> Result<()> {
        log::info!("manager: resolving application '{}'", entry.hostname);
        let paths = apps::resolve(&entry.hostname);
        log::info!(
            "manager: application '{}' resolved to {} path(s): {:?}",
            entry.hostname,
            paths.len(),
            paths
        );
        if paths.is_empty() {
            log::warn!(
                "manager: application '{}' could not be resolved to an executable",
                entry.hostname
            );
            self.unresolved_apps.push(entry.hostname.clone());
            return Ok(());
        }
        for path in paths {
            log::info!("manager: blocking application {}", path.display());
            self.queue_rule(FirewallRule::app(path.display().to_string()));
            self.app_rule_count += 1;
        }
        Ok(())
    }

    fn apply_entry(
        &mut self,
        entry: &BlockEntry,
        resolved: &HashMap<String, Vec<IpAddr>>,
    ) -> Result<()> {
        if !self.added.insert(entry.clone()) {
            log::debug!("manager: skipping duplicate entry {entry:?}");
            return Ok(());
        }

        if entry.kind == EntryKind::App {
            return self.apply_app_entry(entry);
        }

        let is_ip = entry.is_ip();
        let is_ipv4 = entry.is_ipv4();

        if entry.hostname == "*" {
            self.queue_rule(FirewallRule::new(None, entry.port, entry.mask_len));
        } else if is_ipv4 {
            self.queue_rule(FirewallRule::new(
                Some(entry.hostname.clone()),
                entry.port,
                entry.mask_len,
            ));
        } else if !is_ip {
            if domain_is_google(&entry.hostname) {
                if self.is_allowlist {
                    // Blocking Google by IP is too error-prone for allowlists, so we
                    // whitelist the entire published Google range instead.
                    log::info!(
                        "manager: {} is a Google domain; allowing the whole Google range",
                        entry.hostname
                    );
                    for (ip, mask) in GOOGLE_IPS {
                        self.queue_rule(FirewallRule::new(Some((*ip).to_string()), 0, *mask));
                    }
                } else {
                    log::debug!(
                        "manager: {} is a Google domain; relying on hosts only",
                        entry.hostname
                    );
                }
            } else if let Some(ips) = resolved.get(&entry.hostname) {
                for ip in ips {
                    self.queue_rule(FirewallRule::new(
                        Some(ip.to_string()),
                        entry.port,
                        entry.mask_len,
                    ));
                }
            }
        }

        if self.hosts_blocking_enabled && entry.hostname != "*" && entry.port == 0 && !is_ip {
            if let Some(h) = self.hosts.as_mut() {
                h.add_rule_blocking_domain(&entry.hostname);
                self.hosts_rule_count += 1;
                log::debug!("manager: hosts rule added for {}", entry.hostname);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::FirewallBackend;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeFirewall {
        rules: Mutex<Vec<FirewallRule>>,
        block: Mutex<bool>,
        started: Mutex<bool>,
        append_fails: Mutex<bool>,
    }

    impl FirewallBackend for FakeFirewall {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn add_rule(&mut self, rule: FirewallRule) {
            self.rules.lock().unwrap().push(rule);
        }
        fn start_block(&mut self, _allowlist: bool) -> Result<()> {
            *self.started.lock().unwrap() = true;
            *self.block.lock().unwrap() = true;
            Ok(())
        }
        fn append_rules(&mut self, _allowlist: bool) -> Result<()> {
            if *self.append_fails.lock().unwrap() {
                return Err(Error::other("append failed"));
            }
            *self.block.lock().unwrap() = true;
            Ok(())
        }
        fn refresh(&self) -> Result<()> {
            Ok(())
        }
        fn contains_block(&self) -> bool {
            *self.block.lock().unwrap()
        }
        fn stop_block(&self, _force: bool) -> Result<()> {
            *self.block.lock().unwrap() = false;
            Ok(())
        }
    }

    fn temp_hosts() -> PathBuf {
        std::env::temp_dir().join(format!(
            "sl-hosts-test-{}-{}.txt",
            std::process::id(),
            rand_suffix()
        ))
    }

    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    #[test]
    fn blocklist_adds_ipv4_and_hosts_entries() {
        let path = temp_hosts();
        std::fs::write(&path, "127.0.0.1 localhost\n").unwrap();
        let mut mgr = BlockManager::with_parts(
            false,
            true,
            false,
            false,
            path.clone(),
            Box::new(FakeFirewall::default()),
        );
        mgr.set_resolver(|h| {
            if h == "blocked.example" {
                vec!["93.184.216.34".parse().unwrap()]
            } else {
                Vec::new()
            }
        });
        mgr.prepare_to_add_block().unwrap();
        mgr.add_entries_from_strings(&["blocked.example".to_string(), "127.0.0.1".to_string()])
            .unwrap();
        mgr.finalize_block().unwrap();

        // Domains get both a hosts rule and firewall rules (per resolved IP).
        let hosts = std::fs::read_to_string(&path).unwrap();
        assert!(hosts.contains("0.0.0.0\tblocked.example"));
        // IPv4 literals go to the firewall only, never the hosts file.
        assert_eq!(hosts.matches("127.0.0.1").count(), 1);
        assert!(mgr.firewall().contains_block());
        assert!(mgr.block_is_active());

        let cleared = mgr.clear_block(false);
        assert!(cleared);
        let hosts = std::fs::read_to_string(&path).unwrap();
        assert_eq!(hosts, "127.0.0.1 localhost\n");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dedupes_entries() {
        let path = temp_hosts();
        let mut mgr = BlockManager::with_parts(
            false,
            true,
            false,
            false,
            path.clone(),
            Box::new(FakeFirewall::default()),
        );
        mgr.add_entries_from_strings(&["1.2.3.4".into(), "1.2.3.4".into()])
            .unwrap();
        assert_eq!(mgr.added.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn app_entries_have_no_related_hosts() {
        let mgr = BlockManager::with_parts(
            true,
            true,
            true,
            true,
            temp_hosts(),
            Box::new(FakeFirewall::default()),
        );
        let entry = BlockEntry::app("firefox.exe");
        assert!(mgr.related_block_entries(&entry).is_empty());
    }

    #[test]
    fn app_entry_queues_program_rule_and_skips_hosts() {
        let hosts = temp_hosts();
        std::fs::write(&hosts, "127.0.0.1 localhost\n").unwrap();
        let exe = std::env::temp_dir().join(format!(
            "sl-app-test-{}-{}.exe",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::write(&exe, b"MZ").unwrap();

        let mut mgr = BlockManager::with_parts(
            false,
            true,
            false,
            false,
            hosts.clone(),
            Box::new(FakeFirewall::default()),
        );
        mgr.prepare_to_add_block().unwrap();
        mgr.add_entries_from_strings(&[format!("app:{}", exe.display())])
            .unwrap();
        mgr.finalize_block().unwrap();

        assert_eq!(mgr.app_rule_count(), 1);
        assert_eq!(mgr.firewall_rule_count(), 1);
        assert_eq!(mgr.hosts_rule_count(), 0);
        let hosts_text = std::fs::read_to_string(&hosts).unwrap();
        assert!(!hosts_text.contains("sl-app-test"));

        assert!(mgr.clear_block(false));
        let _ = std::fs::remove_file(&exe);
        let _ = std::fs::remove_file(&hosts);
    }

    #[test]
    fn missing_app_fails_the_block() {
        let hosts = temp_hosts();
        let mut mgr = BlockManager::with_parts(
            false,
            true,
            false,
            false,
            hosts.clone(),
            Box::new(FakeFirewall::default()),
        );
        let err = mgr
            .add_entries_from_strings(&[r"app:C:\__selflock_missing__\nope.exe".into()])
            .unwrap_err();
        assert!(matches!(err, Error::AppNotFound(_)));
        let _ = std::fs::remove_file(&hosts);
    }

    #[test]
    fn skips_star_without_port() {
        let path = temp_hosts();
        let mut mgr = BlockManager::with_parts(
            false,
            true,
            false,
            false,
            path.clone(),
            Box::new(FakeFirewall::default()),
        );
        mgr.add_entries_from_strings(&["*".into()]).unwrap();
        assert!(mgr.added.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_keeps_the_running_block_intact() {
        let path = temp_hosts();
        let base = "127.0.0.1 localhost\n";
        std::fs::write(&path, base).unwrap();
        let mut mgr = BlockManager::with_parts(
            false,
            true,
            false,
            false,
            path.clone(),
            Box::new(FakeFirewall::default()),
        );
        mgr.set_resolver(|h| {
            if h == "first.example" || h == "second.example" {
                vec!["93.184.216.34".parse().unwrap()]
            } else {
                Vec::new()
            }
        });
        mgr.start_block_from_strings(&["first.example".to_string()])
            .unwrap();

        let report = mgr
            .append_block_from_strings(&["second.example".to_string()])
            .unwrap();
        // Only the new entry is reported, not the ones added at start.
        assert_eq!(report.hosts_rules, 1);
        assert_eq!(report.firewall_rules, 1);

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("first.example"));
        let second = text.find("second.example").unwrap();
        let footer = text.find("# END SELFLOCK BLOCK").unwrap();
        assert!(
            second < footer,
            "appended rule landed after the footer: {text:?}"
        );
        assert!(mgr.block_is_active());

        // A normal clear removes the appended rules too.
        assert!(mgr.clear_block(false));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), base);
    }

    #[test]
    fn failed_firewall_append_rolls_back_hosts() {
        let path = temp_hosts();
        let base = "127.0.0.1 localhost\n";
        std::fs::write(&path, base).unwrap();
        let fw = FakeFirewall::default();
        *fw.append_fails.lock().unwrap() = true;
        let mut mgr =
            BlockManager::with_parts(false, true, false, false, path.clone(), Box::new(fw));
        mgr.set_resolver(|h| {
            if h == "first.example" || h == "new.example" {
                vec!["93.184.216.34".parse().unwrap()]
            } else {
                Vec::new()
            }
        });
        mgr.start_block_from_strings(&["first.example".to_string()])
            .unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        let err = mgr
            .append_block_from_strings(&["new.example".to_string()])
            .unwrap_err();
        assert!(err.to_string().contains("append failed"), "{err}");
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, before, "hosts file was left modified");
        assert!(!after.contains("new.example"));
    }

    #[test]
    fn append_skips_entries_the_block_already_covers() {
        let path = temp_hosts();
        let base = "127.0.0.1 localhost\n";
        std::fs::write(&path, base).unwrap();

        // Process 1: starts the block.
        let mut starter = BlockManager::with_parts(
            false,
            true,
            false,
            false,
            path.clone(),
            Box::new(FakeFirewall::default()),
        );
        starter.set_resolver(|h| {
            if h == "first.example" {
                vec!["93.184.216.34".parse().unwrap()]
            } else {
                Vec::new()
            }
        });
        starter
            .start_block_from_strings(&["first.example".to_string()])
            .unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        // Process 2 (a separate `add` invocation) seeds the active list first.
        let mut adder = BlockManager::with_parts(
            false,
            true,
            false,
            false,
            path.clone(),
            Box::new(FakeFirewall::default()),
        );
        adder.set_resolver(|_| Vec::new());
        adder.seed_blocked(&["first.example".to_string()]);
        let report = adder
            .append_block_from_strings(&["first.example".to_string()])
            .unwrap();
        assert_eq!(report.hosts_rules, 0);
        assert_eq!(report.firewall_rules, 0);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);

        assert!(starter.clear_block(false));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_refuses_allowlist_and_missing_blocks() {
        let mut allow = BlockManager::with_parts(
            true,
            true,
            false,
            false,
            temp_hosts(),
            Box::new(FakeFirewall::default()),
        );
        let err = allow
            .append_block_from_strings(&["x.example".to_string()])
            .unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)));

        let mut idle = BlockManager::with_parts(
            false,
            true,
            false,
            false,
            temp_hosts(),
            Box::new(FakeFirewall::default()),
        );
        let err = idle
            .append_block_from_strings(&["x.example".to_string()])
            .unwrap_err();
        assert!(
            err.to_string().contains("no active hosts block"),
            "unexpected error: {err}"
        );
    }
}
