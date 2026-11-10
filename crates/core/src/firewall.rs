//! Firewall backend.
//!
//! Port of `PacketFilter`, implemented with Windows Firewall
//! (`netsh advfirewall`).

use crate::error::{Error, Result};
use crate::process::hidden_command;

/// A single firewall rule, mirroring the arguments of
/// `-[PacketFilter addRuleWithIP:port:maskLen:]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirewallRule {
    /// `None` means "any" (the `*` entry).
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub mask_len: Option<u8>,
    /// Absolute path to an executable. When set, this is a Windows Firewall
    /// `program=` rule and `ip`/`port`/`mask_len` are ignored.
    pub program: Option<String>,
}

impl FirewallRule {
    pub fn new(ip: Option<String>, port: u16, mask_len: u8) -> Self {
        FirewallRule {
            ip,
            port: if port == 0 { None } else { Some(port) },
            mask_len: if mask_len == 0 { None } else { Some(mask_len) },
            program: None,
        }
    }

    /// A rule that blocks all outbound traffic for one executable.
    pub fn app(program: impl Into<String>) -> Self {
        FirewallRule {
            ip: None,
            port: None,
            mask_len: None,
            program: Some(program.into()),
        }
    }
}

/// Interface implemented by the Windows firewall backend.
pub trait FirewallBackend: Send + Sync {
    fn name(&self) -> &'static str;
    /// Queue a rule to be applied on the next `start_block`/`refresh`.
    fn add_rule(&mut self, rule: FirewallRule);
    /// Apply all queued rules and enable the block.
    fn start_block(&mut self, allowlist: bool) -> Result<()>;
    /// Add the queued rules to an **already running** block, leaving the existing
    /// rules, hosts backup and firewall policy untouched.
    ///
    /// Backends that cannot extend a live block must return an error rather than
    /// silently dropping the new entries.
    fn append_rules(&mut self, allowlist: bool) -> Result<()> {
        let _ = allowlist;
        Err(Error::Unsupported(
            "this firewall backend cannot add rules to an active block".into(),
        ))
    }
    /// Re-apply the current configuration (used when appending rules).
    fn refresh(&self) -> Result<()>;
    /// Whether our block appears to be present in the system firewall.
    fn contains_block(&self) -> bool;
    /// Remove the block. `force` skips token-based teardown.
    fn stop_block(&self, force: bool) -> Result<()>;
}

/// Return the Windows firewall backend.
pub fn default_backend() -> Box<dyn FirewallBackend> {
    Box::new(netsh::NetshFirewall::new())
}

/// Run a command, returning combined stdout+stderr, erroring on non-zero exit.
pub(crate) fn run_checked(program: &str, args: &[&str]) -> Result<String> {
    match run(program, args) {
        Ok((true, out)) => Ok(out),
        Ok((false, out)) => Err(Error::Command {
            command: format!("{program} {}", args.join(" ")),
            message: out.trim().to_string(),
        }),
        Err(e) => Err(e),
    }
}

/// Truncate command output for logging so a single command (e.g.
/// `netsh show rule name=all` printing hundreds of rules) can't bloat the log.
fn brief(output: &str) -> String {
    const MAX: usize = 500;
    let trimmed = output.trim();
    if trimmed.chars().count() <= MAX {
        return trimmed.to_string();
    }
    let head: String = trimmed.chars().take(MAX).collect();
    format!("{head}… ({} bytes total)", output.len())
}

/// Run a command, returning `(success, combined_output)`.
pub(crate) fn run(program: &str, args: &[&str]) -> Result<(bool, String)> {
    log::info!("exec: {} {}", program, args.join(" "));
    let output = match hidden_command(program).args(args).output() {
        Ok(o) => o,
        Err(e) => {
            log::error!("exec: failed to spawn {program}: {e}");
            return Err(e.into());
        }
    };
    let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    if output.status.success() {
        // Success output is usually just "Ok." and rarely useful; log it only at
        // debug level so normal logs stay small.
        log::debug!("exec: {} -> exit 0: {}", program, brief(&combined));
    } else {
        log::warn!(
            "exec: {} -> exit {:?}: {}",
            program,
            output.status.code(),
            brief(&combined)
        );
        // The brief form above is truncated; diagnosis of a failed batch needs the
        // whole output (netsh prints one line per rejected command).
        log::debug!("exec: {} full output:\n{}", program, combined.trim());
    }
    Ok((output.status.success(), combined))
}

// ---------------------------------------------------------------------------
// Windows: netsh advfirewall
// ---------------------------------------------------------------------------

pub mod netsh {
    use super::*;
    use crate::hosts::write_atomic;
    use std::path::PathBuf;

    pub const NETS: &str = "netsh";

    /// Every rule we create is named with this prefix so we can find and remove it
    /// later. We deliberately avoid `group=`, which some Windows builds reject for
    /// `add/delete/show rule` ("'group' is not a valid argument for this command").
    pub const RULE_PREFIX: &str = "SelfLock-";

    /// File listing the exact rule names we created. Reading this is far cheaper
    /// (and safer) than enumerating every firewall rule via `show rule name=all`,
    /// which can hang when run as SYSTEM in session 0.
    fn state_path() -> PathBuf {
        crate::paths::config_dir().join("firewall-rules.txt")
    }

    /// Records the per-profile outbound firewall policy we replaced when enabling an
    /// allowlist block, so we can restore the user's original policy on clear
    /// instead of assuming the Windows default.
    fn policy_path() -> PathBuf {
        crate::paths::config_dir().join("firewall-policy.txt")
    }

    /// Temporary `netsh -f` batch script used to apply all rules in a single process.
    fn script_path() -> PathBuf {
        crate::paths::config_dir().join("netsh-script.txt")
    }

    pub struct NetshFirewall {
        rules: Vec<FirewallRule>,
        allowlist: bool,
    }

    impl Default for NetshFirewall {
        fn default() -> Self {
            Self::new()
        }
    }

    impl NetshFirewall {
        pub fn new() -> Self {
            NetshFirewall {
                rules: Vec::new(),
                allowlist: false,
            }
        }

        /// Build the `netsh advfirewall firewall add rule` argument list for a rule.
        pub fn add_rule_args(rule: &FirewallRule, index: usize, allowlist: bool) -> Vec<String> {
            let name = format!("{RULE_PREFIX}{index}");
            Self::add_rule_args_named(rule, &name, allowlist, None)
        }

        /// Like `add_rule_args`, but with an explicit rule name and protocol. netsh
        /// requires a protocol (`tcp`/`udp`) whenever `remoteport` is present, so
        /// port-based entries are emitted once per protocol.
        fn add_rule_args_named(
            rule: &FirewallRule,
            name: &str,
            allowlist: bool,
            protocol: Option<&str>,
        ) -> Vec<String> {
            // An application entry always means "block this program", including in
            // allowlist mode: there it is redundant (the default policy is already
            // block), but it must never turn into an `allow` rule.
            let action = if rule.program.is_some() {
                "block"
            } else if allowlist {
                "allow"
            } else {
                "block"
            };
            let mut args: Vec<String> = vec![
                "advfirewall".into(),
                "firewall".into(),
                "add".into(),
                "rule".into(),
                format!("name={name}"),
                "dir=out".into(),
                format!("action={action}"),
            ];
            if let Some(program) = &rule.program {
                // Quotes matter in the `netsh -f` batch script; Windows paths cannot
                // contain `"`, so the value is safe to embed.
                args.push(format!("program=\"{program}\""));
            }
            if let Some(ip) = &rule.ip {
                let mask = rule.mask_len.map(|m| format!("/{m}")).unwrap_or_default();
                args.push(format!("remoteip={ip}{mask}"));
            }
            if let Some(port) = rule.port {
                let protocol = protocol.unwrap_or("tcp");
                args.push(format!("protocol={protocol}"));
                args.push(format!("remoteport={port}"));
            }
            args
        }

        /// Whether `name` is exactly a rule name this program could have created.
        ///
        /// The state file lives in a directory that may be attacker-controlled before
        /// the first elevation, so its contents are never passed to `netsh` without
        /// validation. Generated names contain only ASCII alphanumerics and `-`.
        pub(crate) fn is_our_rule_name(name: &str) -> bool {
            name.strip_prefix(RULE_PREFIX).is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-')
            })
        }

        /// Rule names recorded in our state file, if any.
        fn state_rule_names() -> Vec<String> {
            std::fs::read_to_string(state_path())
                .map(|text| {
                    text.lines()
                        .map(|l| l.trim().to_string())
                        .filter(|l| Self::is_our_rule_name(l))
                        .collect()
                })
                .unwrap_or_default()
        }

        /// Highest `SelfLock-<n>…` index already in use, plus one.
        ///
        /// Suffixes (`-app`, `-tcp`, `-udp`) and service rules
        /// (`SelfLock-svc-tcp-53`) are ignored when parsing, so rules appended to
        /// a live block never collide with names created by `start_block`.
        pub(crate) fn next_rule_index(names: &[String]) -> usize {
            names
                .iter()
                .filter_map(|n| n.strip_prefix(RULE_PREFIX))
                .filter_map(|rest| rest.split('-').next())
                .filter_map(|n| n.parse::<usize>().ok())
                .max()
                .map_or(0, |max| max + 1)
        }

        /// `netsh -f` batch used for incremental additions. Unique per process so a
        /// concurrent auto-clear cannot overwrite it mid-run.
        fn append_script_path(tag: &str) -> PathBuf {
            script_path().with_file_name(format!("netsh-append-{}-{tag}.txt", std::process::id()))
        }

        /// Build the `netsh -f` lines for `rules`, starting at `offset`, and the rule
        /// names they create. Kept separate from [`Self::append_rules`] so the
        /// numbering can be tested without administrator rights.
        pub(crate) fn append_commands(
            rules: &[FirewallRule],
            offset: usize,
        ) -> (Vec<String>, Vec<String>) {
            let mut commands = Vec::new();
            let mut created = Vec::new();
            for (j, rule) in rules.iter().enumerate() {
                let index = offset + j;
                if rule.program.is_some() {
                    let name = format!("{RULE_PREFIX}{index}-app");
                    let args = Self::add_rule_args_named(rule, &name, false, None);
                    commands.push(args.join(" "));
                    created.push(name);
                } else if rule.port.is_some() {
                    for protocol in ["tcp", "udp"] {
                        let name = format!("{RULE_PREFIX}{index}-{protocol}");
                        let args = Self::add_rule_args_named(rule, &name, false, Some(protocol));
                        commands.push(args.join(" "));
                        created.push(name);
                    }
                } else {
                    let name = format!("{RULE_PREFIX}{index}");
                    let args = Self::add_rule_args(rule, index, false);
                    commands.push(args.join(" "));
                    created.push(name);
                }
            }
            (commands, created)
        }

        fn write_state(names: &[String]) -> Result<()> {
            let path = state_path();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            write_atomic(&path, names.join("\n").as_bytes())
        }

        /// Scan all rules for our name prefix (fallback when there is no state file,
        /// e.g. to clean up rules left by an older build).
        fn enumerate_rule_names() -> Vec<String> {
            match run(
                NETS,
                &["advfirewall", "firewall", "show", "rule", "name=all"],
            ) {
                Ok((true, out)) => out
                    .lines()
                    .filter_map(|line| line.trim_start().strip_prefix("Rule Name:"))
                    .map(|n| n.trim().to_string())
                    .filter(|n| Self::is_our_rule_name(n))
                    .collect(),
                _ => Vec::new(),
            }
        }

        /// Names of every firewall rule we own: prefer the state file, fall back to
        /// enumerating all rules.
        fn existing_rule_names() -> Vec<String> {
            let names = Self::state_rule_names();
            if !names.is_empty() {
                return names;
            }
            Self::enumerate_rule_names()
        }

        /// Map a profile name from `netsh` output to the token used by `set`.
        fn profile_key(name: &str) -> String {
            match name {
                "Domain" => "domainprofile".to_string(),
                "Private" => "privateprofile".to_string(),
                "Public" => "publicprofile".to_string(),
                other => format!("{}profile", other.to_ascii_lowercase()),
            }
        }

        /// Read each profile's current outbound firewall policy.
        fn read_policies() -> Vec<(String, String)> {
            let out = match run(
                NETS,
                &["advfirewall", "show", "allprofiles", "firewallpolicy"],
            ) {
                Ok((true, out)) => out,
                _ => return Vec::new(),
            };
            let mut current: Option<String> = None;
            let mut policies = Vec::new();
            for line in out.lines() {
                let t = line.trim();
                if let Some(name) = t.strip_suffix("Profile Settings:") {
                    current = Some(Self::profile_key(name.trim()));
                } else if let Some(rest) = t.strip_prefix("Firewall Policy") {
                    if let Some(key) = current.clone() {
                        let value = rest.trim();
                        if !value.is_empty() {
                            policies.push((key, value.to_string()));
                        }
                    }
                }
            }
            policies
        }

        fn save_policies() -> Result<()> {
            let policies = Self::read_policies();
            if policies.is_empty() {
                log::warn!(
                    "netsh: could not read the current firewall policy; it will not be restored"
                );
                return Ok(());
            }
            let path = policy_path();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let text = policies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("\n");
            log::info!("netsh: saved prior firewall policy: {text}");
            write_atomic(&path, text.as_bytes())
        }

        /// Restore the outbound policy recorded by [`save_policies`], if any.
        fn restore_policies() {
            let path = policy_path();
            let Ok(text) = std::fs::read_to_string(&path) else {
                return;
            };
            for line in text.lines() {
                let Some((key, value)) = line.split_once('=') else {
                    continue;
                };
                let key = key.trim();
                let value = value.trim();
                if key.is_empty() || value.is_empty() {
                    continue;
                }
                log::info!("netsh: restoring firewall policy {key} -> {value}");
                let _ = run(NETS, &["advfirewall", "set", key, "firewallpolicy", value]);
            }
            let _ = std::fs::remove_file(&path);
        }
    }

    impl FirewallBackend for NetshFirewall {
        fn name(&self) -> &'static str {
            "netsh"
        }

        fn add_rule(&mut self, rule: FirewallRule) {
            self.rules.push(rule);
        }

        fn start_block(&mut self, allowlist: bool) -> Result<()> {
            log::info!("netsh: start_block (allowlist={allowlist})");
            self.allowlist = allowlist;
            // Clean any previous rules first (also restores a previously saved policy).
            // A failed cleanup must abort the new block: continuing could leave old
            // rules mixed with the new ones.
            self.stop_block(true)?;

            // Build every command up front as a `netsh -f` batch script. Applying
            // thousands of rules one process per rule takes minutes and makes the
            // app look like malware to AV heuristics; a single netsh process does it
            // in one shot.
            let mut commands: Vec<String> = Vec::new();
            let mut created: Vec<String> = Vec::new();

            if allowlist {
                // No rule can whitelist through a block-all on Windows because block
                // rules win over allow rules, so we flip the default outbound policy
                // to block and add explicit allows — but first remember what the
                // policy was, so we can put it back.
                Self::save_policies()?;
                commands.push(
                    "advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound"
                        .to_string(),
                );
            }

            for (i, rule) in self.rules.iter().enumerate() {
                if rule.program.is_some() {
                    // One program rule per executable; netsh matches `program=` to
                    // the image path (no protocol/port involved).
                    let name = format!("{RULE_PREFIX}{i}-app");
                    let args = Self::add_rule_args_named(rule, &name, allowlist, None);
                    commands.push(args.join(" "));
                    created.push(name);
                } else if rule.port.is_some() {
                    // netsh needs a concrete protocol when a port is given.
                    for protocol in ["tcp", "udp"] {
                        let name = format!("{RULE_PREFIX}{i}-{protocol}");
                        let args =
                            Self::add_rule_args_named(rule, &name, allowlist, Some(protocol));
                        commands.push(args.join(" "));
                        created.push(name);
                    }
                } else {
                    let name = format!("{RULE_PREFIX}{i}");
                    let args = Self::add_rule_args(rule, i, allowlist);
                    commands.push(args.join(" "));
                    created.push(name);
                }
            }

            if allowlist {
                // Always permit DNS/DHCP/mDNS so the machine stays usable.
                for port in [53u16, 123, 67, 68, 5353] {
                    for proto in ["tcp", "udp"] {
                        let name = format!("{RULE_PREFIX}svc-{proto}-{port}");
                        commands.push(format!(
                            "advfirewall firewall add rule name={name} dir=out action=allow protocol={proto} remoteport={port}"
                        ));
                        created.push(name);
                    }
                }
            }

            // Record the intended names *before* applying, so a partial failure can
            // still be cleaned up by name.
            Self::write_state(&created)?;

            let script = script_path();
            if let Some(parent) = script.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let script_text = commands.join("\r\n");
            write_atomic(&script, script_text.as_bytes())?;

            if commands.len() <= 100 {
                log::debug!(
                    "netsh: script ({} commands):\n{}",
                    commands.len(),
                    script_text
                );
            } else {
                for command in &commands {
                    log::debug!("netsh: script: {command}");
                }
            }
            // Always name the program rules explicitly: when an application cannot be
            // blocked, this is the first line to look at in the log.
            for command in &commands {
                if command.contains("program=") {
                    log::info!("netsh: application rule: {command}");
                }
            }

            log::info!(
                "netsh: applying {} command(s) (allowlist={allowlist}) in one batch",
                commands.len()
            );
            let script_arg = script.display().to_string();
            let result = run_checked(NETS, &["-f", &script_arg]);
            match &result {
                Ok(_) => {
                    let _ = std::fs::remove_file(&script);
                }
                Err(_) => {
                    // Keep the exact batch that failed; it is the fastest way to see
                    // which generated line netsh rejected.
                    log::error!(
                        "netsh: batch failed; keeping it for diagnosis at {}",
                        script.display()
                    );
                }
            }

            match result {
                Ok(_) => {
                    log::info!(
                        "netsh: recorded {} rule name(s) in state file",
                        created.len()
                    );
                    Ok(())
                }
                Err(e) => {
                    // Leave the state file in place: the manager's rollback calls
                    // stop_block, which deletes every name we intended to create.
                    Err(e)
                }
            }
        }

        fn append_rules(&mut self, allowlist: bool) -> Result<()> {
            if self.rules.is_empty() {
                return Ok(());
            }
            if allowlist {
                return Err(Error::Unsupported(
                    "cannot add entries to an allowlist block".into(),
                ));
            }
            log::info!(
                "netsh: appending {} rule(s) to the active block",
                self.rules.len()
            );

            let previous_state = Self::existing_rule_names();
            let offset = Self::next_rule_index(&previous_state);
            let (commands, created) = Self::append_commands(&self.rules, offset);

            // Record the intended names *before* applying, so a partial failure can
            // still be cleaned up by name.
            let mut new_state = previous_state.clone();
            new_state.extend(created.iter().cloned());
            Self::write_state(&new_state)?;

            let script_path = Self::append_script_path("add");
            if let Some(parent) = script_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let script_text = commands.join("\r\n");
            write_atomic(&script_path, script_text.as_bytes())?;
            log::debug!(
                "netsh: append script ({} commands):\n{}",
                commands.len(),
                script_text
            );

            let script_arg = script_path.display().to_string();
            match run_checked(NETS, &["-f", script_arg.as_str()]) {
                Ok(_) => {
                    let _ = std::fs::remove_file(&script_path);
                    log::info!(
                        "netsh: appended {} rule(s) to the active block",
                        created.len()
                    );
                    Ok(())
                }
                Err(e) => {
                    log::error!(
                        "netsh: append failed; keeping the batch for diagnosis at {}",
                        script_path.display()
                    );
                    // netsh may have created some rules before it failed: delete
                    // exactly the names we intended to add, then put the original
                    // state file back so a later clear removes only the old rules.
                    let rollback_path = Self::append_script_path("rollback");
                    let rollback = created
                        .iter()
                        .map(|name| format!("advfirewall firewall delete rule name={name}"))
                        .collect::<Vec<_>>()
                        .join("\r\n");
                    if write_atomic(&rollback_path, rollback.as_bytes()).is_ok() {
                        let rollback_arg = rollback_path.display().to_string();
                        let _ = run(NETS, &["-f", rollback_arg.as_str()]);
                        let _ = std::fs::remove_file(&rollback_path);
                    }
                    let _ = Self::write_state(&previous_state);
                    Err(e)
                }
            }
        }

        fn refresh(&self) -> Result<()> {
            let mut clone = NetshFirewall {
                rules: self.rules.clone(),
                allowlist: self.allowlist,
            };
            clone.start_block(self.allowlist)
        }

        fn contains_block(&self) -> bool {
            !Self::existing_rule_names().is_empty()
        }

        fn stop_block(&self, _force: bool) -> Result<()> {
            let names = Self::existing_rule_names();
            if names.is_empty() {
                // No rules to delete: it is safe to restore the policy and drop a
                // stale/empty state file.
                Self::restore_policies();
                let _ = std::fs::remove_file(state_path());
                return Ok(());
            }

            log::info!("netsh: removing {} SelfLock rule(s)", names.len());
            let mut commands: Vec<String> = Vec::new();
            for name in &names {
                commands.push(format!("advfirewall firewall delete rule name={name}"));
            }

            let script = script_path();
            if let Some(parent) = script.parent() {
                std::fs::create_dir_all(parent)?;
            }
            write_atomic(&script, commands.join("\r\n").as_bytes())?;

            let script_arg = script.display().to_string();
            let (success, output) = run(NETS, &["-f", &script_arg])?;
            if !success {
                // Keep the state file: it is the only reliable list of rules that
                // still need removing. Do not restore the old firewall policy while
                // rules may still be active.
                log::error!(
                    "netsh: deleting rules failed; keeping state at {}: {}",
                    state_path().display(),
                    brief(&output)
                );
                return Err(Error::Command {
                    command: format!("netsh -f {}", script.display()),
                    message: output.trim().to_string(),
                });
            }

            let _ = std::fs::remove_file(&script);
            let _ = std::fs::remove_file(state_path());
            // Restore the user's original outbound policy only after the rules are
            // actually gone.
            Self::restore_policies();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_new_normalizes_zero() {
        let r = FirewallRule::new(Some("1.2.3.4".into()), 0, 0);
        assert_eq!(r.port, None);
        assert_eq!(r.mask_len, None);
    }

    #[test]
    fn validates_rule_names_from_state() {
        for name in [
            "SelfLock-0",
            "SelfLock-12-app",
            "SelfLock-3-tcp",
            "SelfLock-svc-udp-5353",
        ] {
            assert!(netsh::NetshFirewall::is_our_rule_name(name), "{name}");
        }
        for name in [
            "Other-0",
            "SelfLock-",
            "SelfLock-0 dir=in",
            "SelfLock-0\r\nadvfirewall set allprofiles firewallpolicy allowinbound,allowoutbound",
            "SelfLock-0;calc",
        ] {
            assert!(!netsh::NetshFirewall::is_our_rule_name(name), "{name:?}");
        }
    }

    #[test]
    fn netsh_args() {
        let args = netsh::NetshFirewall::add_rule_args(
            &FirewallRule::new(Some("1.2.3.0".into()), 443, 24),
            0,
            false,
        );
        assert!(args.contains(&"action=block".to_string()));
        assert!(args.contains(&"remoteip=1.2.3.0/24".to_string()));
        assert!(args.contains(&"remoteport=443".to_string()));
    }

    #[test]
    fn netsh_app_rule_is_always_a_block() {
        let rule = FirewallRule::app("C:\\Program Files\\Mozilla Firefox\\firefox.exe");
        let args = netsh::NetshFirewall::add_rule_args(&rule, 0, false);
        assert!(args.contains(&"action=block".to_string()));
        assert!(args
            .contains(&"program=\"C:\\Program Files\\Mozilla Firefox\\firefox.exe\"".to_string()));
        assert!(!args.iter().any(|a| a.starts_with("remoteip=")));
        assert!(!args.iter().any(|a| a.starts_with("remoteport=")));

        // Even in allowlist mode an application entry must not become an allow rule.
        let allowlist_args = netsh::NetshFirewall::add_rule_args(&rule, 0, true);
        assert!(allowlist_args.contains(&"action=block".to_string()));
    }

    #[test]
    fn netsh_next_rule_index_skips_suffixes_and_service_rules() {
        let names = vec![
            "SelfLock-0".to_string(),
            "SelfLock-1-app".to_string(),
            "SelfLock-2-tcp".to_string(),
            "SelfLock-2-udp".to_string(),
            "SelfLock-svc-tcp-53".to_string(),
            "SelfLock-svc-udp-5353".to_string(),
        ];
        assert_eq!(netsh::NetshFirewall::next_rule_index(&names), 3);
    }

    #[test]
    fn netsh_next_rule_index_starts_at_zero() {
        assert_eq!(netsh::NetshFirewall::next_rule_index(&[]), 0);
        assert_eq!(
            netsh::NetshFirewall::next_rule_index(&["SelfLock-svc-tcp-53".to_string()]),
            0
        );
    }

    #[test]
    fn netsh_append_commands_use_the_offset_and_suffixes() {
        let rules = vec![
            FirewallRule::new(Some("1.2.3.4".into()), 0, 0),
            FirewallRule::new(Some("1.2.3.5".into()), 443, 0),
            FirewallRule::app("C:\\Program Files\\App\\app.exe"),
        ];
        let (commands, names) = netsh::NetshFirewall::append_commands(&rules, 7);
        assert_eq!(
            names,
            vec![
                "SelfLock-7".to_string(),
                "SelfLock-8-tcp".to_string(),
                "SelfLock-8-udp".to_string(),
                "SelfLock-9-app".to_string(),
            ]
        );
        assert_eq!(commands.len(), 4);
        assert!(commands[0].contains("name=SelfLock-7"));
        assert!(commands[0].contains("remoteip=1.2.3.4"));
        assert!(commands[3].contains("program=\"C:\\Program Files\\App\\app.exe\""));
        assert!(commands[3].contains("action=block"));
    }
}
