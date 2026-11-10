//! Application-block entries (`app:...`).
//!
//! SelfLock's normal blocklist is host/IP oriented, and
//! [`crate::cleaner::clean_blocklist_entry`] deliberately strips everything that
//! is not legal in a DNS name. That would turn `C:\Program Files\…\firefox.exe`
//! into the useless hostname `c`. Application entries therefore bypass the
//! hostname cleaner and are kept as Windows paths / image names.
//!
//! Accepted forms:
//!
//! ```text
//! app:firefox.exe
//! app:C:\Program Files\Mozilla Firefox\firefox.exe
//! app:"C:\Program Files\Mozilla Firefox\firefox.exe"
//! ```
//!
//! A bare image name is resolved to one or more full paths at block start
//! (registry `App Paths`, `where.exe`, and a bounded scan of the common install
//! roots). Windows Firewall `program=` rules require a full path, so a name that
//! cannot be resolved is reported as an error instead of silently doing nothing.

use std::path::PathBuf;

/// Prefix that marks a blocklist entry as an application.
pub const PREFIX: &str = "app:";

/// Return the part after a case-insensitive `app:` prefix.
pub fn strip_prefix(input: &str) -> Option<&str> {
    if input.len() >= PREFIX.len()
        && input.is_char_boundary(PREFIX.len())
        && input[..PREFIX.len()].eq_ignore_ascii_case(PREFIX)
    {
        Some(&input[PREFIX.len()..])
    } else {
        None
    }
}

/// Validate and normalize one application spec (without the `app:` prefix).
///
/// The path is deliberately *not* lower-cased: Windows paths are case-insensitive,
/// but keeping the user's spelling makes logs and the UI readable.
pub fn normalize_spec(input: &str) -> Option<String> {
    let mut s = input.trim();

    // Allow the whole spec to be quoted, which is convenient for paths with
    // spaces when the value comes from a shell.
    if s.len() >= 2 {
        let bytes = s.as_bytes();
        if (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')
        {
            s = s[1..s.len() - 1].trim();
        }
    }

    if s.is_empty() {
        return None;
    }

    // Control characters would corrupt the netsh batch script or the saved
    // blocklist. Embedded quotes are rejected for the same reason.
    if s.chars().any(|c| c.is_control()) || s.contains('"') {
        return None;
    }

    // Characters that are illegal in Windows file names and have no place here.
    if s.chars().any(|c| matches!(c, '<' | '>' | '|' | '?' | '*')) {
        return None;
    }

    let looks_like_path =
        s.contains('\\') || s.contains('/') || s.starts_with("\\\\") || is_drive_path(s);

    if looks_like_path {
        // Reject a bare drive letter plus colon with no path (`C:`); that is not a
        // usable executable anyway.
        if s.ends_with(':') {
            return None;
        }
    } else {
        // A bare image name must look like an executable. This catches typos such
        // as `firefox` or `firefox.exe:80` early.
        let lower = s.to_ascii_lowercase();
        if !(lower.ends_with(".exe") || lower.ends_with(".com")) || s.contains(':') {
            return None;
        }
    }

    Some(s.to_string())
}

/// True for `C:\…` / `C:/…` (not the drive-relative `C:foo`).
fn is_drive_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// Resolve an application spec to the executable path(s) that Firewall rules
/// should reference.
pub fn resolve(spec: &str) -> Vec<PathBuf> {
    windows_impl::resolve(spec)
}

mod windows_impl {
    use super::*;
    use crate::process::hidden_command;
    use std::collections::HashSet;

    pub fn resolve(spec: &str) -> Vec<PathBuf> {
        log::debug!("apps: resolving {spec:?}");
        let direct = PathBuf::from(spec);

        // Explicit path: use it as-is when it exists. A path containing a
        // separator is never treated as an image name.
        if direct.is_absolute() || spec.contains('\\') || spec.contains('/') {
            let result = if direct.is_file() {
                vec![direct]
            } else {
                Vec::new()
            };
            log::debug!("apps: {spec:?} treated as an explicit path -> {result:?}");
            return result;
        }

        let mut candidates: Vec<PathBuf> = Vec::new();

        // 1) Registered `App Paths` (this is how Chrome/Edge style installs are
        //    found). Both registry views and HKCU are checked.
        for hive in ["HKLM", "HKCU"] {
            for view in ["", "WOW6432Node\\"] {
                let key = format!(
                    "{hive}\\SOFTWARE\\{view}Microsoft\\Windows\\CurrentVersion\\App Paths\\{spec}"
                );
                for value in query_registry(&key) {
                    candidates.push(PathBuf::from(expand_env(&value)));
                }
            }
        }
        log::debug!("apps: registry App Paths candidates: {candidates:?}");

        // 2) `where.exe` (programs on PATH).
        if let Ok(output) = hidden_command("where").arg(spec).output() {
            if output.status.success() {
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    let line = line.trim();
                    if !line.is_empty() {
                        candidates.push(PathBuf::from(line));
                    }
                }
            }
        }
        log::debug!("apps: after where.exe, candidates: {candidates:?}");

        // 3) Installed-application registry. Per-user installers such as cTrader
        //    register neither `App Paths` nor `PATH`, but they do create an
        //    `Uninstall` key whose `InstallLocation`, `DisplayIcon` or
        //    `UninstallString` points into the real install directory.
        if !candidates.iter().any(|p| p.is_file()) {
            let (hint_files, hint_dirs) = uninstall_hints(spec);
            log::debug!("apps: uninstall registry files: {hint_files:?}");
            log::debug!("apps: uninstall registry dirs: {hint_dirs:?}");
            candidates.extend(hint_files);

            // The advertised install directory usually contains the executable
            // directly (`…\cTrader\<hash>\cTrader.exe`); check that first.
            let mut direct_hits = Vec::new();
            for dir in &hint_dirs {
                let candidate = dir.join(spec);
                if candidate.is_file() {
                    direct_hits.push(candidate);
                }
            }
            candidates.extend(direct_hits.iter().cloned());

            // Many per-user apps ship a launcher plus side-by-side copies (for
            // example `…\cTrader\<hash>\cTrader.exe` and
            // `…\<hash>\app_x\x64\cTrader.exe`). Scan the parent of every direct
            // hit so all copies are blocked, not just the launcher.
            let mut found = Vec::new();
            for hit in &direct_hits {
                if let Some(parent) = hit.parent() {
                    let mut budget = 5_000usize;
                    scan_dir(parent, spec, 3, &mut budget, &mut found);
                }
            }
            log::debug!("apps: side-by-side copies found: {found:?}");
            candidates.extend(found);

            if !candidates.iter().any(|p| p.is_file()) {
                // Shallow scan with a per-directory budget so a single huge
                // directory (e.g. a shared vendor folder) cannot starve the rest.
                let mut found = Vec::new();
                for dir in hint_dirs {
                    let mut budget = 2_000usize;
                    scan_dir(&dir, spec, 2, &mut budget, &mut found);
                    if !found.is_empty() {
                        break;
                    }
                }
                log::debug!("apps: uninstall directory scan found: {found:?}");
                candidates.extend(found);
            }
        }

        // 4) Bounded scan of the usual install roots. This is the last-resort
        //    fallback for portable installs and apps with no registry trace.
        if !candidates.iter().any(|p| p.is_file()) {
            log::debug!("apps: no existing candidate yet; scanning install roots");
            let mut budget = 30_000usize;
            let mut found = Vec::new();
            for root in scan_roots() {
                scan_dir(&root, spec, scan_depth(&root), &mut budget, &mut found);
                if budget == 0 {
                    log::warn!("apps: filesystem scan budget exhausted before finding {spec:?}");
                    break;
                }
            }
            log::debug!("apps: filesystem scan found: {found:?}");
            candidates.extend(found);
        }

        // Keep only existing files whose basename actually matches the requested
        // image name, then deduplicate case-insensitively (Windows semantics).
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for path in candidates {
            if !path.is_file() {
                continue;
            }
            let matches_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.eq_ignore_ascii_case(spec))
                .unwrap_or(false);
            if !matches_name {
                continue;
            }
            let key = path.to_string_lossy().to_ascii_lowercase();
            if seen.insert(key) {
                out.push(path);
            }
        }
        log::debug!("apps: resolved {spec:?} -> {out:?}");
        out
    }

    /// Split one `reg.exe query` output line into `(value name, string value)`.
    ///
    /// Example line: `    DisplayIcon    REG_SZ    C:\App\app.exe,0`.
    fn split_reg_value(line: &str) -> Option<(&str, String)> {
        for marker in ["REG_EXPAND_SZ", "REG_SZ"] {
            if let Some(pos) = line.find(marker) {
                let name = line[..pos].trim();
                let value = line[pos + marker.len()..].trim().trim_matches('"');
                return Some((name, value.to_string()));
            }
        }
        None
    }

    /// Read all string values of a registry key with `reg.exe`.
    ///
    /// `REG_SZ`/`REG_EXPAND_SZ` are not localized, so this works on non-English
    /// Windows. Paths with non-ASCII characters may be mangled by the console code
    /// page; the filesystem scan is the Unicode-safe fallback for those.
    fn query_registry(key: &str) -> Vec<String> {
        let output = match hidden_command("reg").args(["query", key]).output() {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let mut values = Vec::new();
        for line in text.lines() {
            if let Some((_, value)) = split_reg_value(line) {
                if !value.is_empty() {
                    values.push(value);
                }
            }
        }
        values
    }

    /// Directories/executables advertised by the `Uninstall` registry keys.
    ///
    /// Returns `(candidate executables, directories worth scanning)`. Only
    /// `InstallLocation`, `DisplayIcon` and `UninstallString` are used: they are
    /// the values that point at the install directory of per-user applications.
    fn uninstall_hints(spec: &str) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let mut files = Vec::new();
        let mut dirs: Vec<PathBuf> = Vec::new();
        let mut seen_dirs = HashSet::new();

        for root in [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ] {
            let output = match hidden_command("reg").args(["query", root, "/s"]).output() {
                Ok(o) if o.status.success() => o,
                _ => continue,
            };
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let Some((name, value)) = split_reg_value(line) else {
                    continue;
                };
                let value = expand_env(&value);
                match name {
                    "InstallLocation" => {
                        let path = PathBuf::from(value.trim());
                        if path.is_dir()
                            && is_helpful_install_dir(&path)
                            && seen_dirs.insert(lower_key(&path))
                        {
                            dirs.push(path);
                        }
                    }
                    "DisplayIcon" | "UninstallString" => {
                        let Some(path) = exe_from_reg_value(&value) else {
                            continue;
                        };
                        let matches = path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .map(|n| n.eq_ignore_ascii_case(spec))
                            .unwrap_or(false);
                        if matches {
                            files.push(path.clone());
                        }
                        if let Some(parent) = path.parent() {
                            if parent.is_dir()
                                && is_helpful_install_dir(parent)
                                && seen_dirs.insert(lower_key(parent))
                            {
                                dirs.push(parent.to_path_buf());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        (files, dirs)
    }

    /// Extract an executable path from a `DisplayIcon` / `UninstallString` value.
    ///
    /// Handles `"C:\Dir\App.exe" /silent`, `C:\Dir\App.exe,0` and plain paths.
    fn exe_from_reg_value(value: &str) -> Option<PathBuf> {
        let value = value.trim();
        let raw = if let Some(rest) = value.strip_prefix('"') {
            rest.split('"').next().unwrap_or("")
        } else {
            // Unquoted DisplayIcon values may carry a `,index` suffix.
            value.split(',').next().unwrap_or("").trim()
        };
        if raw.is_empty() {
            return None;
        }
        Some(PathBuf::from(raw))
    }

    fn lower_key(path: &std::path::Path) -> String {
        path.to_string_lossy().to_ascii_lowercase()
    }

    /// Reject install directories that are really system/MSI caches: scanning them
    /// is slow and they never contain a normal desktop application.
    fn is_helpful_install_dir(path: &std::path::Path) -> bool {
        let lower = lower_key(path);
        if lower.starts_with(r"c:\windows")
            || lower.starts_with(r"c:\programdata\package cache")
            || lower.starts_with(r"c:\programdata\microsoft")
            || lower.contains(r"\installshield installation information")
        {
            return false;
        }
        // A bare vendor root (`C:\Program Files`) is too broad for a hinted scan;
        // the broad-scan step already covers it with a budget.
        for broad in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
            if let Ok(value) = std::env::var(broad) {
                if !value.is_empty() && lower == value.to_ascii_lowercase() {
                    return false;
                }
            }
        }
        true
    }

    fn scan_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();
        for var in [
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramW6432",
            "LOCALAPPDATA",
        ] {
            if let Ok(value) = std::env::var(var) {
                if !value.is_empty() {
                    roots.push(PathBuf::from(value));
                }
            }
        }
        // `%LOCALAPPDATA%\Programs` is where per-user installs usually live; the
        // LOCALAPPDATA root itself is scanned shallowly (see scan_depth).
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            if !local.is_empty() {
                roots.push(PathBuf::from(local).join("Programs"));
            }
        }

        let mut seen = HashSet::new();
        roots.retain(|p| seen.insert(p.to_string_lossy().to_ascii_lowercase()));
        roots
    }

    fn scan_depth(root: &std::path::Path) -> usize {
        // Program Files has stable `<Vendor>\<Product>\app.exe` layouts. The user
        // profile is much larger, so keep that scan shallow.
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            if !local.is_empty() && root.starts_with(std::path::Path::new(&local)) {
                return 2;
            }
        }
        4
    }

    fn scan_dir(
        dir: &std::path::Path,
        file_name: &str,
        depth: usize,
        budget: &mut usize,
        out: &mut Vec<PathBuf>,
    ) {
        if *budget == 0 {
            return;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            if *budget == 0 {
                return;
            }
            *budget -= 1;

            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };

            if file_type.is_file() {
                let matches = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.eq_ignore_ascii_case(file_name))
                    .unwrap_or(false);
                if matches {
                    out.push(path);
                }
            } else if file_type.is_dir() && depth > 0 {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                // Skip reparse-point-heavy or huge directories that cannot contain a
                // normal desktop application.
                if matches!(
                    name,
                    "WindowsApps"
                        | "Windows Defender"
                        | "$Recycle.Bin"
                        | "System Volume Information"
                        | "node_modules"
                        | ".git"
                ) {
                    continue;
                }
                scan_dir(&path, file_name, depth - 1, budget, out);
            }
        }
    }

    /// Expand `%VAR%` sequences (registry values may be `REG_EXPAND_SZ`).
    fn expand_env(input: &str) -> String {
        let mut out = input.to_string();
        for _ in 0..4 {
            let Some(start) = out.find('%') else { break };
            let Some(rel_end) = out[start + 1..].find('%') else {
                break;
            };
            let end = start + 1 + rel_end;
            let var = &out[start + 1..end];
            let Ok(value) = std::env::var(var) else {
                break;
            };
            out.replace_range(start..=end, &value);
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_registry_value_lines() {
            let (name, value) =
                split_reg_value(r#"    DisplayIcon    REG_SZ    C:\App\app.exe,0"#).unwrap();
            assert_eq!(name, "DisplayIcon");
            assert_eq!(value, r"C:\App\app.exe,0");

            let (name, value) =
                split_reg_value(r#"    InstallLocation    REG_EXPAND_SZ    %LocalAppData%\App"#)
                    .unwrap();
            assert_eq!(name, "InstallLocation");
            assert_eq!(value, r"%LocalAppData%\App");

            // Key headers and non-string values are ignored.
            assert!(split_reg_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\...").is_none());
            assert!(split_reg_value("    EstimatedSize    REG_DWORD    0x10").is_none());
        }

        #[test]
        fn extracts_executable_from_registry_values() {
            assert_eq!(
                exe_from_reg_value(r#""C:\Dir\App.exe" /silent"#).unwrap(),
                PathBuf::from(r"C:\Dir\App.exe")
            );
            assert_eq!(
                exe_from_reg_value(r"C:\Dir\App.exe,0").unwrap(),
                PathBuf::from(r"C:\Dir\App.exe")
            );
            assert!(exe_from_reg_value("").is_none());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_prefix_case_insensitively() {
        assert_eq!(strip_prefix("app:firefox.exe"), Some("firefox.exe"));
        assert_eq!(strip_prefix("APP:C:\\x\\y.exe"), Some("C:\\x\\y.exe"));
        assert_eq!(strip_prefix("application"), None);
        assert_eq!(strip_prefix("firefox.exe"), None);
    }

    #[test]
    fn accepts_image_names_and_paths() {
        assert_eq!(
            normalize_spec("firefox.exe").as_deref(),
            Some("firefox.exe")
        );
        assert_eq!(
            normalize_spec("C:\\Program Files\\Mozilla Firefox\\firefox.exe").as_deref(),
            Some("C:\\Program Files\\Mozilla Firefox\\firefox.exe")
        );
        assert_eq!(
            normalize_spec("\"C:\\Program Files\\Mozilla Firefox\\firefox.exe\"").as_deref(),
            Some("C:\\Program Files\\Mozilla Firefox\\firefox.exe")
        );
        assert_eq!(
            normalize_spec("\\\\server\\share\\app.exe").as_deref(),
            Some("\\\\server\\share\\app.exe")
        );
    }

    #[test]
    fn resolves_a_system_executable() {
        // `notepad.exe` is on PATH, so this exercises `where.exe` without the
        // slower Program Files scan.
        let paths = resolve("notepad.exe");
        assert!(!paths.is_empty(), "notepad.exe should resolve");
        assert!(paths.iter().all(|p| p.is_file()));
        assert!(paths
            .iter()
            .any(|p| p.file_name().unwrap().eq_ignore_ascii_case("notepad.exe")));

        let direct = resolve(r"C:\Windows\System32\notepad.exe");
        assert_eq!(direct.len(), 1);
        assert!(direct[0].is_file());
    }

    #[test]
    fn resolves_explicit_unicode_path() {
        let dir = std::env::temp_dir().join(format!(
            "SelfLock-кириллица-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("приложение.exe");
        std::fs::write(&exe, b"MZ").unwrap();

        let resolved = resolve(exe.to_str().unwrap());
        assert_eq!(resolved, vec![exe.clone()]);

        let normalized = normalize_spec(exe.to_str().unwrap());
        assert_eq!(normalized.as_deref(), exe.to_str());

        let _ = std::fs::remove_file(&exe);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolves_firefox_when_installed() {
        let known = std::path::Path::new(r"C:\Program Files\Mozilla Firefox\firefox.exe");
        if !known.is_file() {
            return; // Firefox is not installed on this machine; nothing to check.
        }
        let paths = resolve("firefox.exe");
        let known = known.to_string_lossy().to_ascii_lowercase();
        assert!(
            paths
                .iter()
                .any(|p| p.to_string_lossy().to_ascii_lowercase() == known),
            "expected firefox.exe to resolve to {known}, got {paths:?}"
        );
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(normalize_spec(""), None);
        assert_eq!(normalize_spec("   "), None);
        assert_eq!(normalize_spec("firefox"), None);
        assert_eq!(normalize_spec("firefox.exe:80"), None);
        assert_eq!(normalize_spec("C:\\bad\nname.exe"), None);
        assert_eq!(normalize_spec("C:\\bad\"name.exe"), None);
        assert_eq!(normalize_spec("C:\\bad*name.exe"), None);
    }
}
