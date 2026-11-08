//! Port of `+[SCMiscUtilities cleanBlocklistEntry:]` and `+cleanBlocklist:`.
//!
//! Normalizes and sanitizes user-provided blocklist input so it renders and blocks
//! correctly. This is the single trusted entry point for raw blocklist text: every
//! caller (CLI and GUI) must route input through it before it reaches the hosts
//! file or the firewall.

use crate::apps;
use std::net::Ipv6Addr;

fn is_newline(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{0085}' | '\u{2028}' | '\u{2029}')
}

/// Port of `+[SCMiscUtilities cleanBlocklistEntry:]`, extended to preserve IPv6
/// literals (splitting them on `:` the way the original does would keep only the
/// first hextet).
///
/// Because the input may contain line breaks, a single raw entry can expand into
/// several cleaned entries, so this returns a `Vec`.
pub fn clean_blocklist_entry(raw_entry: &str) -> Vec<String> {
    let trimmed = raw_entry.trim();

    // If there are newlines, split and process each part independently. Do this
    // before lower-casing so application paths keep their original case.
    if trimmed.chars().any(is_newline) {
        let mut out = Vec::new();
        for part in trimmed.split(is_newline) {
            out.extend(clean_blocklist_entry(part));
        }
        return out;
    }

    // Application entries (`app:firefox.exe`, `app:C:\…\firefox.exe`) must not go
    // through the hostname sanitizer: it would strip `\`, `:`, spaces and turn a
    // path into a useless single letter.
    if let Some(spec) = apps::strip_prefix(trimmed) {
        return match apps::normalize_spec(spec) {
            Some(spec) => vec![format!("{}{}", apps::PREFIX, spec)],
            None => Vec::new(),
        };
    }

    // Remove surrounding whitespace and lowercase.
    let s = trimmed.to_lowercase();

    // Strip a scheme (https://, http://, ...) — we only block hostnames.
    let s = match s.split("://").last() {
        Some(last) => last.to_string(),
        None => s,
    };

    // Strip URL credentials (user:pass@host).
    let s = match s.split('@').next_back() {
        Some(last) => last.to_string(),
        None => s,
    };

    if s.is_empty() {
        return Vec::new();
    }

    // Split an optional CIDR mask. IPv6 literals never contain '/', so this is safe.
    let (addr_part, had_mask) = match s.split_once('/') {
        Some((addr, mask)) => {
            let bits = mask.trim().parse::<i32>().unwrap_or(0);
            (
                addr.to_string(),
                if bits > 0 && bits <= 128 { bits } else { -1 },
            )
        }
        None => (s.clone(), -1),
    };

    // Bracketed IPv6, optionally with a port: `[2001:db8::1]` / `[2001:db8::1]:443`.
    if let Some(rest) = addr_part.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return Vec::new();
        };
        let inner = &rest[..close];
        if inner.parse::<Ipv6Addr>().is_err() {
            return Vec::new();
        }
        let after = &rest[close + 1..];
        let mask_string = if had_mask < 0 {
            String::new()
        } else {
            format!("/{had_mask}")
        };
        return match after {
            "" => vec![format!("[{inner}]{mask_string}")],
            _ => match after.strip_prefix(':').and_then(|p| p.parse::<u32>().ok()) {
                Some(p) if p > 0 && p <= 65535 => vec![format!("[{inner}]:{p}{mask_string}")],
                _ => Vec::new(),
            },
        };
    }

    // Bare IPv6 literal (more than one ':' implies IPv6). A zone id (`%eth0`) is a
    // link-local scope, not part of the address, so strip it.
    let ipv6_candidate = addr_part.split('%').next().unwrap_or(&addr_part);
    if let Ok(v6) = ipv6_candidate.parse::<Ipv6Addr>() {
        let mask_string = if had_mask < 0 {
            String::new()
        } else {
            format!("/{had_mask}")
        };
        return vec![format!("{v6}{mask_string}")];
    }

    // --- IPv4 / hostname handling (mirrors the original) ---
    let cidr_mask_bits: i32 = had_mask;
    let mut port_num: i32 = -1;

    let mut s = addr_part;

    // Check for a port.
    let colon_parts: Vec<&str> = s.split(':').collect();
    let before_colon = colon_parts[0].to_string();
    if colon_parts.len() > 1 {
        let potential = colon_parts[colon_parts.len() - 1]
            .trim()
            .parse::<i32>()
            .unwrap_or(0);
        if potential > 0 && potential <= 65535 {
            port_num = potential;
        }
    }
    s = before_colon;

    // Keep only hostname-legal characters: alphanumeric, '-', '.', '_' (max 253).
    let mut valid = String::with_capacity(s.len());
    for c in s.chars().take(253) {
        if c.is_alphanumeric() || matches!(c, '-' | '.' | '_') {
            valid.push(c);
        }
    }
    s = valid;

    // An empty hostname is only acceptable when we're blocking a bare port (`:80`).
    if s.is_empty() && port_num < 0 {
        return Vec::new();
    }

    let mask_string = if cidr_mask_bits < 0 {
        String::new()
    } else {
        format!("/{cidr_mask_bits}")
    };
    let port_string = if port_num < 0 {
        String::new()
    } else {
        format!(":{port_num}")
    };

    vec![format!("{s}{mask_string}{port_string}")]
}

/// Port of `+[SCMiscUtilities cleanBlocklist:]` — sanitizes every entry.
///
/// Unlike the original (which only trimmed), this routes each item through
/// [`clean_blocklist_entry`] so a saved `.selflock` file cannot inject extra
/// hosts-file lines via an embedded newline.
pub fn clean_blocklist(blocklist: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for item in blocklist {
        out.extend(clean_blocklist_entry(item));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercases_and_trims() {
        assert_eq!(
            clean_blocklist_entry("  Example.COM  "),
            vec!["example.com"]
        );
    }

    #[test]
    fn strips_scheme() {
        assert_eq!(
            clean_blocklist_entry("https://example.com/path"),
            vec!["example.com"]
        );
    }

    #[test]
    fn strips_credentials() {
        assert_eq!(
            clean_blocklist_entry("user:pass@Example.com"),
            vec!["example.com"]
        );
    }

    #[test]
    fn keeps_cidr_and_port() {
        assert_eq!(clean_blocklist_entry("83.0.1.2/24"), vec!["83.0.1.2/24"]);
        assert_eq!(
            clean_blocklist_entry("example.com:8080"),
            vec!["example.com:8080"]
        );
    }

    #[test]
    fn splits_newlines() {
        assert_eq!(
            clean_blocklist_entry("a.com\nb.com\rc.com"),
            vec!["a.com", "b.com", "c.com"]
        );
    }

    #[test]
    fn empty_input_is_empty() {
        assert!(clean_blocklist_entry("   ").is_empty());
        assert!(clean_blocklist_entry("http://").is_empty());
    }

    #[test]
    fn bare_port_is_kept() {
        assert_eq!(clean_blocklist_entry(":80"), vec![":80"]);
    }

    #[test]
    fn removes_invalid_chars() {
        assert_eq!(clean_blocklist_entry("exa mple!*.com"), vec!["example.com"]);
    }

    #[test]
    fn keeps_ipv6_literals() {
        assert_eq!(clean_blocklist_entry("2001:db8::1"), vec!["2001:db8::1"]);
        assert_eq!(clean_blocklist_entry("fe80::1%eth0"), vec!["fe80::1"]);
        assert_eq!(
            clean_blocklist_entry("[2001:db8::1]:443"),
            vec!["[2001:db8::1]:443"]
        );
        assert_eq!(
            clean_blocklist_entry("2001:db8::/32"),
            vec!["2001:db8::/32"]
        );
    }

    #[test]
    fn preserves_application_paths() {
        assert_eq!(
            clean_blocklist_entry("app:C:\\Program Files\\Mozilla Firefox\\firefox.exe"),
            vec!["app:C:\\Program Files\\Mozilla Firefox\\firefox.exe"]
        );
        assert_eq!(
            clean_blocklist_entry("APP:firefox.exe"),
            vec!["app:firefox.exe"]
        );
        assert_eq!(
            clean_blocklist_entry(" app:\"C:\\Program Files\\App\\app.exe\" "),
            vec!["app:C:\\Program Files\\App\\app.exe"]
        );
        assert!(clean_blocklist_entry("app:firefox").is_empty());
    }

    #[test]
    fn app_paths_are_not_lowercased() {
        let cleaned = clean_blocklist_entry("app:C:\\Program Files\\Mozilla Firefox\\Firefox.EXE");
        assert_eq!(
            cleaned,
            vec!["app:C:\\Program Files\\Mozilla Firefox\\Firefox.EXE"]
        );
    }

    #[test]
    fn clean_list_drops_blanks() {
        let input = vec![" a.com ".to_string(), "".to_string(), "   ".to_string()];
        assert_eq!(clean_blocklist(&input), vec!["a.com"]);
    }

    #[test]
    fn clean_list_neutralizes_injection() {
        let input = vec![
            "good.example".to_string(),
            "evil.test\n0.0.0.0\tbank.example".to_string(),
            "x.test evil2.test".to_string(),
        ];
        let cleaned = clean_blocklist(&input);
        assert!(cleaned.contains(&"good.example".to_string()));
        for entry in &cleaned {
            assert!(!entry.is_empty(), "empty entry survived");
            assert!(!entry.contains('\n'), "newline survived: {entry:?}");
            assert!(!entry.contains('\t'), "tab survived: {entry:?}");
            assert!(!entry.contains(' '), "space survived: {entry:?}");
        }
    }
}
