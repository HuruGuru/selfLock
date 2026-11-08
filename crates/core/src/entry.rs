//! Port of `SCBlockEntry` — a single thing to block (hostname, CIDR or `*`) with an
//! optional port and CIDR mask length.

use crate::apps;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

/// What kind of target a [`BlockEntry`] describes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    /// A hostname, IP address, CIDR range or `*` (the original model).
    #[default]
    Network,
    /// A Windows executable (`app:…`), blocked with a `program=` firewall rule.
    App,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockEntry {
    pub hostname: String,
    /// 0 means "no port specified" (mirrors the Objective-C `NSInteger port`).
    pub port: u16,
    /// 0 means "no mask specified".
    pub mask_len: u8,
    /// Network entries behave exactly like the original; app entries are a
    /// Windows-only extension.
    #[serde(default)]
    pub kind: EntryKind,
}

impl BlockEntry {
    pub fn new(hostname: impl Into<String>, port: u16, mask_len: u8) -> Self {
        BlockEntry {
            hostname: hostname.into(),
            port,
            mask_len,
            kind: EntryKind::Network,
        }
    }

    pub fn with_hostname(hostname: impl Into<String>) -> Self {
        Self::new(hostname, 0, 0)
    }

    /// An application entry. `spec` is an image name (`firefox.exe`) or a full
    /// path, already validated by [`crate::apps::normalize_spec`].
    pub fn app(spec: impl Into<String>) -> Self {
        BlockEntry {
            hostname: spec.into(),
            port: 0,
            mask_len: 0,
            kind: EntryKind::App,
        }
    }

    /// True when this entry blocks an application rather than a network target.
    pub fn is_app(&self) -> bool {
        self.kind == EntryKind::App
    }

    /// True if the hostname is a valid IP address (v4 or v6).
    pub fn is_ip(&self) -> bool {
        self.hostname.parse::<IpAddr>().is_ok()
    }

    /// True if the hostname is a valid IPv4 address (the only kind we block by IP
    /// in `pf`-style rules, other than explicit IPv6 CIDRs).
    pub fn is_ipv4(&self) -> bool {
        self.hostname.parse::<Ipv4Addr>().is_ok()
    }

    /// Port of `+[SCBlockEntry entryFromString:]`, extended to recognize IPv6
    /// literals and to reject entries that would produce invalid rules.
    ///
    /// Returns `None` when the string carries nothing useful (or something unsafe)
    /// to block.
    pub fn parse(input: &str) -> Option<BlockEntry> {
        let input = input.trim();
        if input.is_empty() {
            return None;
        }

        // Application entries are a Windows extension and use a completely
        // different syntax; keep them away from the hostname/IP parser.
        if let Some(spec) = apps::strip_prefix(input) {
            return apps::normalize_spec(spec).map(BlockEntry::app);
        }

        // A bare IP literal (IPv4 or IPv6) blocks that exact address; the original
        // would split `2001:db8::1` on ':' and keep only "2001".
        if let Ok(ip) = input.parse::<IpAddr>() {
            return Some(BlockEntry::with_hostname(ip.to_string()));
        }

        // A bracketed IPv6 literal with an optional port: `[2001:db8::1]:443`.
        if let Some((addr, port)) = parse_bracketed_ipv6(input) {
            return Some(BlockEntry::new(addr, clamp_port(port), 0));
        }

        let slash_parts: Vec<&str> = input.split('/').collect();
        let mut hostname = slash_parts[0].to_string();

        let mut mask_len: i64 = 0;
        let mut string_to_search_for_port = slash_parts[0].to_string();

        if slash_parts.len() >= 2 {
            mask_len = objc_int_value(slash_parts[1]);
            string_to_search_for_port = slash_parts[1].to_string();
        }

        let colon_parts: Vec<&str> = string_to_search_for_port.split(':').collect();

        // Only re-derive the hostname from the port string when the mask split
        // didn't already separate it off.
        if string_to_search_for_port == hostname {
            hostname = colon_parts[0].to_string();
        }

        let mut port: i64 = 0;
        if colon_parts.len() >= 2 {
            port = objc_int_value(colon_parts[1]);
        }

        if hostname.is_empty() {
            hostname = "*".to_string();
        }

        // We refuse to block everything (`*`) without a port — too easy to do by mistake.
        // Use an allowlist if that is the intent.
        if hostname == "*" && port == 0 {
            return None;
        }

        // Reject hostnames carrying characters that would corrupt the hosts file or
        // the firewall command line. IPs were already normalized above, but a dotted
        // quad with a mask reaches here too.
        let is_ip = hostname.parse::<IpAddr>().is_ok();
        if !is_ip && hostname != "*" && !hostname_is_valid(&hostname) {
            return None;
        }

        Some(BlockEntry {
            hostname,
            port: clamp_port(port),
            mask_len: validate_mask(&slash_parts, mask_len),
            kind: EntryKind::Network,
        })
    }
}

impl std::fmt::Display for BlockEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[Entry: kind = {:?}, hostname = {}, port = {}, maskLen = {}]",
            self.kind, self.hostname, self.port, self.mask_len
        )
    }
}

fn clamp_port(port: i64) -> u16 {
    port.clamp(0, u16::MAX as i64) as u16
}

/// Hostnames may only contain characters that are legal in a DNS name; anything
/// else (newlines, spaces, `;`, quotes) could inject extra hosts-file lines or
/// break the firewall command line.
fn hostname_is_valid(hostname: &str) -> bool {
    !hostname.is_empty()
        && hostname.len() <= 253
        && hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
}

/// A CIDR mask must fit the address family: `/32` is the maximum for IPv4 and
/// `/128` for IPv6. An out-of-range mask makes `netsh` reject the rule, which would
/// otherwise roll back the entire block.
fn validate_mask(slash_parts: &[&str], mask_len: i64) -> u8 {
    if mask_len <= 0 {
        return 0;
    }
    let max = match slash_parts[0].parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => 32,
        Ok(IpAddr::V6(_)) => 128,
        Err(_) => 128,
    };
    if mask_len <= max {
        mask_len as u8
    } else {
        0
    }
}

/// Parse `[ipv6]` or `[ipv6]:port`.
fn parse_bracketed_ipv6(input: &str) -> Option<(String, i64)> {
    let rest = input.strip_prefix('[')?;
    let close = rest.find(']')?;
    let addr = &rest[..close];
    let ip: IpAddr = addr.parse().ok()?;
    if !ip.is_ipv6() {
        return None;
    }
    let after = &rest[close + 1..];
    let port = if after.is_empty() {
        0
    } else {
        let digits = after.strip_prefix(':')?;
        if digits.is_empty() {
            return None;
        }
        objc_int_value(digits)
    };
    Some((ip.to_string(), port))
}

/// Mimics Foundation's `-[NSString intValue]`: parse a leading integer, returning 0
/// when there is no leading numeric prefix.
pub(crate) fn objc_int_value(s: &str) -> i64 {
    let t = s.trim_start();
    let mut chars = t.chars().peekable();
    let mut sign = 1i64;
    if let Some(&c) = chars.peek() {
        if c == '-' {
            sign = -1;
            chars.next();
        } else if c == '+' {
            chars.next();
        }
    }
    let mut val: i64 = 0;
    let mut any = false;
    for c in chars {
        if let Some(d) = c.to_digit(10) {
            any = true;
            val = val.saturating_mul(10).saturating_add(d as i64);
        } else {
            break;
        }
    }
    if any {
        sign * val
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_hostname() {
        assert_eq!(
            BlockEntry::parse("example.com"),
            Some(BlockEntry::new("example.com", 0, 0))
        );
    }

    #[test]
    fn parses_hostname_with_port() {
        assert_eq!(
            BlockEntry::parse("example.com:8080"),
            Some(BlockEntry::new("example.com", 8080, 0))
        );
    }

    #[test]
    fn parses_cidr() {
        assert_eq!(
            BlockEntry::parse("83.0.1.2/24"),
            Some(BlockEntry::new("83.0.1.2", 0, 24))
        );
    }

    #[test]
    fn parses_cidr_with_port() {
        assert_eq!(
            BlockEntry::parse("83.0.1.2/24:443"),
            Some(BlockEntry::new("83.0.1.2", 443, 24))
        );
    }

    #[test]
    fn empty_hostname_becomes_star() {
        // ":80" -> hostname "*", port 80
        assert_eq!(BlockEntry::parse(":80"), Some(BlockEntry::new("*", 80, 0)));
    }

    #[test]
    fn star_without_port_is_rejected() {
        assert_eq!(BlockEntry::parse("*"), None);
        assert_eq!(BlockEntry::parse(""), None);
    }

    #[test]
    fn whitespace_only_is_rejected() {
        assert_eq!(BlockEntry::parse("   \n\t "), None);
    }

    #[test]
    fn parses_ipv6_literal() {
        assert_eq!(
            BlockEntry::parse("2001:db8::1"),
            Some(BlockEntry::new("2001:db8::1", 0, 0))
        );
        assert_eq!(
            BlockEntry::parse("fe80::1"),
            Some(BlockEntry::new("fe80::1", 0, 0))
        );
    }

    #[test]
    fn parses_bracketed_ipv6_with_port() {
        assert_eq!(
            BlockEntry::parse("[2001:db8::1]:443"),
            Some(BlockEntry::new("2001:db8::1", 443, 0))
        );
        assert_eq!(
            BlockEntry::parse("[::1]"),
            Some(BlockEntry::new("::1", 0, 0))
        );
    }

    #[test]
    fn parses_ipv6_cidr() {
        assert_eq!(
            BlockEntry::parse("2001:db8::/32"),
            Some(BlockEntry::new("2001:db8::", 0, 32))
        );
    }

    #[test]
    fn rejects_invalid_hostname_characters() {
        assert_eq!(BlockEntry::parse("evil.test\tbank.example"), None);
        assert_eq!(BlockEntry::parse("bad host.example"), None);
        assert_eq!(BlockEntry::parse("a;b.example"), None);
    }

    #[test]
    fn drops_out_of_range_masks() {
        // /99 is invalid for IPv4 and must not produce a rule that breaks the block.
        assert_eq!(
            BlockEntry::parse("1.2.3.4/99"),
            Some(BlockEntry::new("1.2.3.4", 0, 0))
        );
        // /40 is valid for IPv6.
        assert_eq!(
            BlockEntry::parse("2001:db8::/40"),
            Some(BlockEntry::new("2001:db8::", 0, 40))
        );
    }

    #[test]
    fn parses_application_entries() {
        assert_eq!(
            BlockEntry::parse("app:firefox.exe"),
            Some(BlockEntry::app("firefox.exe"))
        );
        assert_eq!(
            BlockEntry::parse("app:C:\\Program Files\\Mozilla Firefox\\firefox.exe"),
            Some(BlockEntry::app(
                "C:\\Program Files\\Mozilla Firefox\\firefox.exe"
            ))
        );
        assert_eq!(BlockEntry::parse("app:firefox"), None);
        assert_eq!(BlockEntry::parse("app:"), None);
    }

    #[test]
    fn app_entries_are_not_network_entries() {
        let e = BlockEntry::app("firefox.exe");
        assert!(e.is_app());
        assert!(!e.is_ip());
        assert!(!e.is_ipv4());
        assert!(!BlockEntry::with_hostname("example.com").is_app());
    }

    #[test]
    fn ip_classification() {
        assert!(BlockEntry::with_hostname("127.0.0.1").is_ipv4());
        assert!(BlockEntry::with_hostname("::1").is_ip());
        assert!(!BlockEntry::with_hostname("::1").is_ipv4());
        assert!(!BlockEntry::with_hostname("example.com").is_ip());
    }
}
