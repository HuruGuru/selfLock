//! Port of `AllowlistScraper` — for allowlist blocks, fetch a page and add every
//! external domain it links to, so that linked resources stay reachable.
//!
//! Hardened relative to the original: the fetch uses HTTPS (never plain HTTP, so a
//! MITM cannot inject allowlist entries), refuses to connect to private /
//! loopback / link-local addresses (SSRF guard), caps the number of domains added,
//! and caps the response size.

use crate::entry::BlockEntry;
use regex::Regex;
use std::collections::HashSet;
use std::io::Read;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

/// Sites that are frequently linked but are themselves distracting; never add them.
pub const NEVER_ADD_SITES: &[&str] = &[
    "instagram.com",
    "www.instagram.com",
    "twitter.com",
    "www.twitter.com",
    "facebook.com",
    "www.facebook.com",
    "reddit.com",
    "www.reddit.com",
    "youtube.com",
    "www.youtube.com",
    "pinterest.com",
    "plus.google.com",
    "www.pinterest.com",
    "linkedin.com",
    "www.linkedin.com",
    "tumblr.com",
    "www.tumblr.com",
];

/// Never add more than this many linked domains for a single entry.
const MAX_LINKED_DOMAINS: usize = 500;
/// Never read more than this many bytes of a page.
const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;

fn link_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)href\s*=\s*["']([^"'\s>]+)["']"#).expect("valid href regex")
    })
}

/// Extract the host from an absolute or protocol-relative URL.
fn host_from_url(url: &str) -> Option<(String, String)> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("//") {
        ("http".to_string(), rest.to_string())
    } else if let Some(idx) = url.find("://") {
        (url[..idx].to_lowercase(), url[idx + 3..].to_string())
    } else {
        return None; // relative link, same host
    };
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority: &str = rest.split(['/', '?', '#']).next().unwrap_or("");
    // strip userinfo
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    // strip port
    let host = authority
        .split(':')
        .next()
        .unwrap_or(authority)
        .to_lowercase();
    if host.is_empty() {
        None
    } else {
        Some((scheme, host))
    }
}

/// True for addresses we must never fetch from (fail-closed SSRF guard).
fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                // 100.64.0.0/10 carrier-grade NAT
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40)
            // 169.254.0.0/16 link-local (covered by is_link_local)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // unique local fc00::/7
                || (v6.octets()[0] & 0xfe) == 0xfc
                // link-local fe80::/10
                || (v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xc0) == 0x80)
        }
    }
}

/// Resolve `host` and make sure every address is a public one.
fn host_is_public(host: &str) -> bool {
    // An IP literal is checked directly (lookup_host would return it verbatim).
    if let Ok(ip) = host.parse::<IpAddr>() {
        return !is_blocked_ip(&ip);
    }
    match dns_lookup::lookup_host(host) {
        Ok(addrs) if !addrs.is_empty() => addrs.iter().all(|a| !is_blocked_ip(a)),
        _ => false,
    }
}

/// Fetch a page over HTTPS and return its body, or `None` on any failure.
fn https_get(host: &str) -> Option<String> {
    if host.is_empty() || !host_is_public(host) {
        log::warn!("scraper: refusing to fetch {host} (empty or non-public address)");
        return None;
    }
    let url = format!("https://{host}/");
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(5))
        .timeout_write(Duration::from_secs(5))
        .redirects(3)
        .user_agent("SelfLock/1.0")
        .build();
    let response = match agent.get(&url).call() {
        Ok(r) => r,
        Err(e) => {
            log::debug!("scraper: GET {url} failed: {e}");
            return None;
        }
    };
    let mut buf = Vec::new();
    let mut reader = response.into_reader().take(MAX_BODY_BYTES);
    if reader.read_to_end(&mut buf).is_err() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).to_string())
}

/// Port of `+[AllowlistScraper relatedBlockEntries:]`.
pub fn related_block_entries(domain: &str) -> HashSet<BlockEntry> {
    let root_host = domain
        .rsplit('@')
        .next()
        .unwrap_or(domain)
        .split(':')
        .next()
        .unwrap_or(domain)
        .to_lowercase();

    let mut entries = HashSet::new();
    let Some(html) = https_get(&root_host) else {
        return entries;
    };

    for cap in link_regex().captures_iter(&html) {
        if entries.len() >= MAX_LINKED_DOMAINS {
            log::warn!("scraper: reached the {MAX_LINKED_DOMAINS}-domain limit for {root_host}");
            break;
        }
        if let Some((_scheme, host)) = host_from_url(&cap[1]) {
            if host.is_empty() || host == root_host || NEVER_ADD_SITES.contains(&host.as_str()) {
                continue;
            }
            entries.insert(BlockEntry::with_hostname(host));
        }
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_from_absolute_url() {
        assert_eq!(
            host_from_url("http://Example.com/path"),
            Some(("http".into(), "example.com".into()))
        );
        assert_eq!(
            host_from_url("https://sub.example.com:8443/x"),
            Some(("https".into(), "sub.example.com".into()))
        );
    }

    #[test]
    fn host_from_protocol_relative() {
        assert_eq!(
            host_from_url("//cdn.example.com/lib.js"),
            Some(("http".into(), "cdn.example.com".into()))
        );
    }

    #[test]
    fn relative_links_have_no_host() {
        assert_eq!(host_from_url("/about"), None);
        assert_eq!(host_from_url("page.html"), None);
        assert_eq!(host_from_url("mailto:a@b.com"), None);
    }

    #[test]
    fn ssrf_guard_blocks_internal_addresses() {
        assert!(is_blocked_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip(&"10.0.0.5".parse().unwrap()));
        assert!(is_blocked_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_blocked_ip(&"169.254.1.1".parse().unwrap()));
        assert!(is_blocked_ip(&"::1".parse().unwrap()));
        assert!(is_blocked_ip(&"fc00::1".parse().unwrap()));
        assert!(is_blocked_ip(&"fe80::1".parse().unwrap()));
        assert!(!is_blocked_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_blocked_ip(&"2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn ip_literal_is_not_public_when_internal() {
        assert!(!host_is_public("127.0.0.1"));
        assert!(!host_is_public("192.168.0.1"));
        assert!(host_is_public("8.8.8.8"));
    }
}
