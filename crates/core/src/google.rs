//! Port of `-[BlockManager domainIsGoogle:]`.
//!
//! Google needs special handling because blocking it by IP would take down far more
//! than the user intends (Search, Mail, ...), so on allowlist blocks we whitelist the
//! whole Google range and on blocklist blocks we skip IP-level blocking entirely.

use regex::Regex;
use std::sync::OnceLock;

/// The Google IP ranges copied from the original `addGoogleIPsToPF`
/// (last updated 2021-09-23 from <https://www.gstatic.com/ipranges/goog.json>).
pub const GOOGLE_IPS: &[(&str, u8)] = &[
    ("8.8.4.0", 24),
    ("8.34.208.0", 20),
    ("8.35.192.0", 20),
    ("23.236.48.0", 20),
    ("23.251.128.0", 19),
    ("34.64.0.0", 10),
    ("34.128.0.0", 10),
    ("35.184.0.0", 13),
    ("35.192.0.0", 14),
    ("35.196.0.0", 15),
    ("35.198.0.0", 16),
    ("35.199.0.0", 17),
    ("35.199.128.0", 18),
    ("35.200.0.0", 13),
    ("35.208.0.0", 12),
    ("35.224.0.0", 12),
    ("35.240.0.0", 13),
    ("64.15.112.0", 20),
    ("64.233.160.0", 19),
    ("66.102.0.0", 20),
    ("66.249.64.0", 19),
    ("70.32.128.0", 19),
    ("72.14.192.0", 18),
    ("74.114.24.0", 21),
    ("74.125.0.0", 16),
    ("104.154.0.0", 16),
    ("104.196.0.0", 14),
    ("104.237.160.0", 19),
    ("107.167.160.0", 19),
    ("107.178.192.0", 18),
    ("108.59.80.0", 20),
    ("108.170.192.0", 18),
    ("108.177.0.0", 17),
    ("130.211.0.0", 16),
    ("136.112.0.0", 12),
    ("142.250.0.0", 15),
    ("146.148.0.0", 17),
    ("162.216.148.0", 22),
    ("162.222.176.0", 21),
    ("172.110.32.0", 21),
    ("172.217.0.0", 16),
    ("172.253.0.0", 16),
    ("173.194.0.0", 16),
    ("173.255.112.0", 20),
    ("192.158.28.0", 22),
    ("192.178.0.0", 15),
    ("193.186.4.0", 24),
    ("199.36.154.0", 23),
    ("199.36.156.0", 24),
    ("199.192.112.0", 22),
    ("199.223.232.0", 21),
    ("207.223.160.0", 20),
    ("208.65.152.0", 22),
    ("208.68.108.0", 22),
    ("208.81.188.0", 22),
    ("208.117.224.0", 19),
    ("209.85.128.0", 17),
    ("216.58.192.0", 19),
    ("216.73.80.0", 20),
    ("216.239.32.0", 19),
    ("2001:4860::", 32),
    ("2404:6800::", 32),
    ("2404:f340::", 32),
    ("2600:1900::", 28),
    ("2606:73c0::", 32),
    ("2607:f8b0::", 32),
    ("2620:11a:a000::", 40),
    ("2620:120:e000::", 40),
    ("2800:3f0::", 32),
    ("2a00:1450::", 32),
    ("2c0f:fb50::", 32),
];

fn google_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^([a-z0-9]+\.)*(google|youtube|picasa|sketchup|blogger|blogspot)\.([a-z]{1,3})(\.[a-z]{1,3})?$")
            .expect("valid google regex")
    })
}

/// Port of `-[BlockManager domainIsGoogle:]`.
pub fn domain_is_google(domain: &str) -> bool {
    google_regex().is_match(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_google_domains() {
        assert!(domain_is_google("google.com"));
        assert!(domain_is_google("www.google.com"));
        assert!(domain_is_google("mail.google.com"));
        assert!(domain_is_google("youtube.com"));
        assert!(domain_is_google("blogspot.co.uk"));
    }

    #[test]
    fn rejects_non_google() {
        assert!(!domain_is_google("example.com"));
        assert!(!domain_is_google("notgoogle.com"));
        assert!(!domain_is_google("google.com.evil.com"));
        assert!(!domain_is_google("google"));
    }
}
