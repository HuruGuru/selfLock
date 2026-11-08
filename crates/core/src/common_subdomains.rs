//! Port of `-[BlockManager commonSubdomainsForHostName:]`.
//!
//! Returns commonly-missed sibling hosts for a handful of services plus the
//! `www.`/bare-domain counterpart.

/// Facebook IP ranges (pulled from Facebook's published AS routes), used because
/// Facebook's subdomains resolve to many different IPs.
const FACEBOOK_IPS: &[&str] = &[
    "31.13.24.0/21",
    "31.13.64.0/18",
    "45.64.40.0/22",
    "66.220.144.0/20",
    "69.63.176.0/20",
    "69.171.224.0/19",
    "74.119.76.0/22",
    "102.132.96.0/20",
    "103.4.96.0/22",
    "129.134.0.0/16",
    "147.75.208.0/20",
    "157.240.0.0/16",
    "173.252.64.0/18",
    "179.60.192.0/22",
    "185.60.216.0/22",
    "185.89.216.0/22",
    "199.201.64.0/22",
    "204.15.20.0/22",
];

/// True when `host` is `base` itself or a real subdomain of it.
///
/// A plain `ends_with` would treat `notfacebook.com` as a Facebook domain and add
/// Facebook's IP ranges — blocking an entire unrelated network by accident.
fn is_or_subdomain(host: &str, base: &str) -> bool {
    host == base || host.ends_with(&format!(".{base}"))
}

/// Compute the extra hostnames to block for `hostname`, preserving insertion order
/// while avoiding duplicates.
pub fn common_subdomains_for_hostname(hostname: &str) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    let mut push = |h: &str| {
        if !hosts.iter().any(|x| x == h) {
            hosts.push(h.to_string());
        }
    };

    // Only real hostnames get a `www.` counterpart; an IP or CIDR range must not.
    let is_address =
        hostname == "*" || hostname.contains('/') || hostname.parse::<std::net::IpAddr>().is_ok();
    if is_address {
        return hosts;
    }

    if is_or_subdomain(hostname, "facebook.com") {
        for ip in FACEBOOK_IPS {
            push(ip);
        }
    }
    if is_or_subdomain(hostname, "twitter.com") {
        push("api.twitter.com");
    }
    if is_or_subdomain(hostname, "netflix.com") {
        push("assets.nflxext.com");
        push("codex.nflxext.com");
        push("nflxext.com");
    }

    // Block the bare domain when `www.` is given, and vice versa.
    if let Some(stripped) = hostname.strip_prefix("www.") {
        push(stripped);
    } else {
        push(&format!("www.{hostname}"));
    }

    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_www_counterpart() {
        let out = common_subdomains_for_hostname("example.com");
        assert!(out.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn strips_www_when_present() {
        let out = common_subdomains_for_hostname("www.example.com");
        assert!(out.contains(&"example.com".to_string()));
    }

    #[test]
    fn facebook_adds_ip_ranges() {
        let out = common_subdomains_for_hostname("facebook.com");
        assert!(out.contains(&"31.13.24.0/21".to_string()));
        assert!(out.contains(&"www.facebook.com".to_string()));
    }

    #[test]
    fn twitter_adds_api() {
        let out = common_subdomains_for_hostname("twitter.com");
        assert!(out.contains(&"api.twitter.com".to_string()));
    }

    #[test]
    fn netflix_adds_cdn() {
        let out = common_subdomains_for_hostname("netflix.com");
        assert!(out.contains(&"nflxext.com".to_string()));
    }

    #[test]
    fn does_not_match_lookalike_domains() {
        let out = common_subdomains_for_hostname("notfacebook.com");
        assert!(
            !out.iter().any(|h| h.starts_with("31.13.")),
            "facebook ranges leaked: {out:?}"
        );
        assert_eq!(out, vec!["www.notfacebook.com".to_string()]);

        let out = common_subdomains_for_hostname("my-twitter.com");
        assert!(
            !out.contains(&"api.twitter.com".to_string()),
            "twitter leak: {out:?}"
        );
    }

    #[test]
    fn subdomain_still_matches() {
        let out = common_subdomains_for_hostname("m.facebook.com");
        assert!(out.contains(&"31.13.24.0/21".to_string()));
    }

    #[test]
    fn addresses_get_no_www_counterpart() {
        assert!(common_subdomains_for_hostname("31.13.24.0/21").is_empty());
        assert!(common_subdomains_for_hostname("1.2.3.4").is_empty());
        assert!(common_subdomains_for_hostname("*").is_empty());
    }
}
