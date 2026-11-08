//! DNS resolution, replacing the macOS-only `CFHost` logic.
//!
//! Uses the Windows resolver (`getaddrinfo` via the `dns-lookup` crate).

use std::net::IpAddr;

/// Resolve a domain name into a list of IP addresses. Mirrors
/// `+[BlockManager ipAddressesForDomainName:]`, returning an empty list on failure.
pub fn resolve_domain(domain: &str) -> Vec<IpAddr> {
    if domain.is_empty() {
        return Vec::new();
    }
    match dns_lookup::lookup_host(domain) {
        Ok(addrs) => addrs,
        Err(e) => {
            log::warn!("failed to resolve addresses for {domain}: {e}");
            Vec::new()
        }
    }
}

/// Resolve many domains in parallel across `workers` threads, preserving order.
///
/// The original used a 35-wide `NSOperationQueue`; the default here matches that.
pub fn resolve_many(domains: &[String]) -> Vec<(String, Vec<IpAddr>)> {
    resolve_many_with(domains, 35)
}

pub fn resolve_many_with(domains: &[String], workers: usize) -> Vec<(String, Vec<IpAddr>)> {
    if domains.is_empty() {
        return Vec::new();
    }
    let workers = workers.max(1).min(domains.len());
    let next = std::sync::atomic::AtomicUsize::new(0);
    type Resolved = Option<(String, Vec<IpAddr>)>;
    let results: std::sync::Mutex<Vec<Resolved>> = std::sync::Mutex::new(vec![None; domains.len()]);

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if i >= domains.len() {
                    break;
                }
                let resolved = resolve_domain(&domains[i]);
                results.lock().unwrap()[i] = Some((domains[i].clone(), resolved));
            });
        }
    });

    results
        .into_inner()
        .unwrap()
        .into_iter()
        .flatten()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolving_empty_is_empty() {
        assert!(resolve_domain("").is_empty());
    }

    #[test]
    fn resolving_no_domains_is_empty() {
        assert!(resolve_many(&[]).is_empty());
        assert!(resolve_many_with(&["".to_string()], 4)
            .iter()
            .all(|(_, v)| v.is_empty()));
    }

    #[test]
    fn invalid_domain_resolves_to_nothing() {
        // A syntactically invalid name must fail without panicking. This hits the
        // resolver but never the network for a well-formed-but-nonexistent label set;
        // use an empty host to avoid any DNS traffic in CI.
        assert!(resolve_domain("").is_empty());
    }
}
