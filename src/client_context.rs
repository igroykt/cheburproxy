use dashmap::DashMap;
use lazy_static::lazy_static;
use std::sync::Arc;
use std::time::{Duration, Instant};
use log::debug;
use std::collections::HashSet;

lazy_static! {
    pub static ref CONTEXT_CACHE: Arc<DashMap<String, (String, Instant)>> = Arc::new(DashMap::new());
    /// Small heuristic set for common multi-part public suffixes.
    /// This is NOT a full PSL replacement, but avoids the worst routing/cache poisoning
    /// for popular zones like *.co.uk / *.com.au etc.
    static ref MULTIPART_PUBLIC_SUFFIXES: HashSet<&'static str> = {
        let mut s = HashSet::new();
        // NZ
        s.insert("co.nz");
        // UK
        s.insert("co.uk"); s.insert("org.uk"); s.insert("ac.uk"); s.insert("gov.uk"); s.insert("net.uk"); s.insert("sch.uk");
        // AU
        s.insert("com.au"); s.insert("net.au"); s.insert("org.au"); s.insert("edu.au"); s.insert("gov.au"); s.insert("id.au");
        // JP
        s.insert("co.jp"); s.insert("ne.jp"); s.insert("or.jp"); s.insert("ac.jp"); s.insert("go.jp");
        // KR
        s.insert("co.kr"); s.insert("ne.kr"); s.insert("or.kr"); s.insert("ac.kr"); s.insert("go.kr");
        // IN
        s.insert("co.in"); s.insert("net.in"); s.insert("org.in"); s.insert("ac.in"); s.insert("gov.in");
        // BR
        s.insert("com.br"); s.insert("net.br"); s.insert("org.br"); s.insert("gov.br");
        // CN / HK / TW / SG / MY (common)
        s.insert("com.cn"); s.insert("net.cn"); s.insert("org.cn"); s.insert("gov.cn");
        s.insert("com.hk"); s.insert("net.hk"); s.insert("org.hk");
        s.insert("com.tw"); s.insert("net.tw"); s.insert("org.tw");
        s.insert("com.sg"); s.insert("net.sg"); s.insert("org.sg");
        s.insert("com.my"); s.insert("net.my"); s.insert("org.my");
        s
    };
}

/// Get the top-level domain from a domain string
/// e.g., "api.example.com" -> "example.com"
pub fn get_top_level_domain(domain: &str) -> String {
    // Trim whitespace and trailing dot (FQDN form "example.com.")
    let d = domain.trim().trim_end_matches('.');
    if d.is_empty() {
        return String::new();
    }

    // If it's an IPv4/IPv6 literal (rare here), keep as-is.
    // This avoids turning "1.2.3.4" into "3.4".
    if d.parse::<std::net::IpAddr>().is_ok() {
        return d.to_string();
    }

    let parts: Vec<&str> = d.split('.').filter(|p| !p.is_empty()).collect();
    let len = parts.len();
    if len < 2 {
        return d.to_string();
    }

    // Check common multi-part public suffixes (e.g. co.uk / com.au).
    let last2 = format!("{}.{}", parts[len - 2], parts[len - 1]).to_ascii_lowercase();
    if MULTIPART_PUBLIC_SUFFIXES.contains(last2.as_str()) {
        if len >= 3 {
            return format!("{}.{}", parts[len - 3], last2);
        }
        // edge case: "co.uk" alone (invalid host) -> return as-is
        return last2;
    }

    // Default: eTLD+1 heuristic for normal TLDs like .com/.kz/etc.
    format!("{}.{}", parts[len - 2], parts[len - 1])
}

/// Get cached proxy tag for a client IP and domain
/// P2-8 FIX: Use get() (read lock) instead of get_mut() (write lock) for cache hits.
/// Previously, every cache hit took a write lock to update the timestamp, causing
/// DashMap shard contention under high concurrency for the same client IP + TLD.
/// Now we accept slightly stale timestamps (entries may live up to TTL + cleanup_interval
/// instead of TTL from last access), which is acceptable for proxy routing cache.
pub fn get_cached_proxy_tag(client_ip: &str, domain: &str, ttl: Duration) -> Option<String> {
    let now = Instant::now();
    let tld = get_top_level_domain(domain);
    let key = format!("{}|{}", client_ip, tld);

    if let Some(entry) = CONTEXT_CACHE.get(&key) {
        if now.duration_since(entry.1) < ttl {
            debug!("Context cache hit for client IP '{}' and TLD '{}': proxy '{}'", client_ip, tld, entry.0);
            return Some(entry.0.clone());
        } else {
            // Expired — drop read-ref then remove atomically (avoids TOCTOU M22)
            drop(entry);
            CONTEXT_CACHE.remove_if(&key, |_k, v| now.duration_since(v.1) >= ttl);
        }
    }

    debug!("Context cache miss for client IP '{}' and TLD '{}'", client_ip, tld);
    None
}

/// Cache a proxy tag for a client IP and domain
pub fn set_cached_proxy_tag(client_ip: &str, domain: &str, proxy_tag: &str) {
    let tld = get_top_level_domain(domain);
    let key = format!("{}|{}", client_ip, tld);
    CONTEXT_CACHE.insert(key.clone(), (proxy_tag.to_string(), Instant::now()));
    debug!("Cached proxy tag '{}' for client IP '{}' and TLD '{}'", proxy_tag, client_ip, tld);
}

/// Cleanup expired entries from the context cache
pub fn cleanup_expired_contexts(ttl: Duration) {
    let now = Instant::now();
    // retain() checks and removes in a single pass, eliminating the TOCTOU M23
    // race that existed when keys were collected first and removed in a second loop.
    CONTEXT_CACHE.retain(|key, value| {
        if now.duration_since(value.1) >= ttl {
            debug!("Cleaned up expired context for '{}'", key);
            false
        } else {
            true
        }
    });
}

/// Get context cache statistics
pub fn get_context_stats() -> std::collections::HashMap<String, usize> {
    let mut stats = std::collections::HashMap::new();
    stats.insert("context_cache_size".to_string(), CONTEXT_CACHE.len());
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_context_cache() {
        // Clear cache
        CONTEXT_CACHE.clear();

        let ttl = Duration::from_secs(1);

        // Set context for client IP and domain
        set_cached_proxy_tag("192.168.1.1", "api.example.com", "proxy1");

        // Get for same client IP and TLD
        assert_eq!(get_cached_proxy_tag("192.168.1.1", "api.example.com", ttl), Some("proxy1".to_string()));

        // Get for same client IP but different TLD should miss
        assert_eq!(get_cached_proxy_tag("192.168.1.1", "kaspi.kz", ttl), None);

        // Get for different client IP should miss
        assert_eq!(get_cached_proxy_tag("192.168.1.2", "api.example.com", ttl), None);

        // Wait for expiry
        thread::sleep(Duration::from_secs(2));

        // Should be expired
        assert_eq!(get_cached_proxy_tag("192.168.1.1", "api.example.com", ttl), None);
    }

    #[test]
    fn test_get_top_level_domain_basic() {
        assert_eq!(get_top_level_domain("api.example.com"), "example.com");
        assert_eq!(get_top_level_domain("example.com"), "example.com");
        assert_eq!(get_top_level_domain("kaspi.kz"), "kaspi.kz");
        assert_eq!(get_top_level_domain("example.com."), "example.com");
    }

    #[test]
    fn test_get_top_level_domain_multipart_suffixes() {
        assert_eq!(get_top_level_domain("a.b.example.co.uk"), "example.co.uk");
        assert_eq!(get_top_level_domain("example.co.uk"), "example.co.uk");
        assert_eq!(get_top_level_domain("a.b.c.com.au"), "c.com.au");
        assert_eq!(get_top_level_domain("x.y.z.co.jp"), "z.co.jp");
    }

    #[test]
    fn test_get_top_level_domain_ip_literals() {
        assert_eq!(get_top_level_domain("1.2.3.4"), "1.2.3.4");
        assert_eq!(get_top_level_domain("::1"), "::1");
    }
}