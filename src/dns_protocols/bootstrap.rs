//! Bootstrap DNS Resolver
//!
//! Provides hardcoded IP addresses for popular DoT/DoH DNS servers to avoid initial
//! DNS resolution loops. Only used to resolve DNS server domain names, not general queries.

use super::{DnsError, DnsProtocolHandler, DnsResult};
use async_trait::async_trait;
use log::{debug, warn};
use std::collections::HashMap;
use std::net::IpAddr;

/// Bootstrap resolver with hardcoded IPs and optional fallback
pub struct BootstrapResolver {
    /// Hardcoded domain-to-IP mappings for popular DNS servers
    hardcoded_mappings: HashMap<String, Vec<IpAddr>>,
    /// Optional fallback to plain DNS for unknown domains
    fallback_handler: Option<Box<dyn DnsProtocolHandler>>,
}

impl BootstrapResolver {
    /// Create a new bootstrap resolver with hardcoded mappings
    pub fn new() -> Self {
        let mut mappings = HashMap::new();
        
        // Google Public DNS
        mappings.insert("dns.google".to_string(), vec![
            "8.8.8.8".parse().unwrap(),
            "8.8.4.4".parse().unwrap(),
        ]);
        mappings.insert("dns.google.com".to_string(), vec![
            "8.8.8.8".parse().unwrap(),
            "8.8.4.4".parse().unwrap(),
        ]);
        
        // Cloudflare DNS
        mappings.insert("cloudflare-dns.com".to_string(), vec![
            "1.1.1.1".parse().unwrap(),
            "1.0.0.1".parse().unwrap(),
        ]);
        mappings.insert("one.one.one.one".to_string(), vec![
            "1.1.1.1".parse().unwrap(),
            "1.0.0.1".parse().unwrap(),
        ]);
        mappings.insert("1dot1dot1dot1.cloudflare-dns.com".to_string(), vec![
            "1.1.1.1".parse().unwrap(),
            "1.0.0.1".parse().unwrap(),
        ]);
        
        // Quad9 DNS
        mappings.insert("dns.quad9.net".to_string(), vec![
            "9.9.9.9".parse().unwrap(),
            "149.112.112.112".parse().unwrap(),
        ]);
        mappings.insert("dns9.quad9.net".to_string(), vec![
            "9.9.9.9".parse().unwrap(),
        ]);
        mappings.insert("dns10.quad9.net".to_string(), vec![
            "149.112.112.112".parse().unwrap(),
        ]);
        
        Self {
            hardcoded_mappings: mappings,
            fallback_handler: None,
        }
    }
    
    /// Create bootstrap resolver with a fallback handler for unknown domains
    pub fn with_fallback(fallback: Box<dyn DnsProtocolHandler>) -> Self {
        let mut resolver = Self::new();
        resolver.fallback_handler = Some(fallback);
        resolver
    }
    
    /// Resolve a domain using hardcoded mappings
    /// Returns the first IP address if found
    pub async fn resolve_first(&self, domain: &str) -> DnsResult<IpAddr> {
        let ips = self.query(domain).await?;
        ips.into_iter().next()
            .ok_or_else(|| DnsError::NoIpFound)
    }
    
    /// Check if a domain has a hardcoded mapping
    pub fn has_mapping(&self, domain: &str) -> bool {
        self.hardcoded_mappings.contains_key(domain)
    }
    
    /// Get all hardcoded domains
    pub fn hardcoded_domains(&self) -> Vec<String> {
        self.hardcoded_mappings.keys().cloned().collect()
    }
}

impl Default for BootstrapResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DnsProtocolHandler for BootstrapResolver {
    async fn query(&self, domain: &str) -> DnsResult<Vec<IpAddr>> {
        // Check hardcoded mappings first
        if let Some(ips) = self.hardcoded_mappings.get(domain) {
            debug!("Bootstrap: resolved {} to {:?} (hardcoded)", domain, ips);
            return Ok(ips.clone());
        }
        
        // Try fallback handler if available
        if let Some(fallback) = &self.fallback_handler {
            warn!("Bootstrap: domain {} not in hardcoded list, using fallback handler", domain);
            return fallback.query(domain).await;
        }
        
        // No mapping and no fallback
        Err(DnsError::QueryFailed(
            format!("Domain {} not in bootstrap mappings and no fallback handler configured", domain)
        ))
    }
    
    fn protocol_name(&self) -> &'static str {
        "bootstrap"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_hardcoded_google_dns() {
        let resolver = BootstrapResolver::new();
        let ips = resolver.query("dns.google").await.unwrap();
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"8.8.8.8".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"8.8.4.4".parse::<IpAddr>().unwrap()));
    }
    
    #[tokio::test]
    async fn test_hardcoded_cloudflare_dns() {
        let resolver = BootstrapResolver::new();
        let ips = resolver.query("cloudflare-dns.com").await.unwrap();
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"1.1.1.1".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"1.0.0.1".parse::<IpAddr>().unwrap()));
    }
    
    #[tokio::test]
    async fn test_resolve_first() {
        let resolver = BootstrapResolver::new();
        let ip = resolver.resolve_first("dns.google").await.unwrap();
        assert!(ip == "8.8.8.8".parse::<IpAddr>().unwrap() || ip == "8.8.4.4".parse::<IpAddr>().unwrap());
    }
    
    #[tokio::test]
    async fn test_unknown_domain_without_fallback() {
        let resolver = BootstrapResolver::new();
        let result = resolver.query("unknown.domain.com").await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_has_mapping() {
        let resolver = BootstrapResolver::new();
        assert!(resolver.has_mapping("dns.google"));
        assert!(resolver.has_mapping("cloudflare-dns.com"));
        assert!(!resolver.has_mapping("unknown.com"));
    }
    
    #[tokio::test]
    async fn test_hardcoded_domains() {
        let resolver = BootstrapResolver::new();
        let domains = resolver.hardcoded_domains();
        assert!(domains.contains(&"dns.google".to_string()));
        assert!(domains.contains(&"cloudflare-dns.com".to_string()));
        assert!(domains.contains(&"dns.quad9.net".to_string()));
    }
}
