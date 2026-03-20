//! Internal DNS Resolver
//!
//! Unified DNS resolver for cheburproxy that replaces hickory-resolver with
//! customizable protocol handlers to prevent DNS leaks.

use crate::dns_protocols::{
    bootstrap::BootstrapResolver,
    plain::{PlainDnsConfig, PlainDnsHandler},
    dot::{DotConfig, DotHandler},
    doh::{DohConfig, DohHandler},
    socks5_dns::{Socks5DnsConfig, Socks5DnsHandler},
    DnsError, DnsProtocolHandler, DnsResult,
};
use dashmap::DashMap;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// DNS protocol selection
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsProtocol {
    /// Plain DNS (UDP/TCP) - WARNING: DNS leak!
    Plain,
    /// DNS over TLS
    DoT,
    /// DNS over HTTPS
    DoH,
    /// DNS through SOCKS5 proxy (maximum privacy)
    Socks5,
}

impl Default for DnsProtocol {
    fn default() -> Self {
        Self::Socks5  // Default to most secure
    }
}

/// DNS resolver configuration
#[derive(Debug, Clone)]
pub struct DnsResolverConfig {
    /// Protocol to use
    pub protocol: DnsProtocol,
    
    /// Plain DNS configuration
    pub plain_servers: Vec<String>,
    
    /// DoT configuration
    pub dot_servers: Vec<(String, u16, String)>, // (address, port, tls_name)
    
    /// DoH configuration
    pub doh_urls: Vec<String>,
    pub doh_use_socks5: bool,
    pub doh_socks5_proxy: Option<String>,
    
    /// SOCKS5 DNS configuration
    pub socks5_proxy_addr: Option<String>,
    pub socks5_username: Option<String>,
    pub socks5_password: Option<String>,
    pub socks5_upstream_dns: String,
    
    /// Bootstrap for DoT/DoH (hardcoded IPs + fallback)
    pub bootstrap_enabled: bool,
    pub bootstrap_servers: Vec<String>,
    
    /// Timeouts and caching
    pub timeout: Duration,
    pub cache_ttl: u64,
    pub max_retries: usize,
}

impl Default for DnsResolverConfig {
    fn default() -> Self {
        Self {
            protocol: DnsProtocol::Socks5,
            
            plain_servers: vec![
                "8.8.8.8:53".to_string(),
                "1.1.1.1:53".to_string(),
            ],
            
            dot_servers: vec![
                ("8.8.8.8".to_string(), 853, "dns.google".to_string()),
                ("1.1.1.1".to_string(), 853, "cloudflare-dns.com".to_string()),
            ],
            
            doh_urls: vec![
                "https://dns.google/dns-query".to_string(),
                "https://cloudflare-dns.com/dns-query".to_string(),
            ],
            doh_use_socks5: false,
            doh_socks5_proxy: None,
            
            socks5_proxy_addr: Some("127.0.0.1:1080".to_string()),
            socks5_username: None,
            socks5_password: None,
            socks5_upstream_dns: "8.8.8.8:53".to_string(),
            
            bootstrap_enabled: true,
            bootstrap_servers: vec![
                "8.8.8.8:53".to_string(),
                "1.1.1.1:53".to_string(),
            ],
            
            timeout: Duration::from_secs(5),
            cache_ttl: 3600,
            max_retries: 2,
        }
    }
}

/// Extract the hostname from a DoH URL.
/// E.g. "https://dns.google/dns-query" → "dns.google"
///      "https://example.com:8443/path" → "example.com"
fn extract_doh_hostname(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    // Take everything up to the first '/' (path separator)
    let host_and_port = without_scheme.split('/').next()?;
    // Strip the port if present
    let hostname = host_and_port.split(':').next()?;
    if hostname.is_empty() {
        None
    } else {
        Some(hostname.to_string())
    }
}

/// Cached DNS entry
#[derive(Debug, Clone)]
struct CachedDnsEntry {
    ips: Vec<IpAddr>,
    timestamp: Instant,
    /// Per-entry cache TTL derived from the configured value (clamped to [60, 3600] s).
    /// Full per-record TTL extraction would require the protocol handler to return raw
    /// DNS response bytes; for now the configured cache_ttl is clamped at insert time.
    ttl: Duration,
}

impl CachedDnsEntry {
    fn is_expired(&self) -> bool {
        self.timestamp.elapsed() > self.ttl
    }
}

/// Internal DNS Resolver
pub struct InternalDnsResolver {
    config: Arc<DnsResolverConfig>,
    handler: Arc<dyn DnsProtocolHandler>,
    cache: DashMap<String, CachedDnsEntry>,
    bootstrap: Option<Arc<BootstrapResolver>>,
}

impl InternalDnsResolver {
    /// Create a new DNS resolver from configuration
    pub async fn from_config(config: DnsResolverConfig) -> DnsResult<Self> {
        info!("Initializing Internal DNS Resolver with protocol: {:?}", config.protocol);
        
        // Create bootstrap resolver if needed
        let bootstrap = if config.bootstrap_enabled && 
                          (config.protocol == DnsProtocol::DoT || config.protocol == DnsProtocol::DoH) {
            
            let plain_config = PlainDnsConfig {
                servers: config.bootstrap_servers.iter()
                    .filter_map(|s| s.parse().ok())
                    .collect(),
                timeout: config.timeout,
                max_retries: config.max_retries,
            };
            
            let fallback = Box::new(PlainDnsHandler::new(plain_config));
            Some(Arc::new(BootstrapResolver::with_fallback(fallback)))
        } else {
            None
        };
        
        // Create protocol handler
        let handler: Arc<dyn DnsProtocolHandler> = match config.protocol {
            DnsProtocol::Plain => {
                info!("Using Plain DNS - WARNING: DNS queries will be visible to ISP!");
                let plain_config = PlainDnsConfig {
                    servers: config.plain_servers.iter()
                        .filter_map(|s| s.parse().ok())
                        .collect(),
                    timeout: config.timeout,
                    max_retries: config.max_retries,
                };
                Arc::new(PlainDnsHandler::new(plain_config))
            }
            
            DnsProtocol::DoT => {
                info!("Using DNS over TLS (DoT)");
                
                let mut dot_servers = Vec::new();
                
                for (addr_str, port, tls_name) in &config.dot_servers {
                    // Try to parse as IP first
                    let address = if let Ok(ip) = addr_str.parse::<IpAddr>() {
                        ip
                    } else {
                        // It's a domain, need to resolve using bootstrap
                        if let Some(ref bootstrap_resolver) = bootstrap {
                            debug!("DoT: Resolving server domain {} using bootstrap", addr_str);
                            bootstrap_resolver.resolve_first(addr_str).await
                                .map_err(|e| DnsError::QueryFailed(
                                    format!("Failed to bootstrap resolve DoT server {}: {}", addr_str, e)
                                ))?
                        } else {
                            return Err(DnsError::QueryFailed(
                                format!("DoT server {} is a domain but bootstrap is disabled", addr_str)
                            ));
                        }
                    };
                    
                    dot_servers.push(crate::dns_protocols::dot::DotServer {
                        address,
                        port: *port,
                        tls_name: tls_name.clone(),
                    });
                }
                
                let dot_config = DotConfig {
                    servers: dot_servers,
                    timeout: config.timeout,
                    max_retries: config.max_retries,
                };
                
                Arc::new(DotHandler::new(dot_config)?)
            }
            
            DnsProtocol::DoH => {
                info!("Using DNS over HTTPS (DoH){}",
                    if config.doh_use_socks5 { " through SOCKS5 proxy" } else { "" });
                
                // Pre-resolve DoH server hostnames via the bootstrap resolver so the
                // reqwest HTTP client never calls the OS resolver.  This breaks the
                // DNS-resolution loop that occurs in transparent-proxy deployments
                // where all DNS traffic is intercepted by this proxy.
                // Not needed when SOCKS5 is in use because the proxy handles resolution.
                let mut resolve_overrides = Vec::new();
                if !config.doh_use_socks5 {
                    if let Some(ref bootstrap_resolver) = bootstrap {
                        for url in &config.doh_urls {
                            if let Some(hostname) = extract_doh_hostname(url) {
                                // Only override if it's actually a hostname, not an IP
                                if hostname.parse::<IpAddr>().is_err() {
                                    match bootstrap_resolver.resolve_first(&hostname).await {
                                        Ok(ip) => {
                                            debug!("DoH: bootstrap-resolved {} -> {} (prevents DNS loop)", hostname, ip);
                                            resolve_overrides.push((hostname, SocketAddr::new(ip, 443)));
                                        }
                                        Err(e) => {
                                            warn!("DoH: could not bootstrap-resolve {}: {}", hostname, e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                let doh_config = DohConfig {
                    servers: config.doh_urls.iter()
                        .map(|url| crate::dns_protocols::doh::DohServer {
                            url: url.clone(),
                        })
                        .collect(),
                    timeout: config.timeout,
                    max_retries: config.max_retries,
                    use_socks5: config.doh_use_socks5,
                    socks5_proxy: config.doh_socks5_proxy.clone(),
                    resolve_overrides,
                };
                
                Arc::new(DohHandler::new(doh_config)?)
            }
            
            DnsProtocol::Socks5 => {
                info!("Using DNS through SOCKS5 proxy (maximum privacy)");
                
                let proxy_addr = config.socks5_proxy_addr.as_ref()
                    .ok_or_else(|| DnsError::Socks5Error("socks5_proxy_addr not configured".to_string()))?
                    .parse()
                    .map_err(|_| DnsError::Socks5Error("Invalid socks5_proxy_addr".to_string()))?;
                
                let auth = if let (Some(username), Some(password)) = 
                    (&config.socks5_username, &config.socks5_password) {
                    Some(crate::dns_protocols::socks5_dns::Socks5Auth {
                        username: username.clone(),
                        password: password.clone(),
                    })
                } else {
                    None
                };
                
                let upstream_dns = config.socks5_upstream_dns.parse()
                    .map_err(|_| DnsError::Socks5Error("Invalid socks5_upstream_dns".to_string()))?;
                
                let socks5_config = Socks5DnsConfig {
                    proxy_addr,
                    auth,
                    upstream_dns,
                    timeout: config.timeout,
                    max_retries: config.max_retries,
                };
                
                Arc::new(Socks5DnsHandler::new(socks5_config))
            }
        };
        
        info!("Internal DNS Resolver initialized successfully with {} protocol", 
            handler.protocol_name());
        
        Ok(Self {
            config: Arc::new(config),
            handler,
            cache: DashMap::new(),
            bootstrap,
        })
    }
    
    /// Resolve a domain name to IP addresses
    pub async fn resolve(&self, domain: &str) -> DnsResult<Vec<IpAddr>> {
        // Check cache first
        if let Some(entry) = self.cache.get(domain) {
            if !entry.is_expired() {
                debug!("Internal DNS Resolver: cache hit for {}", domain);
                return Ok(entry.ips.clone());
            }
        }
        
        // Query using protocol handler
        debug!("Internal DNS Resolver: querying {} using {} protocol",
            domain, self.handler.protocol_name());
        
        let ips = self.handler.query(domain).await?;
        
        // Cache the result — clamp configured TTL to [60, 3600] seconds so we never
        // cache for less than a minute (excessive re-queries) or more than an hour.
        // Per-record TTL from the DNS wire response is not available here because
        // handler.query() only returns IP addresses; full TTL extraction would require
        // switching to handler.query_raw() with manual response parsing.
        let cache_duration = Duration::from_secs(
            self.config.cache_ttl.max(60).min(3600)
        );
        self.cache.insert(domain.to_string(), CachedDnsEntry {
            ips: ips.clone(),
            timestamp: Instant::now(),
            ttl: cache_duration,
        });
        
        debug!("Internal DNS Resolver: resolved {} to {:?}", domain, ips);
        
        Ok(ips)
    }
    
    /// Forward a raw DNS query through the configured protocol handler
    /// Returns the raw DNS response bytes from the upstream server
    pub async fn resolve_raw(&self, query_data: &[u8]) -> DnsResult<Vec<u8>> {
        self.handler.query_raw(query_data).await
    }
    
    /// Resolve and return the first IP address
    pub async fn resolve_first(&self, domain: &str) -> DnsResult<IpAddr> {
        let ips = self.resolve(domain).await?;
        ips.into_iter().next()
            .ok_or_else(|| DnsError::NoIpFound)
    }
    
    /// Clear the DNS cache
    pub fn clear_cache(&self) {
        let before = self.cache.len();
        self.cache.clear();
        debug!("Internal DNS Resolver: cleared cache ({} entries)", before);
    }
    
    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let total = self.cache.len();
        let expired = self.cache.iter()
            .filter(|entry| entry.is_expired())
            .count();
        (total, expired)
    }
    
    /// Get protocol name
    pub fn protocol_name(&self) -> &'static str {
        self.handler.protocol_name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_resolver_plain() {
        let config = DnsResolverConfig {
            protocol: DnsProtocol::Plain,
            ..Default::default()
        };
        
        let resolver = InternalDnsResolver::from_config(config).await.unwrap();
        let ips = resolver.resolve("google.com").await.unwrap();
        assert!(!ips.is_empty());
        println!("Resolved google.com: {:?}", ips);
    }
    
    #[tokio::test]
    async fn test_resolver_cache() {
        let config = DnsResolverConfig {
            protocol: DnsProtocol::Plain,
            cache_ttl: 60,
            ..Default::default()
        };
        
        let resolver = InternalDnsResolver::from_config(config).await.unwrap();
        
        // First query
        let ips1 = resolver.resolve("example.com").await.unwrap();
        
        // Second query (should be cached)
        let ips2 = resolver.resolve("example.com").await.unwrap();
        
        assert_eq!(ips1, ips2);
        
        let (total, expired) = resolver.cache_stats();
        assert_eq!(total, 1);
        assert_eq!(expired, 0);
    }
    
    #[tokio::test]
    #[ignore] // Requires DoT server
    async fn test_resolver_dot() {
        let config = DnsResolverConfig {
            protocol: DnsProtocol::DoT,
            bootstrap_enabled: true,
            ..Default::default()
        };
        
        let resolver = InternalDnsResolver::from_config(config).await.unwrap();
        let ips = resolver.resolve("google.com").await.unwrap();
        assert!(!ips.is_empty());
    }
    
    #[tokio::test]
    #[ignore] // Requires SOCKS5 proxy
    async fn test_resolver_socks5() {
        let config = DnsResolverConfig {
            protocol: DnsProtocol::Socks5,
            socks5_proxy_addr: Some("127.0.0.1:1080".to_string()),
            ..Default::default()
        };
        
        let resolver = InternalDnsResolver::from_config(config).await.unwrap();
        let ips = resolver.resolve("google.com").await.unwrap();
        assert!(!ips.is_empty());
    }
}
