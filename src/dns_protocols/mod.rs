//! DNS Protocol Handlers
//!
//! This module provides implementations of various DNS protocols for DNS leak prevention:
//! - Bootstrap: Hardcoded IPs for DoT/DoH servers to avoid initial DNS resolution loop
//! - Plain DNS: Traditional UDP/TCP DNS queries (for fallback)
//! - DNS over TLS (DoT): RFC 7858 - encrypted DNS over TLS
//! - DNS over HTTPS (DoH): RFC 8484 - encrypted DNS over HTTPS
//! - SOCKS5 DNS: DNS queries tunneled through upstream SOCKS5 proxy

pub mod bootstrap;
pub mod plain;
pub mod dot;
pub mod doh;
pub mod socks5_dns;

use async_trait::async_trait;
use std::net::IpAddr;
use thiserror::Error;

/// DNS protocol handler errors
#[derive(Debug, Error)]
pub enum DnsError {
    #[error("DNS query failed: {0}")]
    QueryFailed(String),
    
    #[error("DNS timeout")]
    Timeout,
    
    #[error("No IP addresses found in response")]
    NoIpFound,
    
    #[error("Invalid DNS response: {0}")]
    InvalidResponse(String),
    
    #[error("Connection error: {0}")]
    ConnectionError(String),
    
    #[error("TLS error: {0}")]
    TlsError(String),
    
    #[error("SOCKS5 error: {0}")]
    Socks5Error(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// DNS query result
pub type DnsResult<T> = Result<T, DnsError>;

/// Trait for DNS protocol handlers
#[async_trait]
pub trait DnsProtocolHandler: Send + Sync {
    /// Query a domain name and return resolved IP addresses
    async fn query(&self, domain: &str) -> DnsResult<Vec<IpAddr>>;
    
    /// Forward a raw DNS query and return the raw DNS response bytes.
    /// This enables transparent proxying of any record type (HTTPS/SVCB, MX, etc.)
    /// without needing to understand the record format.
    async fn query_raw(&self, _query_data: &[u8]) -> DnsResult<Vec<u8>> {
        Err(DnsError::QueryFailed("Raw query forwarding not supported by this handler".to_string()))
    }
    
    /// Get protocol name for logging/debugging
    fn protocol_name(&self) -> &'static str;
}

/// Normalize domain name to FQDN to prevent search domain appending
/// 
/// DNS resolvers (especially hickory/trust-dns with system config) will append
/// search domains from /etc/resolv.conf if a domain doesn't end with '.'.
/// This function ensures domains with dots are treated as absolute.
///
/// # Examples
/// ```
/// use cheburproxy::dns_protocols::normalize_domain_to_fqdn;
/// 
/// assert_eq!(normalize_domain_to_fqdn("example.com"), "example.com.");
/// assert_eq!(normalize_domain_to_fqdn("example.com."), "example.com.");
/// assert_eq!(normalize_domain_to_fqdn("localhost"), "localhost"); // single-label OK
/// ```
pub fn normalize_domain_to_fqdn(domain: &str) -> String {
    if domain.is_empty() {
        return domain.to_string();
    }
    
    // Already absolute (ends with .)
    if domain.ends_with('.') {
        return domain.to_string();
    }
    
    // Contains dots → likely FQDN, make absolute to prevent search domain
    if domain.contains('.') {
        return format!("{}.", domain);
    }
    
    // Single-label hostname → leave as-is (search domains may be intended)
    domain.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_domain_to_fqdn() {
        // Domains with dots should get trailing dot
        assert_eq!(normalize_domain_to_fqdn("example.com"), "example.com.");
        assert_eq!(normalize_domain_to_fqdn("sub.example.com"), "sub.example.com.");
        assert_eq!(normalize_domain_to_fqdn("basketgear.org"), "basketgear.org.");
        
        // Already absolute should stay unchanged
        assert_eq!(normalize_domain_to_fqdn("example.com."), "example.com.");
        
        // Single-label hostnames should NOT get trailing dot
        assert_eq!(normalize_domain_to_fqdn("localhost"), "localhost");
        assert_eq!(normalize_domain_to_fqdn("router"), "router");
        
        // Empty string
        assert_eq!(normalize_domain_to_fqdn(""), "");
    }
}
