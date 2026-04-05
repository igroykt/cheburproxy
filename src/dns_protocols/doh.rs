//! DNS over HTTPS (DoH) Handler
//!
//! RFC 8484 - DNS Queries over HTTPS
//! Supports both direct HTTPS connections and routing through SOCKS5 proxy

use super::{DnsError, DnsProtocolHandler, DnsResult};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
    serialize::binary::{BinDecodable, BinEncodable},
};
use log::{debug, warn};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// DoH server configuration
#[derive(Debug, Clone)]
pub struct DohServer {
    /// DoH URL (e.g., "https://dns.google/dns-query")
    pub url: String,
}

/// DoH handler configuration
#[derive(Debug, Clone)]
pub struct DohConfig {
    /// List of DoH servers
    pub servers: Vec<DohServer>,
    /// Request timeout
    pub timeout: Duration,
    /// Maximum retries per server
    pub max_retries: usize,
    /// Route through SOCKS5 proxy
    pub use_socks5: bool,
    /// SOCKS5 proxy address (if use_socks5 = true)
    pub socks5_proxy: Option<String>,
    /// Pre-resolved hostname -> address mappings fed to the HTTP client so it
    /// never calls the OS resolver for DoH server hostnames.  This prevents
    /// the DNS-resolution loop that occurs in transparent-proxy deployments.
    pub resolve_overrides: Vec<(String, SocketAddr)>,
}

impl Default for DohConfig {
    fn default() -> Self {
        Self {
            servers: vec![
                DohServer {
                    url: "https://dns.google/dns-query".to_string(),
                },
                DohServer {
                    url: "https://cloudflare-dns.com/dns-query".to_string(),
                },
            ],
            timeout: Duration::from_secs(10),
            max_retries: 2,
            use_socks5: false,
            socks5_proxy: None,
            resolve_overrides: vec![],
        }
    }
}

/// DNS over HTTPS handler
pub struct DohHandler {
    config: DohConfig,
    client: reqwest::Client,
}

/// Normalize a SOCKS5 proxy URL for use with DoH:
///
/// 1. Forces `socks5://` → `socks5h://` so that DNS resolution of the DoH
///    server hostname is performed by the SOCKS5 proxy, not locally.
///    Using `socks5://` causes reqwest to call `getaddrinfo()` locally before
///    tunnelling; if the system DNS points back at cheburproxy this creates an
///    infinite DNS resolution loop and every query times out.
///
/// 2. Encloses bare (unbracketed) IPv6 addresses in square brackets per
///    RFC 3986, so the URL can be parsed correctly by reqwest / the `url` crate.
///
/// Examples:
///   "socks5://20d:9cf7:cd19:5a82:af8b:f1be:f538:3d59:1080"
///     -> "socks5h://[20d:9cf7:cd19:5a82:af8b:f1be:f538:3d59]:1080"
///   "socks5://127.0.0.1:1080"  ->  "socks5h://127.0.0.1:1080"
///   "socks5://[::1]:1080"      ->  "socks5h://[::1]:1080"
///   "socks5h://[::1]:1080"     ->  unchanged
fn normalize_proxy_url(url: &str) -> String {
    // Find scheme end (e.g., "socks5://")
    let scheme_end = match url.find("://") {
        Some(pos) => pos + 3,
        None => return url.to_string(),
    };
    let scheme_str = &url[..scheme_end - 3]; // e.g. "socks5" or "socks5h"
    let rest = &url[scheme_end..];

    // Step 1: normalize scheme — always use socks5h:// so the SOCKS5 proxy
    // handles DNS resolution of the DoH server hostname, avoiding DNS loops.
    let target_scheme = match scheme_str {
        "socks5" => {
            warn!(
                "DoH: converting socks5:// to socks5h:// so the proxy resolves DoH server \
                 hostnames — this prevents a DNS resolution loop when the system resolver \
                 points back at cheburproxy"
            );
            "socks5h"
        }
        other => other,
    };

    // Separate optional "user:pass@" auth prefix from host:port
    let (auth_prefix, host_port) = match rest.rfind('@') {
        Some(at) => (&rest[..=at], &rest[at + 1..]),
        None => ("", rest),
    };

    // Step 2: normalize IPv6 brackets.
    // If the host is already bracketed, just rebuild with the correct scheme.
    if host_port.starts_with('[') {
        if target_scheme == scheme_str {
            return url.to_string();
        }
        return format!("{}://{}{}", target_scheme, auth_prefix, host_port);
    }

    // Count colons in host_port; more than one means it's likely a bare IPv6.
    let colon_count = host_port.chars().filter(|&c| c == ':').count();
    if colon_count <= 1 {
        // IPv4 or hostname — only scheme normalisation needed.
        if target_scheme == scheme_str {
            return url.to_string();
        }
        return format!("{}://{}{}", target_scheme, auth_prefix, host_port);
    }

    // Try to split off the last segment as a port number.
    if let Some(last_colon) = host_port.rfind(':') {
        let candidate_addr = &host_port[..last_colon];
        let candidate_port = &host_port[last_colon + 1..];

        // Validate: candidate_port must be a u16, candidate_addr must be IPv6.
        if candidate_port.parse::<u16>().is_ok()
            && candidate_addr.parse::<Ipv6Addr>().is_ok()
        {
            let normalized = format!(
                "{}://{}[{}]:{}",
                target_scheme, auth_prefix, candidate_addr, candidate_port
            );
            debug!("DoH: normalized proxy URL: '{}' -> '{}'", url, normalized);
            return normalized;
        }
    }

    // Could not normalize IPv6 — apply scheme fix only and let reqwest report
    // any remaining parse error.
    if target_scheme == scheme_str {
        url.to_string()
    } else {
        format!("{}://{}{}", target_scheme, auth_prefix, host_port)
    }
}

impl DohHandler {
    /// Create a new DoH handler
    pub fn new(config: DohConfig) -> DnsResult<Self> {
        let mut client_builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent("cheburproxy-doh/1.0");
        
        // Wire in pre-resolved addresses so the HTTP client never calls the OS
        // resolver for DoH server hostnames.  This prevents the DNS resolution
        // loop that occurs in transparent-proxy deployments where all DNS
        // queries are intercepted by this proxy itself.
        for (hostname, addr) in &config.resolve_overrides {
            client_builder = client_builder.resolve(hostname, *addr);
        }
        
        // Configure SOCKS5 proxy if needed
        if config.use_socks5 {
            if let Some(proxy_url) = &config.socks5_proxy {
                let normalized_url = normalize_proxy_url(proxy_url);
                let proxy = reqwest::Proxy::all(normalized_url.as_str())
                    .map_err(|e| DnsError::Socks5Error(format!("Invalid SOCKS5 proxy URL: {}", e)))?;
                client_builder = client_builder.proxy(proxy);
                debug!("DoH: configured to use SOCKS5 proxy at {}", normalized_url);
            } else {
                return Err(DnsError::Socks5Error(
                    "use_socks5 enabled but no socks5_proxy configured".to_string()
                ));
            }
        }
        
        let client = client_builder.build()
            .map_err(|e| DnsError::ConnectionError(format!("Failed to build HTTP client: {}", e)))?;
        
        Ok(Self { config, client })
    }
    
    /// Build DNS query message
    fn build_query(domain: &str, record_type: RecordType) -> DnsResult<Vec<u8>> {
        let normalized = crate::dns_protocols::normalize_domain_to_fqdn(domain);
        let name = Name::from_utf8(&normalized)
            .map_err(|e| DnsError::InvalidResponse(format!("Invalid domain name: {}", e)))?;
        
        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);
        
        let query = Query::query(name, record_type);
        message.add_query(query);
        
        let buffer = message.to_bytes()
            .map_err(|e| DnsError::InvalidResponse(format!("Failed to encode DNS query: {}", e)))?
            .to_vec();
        
        Ok(buffer)
    }
    
    /// Parse DNS response
    fn parse_response(response: &[u8]) -> DnsResult<Vec<IpAddr>> {
        let message = Message::from_bytes(response)
            .map_err(|e| DnsError::InvalidResponse(format!("Failed to parse DNS response: {}", e)))?;
        
        use hickory_proto::op::ResponseCode;
        if message.response_code() != ResponseCode::NoError {
            return Err(DnsError::QueryFailed(
                format!("DNS query failed with response code: {:?}", message.response_code())
            ));
        }
        
        let mut ips = Vec::new();
        
        for answer in message.answers() {
            match answer.data() {
                Some(hickory_proto::rr::RData::A(addr)) => {
                    ips.push(IpAddr::V4(addr.0));
                }
                Some(hickory_proto::rr::RData::AAAA(addr)) => {
                    ips.push(IpAddr::V6(addr.0));
                }
                _ => {}
            }
        }
        
        if ips.is_empty() {
            return Err(DnsError::NoIpFound);
        }
        
        Ok(ips)
    }
    
    /// Query a single DoH server using GET method with concurrent A+AAAA queries
    async fn query_server(&self, server: &DohServer, domain: &str) -> DnsResult<Vec<IpAddr>> {
        // Build both queries
        let query_a = Self::build_query(domain, RecordType::A)?;
        let query_aaaa = Self::build_query(domain, RecordType::AAAA)?;
        
        let dns_param_a = general_purpose::URL_SAFE_NO_PAD.encode(&query_a);
        let dns_param_aaaa = general_purpose::URL_SAFE_NO_PAD.encode(&query_aaaa);
        
        let url_a = format!("{}?dns={}", server.url, dns_param_a);
        let url_aaaa = format!("{}?dns={}", server.url, dns_param_aaaa);
        
        debug!("DoH: querying {} for {} (A + AAAA)", server.url, domain);
        
        // Launch both HTTP requests concurrently
        let a_future = self.client
            .get(&url_a)
            .header("Accept", "application/dns-message")
            .send();
        
        let aaaa_future = self.client
            .get(&url_aaaa)
            .header("Accept", "application/dns-message")
            .send();
        
        let (a_response, aaaa_response) = tokio::join!(a_future, aaaa_future);
        
        // Collect all successful IPs
        let mut ips = Vec::new();
        
        // Process A response
        if let Ok(response) = a_response {
            if response.status().is_success() {
                if let Ok(response_bytes) = response.bytes().await {
                    match Self::parse_response(&response_bytes) {
                        Ok(a_ips) if !a_ips.is_empty() => {
                            debug!("DoH: found {} A record(s) for {} via {}", a_ips.len(), domain, server.url);
                            ips.extend(a_ips);
                        }
                        Ok(_) => {
                            debug!("DoH: no A records for {} via {}", domain, server.url);
                        }
                        Err(e) => {
                            debug!("DoH: failed to parse A response from {}: {}", server.url, e);
                        }
                    }
                }
            } else {
                debug!("DoH: A query to {} returned status {}", server.url, response.status());
            }
        } else {
            debug!("DoH: A query HTTP request failed for {} via {}", domain, server.url);
        }
        
        // Process AAAA response
        if let Ok(response) = aaaa_response {
            if response.status().is_success() {
                if let Ok(response_bytes) = response.bytes().await {
                    match Self::parse_response(&response_bytes) {
                        Ok(aaaa_ips) if !aaaa_ips.is_empty() => {
                            debug!("DoH: found {} AAAA record(s) for {} via {}", aaaa_ips.len(), domain, server.url);
                            ips.extend(aaaa_ips);
                        }
                        Ok(_) => {
                            debug!("DoH: no AAAA records for {} via {}", domain, server.url);
                        }
                        Err(e) => {
                            debug!("DoH: failed to parse AAAA response from {}: {}", server.url, e);
                        }
                    }
                }
            } else {
                debug!("DoH: AAAA query to {} returned status {}", server.url, response.status());
            }
        } else {
            debug!("DoH: AAAA query HTTP request failed for {} via {}", domain, server.url);
        }
        
        if ips.is_empty() {
            Err(DnsError::NoIpFound)
        } else {
            debug!("DoH: resolved {} to {:?} via {}", domain, ips, server.url);
            Ok(ips)
        }
    }
}

#[async_trait]
impl DnsProtocolHandler for DohHandler {
    async fn query(&self, domain: &str) -> DnsResult<Vec<IpAddr>> {
        // Try each server until one succeeds
        let mut last_error = None;
        
        for server in &self.config.servers {
            for attempt in 0..self.config.max_retries {
                match self.query_server(server, domain).await {
                    Ok(ips) => {
                        debug!("DoH: successfully resolved {} via {} (attempt {})",
                            domain, server.url, attempt + 1);
                        return Ok(ips);
                    }
                    Err(e) => {
                        warn!("DoH: attempt {} failed for {} via {}: {}",
                            attempt + 1, domain, server.url, e);
                        last_error = Some(e);
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(||
            DnsError::QueryFailed("All DoH servers failed".to_string())
        ))
    }
    
    async fn query_raw(&self, query_data: &[u8]) -> DnsResult<Vec<u8>> {
        let mut last_error = None;
        
        for server in &self.config.servers {
            for attempt in 0..self.config.max_retries {
                // DoH POST with application/dns-message content type (RFC 8484 §4.1)
                match self.client
                    .post(&server.url)
                    .header("Content-Type", "application/dns-message")
                    .header("Accept", "application/dns-message")
                    .body(query_data.to_vec())
                    .send()
                    .await
                {
                    Ok(response) => {
                        if response.status().is_success() {
                            match response.bytes().await {
                                Ok(bytes) => {
                                    debug!("DoH raw: received {} bytes from {} (attempt {})",
                                        bytes.len(), server.url, attempt + 1);
                                    return Ok(bytes.to_vec());
                                }
                                Err(e) => {
                                    warn!("DoH raw: failed to read response body from {}: {}", server.url, e);
                                    last_error = Some(DnsError::QueryFailed(format!("Failed to read response: {}", e)));
                                }
                            }
                        } else {
                            warn!("DoH raw: server {} returned status {} (attempt {})",
                                server.url, response.status(), attempt + 1);
                            last_error = Some(DnsError::QueryFailed(
                                format!("DoH server returned status {}", response.status())
                            ));
                        }
                    }
                    Err(e) => {
                        warn!("DoH raw: request to {} failed (attempt {}): {}",
                            server.url, attempt + 1, e);
                        last_error = Some(DnsError::QueryFailed(format!("HTTP request failed: {}", e)));
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(||
            DnsError::QueryFailed("All DoH servers failed for raw query".to_string())
        ))
    }
    
    fn protocol_name(&self) -> &'static str {
        "doh"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_doh_query() {
        let config = DohConfig::default();
        let handler = DohHandler::new(config).unwrap();
        
        let ips = handler.query("google.com").await.unwrap();
        assert!(!ips.is_empty());
        println!("Resolved google.com via DoH: {:?}", ips);
    }
    
    #[tokio::test]
    async fn test_doh_cloudflare() {
        let config = DohConfig {
            servers: vec![DohServer {
                url: "https://cloudflare-dns.com/dns-query".to_string(),
            }],
            timeout: Duration::from_secs(10),
            max_retries: 2,
            use_socks5: false,
            socks5_proxy: None,
            resolve_overrides: vec![],
        };
        let handler = DohHandler::new(config).unwrap();
        
        let ips = handler.query("example.com").await.unwrap();
        assert!(!ips.is_empty());
    }
    
    #[tokio::test]
    #[ignore] // Requires SOCKS5 proxy
    async fn test_doh_via_socks5() {
        let config = DohConfig {
            servers: vec![DohServer {
                url: "https://dns.google/dns-query".to_string(),
            }],
            timeout: Duration::from_secs(10),
            max_retries: 2,
            use_socks5: true,
            socks5_proxy: Some("socks5://127.0.0.1:1080".to_string()),
            resolve_overrides: vec![],
        };
        let handler = DohHandler::new(config).unwrap();
        
        let ips = handler.query("google.com").await.unwrap();
        assert!(!ips.is_empty());
    }
}
