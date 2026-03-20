//! SOCKS5 DNS Handler
//!
//! Tunnels DNS queries through upstream SOCKS5 proxy for maximum privacy.
//! This completely prevents DNS leaks by routing all DNS traffic through the proxy.

use super::{DnsError, DnsProtocolHandler, DnsResult};
use async_trait::async_trait;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
    serialize::binary::{BinDecodable, BinEncodable},
};
use log::{debug, warn};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::transparent::connect_tcp_with_mark;

/// SOCKS5 proxy authentication
#[derive(Debug, Clone)]
pub struct Socks5Auth {
    pub username: String,
    pub password: String,
}

/// SOCKS5 DNS handler configuration
#[derive(Debug, Clone)]
pub struct Socks5DnsConfig {
    /// SOCKS5 proxy address
    pub proxy_addr: SocketAddr,
    /// Optional authentication
    pub auth: Option<Socks5Auth>,
    /// DNS server to connect to through proxy
    pub upstream_dns: SocketAddr,
    /// Connection timeout
    pub timeout: Duration,
    /// Maximum retries
    pub max_retries: usize,
}

impl Default for Socks5DnsConfig {
    fn default() -> Self {
        Self {
            proxy_addr: "127.0.0.1:1080".parse().unwrap(),
            auth: None,
            upstream_dns: "8.8.8.8:53".parse().unwrap(),
            timeout: Duration::from_secs(10),
            max_retries: 2,
        }
    }
}

/// SOCKS5 DNS handler
pub struct Socks5DnsHandler {
    config: Socks5DnsConfig,
}

impl Socks5DnsHandler {
    /// Create a new SOCKS5 DNS handler
    pub fn new(config: Socks5DnsConfig) -> Self {
        Self { config }
    }
    
    /// Establish SOCKS5 connection to DNS server
    /// Wraps the entire handshake in a 30-second timeout to prevent blocking
    /// indefinitely if the SOCKS5 proxy hangs during negotiation.
    async fn connect_through_proxy(&self) -> DnsResult<tokio::net::TcpStream> {
        tokio::time::timeout(
            Duration::from_secs(30),
            self.connect_through_proxy_inner()
        )
        .await
        .map_err(|_| DnsError::Timeout)?
    }

    /// Inner SOCKS5 handshake implementation without the overall timeout wrapper.
    async fn connect_through_proxy_inner(&self) -> DnsResult<tokio::net::TcpStream> {
        // Connect to SOCKS5 proxy
        let mut stream = tokio::time::timeout(
            self.config.timeout,
            connect_tcp_with_mark(&self.config.proxy_addr)
        )
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(|e| DnsError::ConnectionError(format!("Failed to connect to SOCKS5 proxy: {}", e)))?;
        
        // SOCKS5 greeting — when credentials are configured offer ONLY
        // USERNAME_PASSWORD (0x02) so a MITM server cannot downgrade to
        // NO_AUTH (0x00) and bypass authentication entirely.
        let auth_methods = if self.config.auth.is_some() {
            vec![2] // USERNAME_PASSWORD only (prevents downgrade attack)
        } else {
            vec![0] // NO_AUTH only
        };
        
        let mut greeting = vec![5, auth_methods.len() as u8];
        greeting.extend(auth_methods);
        
        stream.write_all(&greeting).await
            .map_err(|e| DnsError::Socks5Error(format!("Failed to send SOCKS5 greeting: {}", e)))?;
        
        let mut method_resp = [0u8; 2];
        stream.read_exact(&mut method_resp).await
            .map_err(|e| DnsError::Socks5Error(format!("Failed to read SOCKS5 method response: {}", e)))?;
        
        if method_resp[0] != 5 {
            return Err(DnsError::Socks5Error(
                format!("Invalid SOCKS5 version in method response: {}", method_resp[0])
            ));
        }
        
        let selected_method = method_resp[1];
        
        // Authenticate if needed
        if selected_method == 2 {
            if let Some(auth) = &self.config.auth {
                let username = auth.username.as_bytes();
                let password = auth.password.as_bytes();
                
                let mut auth_msg = vec![1, username.len() as u8];
                auth_msg.extend(username);
                auth_msg.push(password.len() as u8);
                auth_msg.extend(password);
                
                stream.write_all(&auth_msg).await
                    .map_err(|e| DnsError::Socks5Error(format!("Failed to send auth: {}", e)))?;
                
                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await
                    .map_err(|e| DnsError::Socks5Error(format!("Failed to read auth response: {}", e)))?;
                
                if auth_resp[0] != 1 || auth_resp[1] != 0 {
                    return Err(DnsError::Socks5Error("Authentication failed".to_string()));
                }
            } else {
                return Err(DnsError::Socks5Error(
                    "Server requires authentication but no credentials provided".to_string()
                ));
            }
        } else if selected_method != 0 {
            return Err(DnsError::Socks5Error(
                format!("Unsupported authentication method: {}", selected_method)
            ));
        }
        
        // SOCKS5 CONNECT request
        let mut connect_req = vec![5, 1, 0]; // VER, CMD=CONNECT, RSV
        
        match self.config.upstream_dns.ip() {
            IpAddr::V4(addr) => {
                connect_req.push(1); // ATYP=IPv4
                connect_req.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                connect_req.push(4); // ATYP=IPv6
                connect_req.extend_from_slice(&addr.octets());
            }
        }
        
        connect_req.extend_from_slice(&self.config.upstream_dns.port().to_be_bytes());
        
        stream.write_all(&connect_req).await
            .map_err(|e| DnsError::Socks5Error(format!("Failed to send CONNECT request: {}", e)))?;
        
        // Read CONNECT response
        let mut connect_resp = [0u8; 10];
        stream.read_exact(&mut connect_resp[..4]).await
            .map_err(|e| DnsError::Socks5Error(format!("Failed to read CONNECT response: {}", e)))?;
        
        if connect_resp[0] != 5 {
            return Err(DnsError::Socks5Error(
                format!("Invalid SOCKS5 version in CONNECT response: {}", connect_resp[0])
            ));
        }
        
        if connect_resp[1] != 0 {
            return Err(DnsError::Socks5Error(
                format!("SOCKS5 CONNECT failed with code: {}", connect_resp[1])
            ));
        }
        
        // Read remaining response based on ATYP
        let atyp = connect_resp[3];
        match atyp {
            1 => {
                stream.read_exact(&mut connect_resp[4..10]).await
                    .map_err(|e| DnsError::Socks5Error(format!("Failed to read IPv4 address: {}", e)))?;
            }
            4 => {
                let mut ipv6_buf = [0u8; 18];
                stream.read_exact(&mut ipv6_buf).await
                    .map_err(|e| DnsError::Socks5Error(format!("Failed to read IPv6 address: {}", e)))?;
            }
            3 => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await
                    .map_err(|e| DnsError::Socks5Error(format!("Failed to read domain length: {}", e)))?;
                let mut domain_buf = vec![0u8; len_buf[0] as usize + 2];
                stream.read_exact(&mut domain_buf).await
                    .map_err(|e| DnsError::Socks5Error(format!("Failed to read domain: {}", e)))?;
            }
            _ => return Err(DnsError::Socks5Error(format!("Unsupported ATYP: {}", atyp))),
        }
        
        debug!("SOCKS5 DNS: Successfully connected to {} through proxy {}", 
            self.config.upstream_dns, self.config.proxy_addr);
        
        Ok(stream)
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
    
    /// Send a DNS query over a TCP stream and read the response
    async fn send_query_and_read(
        stream: &mut tokio::net::TcpStream,
        query: &[u8],
        timeout_duration: Duration,
    ) -> DnsResult<Vec<u8>> {
        // DNS over TCP uses 2-byte length prefix
        let len_prefix = (query.len() as u16).to_be_bytes();
        let mut tcp_query = Vec::with_capacity(2 + query.len());
        tcp_query.extend_from_slice(&len_prefix);
        tcp_query.extend_from_slice(query);
        
        stream.write_all(&tcp_query).await
            .map_err(|e| DnsError::Io(e))?;
        
        // Read response length
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(timeout_duration, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Io(e))?;
        
        let response_len = u16::from_be_bytes(len_buf) as usize;
        
        // Read response
        let mut response_buf = vec![0u8; response_len];
        tokio::time::timeout(timeout_duration, stream.read_exact(&mut response_buf))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Io(e))?;
        
        Ok(response_buf)
    }
    
    /// Forward raw DNS query bytes through SOCKS5 proxy
    async fn query_raw_internal(&self, query_data: &[u8]) -> DnsResult<Vec<u8>> {
        let mut stream = self.connect_through_proxy().await?;
        Self::send_query_and_read(&mut stream, query_data, self.config.timeout).await
    }
    
    /// Query DNS through SOCKS5 proxy with both A and AAAA queries
    async fn query_internal(&self, domain: &str) -> DnsResult<Vec<IpAddr>> {
        let mut stream = self.connect_through_proxy().await?;
        
        // Build both queries
        let query_a = Self::build_query(domain, RecordType::A)?;
        let query_aaaa = Self::build_query(domain, RecordType::AAAA)?;
        
        let mut ips = Vec::new();
        
        // Query A record
        match Self::send_query_and_read(&mut stream, &query_a, self.config.timeout).await {
            Ok(response_bytes) => {
                match Self::parse_response(&response_bytes) {
                    Ok(a_ips) if !a_ips.is_empty() => {
                        debug!("SOCKS5 DNS: found {} A record(s) for {}", a_ips.len(), domain);
                        ips.extend(a_ips);
                    }
                    Ok(_) => {
                        debug!("SOCKS5 DNS: no A records for {}", domain);
                    }
                    Err(e) => {
                        debug!("SOCKS5 DNS: failed to parse A response: {}", e);
                    }
                }
            }
            Err(e) => {
                debug!("SOCKS5 DNS: A query failed for {}: {}", domain, e);
            }
        }
        
        // Query AAAA record (sequential on same TCP connection)
        match Self::send_query_and_read(&mut stream, &query_aaaa, self.config.timeout).await {
            Ok(response_bytes) => {
                match Self::parse_response(&response_bytes) {
                    Ok(aaaa_ips) if !aaaa_ips.is_empty() => {
                        debug!("SOCKS5 DNS: found {} AAAA record(s) for {}", aaaa_ips.len(), domain);
                        ips.extend(aaaa_ips);
                    }
                    Ok(_) => {
                        debug!("SOCKS5 DNS: no AAAA records for {}", domain);
                    }
                    Err(e) => {
                        debug!("SOCKS5 DNS: failed to parse AAAA response: {}", e);
                    }
                }
            }
            Err(e) => {
                debug!("SOCKS5 DNS: AAAA query failed for {}: {}", domain, e);
            }
        }
        
        if ips.is_empty() {
            Err(DnsError::NoIpFound)
        } else {
            debug!("SOCKS5 DNS: resolved {} to {:?}", domain, ips);
            Ok(ips)
        }
    }
}

#[async_trait]
impl DnsProtocolHandler for Socks5DnsHandler {
    async fn query(&self, domain: &str) -> DnsResult<Vec<IpAddr>> {
        let mut last_error = None;
        
        for attempt in 0..self.config.max_retries {
            match self.query_internal(domain).await {
                Ok(ips) => {
                    debug!("SOCKS5 DNS: successfully resolved {} (attempt {})", domain, attempt + 1);
                    return Ok(ips);
                }
                Err(e) => {
                    warn!("SOCKS5 DNS: attempt {} failed for {}: {}", attempt + 1, domain, e);
                    last_error = Some(e);
                }
            }
        }
        
        Err(last_error.unwrap_or_else(||
            DnsError::QueryFailed("All retry attempts failed".to_string())
        ))
    }
    
    async fn query_raw(&self, query_data: &[u8]) -> DnsResult<Vec<u8>> {
        let mut last_error = None;
        
        for attempt in 0..self.config.max_retries {
            match self.query_raw_internal(query_data).await {
                Ok(response) => {
                    debug!("SOCKS5 DNS raw: received {} bytes (attempt {})", response.len(), attempt + 1);
                    return Ok(response);
                }
                Err(e) => {
                    warn!("SOCKS5 DNS raw: attempt {} failed: {}", attempt + 1, e);
                    last_error = Some(e);
                }
            }
        }
        
        Err(last_error.unwrap_or_else(||
            DnsError::QueryFailed("All retry attempts failed for raw query".to_string())
        ))
    }
    
    fn protocol_name(&self) -> &'static str {
        "socks5"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Note: These tests require a running SOCKS5 proxy
    // Skip them in CI or configure test proxy address
    
    #[tokio::test]
    #[ignore] // Remove this to test with real proxy
    async fn test_socks5_dns_query() {
        let config = Socks5DnsConfig {
            proxy_addr: "127.0.0.1:1080".parse().unwrap(),
            auth: None,
            upstream_dns: "8.8.8.8:53".parse().unwrap(),
            timeout: Duration::from_secs(10),
            max_retries: 2,
        };
        let handler = Socks5DnsHandler::new(config);
        
        let ips = handler.query("google.com").await.unwrap();
        assert!(!ips.is_empty());
        println!("Resolved google.com through SOCKS5: {:?}", ips);
    }
    
    #[tokio::test]
    #[ignore]
    async fn test_socks5_dns_with_auth() {
        let config = Socks5DnsConfig {
            proxy_addr: "127.0.0.1:1080".parse().unwrap(),
            auth: Some(Socks5Auth {
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
            upstream_dns: "8.8.8.8:53".parse().unwrap(),
            timeout: Duration::from_secs(10),
            max_retries: 2,
        };
        let handler = Socks5DnsHandler::new(config);
        
        let ips = handler.query("example.com").await.unwrap();
        assert!(!ips.is_empty());
    }
}
