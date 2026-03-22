//! Plain DNS Handler
//!
//! Traditional UDP DNS queries (RFC 1035). Can also use TCP for large responses.
//! WARNING: This exposes DNS queries to ISP. Use only for testing or as bootstrap fallback.

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
use tokio::net::UdpSocket;

/// Plain DNS handler configuration
#[derive(Debug, Clone)]
pub struct PlainDnsConfig {
    /// DNS servers to query
    pub servers: Vec<SocketAddr>,
    /// Query timeout
    pub timeout: Duration,
    /// Maximum retries per server
    pub max_retries: usize,
}

impl Default for PlainDnsConfig {
    fn default() -> Self {
        Self {
            servers: vec![
                "8.8.8.8:53".parse().unwrap(),
                "1.1.1.1:53".parse().unwrap(),
            ],
            timeout: Duration::from_secs(5),
            max_retries: 2,
        }
    }
}

/// Plain DNS handler using UDP
pub struct PlainDnsHandler {
    config: PlainDnsConfig,
}

impl PlainDnsHandler {
    /// Create a new plain DNS handler with the given configuration
    pub fn new(config: PlainDnsConfig) -> Self {
        Self { config }
    }
    
    /// Build a DNS query message for a domain
    fn build_query(domain: &str, record_type: RecordType) -> Result<Vec<u8>, DnsError> {
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
    
    /// Parse DNS response and extract IP addresses
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
    
    /// Parse DNS response and extract domain name for PTR record
    fn parse_reverse_response(response: &[u8]) -> DnsResult<String> {
        let message = Message::from_bytes(response)
            .map_err(|e| DnsError::InvalidResponse(format!("Failed to parse DNS response: {}", e)))?;
        
        use hickory_proto::op::ResponseCode;
        if message.response_code() != ResponseCode::NoError {
            return Err(DnsError::QueryFailed(
                format!("DNS query failed with response code: {:?}", message.response_code())
            ));
        }
        
        for answer in message.answers() {
            if let Some(hickory_proto::rr::RData::PTR(name)) = answer.data() {
                return Ok(name.to_utf8().trim_end_matches('.').to_string());
            }
        }
        
        Err(DnsError::QueryFailed("No PTR record found in response".to_string()))
    }
    
    /// Query a single DNS server via UDP with concurrent A+AAAA queries (Happy Eyeballs)
    async fn query_server(&self, server: &SocketAddr, domain: &str) -> DnsResult<Vec<IpAddr>> {
        // Build both A and AAAA queries
        let query_a = Self::build_query(domain, RecordType::A)?;
        let query_aaaa = Self::build_query(domain, RecordType::AAAA)?;
        
        // Create two separate sockets for concurrent queries
        let socket_a = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| DnsError::Io(e))?;
        let socket_aaaa = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| DnsError::Io(e))?;


        
        let server_clone = *server;
        let timeout = self.config.timeout;
        let max_retries = self.config.max_retries;
        
        // Helper function for sending query and receiving response with retries
        let send_and_receive_a = async {
            for attempt in 0..max_retries {
                if let Err(e) = socket_a.send_to(&query_a, &server_clone).await {
                    debug!("Plain DNS: send error to {} for A (attempt {}): {}", 
                        server_clone, attempt + 1, e);
                    continue;
                }
                
                let mut response_buf = vec![0u8; 4096];
                match tokio::time::timeout(timeout, socket_a.recv_from(&mut response_buf)).await {
                    Ok(Ok((size, src_addr))) => {
                        if src_addr != server_clone {
                            debug!("Plain DNS: A response from unexpected source {}, expected {}", src_addr, server_clone);
                            continue;
                        }
                        // Check TC (truncation) flag: bit 1 of byte 2 in the DNS header
                        if size >= 3 && response_buf[2] & 0x02 != 0 {
                            warn!("Plain DNS: A response from {} was truncated (TC flag set), response may be incomplete", server_clone);
                        }
                        return Ok(response_buf[..size].to_vec());
                    }
                    Ok(Err(e)) => {
                        debug!("Plain DNS: recv error from {} for A (attempt {}): {}",
                            server_clone, attempt + 1, e);
                        continue;
                    }
                    Err(_) => {
                        debug!("Plain DNS: timeout for A via {} (attempt {})",
                            server_clone, attempt + 1);
                        continue;
                    }
                }
            }
            Err(DnsError::Timeout)
        };
        
        let send_and_receive_aaaa = async {
            for attempt in 0..max_retries {
                if let Err(e) = socket_aaaa.send_to(&query_aaaa, &server_clone).await {
                    debug!("Plain DNS: send error to {} for AAAA (attempt {}): {}", 
                        server_clone, attempt + 1, e);
                    continue;
                }
                
                let mut response_buf = vec![0u8; 4096];
                match tokio::time::timeout(timeout, socket_aaaa.recv_from(&mut response_buf)).await {
                    Ok(Ok((size, src_addr))) => {
                        if src_addr != server_clone {
                            debug!("Plain DNS: AAAA response from unexpected source {}, expected {}", src_addr, server_clone);
                            continue;
                        }
                        // Check TC (truncation) flag: bit 1 of byte 2 in the DNS header
                        if size >= 3 && response_buf[2] & 0x02 != 0 {
                            warn!("Plain DNS: AAAA response from {} was truncated (TC flag set), response may be incomplete", server_clone);
                        }
                        return Ok(response_buf[..size].to_vec());
                    }
                    Ok(Err(e)) => {
                        debug!("Plain DNS: recv error from {} for AAAA (attempt {}): {}",
                            server_clone, attempt + 1, e);
                        continue;
                    }
                    Err(_) => {
                        debug!("Plain DNS: timeout for AAAA via {} (attempt {})",
                            server_clone, attempt + 1);
                        continue;
                    }
                }
            }
            Err(DnsError::Timeout)
        };
        
        // Launch both queries concurrently
        let (a_result, aaaa_result) = tokio::join!(
            send_and_receive_a,
            send_and_receive_aaaa
        );
        
        // Collect all successful IPs
        let mut ips = Vec::new();
        
        // Process A record response
        if let Ok(response_bytes) = a_result {
            match Self::parse_response(&response_bytes) {
                Ok(a_ips) if !a_ips.is_empty() => {
                    debug!("Plain DNS: found {} A record(s) for {} via {}", 
                        a_ips.len(), domain, server);
                    ips.extend(a_ips);
                }
                Ok(_) => {
                    debug!("Plain DNS: no A records for {} via {}", domain, server);
                }
                Err(e) => {
                    debug!("Plain DNS: failed to parse A response from {}: {}", server, e);
                }
            }
        }
        
        // Process AAAA record response
        if let Ok(response_bytes) = aaaa_result {
            match Self::parse_response(&response_bytes) {
                Ok(aaaa_ips) if !aaaa_ips.is_empty() => {
                    debug!("Plain DNS: found {} AAAA record(s) for {} via {}", 
                        aaaa_ips.len(), domain, server);
                    ips.extend(aaaa_ips);
                }
                Ok(_) => {
                    debug!("Plain DNS: no AAAA records for {} via {}", domain, server);
                }
                Err(e) => {
                    debug!("Plain DNS: failed to parse AAAA response from {}: {}", server, e);
                }
            }
        }
        
        if ips.is_empty() {
            Err(DnsError::NoIpFound)
        } else {
            debug!("Plain DNS: resolved {} to {:?} via {}", domain, ips, server);
            Ok(ips)
        }
    }
}

#[async_trait]
impl DnsProtocolHandler for PlainDnsHandler {
    async fn query(&self, domain: &str) -> DnsResult<Vec<IpAddr>> {
        // Try each server in sequence until one succeeds
        let mut last_error = None;
        
        for server in &self.config.servers {
            match self.query_server(server, domain).await {
                Ok(ips) => return Ok(ips),
                Err(e) => {
                    warn!("Plain DNS: server {} failed for {}: {}", server, domain, e);
                    last_error = Some(e);
                }
            }
        }
        
        Err(last_error.unwrap_or_else(||
            DnsError::QueryFailed("All DNS servers failed".to_string())
        ))
    }
    
    async fn query_raw(&self, query_data: &[u8]) -> DnsResult<Vec<u8>> {
        let mut last_error = None;
        
        for server in &self.config.servers {
            for attempt in 0..self.config.max_retries {
                let socket = UdpSocket::bind("0.0.0.0:0").await
                    .map_err(|e| DnsError::Io(e))?;

                
                if let Err(e) = socket.send_to(query_data, server).await {
                    debug!("Plain DNS raw: send error to {} (attempt {}): {}", server, attempt + 1, e);
                    last_error = Some(DnsError::Io(e));
                    continue;
                }
                
                let mut response_buf = vec![0u8; 4096];
                match tokio::time::timeout(self.config.timeout, socket.recv_from(&mut response_buf)).await {
                    Ok(Ok((size, src_addr))) => {
                        if src_addr != *server {
                            debug!("Plain DNS raw: response from unexpected source {}, expected {}", src_addr, server);
                            continue;
                        }
                        // Check TC (truncation) flag: bit 1 of byte 2 in the DNS header
                        if size >= 3 && response_buf[2] & 0x02 != 0 {
                            warn!("Plain DNS raw: response from {} was truncated (TC flag set), response may be incomplete", server);
                        }
                        debug!("Plain DNS raw: received {} bytes from {}", size, server);
                        return Ok(response_buf[..size].to_vec());
                    }
                    Ok(Err(e)) => {
                        debug!("Plain DNS raw: recv error from {} (attempt {}): {}", server, attempt + 1, e);
                        last_error = Some(DnsError::Io(e));
                        continue;
                    }
                    Err(_) => {
                        debug!("Plain DNS raw: timeout from {} (attempt {})", server, attempt + 1);
                        last_error = Some(DnsError::Timeout);
                        continue;
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| DnsError::QueryFailed("All DNS servers failed for raw query".to_string())))
    }

    async fn reverse_query(&self, ip: IpAddr) -> DnsResult<String> {
        let ptr_name = match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!("{}.{}.{}.{}.in-addr.arpa.", octets[3], octets[2], octets[1], octets[0])
            }
            IpAddr::V6(v6) => {
                let mut nibbles = String::new();
                for &octet in v6.octets().iter().rev() {
                    nibbles.push_str(&format!("{:x}.{:x}.", octet & 0xf, octet >> 4));
                }
                format!("{}ip6.arpa.", nibbles)
            }
        };
        let query_bytes = Self::build_query(&ptr_name, RecordType::PTR)?;
        
        let response_bytes = self.query_raw(&query_bytes).await?;
        Self::parse_reverse_response(&response_bytes)
    }
    
    fn protocol_name(&self) -> &'static str {
        "plain"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_plain_dns_query() {
        let config = PlainDnsConfig::default();
        let handler = PlainDnsHandler::new(config);
        
        let ips = handler.query("google.com").await.unwrap();
        assert!(!ips.is_empty());
        println!("Resolved google.com to: {:?}", ips);
    }
    
    #[tokio::test]
    async fn test_plain_dns_multiple_servers() {
        let config = PlainDnsConfig {
            servers: vec![
                "8.8.8.8:53".parse().unwrap(),
                "1.1.1.1:53".parse().unwrap(),
            ],
            timeout: Duration::from_secs(5),
            max_retries: 2,
        };
        let handler = PlainDnsHandler::new(config);
        
        let ips = handler.query("cloudflare.com").await.unwrap();
        assert!(!ips.is_empty());
    }
    
    #[tokio::test]
    async fn test_plain_dns_timeout() {
        let config = PlainDnsConfig {
            servers: vec!["192.0.2.1:53".parse().unwrap()], // Non-routable IP
            timeout: Duration::from_secs(1),
            max_retries: 1,
        };
        let handler = PlainDnsHandler::new(config);
        
        let result = handler.query("example.com").await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_plain_dns_invalid_domain() {
        let config = PlainDnsConfig::default();
        let handler = PlainDnsHandler::new(config);
        
        let result = handler.query("this-domain-definitely-does-not-exist-12345.com").await;
        assert!(result.is_err());
    }
}
