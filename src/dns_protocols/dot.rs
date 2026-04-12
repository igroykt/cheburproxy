//! DNS over TLS (DoT) Handler
//!
//! RFC 7858 - DNS over TLS for encrypted DNS queries
//! NOTE: Previous implementation had issues with tokio::spawn hanging after ~10 queries
//! This implementation avoids connection pooling and creates new connections for each query

use super::{DnsError, DnsProtocolHandler, DnsResult};
use async_trait::async_trait;
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
    serialize::binary::{BinDecodable, BinEncodable},
};
use log::{debug, warn};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::transparent::connect_tcp_with_mark;
use tokio_rustls::TlsConnector;

/// DNS server configuration for DoT
#[derive(Debug, Clone)]
pub struct DotServer {
    /// Server IP address
    pub address: IpAddr,
    /// Server port (typically 853)
    pub port: u16,
    /// TLS SNI name (e.g., "dns.google")
    pub tls_name: String,
}

/// DoT handler configuration
#[derive(Debug, Clone)]
pub struct DotConfig {
    /// List of DoT servers
    pub servers: Vec<DotServer>,
    /// Connection timeout
    pub timeout: Duration,
    /// Maximum retries per server
    pub max_retries: usize,
}

impl Default for DotConfig {
    fn default() -> Self {
        Self {
            servers: vec![
                DotServer {
                    address: "8.8.8.8".parse().unwrap(),
                    port: 853,
                    tls_name: "dns.google".to_string(),
                },
                DotServer {
                    address: "1.1.1.1".parse().unwrap(),
                    port: 853,
                    tls_name: "cloudflare-dns.com".to_string(),
                },
            ],
            timeout: Duration::from_secs(10),
            max_retries: 2,
        }
    }
}

/// DNS over TLS handler
pub struct DotHandler {
    config: DotConfig,
    tls_config: Arc<ClientConfig>,
}

impl DotHandler {
    /// Create a new DoT handler
    pub fn new(config: DotConfig) -> DnsResult<Self> {
        // Create TLS config with native root certificates
        let mut root_store = rustls::RootCertStore::empty();
        
        // Load native certificates
        let native_certs = rustls_native_certs::load_native_certs()
            .map_err(|e| DnsError::TlsError(format!("Failed to load native certs: {}", e)))?;
        
        for cert in native_certs {
            root_store.add(cert).map_err(|e| 
                DnsError::TlsError(format!("Failed to add cert: {}", e))
            )?;
        }
        
        let tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        
        Ok(Self {
            config,
            tls_config: Arc::new(tls_config),
        })
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

        // Set EDNS0 OPT record with DO (DNSSEC OK) bit so the upstream validates DNSSEC.
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        edns.set_dnssec_ok(true);
        message.set_edns(edns);

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
    
    /// Send a DNS query over a TLS stream and read the response
    async fn send_query_and_read(
        tls_stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
        query: &[u8],
        timeout_duration: Duration,
    ) -> DnsResult<Vec<u8>> {
        // DNS over TCP uses 2-byte length prefix
        let len_prefix = (query.len() as u16).to_be_bytes();
        let mut tcp_query = Vec::with_capacity(2 + query.len());
        tcp_query.extend_from_slice(&len_prefix);
        tcp_query.extend_from_slice(query);
        
        tls_stream.write_all(&tcp_query).await
            .map_err(|e| DnsError::Io(e))?;
        
        // Read response length
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(timeout_duration, tls_stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Io(e))?;
        
        let response_len = u16::from_be_bytes(len_buf) as usize;
        
        // Read response
        let mut response_buf = vec![0u8; response_len];
        tokio::time::timeout(timeout_duration, tls_stream.read_exact(&mut response_buf))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Io(e))?;
        
        Ok(response_buf)
    }
    
    /// Forward raw DNS query bytes to a DoT server and return raw response bytes
    async fn query_raw_server(&self, server: &DotServer, query_data: &[u8]) -> DnsResult<Vec<u8>> {
        let server_addr = SocketAddr::new(server.address, server.port);
        
        // Connect TCP
        let tcp_stream = tokio::time::timeout(
            self.config.timeout,
            connect_tcp_with_mark(&server_addr)
        )
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(|e| DnsError::ConnectionError(format!("Failed to connect to {}: {}", server_addr, e)))?;
        
        // Establish TLS
        let connector = TlsConnector::from(self.tls_config.clone());
        let server_name = ServerName::try_from(server.tls_name.clone())
            .map_err(|e| DnsError::TlsError(format!("Invalid server name: {}", e)))?;
        
        let mut tls_stream = tokio::time::timeout(
            self.config.timeout,
            connector.connect(server_name.to_owned(), tcp_stream)
        )
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(|e| DnsError::TlsError(format!("TLS handshake failed: {}", e)))?;
        
        // Send query and read response using existing helper
        Self::send_query_and_read(&mut tls_stream, query_data, self.config.timeout).await
    }
    
    /// Query a single DoT server with both A and AAAA queries
    /// IMPORTANT: Creates new connection for each query to avoid previous tokio::spawn issues
    async fn query_server(&self, server: &DotServer, domain: &str) -> DnsResult<Vec<IpAddr>> {
        let server_addr = SocketAddr::new(server.address, server.port);
        
        // Connect TCP
        let tcp_stream = tokio::time::timeout(
            self.config.timeout,
            connect_tcp_with_mark(&server_addr)
        )
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(|e| DnsError::ConnectionError(format!("Failed to connect to {}: {}", server_addr, e)))?;
        
        // Establish TLS
        let connector = TlsConnector::from(self.tls_config.clone());
        let server_name = ServerName::try_from(server.tls_name.clone())
            .map_err(|e| DnsError::TlsError(format!("Invalid server name: {}", e)))?;
        
        let mut tls_stream = tokio::time::timeout(
            self.config.timeout,
            connector.connect(server_name.to_owned(), tcp_stream)
        )
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(|e| DnsError::TlsError(format!("TLS handshake failed: {}", e)))?;
        
        debug!("DoT: Established TLS connection to {} ({})", server.tls_name, server_addr);
        
        // Build both queries
        let query_a = Self::build_query(domain, RecordType::A)?;
        let query_aaaa = Self::build_query(domain, RecordType::AAAA)?;
        
        // Extract transaction IDs (first 2 bytes of DNS wire format)
        let id_a = if query_a.len() >= 2 {
            u16::from_be_bytes([query_a[0], query_a[1]])
        } else {
            0
        };
        let id_aaaa = if query_aaaa.len() >= 2 {
            u16::from_be_bytes([query_aaaa[0], query_aaaa[1]])
        } else {
            0
        };
        
        let mut ips = Vec::new();
        
        // Send A query and read first response (sequential)
        let resp_a_result = Self::send_query_and_read(&mut tls_stream, &query_a, self.config.timeout).await;
        // Send AAAA query and read second response (sequential)
        let resp_aaaa_result = Self::send_query_and_read(&mut tls_stream, &query_aaaa, self.config.timeout).await;
        
        // Validate transaction IDs to detect server response reordering (RFC 1035 §4.1.1).
        // Although reordering is impossible in this strict sequential send/recv pattern,
        // the check is a safety net against corrupt or out-of-order responses.
        let (a_bytes, aaaa_bytes) = match (resp_a_result, resp_aaaa_result) {
            (Ok(r1), Ok(r2)) => {
                let id_r1 = if r1.len() >= 2 {
                    u16::from_be_bytes([r1[0], r1[1]])
                } else {
                    0
                };
                // Swap only when the first response clearly belongs to the AAAA query
                // and NOT to the A query (guard against the id_a == id_aaaa edge case).
                if id_r1 == id_aaaa && id_r1 != id_a {
                    warn!("DoT: responses arrived out of order for {} via {}, correcting by transaction ID",
                        domain, server.tls_name);
                    (Some(r2), Some(r1))
                } else {
                    (Some(r1), Some(r2))
                }
            }
            (Ok(r1), Err(e)) => {
                debug!("DoT: AAAA query failed for {} via {}: {}", domain, server.tls_name, e);
                (Some(r1), None)
            }
            (Err(e), Ok(r2)) => {
                debug!("DoT: A query failed for {} via {}: {}", domain, server.tls_name, e);
                (None, Some(r2))
            }
            (Err(e1), Err(e2)) => {
                debug!("DoT: A query failed for {} via {}: {}", domain, server.tls_name, e1);
                debug!("DoT: AAAA query failed for {} via {}: {}", domain, server.tls_name, e2);
                (None, None)
            }
        };
        
        // Process A response
        if let Some(response_bytes) = a_bytes {
            match Self::parse_response(&response_bytes) {
                Ok(a_ips) if !a_ips.is_empty() => {
                    debug!("DoT: found {} A record(s) for {} via {}", a_ips.len(), domain, server.tls_name);
                    ips.extend(a_ips);
                }
                Ok(_) => {
                    debug!("DoT: no A records for {} via {}", domain, server.tls_name);
                }
                Err(e) => {
                    debug!("DoT: failed to parse A response from {}: {}", server.tls_name, e);
                }
            }
        }
        
        // Process AAAA response
        if let Some(response_bytes) = aaaa_bytes {
            match Self::parse_response(&response_bytes) {
                Ok(aaaa_ips) if !aaaa_ips.is_empty() => {
                    debug!("DoT: found {} AAAA record(s) for {} via {}", aaaa_ips.len(), domain, server.tls_name);
                    ips.extend(aaaa_ips);
                }
                Ok(_) => {
                    debug!("DoT: no AAAA records for {} via {}", domain, server.tls_name);
                }
                Err(e) => {
                    debug!("DoT: failed to parse AAAA response from {}: {}", server.tls_name, e);
                }
            }
        }
        
        if ips.is_empty() {
            Err(DnsError::NoIpFound)
        } else {
            debug!("DoT: resolved {} to {:?} via {}", domain, ips, server.tls_name);
            Ok(ips)
        }
    }
}

#[async_trait]
impl DnsProtocolHandler for DotHandler {
    async fn query(&self, domain: &str) -> DnsResult<Vec<IpAddr>> {
        // Try each server until one succeeds
        let mut last_error = None;
        
        for server in &self.config.servers {
            for attempt in 0..self.config.max_retries {
                match self.query_server(server, domain).await {
                    Ok(ips) => {
                        debug!("DoT: successfully resolved {} via {} (attempt {})",
                            domain, server.tls_name, attempt + 1);
                        return Ok(ips);
                    }
                    Err(e) => {
                        warn!("DoT: attempt {} failed for {} via {}: {}",
                            attempt + 1, domain, server.tls_name, e);
                        last_error = Some(e);
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(||
            DnsError::QueryFailed("All DoT servers failed".to_string())
        ))
    }
    
    async fn query_raw(&self, query_data: &[u8]) -> DnsResult<Vec<u8>> {
        let mut last_error = None;
        
        for server in &self.config.servers {
            for attempt in 0..self.config.max_retries {
                match self.query_raw_server(server, query_data).await {
                    Ok(response) => {
                        debug!("DoT raw: received {} bytes from {} (attempt {})",
                            response.len(), server.tls_name, attempt + 1);
                        return Ok(response);
                    }
                    Err(e) => {
                        warn!("DoT raw: attempt {} failed via {}: {}",
                            attempt + 1, server.tls_name, e);
                        last_error = Some(e);
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(||
            DnsError::QueryFailed("All DoT servers failed for raw query".to_string())
        ))
    }
    
    fn protocol_name(&self) -> &'static str {
        "dot"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_dot_query() {
        let config = DotConfig::default();
        let handler = DotHandler::new(config).unwrap();
        
        let ips = handler.query("google.com").await.unwrap();
        assert!(!ips.is_empty());
        println!("Resolved google.com via DoT: {:?}", ips);
    }
    
    #[tokio::test]
    async fn test_dot_multiple_queries() {
        // Regression test for previous tokio::spawn hanging issue
        let config = DotConfig::default();
        let handler = DotHandler::new(config).unwrap();
        
        for i in 0..20 {
            let ips = handler.query("google.com").await.unwrap();
            assert!(!ips.is_empty());
            println!("Query #{}: {:?}", i + 1, ips);
        }
    }
    
    #[tokio::test]
    async fn test_dot_cloudflare() {
        let config = DotConfig {
            servers: vec![DotServer {
                address: "1.1.1.1".parse().unwrap(),
                port: 853,
                tls_name: "cloudflare-dns.com".to_string(),
            }],
            timeout: Duration::from_secs(10),
            max_retries: 2,
        };
        let handler = DotHandler::new(config).unwrap();
        
        let ips = handler.query("example.com").await.unwrap();
        assert!(!ips.is_empty());
    }
}
