//! DNS Proxy Server
//!
//! Provides DNS service for LAN clients to prevent direct DNS queries to ISP.
//! Listens on UDP port 53 and forwards queries through Internal DNS Resolver.
//!
//! Uses raw query forwarding to support all DNS record types transparently,
//! including TYPE65 (HTTPS/SVCB) which is required for iOS compatibility.
//!
//! Uses IP_PKTINFO to preserve destination IP for correct source IP in responses,
//! which is critical for VPN clients that query a specific IP.

use crate::dns_resolver::InternalDnsResolver;
use dashmap::DashMap;
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    serialize::binary::{BinDecodable, BinEncodable},
};
use log::{debug, error, info, warn};
use std::net::{Ipv4Addr, IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Maximum DNS UDP message size (EDNS0 default)
const MAX_DNS_UDP_SIZE: usize = 4096;

/// DNS proxy configuration
#[derive(Debug, Clone)]
pub struct DnsProxyConfig {
    /// Enable DNS proxy
    pub enabled: bool,
    /// Listen address (typically "0.0.0.0")
    pub listen_addr: String,
    /// Listen port (typically 53)
    pub listen_port: u16,
    /// Cache size limit
    pub cache_size_limit: usize,
    /// Cache TTL in seconds
    pub cache_ttl: u64,
    /// Log DNS queries (for debugging)
    pub log_queries: bool,
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: "0.0.0.0".to_string(),
            listen_port: 53,
            cache_size_limit: 10000,
            cache_ttl: 3600,
            log_queries: false,
        }
    }
}

/// Cached DNS response
#[derive(Debug, Clone)]
struct CachedDnsResponse {
    response: Vec<u8>,
    timestamp: Instant,
    /// Per-entry TTL derived from the DNS response records (clamped to [60, 3600] s).
    ttl: Duration,
}

impl CachedDnsResponse {
    fn is_expired(&self) -> bool {
        self.timestamp.elapsed() > self.ttl
    }
}

/// DNS Proxy Server
pub struct DnsProxy {
    config: DnsProxyConfig,
    resolver: Arc<InternalDnsResolver>,
    cache: Arc<DashMap<String, CachedDnsResponse>>,
}

impl DnsProxy {
    /// Create a new DNS proxy
    pub fn new(config: DnsProxyConfig, resolver: Arc<InternalDnsResolver>) -> Self {
        Self {
            config,
            resolver,
            cache: Arc::new(DashMap::new()),
        }
    }
    
    /// Start the DNS proxy server
    pub async fn start(self: Arc<Self>) -> anyhow::Result<()> {
        if !self.config.enabled {
            info!("DNS Proxy is disabled");
            return Ok(());
        }
        
        let bind_addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        
        // Create socket with IP_PKTINFO enabled for correct source IP in responses.
        // This is critical for VPN clients that query a specific server IP —
        // without IP_PKTINFO, the kernel may choose a different source IP
        // (e.g., the tun0 IP instead of the LAN IP), causing the client
        // to drop the response due to source address mismatch.
        let std_socket = std::net::UdpSocket::bind(&bind_addr)?;
        std_socket.set_nonblocking(true)?;
        
        let raw_fd = std_socket.as_raw_fd();
        enable_ip_pktinfo(raw_fd)?;
        
        let socket = Arc::new(UdpSocket::from_std(std_socket)?);
        
        info!("DNS Proxy listening on {} (IP_PKTINFO enabled)", bind_addr);
        info!("DNS Proxy using {} protocol for upstream queries", 
            self.resolver.protocol_name());
        
        let mut query_count: u64 = 0;
        
        loop {
            // Wait for readable
            socket.readable().await?;
            
            // Use try_io with recvmsg to get both the query data and the destination IP
            let recv_result = socket.try_io(tokio::io::Interest::READABLE, || {
                let mut buf = vec![0u8; MAX_DNS_UDP_SIZE];
                let (size, src_addr, dst_ip) = recv_with_pktinfo(raw_fd, &mut buf)?;
                buf.truncate(size);
                Ok((buf, src_addr, dst_ip))
            });
            
            match recv_result {
                Ok((query_data, client_addr, dst_ip)) => {
                    query_count += 1;
                    
                    if self.config.log_queries {
                        debug!("DNS Proxy: Received query #{} from {} ({} bytes, dst_ip={:?})",
                            query_count, client_addr, query_data.len(), dst_ip);
                    }
                    
                    let socket_clone = socket.clone();
                    let proxy_clone = self.clone();
                    let fd = raw_fd;
                    
                    // Spawn handler for this query
                    tokio::spawn(async move {
                        if let Err(e) = proxy_clone.handle_query(query_data, client_addr, dst_ip, socket_clone, fd).await {
                            error!("DNS Proxy: Error handling query from {}: {}", client_addr, e);
                        }
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Spurious wakeup from try_io, continue
                    continue;
                }
                Err(e) => {
                    error!("DNS Proxy: Error receiving from socket: {}", e);
                }
            }
            
            // Periodic cache cleanup
            if query_count % 1000 == 0 {
                self.cleanup_cache();
            }
        }
    }
    
    /// Handle a DNS query by forwarding it transparently to upstream
    async fn handle_query(
        &self,
        query_data: Vec<u8>,
        client_addr: SocketAddr,
        dst_ip: Option<Ipv4Addr>,
        socket: Arc<UdpSocket>,
        raw_fd: i32,
    ) -> anyhow::Result<()> {
        // Parse query to extract info for logging and cache key
        let (query_id, cache_key, log_info) = match Message::from_bytes(&query_data) {
            Ok(msg) => {
                if msg.queries().is_empty() {
                    warn!("DNS Proxy: Empty query from {}", client_addr);
                    return Ok(());
                }
                
                let query = &msg.queries()[0];
                let domain = query.name().to_utf8();
                let record_type = query.query_type();
                let cache_key = format!("{}:{:?}", domain, record_type);
                let log_info = format!("{} ({:?})", domain, record_type);
                
                if self.config.log_queries {
                    debug!("DNS Proxy: Query from {} for {}", client_addr, log_info);
                }
                
                (msg.id(), cache_key, log_info)
            }
            Err(e) => {
                warn!("DNS Proxy: Invalid DNS query from {}: {}", client_addr, e);
                return Ok(());
            }
        };
        
        // Check cache
        if let Some(cached) = self.cache.get(&cache_key) {
            if !cached.is_expired() {
                if self.config.log_queries {
                    debug!("DNS Proxy: Cache hit for {}", log_info);
                }
                // Update the ID in the cached response to match the current query
                let response = Self::rewrite_response_id(&cached.response, query_id);
                self.send_response(raw_fd, &socket, &response, client_addr, dst_ip).await?;
                return Ok(());
            }
        }
        
        // Forward the query transparently to upstream via raw forwarding
        let response = match self.resolver.resolve_raw(&query_data).await {
            Ok(response_bytes) => {
                if self.config.log_queries {
                    debug!("DNS Proxy: Got {} byte response for {}", response_bytes.len(), log_info);
                }
                response_bytes
            }
            Err(e) => {
                warn!("DNS Proxy: Raw forwarding failed for {}: {}", log_info, e);
                // Build SERVFAIL response
                let err_response = self.build_error_response_from_query(&query_data, ResponseCode::ServFail);
                if err_response.is_empty() {
                    // build_error_response_from_query failed (query unparseable or encoding
                    // error).  Without a fallback the client would hang until timeout —
                    // send a minimal hardcoded SERVFAIL with the original query ID instead.
                    error!("DNS Proxy: Failed to encode SERVFAIL for {} — sending minimal fallback", log_info);
                    let id = query_id.to_be_bytes();
                    vec![id[0], id[1], 0x81, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
                } else {
                    err_response
                }
            }
        };
        
        // Send response with correct source IP
        self.send_response(raw_fd, &socket, &response, client_addr, dst_ip).await?;
        
        // Cache response (only cache successful responses)
        if self.cache.len() < self.config.cache_size_limit {
            if let Ok(msg) = Message::from_bytes(&response) {
                if msg.response_code() == ResponseCode::NoError ||
                   msg.response_code() == ResponseCode::NXDomain {
                    // Extract the minimum TTL from answer records and clamp to [60, 3600] s
                    // so we respect the authoritative server's intended lifetime instead of
                    // always using the hardcoded 3600 s default.
                    let min_ttl_secs = msg.answers().iter()
                        .map(|r| r.ttl())
                        .min()
                        .unwrap_or(self.config.cache_ttl as u32);
                    let cache_duration = Duration::from_secs(
                        (min_ttl_secs as u64).max(60).min(3600)
                    );
                    self.cache.insert(cache_key, CachedDnsResponse {
                        response: response.clone(),
                        timestamp: Instant::now(),
                        ttl: cache_duration,
                    });
                }
            }
        }
        
        Ok(())
    }
    
    /// Send a DNS response, using IP_PKTINFO to set the correct source IP
    /// when the destination IP from the original query is known.
    async fn send_response(
        &self,
        raw_fd: i32,
        socket: &UdpSocket,
        data: &[u8],
        dst: SocketAddr,
        src_ip: Option<Ipv4Addr>,
    ) -> anyhow::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        
        if src_ip.is_some() {
            // Use sendmsg with IP_PKTINFO for correct source IP
            let data_owned = data.to_vec();
            let src = src_ip;
            socket.writable().await?;
            let result = socket.try_io(tokio::io::Interest::WRITABLE, || {
                send_with_pktinfo(raw_fd, &data_owned, dst, src)
            });
            match result {
                Ok(_) => Ok(()),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Retry with regular send_to
                    socket.send_to(data, dst).await?;
                    Ok(())
                }
                Err(e) => {
                    warn!("DNS Proxy: sendmsg failed: {}, falling back to send_to", e);
                    socket.send_to(data, dst).await?;
                    Ok(())
                }
            }
        } else {
            // No destination IP info, use regular send_to
            socket.send_to(data, dst).await?;
            Ok(())
        }
    }
    
    /// Rewrite the ID field of a DNS response to match a query ID.
    /// The ID is the first 2 bytes of the DNS message.
    fn rewrite_response_id(response: &[u8], new_id: u16) -> Vec<u8> {
        if response.len() < 2 {
            return response.to_vec();
        }
        let mut result = response.to_vec();
        let id_bytes = new_id.to_be_bytes();
        result[0] = id_bytes[0];
        result[1] = id_bytes[1];
        result
    }
    
    /// Build an error DNS response from raw query data
    fn build_error_response_from_query(&self, query_data: &[u8], rcode: ResponseCode) -> Vec<u8> {
        if let Ok(query_message) = Message::from_bytes(query_data) {
            return self.build_error_response(&query_message, rcode);
        }
        warn!("DNS Proxy: Cannot build error response - query unparseable");
        Vec::new()
    }
    
    /// Build an error DNS response
    fn build_error_response(&self, query_message: &Message, rcode: ResponseCode) -> Vec<u8> {
        let mut response = Message::new();
        response.set_id(query_message.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_response_code(rcode);
        response.set_recursion_desired(true);
        response.set_recursion_available(true);
        
        for query in query_message.queries() {
            response.add_query(query.clone());
        }
        
        match response.to_bytes() {
            Ok(encoder) => encoder.to_vec(),
            Err(e) => {
                warn!("DNS Proxy: Failed to encode error response: {}", e);
                Vec::new()
            }
        }
    }
    
    /// Clean up expired cache entries
    fn cleanup_cache(&self) {
        let before_size = self.cache.len();

        self.cache.retain(|_, entry| !entry.is_expired());
        
        let after_size = self.cache.len();
        if before_size != after_size {
            debug!("DNS Proxy: Cache cleanup: {} -> {} entries", before_size, after_size);
        }
    }
    
    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let total = self.cache.len();
        let expired = self.cache.iter()
            .filter(|entry| entry.is_expired())
            .count();
        (total, expired)
    }
}

/// Enable IP_PKTINFO socket option to retrieve destination IP on incoming packets.
fn enable_ip_pktinfo(fd: i32) -> anyhow::Result<()> {
    let enable: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "Failed to set IP_PKTINFO: {}",
            std::io::Error::last_os_error()
        ));
    }
    debug!("DNS Proxy: IP_PKTINFO enabled on socket fd={}", fd);
    Ok(())
}

/// Receive a UDP packet with IP_PKTINFO control message to get the destination IP.
/// Returns (bytes_read, source_address, destination_ipv4).
fn recv_with_pktinfo(
    fd: i32,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, Option<Ipv4Addr>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    
    let mut src_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    
    // Control message buffer — needs enough space for IP_PKTINFO
    let mut cmsg_buf = [0u8; 128];
    
    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    msghdr.msg_name = &mut src_addr as *mut _ as *mut libc::c_void;
    msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msghdr.msg_iov = &mut iov;
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msghdr.msg_controllen = cmsg_buf.len();
    
    let n = unsafe { libc::recvmsg(fd, &mut msghdr, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    
    // Extract destination IP from IP_PKTINFO control message
    let mut dst_ip = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msghdr);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_PKTINFO {
                let pktinfo = libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo;
                let addr = (*pktinfo).ipi_spec_dst;
                dst_ip = Some(Ipv4Addr::from(u32::from_be(addr.s_addr)));
            }
            cmsg = libc::CMSG_NXTHDR(&msghdr, cmsg);
        }
    }
    
    let src_socket_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(u32::from_be(src_addr.sin_addr.s_addr))),
        u16::from_be(src_addr.sin_port),
    );
    
    Ok((n as usize, src_socket_addr, dst_ip))
}

/// Send a UDP packet with IP_PKTINFO control message to set the source IP.
/// This ensures responses come from the same IP that the query was sent to.
fn send_with_pktinfo(
    fd: i32,
    data: &[u8],
    dst: SocketAddr,
    src_ip: Option<Ipv4Addr>,
) -> std::io::Result<usize> {
    let dst_v4 = match dst {
        SocketAddr::V4(a) => a,
        SocketAddr::V6(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "IPv6 not yet supported for IP_PKTINFO send",
            ));
        }
    };
    
    let mut dst_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    dst_addr.sin_family = libc::AF_INET as libc::sa_family_t;
    dst_addr.sin_port = dst_v4.port().to_be();
    dst_addr.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(dst_v4.ip().octets()),
    };
    
    let iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    
    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    msghdr.msg_name = &mut dst_addr as *mut _ as *mut libc::c_void;
    msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msghdr.msg_iov = &iov as *const _ as *mut libc::iovec;
    msghdr.msg_iovlen = 1;
    
    // Build IP_PKTINFO control message to set source IP
    let mut cmsg_storage = [0u8; 256];
    
    if let Some(src) = src_ip {
        unsafe {
            msghdr.msg_control = cmsg_storage.as_mut_ptr() as *mut libc::c_void;
            msghdr.msg_controllen = libc::CMSG_SPACE(
                std::mem::size_of::<libc::in_pktinfo>() as u32
            ) as usize;
            
            let cmsg = libc::CMSG_FIRSTHDR(&msghdr);
            (*cmsg).cmsg_level = libc::IPPROTO_IP;
            (*cmsg).cmsg_type = libc::IP_PKTINFO;
            (*cmsg).cmsg_len = libc::CMSG_LEN(
                std::mem::size_of::<libc::in_pktinfo>() as u32
            ) as usize;
            
            let pktinfo = libc::CMSG_DATA(cmsg) as *mut libc::in_pktinfo;
            (*pktinfo).ipi_ifindex = 0; // let kernel choose interface
            (*pktinfo).ipi_spec_dst = libc::in_addr {
                s_addr: u32::from_ne_bytes(src.octets()),
            };
            (*pktinfo).ipi_addr = libc::in_addr { s_addr: 0 };
        }
    }
    
    let n = unsafe { libc::sendmsg(fd, &msghdr, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    
    Ok(n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_resolver::{DnsProtocol, DnsResolverConfig};
    
    #[tokio::test]
    #[ignore] // Requires binding to :53 (root)
    async fn test_dns_proxy_basic() {
        let resolver_config = DnsResolverConfig {
            protocol: DnsProtocol::Plain,
            ..Default::default()
        };
        
        let resolver = InternalDnsResolver::from_config(resolver_config).await.unwrap();
        let resolver = Arc::new(resolver);
        
        let proxy_config = DnsProxyConfig {
            enabled: true,
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 5353, // Non-privileged port for testing
            log_queries: true,
            ..Default::default()
        };
        
        let proxy = Arc::new(DnsProxy::new(proxy_config, resolver));
        
        let proxy_clone = proxy.clone();
        tokio::spawn(async move {
            proxy_clone.start().await.unwrap();
        });
        
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    #[test]
    fn test_rewrite_response_id() {
        let response = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01];
        let rewritten = DnsProxy::rewrite_response_id(&response, 0xABCD);
        assert_eq!(rewritten[0], 0xAB);
        assert_eq!(rewritten[1], 0xCD);
        assert_eq!(rewritten[2..], response[2..]);
    }
    
    #[test]
    fn test_enable_ip_pktinfo() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();
        assert!(enable_ip_pktinfo(fd).is_ok());
    }
}
