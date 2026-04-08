//! DNS Proxy Server
//!
//! Provides DNS service for LAN clients to prevent direct DNS queries to ISP.
//! Listens on UDP port 53 and forwards queries through Internal DNS Resolver.
//!
//! Uses raw query forwarding to support all DNS record types transparently,
//! including TYPE65 (HTTPS/SVCB) which is required for iOS compatibility.
//!
//! Supports dual-stack operation: set `listen_addr = "::"` to handle both
//! IPv4 and IPv6 clients from a single socket (Linux dual-stack default).
//! Uses IP_PKTINFO / IPV6_PKTINFO to preserve destination IP for correct
//! source IP in responses, which is critical for VPN clients that query
//! a specific IP.

use crate::dns_resolver::InternalDnsResolver;
use dashmap::DashMap;
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{RData, RecordType},
    serialize::binary::{BinDecodable, BinEncodable},
};
use log::{debug, error, info, warn};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// IP→domain mapping cache shared with the TPROXY accept loop.
/// Populated from DNS A/AAAA records so the real target domain is available
/// even when ECH hides it behind a public outer SNI (e.g. cloudflare-ech.com).
type DomainCache = Arc<DashMap<IpAddr, (String, Instant)>>;

/// Maximum DNS UDP message size (EDNS0 default)
const MAX_DNS_UDP_SIZE: usize = 4096;

/// Maximum concurrent DNS query handler tasks to prevent OOM under DNS floods.
const MAX_CONCURRENT_DNS_QUERIES: usize = 512;

/// DNS proxy configuration
#[derive(Debug, Clone)]
pub struct DnsProxyConfig {
    /// Enable DNS proxy
    pub enabled: bool,
    /// Listen address.
    /// Use `"0.0.0.0"` for IPv4-only (default).
    /// Use `"::"` for dual-stack IPv4 + IPv6 (recommended when IPv6 is available).
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
    /// Shared IP→domain cache.  Populated from A/AAAA records in DNS responses so
    /// the TPROXY accept loop can find the real target domain even when ECH is used.
    domain_cache: DomainCache,
}

impl DnsProxy {
    /// Create a new DNS proxy
    pub fn new(config: DnsProxyConfig, resolver: Arc<InternalDnsResolver>, domain_cache: DomainCache) -> Self {
        Self {
            config,
            resolver,
            cache: Arc::new(DashMap::new()),
            domain_cache,
        }
    }

    /// Start the DNS proxy server
    pub async fn start(self: Arc<Self>) -> anyhow::Result<()> {
        if !self.config.enabled {
            info!("DNS Proxy is disabled");
            return Ok(());
        }

        // Format bind address — IPv6 literals must be bracketed for std::net parsing.
        let listen_addr = &self.config.listen_addr;
        let bind_addr = if listen_addr.contains(':') && !listen_addr.starts_with('[') {
            // Bare IPv6 address (e.g. "::" or "::1") — wrap in brackets
            format!("[{}]:{}", listen_addr, self.config.listen_port)
        } else {
            format!("{}:{}", listen_addr, self.config.listen_port)
        };

        let is_ipv6 = listen_addr.contains(':');

        // Build the socket using socket2 so we can set options BEFORE bind().
        // std::net::UdpSocket::bind() wraps socket+bind in one call, making it
        // impossible to set IPV6_V6ONLY=0 before binding — the kernel returns EINVAL.
        let addr: SocketAddr = bind_addr.parse()?;
        let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
        let sock2 = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        sock2.set_reuse_address(true)?;

        // On Linux, an AF_INET6 socket bound to "::" accepts both IPv4 and IPv6
        // clients by default (IPV6_V6ONLY=0).  Make this explicit BEFORE bind() so
        // behaviour is consistent across kernels/distros.
        if is_ipv6 {
            sock2.set_only_v6(false)?;
        }

        sock2.bind(&addr.into())?;
        sock2.set_nonblocking(true)?;

        let raw_fd = sock2.as_raw_fd();

        // Enable pktinfo socket options so we can read the destination IP from each
        // incoming packet and stamp the same IP as source on the reply.
        enable_pktinfo(raw_fd, is_ipv6)?;

        let std_socket: std::net::UdpSocket = sock2.into();
        let socket = Arc::new(UdpSocket::from_std(std_socket)?);

        info!(
            "DNS Proxy listening on {} ({} pktinfo enabled)",
            bind_addr,
            if is_ipv6 { "IPv4+IPv6" } else { "IPv4" }
        );
        info!(
            "DNS Proxy using {} protocol for upstream queries",
            self.resolver.protocol_name()
        );

        let mut query_count: u64 = 0;
        // Pre-allocate receive buffer outside the loop to avoid allocation per packet.
        let mut recv_buf = vec![0u8; MAX_DNS_UDP_SIZE];
        // Limit concurrent query handler tasks to prevent OOM during DNS floods
        let query_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_DNS_QUERIES));

        loop {
            // Wait for readable
            socket.readable().await?;

            // Use try_io with recvmsg to get both the query data and the destination IP
            let recv_result = socket.try_io(tokio::io::Interest::READABLE, || {
                let (size, src_addr, dst_ip) = recv_with_pktinfo(raw_fd, &mut recv_buf)?;
                let query_data = recv_buf[..size].to_vec();
                Ok((query_data, src_addr, dst_ip))
            });

            match recv_result {
                Ok((query_data, client_addr, dst_ip)) => {
                    query_count += 1;

                    if self.config.log_queries {
                        debug!(
                            "DNS Proxy: Received query #{} from {} ({} bytes, dst_ip={:?})",
                            query_count,
                            client_addr,
                            query_data.len(),
                            dst_ip
                        );
                    }

                    let socket_clone = socket.clone();
                    let proxy_clone = self.clone();
                    let fd = raw_fd;
                    let sem = query_semaphore.clone();

                    // Spawn handler for this query with concurrency limit
                    tokio::spawn(async move {
                        let _permit = match sem.try_acquire() {
                            Ok(permit) => permit,
                            Err(_) => {
                                warn!(
                                    "DNS Proxy: query limit reached ({}), dropping query from {}",
                                    MAX_CONCURRENT_DNS_QUERIES, client_addr
                                );
                                return;
                            }
                        };
                        if let Err(e) = proxy_clone
                            .handle_query(query_data, client_addr, dst_ip, socket_clone, fd)
                            .await
                        {
                            error!("DNS Proxy: Error handling query from {}: {}", client_addr, e);
                        }
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
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
        dst_ip: Option<IpAddr>,
        socket: Arc<UdpSocket>,
        raw_fd: i32,
    ) -> anyhow::Result<()> {
        // Parse query to extract info for logging, cache key, and ECH domain bridge.
        let (query_id, cache_key, log_info, queried_domain, record_type) = match Message::from_bytes(&query_data) {
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
                // Strip trailing dot (FQDN form "example.com.") for the domain cache.
                let queried_domain = domain.trim_end_matches('.').to_lowercase();

                if self.config.log_queries {
                    debug!("DNS Proxy: Query from {} for {}", client_addr, log_info);
                }

                (msg.id(), cache_key, log_info, queried_domain, record_type)
            }
            Err(e) => {
                warn!("DNS Proxy: Invalid DNS query from {}: {}", client_addr, e);
                return Ok(());
            }
        };

        // Suppress HTTPS/SVCB records (TYPE65/TYPE64) to prevent ECH.
        //
        // Encrypted Client Hello (ECH) requires the browser to first receive an
        // HTTPS/SVCB DNS record (TYPE65) containing the ECH configuration. By
        // returning a valid NOERROR response with zero answers, the browser sees
        // "no HTTPS record exists" and falls back to standard TLS with a plaintext
        // SNI — which the transparent proxy can extract and use for routing.
        //
        // Without this, Cloudflare-hosted domains in the `direct` rule would still
        // be routed through the upstream proxy because the browser sends ECH with
        // outer SNI "cloudflare-ech.com" instead of the real domain.
        //
        // Cost: ECH privacy is not useful in a transparent-proxy context (the proxy
        // sees all traffic anyway), and HTTP/3 negotiation via SVCB is lost (HTTP/2
        // still works normally).
        if record_type == RecordType::HTTPS || record_type == RecordType::SVCB {
            if self.config.log_queries {
                debug!("DNS Proxy: Suppressing {} (ECH prevention)", log_info);
            }
            let response = self.build_error_response_from_query(&query_data, ResponseCode::NoError);
            self.send_response(raw_fd, &socket, &response, client_addr, dst_ip).await?;
            return Ok(());
        }

        // Check cache
        if let Some(cached) = self.cache.get(&cache_key) {
            if !cached.is_expired() {
                if self.config.log_queries {
                    debug!("DNS Proxy: Cache hit for {}", log_info);
                }
                let response = Self::rewrite_response_id(&cached.response, query_id);
                // Even on a cache hit, refresh the IP→domain mapping so the TPROXY
                // path always has a fresh entry for this client's recent DNS query.
                self.populate_domain_cache_from_response(&cached.response, &queried_domain);
                self.send_response(raw_fd, &socket, &response, client_addr, dst_ip)
                    .await?;
                return Ok(());
            }
        }

        // Forward the query transparently to upstream via raw forwarding
        let response = match self.resolver.resolve_raw(&query_data).await {
            Ok(response_bytes) => {
                if self.config.log_queries {
                    debug!(
                        "DNS Proxy: Got {} byte response for {}",
                        response_bytes.len(),
                        log_info
                    );
                }
                response_bytes
            }
            Err(e) => {
                warn!("DNS Proxy: Raw forwarding failed for {}: {}", log_info, e);
                let err_response =
                    self.build_error_response_from_query(&query_data, ResponseCode::ServFail);
                if err_response.is_empty() {
                    error!(
                        "DNS Proxy: Failed to encode SERVFAIL for {} — sending minimal fallback",
                        log_info
                    );
                    let id = query_id.to_be_bytes();
                    vec![
                        id[0], id[1], 0x81, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    ]
                } else {
                    err_response
                }
            }
        };

        self.send_response(raw_fd, &socket, &response, client_addr, dst_ip)
            .await?;

        // Cache successful responses only
        if self.cache.len() < self.config.cache_size_limit {
            if let Ok(msg) = Message::from_bytes(&response) {
                if msg.response_code() == ResponseCode::NoError
                    || msg.response_code() == ResponseCode::NXDomain
                {
                    let min_ttl_secs = msg
                        .answers()
                        .iter()
                        .map(|r| r.ttl())
                        .min()
                        .unwrap_or(self.config.cache_ttl as u32);
                    let cache_duration =
                        Duration::from_secs((min_ttl_secs as u64).max(60).min(3600));
                    self.cache.insert(
                        cache_key,
                        CachedDnsResponse {
                            response: response.clone(),
                            timestamp: Instant::now(),
                            ttl: cache_duration,
                        },
                    );
                }
            }
        }

        // Populate the shared IP→domain cache from A/AAAA records in the response.
        // This lets the TPROXY accept loop find the real target domain even when ECH
        // replaces the visible SNI with cloudflare-ech.com or another public name.
        self.populate_domain_cache_from_response(&response, &queried_domain);

        Ok(())
    }

    /// Parse a raw DNS response and write every A/AAAA answer IP to `domain_cache`,
    /// keyed by IP address and mapping to the original queried domain name.
    ///
    /// We intentionally key by the **queried** domain (question section) rather than
    /// the CNAME target so that the routing decision is made against the name the
    /// client actually asked for — which is the name the operator put in router.json.
    fn populate_domain_cache_from_response(&self, response: &[u8], queried_domain: &str) {
        if queried_domain.is_empty() {
            return;
        }
        if let Ok(msg) = Message::from_bytes(response) {
            if msg.response_code() != ResponseCode::NoError {
                return;
            }
            let now = Instant::now();
            for record in msg.answers() {
                match record.data() {
                    Some(RData::A(addr)) => {
                        self.domain_cache.insert(
                            IpAddr::V4(addr.0),
                            (queried_domain.to_string(), now),
                        );
                        debug!("DNS→DomainCache: {} → {}", addr.0, queried_domain);
                    }
                    Some(RData::AAAA(addr)) => {
                        self.domain_cache.insert(
                            IpAddr::V6(addr.0),
                            (queried_domain.to_string(), now),
                        );
                        debug!("DNS→DomainCache: {} → {}", addr.0, queried_domain);
                    }
                    _ => {} // CNAME, HTTPS/SVCB, MX, etc. — skip
                }
            }
        }
    }

    /// Send a DNS response, using pktinfo to set the correct source IP
    /// when the destination IP from the original query is known.
    async fn send_response(
        &self,
        raw_fd: i32,
        socket: &UdpSocket,
        data: &[u8],
        dst: SocketAddr,
        src_ip: Option<IpAddr>,
    ) -> anyhow::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        if src_ip.is_some() {
            let data_owned = data.to_vec();
            let src = src_ip;
            socket.writable().await?;
            let result = socket.try_io(tokio::io::Interest::WRITABLE, || {
                send_with_pktinfo(raw_fd, &data_owned, dst, src)
            });
            match result {
                Ok(_) => Ok(()),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    socket.send_to(data, dst).await?;
                    Ok(())
                }
                Err(e) => {
                    warn!(
                        "DNS Proxy: sendmsg failed: {}, falling back to send_to",
                        e
                    );
                    socket.send_to(data, dst).await?;
                    Ok(())
                }
            }
        } else {
            socket.send_to(data, dst).await?;
            Ok(())
        }
    }

    /// Rewrite the ID field of a DNS response to match a query ID.
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
            debug!(
                "DNS Proxy: Cache cleanup: {} -> {} entries",
                before_size, after_size
            );
        }
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let total = self.cache.len();
        let expired = self.cache.iter().filter(|entry| entry.is_expired()).count();
        (total, expired)
    }
}

// ---------------------------------------------------------------------------
// Socket helpers
// ---------------------------------------------------------------------------

/// Enable pktinfo socket options so we can read/write the destination IP.
///
/// For IPv4 sockets: IP_PKTINFO.
/// For IPv6 (dual-stack) sockets: both IPV6_RECVPKTINFO and IP_PKTINFO.
/// On a Linux dual-stack socket, native IPv6 packets deliver IPV6_PKTINFO
/// cmsgs while IPv4-mapped packets deliver IP_PKTINFO cmsgs; enabling both
/// ensures we capture the destination address regardless of address family.
fn enable_pktinfo(fd: i32, is_ipv6: bool) -> anyhow::Result<()> {
    let enable: libc::c_int = 1;

    // Always enable IP_PKTINFO (works for IPv4 and IPv4-mapped on dual-stack).
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

    if is_ipv6 {
        // Also enable IPV6_RECVPKTINFO for native IPv6 clients.
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVPKTINFO,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "Failed to set IPV6_RECVPKTINFO: {}",
                std::io::Error::last_os_error()
            ));
        }
        debug!("DNS Proxy: IP_PKTINFO + IPV6_RECVPKTINFO enabled on socket fd={}", fd);
    } else {
        debug!("DNS Proxy: IP_PKTINFO enabled on socket fd={}", fd);
    }

    Ok(())
}

/// Receive a UDP packet with pktinfo control message to get the destination IP.
/// Returns `(bytes_read, source_address, destination_ip)`.
///
/// Handles both IPv4 (IP_PKTINFO) and IPv6 (IPV6_PKTINFO) packets.
fn recv_with_pktinfo(
    fd: i32,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // sockaddr_storage is large enough for both IPv4 and IPv6 source addresses.
    let mut src_addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    // Control message buffer — needs space for in_pktinfo or in6_pktinfo.
    // 256 bytes is enough for both.
    let mut cmsg_buf = [0u8; 256];

    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    msghdr.msg_name = &mut src_addr as *mut _ as *mut libc::c_void;
    msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msghdr.msg_iov = &mut iov;
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msghdr.msg_controllen = cmsg_buf.len();

    let n = unsafe { libc::recvmsg(fd, &mut msghdr, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Walk control messages to find destination IP.
    let mut dst_ip: Option<IpAddr> = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msghdr);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let typ = (*cmsg).cmsg_type;

            if level == libc::IPPROTO_IP && typ == libc::IP_PKTINFO {
                // IPv4 (or IPv4-mapped on dual-stack socket)
                let pktinfo = libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo;
                let addr = (*pktinfo).ipi_spec_dst;
                dst_ip = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.s_addr))));
            } else if level == libc::IPPROTO_IPV6 && typ == libc::IPV6_PKTINFO {
                // Native IPv6 (or IPv4-mapped on dual-stack — normalise to V4).
                let pktinfo = libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo;
                let raw: [u8; 16] = (*pktinfo).ipi6_addr.s6_addr;
                let ip6 = Ipv6Addr::from(raw);
                dst_ip = Some(if let Some(ip4) = ip6.to_ipv4_mapped() {
                    IpAddr::V4(ip4)
                } else {
                    IpAddr::V6(ip6)
                });
            }

            cmsg = libc::CMSG_NXTHDR(&msghdr, cmsg);
        }
    }

    // Reconstruct source SocketAddr from sockaddr_storage.
    let src_socket_addr = sockaddr_storage_to_socketaddr(&src_addr)?;

    Ok((n as usize, src_socket_addr, dst_ip))
}

/// Send a UDP packet with pktinfo control message to set the source IP.
/// This ensures responses come from the same IP that the query was sent to.
///
/// Handles both IPv4 (IP_PKTINFO) and IPv6 (IPV6_PKTINFO) destinations.
fn send_with_pktinfo(
    fd: i32,
    data: &[u8],
    dst: SocketAddr,
    src_ip: Option<IpAddr>,
) -> std::io::Result<usize> {
    // Normalise IPv4-mapped IPv6 addresses so both dst and src_ip are
    // consistently either V4 or V6.  On a dual-stack socket the kernel
    // presents IPv4 clients as ::ffff:x.x.x.x; we must reply using
    // IP_PKTINFO (V4 path), not IPV6_PKTINFO, otherwise the source IP
    // of the reply is chosen by the routing table instead of being
    // pinned to the address the query was sent to.
    let dst = match dst {
        SocketAddr::V6(a) => {
            if let Some(ip4) = a.ip().to_ipv4_mapped() {
                SocketAddr::new(IpAddr::V4(ip4), a.port())
            } else {
                SocketAddr::V6(a)
            }
        }
        other => other,
    };
    let src_ip = match src_ip {
        Some(IpAddr::V6(ip6)) => {
            if let Some(ip4) = ip6.to_ipv4_mapped() {
                Some(IpAddr::V4(ip4))
            } else {
                Some(IpAddr::V6(ip6))
            }
        }
        other => other,
    };

    let iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };

    let mut cmsg_storage = [0u8; 256];
    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    msghdr.msg_iov = &iov as *const _ as *mut libc::iovec;
    msghdr.msg_iovlen = 1;

    match dst {
        SocketAddr::V4(dst_v4) => {
            let mut dst_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            dst_addr.sin_family = libc::AF_INET as libc::sa_family_t;
            dst_addr.sin_port = dst_v4.port().to_be();
            dst_addr.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(dst_v4.ip().octets()),
            };

            msghdr.msg_name = &mut dst_addr as *mut _ as *mut libc::c_void;
            msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

            if let Some(IpAddr::V4(src)) = src_ip {
                unsafe {
                    msghdr.msg_control = cmsg_storage.as_mut_ptr() as *mut libc::c_void;
                    msghdr.msg_controllen = libc::CMSG_SPACE(
                        std::mem::size_of::<libc::in_pktinfo>() as u32,
                    ) as usize;

                    let cmsg = libc::CMSG_FIRSTHDR(&msghdr);
                    (*cmsg).cmsg_level = libc::IPPROTO_IP;
                    (*cmsg).cmsg_type = libc::IP_PKTINFO;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(
                        std::mem::size_of::<libc::in_pktinfo>() as u32,
                    ) as usize;

                    let pktinfo = libc::CMSG_DATA(cmsg) as *mut libc::in_pktinfo;
                    (*pktinfo).ipi_ifindex = 0;
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

        SocketAddr::V6(dst_v6) => {
            let mut dst_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            dst_addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            dst_addr.sin6_port = dst_v6.port().to_be();
            dst_addr.sin6_addr = libc::in6_addr {
                s6_addr: dst_v6.ip().octets(),
            };
            dst_addr.sin6_scope_id = dst_v6.scope_id();

            msghdr.msg_name = &mut dst_addr as *mut _ as *mut libc::c_void;
            msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

            if let Some(IpAddr::V6(src)) = src_ip {
                unsafe {
                    msghdr.msg_control = cmsg_storage.as_mut_ptr() as *mut libc::c_void;
                    msghdr.msg_controllen = libc::CMSG_SPACE(
                        std::mem::size_of::<libc::in6_pktinfo>() as u32,
                    ) as usize;

                    let cmsg = libc::CMSG_FIRSTHDR(&msghdr);
                    (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                    (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(
                        std::mem::size_of::<libc::in6_pktinfo>() as u32,
                    ) as usize;

                    let pktinfo = libc::CMSG_DATA(cmsg) as *mut libc::in6_pktinfo;
                    (*pktinfo).ipi6_addr = libc::in6_addr {
                        s6_addr: src.octets(),
                    };
                    (*pktinfo).ipi6_ifindex = 0;
                }
            }

            let n = unsafe { libc::sendmsg(fd, &msghdr, 0) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(n as usize)
        }
    }
}

/// Convert a `sockaddr_storage` (as returned by `recvmsg`) to a `SocketAddr`.
fn sockaddr_storage_to_socketaddr(
    ss: &libc::sockaddr_storage,
) -> std::io::Result<SocketAddr> {
    match ss.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { &*(ss as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        libc::AF_INET6 => {
            let sin6 =
                unsafe { &*(ss as *const libc::sockaddr_storage as *const libc::sockaddr_in6) };
            let ip6 = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            // Unwrap IPv4-mapped addresses (::ffff:x.x.x.x) so that IPv4 clients
            // connecting through a dual-stack socket are treated as plain IPv4.
            // This ensures send_with_pktinfo uses the V4 path with IP_PKTINFO.
            if let Some(ip4) = ip6.to_ipv4_mapped() {
                Ok(SocketAddr::new(IpAddr::V4(ip4), port))
            } else {
                Ok(SocketAddr::new(IpAddr::V6(ip6), port))
            }
        }
        family => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Unsupported address family: {}", family),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_resolver::{DnsProtocol, DnsResolverConfig};
    use std::os::unix::io::AsRawFd;

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
            listen_port: 5353,
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
    fn test_enable_pktinfo_v4() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();
        assert!(enable_pktinfo(fd, false).is_ok());
    }
}
