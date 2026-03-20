use crate::rule::{RuleEngine, RoutingDecision};
use crate::sni::extract_sni;
use crate::router::Proxy;
use crate::proxy_health;
use crate::transparent::connect_tcp_with_mark;
use tokio::{net::TcpStream, time::{timeout, Duration}, io::AsyncWriteExt, sync::{OwnedSemaphorePermit, Semaphore}};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;
use log::{debug, info, warn};
use lazy_static::lazy_static;
use dashmap::DashMap;
use std::hash::{Hash, Hasher};
use socket2::SockRef;

// Constants for better maintainability
const CONNECTION_POOL_TIMEOUT_SECS: u64 = 60;
const PEEK_TIMEOUT_SECS: u64 = 10;
const PEEK_BUFFER_SIZE: usize = 4096;
// Maximum connection lifetime (hard limit to prevent stalled connections)
const MAX_CONNECTION_LIFETIME_SECS: u64 = 3600; // 1 hour
const MAX_CONNECTION_POOL_SIZE: usize = 10;
// TCP keepalive settings for pooled proxy connections:
// Detect dead connections proactively instead of waiting until use.
const TCP_KEEPALIVE_TIME_SECS: u64 = 30;      // Time before first keepalive probe
const TCP_KEEPALIVE_INTERVAL_SECS: u64 = 10;  // Interval between probes
const TCP_KEEPALIVE_RETRIES: u32 = 3;         // Max failed probes before connection is dead
// Number of connections to pre-establish when a proxy recovers
const POOL_WARMUP_SIZE: usize = 3;
const SOCKS5_VERSION: u8 = 5;
const SOCKS5_CONNECT_CMD: u8 = 1;
const SOCKS5_NO_AUTH: u8 = 0;
const SOCKS5_USER_PASS_AUTH: u8 = 2;
const SOCKS5_ATYP_IPV4: u8 = 1;
const SOCKS5_ATYP_IPV6: u8 = 4;
const SOCKS5_ATYP_DOMAIN: u8 = 3;
const SOCKS5_AUTH_VERSION: u8 = 1;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProxyKey {
    addr: String,
    port: u16,
    tag: String,
}

impl Hash for ProxyKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.port.hash(state);
        self.tag.hash(state);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KeepaliveConfig {
    pub time: Duration,
    pub interval: Duration,
    pub retries: u32,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        KeepaliveConfig {
            time: Duration::from_secs(TCP_KEEPALIVE_TIME_SECS),
            interval: Duration::from_secs(TCP_KEEPALIVE_INTERVAL_SECS),
            retries: TCP_KEEPALIVE_RETRIES,
        }
    }
}

lazy_static! {
    pub static ref KEEPALIVE_CONFIG: RwLock<KeepaliveConfig> = RwLock::new(KeepaliveConfig::default());
    pub static ref CONNECTION_POOL: DashMap<ProxyKey, Vec<(TcpStream, Instant, OwnedSemaphorePermit)>> = DashMap::new();
    /// Per-proxy connection limits to prevent one failing proxy from exhausting global semaphore (default 1024).
    pub static ref PER_PROXY_LIMITS: DashMap<ProxyKey, Arc<Semaphore>> = DashMap::new();
    /// Configured maximum connections per proxy.
    pub static ref PER_PROXY_MAX_CONNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1024);
}

pub fn get_proxy_key(proxy: &Proxy) -> ProxyKey {
    ProxyKey {
        addr: proxy.server_addr.clone(),
        port: proxy.server_port,
        tag: proxy.tag.clone(),
    }
}

pub fn acquire_proxy_permit(proxy_key: &ProxyKey) -> Result<OwnedSemaphorePermit> {
    let proxy_addr = format!("{}:{}", proxy_key.addr, proxy_key.port);
    let limit = get_per_proxy_max_conns();
    let semaphore = PER_PROXY_LIMITS
        .entry(proxy_key.clone())
        .or_insert_with(|| Arc::new(Semaphore::new(limit)))
        .value()
        .clone();

    match semaphore.try_acquire_owned() {
        Ok(p) => Ok(p),
        Err(_) => {
            warn!("Per-proxy connection limit reached ({}) for {}, dropping connection to prevent global stall",
                  limit, proxy_addr);
            Err(ProxyError::ProxyUnavailable { addr: proxy_addr })
        }
    }
}

pub fn set_per_proxy_max_conns(limit: usize) {
    PER_PROXY_MAX_CONNS.store(limit, std::sync::atomic::Ordering::Relaxed);
    info!("Updated per-proxy connection limit to {}", limit);
}

pub fn get_per_proxy_max_conns() -> usize {
    PER_PROXY_MAX_CONNS.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn set_keepalive_config(time: Duration, interval: Duration, retries: u32) {
    let mut config = KEEPALIVE_CONFIG.write().unwrap_or_else(|e| e.into_inner());
    config.time = time;
    config.interval = interval;
    config.retries = retries;
    info!("Updated TCP Keepalive config: time={:?}, interval={:?}, retries={}", time, interval, retries);
}

pub fn get_keepalive_config() -> KeepaliveConfig {
    KEEPALIVE_CONFIG.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Get summary of per-proxy connection states for diagnostics.
/// Returns a string like "proxy1:10/256(5), proxy2:0/256(0)" where
/// 10 is active connections, 256 is limit, and 5 is pooled connections.
pub fn get_proxy_stats_summary() -> String {
    let mut stats = Vec::new();
    let limit = get_per_proxy_max_conns();
    for entry in PER_PROXY_LIMITS.iter() {
        let key = entry.key();
        let semaphore = entry.value();
        let active = limit - semaphore.available_permits();
        let pooled = CONNECTION_POOL.get(key).map(|v| v.len()).unwrap_or(0);
        stats.push(format!("{}:{}/{}({})", key.addr, active, limit, pooled));
    }
    stats.join(", ")
}

#[derive(Debug, thiserror::Error)]
enum ConnectionPoolError {
    #[error("Connection pool exhausted")]
    PoolExhausted,
    #[error("Connection timeout")]
    ConnectionTimeout,
    #[error("Invalid proxy configuration")]
    InvalidProxyConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("SOCKS5 negotiation failed: {message}")]
    Socks5Error { message: String },

    #[error("Connection pool error: {0}")]
    PoolError(#[from] ConnectionPoolError),

    #[error("Connection timeout after {duration:?}")]
    ConnectionTimeout { duration: Duration },

    #[error("DNS resolution failed for {domain}: {source}")]
    DnsResolutionError { domain: String, source: std::io::Error },

    #[error("TLS handshake failed: {message}")]
    TlsError { message: String },

    #[error("Routing decision error: no rule matched for domain '{domain}'")]
    NoRoutingRule { domain: String },

    #[error("Proxy {addr} unavailable (circuit breaker open)")]
    ProxyUnavailable { addr: String },

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Generic error: {message}")]
    GenericError { message: String },
}

impl From<anyhow::Error> for ProxyError {
    fn from(err: anyhow::Error) -> Self {
        ProxyError::GenericError {
            message: err.to_string(),
        }
    }
}

impl From<crate::sni::SniError> for ProxyError {
    fn from(err: crate::sni::SniError) -> Self {
        ProxyError::TlsError {
            message: err.to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, ProxyError>;

#[derive(Debug, Clone)]
struct ConnectionInfo {
    candidate_domains: Vec<String>,
    routing_domain: String,
    is_tls: bool,
    sni: Option<String>,
}

fn format_target(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') && !host.ends_with(']') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

fn determine_auth_methods(proxy: &Proxy) -> Vec<u8> {
    if proxy.auth.username.is_empty() && proxy.auth.pass.is_empty() {
        vec![SOCKS5_NO_AUTH]
    } else {
        vec![SOCKS5_USER_PASS_AUTH]
    }
}

async fn send_socks5_greeting(stream: &mut TcpStream, methods: &[u8]) -> anyhow::Result<()> {
    use tokio::io::{AsyncWriteExt};

    let mut greeting = vec![SOCKS5_VERSION, methods.len() as u8];
    greeting.extend(methods);
    stream.write_all(&greeting).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_method_selection(stream: &mut TcpStream) -> Result<u8> {
    use tokio::io::AsyncReadExt;

    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    debug!("SOCKS5 handshake: method selection received - version={}, method=0x{:02x}", buf[0], buf[1]);

    if buf[0] != SOCKS5_VERSION {
        return Err(ProxyError::Socks5Error {
            message: format!("SOCKS5 protocol error: invalid version (expected {}, got {})", SOCKS5_VERSION, buf[0])
        });
    }

    Ok(buf[1])
}

fn validate_selected_method(supported_methods: &[u8], selected_method: u8) -> Result<()> {
    if !supported_methods.contains(&selected_method) {
        return Err(ProxyError::Socks5Error {
            message: format!("Unsupported auth method: {}", selected_method)
        });
    }
    Ok(())
}

async fn perform_username_password_auth(stream: &mut TcpStream, proxy: &Proxy) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let username = proxy.auth.username.as_bytes();
    let password = proxy.auth.pass.as_bytes();
    let mut auth_msg = vec![SOCKS5_AUTH_VERSION, username.len() as u8];
    auth_msg.extend(username);
    auth_msg.push(password.len() as u8);
    auth_msg.extend(password);

    stream.write_all(&auth_msg).await?;
    stream.flush().await?;

    let mut auth_resp = [0u8; 2];
    stream.read_exact(&mut auth_resp).await?;
    if auth_resp[0] != SOCKS5_AUTH_VERSION || auth_resp[1] != 0 {
        return Err(ProxyError::Socks5Error {
            message: format!("SOCKS5 authentication failed: version={}, status={}", auth_resp[0], auth_resp[1])
        });
    }

    Ok(())
}

async fn send_connect_request(stream: &mut TcpStream, target_host: &str, target_port: u16) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let port_bytes = target_port.to_be_bytes();
    let mut connect_req = vec![SOCKS5_VERSION, SOCKS5_CONNECT_CMD, 0u8]; // VER, CMD, RSV

    // Add address based on type
    if let Ok(ip) = target_host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                connect_req.push(SOCKS5_ATYP_IPV4);
                connect_req.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                connect_req.push(SOCKS5_ATYP_IPV6);
                connect_req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        let domain_bytes = target_host.as_bytes();
        connect_req.push(SOCKS5_ATYP_DOMAIN);
        connect_req.push(domain_bytes.len() as u8);
        connect_req.extend_from_slice(domain_bytes);
    }

    connect_req.extend_from_slice(&port_bytes);

    debug!(
        "SOCKS5 CONNECT {} via proxy",
        format_target(target_host, target_port)
    );

    stream.write_all(&connect_req).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_connect_response(stream: &mut TcpStream) -> Result<()> {
    use tokio::io::AsyncReadExt;

    let mut resp_buf = [0u8; 4];
    stream.read_exact(&mut resp_buf).await?;

    if resp_buf[0] != SOCKS5_VERSION {
        return Err(ProxyError::Socks5Error {
            message: format!("Invalid SOCKS5 response version: expected {}, got {}", SOCKS5_VERSION, resp_buf[0])
        });
    }

    if resp_buf[1] != 0 {
        return Err(ProxyError::Socks5Error {
            message: format!("SOCKS5 CONNECT failed with code: {}", resp_buf[1])
        });
    }

    let atyp = resp_buf[3];
    match atyp {
        SOCKS5_ATYP_IPV4 => {
            stream.read_exact(&mut [0u8; 6]).await?; // IPv4 + port
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            stream.read_exact(&mut vec![0u8; len + 2]).await?; // domain + port
        }
        SOCKS5_ATYP_IPV6 => {
            stream.read_exact(&mut [0u8; 18]).await?; // IPv6 + port
        }
        _ => return Err(ProxyError::Socks5Error {
            message: format!("Unsupported address type in SOCKS5 response: {}", atyp)
        }),
    }

    Ok(())
}

async fn perform_socks5_handshake(stream: &mut TcpStream, proxy: &Proxy, target_host: &str, target_port: u16, _upstream_proxy_timeout: Duration) -> Result<()> {
    // SOCKS5 greeting
    let auth_methods = determine_auth_methods(proxy);
    send_socks5_greeting(stream, &auth_methods).await?;

    // Read method selection response
    let selected_method = read_method_selection(stream).await?;
    validate_selected_method(&auth_methods, selected_method)?;

    // Perform authentication if needed
    if selected_method == SOCKS5_USER_PASS_AUTH {
        perform_username_password_auth(stream, proxy).await?;
    }

    // Send CONNECT request
    send_connect_request(stream, target_host, target_port).await?;

    // Read CONNECT response
    read_connect_response(stream).await?;

    Ok(())
}

/// Establish or reuse a proxy connection with per-proxy connection limiting.
/// Returns both the TcpStream and the OwnedSemaphorePermit that must be held for the connection's lifetime.
async fn get_pooled_proxy_stream(proxy: &Proxy, target_host: &str, target_port: u16, upstream_proxy_timeout: Duration) -> Result<(TcpStream, OwnedSemaphorePermit)> {
    let proxy_addr = format!("{}:{}", proxy.server_addr, proxy.server_port);
    let proxy_key = ProxyKey {
        addr: proxy.server_addr.clone(),
        port: proxy.server_port,
        tag: proxy.tag.clone(),
    };

    // 1. Try to take an existing connection from the pool
    let mut to_try = Vec::new();
    if let Some(mut entry) = CONNECTION_POOL.get_mut(&proxy_key) {
        to_try = std::mem::take(entry.value_mut());
    }

    let mut found = None;
    let mut unused = Vec::new();

    for (mut stream, created, permit) in to_try {
        if found.is_none() && created.elapsed() < Duration::from_secs(CONNECTION_POOL_TIMEOUT_SECS) {
            // Verify connection is still alive with a quick peek (OUTSIDE lock).
            // A peek timeout (Err from outer timeout) means no data is buffered yet —
            // the connection is idle but alive (normal for SOCKS5 proxies waiting for
            // a client greeting). Only Ok(Ok(0)) (EOF / FIN from peer) or Ok(Err(_))
            // (socket error) indicate a genuinely dead connection.
            let is_live = match timeout(Duration::from_millis(50), stream.peek(&mut [0u8; 1])).await {
                Ok(Ok(0)) => false,  // EOF: remote closed the connection
                Ok(Err(_)) => false, // Socket error: connection is broken
                Ok(Ok(_)) => true,   // Unexpected data buffered: connection is live
                Err(_) => true,      // Timed out: no data yet, but connection is alive
            };
            if is_live {
                debug!("Reusing pooled connection for {} (tag: {})", proxy_addr, proxy.tag);
                found = Some((stream, permit));
                continue;
            }
        }
        // Either we found a connection, or this one is stale/dead.
        if found.is_some() {
            unused.push((stream, created, permit));
        } else {
            debug!("Closing dead/stale pooled connection for {}", proxy_addr);
            let _ = stream.shutdown().await;
        }
    }

    // Put back unused healthy connections
    if !unused.is_empty() {
        CONNECTION_POOL.entry(proxy_key.clone()).or_insert_with(Vec::new).extend(unused);
    }

    if let Some(res) = found {
        return Ok(res);
    }

    // 2. Acquire a new permit
    let permit = acquire_proxy_permit(&proxy_key)?;

    // 3. Circuit breaker check (fast-fail)
    if !crate::proxy_health::is_healthy(&proxy_addr) {
        warn!(
            "Proxy {} (tag: {}) unavailable (circuit breaker open), fast-failing for {}",
            proxy_addr, proxy.tag, format_target(target_host, target_port)
        );
        return Err(ProxyError::ProxyUnavailable { addr: proxy_addr });
    }

    // 4. Connect and handshake
    debug!("Creating new proxy connection to {} (timeout {:?})", proxy_addr, upstream_proxy_timeout);
    let mut stream = match timeout(upstream_proxy_timeout, connect_tcp_with_mark((proxy.server_addr.as_str(), proxy.server_port))).await {
        Ok(Ok(s)) => {
            if let Err(e) = configure_tcp_keepalive(&s, None, None, None) {
                debug!("Failed to set TCP keepalive on proxy connection: {}", e);
            }
            s
        }
        Ok(Err(e)) => {
            let err_msg = format!("connect error: {}", e);
            proxy_health::record_failure(&proxy_addr, &err_msg);
            warn!("Proxy {} connect failed: {}", proxy_addr, e);
            return Err(ProxyError::ConnectionTimeout { duration: upstream_proxy_timeout });
        }
        Err(_) => {
            let err_msg = format!("connect timeout ({}s)", upstream_proxy_timeout.as_secs());
            proxy_health::record_failure(&proxy_addr, &err_msg);
            warn!("Proxy {} connect timeout", proxy_addr);
            return Err(ProxyError::ConnectionTimeout { duration: upstream_proxy_timeout });
        }
    };

    match perform_socks5_handshake(&mut stream, proxy, target_host, target_port, upstream_proxy_timeout).await {
        Ok(()) => {
            proxy_health::record_success(&proxy_addr);
            Ok((stream, permit))
        }
        Err(e) => {
            let err_msg = format!("SOCKS5 handshake failed: {}", e);
            proxy_health::record_failure(&proxy_addr, &err_msg);
            Err(e)
        }
    }
}

/// Clean up stale connections from the pool for a specific key
fn cleanup_stale_connections(key: &ProxyKey) {
    if let Some(mut entry) = CONNECTION_POOL.get_mut(key) {
        let original_len = entry.len();
        entry.retain(|(_, created, _)| {
            created.elapsed() < Duration::from_secs(CONNECTION_POOL_TIMEOUT_SECS)
        });
        let cleaned = original_len - entry.len();
        if cleaned > 0 {
            debug!("Cleaned up {} stale connections for key {:?}", cleaned, key);
        }
    }
}

/// Maintain connection pool size by removing oldest connections if over limit
fn maintain_pool_size(key: &ProxyKey) {
    if let Some(mut entry) = CONNECTION_POOL.get_mut(key) {
        if entry.len() > MAX_CONNECTION_POOL_SIZE {
            let excess = entry.len() - MAX_CONNECTION_POOL_SIZE;
            entry.drain(0..excess); // Remove oldest connections
            debug!("Pool maintenance: removed {} excess connections for key {:?}", excess, key);
        }
    }
}

/// Clean up all stale connections across all proxy keys in the pool
pub fn cleanup_all_stale_connections() {
    let mut cleanup_count = 0;

    for entry in CONNECTION_POOL.iter() {
        let key = entry.key().clone();
        cleanup_stale_connections(&key);
        cleanup_count += 1;
    }

    debug!("Global pool cleanup: processed {} proxy keys", cleanup_count);
}

/// Get connection pool statistics for monitoring
pub fn get_pool_stats() -> std::collections::HashMap<String, usize> {
    let mut stats = std::collections::HashMap::new();

    for entry in CONNECTION_POOL.iter() {
        let key = entry.key();
        let connection_count = entry.value().len();
        stats.insert(format!("{}:{}:{}", key.addr, key.port, key.tag), connection_count);
    }

    stats
}

/// Background task to periodically clean up stale connections
pub async fn start_pool_cleanup_task() {
    use tokio::time::{interval, Duration};

    let mut interval = interval(Duration::from_secs(CONNECTION_POOL_TIMEOUT_SECS * 2));

    loop {
        interval.tick().await;
        cleanup_all_stale_connections();
    }
}

async fn gather_connection_info(
    inbound: &TcpStream,
    optional_domain: &Option<String>,
    original_dst: &SocketAddr,
) -> Result<ConnectionInfo> {

    let mut peek_buf = [0u8; PEEK_BUFFER_SIZE];
    // P1-1 FIX: Add timeout to peek to prevent slow-loris attacks
    let n = match timeout(Duration::from_secs(PEEK_TIMEOUT_SECS), inbound.peek(&mut peek_buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(ProxyError::IoError(e)),
        Err(_) => {
            debug!("Peek timeout ({}s) for dst {}, treating as non-TLS", PEEK_TIMEOUT_SECS, original_dst);
            0 // treat as empty peek — will fall through to IP-based routing
        }
    };
    let sni = if n > 0 { extract_sni(&peek_buf[..n])? } else { None };
    let is_tls = n > 0 && peek_buf[0] == 0x16;

    // Use SNI immediately for HTTPS if available, skip reverse DNS to speed up 80% traffic
    let mut candidate_domains = Vec::new();

    if is_tls {
        if let Some(sni_domain) = sni.as_ref() {
            debug!("SNI detection: domain='{}' for TLS connection", sni_domain);
            candidate_domains.push(sni_domain.clone());
        }
    }

    if let Some(ref reverse_domain) = optional_domain {
        if !reverse_domain.is_empty() && !candidate_domains.contains(reverse_domain) {
            debug!("DNS reverse lookup: domain='{}' added as candidate", reverse_domain);
            candidate_domains.push(reverse_domain.clone());
        }
    }

    let ip_candidate = original_dst.ip().to_string();
    if candidate_domains.is_empty() {
        debug!("Routing fallback: using IP '{}' as routing candidate", ip_candidate);
        candidate_domains.push(ip_candidate.clone());
    } else if !candidate_domains.contains(&ip_candidate) {
        debug!("Adding IP candidate '{}' for completeness", ip_candidate);
        candidate_domains.push(ip_candidate.clone());
    }

    // Use first candidate as routing domain
    let routing_domain = candidate_domains[0].clone();

    Ok(ConnectionInfo {
        candidate_domains,
        routing_domain,
        is_tls,
        sni,
    })
}

pub async fn handle_tcp_stream(
    inbound: TcpStream,
    original_dst: SocketAddr,
    rules: RuleEngine,
    optional_domain: Option<String>,
    upstream_proxy_timeout: Duration,
    context_enabled: bool,
    context_ttl: Duration,
) -> Result<()> {
    let client_addr = inbound.peer_addr().ok();
    let client_label = client_addr
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| "<unknown>".to_string());
    debug!(
        "Incoming TCP connection: client={} -> dst={}",
        client_label, original_dst
    );

    let client_ip = client_addr.map(|addr| addr.ip());
    let client_ip_str = client_ip.map(|ip| ip.to_string());

    let connection_info = gather_connection_info(&inbound, &optional_domain, &original_dst).await?;

    // DNS ports: always direct (bypass routing).
    if original_dst.port() == 53 || original_dst.port() == 853 {
        debug!("DNS port detected ({}), using direct connection", original_dst.port());
        let out = connect_tcp_with_mark(original_dst).await?;
        return forward(inbound, out, None).await;
    }

    // ── Routing decision ─────────────────────────────────────────────────
    let mut context_proxy_tag = None;
    if context_enabled && client_ip_str.is_some() {
        let cip_str = client_ip_str.as_ref().unwrap();
        context_proxy_tag = crate::client_context::get_cached_proxy_tag(cip_str, &connection_info.routing_domain, context_ttl);
        if let Some(ref tag) = context_proxy_tag {
            debug!("Context cache hit: forcing proxy tag '{}' for client IP '{}' and domain '{}'", tag, cip_str, connection_info.routing_domain);
        }
    }

    let mut routing_decision = None;
    let mut matched_tag = None;

    // Context cache has highest priority.
    if let Some(tag) = &context_proxy_tag {
        if let Some(proxy) = rules.get_proxy_by_tag(tag) {
            routing_decision = Some(RoutingDecision::Proxy(proxy.clone()));
            matched_tag = Some(tag.clone());
            debug!("Context priority: using cached proxy '{}' for client IP '{}', skipping rule lookup", tag, client_ip_str.as_ref().unwrap());
        } else {
            debug!("Context cache contains invalid proxy tag '{}' for client IP '{}'", tag, client_ip_str.as_ref().unwrap());
            context_proxy_tag = None;
        }
    }

    // Rule lookup.
    if routing_decision.is_none() {
        for domain in &connection_info.candidate_domains {
            debug!("Routing lookup: checking domain='{}'", domain);
            let decision = if connection_info.is_tls && connection_info.sni.as_ref() == Some(domain) {
                rules.get_sni_routing_decision_async(domain, original_dst.port()).await
            } else {
                rules.get_routing_decision(domain)
            };
            if let Some(dec) = decision {
                routing_decision = Some(dec.clone());
                if let RoutingDecision::Proxy(ref p) = dec {
                    matched_tag = Some(p.tag.clone());
                }
                debug!("Routing match: domain='{}' -> decision={:?}", domain, dec);
                break;
            }
        }
    }

    // No rule matched → use default proxy (NO fallback to direct).
    if routing_decision.is_none() {
        if let Some(default_proxy) = rules.get_proxy_by_tag("default") {
            debug!("No rule match for '{}', using default proxy {}:{} (tag: {})",
                   connection_info.routing_domain, default_proxy.server_addr, default_proxy.server_port, default_proxy.tag);
            routing_decision = Some(RoutingDecision::Proxy(default_proxy.clone()));
            matched_tag = Some(default_proxy.tag.clone());
        } else {
            debug!("No default proxy and no rule for '{}', falling back to direct", connection_info.routing_domain);
            routing_decision = Some(RoutingDecision::Direct);
        }
    }

    debug!("Final routing for '{}' (tag: {:?}) -> {:?}",
           connection_info.routing_domain, matched_tag, routing_decision);

    // ── Execute routing decision (NO FALLBACK) ───────────────────────────
    match routing_decision {
        Some(RoutingDecision::Proxy(proxy)) => {
            let target_port = original_dst.port();
            let target_display = format_target(&connection_info.routing_domain, target_port);

            // Connect via proxy — no fallback to direct or other proxy.
            let (out, permit) = get_pooled_proxy_stream(&proxy, &connection_info.routing_domain, target_port, upstream_proxy_timeout).await?;

            // Cache successful proxy decision.
            if context_enabled && context_proxy_tag.is_none() {
                if let Some(cip_str) = &client_ip_str {
                    crate::client_context::set_cached_proxy_tag(cip_str, &connection_info.routing_domain, &proxy.tag);
                }
            }

            forward(inbound, out, Some(permit)).await
        }
        Some(RoutingDecision::Direct) | None => {
            debug!("Direct connection to {} for '{}'", original_dst, connection_info.routing_domain);
            let out = connect_tcp_with_mark(original_dst).await?;
            forward(inbound, out, None).await
        }
    }
}

/// Classify whether an IO error is a normal data-plane event
/// (peer disconnect, broken pipe, connection reset) rather than a real infrastructure error.
/// Data-plane errors are expected during proxy forwarding and should be logged at debug level.
pub fn is_data_plane_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset     // ECONNRESET (104) — peer sent RST
        | std::io::ErrorKind::BrokenPipe        // EPIPE (32) — write to closed socket
        | std::io::ErrorKind::ConnectionAborted  // ECONNABORTED (103) — connection aborted
        | std::io::ErrorKind::NotConnected       // ENOTCONN (107) — socket not connected
        | std::io::ErrorKind::UnexpectedEof      // EOF during read — peer closed gracefully
    )
}

async fn forward(a: TcpStream, b: TcpStream, _permit: Option<OwnedSemaphorePermit>) -> Result<()> {
    let (mut ar, mut aw) = a.into_split();
    let (mut br, mut bw) = b.into_split();

    // Spawn copy tasks with explicit shutdown(Write) for proper half-close
    let a_to_b = tokio::spawn(async move {
        let res = tokio::io::copy(&mut ar, &mut bw).await;
        // Explicitly shutdown write half to send FIN to peer
        let _ = bw.shutdown().await;
        res
    });

    let b_to_a = tokio::spawn(async move {
        let res = tokio::io::copy(&mut br, &mut aw).await;
        // Explicitly shutdown write half to send FIN to peer
        let _ = aw.shutdown().await;
        res
    });

    // P0-1 FIX: Obtain AbortHandles BEFORE moving JoinHandles into select!.
    // Previously, JoinHandles were moved into a timeout() closure, so dropping them
    // on timeout only *detached* the tasks (they ran as zombies forever).
    // Now we explicitly .abort() via AbortHandle when the lifetime timer fires.
    let a_abort = a_to_b.abort_handle();
    let b_abort = b_to_a.abort_handle();
    let max_lifetime = Duration::from_secs(MAX_CONNECTION_LIFETIME_SECS);

    tokio::select! {
        (r1, r2) = async { tokio::join!(a_to_b, b_to_a) } => {
            // Both directions completed within lifetime — normal path
            let err1 = match r1 {
                Ok(Ok(_bytes)) => None,
                Ok(Err(e)) => Some(e),
                Err(e) => return Err(ProxyError::GenericError { message: format!("Forwarding task panicked: {}", e) }),
            };
            let err2 = match r2 {
                Ok(Ok(_bytes)) => None,
                Ok(Err(e)) => Some(e),
                Err(e) => return Err(ProxyError::GenericError { message: format!("Forwarding task panicked: {}", e) }),
            };

            // Classify errors: data-plane errors (ECONNRESET, EPIPE) are normal and swallowed.
            // Only real infrastructure errors are propagated.
            match (err1, err2) {
                (None, None) => Ok(()),
                (Some(e), None) | (None, Some(e)) => {
                    if is_data_plane_error(&e) {
                        debug!("Stream forwarding ended (peer disconnect): {}", e);
                        Ok(())
                    } else {
                        Err(ProxyError::IoError(e))
                    }
                }
                (Some(e1), Some(e2)) => {
                    let e1_data = is_data_plane_error(&e1);
                    let e2_data = is_data_plane_error(&e2);
                    match (e1_data, e2_data) {
                        (true, true) => {
                            debug!("Stream forwarding ended (both sides disconnected): {} / {}", e1, e2);
                            Ok(())
                        }
                        (false, _) => Err(ProxyError::IoError(e1)),
                        (_, false) => Err(ProxyError::IoError(e2)),
                    }
                }
            }
        }
        _ = tokio::time::sleep(max_lifetime) => {
            // P0-1 FIX: Explicitly abort both spawned tasks via AbortHandle to prevent zombie task leak.
            // Previously, dropping JoinHandles only detached tasks — they ran forever
            // if the remote peer never closed the connection.
            a_abort.abort();
            b_abort.abort();
            debug!("Connection exceeded max lifetime ({}s), tasks aborted", MAX_CONNECTION_LIFETIME_SECS);
            Ok(())
        }
    }
}

pub async fn handle_socks5_handshake(stream: &mut tokio::net::TcpStream) -> anyhow::Result<(SocketAddr, Option<String>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use crate::dns_pool::DNS_POOL;

    let mut buf = [0u8; 256];

    // Read SOCKS5 greeting
    stream.read_exact(&mut buf[..2]).await?;
    if buf[0] != 5 {
        return Err(anyhow::anyhow!("Only SOCKS5 supported"));
    }
    let nmethods = buf[1] as usize;
    stream.read_exact(&mut buf[..nmethods]).await?;
    if !buf[..nmethods].contains(&0) {
        return Err(anyhow::anyhow!("No method 0x00 support requested"));
    }

    // Send our choice: method 0x00
    stream.write_all(&[5, 0]).await?;

    // Read SOCKS5 request
    stream.read_exact(&mut buf[..4]).await?;
    if buf[0] != 5 || buf[1] != 1 {
        return Err(anyhow::anyhow!("Only CONNECT command supported"));
    }
    let atyp = buf[3];

    let target = match atyp {
        1 => { // IPv4
            stream.read_exact(&mut buf[..6]).await?;
            let ip = std::net::Ipv4Addr::from([buf[0], buf[1], buf[2], buf[3]]);
            let port = ((buf[4] as u16) << 8) | buf[5] as u16;
            (SocketAddr::new(std::net::IpAddr::V4(ip), port), None)
        }
        3 => { // Domain name
            stream.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            stream.read_exact(&mut buf[..len + 2]).await?;
            let domain = std::string::String::from_utf8_lossy(&buf[..len]).to_string();
            let port = ((buf[len] as u16) << 8) | buf[len + 1] as u16;
            let resolver = DNS_POOL.get_resolver().await;
            let response = timeout(
                Duration::from_secs(10),
                resolver.lookup_ip(domain.clone()),
            )
            .await
            .map_err(|_| anyhow::anyhow!("DNS lookup timed out for domain: {}", domain))??;
            let ip_addr = response.iter().next().ok_or(anyhow::anyhow!("No IP found for domain"))?;
            let target_addr = SocketAddr::new(ip_addr, port);
            (target_addr, Some(domain))
        }
        _ => return Err(anyhow::anyhow!("Unsupported address type")),
    };

    // Send success response
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(target)
}

/// Configure TCP keepalive on a proxy connection to detect dead connections proactively.
///
/// Without keepalive, a silently-dropped connection (firewall timeout, server restart)
/// sits in the pool and only fails when a user request tries to use it.
/// With keepalive, the kernel detects the dead connection and marks the socket as error,
/// so the next pool peek() check discards it automatically.
pub fn configure_tcp_keepalive(
    stream: &TcpStream,
    keepalive_time: Option<Duration>,
    keepalive_interval: Option<Duration>,
    keepalive_retries: Option<u32>,
) -> std::io::Result<()> {
    let config = get_keepalive_config();
    let sock_ref = socket2::SockRef::from(stream);
    let mut keepalive = socket2::TcpKeepalive::new()
        .with_time(keepalive_time.unwrap_or(config.time))
        .with_interval(keepalive_interval.unwrap_or(config.interval));

    if let Some(retries) = keepalive_retries {
        keepalive = keepalive.with_retries(retries);
    } else {
        keepalive = keepalive.with_retries(config.retries);
    }

    sock_ref.set_tcp_keepalive(&keepalive)
}

/// Pre-establish connections to a proxy when it recovers from a circuit breaker trip.
///
/// When a proxy recovers, the connection pool is empty. The first wave of user
/// connections all need fresh SOCKS5 handshakes (~200-500ms each), causing a visible
/// latency spike. This function pre-warms the pool by establishing POOL_WARMUP_SIZE
/// TCP connections to the proxy.
///
/// NOTE: Only TCP connections are pre-established (no SOCKS5 handshake), since we don't
/// know which target hosts will be requested. The SOCKS5 handshake is target-specific.
pub async fn warmup_connection_pool(proxy: &Proxy, upstream_proxy_timeout: Duration) {
    let proxy_addr = format!("{}:{}", proxy.server_addr, proxy.server_port);
    let key = ProxyKey {
        addr: proxy.server_addr.clone(),
        port: proxy.server_port,
        tag: proxy.tag.clone(),
    };

    info!(
        "Pool warmup: pre-establishing {} connections to recovered proxy {} (tag: {})",
        POOL_WARMUP_SIZE, proxy_addr, proxy.tag
    );

    let mut established = 0usize;
    for i in 0..POOL_WARMUP_SIZE {
        // Only warm up if we can get a permit
        let permit = match acquire_proxy_permit(&key) {
            Ok(p) => p,
            Err(_) => {
                debug!("Pool warmup: skipping connection {} for {} - limit reached", i, proxy_addr);
                break;
            }
        };

        match timeout(upstream_proxy_timeout, connect_tcp_with_mark((&*proxy.server_addr, proxy.server_port))).await {
            Ok(Ok(stream)) => {
                if let Err(e) = configure_tcp_keepalive(&stream, None, None, None) {
                    debug!("Pool warmup: failed to set keepalive on connection {}: {}", i, e);
                }
                CONNECTION_POOL.entry(key.clone()).or_insert_with(Vec::new)
                    .push((stream, Instant::now(), permit));
                established += 1;
            }
            Ok(Err(e)) => {
                debug!("Pool warmup: connection {} to {} failed: {}", i, proxy_addr, e);
                break; // Don't keep trying if one fails
            }
            Err(_) => {
                debug!("Pool warmup: connection {} to {} timed out", i, proxy_addr);
                break;
            }
        }
    }

    if established > 0 {
        info!(
            "Pool warmup: established {}/{} connections to proxy {} (tag: {})",
            established, POOL_WARMUP_SIZE, proxy_addr, proxy.tag
        );
    }
}

#[cfg(test)]
mod tests {
    use super::format_target;

    #[test]
    fn format_target_ipv4() {
        assert_eq!(format_target("192.0.2.1", 8080), "192.0.2.1:8080");
    }

    #[test]
    fn format_target_ipv6() {
        assert_eq!(format_target("2001:db8::1", 443), "[2001:db8::1]:443");
    }

    #[test]
    fn format_target_domain() {
        assert_eq!(format_target("example.com", 80), "example.com:80");
    }
}