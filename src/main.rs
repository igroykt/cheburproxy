//! CheburProxy - A high-performance transparent and SOCKS5 proxy server
//!
//! This proxy supports both transparent proxying and SOCKS5 protocol with advanced
//! routing capabilities, DNS caching, and UDP relay functionality.

use std::env;
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant};
use toml::Value;
use log::{debug, error, info, warn};
use tokio::signal::unix::{signal, SignalKind};
use arc_swap::ArcSwap;

mod tproxy_health;
mod router;
mod proxy;
mod proxy_health;
mod rule;
mod transparent;
mod udp_proxy;
mod sni;
mod dns_protocols;  // NEW: DNS protocol handlers (Plain, DoT, DoH, SOCKS5)
mod dns_resolver;   // NEW: Internal DNS resolver
mod dns_proxy;      // NEW: DNS proxy server for LAN clients
mod client_context;
pub mod udp_tunnel_frame;  // UDP-over-TCP tunnel framing protocol

use crate::dns_resolver::{DnsResolverConfig, InternalDnsResolver, DnsProtocol};
use crate::dns_protocols::DnsError;
use crate::dns_proxy::{DnsProxy, DnsProxyConfig};
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::OwnedSemaphorePermit;
use thiserror::Error;

use crate::router::load_config;
use crate::proxy::handle_tcp_stream;
use crate::rule::{RuleEngine, RuleEngineConfig};
use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use std::net::IpAddr;

static ACCEPTED_CONNS_COUNTER: AtomicU64 = AtomicU64::new(0);
static ZERO_TRAFFIC_STREAK: AtomicU32 = AtomicU32::new(0);
use crate::transparent::{get_original_dst, create_transparent_tcp_socket_default};
use crate::udp_proxy::{run_udp_proxy, Config, handle_udp_packet, SessionKey, UdpSession};
// use crate::dns_proxy::run_dns_proxy;  // Removed - unstable
use crate::sni::extract_sni;
use std::net::SocketAddr;

// Configuration constants
const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0";
const DEFAULT_PORT: u16 = 12345;
const DEFAULT_DNS_PORT: u16 = 53;
const DEFAULT_MODE: &str = "transparent";
const DEFAULT_UPSTREAM_TIMEOUT_SECS: u64 = 10;

// Connection limit to prevent resource exhaustion under high load
const MAX_CONCURRENT_TCP_CONNECTIONS: usize = 10_000;

// UDP task limit to prevent memory exhaustion under a UDP flood (H2 fix)
const MAX_CONCURRENT_UDP_TASKS: usize = 4096;

// Timeout for initial peek (prevents slow-loris)
const PEEK_TIMEOUT_SECS: u64 = 10;

// DNS and caching constants
const DNS_CACHE_TTL_SECS: u64 = 3600; // 1 hour
const DNS_CACHE_FAILURE_TTL_SECS: u64 = 60; // 1 minute for failures
const DNS_REVERSE_LOOKUP_TIMEOUT_MS: u64 = 200;
const DNS_FORWARD_LOOKUP_TIMEOUT_MS: u64 = 100;
const DNS_NAMESERVER_IP: &str = "8.8.8.8";

// Connection pool constants
const CONNECTION_POOL_CLEANUP_INTERVAL_SECS: u64 = 60;
const MAX_CONNECTIONS_PER_PROXY: usize = 5;
const CONNECTION_TTL_SECS: u64 = 60;

// Domain cache constants
const DOMAIN_CACHE_TTL_SECS: u64 = 3600; // 1 hour for UDP relay
const DOMAIN_CACHE_CLEANUP_INTERVAL_SECS: u64 = 1800; // 30 minutes

// Buffer and packet constants
const SOCKS5_BUFFER_SIZE: usize = 256;
const PEEK_BUFFER_SIZE: usize = 8192;
const UDP_PACKET_BUFFER_SIZE: usize = 65536;
const MAX_EXACT_DOMAINS_TO_CHECK: usize = 5;

// SOCKS5 protocol constants
const SOCKS5_VERSION: u8 = 5;
const SOCKS5_NO_AUTH: u8 = 0;
const SOCKS5_CONNECT_CMD: u8 = 1;
const SOCKS5_SUCCESS: u8 = 0;
const SOCKS5_IPV4_ATYP: u8 = 1;
const SOCKS5_DOMAIN_ATYP: u8 = 3;
const SOCKS5_FRAGMENT_ZERO: u8 = 0;

/// DNS cache entry with metadata
#[derive(Clone)]
struct DnsCacheEntry {
    /// Resolved IP address (None if resolution failed)
    ip: Option<std::net::IpAddr>,
    /// Timestamp of when this entry was created
    timestamp: Instant,
    /// Domain name for this entry
    domain: Option<String>,
}

type DnsCache = Arc<DashMap<String, DnsCacheEntry>>;

/// Domain cache for UDP relay (IP->Domain mapping)
type DomainCache = Arc<DashMap<IpAddr, (String, Instant)>>;

/// Application configuration structure
#[derive(Debug, Clone)]
struct AppConfig {
    listen: String,
    port: u16,
    mode: String,
    dns_enabled: bool,
    dns_listen_port: u16,
    udp_port: u16,
    udp_desync_enabled: bool,
    udp_desync_min_size: usize,
    udp_desync_max_size: usize,
    upstream_proxy_timeout: Duration,
    tcp_keepalive_time: Duration,
    tcp_keepalive_interval: Duration,
    tcp_keepalive_retries: u32,
}

// Shared state for hot-reloadable configuration (lock-free reads via ArcSwap)
type SharedRuleEngine = Arc<ArcSwap<RuleEngine>>;

/// Custom error types for better error handling
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("SOCKS5 error: {0}")]
    Socks5(String),
    #[error("Config error: {0}")]
    Config(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("Only SOCKS5 supported, got version: {0}")]
    UnsupportedVersion(u8),
    #[error("No authentication method supported")]
    NoAuthMethod,
    #[error("Only CONNECT command supported, got: {0}")]
    UnsupportedCommand(u8),
    #[error("Unsupported address type: {0}")]
    UnsupportedAddressType(u8),
    #[error("No IP found for domain")]
    NoIpForDomain,
    #[error("DNS resolution failed: {0}")]
    DnsError(#[from] DnsError),
    #[error("Router configuration error: {0}")]
    Router(String),
    #[error("Domain resolution error: {0}")]
    DomainResolution(String),
}


/// Attempt to resolve an IP address back to a domain name using reverse DNS lookup
/// and fall back to forward DNS lookup against known domains if necessary
async fn resolve_domain_from_ip(
    ip: std::net::IpAddr,
    rules: &RuleEngine,
    dns_cache: &DnsCache,
    resolver: Arc<InternalDnsResolver>,
) -> anyhow::Result<String> {
    use std::time::Instant;
    let start_time = Instant::now();

    // Try reverse DNS first with timeout
    match tokio::time::timeout(Duration::from_millis(200), resolver.reverse_resolve(ip)).await {
        Ok(Ok(domain)) => {
            let domain = domain.trim_end_matches('.').to_string();
            debug!("Reverse DNS resolved IP {} to domain: {} ({}ms)",
                  ip, domain, start_time.elapsed().as_millis());

            // Check if the resolved domain matches any rule
            if rules.get_routing_decision(&domain).is_some() {
                return Ok(domain);
            }
            debug!("Reverse DNS domain {} does not match any rules", domain);
        }
        Ok(Err(e)) => {
            debug!("Reverse DNS lookup for IP {} failed: {}", ip, e);
        }
        Err(_) => {
            debug!("Reverse DNS lookup for IP {} timed out", ip);
        }
    }

    // P2-9 FIX: Use join_all instead of unbounded tokio::spawn for forward DNS lookups.
    // Previously, up to 5 tokio::spawn tasks were created per transparent connection
    // without SNI. Under high load with many non-TLS connections, this caused
    // unbounded task spawning. join_all runs futures concurrently on the current task
    // without creating new tokio tasks.
    let top_level_domains: Vec<String> = rules.get_top_level_domains();
    let domains_to_check = top_level_domains.into_iter().take(5).collect::<Vec<_>>();

    let lookup_futures: Vec<_> = domains_to_check.into_iter().map(|rule_domain| {
        let resolver_clone = resolver.clone();
        let dns_cache_clone = dns_cache.clone();
        async move {
            // Check DNS cache first
            if let Some(cached) = dns_cache_clone.get(&rule_domain) {
                if let Some(cached_ip) = cached.ip {
                    if cached_ip == ip && cached.timestamp.elapsed() < Duration::from_secs(3600) {
                        debug!("DNS cache hit for {} -> {} ({}ms)",
                            rule_domain, ip, start_time.elapsed().as_millis());
                        return Some(rule_domain);
                    }
                } else if cached.timestamp.elapsed() < Duration::from_secs(60) {
                    debug!("DNS cache failure hit for {} ({}ms)", rule_domain, start_time.elapsed().as_millis());
                    return None;
                }
            }

            // Ретри за доменным именем для логирования/правил (на горячем пути)
            match tokio::time::timeout(Duration::from_millis(100), resolver_clone.resolve_first(&rule_domain)).await {
                Ok(Ok(response)) => {
                    if response == ip {
                        dns_cache_clone.insert(rule_domain.clone(), DnsCacheEntry {
                            ip: Some(ip),
                            timestamp: Instant::now(),
                            domain: Some(rule_domain.clone()),
                        });
                        debug!("Forward DNS lookup matched IP {} to domain {} ({}ms)",
                            ip, rule_domain, start_time.elapsed().as_millis());
                        return Some(rule_domain);
                    }
                }
                Ok(Err(e)) => {
                    debug!("Forward DNS lookup for {} failed: {}", rule_domain, e);
                    dns_cache_clone.insert(rule_domain.clone(), DnsCacheEntry {
                        ip: None,
                        timestamp: Instant::now(),
                        domain: None,
                    });
                }
                Err(_) => {
                    debug!("Forward DNS lookup for {} timed out", rule_domain);
                    dns_cache_clone.insert(rule_domain.clone(), DnsCacheEntry {
                        ip: None,
                        timestamp: Instant::now(),
                        domain: None,
                    });
                }
            }
            None
        }
    }).collect();

    let results = futures::future::join_all(lookup_futures).await;
    for result in results {
        if let Some(domain) = result {
            debug!("Found matching domain for IP {}: {} ({}ms)", ip, domain, start_time.elapsed().as_millis());
            return Ok(domain);
        }
    }

    debug!("No matching domain found for IP: {} ({}ms)", ip, start_time.elapsed().as_millis());
    Err(anyhow::anyhow!("No matching domain found for IP: {}", ip))
}

/// Поиск домена по IP адресу в кэше TCP соединений (UDP relay)
pub async fn find_domain_by_ip(ip: std::net::IpAddr, domain_cache: &DomainCache) -> Option<String> {
    if let Some(cached) = domain_cache.get(&ip) {
        if cached.1.elapsed() < Duration::from_secs(3600) { // 1 час актуальности
            debug!("Domain cache hit: {} -> {}", ip, cached.0);
            return Some(cached.0.clone());
        }
    }
    None
}


/// SOCKS5 UDP packet handler with improved error handling and performance
async fn run_socks5_udp_handler(
    socket: tokio::net::UdpSocket,
    rule_engine: RuleEngine,
    config: Arc<udp_proxy::Config>,
    domain_cache: DomainCache,
    upstream_proxy_timeout: Duration,
    resolver: Arc<InternalDnsResolver>,
) -> Result<(), ProxyError> {
    let socket = Arc::new(socket);
    let sessions: Arc<DashMap<SessionKey, Arc<UdpSession>>> = Arc::new(DashMap::new());
    let mut buf = [0u8; UDP_PACKET_BUFFER_SIZE];

    // PHASE 1 FIX: Create shared transparent UDP sender for SOCKS5 mode
    let transparent_sender = udp_proxy::TransparentUdpSender::new()
        .map_err(|e| ProxyError::Config(format!("Failed to create TransparentUdpSender: {}", e)))?;

    // H2 FIX: Semaphore to bound concurrent UDP processing tasks and prevent
    // memory/FD exhaustion under a UDP flood (try_acquire_owned drops packet if full).
    let udp_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_UDP_TASKS));

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((size, client_addr)) => {
                if let Err(e) = process_udp_packet(
                    &buf[..size],
                    size,
                    client_addr,
                    &rule_engine,
                    &sessions,
                    &config,
                    &domain_cache,
                    upstream_proxy_timeout,
                    transparent_sender.clone(),
                    &udp_semaphore,
                    resolver.clone(),
                ).await {
                    debug!("Error processing UDP packet from {}: {}", client_addr, e);
                }
            }
            Err(e) => {
                debug!("Error receiving UDP packet: {}", e);
            }
        }
    }
}

/// Process a single UDP packet with validation and parsing
async fn process_udp_packet(
    packet: &[u8],
    size: usize,
    client_addr: SocketAddr,
    rule_engine: &RuleEngine,
    sessions: &Arc<DashMap<SessionKey, Arc<UdpSession>>>,
    config: &Config,
    domain_cache: &DomainCache,
    timeout: Duration,
    transparent_sender: Arc<udp_proxy::TransparentUdpSender>,
    udp_semaphore: &Arc<tokio::sync::Semaphore>,
    resolver: Arc<InternalDnsResolver>,
) -> Result<(), ProxyError> {
    // Validate packet size and SOCKS5 header
    validate_socks5_udp_packet(packet, size)?;

    let atype = packet[3];
    let (target_addr, payload_start) = parse_udp_target_address(packet, size, atype, resolver).await?;

    let payload = packet[payload_start..size].to_vec();

    // H2 FIX: Acquire a semaphore permit before spawning to bound concurrency.
    // If the limit is reached, log a warning and drop this packet (acceptable for UDP).
    let permit = match udp_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            warn!("UDP task limit reached ({}), dropping packet from {}", MAX_CONCURRENT_UDP_TASKS, client_addr);
            return Ok(());
        }
    };

    // Spawn handler for this packet
    let rules_cloned = rule_engine.clone();
    let sessions_cloned = sessions.clone();
    let config_cloned = config.clone();
    let domain_cache_cloned = domain_cache.clone();

    tokio::spawn(async move {
        let _permit = permit; // hold permit for the lifetime of the task; released on drop
        if let Err(e) = handle_udp_packet(
            client_addr,
            target_addr,
            payload,
            rules_cloned,
            sessions_cloned,
            Arc::new(config_cloned),
            domain_cache_cloned,
            timeout,
            transparent_sender,
        ).await {
            debug!("Error processing UDP packet from {} to {}: {}", client_addr, target_addr, e);
        }
    });

    Ok(())
}

/// Validate SOCKS5 UDP packet format
fn validate_socks5_udp_packet(packet: &[u8], size: usize) -> Result<(), ProxyError> {
    if size < 10 {
        return Err(ProxyError::Socks5("Packet too small".to_string()));
    }

    // Validate SOCKS5 UDP header (RSV + FRAG + ATYP)
    if packet[0] != 0x00 || packet[1] != 0x00 {
        return Err(ProxyError::Socks5("Invalid SOCKS5 UDP header".to_string()));
    }

    if packet[2] != SOCKS5_FRAGMENT_ZERO {
        return Err(ProxyError::Socks5("Fragmentation not supported".to_string()));
    }

    Ok(())
}

/// Parse target address from UDP packet
async fn parse_udp_target_address(
    packet: &[u8],
    size: usize,
    atyp: u8,
    resolver: Arc<InternalDnsResolver>,
) -> Result<(SocketAddr, usize), ProxyError> {
    match atyp {
        SOCKS5_IPV4_ATYP => {
            if size < 10 {
                return Err(ProxyError::Socks5("IPv4 packet too small".to_string()));
            }
            let ip = std::net::Ipv4Addr::from([packet[4], packet[5], packet[6], packet[7]]);
            let port = u16::from_be_bytes([packet[8], packet[9]]);
            Ok((SocketAddr::from((ip, port)), 10))
        }
        SOCKS5_DOMAIN_ATYP => {
            if size < 7 {
                return Err(ProxyError::Socks5("Domain packet too small".to_string()));
            }

            let domain_len = packet[4] as usize;
            let domain_end = 5 + domain_len;

            if domain_end + 2 > size {
                return Err(ProxyError::Socks5("Domain packet truncated".to_string()));
            }

            let domain = String::from_utf8_lossy(&packet[5..domain_end]);
            let port = u16::from_be_bytes([packet[domain_end], packet[domain_end + 1]]);

            let ip = resolver.resolve_first(&domain).await
                .map_err(|e| ProxyError::Socks5(format!("Domain resolution failed: {}", e)))?;

            Ok((SocketAddr::new(ip, port), domain_end + 2))
        }
        _ => Err(ProxyError::Socks5(format!("Unsupported address type: {}", atyp))),
    }
}

/// Reload router configuration from router.json (preserving GeoIP/GeoSite databases)
async fn reload_router_config_with_static_geodata(
    rule_engine_config: &RuleEngineConfig,
    geoip_countries: Arc<std::collections::HashMap<String, Vec<crate::rule::CidrBlock>>>,
    geosite_categories: Arc<std::collections::HashMap<String, crate::rule::OptimizedGeoSite>>,
    resolver: Arc<InternalDnsResolver>,
) -> anyhow::Result<RuleEngine> {
    info!("Reloading router configuration from router.json (preserving GeoIP/GeoSite databases in memory)");
    let router = load_config("router.json").await?;
    let rule_engine = RuleEngine::from_config_with_shared_geodata(
        router,
        rule_engine_config.clone(),
        geoip_countries,
        geosite_categories,
        resolver,
    )?;
    info!("Router configuration reloaded successfully (GeoIP/GeoSite databases preserved - memory optimized)");
    Ok(rule_engine)
}

/// Reload function kept for reference
async fn reload_router_config(_rule_engine_config: &RuleEngineConfig, _resolver: Arc<InternalDnsResolver>) -> anyhow::Result<RuleEngine> {
    let router = load_config("router.json").await?;
    RuleEngine::from_config(router, _resolver)
}

/// Establish UDP associate with upstream proxy
async fn establish_udp_associate(proxy: &crate::router::Proxy, timeout: Duration) -> Result<SocketAddr, ProxyError> {
    let mut stream = TcpStream::connect((proxy.server_addr.as_str(), proxy.server_port)).await
        .map_err(ProxyError::Io)?;

    // SOCKS5 greeting
    let auth_methods = if proxy.auth.username.is_empty() && proxy.auth.pass.is_empty() {
        vec![0] // NO_AUTH
    } else {
        vec![0, 2] // NO_AUTH, USERNAME_PASSWORD
    };
    let mut greeting = vec![5, auth_methods.len() as u8];
    greeting.extend(auth_methods);
    stream.write_all(&greeting).await?;

    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp).await?;
    if method_resp[0] != 5 {
        return Err(ProxyError::Socks5("Invalid SOCKS5 response".to_string()));
    }
    let selected_method = method_resp[1];

    // Authenticate if needed
    if selected_method == 2 {
        let username = proxy.auth.username.as_bytes();
        let password = proxy.auth.pass.as_bytes();
        let mut auth_msg = vec![1, username.len() as u8];
        auth_msg.extend(username);
        auth_msg.push(password.len() as u8);
        auth_msg.extend(password);
        stream.write_all(&auth_msg).await?;

        let mut auth_resp = [0u8; 2];
        stream.read_exact(&mut auth_resp).await?;
        if auth_resp[0] != 1 || auth_resp[1] != 0 {
            return Err(ProxyError::Socks5("Authentication failed".to_string()));
        }
    } else if selected_method != 0 {
        return Err(ProxyError::Socks5("Unsupported auth method".to_string()));
    }

    // Send UDP associate request
    let associate_req = [5u8, 3, 0, 1, 0, 0, 0, 0, 0, 0]; // CMD=3, ATYP=1, DST=0.0.0.0:0
    stream.write_all(&associate_req).await?;

    // Read response
    let mut resp = [0u8; 10];
    stream.read_exact(&mut resp).await?;
    if resp[0] == 5 && resp[1] == 0 {
        let ip = std::net::Ipv4Addr::from([resp[4], resp[5], resp[6], resp[7]]);
        let port = ((resp[8] as u16) << 8) | resp[9] as u16;
        let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);

        // Keep the TCP connection alive in background
        // P0-2 FIX: Add idle timeout to prevent permanent leak if proxy server hangs.
        // Previously, this task ran forever if the SOCKS5 server never closed the connection.
        tokio::spawn(async move {
            let mut buf = [0u8; 1];
            loop {
                match tokio::time::timeout(Duration::from_secs(300), stream.read(&mut buf)).await {
                    Ok(Ok(0)) | Ok(Err(_)) => break,  // EOF or error — connection closed
                    Ok(Ok(_)) => continue,              // got data — keep reading
                    Err(_) => break,                    // 5min idle timeout — close stale connection
                }
            }
            debug!("UDP ASSOCIATE TCP control connection closed");
        });

        Ok(addr)
    } else {
        Err(ProxyError::Socks5("UDP associate failed".to_string()))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut config_path = "config.toml";
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                if i + 1 < args.len() {
                    config_path = &args[i + 1];
                    i += 2;
                } else {
                    error!("-c requires a value");
                    process::exit(1);
                }
            }
            _ => {
                error!("Unknown argument: {}", args[i]);
                process::exit(1);
            }
        }
    }

    env_logger::builder().filter_level(log::LevelFilter::Info).init();

    let parsed = match std::fs::read_to_string(config_path)
        .map_err(|e| anyhow::anyhow!("Failed to read config file '{}': {}", config_path, e))
        .and_then(|s| s.parse::<Value>().map_err(|e| anyhow::anyhow!("Failed to parse config file '{}': {}", config_path, e)))
    {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to parse config file '{}': {}", config_path, e);
            process::exit(1);
        }
    };

    // Support [general] section (preferred) with fallback to top-level keys for backward compat.
    let general = parsed.get("general");

    let listen = general.and_then(|g| g.get("listen")).and_then(|v| v.as_str())
        .or_else(|| parsed.get("listen").and_then(|v| v.as_str()))
        .unwrap_or("0.0.0.0");
    let port = general.and_then(|g| g.get("port")).and_then(|v| v.as_integer()).map(|p| p as u16)
        .or_else(|| parsed.get("port").and_then(|v| v.as_integer()).map(|p| p as u16))
        .unwrap_or(1080u16);
    let mode = general.and_then(|g| g.get("mode")).and_then(|v| v.as_str())
        .or_else(|| parsed.get("mode").and_then(|v| v.as_str()))
        .unwrap_or("transparent");
    let username = general.and_then(|g| g.get("username")).and_then(|v| v.as_str())
        .or_else(|| parsed.get("username").and_then(|v| v.as_str()))
        .unwrap_or("");
    let password = general.and_then(|g| g.get("password")).and_then(|v| v.as_str())
        .or_else(|| parsed.get("password").and_then(|v| v.as_str()))
        .unwrap_or("");

    // Load upstream proxy timeout from [client] section (in seconds, default 10s)
    // This replaces the CHEBUR_PROXY_CONNECT_TIMEOUT_MS env var for all upstream connections
    let dns_enabled = parsed.get("client")
        .and_then(|client| client.get("dns_enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let dns_listen_port = parsed.get("client")
        .and_then(|client| client.get("dns_listen_port"))
        .and_then(|v| v.as_integer())
        .map(|p| p as u16)
        .unwrap_or(53u16);

    // UDP defaults to TCP port + 1, so TCP and UDP can each be bound on all address families
    // without a port conflict between the dual-stack TCP listener and the separate
    // IPv4/IPv6 UDP sockets that the UDP proxy always creates.
    let udp_port = parsed.get("client")
        .and_then(|client| client.get("udp_port"))
        .and_then(|v| v.as_integer())
        .map(|p| p as u16)
        .unwrap_or(port + 1);

    let udp_desync_enabled = parsed.get("client")
        .and_then(|client| client.get("udp_desync_enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let udp_desync_min_size = parsed.get("client")
        .and_then(|client| client.get("udp_desync_min_size"))
        .and_then(|v| v.as_integer())
        .map(|s| s as usize)
        .unwrap_or(64);

    let udp_desync_max_size = parsed.get("client")
        .and_then(|client| client.get("udp_desync_max_size"))
        .and_then(|v| v.as_integer())
        .map(|s| s as usize)
        .unwrap_or(256);

    let upstream_proxy_timeout = parsed.get("client")
        .and_then(|client| client.get("upstream_proxy_timeout"))
        .and_then(|v| v.as_integer())
        .map(|secs| Duration::from_secs(secs as u64))
        .unwrap_or(Duration::from_secs(10));

    // Idle timeout: kill connections where no data flows in either direction.
    // Catches DPI-stalled HTTP/2 connections that hold TCP open but stop forwarding.
    // Set to 0 to disable.
    let connection_idle_timeout = parsed.get("client")
        .and_then(|client| client.get("connection_idle_timeout"))
        .and_then(|v| v.as_integer())
        .map(|secs| Duration::from_secs(secs as u64))
        .unwrap_or(Duration::from_secs(crate::proxy::DEFAULT_IDLE_TIMEOUT_SECS));

    // Initial (Phase 1) idle timeout: aggressive short window for brand-new connections.
    // If zero data flows during this window the connection is almost certainly DPI-stalled.
    // After any data flows the connection graduates to the lenient connection_idle_timeout.
    let connection_initial_idle_timeout = parsed.get("client")
        .and_then(|client| client.get("connection_initial_idle_timeout"))
        .and_then(|v| v.as_integer())
        .map(|secs| Duration::from_secs(secs as u64))
        .unwrap_or(Duration::from_secs(crate::proxy::DEFAULT_INITIAL_IDLE_TIMEOUT_SECS));

    let tcp_keepalive_time = parsed.get("client")
        .and_then(|c| c.get("tcp_keepalive_time"))
        .and_then(|v| v.as_integer())
        .map(|s| Duration::from_secs(s as u64))
        .unwrap_or(Duration::from_secs(30));

    let tcp_keepalive_interval = parsed.get("client")
        .and_then(|c| c.get("tcp_keepalive_interval"))
        .and_then(|v| v.as_integer())
        .map(|s| Duration::from_secs(s as u64))
        .unwrap_or(Duration::from_secs(10));

    let tcp_keepalive_retries = parsed.get("client")
        .and_then(|c| c.get("tcp_keepalive_retries"))
        .and_then(|v| v.as_integer())
        .map(|n| n as u32)
        .unwrap_or(3);

    // TPROXY health monitoring config (transparent mode only)
    let auto_recover_tproxy = parsed.get("client")
        .and_then(|c| c.get("auto_recover_tproxy"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let tproxy_lan_iface: Option<String> = parsed.get("client")
        .and_then(|c| c.get("tproxy_lan_iface"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let tproxy_recovery_script: Option<String> = parsed.get("client")
        .and_then(|c| c.get("tproxy_recovery_script"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let tproxy_fwmark = parsed.get("client")
        .and_then(|c| c.get("tproxy_fwmark"))
        .and_then(|v| v.as_integer())
        .map(|n| n as u32)
        .unwrap_or(1);

    let tproxy_route_table = parsed.get("client")
        .and_then(|c| c.get("tproxy_route_table"))
        .and_then(|v| v.as_integer())
        .map(|n| n as u32)
        .unwrap_or(100);

    let tproxy_health_interval = parsed.get("client")
        .and_then(|c| c.get("tproxy_health_interval"))
        .and_then(|v| v.as_integer())
        .map(|n| n as u64)
        .unwrap_or(300);

    let tproxy_iface_poll_interval = parsed.get("client")
        .and_then(|c| c.get("tproxy_iface_poll_interval"))
        .and_then(|v| v.as_integer())
        .map(|n| n as u64)
        .unwrap_or(10);

    let max_connections_per_proxy = parsed.get("client")
        .and_then(|c| c.get("max_connections_per_proxy"))
        .and_then(|v| v.as_integer())
        .map(|n| n as usize)
        .unwrap_or(1024);

    // Update global settings in proxy module
    crate::proxy::set_keepalive_config(tcp_keepalive_time, tcp_keepalive_interval, tcp_keepalive_retries);
    crate::proxy::set_per_proxy_max_conns(max_connections_per_proxy);

    // ── Circuit breaker configuration ────────────────────────────────────
    {
        let cb_enabled = parsed.get("client")
            .and_then(|c| c.get("circuit_breaker_enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let cb_cooldown = parsed.get("client")
            .and_then(|c| c.get("circuit_breaker_cooldown"))
            .and_then(|v| v.as_integer())
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(Duration::from_secs(30));

        let cb_threshold = parsed.get("client")
            .and_then(|c| c.get("circuit_breaker_threshold"))
            .and_then(|v| v.as_integer())
            .map(|n| n as u32)
            .unwrap_or(5);

        let cb_probe_interval = parsed.get("client")
            .and_then(|c| c.get("circuit_breaker_probe_interval"))
            .and_then(|v| v.as_integer())
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(Duration::from_secs(10));

        let cb_probe_timeout = parsed.get("client")
            .and_then(|c| c.get("circuit_breaker_probe_timeout"))
            .and_then(|v| v.as_integer())
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(Duration::from_secs(3));

        let cb_max_open = parsed.get("client")
            .and_then(|c| c.get("circuit_breaker_max_open_duration"))
            .and_then(|v| v.as_integer())
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(Duration::from_secs(300));

        let health_config = proxy_health::HealthConfig {
            enabled: cb_enabled,
            cooldown: cb_cooldown,
            failure_threshold: cb_threshold,
            probe_interval: cb_probe_interval,
            probe_timeout: cb_probe_timeout,
            max_open_duration: cb_max_open,
        };

        if cb_enabled {
            info!("Circuit breaker config: enabled=true, cooldown={}s, threshold={}, \
                   probe_interval={}s, probe_timeout={}s, max_open={}s",
                  cb_cooldown.as_secs(), cb_threshold, cb_probe_interval.as_secs(),
                  cb_probe_timeout.as_secs(), cb_max_open.as_secs());
        } else {
            info!("Circuit breaker config: enabled=false (fast-fail and health probes DISABLED)");
        }

        proxy_health::init(health_config);
    }

    // SNI routing enhancements
    let availability_check = parsed.get("client")
        .and_then(|client| client.get("availability_check"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let availability_check_timeout = parsed.get("client")
        .and_then(|client| client.get("availability_check_timeout"))
        .and_then(|v| v.as_integer())
        .map(|secs| Duration::from_secs(secs as u64))
        .unwrap_or(Duration::from_secs(5));

    let dns_cache_ttl = parsed.get("client")
        .and_then(|client| client.get("dns_cache_ttl"))
        .and_then(|v| v.as_integer())
        .map(|u| u as u64)
        .unwrap_or(3600);

    let availability_cache_ttl = parsed.get("client")
        .and_then(|client| client.get("availability_cache_ttl"))
        .and_then(|v| v.as_integer())
        .map(|u| u as u64)
        .unwrap_or(300);

    let context_enabled = parsed.get("client")
        .and_then(|client| client.get("context_enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let context_ttl = parsed.get("client")
        .and_then(|client| client.get("context_ttl"))
        .and_then(|v| v.as_integer())
        .map(|u| u as u64)
        .unwrap_or(3600);

    println!("Cheburproxy client v1.0");

    // Create domain cache early so it can be shared with both the DNS proxy
    // (which populates it from DNS responses) and the TPROXY accept loop
    // (which uses it to resolve the real domain behind ECH).
    let domain_cache: DomainCache = Arc::new(DashMap::new());

    // ============ DNS Leak Prevention: Initialize DNS Proxy ============
    // Parse DNS configuration and initialize resolver
    let shared_dns_resolver = {
        // Parse DNS resolver protocol from config
        let dns_resolver_protocol_str = parsed.get("client")
            .and_then(|c| c.get("dns_resolver_protocol"))
            .and_then(|v| v.as_str())
            .unwrap_or("plain");

        let dns_resolver_protocol = match dns_resolver_protocol_str {
            "plain" => DnsProtocol::Plain,
            "dot"   => DnsProtocol::DoT,
            "doh"   => DnsProtocol::DoH,
            "socks5" => DnsProtocol::Socks5,
            other => {
                warn!("Unknown dns_resolver_protocol '{}', defaulting to plain", other);
                DnsProtocol::Plain
            }
        };

        let dns_resolver_timeout = parsed.get("client")
            .and_then(|c| c.get("dns_resolver_timeout"))
            .and_then(|v| v.as_integer())
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(Duration::from_secs(5));

        let dns_resolver_cache_ttl = parsed.get("client")
            .and_then(|c| c.get("dns_resolver_cache_ttl"))
            .and_then(|v| v.as_integer())
            .map(|u| u as u64)
            .unwrap_or(3600);

        // SOCKS5 DNS settings
        let dns_socks5_proxy_addr = parsed.get("client")
            .and_then(|c| c.get("dns_socks5_proxy_addr"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let dns_socks5_upstream_dns = parsed.get("client")
            .and_then(|c| c.get("dns_socks5_upstream_dns"))
            .and_then(|v| v.as_str())
            .unwrap_or("8.8.8.8:53")
            .to_string();

        // DoH settings
        let dns_doh_url = parsed.get("client")
            .and_then(|c| c.get("dns_doh_url"))
            .and_then(|v| v.as_str())
            .unwrap_or("https://dns.google/dns-query")
            .to_string();

        let dns_doh_use_socks5 = parsed.get("client")
            .and_then(|c| c.get("dns_doh_use_socks5"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let dns_doh_socks5_proxy = parsed.get("client")
            .and_then(|c| c.get("dns_doh_socks5_proxy"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let dns_config = DnsResolverConfig {
            protocol: dns_resolver_protocol,
            timeout: dns_resolver_timeout,
            cache_ttl: dns_resolver_cache_ttl,
            socks5_proxy_addr: dns_socks5_proxy_addr,
            socks5_upstream_dns: dns_socks5_upstream_dns,
            doh_urls: vec![dns_doh_url],
            doh_use_socks5: dns_doh_use_socks5,
            doh_socks5_proxy: dns_doh_socks5_proxy,
            ..Default::default()
        };

        // Parse DNS proxy settings
        let dns_proxy_enabled = parsed.get("client")
            .and_then(|c| c.get("dns_proxy_enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Initialize the Core DNS Resolver (used by both DNS Proxy and Rule Engine)
        let dns_resolver = match InternalDnsResolver::from_config(dns_config).await {
            Ok(resolver) => {
                let resolver = Arc::new(resolver);
                info!("Core DNS Resolver initialized (protocol={})", resolver.protocol_name());
                resolver
            }
            Err(e) => {
                error!("CRITICAL: Failed to initialize Core DNS Resolver: {}. Application may function incorrectly.", e);
                // Fallback to a plain resolver if possible, or exit
                // For now, we'll try to continue but rule-based DNS and DNS Proxy will fail
                return Err(anyhow::anyhow!("Failed to initialize DNS resolver: {}", e));
            }
        };

        if dns_proxy_enabled {
            let dns_proxy_listen = parsed.get("client")
                .and_then(|c| c.get("dns_proxy_listen"))
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0.0")
                .to_string();

            let dns_proxy_port = parsed.get("client")
                .and_then(|c| c.get("dns_proxy_port"))
                .and_then(|v| v.as_integer())
                .map(|p| p as u16)
                .unwrap_or(53);

            let dns_proxy_cache_ttl = parsed.get("client")
                .and_then(|c| c.get("dns_proxy_cache_ttl"))
                .and_then(|v| v.as_integer())
                .map(|u| u as u64)
                .unwrap_or(3600);

            let dns_proxy_log_queries = parsed.get("client")
                .and_then(|c| c.get("dns_proxy_log_queries"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            info!("Starting DNS Proxy (listen={}:{})...", dns_proxy_listen, dns_proxy_port);

            let proxy_config = DnsProxyConfig {
                enabled: true,
                listen_addr: dns_proxy_listen,
                listen_port: dns_proxy_port,
                cache_size_limit: 10000,
                cache_ttl: dns_proxy_cache_ttl,
                log_queries: dns_proxy_log_queries,
            };

            let dns_proxy = Arc::new(DnsProxy::new(proxy_config, dns_resolver.clone(), domain_cache.clone()));
            tokio::spawn(async move {
                if let Err(e) = dns_proxy.start().await {
                    error!("DNS Proxy failed: {}", e);
                }
            });
        } else {
            debug!("DNS Proxy is disabled (dns_proxy_enabled = false)");
        }

        // Shared resolver for RuleEngine
        dns_resolver
    };

    let router = load_config("router.json").await?;
    
    // Parse new V2 availability check configuration (optional, with defaults)
    let availability_connect_timeout = parsed.get("client")
        .and_then(|client| client.get("availability_connect_timeout"))
        .and_then(|v| v.as_integer())
        .map(|ms| Duration::from_millis(ms as u64));
    
    let availability_tls_timeout = parsed.get("client")
        .and_then(|client| client.get("availability_tls_timeout"))
        .and_then(|v| v.as_integer())
        .map(|ms| Duration::from_millis(ms as u64));
    
    let availability_ttfb_timeout = parsed.get("client")
        .and_then(|client| client.get("availability_ttfb_timeout"))
        .and_then(|v| v.as_integer())
        .map(|ms| Duration::from_millis(ms as u64));
    
    let availability_read_timeout = parsed.get("client")
        .and_then(|client| client.get("availability_read_timeout"))
        .and_then(|v| v.as_integer())
        .map(|ms| Duration::from_millis(ms as u64));
    
    let availability_overall_budget = parsed.get("client")
        .and_then(|client| client.get("availability_overall_budget"))
        .and_then(|v| v.as_integer())
        .map(|ms| Duration::from_millis(ms as u64));
    
    let availability_max_redirects = parsed.get("client")
        .and_then(|client| client.get("availability_max_redirects"))
        .and_then(|v| v.as_integer())
        .map(|n| n as u8)
        .unwrap_or(2);
    
    let availability_min_bytes = parsed.get("client")
        .and_then(|client| client.get("availability_min_bytes"))
        .and_then(|v| v.as_integer())
        .map(|n| n as usize)
        .unwrap_or(512);
    
    let availability_max_bytes = parsed.get("client")
        .and_then(|client| client.get("availability_max_bytes"))
        .and_then(|v| v.as_integer())
        .map(|n| n as usize)
        .unwrap_or(16384);
    
    // Build V2 availability config - use granular timeouts if specified, otherwise derive from legacy timeout
    let availability_config = if availability_connect_timeout.is_some() ||
                                  availability_tls_timeout.is_some() ||
                                  availability_ttfb_timeout.is_some() ||
                                  availability_read_timeout.is_some() ||
                                  availability_overall_budget.is_some() {
        // V2 config with granular timeouts
        let mut config = crate::rule::AvailabilityCheckConfig::default();
        if let Some(t) = availability_connect_timeout { config.connect_timeout = t; }
        if let Some(t) = availability_tls_timeout { config.tls_timeout = t; }
        if let Some(t) = availability_ttfb_timeout { config.ttfb_timeout = t; }
        if let Some(t) = availability_read_timeout { config.read_timeout = t; }
        if let Some(t) = availability_overall_budget { config.overall_budget = t; }
        config.max_redirects = availability_max_redirects;
        config.min_bytes = availability_min_bytes;
        config.max_bytes = availability_max_bytes;
        info!("Using V2 availability check config: connect={}ms, tls={}ms, ttfb={}ms, read={}ms, budget={}ms, max_redirects={}, min_bytes={}",
              config.connect_timeout.as_millis(), config.tls_timeout.as_millis(),
              config.ttfb_timeout.as_millis(), config.read_timeout.as_millis(),
              config.overall_budget.as_millis(), config.max_redirects, config.min_bytes);
        config
    } else {
        // Legacy mode: derive from single availability_check_timeout
        let config = crate::rule::AvailabilityCheckConfig::from_legacy_timeout(availability_check_timeout);
        info!("Using legacy availability check config derived from timeout={}s: connect={}ms, tls={}ms, ttfb={}ms, read={}ms",
              availability_check_timeout.as_secs(), config.connect_timeout.as_millis(),
              config.tls_timeout.as_millis(), config.ttfb_timeout.as_millis(), config.read_timeout.as_millis());
        config
    };
    
    let rule_config = crate::rule::RuleEngineConfig {
        geoip_path: "geoip.dat".to_string(),
        geosite_path: "geosite.dat".to_string(),
        cache_duration_seconds: 600,
        enable_detailed_logging: true,
        availability_check,
        availability_check_timeout,
        availability_config,
        dns_cache_ttl,
        availability_cache_ttl,
    };
    // Create shared state for hot-reload
    let initial_rule_engine = RuleEngine::from_config_with_resolver(router.clone(), rule_config.clone(), shared_dns_resolver.clone())?;
    
    // Extract static GeoIP/GeoSite data for memory-efficient hot-reloads
    let (geoip_countries, geosite_categories, resolver) = initial_rule_engine.extract_static_geodata();
    info!("Extracted static GeoIP/GeoSite databases for memory-efficient reloads");
    
    let shared_state: SharedRuleEngine = Arc::new(ArcSwap::from_pointee(initial_rule_engine));

    // Pre-resolve all explicit rule domains into the ECH reverse IP→domain map.
    // This runs asynchronously so it does not delay startup; connections arriving
    // before resolution completes fall through to normal routing (via proxy for
    // ECH domains).  After it finishes, Stage 1.5 in proxy.rs can match any
    // destination IP back to the explicit rule domain that should handle it,
    // regardless of whether the client used the local DNS proxy or DoH.
    {
        let engine = (**shared_state.load()).clone();
        tokio::spawn(async move {
            engine.populate_ip_domain_map().await;
        });
    }

    // Spawn signal handler for hot-reload
    let reload_shared_state = shared_state.clone();
    let reload_rule_config = rule_config.clone();
    let reload_geoip = geoip_countries.clone();
    let reload_geosite = geosite_categories.clone();
    let reload_resolver = resolver.clone();
    tokio::spawn(async move {
        let mut signal = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to create SIGHUP signal handler: {}", e);
                return;
            }
        };
        loop {
            signal.recv().await;
            info!("Received SIGHUP, reloading router configuration (memory-efficient mode)");
            match reload_router_config_with_static_geodata(
                &reload_rule_config,
                reload_geoip.clone(),
                reload_geosite.clone(),
                reload_resolver.clone(),
            ).await {
                Ok(new_rule_engine) => {
                    reload_shared_state.store(Arc::new(new_rule_engine));
                    // Clear the client context cache so that stale proxy-tag entries from
                    // before the reload do not override the freshly-loaded rules.
                    // (The context cache is a global lazy_static — it is NOT part of
                    // RuleEngine and would otherwise persist across reloads for up to
                    // context_ttl seconds, causing domains newly moved to "direct" to keep
                    // going through the proxy until the TTL expires.)
                    let cleared = crate::client_context::CONTEXT_CACHE.len();
                    crate::client_context::CONTEXT_CACHE.clear();
                    info!("Router configuration reloaded successfully (GeoIP databases shared - memory optimized); \
                           client context cache cleared ({} entries evicted)", cleared);
                    // Re-build the ECH reverse IP→domain map for the new rules.
                    let engine = (**reload_shared_state.load()).clone();
                    tokio::spawn(async move {
                        engine.populate_ip_domain_map().await;
                    });
                }
                Err(e) => {
                    error!("Failed to reload router configuration: {}", e);
                }
            }
        }
    });

    // Create DNS cache for performance optimization (limited size)
    let dns_cache: DnsCache = Arc::new(DashMap::new());
    // (domain_cache was already created above, before the DNS proxy, so it
    // can be shared between the DNS proxy and the TPROXY accept loop.)

    // Periodic cleanup of connection pool
    // P2-7 FIX: Two-pass cleanup to reduce DashMap write lock contention.
    // Pass 1: Collect keys that need cleanup using read-only iter() (no write locks).
    // Pass 2: Clean each key individually with short-lived write locks.
    // Previously, iter_mut() held shard write locks across the entire iteration,
    // causing latency spikes in get_pooled_proxy_stream() under concurrent load.
    tokio::spawn(async {
        use tokio::time::{interval, Duration};
        let mut interval = interval(Duration::from_secs(60));
        interval.tick().await; // Skip first immediate tick
        loop {
            interval.tick().await;
            use crate::proxy::CONNECTION_POOL;
            let mut total_connections = 0;
            let mut removed_connections = 0;

            const MAX_CONNECTIONS_PER_PROXY: usize = 5;

            // Pass 1: Collect keys that may need cleanup (read locks only)
            let keys_to_check: Vec<_> = CONNECTION_POOL.iter()
                .filter(|entry| {
                    let conns = entry.value();
                    conns.len() > MAX_CONNECTIONS_PER_PROXY ||
                    conns.iter().any(|(_, created, _)| created.elapsed() >= Duration::from_secs(60))
                })
                .map(|entry| entry.key().clone())
                .collect();

            // Pass 2: Clean each key individually (short-lived write locks)
            for key in keys_to_check {
                if let Some(mut entry) = CONNECTION_POOL.get_mut(&key) {
                    let before_len = entry.len();
                    let after_list = entry.value_mut();
                    after_list.retain(|(_, created, _)| created.elapsed() < Duration::from_secs(60));
                    let after_len = after_list.len();

                    if after_len > MAX_CONNECTIONS_PER_PROXY {
                        let mut timed_connections: Vec<(TcpStream, Instant, OwnedSemaphorePermit)> = std::mem::take(after_list);
                        timed_connections.sort_by_key(|&(_, ref created, _)| *created);
                        let to_drop = after_len.saturating_sub(MAX_CONNECTIONS_PER_PROXY);
                        if to_drop > 0 {
                            timed_connections.drain(..to_drop);
                            *after_list = timed_connections;
                        }
                    }

                    removed_connections += before_len - after_list.len();
                    total_connections += after_list.len();
                }
            }

            // Remove empty entries
            let before_count = CONNECTION_POOL.len();
            CONNECTION_POOL.retain(|_, v| !v.is_empty());
            let after_count = CONNECTION_POOL.len();

            if removed_connections > 0 || before_count != after_count {
                debug!("Connection pool cleanup: {} proxies, {} total connections (removed {}), {} empty entries removed (max per proxy: {})",
                      after_count, total_connections, removed_connections, before_count - after_count, MAX_CONNECTIONS_PER_PROXY);
            }
        }
    });

    // Periodic cleanup of domain cache for UDP relay
    let domain_cache_cleanup = domain_cache.clone();
    tokio::spawn(async move {
        use tokio::time::{interval, Duration};
        let mut interval = interval(Duration::from_secs(1800)); // 30 minutes
        interval.tick().await; // Skip first immediate tick
        loop {
            interval.tick().await;
            // Remove old domain cache entries (older than 2 hours)
            let before_cleanup = domain_cache_cleanup.len();
            domain_cache_cleanup.retain(|_, (_, timestamp)| {
                timestamp.elapsed() < Duration::from_secs(7200) // 2 hours
            });
            let after_cleanup = domain_cache_cleanup.len();
            if before_cleanup != after_cleanup {
                debug!("Cleaned up domain cache: {} -> {} entries", before_cleanup, after_cleanup);
            }
        }
    });

    // Periodic cleanup of DNS cache
    let dns_cache_cleanup = dns_cache.clone();
    tokio::spawn(async move {
        use tokio::time::{interval, Duration};
        let mut interval = interval(Duration::from_secs(1800)); // 30 minutes
        interval.tick().await; // Skip first immediate tick
        loop {
            interval.tick().await;
            // Remove old DNS cache entries (older than 1 hour)
            let before_cleanup = dns_cache_cleanup.len();
            dns_cache_cleanup.retain(|_, entry| {
                entry.timestamp.elapsed() < Duration::from_secs(3600) // 1 hour
            });
            let after_cleanup = dns_cache_cleanup.len();
            if before_cleanup != after_cleanup {
                debug!("Cleaned up DNS cache: {} -> {} entries", before_cleanup, after_cleanup);
            }
        }
    });

    // Periodic cleanup of context cache
    let context_cleanup_ttl = Duration::from_secs(context_ttl);
    tokio::spawn(async move {
        use tokio::time::{interval, Duration};
        let mut interval = interval(Duration::from_secs(1800)); // 30 minutes
        interval.tick().await; // Skip first immediate tick
        loop {
            interval.tick().await;
            crate::client_context::cleanup_expired_contexts(context_cleanup_ttl);
        }
    });

    // Periodic cleanup of RuleEngine caches
    let rule_engine_cleanup = shared_state.clone();
    tokio::spawn(async move {
        use tokio::time::{interval, Duration};
        let mut interval = interval(Duration::from_secs(1800)); // 30 minutes
        interval.tick().await; // Skip first immediate tick
        loop {
            interval.tick().await;
            let engine = rule_engine_cleanup.load();
            engine.clear_dns_cache();
            engine.clear_availability_cache();
            let (routing_cache_size, dns_cache_size, availability_cache_size, inflight_size) = engine.get_cache_stats();
            debug!("RuleEngine cache stats: routing={}, dns={}, availability={}, inflight={}",
                   routing_cache_size, dns_cache_size, availability_cache_size, inflight_size);
        }
    });

    // Periodic memory usage monitoring
    let memory_monitor_dns_cache = dns_cache.clone();
    let memory_monitor_domain_cache = domain_cache.clone();
    let memory_monitor_shared_state = shared_state.clone();
    tokio::spawn(async move {
        use tokio::time::{interval, Duration};
        let mut interval = interval(Duration::from_secs(300)); // 5 minutes
        interval.tick().await; // Skip first immediate tick
        loop {
            interval.tick().await;
            let dns_cache_size = memory_monitor_dns_cache.len();
            let domain_cache_size = memory_monitor_domain_cache.len();
            let context_cache_size = crate::client_context::get_context_stats().get("context_cache_size").copied().unwrap_or(0);
            let connection_pool_stats = crate::proxy::get_pool_stats();
            let total_pool_connections: usize = connection_pool_stats.values().sum();
            let pool_proxies = connection_pool_stats.len();

            let engine = memory_monitor_shared_state.load();
            let (routing_cache_size, rule_dns_cache_size, availability_cache_size, inflight_size) = engine.get_cache_stats();

            let proxy_health_summary = proxy_health::status_summary();
            info!("Memory stats: DNS cache={}, Domain cache={}, Context cache={}, Connection pool: {} proxies, {} connections, RuleEngine: routing={}, dns={}, availability={}, inflight={}, Proxy health: {}",
                  dns_cache_size, domain_cache_size, context_cache_size, pool_proxies, total_pool_connections,
                  routing_cache_size, rule_dns_cache_size, availability_cache_size, inflight_size, proxy_health_summary);
        }
    });

    // ── Proxy health probe background task ───────────────────────────────
    tokio::spawn(async move {
        proxy_health::get().run_health_probes().await;
    });

    match mode {
        "transparent" => {
            let std_listener = create_transparent_tcp_socket_default(listen, port)?;
            let listener = TcpListener::from_std(std_listener)?;
            println!("Listening TCP on {}:{} (transparent mode)", listen, port);

            // Establish UDP associate with upstream proxy for UDP forwarding
            let udp_relay_addr = {
                let engine = shared_state.load();
                if let Some(default_proxy) = engine.get_proxy_by_tag("default") {
                    match establish_udp_associate(&default_proxy, upstream_proxy_timeout).await {
                        Ok(addr) => {
                            info!("Established UDP relay at {}", addr);
                            Some(addr)
                        }
                        Err(e) => {
                            warn!("Failed to establish UDP associate: {}", e);
                            None
                        }
                    }
                } else {
                    None
                }
            };

            let udp_config = Arc::new(Config {
                listen: listen.to_string(),
                port: udp_port,
                udp_desync_enabled,
                udp_desync_min_size,
                udp_desync_max_size,
            });
            let udp_shared_state = shared_state.clone();
            let domain_cache_for_udp = domain_cache.clone();
            let _udp_relay = udp_relay_addr;
            let udp_resolver = shared_dns_resolver.clone();
            tokio::spawn(async move {
                let udp_rules = (**udp_shared_state.load()).clone();
                if let Err(e) = run_udp_proxy(udp_rules, udp_config, domain_cache_for_udp, upstream_proxy_timeout, udp_resolver).await {
                    error!("Failed to start UDP proxy: {}", e);
                }
            });

            // P0-2 FIX: Limit concurrent TCP connections to prevent resource exhaustion
            let tcp_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_TCP_CONNECTIONS));
            info!("TCP connection limiter: max {} concurrent connections", MAX_CONCURRENT_TCP_CONNECTIONS);

            // Create and spawn TPROXY health checker
            let tproxy_checker = Arc::new(crate::tproxy_health::TproxyHealthChecker::new(
                tproxy_fwmark,
                tproxy_route_table,
                tproxy_lan_iface.clone(),
                auto_recover_tproxy,
                tproxy_recovery_script.clone(),
            ));
            info!("TPROXY health checker created (fwmark=0x{:x}, table={}, auto_recover={}, iface={:?})",
                  tproxy_fwmark, tproxy_route_table, auto_recover_tproxy, tproxy_lan_iface);
            let checker_for_monitor = tproxy_checker.clone();
            tokio::spawn(async move {
                checker_for_monitor.monitoring_loop(
                    Duration::from_secs(tproxy_health_interval),
                    Duration::from_secs(tproxy_iface_poll_interval),
                ).await;
            });

            // Heartbeat task for monitoring
            let heartbeat_sem = tcp_semaphore.clone();
            let heartbeat_checker = tproxy_checker.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    let active = MAX_CONCURRENT_TCP_CONNECTIONS - heartbeat_sem.available_permits();
                    let health = crate::proxy_health::status_summary();
                    let proxy_stats = crate::proxy::get_proxy_stats_summary();
                    let udp_stats = crate::udp_proxy::get_udp_stats_summary();
                    let proxy_limit = crate::proxy::get_per_proxy_max_conns();
                    let accepted_since_last = ACCEPTED_CONNS_COUNTER.swap(0, Ordering::Relaxed);
                    let tproxy_status = heartbeat_checker.status();
                    if active == 0 && accepted_since_last == 0 {
                        let streak = ZERO_TRAFFIC_STREAK.fetch_add(1, Ordering::Relaxed) + 1;
                        if streak >= 3 {
                            warn!("No connections received for {} consecutive heartbeats ({} seconds) - possible TPROXY rule disruption or network issue", streak, streak * 30);
                            let status = heartbeat_checker.check_health().await;
                            if status != crate::tproxy_health::TproxyHealthStatus::Ok {
                                warn!("TPROXY health check: {} - attempting recovery", status);
                                heartbeat_checker.attempt_recovery().await;
                            }
                        }
                    } else {
                        ZERO_TRAFFIC_STREAK.store(0, Ordering::Relaxed);
                    }
                    info!("HEARTBEAT: active_conns={}, {}, proxy_health=[{}], proxy_limits[{}]=[{}], accepted_since_last={}, tproxy={}",
                          active, udp_stats, health, proxy_limit, proxy_stats, accepted_since_last, tproxy_status);
                }
            });

            loop {
                let (stream, _) = listener.accept().await?;
                ACCEPTED_CONNS_COUNTER.fetch_add(1, Ordering::Relaxed);
                // P0-2 FIX: Apply connection limit (non-blocking check)
                let permit = match tcp_semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("TCP connection limit reached ({}), dropping connection", MAX_CONCURRENT_TCP_CONNECTIONS);
                        drop(stream);
                        continue;
                    }
                };
                // P0-1 FIX: Lock-free read via ArcSwap (was: std::sync::Mutex blocking worker threads)
                let engine: RuleEngine = (**shared_state.load()).clone();
                let cache = dns_cache.clone();
                let domain_cache = domain_cache.clone();
                let resolver = shared_dns_resolver.clone();
                tokio::spawn(async move {
                    let _permit = permit; // hold permit for lifetime of connection
                    let peer_addr = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "unknown".to_string());
                    match get_original_dst(&stream) {
                        Ok(dst) => {
                            info!("Transparent connection accepted: client {} -> dst {}", peer_addr, dst);
                            let mut peek_buf = [0u8; 8192];
                            // P1-1 FIX: Add timeout to peek to prevent slow-loris attacks
                            let peek_result = match tokio::time::timeout(
                                Duration::from_secs(PEEK_TIMEOUT_SECS),
                                stream.peek(&mut peek_buf[..])
                            ).await {
                                Ok(result) => result,
                                Err(_) => {
                                    debug!("Peek timeout ({}s) for dst {}, will use reverse DNS", PEEK_TIMEOUT_SECS, dst);
                                    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "peek timeout"))
                                }
                            };
                            let (is_tls, sni_domain, use_reverse_dns) = match peek_result {
                                Ok(n) => {
                                    let sni = extract_sni(&peek_buf[..n]);
                                    let is_tls = n > 0 && peek_buf[0] == 0x16;
                                    match sni {
                                        Ok(Some(sni_str)) => {
                                            debug!("SNI extracted: {} (TLS: {}) for dst {}", sni_str, is_tls, dst);
                                            (is_tls, Some(sni_str), false)
                                        }
                                        Ok(None) => {
                                            debug!("No SNI found (TLS: {}) for dst {}, will use reverse DNS", is_tls, dst);
                                            (is_tls, None, true)
                                        }
                                        Err(e) => {
                                            debug!("SNI extraction failed: {} for dst {}, will use reverse DNS", e, dst);
                                            (false, None, true)
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!("Peek failed: {} for dst {}, will use reverse DNS", e, dst);
                                    (false, None, true)
                                }
                            };

                            let optional_domain = if !use_reverse_dns {
                                // SNI was successfully extracted from the TLS ClientHello.
                                //
                                // ECH workaround: when the client uses Encrypted Client Hello
                                // (ECH), the visible SNI is a public/outer name chosen by the
                                // CDN — Cloudflare uses "cloudflare-ech.com". The real target
                                // domain is encrypted inside the ECH extension and invisible to
                                // the proxy.
                                //
                                // To recover the real domain, we look up the destination IP in
                                // the DomainCache, which is populated by the DNS proxy from
                                // A/AAAA records in every DNS response it forwards. If the
                                // cached domain differs from the SNI, we use the cached domain
                                // as optional_domain so it appears in candidate_domains alongside
                                // the outer SNI, giving the routing rules a chance to match it.
                                let dns_cached_domain = find_domain_by_ip(dst.ip(), &domain_cache).await;
                                match (&sni_domain, &dns_cached_domain) {
                                    (Some(sni), Some(dns)) if sni != dns => {
                                        info!(
                                            "ECH detected for {}: outer SNI='{}' differs from \
                                             DNS-cached domain='{}', using DNS domain for routing",
                                            dst.ip(), sni, dns
                                        );
                                        Some(dns.clone())
                                    }
                                    // No DNS cache entry, or outer SNI equals the real domain
                                    // (no ECH) — fall through to the plain SNI path.
                                    _ => sni_domain,
                                }
                            } else {
                                match resolve_domain_from_ip(dst.ip(), &engine, &cache, resolver).await {
                                    Ok(domain) => {
                                        info!("Reverse DNS resolved {} to {}", dst.ip(), domain);

                                        // Сохраняем в кэш IP->Domain для UDP relay
                                        domain_cache.insert(dst.ip(), (domain.clone(), Instant::now()));

                                        Some(domain)
                                    }
                                    Err(e) => {
                                        debug!("Reverse DNS failed for {}: {}, fallback to IP", dst.ip(), e);
                                        None
                                    }
                                }
                            };

                            // Если у нас есть домен из SNI, также сохраняем в кэш
                            if let Some(domain) = &optional_domain {
                                domain_cache.insert(dst.ip(), (domain.clone(), Instant::now()));
                            }

                            debug!("Final domain for routing: {:?}", optional_domain);
                            if let Err(e) = handle_tcp_stream(stream, dst, engine, optional_domain, upstream_proxy_timeout, context_enabled, Duration::from_secs(context_ttl), connection_initial_idle_timeout, connection_idle_timeout).await {
                                match &e {
                                    crate::proxy::ProxyError::IoError(io_err) if crate::proxy::is_data_plane_error(io_err) => {
                                        debug!("Connection to {} closed (peer disconnect): {}", dst, io_err);
                                    }
                                    crate::proxy::ProxyError::ProxyUnavailable { addr } => {
                                        // Already logged at WARN in proxy.rs, just debug here
                                        debug!("Connection to {} failed: proxy {} unavailable", dst, addr);
                                    }
                                    crate::proxy::ProxyError::ConnectionTimeout { .. } => {
                                        warn!("Connection to {} timed out: {}", dst, e);
                                    }
                                    crate::proxy::ProxyError::TargetUnreachable { target, reply_code } => {
                                        debug!("Target {} unreachable (SOCKS5 reply {:#04x})", target, reply_code);
                                    }
                                    _ => {
                                        error!("Error processing connection to {}: {:?}", dst, e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to get original destination: {:?}", e);
                        }
                    }
                });
            }
        }
        "proxy" => {
            let tcp_listener = TcpListener::bind((listen, port)).await?;
            println!("Listening TCP on {}:{} (proxy mode)", listen, port);

            let udp_port = port;
            let udp_socket = tokio::net::UdpSocket::bind((listen, udp_port)).await?;
            println!("Listening UDP on {}:{} (SOCKS5 UDP associate)", listen, udp_port);

            let udp_config = Arc::new(Config {
                listen: listen.to_string(),
                port,
                udp_desync_enabled,
                udp_desync_min_size,
                udp_desync_max_size,
            });
            let udp_handler_shared_state = shared_state.clone();
            let upstream_timeout_clone = upstream_proxy_timeout;
            let udp_config_clone = udp_config.clone();
            let domain_cache_clone = domain_cache.clone();
            let udp_resolver = shared_dns_resolver.clone();
            tokio::spawn(async move {
                let udp_rules = (**udp_handler_shared_state.load()).clone();
                if let Err(e) = run_socks5_udp_handler(udp_socket, udp_rules, udp_config_clone, domain_cache_clone, upstream_timeout_clone, udp_resolver).await {
                    error!("UDP handler failed: {}", e);
                }
            });
            let udp_proxy_shared_state = shared_state.clone();
            let udp_resolver_for_run_udp_proxy = shared_dns_resolver.clone();
            tokio::spawn(async move {
                let udp_rules = (**udp_proxy_shared_state.load()).clone();
                if let Err(e) = run_udp_proxy(udp_rules, udp_config, domain_cache, upstream_proxy_timeout, udp_resolver_for_run_udp_proxy).await {
                    error!("Failed to start UDP proxy: {}", e);
                }
            });

            // P0-2 FIX: Limit concurrent TCP connections to prevent resource exhaustion
            let tcp_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_TCP_CONNECTIONS));
            info!("TCP connection limiter: max {} concurrent connections", MAX_CONCURRENT_TCP_CONNECTIONS);

            // Heartbeat task for monitoring
            let heartbeat_sem = tcp_semaphore.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    let active = MAX_CONCURRENT_TCP_CONNECTIONS - heartbeat_sem.available_permits();
                    let health = crate::proxy_health::status_summary();
                    let proxy_stats = crate::proxy::get_proxy_stats_summary();
                    let udp_stats = crate::udp_proxy::get_udp_stats_summary();
                    let proxy_limit = crate::proxy::get_per_proxy_max_conns();
                    let accepted_since_last = ACCEPTED_CONNS_COUNTER.swap(0, Ordering::Relaxed);
                    if active == 0 && accepted_since_last == 0 {
                        let streak = ZERO_TRAFFIC_STREAK.fetch_add(1, Ordering::Relaxed) + 1;
                        if streak >= 3 {
                            warn!("No connections received for {} consecutive heartbeats ({} seconds) - possible TPROXY rule disruption or network issue", streak, streak * 30);
                        }
                    } else {
                        ZERO_TRAFFIC_STREAK.store(0, Ordering::Relaxed);
                    }
                    info!("HEARTBEAT: active_conns={}, {}, proxy_health=[{}], proxy_limits[{}]=[{}], accepted_since_last={}", 
                          active, udp_stats, health, proxy_limit, proxy_stats, accepted_since_last);
                }
            });

            loop {
                let (mut stream, _) = tcp_listener.accept().await?;
                ACCEPTED_CONNS_COUNTER.fetch_add(1, Ordering::Relaxed);
                // P0-2 FIX: Apply connection limit
                let permit = match tcp_semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("TCP connection limit reached ({}), dropping connection", MAX_CONCURRENT_TCP_CONNECTIONS);
                        drop(stream);
                        continue;
                    }
                };
                // P0-1 FIX: Lock-free read via ArcSwap
                let engine: RuleEngine = (**shared_state.load()).clone();
                let resolver_for_socks5 = shared_dns_resolver.clone();
                tokio::spawn(async move {
                    let _permit = permit; // hold permit for lifetime of connection
                    let (dst, domain) = match crate::proxy::handle_socks5_handshake(&mut stream, &resolver_for_socks5).await {
                        Ok(d) => d,
                        Err(e) => {
                            error!("SOCKS5 handshake failed: {e:?}");
                            return;
                        }
                    };
                    if let Err(e) = handle_tcp_stream(stream, dst, engine, domain, upstream_proxy_timeout, context_enabled, Duration::from_secs(context_ttl), connection_initial_idle_timeout, connection_idle_timeout).await {
                        match &e {
                            crate::proxy::ProxyError::IoError(io_err) if crate::proxy::is_data_plane_error(io_err) => {
                                debug!("Connection closed (peer disconnect): {}", io_err);
                            }
                            crate::proxy::ProxyError::ProxyUnavailable { addr } => {
                                debug!("Connection to {} failed: proxy {} unavailable", dst, addr);
                            }
                            crate::proxy::ProxyError::ConnectionTimeout { .. } => {
                                warn!("Connection to {} timed out: {}", dst, e);
                            }
                            crate::proxy::ProxyError::TargetUnreachable { target, reply_code } => {
                                debug!("Target {} unreachable (SOCKS5 reply {:#04x})", target, reply_code);
                            }
                            _ => {
                                error!("Error processing connection: {e:?}");
                            }
                        }
                    }
                });
            }
        }
        _ => {
            error!("Invalid mode: {}", mode);
            process::exit(1);
        }
    }
}