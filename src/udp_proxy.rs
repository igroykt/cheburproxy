use anyhow::{anyhow, Result};
use dashmap::DashMap;
use log::{debug, error, info, warn};
use nix::libc;
use rand::{Rng, thread_rng};
// socket2 types no longer needed after removing per-flow create_transparent_sender
#[allow(unused_imports)]
use socket2::{Domain, Protocol, Socket, SockAddr, Type};
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use socket2::SockRef;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};
use tokio::sync::{mpsc, Mutex, Semaphore, OwnedSemaphorePermit};

use crate::router::{Proxy, UdpMode};
use crate::rule::{RuleEngine, RoutingDecision};
use crate::find_domain_by_ip;
use crate::proxy_health;
use crate::proxy::{self, ProxyError};
use crate::transparent::{connect_tcp_with_mark, set_socket_mark};
use crate::udp_tunnel_frame;

// Constants for better maintainability and performance
// P1-5 FIX: Reduced from 65535 to 4096. Each UDP session spawns a response task
// with its own buffer. With MAX_UDP_SESSIONS=200K, 65KB buffers = ~13GB theoretical max.
// Most UDP responses (DNS, QUIC) fit within 1500 bytes (MTU). 4096 is generous enough
// for jumbo frames while reducing memory by 16x.
const UDP_PACKET_BUFFER_SIZE: usize = 4096;
const UDP_ANCILLARY_BUFFER_SIZE: usize = 1024;
const UDP_SESSION_CLEANUP_INTERVAL_SECONDS: u64 = 30;
const UDP_CONCURRENT_PROCESSING_LIMIT: usize = 100;
const UDP_DESYNC_RESERVED_BYTES: [u8; 2] = [0x00, 0x00];
const UDP_DESYNC_FRAGMENT_NONE: u8 = 0x00;

// Hard limit on concurrent UDP sessions to prevent FD exhaustion
const MAX_UDP_SESSIONS: usize = 200_000;

// Circuit breaker now uses shared proxy_health module (configurable via config.toml).

// FIX 5: Rate-limited UDP success recording for circuit breaker recovery.
// UDP can send thousands of packets per second (QUIC). Recording every success
// would cause lock contention on the DashMap in proxy_health. Instead, we
// record success at most once per second per proxy using an atomic timestamp.
lazy_static::lazy_static! {
    /// Last time we recorded a success for each proxy (epoch millis).
    /// Key: proxy_addr String, Value: AtomicU64 (epoch millis of last record_success call).
    static ref UDP_LAST_SUCCESS_RECORD: DashMap<String, Arc<AtomicU64>> = DashMap::new();
    /// Total number of active UDP sessions across all listeners.
    pub(crate) static ref GLOBAL_UDP_SESSION_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    /// Tracks UDP session creation attempts in flight to coalesce parallel requests for the same flow.
    /// Maps SessionKey to a watch channel that signals completion.
    pub(crate) static ref IN_FLIGHT_SESSIONS: DashMap<SessionKey, tokio::sync::watch::Receiver<Option<Arc<UdpSession>>>> = DashMap::new();
    /// Tracks TCP tunnel creation attempts in flight to coalesce parallel requests for the same proxy.
    pub(crate) static ref IN_FLIGHT_TUNNELS: DashMap<String, tokio::sync::watch::Receiver<Option<Arc<TcpUdpTunnel>>>> = DashMap::new();
}

/// Get summary of global UDP state for diagnostics.
pub fn get_udp_stats_summary() -> String {
    format!("udp_sessions={}", GLOBAL_UDP_SESSION_COUNT.load(std::sync::atomic::Ordering::Relaxed))
}

/// Minimum interval between `record_success` calls for the same proxy (1 second).
/// This prevents hot-path overhead while still providing timely recovery signals.
const UDP_SUCCESS_RECORD_INTERVAL: Duration = Duration::from_secs(1);

/// Record success for a proxy, rate-limited to at most once per UDP_SUCCESS_RECORD_INTERVAL.
/// Returns without doing anything if we already recorded success recently.
fn record_udp_success_rate_limited(proxy_addr: &str) {
    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let interval_millis = UDP_SUCCESS_RECORD_INTERVAL.as_millis() as u64;

    let entry = UDP_LAST_SUCCESS_RECORD
        .entry(proxy_addr.to_string())
        .or_insert_with(|| Arc::new(AtomicU64::new(0)));

    let last = entry.value().load(Ordering::Relaxed);
    if now_millis.saturating_sub(last) >= interval_millis {
        // Try to claim with CAS to avoid duplicate calls from concurrent tasks
        if entry.value().compare_exchange(last, now_millis, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
            proxy_health::record_success(proxy_addr);
        }
    }
}

/// Helper to remove a UDP session and decrement the global counter.
fn remove_udp_session(key: &SessionKey, sessions: &DashMap<SessionKey, Arc<UdpSession>>) {
    if sessions.remove(key).is_some() {
        GLOBAL_UDP_SESSION_COUNT.fetch_sub(1, Ordering::Relaxed);
    }
}

// Per-type session TTLs (seconds)
const UDP_TTL_DNS: u64 = 15;      // DNS flows: short-lived
const UDP_TTL_QUIC: u64 = 120;    // QUIC flows: need longer for connection persistence
const UDP_TTL_OTHER: u64 = 60;    // Generic UDP: moderate
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_RESERVED: u8 = 0x00;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_USERNAME_PASSWORD_AUTH: u8 = 0x02;
const SOCKS5_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_AUTH_SUCCESS: u8 = 0x00;

// Config struct for UDP proxy settings
#[derive(Clone, Debug)]
pub struct Config {
    pub listen: String,
    pub port: u16,
    pub udp_desync_enabled: bool,
    pub udp_desync_min_size: usize,
    pub udp_desync_max_size: usize,
}

// Standard socket options and protocol constants for Linux
pub const SOL_IP: i32 = 0; // IP protocol level
pub const SOL_IPV6: i32 = 41; // IPv6 protocol level
pub const SO_MARK: i32 = 36; // Standard value for SO_MARK (matches transparent.rs)
pub const IP_TRANSPARENT: i32 = 19; // Constant for transparent proxy
pub const IP_RECVORIGDSTADDR: i32 = 20; // Constant to receive original destination in ancillary data (Linux-specific)
pub const IPV6_TRANSPARENT: i32 = 75; // Constant for IPv6 transparent proxy
pub const IPV6_RECVORIGDSTADDR: i32 = 74; // Constant to receive IPv6 original destination in ancillary data (Linux-specific)
pub const IPV6_FREEBIND: i32 = 78; // Constant for IPv6 freebind option (Linux-specific)

/// Traffic classification for per-type session TTL management.
/// Classified by destination port heuristics.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum FlowType {
    /// DNS flows (port 53) — short TTL
    Dns,
    /// QUIC flows (port 443) — longer TTL for connection persistence
    Quic,
    /// Generic UDP — moderate TTL
    Other,
}

impl FlowType {
    /// Classify flow type by destination port
    pub fn from_target(target: SocketAddr) -> Self {
        match target.port() {
            53 => FlowType::Dns,
            443 => FlowType::Quic,
            _ => FlowType::Other,
        }
    }

    /// Get the session TTL for this flow type
    pub fn ttl(&self) -> Duration {
        match self {
            FlowType::Dns => Duration::from_secs(UDP_TTL_DNS),
            FlowType::Quic => Duration::from_secs(UDP_TTL_QUIC),
            FlowType::Other => Duration::from_secs(UDP_TTL_OTHER),
        }
    }

    /// Human-readable label
    pub fn label(&self) -> &'static str {
        match self {
            FlowType::Dns => "DNS",
            FlowType::Quic => "QUIC",
            FlowType::Other => "UDP",
        }
    }
}

/// UDP packet container with original destination information
///
/// This structure holds the complete UDP packet data along with routing information
/// extracted from the TPROXY setup, including the original destination address
/// and the actual client source address.
#[derive(Debug)]
struct UdpPacket {
    /// Raw UDP packet payload data
    data: Vec<u8>,
    /// Original destination address extracted from IP_RECVORIGDSTADDR ancillary data
    original_dst: SocketAddr,
    /// Actual client source address from the packet header
    client_addr: SocketAddr,
}

/// Routing decision for UDP sessions
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub(crate) enum SessionRoute {
    /// Direct connection without proxy
    Direct,
    /// Proxy-based connection with proxy server address
    Proxy(String),
}

impl SessionRoute {
    /// Get proxy server address if this is a proxy route
    pub fn proxy_addr(&self) -> Option<&str> {
        match self {
            SessionRoute::Direct => None,
            SessionRoute::Proxy(addr) => Some(addr),
        }
    }

    /// Check if this route uses a proxy
    pub fn is_proxy(&self) -> bool {
        matches!(self, SessionRoute::Proxy(_))
    }
}

/// Unique key for UDP session identification and caching
///
/// Sessions are identified by the combination of client address, target address,
/// and routing method to ensure proper traffic isolation and management.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub(crate) struct SessionKey {
    /// Source client address
    client: SocketAddr,
    /// Target destination address
    target: SocketAddr,
    /// Routing method (direct or proxy)
    route: SessionRoute,
}

impl SessionKey {
    /// Create a new session key
    pub fn new(client: SocketAddr, target: SocketAddr, route: SessionRoute) -> Self {
        Self { client, target, route }
    }

    /// Get the client address
    pub fn client(&self) -> &SocketAddr {
        &self.client
    }

    /// Get the target address
    pub fn target(&self) -> &SocketAddr {
        &self.target
    }

    /// Get the routing method
    pub fn route(&self) -> &SessionRoute {
        &self.route
    }
}

/// Generate a fake UDP packet for DPI bypass desynchronization
///
/// Creates a random-sized packet filled with random data to help bypass
/// Deep Packet Inspection systems that may be filtering or analyzing traffic.
///
/// # Arguments
/// * `min_size` - Minimum packet size in bytes
/// * `max_size` - Maximum packet size in bytes
///
/// # Returns
/// * Random fake UDP packet data
///
/// # Panics
/// * If min_size > max_size
fn generate_fake_udp_packet(min_size: usize, max_size: usize) -> Vec<u8> {
    assert!(min_size <= max_size, "min_size must be <= max_size");

    let size = thread_rng().gen_range(min_size..=max_size);
    let mut packet = Vec::with_capacity(size);
    // Use unsafe initialization for better performance with random data
    unsafe {
        packet.set_len(size);
        thread_rng().fill(&mut packet[..]);
    }
    packet
}

/// UDP session management for proxy connections
///
/// Maintains state for UDP proxy sessions including outbound connection management,
/// desynchronization tracking, and session lifecycle management. Sessions are
/// automatically cleaned up after a TTL to prevent memory leaks.
pub(crate) struct UdpSession {
    /// Outbound connection (direct UDP socket or SOCKS5 UDP association)
    outbound: UdpOutbound,
    /// Tracks whether UDP desync packet has been sent for this session
    desync_sent: Arc<AtomicBool>,
    /// Configuration settings for this session
    config: Arc<Config>,
    /// Session creation timestamp for TTL management
    created: Instant,
    /// Flag to signal response tasks to stop when session is being cleaned up
    /// This prevents socket leaks from orphaned response tasks
    active: Arc<AtomicBool>,
    /// Traffic type classification for per-type TTL
    flow_type: FlowType,
    /// Connection permit for per-proxy limiting (None if direct)
    _permit: Option<OwnedSemaphorePermit>,
}

impl UdpSession {
    /// Get session age in seconds
    pub fn age(&self) -> u64 {
        self.created.elapsed().as_secs()
    }

    /// Check if session has exceeded its per-type TTL
    pub fn is_expired(&self) -> bool {
        self.created.elapsed() > self.flow_type.ttl()
    }

    /// Check if desync packet has been sent for this session
    pub fn desync_sent(&self) -> bool {
        self.desync_sent.load(Ordering::Relaxed)
    }

    /// Mark desync as sent for this session
    pub fn mark_desync_sent(&self) {
        self.desync_sent.store(true, Ordering::Relaxed);
    }

    /// Check if session is still active (not being cleaned up)
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Mark session as inactive to signal response tasks to stop
    pub fn mark_inactive(&self) {
        self.active.store(false, Ordering::Relaxed);
    }
}

pub(crate) enum UdpOutbound {
    Direct { socket: Arc<UdpSocket> },
    Socks5 { assoc: Socks5UdpSocket },
    /// UDP-over-TCP tunnel: multiplexed UDP packets inside a single TCP connection
    TcpTunnel { tunnel: Arc<TcpUdpTunnel> },
}

/// UDP-over-TCP tunnel connection.
///
/// Multiplexes multiple UDP flows over a single TCP connection to the SOCKS5 proxy
/// using a custom framing protocol (CMD=0x04). This eliminates the need for separate
/// UDP channels and works through firewalls (e.g., Yggdrasil/cheburnet).
pub struct TcpUdpTunnel {
    /// TCP writer half, protected by mutex for concurrent access from multiple sessions
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    /// Response routing: maps (client_addr, target_addr) to per-flow response senders
    response_routes: Arc<DashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>>,
    /// Proxy address for circuit breaker integration
    proxy_addr: String,
    /// Flag to indicate tunnel is alive
    active: Arc<AtomicBool>,
    /// Keep TCP stream alive
    _reader_task: Arc<tokio::task::JoinHandle<()>>,
    /// Connection permit
    _permit: OwnedSemaphorePermit,
}

impl TcpUdpTunnel {
    /// Create a new TCP tunnel to the proxy, performing SOCKS5 CMD=0x04 handshake.
    pub async fn connect(
        proxy: &Proxy,
        upstream_proxy_timeout: Duration,
        permit: OwnedSemaphorePermit,
    ) -> Result<Arc<Self>> {
        let proxy_addr = format!("{}:{}", proxy.server_addr, proxy.server_port);

        // Establish TCP connection to SOCKS5 proxy
        let mut stream = tokio::time::timeout(upstream_proxy_timeout, connect_tcp_with_mark(&proxy_addr))
            .await
            .map_err(|_| anyhow!("TCP tunnel connect timeout to {}", proxy_addr))??;

        // Configure TCP keepalive (uses global config if args are None)
        if let Err(e) = crate::proxy::configure_tcp_keepalive(&stream, None, None, None) {
             warn!("Failed to set TCP keepalive for TCP tunnel to {}: {}", proxy_addr, e);
        }

        // Perform SOCKS5 authentication
        let auth_methods = if proxy.auth.username.is_empty() && proxy.auth.pass.is_empty() {
            vec![SOCKS5_NO_AUTH]
        } else {
            vec![SOCKS5_NO_AUTH, SOCKS5_USERNAME_PASSWORD_AUTH]
        };

        let mut handshake = vec![SOCKS5_VERSION, auth_methods.len() as u8];
        handshake.extend(&auth_methods);
        stream.write_all(&handshake).await?;

        let mut method_response = [0u8; 2];
        stream.read_exact(&mut method_response).await?;
        if method_response[0] != SOCKS5_VERSION {
            return Err(anyhow!("TCP tunnel: invalid SOCKS5 version: 0x{:02x}", method_response[0]));
        }

        let selected_method = method_response[1];
        if selected_method == SOCKS5_USERNAME_PASSWORD_AUTH {
            let uname = proxy.auth.username.as_bytes();
            let pass = proxy.auth.pass.as_bytes();
            let mut auth_req = vec![0x01, uname.len() as u8];
            auth_req.extend_from_slice(uname);
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass);
            stream.write_all(&auth_req).await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[1] != SOCKS5_AUTH_SUCCESS {
                return Err(anyhow!("TCP tunnel: SOCKS5 auth failed: 0x{:02x}", auth_resp[1]));
            }
        } else if selected_method != SOCKS5_NO_AUTH {
            return Err(anyhow!("TCP tunnel: unsupported auth method: 0x{:02x}", selected_method));
        }

        // Send CMD=0x04 (UDP_TUNNEL) with dummy address 0.0.0.0:0
        stream.write_all(&[
            SOCKS5_VERSION,
            udp_tunnel_frame::SOCKS5_CMD_UDP_TUNNEL,
            0x00, // RSV
            SOCKS5_ATYP_IPV4,
            0x00, 0x00, 0x00, 0x00, // 0.0.0.0
            0x00, 0x00,             // port 0
        ]).await?;

        // Read response
        let mut resp = [0u8; 4];
        stream.read_exact(&mut resp).await?;
        if resp[0] != SOCKS5_VERSION || resp[1] != SOCKS5_AUTH_SUCCESS {
            return Err(anyhow!("TCP tunnel: CMD=0x04 rejected: ver=0x{:02x} rep=0x{:02x}", resp[0], resp[1]));
        }

        // Consume bind address from response
        let atyp = resp[3];
        match atyp {
            SOCKS5_ATYP_IPV4 => {
                let mut skip = [0u8; 6];
                stream.read_exact(&mut skip).await?;
            }
            SOCKS5_ATYP_IPV6 => {
                let mut skip = [0u8; 18];
                stream.read_exact(&mut skip).await?;
            }
            _ => {
                let mut skip = [0u8; 6];
                stream.read_exact(&mut skip).await?;
            }
        }

        info!("TCP UDP tunnel established to {}", proxy_addr);

        // Split TCP stream
        let (reader, writer) = stream.into_split();
        let response_routes: Arc<DashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>> = Arc::new(DashMap::new());
        let active = Arc::new(AtomicBool::new(true));

        // Spawn reader task that demultiplexes responses
        let routes = response_routes.clone();
        let active_clone = active.clone();
        let proxy_addr_clone = proxy_addr.clone();
        let reader_task = tokio::spawn(async move {
            let mut reader = reader;
            loop {
                if !active_clone.load(Ordering::Relaxed) {
                    break;
                }
                match udp_tunnel_frame::read_frame(&mut reader).await {
                    Ok((from_addr, payload)) => {
                        let mut delivered = false;
                        for entry in routes.iter() {
                            let ((_client, tgt), sender) = entry.pair();
                            if *tgt == from_addr {
                                if sender.try_send(payload.clone()).is_err() {
                                    debug!("TCP tunnel: response channel full for {}, dropping packet", from_addr);
                                }
                                delivered = true;
                            }
                        }
                        if !delivered {
                            debug!("TCP tunnel: no subscriber for response from {}", from_addr);
                        }
                    }
                    Err(e) => {
                        if active_clone.load(Ordering::Relaxed) {
                            warn!("TCP tunnel reader ended for {}: {}", proxy_addr_clone, e);
                        }
                        break;
                    }
                }
            }
            active_clone.store(false, Ordering::Relaxed);
        });

        Ok(Arc::new(Self {
            writer: Arc::new(Mutex::new(writer)),
            response_routes,
            proxy_addr,
            active,
            _reader_task: Arc::new(reader_task),
            _permit: permit,
        }))
    }

    /// Send a UDP packet through the TCP tunnel.
    pub async fn send(&self, target: SocketAddr, payload: &[u8]) -> Result<()> {
        if !self.active.load(Ordering::Relaxed) {
            return Err(anyhow!("TCP tunnel to {} is closed", self.proxy_addr));
        }
        let mut writer = self.writer.lock().await;
        udp_tunnel_frame::write_frame(&mut *writer, target, payload).await
    }

    /// Subscribe to responses from a specific (client_addr, target_addr) pair.
    /// Returns a receiver that will get UDP payloads from that target for that client.
    pub fn subscribe(&self, client_addr: SocketAddr, target: SocketAddr) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(64);
        self.response_routes.insert((client_addr, target), tx);
        rx
    }

    /// Unsubscribe from responses for a (client_addr, target_addr) pair.
    pub fn unsubscribe(&self, client_addr: &SocketAddr, target: &SocketAddr) {
        self.response_routes.remove(&(*client_addr, *target));
    }

    /// Check if tunnel is still alive.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
}

/// Global pool of TCP tunnels, keyed by proxy address.
/// Allows multiple UDP sessions to share a single TCP tunnel to the same proxy.
lazy_static::lazy_static! {
    static ref TCP_TUNNEL_POOL: DashMap<String, Arc<TcpUdpTunnel>> = DashMap::new();
}

/// Get or create a TCP tunnel for the given proxy.
///
/// Also spawns a watchdog task that monitors tunnel health and proactively
/// cleans up dead tunnels. This prevents sessions from discovering a dead
/// tunnel one-by-one on each send attempt.
async fn get_or_create_tcp_tunnel(
    proxy: &Proxy,
    upstream_proxy_timeout: Duration,
) -> Result<Arc<TcpUdpTunnel>> {
    let proxy_addr = format!("{}:{}", proxy.server_addr, proxy.server_port);

    // 1. Check existing tunnel
    if let Some(tunnel) = TCP_TUNNEL_POOL.get(&proxy_addr) {
        if tunnel.is_active() {
            return Ok(tunnel.clone());
        }
        TCP_TUNNEL_POOL.remove(&proxy_addr);
    }

    // 2. Check in-flight creation
    if let Some(mut rx) = IN_FLIGHT_TUNNELS.get(&proxy_addr).map(|v| v.value().clone()) {
        debug!("Joining in-flight TCP tunnel creation for {}", proxy_addr);
        {
            let current = rx.borrow();
            if let Some(ref tunnel) = *current {
                return Ok(tunnel.clone());
            }
        }
        if rx.changed().await.is_err() {
            return Err(anyhow!("In-flight TCP tunnel creation failed for {}", proxy_addr));
        }
        return rx.borrow().as_ref().cloned().ok_or_else(|| anyhow!("In-flight TCP tunnel creation failed for {}", proxy_addr));
    }

    // 3. We are the creators
    let (tx, rx) = tokio::sync::watch::channel(None);
    IN_FLIGHT_TUNNELS.insert(proxy_addr.clone(), rx);

    let result = async {
        // Create new tunnel
        let proxy_key = crate::proxy::get_proxy_key(proxy);
        let permit = crate::proxy::acquire_proxy_permit(&proxy_key)?;
        let tunnel = TcpUdpTunnel::connect(proxy, upstream_proxy_timeout, permit).await?;
        TCP_TUNNEL_POOL.insert(proxy_addr.clone(), tunnel.clone());

        // Spawn a watchdog task that monitors tunnel health.
        let watchdog_addr = proxy_addr.clone();
        let watchdog_tunnel = tunnel.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(5)).await;
                if !watchdog_tunnel.is_active() {
                    warn!(
                        "TCP tunnel watchdog: tunnel to {} is dead — removing from pool",
                        watchdog_addr
                    );
                    TCP_TUNNEL_POOL.remove(&watchdog_addr);

                    if proxy_health::is_healthy(&watchdog_addr) {
                        info!(
                            "TCP tunnel watchdog: proxy {} is healthy — new tunnel will be created on next packet",
                            watchdog_addr
                        );
                    }
                    break;
                }
            }
            debug!("TCP tunnel watchdog exiting for {}", watchdog_addr);
        });
        Ok(tunnel)
    }.await;

    match result {
        Ok(tunnel) => {
            let _ = tx.send(Some(tunnel.clone()));
            IN_FLIGHT_TUNNELS.remove(&proxy_addr);
            Ok(tunnel)
        }
        Err(e) => {
            IN_FLIGHT_TUNNELS.remove(&proxy_addr);
            Err(e)
        }
    }
}

impl UdpSession {
    async fn new_direct(
        client_addr: SocketAddr,
        target: SocketAddr,
        key: SessionKey,
        sessions: Arc<DashMap<SessionKey, Arc<UdpSession>>>,
        config: Arc<Config>,
        upstream_proxy_timeout: Duration,
        transparent_sender: Arc<TransparentUdpSender>,
    ) -> Result<Arc<UdpSession>> {
        let _ = upstream_proxy_timeout;
        let outbound_socket = Arc::new(UdpSocket::bind("[::]:0").await?);
        // Set SO_MARK on direct UDP socket
        if let Err(e) = set_socket_mark(outbound_socket.as_raw_fd(), 2) {
            warn!("Failed to set SO_MARK on direct UDP socket: {}", e);
        }

        outbound_socket.connect(target).await?;

        let active = Arc::new(AtomicBool::new(true));
        let flow_type = FlowType::from_target(target);

        let session = Arc::new(UdpSession {
            outbound: UdpOutbound::Direct {
                socket: outbound_socket.clone(),
            },
            desync_sent: Arc::new(AtomicBool::new(false)),
            config: config.clone(),
            created: Instant::now(),
            active: active.clone(),
            flow_type,
            _permit: None,
        });

        Self::spawn_direct_response_task(
            outbound_socket,
            transparent_sender,
            client_addr,
            target,
            key,
            sessions,
            active,
        );

        Ok(session)
    }

    async fn new_socks5(
        client_addr: SocketAddr,
        target: SocketAddr,
        key: SessionKey,
        sessions: Arc<DashMap<SessionKey, Arc<UdpSession>>>,
        proxy: Proxy,
        config: Arc<Config>,
        upstream_proxy_timeout: Duration,
        transparent_sender: Arc<TransparentUdpSender>,
    ) -> Result<Arc<UdpSession>> {
        let proxy_key = crate::proxy::get_proxy_key(&proxy);
        let permit = crate::proxy::acquire_proxy_permit(&proxy_key)?;
        
        let proxy_addr = format!("{}:{}", proxy.server_addr, proxy.server_port);
        let assoc = create_socks5_udp_associate(
            &proxy_addr,
            &proxy.auth.username,
            &proxy.auth.pass,
            upstream_proxy_timeout,
        ).await?;

        let active = Arc::new(AtomicBool::new(true));
        let flow_type = FlowType::from_target(target);

        let session = Arc::new(UdpSession {
            outbound: UdpOutbound::Socks5 {
                assoc: assoc.clone(),
            },
            desync_sent: Arc::new(AtomicBool::new(false)),
            config: config.clone(),
            created: Instant::now(),
            active: active.clone(),
            flow_type,
            _permit: Some(permit),
        });

        let snapshot_key = key.clone();
        let snapshot_sessions = sessions.clone();
        
        Self::spawn_socks5_response_task(
            assoc,
            transparent_sender,
            client_addr,
            target,
            snapshot_key,
            snapshot_sessions,
            active,
        );

        Ok(session)
    }

    /// Create a new TCP tunnel session (UDP-over-TCP).
    /// The tunnel is shared across multiple sessions to the same proxy via
    /// the global TCP_TUNNEL_POOL.
    async fn new_tcp_tunnel(
        client_addr: SocketAddr,
        target: SocketAddr,
        key: SessionKey,
        sessions: Arc<DashMap<SessionKey, Arc<UdpSession>>>,
        proxy: Proxy,
        config: Arc<Config>,
        upstream_proxy_timeout: Duration,
        transparent_sender: Arc<TransparentUdpSender>,
    ) -> Result<Arc<UdpSession>> {
        let tunnel = get_or_create_tcp_tunnel(&proxy, upstream_proxy_timeout).await?;

        // Subscribe to responses from this target for this specific client
        let mut response_rx = tunnel.subscribe(client_addr, target);

        let active = Arc::new(AtomicBool::new(true));
        let flow_type = FlowType::from_target(target);

        let session = Arc::new(UdpSession {
            outbound: UdpOutbound::TcpTunnel {
                tunnel: tunnel.clone(),
            },
            desync_sent: Arc::new(AtomicBool::new(false)),
            config: config.clone(),
            created: Instant::now(),
            active: active.clone(),
            flow_type,
            _permit: None,
        });

        // Spawn response task that reads from the tunnel's demultiplexed channel
        let active_clone = active.clone();
        let key_clone = key.clone();
        let sessions_clone = sessions.clone();
        let tunnel_clone = tunnel.clone();
        tokio::spawn(async move {
            loop {
                if !active_clone.load(Ordering::Relaxed) {
                    break;
                }
                match timeout(Duration::from_secs(5), response_rx.recv()).await {
                    Ok(Some(payload)) => {
                        if let Err(e) = transparent_sender.send_response(client_addr, target, &payload) {
                            debug!("TCP tunnel response forward failed for {} -> {}: {}", client_addr, target, e);
                            break;
                        }
                    }
                    Ok(None) => {
                        // Channel closed (tunnel dropped)
                        debug!("TCP tunnel response channel closed for {} -> {}", client_addr, target);
                        break;
                    }
                    Err(_) => {
                        // Timeout — check active flag
                        if !tunnel_clone.is_active() {
                            debug!("TCP tunnel died for {} -> {}", client_addr, target);
                            break;
                        }
                        continue;
                    }
                }
            }
            tunnel_clone.unsubscribe(&client_addr, &target);
            remove_udp_session(&key_clone, &sessions_clone);
        });

        Ok(session)
    }

    /// Send UDP packet with optional desynchronization support
    ///
    /// Sends the payload to the target address, optionally sending a fake packet first
    /// for DPI bypass if UDP desync is enabled and hasn't been sent for this session.
    ///
    /// # Arguments
    /// * `target` - Target destination address
    /// * `payload` - UDP packet payload to send
    ///
    /// # Returns
    /// * `Ok(())` - Packet sent successfully
    /// * `Err` - Send operation failed
    async fn send(&self, target: SocketAddr, payload: &[u8]) -> Result<()> {
        // Validate inputs
        if payload.is_empty() {
            return Err(anyhow!("Cannot send empty UDP payload"));
        }

        if target.port() == 0 {
            return Err(anyhow!("Invalid target port: 0"));
        }

        // Handle UDP desync: send fake packet before real one if enabled and not sent yet
        if self.config.udp_desync_enabled && !self.desync_sent() {
            let fake_packet = generate_fake_udp_packet(
                self.config.udp_desync_min_size,
                self.config.udp_desync_max_size
            );

            debug!(
                "Sending UDP desync fake packet of size {} to {}",
                fake_packet.len(),
                target
            );

            // Send fake packet (don't fail the entire operation if this fails)
            match &self.outbound {
                UdpOutbound::Direct { socket } => {
                    if let Err(e) = socket.send(&fake_packet).await {
                        warn!("Failed to send UDP desync fake packet directly: {}", e);
                    } else {
                        self.mark_desync_sent();
                    }
                }
                UdpOutbound::Socks5 { assoc } => {
                    if let Err(e) = send_udp_via_socks5(assoc, target, &fake_packet).await {
                        warn!("Failed to send UDP desync fake packet via SOCKS5: {}", e);
                    } else {
                        self.mark_desync_sent();
                    }
                }
                UdpOutbound::TcpTunnel { tunnel } => {
                    if let Err(e) = tunnel.send(target, &fake_packet).await {
                        warn!("Failed to send UDP desync fake packet via TCP tunnel: {}", e);
                    } else {
                        self.mark_desync_sent();
                    }
                }
            }
        }

        // Send real packet
        match &self.outbound {
            UdpOutbound::Direct { socket } => {
                socket.send(payload).await?;
                Ok(())
            }
            UdpOutbound::Socks5 { assoc } => {
                send_udp_via_socks5(assoc, target, payload).await
            }
            UdpOutbound::TcpTunnel { tunnel } => {
                tunnel.send(target, payload).await
            }
        }
    }

    fn spawn_direct_response_task(
        socket: Arc<UdpSocket>,
        transparent_sender: Arc<TransparentUdpSender>,
        client_addr: SocketAddr,
        target: SocketAddr,
        key: SessionKey,
        sessions: Arc<DashMap<SessionKey, Arc<UdpSession>>>,
        active: Arc<AtomicBool>,
    ) {
        tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_PACKET_BUFFER_SIZE];
            loop {
                // Check if session is still active (not being cleaned up)
                if !active.load(Ordering::Relaxed) {
                    debug!("UDP direct response task stopping: session marked inactive for {} -> {}", client_addr, target);
                    break;
                }

                // Use timeout to periodically check active flag
                match timeout(Duration::from_secs(5), socket.recv(&mut buf)).await {
                    Ok(Ok(size)) => {
                        if size == 0 {
                            continue;
                        }
                        // Use shared transparent sender with IP_PKTINFO
                        if let Err(e) = transparent_sender.send_response(client_addr, target, &buf[..size]) {
                            debug!(
                                "UDP response forward ended for {} -> {} (peer disconnect): {}",
                                client_addr, target, e
                            );
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        debug!(
                            "Direct UDP session recv ended for {} -> {}: {}",
                            client_addr, target, e
                        );
                        break;
                    }
                    Err(_) => {
                        // Timeout - check active flag and continue
                        continue;
                    }
                }
            }
            debug!("UDP direct response task exiting for {} -> {}", client_addr, target);
            remove_udp_session(&key, &sessions);
        });
    }

    fn spawn_socks5_response_task(
        assoc: Socks5UdpSocket,
        transparent_sender: Arc<TransparentUdpSender>,
        client_addr: SocketAddr,
        target: SocketAddr,
        key: SessionKey,
        sessions: Arc<DashMap<SessionKey, Arc<UdpSession>>>,
        active: Arc<AtomicBool>,
    ) {
        let socket = assoc.socket.clone();
        let tcp_control = assoc.tcp_control.clone();
        
        tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_PACKET_BUFFER_SIZE];
            let mut tcp_buf = [0u8; 1];

            loop {
                // Check if session is still active (not being cleaned up)
                if !active.load(Ordering::Relaxed) {
                    debug!("UDP SOCKS5 response task stopping: session marked inactive for {} -> {}", client_addr, target);
                    break;
                }

                tokio::select! {
                    // UDP packet reception
                    res = socket.recv(&mut buf) => {
                        match res {
                            Ok(size) => {
                                if size == 0 {
                                    continue;
                                }
                                match parse_socks5_udp_reply(&buf[..size]) {
                                    Ok((offset, _remote)) => {
                                        // Use shared transparent sender with IP_PKTINFO
                                        if let Err(e) = transparent_sender.send_response(
                                            client_addr,
                                            target,
                                            &buf[offset..size],
                                        ) {
                                            debug!(
                                                "SOCKS5 UDP response forward ended for {} -> {} (peer disconnect): {}",
                                                client_addr, target, e
                                            );
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        debug!(
                                            "Failed to parse SOCKS5 UDP reply for client {} (target {}): {}",
                                            client_addr, target, e
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(
                                    "SOCKS5 UDP session recv ended for client {} (target {}): {}",
                                    client_addr, target, e
                                );
                                break;
                            }
                        }
                    }

                    // TCP control connection monitoring
                    // Uses peek to detect closure without consuming data
                    res = tcp_control.peek(&mut tcp_buf) => {
                        match res {
                            Ok(0) => {
                                // EOF - connection closed
                                warn!("SOCKS5 TCP control connection closed (EOF) for {} -> {}", client_addr, target);
                                break;
                            }
                            Ok(_) => {
                                // Data available but we don't expect any data on control channel after handshake
                                // Just consume it to avoid busy loop if server sends keepalives/junk
                                let mut drain_buf = [0u8; 1024];
                                let _ = tcp_control.try_read(&mut drain_buf); 
                            }
                            Err(e) => {
                                warn!("SOCKS5 TCP control connection error for {} -> {}: {}", client_addr, target, e);
                                break;
                            }
                        }
                    }
                    
                    // Periodic check for active flag (fallback)
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {
                        if !active.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                }
            }
            debug!("UDP SOCKS5 response task exiting for {} -> {}", client_addr, target);
            remove_udp_session(&key, &sessions);
        });
    }
}

/// Receive UDP packet with original destination information via ancillary data
///
/// This function uses `recvmsg` with IP_RECVORIGDSTADDR socket option to receive
/// both the packet data and the original destination address for transparent proxying.
///
/// # Arguments
/// * `socket` - UDP socket configured for transparent proxying
///
/// # Returns
/// * `Ok(UdpPacket)` - Packet with data, original destination, and client address
/// * `Err` - Reception error, including special case for EAGAIN/EWOULDBLOCK
async fn recv_udp_packet_with_orig_dst(socket: &UdpSocket) -> Result<UdpPacket> {
    // P1-3 FIX: Wait for socket readiness via tokio's epoll-based reactor
    // instead of busy-polling with libc::recvmsg + sleep(1ms).
    // This properly yields to the tokio scheduler when no data is available.
    socket.readable().await.map_err(|e| anyhow!("socket readable() failed: {}", e))?;

    let mut buf = [0u8; UDP_PACKET_BUFFER_SIZE];
    let mut ancillary_buf = [0u8; UDP_ANCILLARY_BUFFER_SIZE];
    let mut src_addr: libc::sockaddr_storage = unsafe { mem::zeroed() };

    // Set up I/O vector for data reception
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // Set up message header for recvmsg call
    let mut msg = libc::msghdr {
        msg_name: &mut src_addr as *mut _ as *mut _,
        msg_namelen: mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: ancillary_buf.as_mut_ptr() as *mut _,
        msg_controllen: ancillary_buf.len(),
        msg_flags: 0,
    };

    let fd = socket.as_raw_fd();
    // Use MSG_DONTWAIT since we've already confirmed readiness via readable().await
    let ret = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };

    if ret < 0 {
        let err = io::Error::last_os_error();

        // Handle EAGAIN/EWOULDBLOCK (no data available) as a special case for non-blocking sockets
        if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) {
            return Err(anyhow!("UDP receive operation would block - no data available"));
        }

        // Log detailed error information for debugging
        debug!(
            "recvmsg failed: {} (errno: {}). This may indicate socket configuration issues or network problems.",
            err, err.raw_os_error().unwrap_or(0)
        );
        return Err(anyhow!("UDP packet reception failed: {}", err));
    }

    // Validate received data length
    let data_len = ret as usize;
    if data_len == 0 {
        return Err(anyhow!("Received empty UDP packet (length 0)"));
    }

    let data = buf[..data_len].to_vec();

    // Parse ancillary data to find original destination address
    let mut original_dst = None;
    if msg.msg_controllen > 0 {
        let mut control_ptr = msg.msg_control;
        let control_end = unsafe { control_ptr.add(msg.msg_controllen as usize) };

        while control_ptr < control_end {
            let cmsg = unsafe { &*(control_ptr as *const libc::cmsghdr) };

            // Check for IP original destination address in ancillary data
            if cmsg.cmsg_level == SOL_IP && cmsg.cmsg_type == libc::IP_ORIGDSTADDR {
                // Validate control message length for sockaddr_in
                if cmsg.cmsg_len as usize >= mem::size_of::<libc::cmsghdr>() + mem::size_of::<libc::sockaddr_in>() {
                    let addr = unsafe { &*(libc::CMSG_DATA(control_ptr as *const _) as *const libc::sockaddr_in) };
                    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                    let port = u16::from_be(addr.sin_port);
                    original_dst = Some(SocketAddr::new(IpAddr::V4(ip), port));
                    debug!("Found original destination in ancillary data: {}", original_dst.unwrap());
                    break;
                } else {
                    warn!("Invalid control message length for IP_ORIGDSTADDR: {}", cmsg.cmsg_len);
                }
            }

            // Check for IPv6 original destination address in ancillary data
            if cmsg.cmsg_level == SOL_IPV6 && cmsg.cmsg_type == libc::IPV6_ORIGDSTADDR {
                // Validate control message length for sockaddr_in6
                if cmsg.cmsg_len as usize >= mem::size_of::<libc::cmsghdr>() + mem::size_of::<libc::sockaddr_in6>() {
                    let addr = unsafe { &*(libc::CMSG_DATA(control_ptr as *const _) as *const libc::sockaddr_in6) };
                    let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
                    let port = u16::from_be(addr.sin6_port);
                    original_dst = Some(SocketAddr::new(IpAddr::V6(ip), port));
                    debug!("Found IPv6 original destination in ancillary data: {}", original_dst.unwrap());
                    break;
                } else {
                    warn!("Invalid control message length for IPV6_ORIGDSTADDR: {}", cmsg.cmsg_len);
                }
            }

            // Manual alignment calculation for portability (CMSG_ALIGN not always available)
            let align = mem::size_of::<usize>();
            let len = ((cmsg.cmsg_len as usize + align - 1) / align) * align;
            control_ptr = unsafe { control_ptr.add(len) };
        }
    } else {
        debug!("No ancillary data received with UDP packet");
    }

    // Parse client address from message header
    let client_addr = match src_addr.ss_family as i32 {
        libc::AF_INET => {
            // Validate that we have enough data for sockaddr_in
            if msg.msg_namelen < mem::size_of::<libc::sockaddr_in>() as libc::socklen_t {
                return Err(anyhow!(
                    "Truncated IPv4 address in recvmsg (got {} bytes, expected {})",
                    msg.msg_namelen, mem::size_of::<libc::sockaddr_in>()
                ));
            }
            let addr4 = unsafe { *(&src_addr as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(addr4.sin_addr.s_addr));
            let port = u16::from_be(addr4.sin_port);
            SocketAddr::new(IpAddr::V4(ip), port)
        }
        libc::AF_INET6 => {
            // Validate that we have enough data for sockaddr_in6
            if msg.msg_namelen < mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t {
                return Err(anyhow!(
                    "Truncated IPv6 address in recvmsg (got {} bytes, expected {})",
                    msg.msg_namelen, mem::size_of::<libc::sockaddr_in6>()
                ));
            }
            let addr6 = unsafe { *(&src_addr as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(addr6.sin6_addr.s6_addr);
            let port = u16::from_be(addr6.sin6_port);
            SocketAddr::new(IpAddr::V6(ip), port)
        }
        family => {
            return Err(anyhow!(
                "Unsupported client address family in recvmsg: {} (supported: AF_INET={}, AF_INET6={})",
                family, libc::AF_INET, libc::AF_INET6
            ));
        }
    };

    // Validate that we received original destination information
    let original_dst = match original_dst {
        Some(dst) => {
            if dst.port() == 0 {
                return Err(anyhow!("Invalid original destination: port cannot be zero"));
            }
            dst
        }
        None => {
            return Err(anyhow!("No original destination found in ancillary data - this may indicate a TPROXY configuration issue"));
        }
    };

    Ok(UdpPacket {
        data,
        original_dst,
        client_addr,
    })
}

/// Parse SOCKS5 UDP reply packet and extract remote address information
///
/// # Arguments
/// * `packet` - Raw SOCKS5 UDP reply packet
///
/// # Returns
/// * `Ok((offset, remote_addr))` - Offset where payload starts and optional remote address
/// * `Err` - Parsing error with descriptive message
fn parse_socks5_udp_reply(packet: &[u8]) -> Result<(usize, Option<SocketAddr>)> {
    // Validate minimum packet length
    if packet.len() < 4 {
        return Err(anyhow!("SOCKS5 UDP reply too short: {} bytes (minimum 4)", packet.len()));
    }

    // Validate reserved bytes (should be 0x00, 0x00)
    if packet[0] != UDP_DESYNC_RESERVED_BYTES[0] || packet[1] != UDP_DESYNC_RESERVED_BYTES[1] {
        return Err(anyhow!(
            "SOCKS5 UDP reply has non-zero reserved bytes: {:02x?} (expected 0x00 0x00)",
            &packet[..2]
        ));
    }

    // Validate fragment field (must be 0 for no fragmentation)
    let frag = packet[2];
    if frag != UDP_DESYNC_FRAGMENT_NONE {
        return Err(anyhow!(
            "SOCKS5 UDP fragmentation not supported (frag={}, must be 0)",
            frag
        ));
    }

    let atyp = packet[3];
    let mut idx = 4usize;

    match atyp {
        SOCKS5_ATYP_IPV4 => {
            // IPv4 address format: RSV + FRAG + ATYP + IPv4(4) + PORT(2)
            if packet.len() < idx + 4 + 2 {
                return Err(anyhow!("SOCKS5 UDP reply truncated for IPv4 (need {} bytes, got {})",
                    idx + 4 + 2, packet.len()));
            }
            let ip = Ipv4Addr::new(packet[idx], packet[idx + 1], packet[idx + 2], packet[idx + 3]);
            idx += 4;
            let port = u16::from_be_bytes([packet[idx], packet[idx + 1]]);
            let offset = idx + 2; // Skip past the port bytes
            Ok((offset, Some(SocketAddr::new(IpAddr::V4(ip), port))))
        }
        SOCKS5_ATYP_DOMAIN => {
            // Domain address format: RSV + FRAG + ATYP + LEN(1) + DOMAIN(LEN) + PORT(2)
            if packet.len() <= idx {
                return Err(anyhow!("SOCKS5 UDP reply missing domain length byte"));
            }
            let domain_len = packet[idx] as usize;
            idx += 1;

            if packet.len() < idx + domain_len + 2 {
                return Err(anyhow!("SOCKS5 UDP reply truncated for domain (need {} bytes, got {})",
                    idx + domain_len + 2, packet.len()));
            }

            // Skip domain and port for offset calculation
            idx += domain_len;
            let _port = u16::from_be_bytes([packet[idx], packet[idx + 1]]);
            let offset = idx + 2; // Skip past the port bytes
            Ok((offset, None)) // No IP address for domain-based replies
        }
        SOCKS5_ATYP_IPV6 => {
            // IPv6 address format: RSV + FRAG + ATYP + IPv6(16) + PORT(2)
            if packet.len() < idx + 16 + 2 {
                return Err(anyhow!("SOCKS5 UDP reply truncated for IPv6 (need {} bytes, got {})",
                    idx + 16 + 2, packet.len()));
            }
            let ipv6_bytes: [u8; 16] = packet[idx..idx + 16].try_into().unwrap();
            let ipv6 = Ipv6Addr::from(ipv6_bytes);
            idx += 16;
            let port = u16::from_be_bytes([packet[idx], packet[idx + 1]]);
            let offset = idx + 2; // Skip past the port bytes
            Ok((offset, Some(SocketAddr::new(IpAddr::V6(ipv6), port))))
        }
        other => {
            Err(anyhow!("Unsupported SOCKS5 address type: 0x{:02x} (supported: IPv4=0x01, Domain=0x03)", other))
        }
    }
}

/// Shared transparent UDP sender using sendmsg() with IP_PKTINFO
/// 
/// Replaces per-flow transparent sender sockets. Uses only 2 FDs total (IPv4+IPv6)
/// regardless of flow count. Spoofs source address via IP_PKTINFO ancillary data.
///
/// # Safety
/// This struct holds raw file descriptors and is used from multiple tokio tasks via Arc.
/// This is safe because:
/// - `sendmsg()` is thread-safe on Linux (each call is atomic for datagrams)
/// - The FDs are only used for `sendmsg()` operations (read-only on the buffer)
/// - FDs are properly closed in the `Drop` impl
pub struct TransparentUdpSender {
    fd_v4: std::os::fd::RawFd,
    fd_v6: Option<std::os::fd::RawFd>,
}

impl TransparentUdpSender {
    /// Create shared transparent sender sockets (IPv4 + IPv6)
    pub fn new() -> Result<Arc<Self>> {
        // Create IPv4 socket
        let sock_v4 = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock_v4 < 0 {
            return Err(anyhow!("Failed to create IPv4 UDP socket: {}", io::Error::last_os_error()));
        }

        let one: libc::c_int = 1;
        
        // Set IP_TRANSPARENT
        let res = unsafe {
            libc::setsockopt(
                sock_v4,
                SOL_IP,
                IP_TRANSPARENT,
                &one as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if res != 0 {
            unsafe { libc::close(sock_v4); }
            return Err(anyhow!("Failed to set IP_TRANSPARENT on IPv4: {}", io::Error::last_os_error()));
        }

        // Set IP_FREEBIND
        let res = unsafe {
            libc::setsockopt(
                sock_v4,
                SOL_IP,
                libc::IP_FREEBIND,
                &one as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if res != 0 {
            unsafe { libc::close(sock_v4); }
            return Err(anyhow!("Failed to set IP_FREEBIND on IPv4: {}", io::Error::last_os_error()));
        }

        // Set SO_MARK on IPv4 socket to bypass TPROXY rules
        // Mark 0x2: identifies proxy-originated traffic. Must differ from TPROXY mark (0x1) to avoid policy routing loop.
        let mark: libc::c_int = 2;
        let res = unsafe {
            libc::setsockopt(
                sock_v4,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if res != 0 {
            warn!("Failed to set SO_MARK on IPv4 transparent UDP sender: {}", std::io::Error::last_os_error());
        }

        // Bind to 0.0.0.0:0
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        let res = unsafe {
            libc::bind(
                sock_v4,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if res != 0 {
            unsafe { libc::close(sock_v4); }
            return Err(anyhow!("Failed to bind IPv4 socket: {}", io::Error::last_os_error()));
        }

        // Create IPv6 socket
        let sock_v6 = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
        let fd_v6 = if sock_v6 >= 0 {
            // Set IPV6_TRANSPARENT
            let res = unsafe {
                libc::setsockopt(
                    sock_v6,
                    SOL_IPV6,
                    IPV6_TRANSPARENT,
                    &one as *const _ as *const libc::c_void,
                    mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if res != 0 {
                warn!("Failed to set IPV6_TRANSPARENT: {}", io::Error::last_os_error());
                unsafe { libc::close(sock_v6); }
                None
            } else {
                // Set SO_MARK for IPv6
                let res = unsafe {
                    libc::setsockopt(
                        sock_v6,
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        &mark as *const _ as *const libc::c_void,
                        mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if res != 0 {
                    warn!("Failed to set SO_MARK on IPv6 UDP socket: {}", io::Error::last_os_error());
                }
                // Set IPV6_FREEBIND
                let res = unsafe {
                    libc::setsockopt(
                        sock_v6,
                        SOL_IPV6,
                        IPV6_FREEBIND,
                        &one as *const _ as *const libc::c_void,
                        mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if res != 0 {
                    warn!("Failed to set IPV6_FREEBIND: {}", io::Error::last_os_error());
                    unsafe { libc::close(sock_v6); }
                    None
                } else {
                    // Bind to [::]:0
                    let addr = libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as libc::sa_family_t,
                        sin6_port: 0,
                        sin6_flowinfo: 0,
                        sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
                        sin6_scope_id: 0,
                    };
                    let res = unsafe {
                        libc::bind(
                            sock_v6,
                            &addr as *const _ as *const libc::sockaddr,
                            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                        )
                    };
                    if res != 0 {
                        warn!("Failed to bind IPv6 socket: {}", io::Error::last_os_error());
                        unsafe { libc::close(sock_v6); }
                        None
                    } else {
                        Some(sock_v6)
                    }
                }
            }
        } else {
            warn!("Failed to create IPv6 socket: {}", io::Error::last_os_error());
            None
        };

        info!("TransparentUdpSender created: IPv4_FD={}, IPv6_FD={:?}", sock_v4, fd_v6);
        
        Ok(Arc::new(Self {
            fd_v4: sock_v4,
            fd_v6,
        }))
    }

    /// Send response to client, spoofing source address as original_dst
    /// Uses sendmsg() with IP_PKTINFO/IPV6_PKTINFO ancillary data
    pub fn send_response(
        &self,
        client_addr: SocketAddr,
        original_dst: SocketAddr,
        data: &[u8],
    ) -> Result<usize> {
        match (client_addr, original_dst) {
            (SocketAddr::V4(client), SocketAddr::V4(orig)) => {
                // Build sockaddr for destination (client)
                let dest_addr = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: client.port().to_be(),
                    sin_addr: libc::in_addr { s_addr: u32::from(*client.ip()).to_be() },
                    sin_zero: [0; 8],
                };

                // Build IP_PKTINFO to set source address
                let pktinfo = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr { s_addr: u32::from(*orig.ip()).to_be() },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };

                // Build control message buffer
                let cmsg_space = unsafe { libc::CMSG_SPACE(mem::size_of::<libc::in_pktinfo>() as u32) } as usize;
                let mut cmsg_buf = vec![0u8; cmsg_space];
                
                // SAFETY: sendmsg() only reads from iov_base, never writes.
                // The *mut cast is required by the libc signature but the data is not modified.
                let mut iov = libc::iovec {
                    iov_base: data.as_ptr() as *mut libc::c_void,
                    iov_len: data.len(),
                };

                let mut msg: libc::msghdr = unsafe { mem::zeroed() };
                msg.msg_name = &dest_addr as *const _ as *mut libc::c_void;
                msg.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
                msg.msg_controllen = cmsg_buf.len();

                // Fill control message
                unsafe {
                    let cmsg = libc::CMSG_FIRSTHDR(&msg);
                    if cmsg.is_null() {
                        return Err(anyhow!("Failed to get first cmsg header"));
                    }
                    (*cmsg).cmsg_level = SOL_IP;
                    (*cmsg).cmsg_type = libc::IP_PKTINFO;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::in_pktinfo>() as u32) as _;
                    
                    let data_ptr = libc::CMSG_DATA(cmsg);
                    std::ptr::copy_nonoverlapping(
                        &pktinfo as *const _ as *const u8,
                        data_ptr,
                        mem::size_of::<libc::in_pktinfo>(),
                    );

                    msg.msg_controllen = (*cmsg).cmsg_len;
                }

                // P0-3 FIX: Use MSG_DONTWAIT to prevent blocking tokio worker threads.
                // Previously, sendmsg(fd, &msg, 0) could block the calling thread when
                // the kernel send buffer is full, freezing the entire tokio runtime under
                // heavy UDP load (e.g., QUIC traffic).
                let sent = unsafe { libc::sendmsg(self.fd_v4, &msg, libc::MSG_DONTWAIT) };
                if sent < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::WouldBlock {
                        // Send buffer full — drop packet (UDP is unreliable by design)
                        debug!("UDP sendmsg would block (IPv4), dropping packet to {}", client_addr);
                        Ok(0)
                    } else {
                        Err(anyhow!("sendmsg failed: {}", err))
                    }
                } else {
                    Ok(sent as usize)
                }
            }
            (SocketAddr::V6(client), SocketAddr::V6(orig)) => {
                let fd = self.fd_v6.ok_or_else(|| anyhow!("IPv6 sender not available"))?;

                // Build sockaddr for destination (client)
                let dest_addr = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: client.port().to_be(),
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr { s6_addr: client.ip().octets() },
                    sin6_scope_id: 0,
                };

                // Build IPV6_PKTINFO to set source address
                let pktinfo = libc::in6_pktinfo {
                    ipi6_ifindex: 0,
                    ipi6_addr: libc::in6_addr { s6_addr: orig.ip().octets() },
                };

                // Build control message buffer
                let cmsg_space = unsafe { libc::CMSG_SPACE(mem::size_of::<libc::in6_pktinfo>() as u32) } as usize;
                let mut cmsg_buf = vec![0u8; cmsg_space];
                
                // SAFETY: sendmsg() only reads from iov_base, never writes.
                let mut iov = libc::iovec {
                    iov_base: data.as_ptr() as *mut libc::c_void,
                    iov_len: data.len(),
                };

                let mut msg: libc::msghdr = unsafe { mem::zeroed() };
                msg.msg_name = &dest_addr as *const _ as *mut libc::c_void;
                msg.msg_namelen = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
                msg.msg_controllen = cmsg_buf.len();

                // Fill control message
                unsafe {
                    let cmsg = libc::CMSG_FIRSTHDR(&msg);
                    if cmsg.is_null() {
                        return Err(anyhow!("Failed to get first cmsg header (IPv6)"));
                    }
                    (*cmsg).cmsg_level = SOL_IPV6;
                    (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::in6_pktinfo>() as u32) as _;
                    
                    let data_ptr = libc::CMSG_DATA(cmsg);
                    std::ptr::copy_nonoverlapping(
                        &pktinfo as *const _ as *const u8,
                        data_ptr,
                        mem::size_of::<libc::in6_pktinfo>(),
                    );

                    msg.msg_controllen = (*cmsg).cmsg_len;
                }

                // P0-3 FIX: Use MSG_DONTWAIT for IPv6 as well
                let sent = unsafe { libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT) };
                if sent < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::WouldBlock {
                        debug!("UDP sendmsg would block (IPv6), dropping packet to {}", client_addr);
                        Ok(0)
                    } else {
                        Err(anyhow!("sendmsg (IPv6) failed: {}", err))
                    }
                } else {
                    Ok(sent as usize)
                }
            }
            _ => Err(anyhow!("Address family mismatch: client={:?}, original_dst={:?}", client_addr, original_dst)),
        }
    }
}

impl Drop for TransparentUdpSender {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd_v4);
            if let Some(fd) = self.fd_v6 {
                libc::close(fd);
            }
        }
        debug!("TransparentUdpSender dropped");
    }
}

/// SOCKS5 UDP socket wrapper that maintains both the UDP socket and the control TCP connection
///
/// Per RFC 1928, the UDP relay terminates when the TCP control connection closes,
/// so we must keep it alive for the duration of the UDP session.
#[derive(Clone)]
pub struct Socks5UdpSocket {
    pub socket: Arc<UdpSocket>,
    // This is necessary because per SOCKS5 spec, UDP relay is tied to TCP control channel
    pub tcp_control: Arc<tokio::net::TcpStream>,
}

/// Create SOCKS5 UDP associate connection for UDP proxying
///
/// This function establishes a SOCKS5 TCP connection and performs UDP associate
/// handshake to enable UDP traffic forwarding through the SOCKS5 proxy.
///
/// # Arguments
/// * `proxy_addr` - SOCKS5 proxy server address (host:port)
/// * `username` - SOCKS5 authentication username (empty string for no auth)
/// * `password` - SOCKS5 authentication password
/// * `upstream_proxy_timeout` - Connection timeout for proxy operations
///
/// # Returns
/// * `Ok(Socks5UdpSocket)` - Connected UDP socket ready for SOCKS5 forwarding
/// * `Err` - Connection or handshake failure
pub async fn create_socks5_udp_associate(
    proxy_addr: &str,
    username: &str,
    password: &str,
    upstream_proxy_timeout: Duration,
) -> anyhow::Result<Socks5UdpSocket> {
    // Input validation
    if proxy_addr.is_empty() {
        return Err(anyhow!("Proxy address cannot be empty"));
    }

    // Establish TCP connection to SOCKS5 proxy with SO_MARK=2 (0x2: proxy-originated traffic, avoids TPROXY re-interception)
    let mut stream = timeout(upstream_proxy_timeout, connect_tcp_with_mark(proxy_addr)).await
        .map_err(|_| anyhow!("SOCKS5 UDP associate connect timeout after {:?}", upstream_proxy_timeout))??;

    // Send SOCKS5 handshake with supported authentication methods
    let auth_methods = if username.is_empty() && password.is_empty() {
        vec![SOCKS5_NO_AUTH]
    } else {
        vec![SOCKS5_NO_AUTH, SOCKS5_USERNAME_PASSWORD_AUTH] // Prefer no auth if available
    };

    let mut handshake = vec![SOCKS5_VERSION, auth_methods.len() as u8];
    handshake.extend(auth_methods);
    stream.write_all(&handshake).await?;

    // Read authentication method selection
    let mut method_response = [0u8; 2];
    stream.read_exact(&mut method_response).await?;

    if method_response[0] != SOCKS5_VERSION {
        return Err(anyhow!("Invalid SOCKS5 version in response: 0x{:02x}", method_response[0]));
    }

    let selected_method = method_response[1];

    // Handle username/password authentication if required
    if selected_method == SOCKS5_USERNAME_PASSWORD_AUTH {
        let uname_bytes = username.as_bytes();
        let pass_bytes = password.as_bytes();

        if uname_bytes.len() > 255 || pass_bytes.len() > 255 {
            return Err(anyhow!("SOCKS5 authentication credentials too long (max 255 bytes each)"));
        }

        // Send username/password authentication
        let mut auth_request = vec![
            0x01, // Version
            uname_bytes.len() as u8,
        ];
        auth_request.extend_from_slice(uname_bytes);
        auth_request.push(pass_bytes.len() as u8);
        auth_request.extend_from_slice(pass_bytes);

        stream.write_all(&auth_request).await?;

        // Read authentication response
        let mut auth_resp = [0u8; 2];
        stream.read_exact(&mut auth_resp).await?;

        if auth_resp[0] != 0x01 {
            return Err(anyhow!("Invalid SOCKS5 auth response version: 0x{:02x}", auth_resp[0]));
        }

        if auth_resp[1] != SOCKS5_AUTH_SUCCESS {
            return Err(anyhow!("SOCKS5 authentication failed with status: 0x{:02x}", auth_resp[1]));
        }
    } else if selected_method != SOCKS5_NO_AUTH {
        return Err(anyhow!("Unsupported SOCKS5 authentication method: 0x{:02x}", selected_method));
    }

    // Configure TCP keepalive (uses global config if args are None)
    if let Err(e) = crate::proxy::configure_tcp_keepalive(&stream, None, None, None) {
        warn!("Failed to set TCP keepalive for SOCKS5 UDP associate: {}", e);
    }

    // Send UDP associate request
    stream.write_all(&[
        SOCKS5_VERSION,
        SOCKS5_UDP_ASSOCIATE,
        SOCKS5_RESERVED,
        SOCKS5_ATYP_IPV4, // IPv4 address type
        0x00, 0x00, 0x00, 0x00, // 0.0.0.0 (bind to any)
        0x00, 0x00  // Port 0 (any port)
    ]).await?;

    // Read UDP associate response header
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    // Validate response format
    if header[0] != SOCKS5_VERSION {
        return Err(anyhow!("Invalid SOCKS5 version in UDP associate response: 0x{:02x}", header[0]));
    }

    if header[1] != SOCKS5_AUTH_SUCCESS {
        return Err(anyhow!("SOCKS5 UDP associate request failed with status: 0x{:02x}", header[1]));
    }

    if header[2] != SOCKS5_RESERVED {
        warn!("Non-zero reserved byte in SOCKS5 UDP associate response: 0x{:02x}", header[2]);
    }

    // Parse bind address and port from response
    let atyp = header[3];
    let send_to = match atyp {
        SOCKS5_ATYP_IPV4 => {
            let mut addr_port = [0u8; 6];
            stream.read_exact(&mut addr_port).await?;
            let bind_ip = Ipv4Addr::new(addr_port[0], addr_port[1], addr_port[2], addr_port[3]);
            let bind_port = u16::from_be_bytes([addr_port[4], addr_port[5]]);
            SocketAddr::new(IpAddr::V4(bind_ip), bind_port)
        }
        SOCKS5_ATYP_IPV6 => {
            let mut addr_port = [0u8; 18];
            stream.read_exact(&mut addr_port).await?;
            let ipv6_bytes: [u8; 16] = addr_port[0..16].try_into().unwrap();
            let ipv6 = Ipv6Addr::from(ipv6_bytes);
            let bind_port = u16::from_be_bytes([addr_port[16], addr_port[17]]);
            SocketAddr::new(IpAddr::V6(ipv6), bind_port)
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            let domain_len = len_byte[0] as usize;
            let mut domain_buf = vec![0u8; domain_len + 2];
            stream.read_exact(&mut domain_buf).await?;
            return Err(anyhow!("Domain addresses not supported in SOCKS5 UDP associate bind"));
        }
        _ => {
            return Err(anyhow!("Unsupported address type in SOCKS5 UDP associate response: 0x{:02x}", atyp));
        }
    };

    // FIX D: Per RFC 1928, if the bind address is a wildcard (0.0.0.0 or ::),
    // replace it with the actual proxy server IP from the TCP connection.
    // Otherwise the client connects UDP to localhost instead of the remote proxy.
    let send_to = {
        let is_wildcard = match send_to.ip() {
            IpAddr::V4(ip) => ip.is_unspecified(),  // 0.0.0.0
            IpAddr::V6(ip) => ip.is_unspecified(),  // ::
        };
        if is_wildcard {
            // Extract IP from proxy_addr "host:port"
            if let Some(colon_pos) = proxy_addr.rfind(':') {
                let host_part = &proxy_addr[..colon_pos];
                if let Ok(proxy_ip) = host_part.parse::<IpAddr>() {
                    let fixed = SocketAddr::new(proxy_ip, send_to.port());
                    info!(
                        "SOCKS5 UDP ASSOCIATE: Replacing wildcard bind address {} with proxy IP: {}",
                        send_to, fixed
                    );
                    fixed
                } else {
                    warn!(
                        "SOCKS5 UDP ASSOCIATE: bind address is wildcard {} but cannot parse proxy IP from '{}', using as-is",
                        send_to, proxy_addr
                    );
                    send_to
                }
            } else {
                warn!("SOCKS5 UDP ASSOCIATE: bind address is wildcard {} but proxy_addr '{}' has no port separator", send_to, proxy_addr);
                send_to
            }
        } else {
            send_to
        }
    };

    // Create and connect UDP socket for SOCKS5 communication
    let udp_socket = Arc::new(UdpSocket::bind("[::]:0").await?);
    
    // Set SO_MARK to avoid TPROXY loops for SOCKS5 UDP relay traffic (mark = 2)
    if let Err(e) = set_socket_mark(udp_socket.as_raw_fd(), 2) {
        warn!("Failed to set SO_MARK on SOCKS5 UDP socket: {}", e);
    }
    
    udp_socket.connect(send_to).await?;

    debug!("SOCKS5 UDP associate established with relay address: {}", send_to);

    // CRITICAL FIX: Keep TCP control connection alive
    // Per RFC 1928, the UDP relay terminates when the TCP control connection closes.
    // We wrap the stream in Arc so all clones of Socks5UdpSocket share ownership.
    // Monitoring is now done in the response task via the referenced stream.
    let tcp_stream = Arc::new(stream);

    Ok(Socks5UdpSocket {
        socket: udp_socket,
        tcp_control: tcp_stream,
    })
}

pub async fn send_udp_via_socks5(
    socks: &Socks5UdpSocket,
    target: SocketAddr,
    payload: &[u8],
) -> anyhow::Result<()> {
    let mut packet = vec![];

    match target.ip() {
        IpAddr::V4(ipv4) => {
            packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
            packet.extend_from_slice(&ipv4.octets());
        }
        IpAddr::V6(ipv6) => {
            packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]);
            packet.extend_from_slice(&ipv6.octets());
        }
    }

    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);

    socks.socket.send(&packet).await?;
    Ok(())
}

/// Handle incoming UDP packet for proxy routing
///
/// Processes UDP packets received through transparent proxying, determines routing
/// rules, manages sessions, and forwards packets to appropriate destinations.
///
/// # Arguments
/// * `client_addr` - Source client address
/// * `target` - Original destination address from TPROXY
/// * `payload` - UDP packet payload data
/// * `rules` - Rule engine for routing decisions
/// * `sessions` - Session cache for connection reuse
/// * `config` - UDP proxy configuration
/// * `domain_cache` - DNS cache for domain lookups
/// * `upstream_proxy_timeout` - Timeout for proxy connections
///
/// # Returns
/// * `Ok(())` - Packet processed successfully
/// * `Err` - Processing failed (network, routing, or configuration error)
pub async fn handle_udp_packet(
    client_addr: SocketAddr,
    target: SocketAddr,
    payload: Vec<u8>,
    rules: RuleEngine,
    sessions: Arc<DashMap<SessionKey, Arc<UdpSession>>>,
    config: Arc<Config>,
    domain_cache: Arc<DashMap<std::net::IpAddr, (String, std::time::Instant)>>,
    upstream_proxy_timeout: Duration,
    transparent_sender: Arc<TransparentUdpSender>,
) -> Result<()> {
    // Input validation
    if payload.is_empty() {
        return Err(anyhow!("Empty UDP payload received"));
    }

    if payload.len() > UDP_PACKET_BUFFER_SIZE {
        return Err(anyhow!("UDP payload too large: {} bytes (max: {})",
            payload.len(), UDP_PACKET_BUFFER_SIZE));
    }

    if client_addr.port() == 0 || target.port() == 0 {
        return Err(anyhow!("Invalid port: client={}, target={}", client_addr.port(), target.port()));
    }

    // Hard limit on session count to prevent FD exhaustion
    if sessions.len() >= MAX_UDP_SESSIONS {
        warn!(
            "UDP session limit reached ({}/{}) - dropping packet from {} to {}",
            sessions.len(),
            MAX_UDP_SESSIONS,
            client_addr,
            target
        );
        return Err(anyhow!("UDP session limit exceeded ({})", MAX_UDP_SESSIONS));
    }
    let target_ip = target.ip();
    let ip_str = target_ip.to_string();

    // Сначала ищем в кэше TCP->UDP
    let mut routing_domain: Option<String> = if let Some(domain) = find_domain_by_ip(target_ip, &domain_cache).await {
        debug!("UDP relay: Found domain {} for IP {} from TCP cache", domain, target_ip);
        Some(domain)
    } else {
        // Fallback к reverse DNS если нет в кэше
        debug!("UDP relay: No cached domain for IP {}, trying reverse DNS", target_ip);
        None
    };

    // If no domain, fallback to using IP string for routing decision (geoip check)
    let route_decision = if let Some(ref domain) = routing_domain {
        debug!("UDP relay: Using domain '{}' for IP {} to get routing decision", domain, target_ip);
        rules.get_routing_decision(domain)
    } else {
        debug!("UDP relay: No domain for IP {}, falling back to IP-based routing decision: '{}'", target_ip, ip_str);
        routing_domain = Some(ip_str.clone()); // Use IP for routing
        rules.get_routing_decision(&ip_str)
    };

    let (route, proxy_opt) = match route_decision {
        Some(RoutingDecision::Proxy(proxy)) => {
            debug!("UDP relay: Routing {} -> {} via proxy {}:{} (tag: {})",
                  client_addr, target, proxy.server_addr, proxy.server_port, proxy.tag);
            (SessionRoute::Proxy(proxy.server_addr.clone()), Some(proxy))
        },
        Some(RoutingDecision::Direct) => {
            debug!("UDP relay: Routing {} -> {} directly", client_addr, target);
            (SessionRoute::Direct, None)
        },
        None => {
            debug!("UDP relay: No rule for target {} (domain/IP: '{}'), routing through default proxy", target, routing_domain.as_deref().unwrap_or(&ip_str));
            if let Some(default_proxy) = rules.get_proxy_by_tag("default") {
                debug!("UDP relay: Using default proxy {}:{} for {}", default_proxy.server_addr, default_proxy.server_port, target);
                (SessionRoute::Proxy(default_proxy.server_addr.clone()), Some(default_proxy.clone()))
            } else {
                warn!("UDP relay: No default proxy configured, falling back to direct for {}", target);
                (SessionRoute::Direct, None)
            }
        }
    };

    // Create session key for caching and reuse
    let key = SessionKey::new(client_addr, target, route.clone());

    // Clone proxy_opt for potential retry after send failure and circuit breaker lookup
    let proxy_opt_for_retry = proxy_opt.clone();
    let proxy_opt_for_cb = proxy_opt.clone();

    // Try to get existing session or create new one
    let session = if let Some(existing) = sessions.get(&key) {
        let existing_session = existing.value();

        // Check if session is still valid
        if existing_session.is_expired() {
            debug!("UDP session expired, removing and creating new one");
            remove_udp_session(&key, &sessions);
            create_new_session(&key, proxy_opt, &sessions, &config, upstream_proxy_timeout, transparent_sender.clone()).await?
        } else {
            debug!("Reusing existing UDP session (age: {}s)", existing_session.age());
            existing_session.clone()
        }
    } else {
        create_new_session(&key, proxy_opt, &sessions, &config, upstream_proxy_timeout, transparent_sender.clone()).await?
    };

    // Send packet through the session; on error, check if persistent and handle accordingly
    match session.send(target, &payload).await {
        Ok(()) => {
            // FIX 1: Record success for circuit breaker recovery.
            // Previously, UDP sends NEVER called record_success, making it
            // impossible for the circuit breaker to recover through UDP traffic.
            // The SoftRecovery state requires N successes to transition to Healthy,
            // but without this call, UDP successes were invisible to the circuit breaker.
            //
            // Rate-limited (max 1 call/sec/proxy) to avoid hot-path overhead
            // under QUIC traffic (thousands of packets per second).
            if let Some(proxy_addr) = proxy_addr_from_route(key.route(), &proxy_opt_for_retry) {
                record_udp_success_rate_limited(&proxy_addr);
            }
            Ok(())
        }
        Err(e) => {
            let persistent = is_persistent_send_error(&e);
            let route_label = if key.route().is_proxy() { "proxy" } else { "direct" };

            if persistent {
                // Persistent error (EACCES, EPERM, etc.) — trigger circuit breaker, do NOT retry.
                // Retrying will just waste TCP connections and UDP sockets.
                if let Some(proxy_addr) = proxy_addr_from_route(key.route(), &proxy_opt_for_retry) {
                    proxy_health::record_failure(&proxy_addr, &e.to_string());
                    error!(
                        "UDP send persistent error for {} -> {} via {} ({}), circuit breaker notified: {}",
                        client_addr, target, proxy_addr, route_label, e
                    );
                } else {
                    error!(
                        "UDP send persistent error for {} -> {} ({}), no retry: {}",
                        client_addr, target, route_label, e
                    );
                }
                session.mark_inactive();
                remove_udp_session(&key, &sessions);
                Err(e)
            } else {
                // Transient error — invalidate session and retry once with a fresh session
                warn!(
                    "UDP send failed for {} -> {} ({}), invalidating session and retrying: {}",
                    client_addr, target, route_label, e
                );
                session.mark_inactive();
                remove_udp_session(&key, &sessions);

                match create_new_session(&key, proxy_opt_for_retry, &sessions, &config, upstream_proxy_timeout, transparent_sender).await {
                    Ok(new_session) => {
                        new_session.send(target, &payload).await.map_err(|e2| {
                            // Second failure — check if persistent, trigger circuit breaker
                            if is_persistent_send_error(&e2) {
                                remove_udp_session(&key, &sessions);
                                if let Some(proxy_addr) = proxy_addr_from_route(key.route(), &proxy_opt_for_cb) {
                                    proxy_health::record_failure(&proxy_addr, &e2.to_string());
                                    error!(
                                        "UDP send retry persistent error for {} -> {} via {}, circuit breaker notified: {}",
                                        client_addr, target, proxy_addr, e2
                                    );
                                }
                            }
                            new_session.mark_inactive();
                            remove_udp_session(&key, &sessions);
                            anyhow!("UDP send retry also failed for {} -> {}: {}", client_addr, target, e2)
                        })
                    }
                    Err(e2) => {
                        warn!("Failed to create replacement UDP session for {} -> {}: {}", client_addr, target, e2);
                        Err(anyhow!("UDP session recreation failed: {} (original error: {})", e2, e))
                    }
                }
            }
        }
    }
}

// Circuit breaker now uses the shared ProxyHealthTracker from proxy_health module.
// See proxy_health::record_failure() and proxy_health::is_healthy().

/// Check if an error is persistent (not worth retrying).
///
/// Persistent errors include:
/// - EACCES (os error 13): Permission denied — typically caused by firewall/ICMP admin-prohibited
/// - EPERM (os error 1): Operation not permitted — security policy rejection
/// - ENETUNREACH (os error 101): Network unreachable — no route to host
/// - EHOSTUNREACH (os error 113): Host unreachable — no path to destination
///
/// These errors will not resolve by retrying with a new session, so we should
/// trigger the circuit breaker and avoid wasting resources on retries.
fn is_persistent_send_error(err: &anyhow::Error) -> bool {
    let err_str = err.to_string();
    err_str.contains("os error 13)")  // EACCES - Permission denied (closing ) avoids matching os error 130, 131, etc.)
        || err_str.contains("os error 1)")  // EPERM - note the ) to avoid matching os error 1xx
        || err_str.contains("os error 101") // ENETUNREACH - Network unreachable
        || err_str.contains("os error 113") // EHOSTUNREACH - No route to host
        || err_str.contains("Permission denied")
        || err_str.contains("Network is unreachable")
}

/// Extract proxy address from a SessionRoute, formatted as "host:port"
fn proxy_addr_from_route(route: &SessionRoute, proxy_opt: &Option<Proxy>) -> Option<String> {
    match route {
        SessionRoute::Proxy(_) => {
            proxy_opt.as_ref().map(|p| format!("{}:{}", p.server_addr, p.server_port))
        }
        SessionRoute::Direct => None,
    }
}

/// Create a new UDP session based on routing decision.
///
/// NO FALLBACK: If a proxy is assigned but unavailable (circuit breaker open or
/// Coalesced session creation: multiple parallel packets for the same flow
/// join a single creation task instead of spawning N associations.
async fn create_new_session(
    key: &SessionKey,
    proxy_opt: Option<Proxy>,
    sessions: &Arc<DashMap<SessionKey, Arc<UdpSession>>>,
    config: &Arc<Config>,
    upstream_proxy_timeout: Duration,
    transparent_sender: Arc<TransparentUdpSender>,
) -> Result<Arc<UdpSession>> {
    // 1. Check if another task is already creating this session
    if let Some(mut rx) = IN_FLIGHT_SESSIONS.get(key).map(|v| v.value().clone()) {
        debug!("Joining in-flight UDP session creation for {} -> {}", key.client, key.target);
        
        // Wait for next update (or use current if already finished)
        {
            let current = rx.borrow();
            if let Some(ref session) = *current {
                return Ok(session.clone());
            }
        }
        
        if rx.changed().await.is_err() {
            return Err(anyhow!("In-flight UDP session creation failed or cancelled"));
        }
        
        let result = rx.borrow().as_ref().cloned();
        return result.ok_or_else(|| anyhow!("In-flight UDP session creation failed"));
    }

    // 2. We are the creators
    let (tx, rx) = tokio::sync::watch::channel(None);
    IN_FLIGHT_SESSIONS.insert(key.clone(), rx);
    
    debug!("Creating new UDP session for {} -> {} (lead task)", key.client, key.target);
    let result = create_new_session_internal(key, proxy_opt, sessions, config, upstream_proxy_timeout, transparent_sender).await;
    
    match result {
        Ok(session) => {
            let _ = tx.send(Some(session.clone()));
            IN_FLIGHT_SESSIONS.remove(key);
            Ok(session)
        }
        Err(e) => {
            // Error - ensure watchers are notified of failure
            IN_FLIGHT_SESSIONS.remove(key);
            Err(e)
        }
    }
}

async fn create_new_session_internal(
    key: &SessionKey,
    proxy_opt: Option<Proxy>,
    sessions: &Arc<DashMap<SessionKey, Arc<UdpSession>>>,
    config: &Arc<Config>,
    upstream_proxy_timeout: Duration,
    transparent_sender: Arc<TransparentUdpSender>,
) -> Result<Arc<UdpSession>> {
    let new_session = match proxy_opt {
        Some(proxy) => {
            let proxy_addr = format!("{}:{}", proxy.server_addr, proxy.server_port);

            // Circuit breaker: fast-fail if proxy is known to be down.
            if !proxy_health::is_healthy(&proxy_addr) {
                warn!(
                    "UDP proxy {} unavailable (circuit breaker open), rejecting {} -> {}",
                    proxy_addr, key.client, key.target
                );
                return Err(anyhow!("Proxy {} is unavailable (circuit breaker open)", proxy_addr));
            }

            // Choose UDP mode based on proxy configuration
            let use_tcp_tunnel = proxy.udp_mode == UdpMode::TcpTunnel;

            if use_tcp_tunnel {
                // UDP-over-TCP tunnel mode (recommended for Yggdrasil/cheburnet)
                match UdpSession::new_tcp_tunnel(
                    key.client,
                    key.target,
                    key.clone(),
                    sessions.clone(),
                    proxy,
                    config.clone(),
                    upstream_proxy_timeout,
                    transparent_sender,
                ).await {
                    Ok(session) => {
                        // NOTE: Do NOT call record_success here. TCP tunnel/SOCKS5 handshake
                        // success only proves TCP connectivity to the proxy, not that the
                        // UDP data plane works. When the tunnel has MTU issues, TCP handshakes
                        // succeed (small packets) but UDP data sends fail (larger packets),
                        // causing record_success to continuously reset the failure counter
                        // and preventing the circuit breaker from ever tripping.
                        // Recovery is handled by the health probe in proxy_health.
                        session
                    }
                    Err(e) => {
                        proxy_health::record_failure(&proxy_addr, &e.to_string());
                        warn!(
                            "TCP tunnel UDP session failed for {} (no fallback): {}",
                            proxy_addr, e
                        );
                        return Err(e);
                    }
                }
            } else {
                // Standard SOCKS5 UDP ASSOCIATE mode
                match UdpSession::new_socks5(
                    key.client,
                    key.target,
                    key.clone(),
                    sessions.clone(),
                    proxy,
                    config.clone(),
                    upstream_proxy_timeout,
                    transparent_sender,
                ).await {
                    Ok(session) => {
                        // NOTE: Do NOT call record_success here — same reason as TCP tunnel above.
                        // SOCKS5 UDP ASSOCIATE handshake success doesn't prove the UDP data plane works.
                        session
                    }
                    Err(e) => {
                        proxy_health::record_failure(&proxy_addr, &e.to_string());
                        warn!(
                            "SOCKS5 UDP association failed for {} (no fallback): {}",
                            proxy_addr, e
                        );
                        return Err(e);
                    }
                }
            }
        }
        None => {
            UdpSession::new_direct(
                key.client,
                key.target,
                key.clone(),
                sessions.clone(),
                config.clone(),
                upstream_proxy_timeout,
                transparent_sender,
            ).await?
        }
    };

    if sessions.insert(key.clone(), new_session.clone()).is_none() {
        GLOBAL_UDP_SESSION_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    Ok(new_session)
}

/// Run the UDP transparent proxy server
///
/// Starts a UDP proxy that intercepts traffic using TPROXY (Linux iptables) and
/// routes packets based on configured rules. Supports both direct routing and
/// SOCKS5 proxy routing with UDP desynchronization for DPI bypass.
///
/// # Arguments
/// * `rules` - Rule engine for making routing decisions
/// * `config` - UDP proxy configuration settings
/// * `domain_cache` - DNS cache for domain-based routing decisions
/// * `upstream_proxy_timeout` - Timeout for upstream proxy connections
///
/// # Returns
/// * `Ok(())` - Proxy started successfully and ran until shutdown
/// * `Err` - Failed to start proxy due to configuration or socket error
///
/// # Features
/// - Transparent proxying with TPROXY (Linux iptables integration)
/// - SOCKS5 UDP associate support for proxy chaining
/// - UDP desynchronization for DPI bypass
/// - Session management with TTL-based cleanup
/// - Concurrent packet processing with overload protection
/// - Comprehensive error handling and logging
pub async fn run_udp_proxy(
    rules: RuleEngine,
    config: Arc<Config>,
    domain_cache: Arc<DashMap<std::net::IpAddr, (String, std::time::Instant)>>,
    upstream_proxy_timeout: Duration,
) -> Result<()> {
    info!("Starting UDP proxy on port {} with config: desync_enabled={}, min_size={}, max_size={}",
          config.port, config.udp_desync_enabled, config.udp_desync_min_size, config.udp_desync_max_size);

    // Bind separate IPv4 and IPv6 sockets.
    // Relying on a single "dual-stack" [::]:PORT socket is fragile because
    // net.ipv6.bindv6only=1 (or socket-level IPV6_V6ONLY=1) prevents IPv4 QUIC
    // packets from reaching the listener.
    let ipv4_addr = format!("0.0.0.0:{}", config.port);
    let ipv4_socket = Arc::new(UdpSocket::bind(&ipv4_addr).await?);
    info!("IPv4 UDP socket bound to {}", ipv4_addr);
    let ipv4_fd = ipv4_socket.as_ref().as_raw_fd();

    let ipv6_addr = format!("[::]:{}", config.port);
    let ipv6_socket = match UdpSocket::bind(&ipv6_addr).await {
        Ok(socket) => {
            info!("IPv6 UDP socket bound to {}", ipv6_addr);
            Some(Arc::new(socket))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            warn!("IPv6 UDP bind failed with address in use, skipping IPv6 support");
            None
        }
        Err(e) => return Err(anyhow!("Failed to bind IPv6 UDP socket: {}", e)),
    };
    let ipv6_fd = ipv6_socket.as_ref().map(|s| s.as_raw_fd());

    let sessions: Arc<DashMap<SessionKey, Arc<UdpSession>>> = Arc::new(DashMap::new());

    // PHASE 1 FIX: Create shared transparent UDP sender (only 2 FDs for all flows)
    let transparent_sender = TransparentUdpSender::new()?;
    info!("Shared TransparentUdpSender initialized - replaces per-flow sender sockets");

    // Spawn periodic cleanup for expired sessions with optimized performance
    let cleanup_sessions = sessions.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(UDP_SESSION_CLEANUP_INTERVAL_SECONDS));
        loop {
            interval.tick().await;

            let start_time = Instant::now();
            let mut removed = 0usize;

            // Collect expired session keys efficiently
            let keys_to_remove: Vec<SessionKey> = cleanup_sessions
                .iter()
                .filter_map(|entry| {
                    let session = entry.value();
                    if session.is_expired() {
                        Some(entry.key().clone())
                    } else {
                        None
                    }
                })
                .collect();

            // Remove expired sessions - first mark them inactive to stop response tasks
            for key in &keys_to_remove {
                if let Some(session) = cleanup_sessions.get(key) {
                    // Signal response task to stop
                    session.mark_inactive();
                }
            }
            
            // Give response tasks time to notice the inactive flag and exit gracefully
            if !keys_to_remove.is_empty() {
                sleep(Duration::from_millis(100)).await;
            }
            
            // Now remove the sessions
            for key in keys_to_remove {
                remove_udp_session(&key, &cleanup_sessions);
                removed += 1;
            }

            // Log cleanup statistics with session count
            let total_sessions = cleanup_sessions.len();
            if removed > 0 || total_sessions > 1000 {
                let duration = start_time.elapsed();
                info!(
                    "UDP sessions: {} active (removed {} expired in {:?})",
                    total_sessions, removed, duration
                );
            }

            // Adaptive cleanup interval based on removal rate
            // If many sessions are being removed, cleanup more frequently
            if removed > 100 {
                interval = tokio::time::interval(Duration::from_secs(UDP_SESSION_CLEANUP_INTERVAL_SECONDS / 2));
            }
        }
    });


    // Set transparent proxy options for IPv4 and IPv6 sockets.
    // NOTE: SO_MARK must match the fwmark used in iptables/nftables TPROXY rule.
    let one = 1i32;
    let mark = 1i32;
    unsafe {
        // ---- IPv4 socket options ----
        let ret = libc::setsockopt(
            ipv4_fd,
            SOL_IP,
            IP_TRANSPARENT,
            &one as *const _ as *const _,
            mem::size_of::<i32>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(anyhow!("Failed to set IP_TRANSPARENT (IPv4): {}", std::io::Error::last_os_error()));
        }

        let ret = libc::setsockopt(
            ipv4_fd,
            libc::SOL_SOCKET,
            SO_MARK,
            &mark as *const _ as *const _,
            mem::size_of::<i32>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(anyhow!("Failed to set SO_MARK (IPv4): {}", std::io::Error::last_os_error()));
        }

        let ret = libc::setsockopt(
            ipv4_fd,
            SOL_IP,
            IP_RECVORIGDSTADDR,
            &one as *const _ as *const _,
            mem::size_of::<i32>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(anyhow!("Failed to set IP_RECVORIGDSTADDR (IPv4): {}", std::io::Error::last_os_error()));
        }

        // ---- IPv6 socket options ----
        if let Some(ipv6_fd) = ipv6_fd {
            let ret = libc::setsockopt(
                ipv6_fd,
                SOL_IPV6,
                IPV6_TRANSPARENT,
                &one as *const _ as *const _,
                mem::size_of::<i32>() as libc::socklen_t,
            );
            if ret != 0 {
                return Err(anyhow!("Failed to set IPV6_TRANSPARENT (IPv6): {}", std::io::Error::last_os_error()));
            }

            let ret = libc::setsockopt(
                ipv6_fd,
                libc::SOL_SOCKET,
                SO_MARK,
                &mark as *const _ as *const _,
                mem::size_of::<i32>() as libc::socklen_t,
            );
            if ret != 0 {
                return Err(anyhow!("Failed to set SO_MARK (IPv6): {}", std::io::Error::last_os_error()));
            }

            let ret = libc::setsockopt(
                ipv6_fd,
                SOL_IPV6,
                IPV6_RECVORIGDSTADDR,
                &one as *const _ as *const _,
                mem::size_of::<i32>() as libc::socklen_t,
            );
            if ret != 0 {
                return Err(anyhow!("Failed to set IPV6_RECVORIGDSTADDR (IPv6): {}", std::io::Error::last_os_error()));
            }
        }
    }

    // Single success message after everything is set up
    let listener_desc = if ipv6_socket.is_some() { "separate IPv4+IPv6 listeners" } else { "IPv4 only listener" };
    
    println!("Listening UDP on port {} (transparent mode, {})", config.port, listener_desc);
    
    // Use semaphore to limit concurrent packet processing and prevent overload
    let semaphore = Arc::new(Semaphore::new(UDP_CONCURRENT_PROCESSING_LIMIT));

    let rules = rules.clone();
    let sessions = sessions.clone();
    let config = config.clone();
    let domain_cache = domain_cache.clone();
    let upstream_proxy_timeout = upstream_proxy_timeout;

    // Spawn IPv4 and IPv6 packet receivers with better error handling
    let spawn_receiver = |socket: Arc<UdpSocket>, label: &'static str| {
        let semaphore = semaphore.clone();
        let rules = rules.clone();
        let sessions = sessions.clone();
        let config = config.clone();
        let domain_cache = domain_cache.clone();
        let upstream_proxy_timeout = upstream_proxy_timeout;
        let transparent_sender = transparent_sender.clone();

        tokio::spawn(async move {
            let mut consecutive_errors = 0u32;
            const MAX_CONSECUTIVE_ERRORS: u32 = 10;

            loop {
                match recv_udp_packet_with_orig_dst(&socket).await {
                Ok(packet) => {
                    let UdpPacket {
                        data,
                        original_dst,
                        client_addr,
                    } = packet;

                    consecutive_errors = 0;

                    debug!(
                        "UDP packet [{}]: client={} -> target={} ({} bytes)",
                        label,
                        client_addr,
                        original_dst,
                        data.len()
                    );

                    if data.is_empty() {
                        debug!("Received empty UDP packet from {}, skipping", client_addr);
                        continue;
                    }

                    // Process packet with semaphore to limit concurrency
                    let semaphore = semaphore.clone();
                    let rules = rules.clone();
                    let sessions = sessions.clone();
                    let config = config.clone();
                    let domain_cache = domain_cache.clone();
                    let upstream_proxy_timeout = upstream_proxy_timeout;
                    let target_addr = original_dst;
                    let client_address = client_addr;
                    let transparent_sender = transparent_sender.clone();

                    tokio::spawn(async move {
                        let _permit = match semaphore.try_acquire() {
                            Ok(permit) => permit,
                            Err(_) => {
                                warn!("UDP packet processing overload, dropping packet from {} to {}", client_address, target_addr);
                                return;
                            }
                        };

                        if let Err(e) = handle_udp_packet(
                            client_address,
                            target_addr,
                            data,
                            rules,
                            sessions,
                            config,
                            domain_cache,
                            upstream_proxy_timeout,
                            transparent_sender,
                        ).await {
                            warn!(
                                "Error processing UDP packet from {} to {}: {}",
                                client_address, target_addr, e
                            );
                        }
                    });
                }
                Err(e) => {
                    if e.to_string().contains("would block") {
                        sleep(Duration::from_millis(1)).await;
                        continue;
                    }

                    consecutive_errors += 1;

                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                        warn!(
                            "Too many consecutive UDP packet errors on [{}] ({}), possible socket issue: {}",
                            label,
                            consecutive_errors,
                            e
                        );
                        consecutive_errors = 0;
                    } else {
                        debug!("UDP packet receiver error on [{}]: {}", label, e);
                    }

                    sleep(Duration::from_millis(1)).await;
                }
            }
        }
        })
    };

    // Run both listeners. This avoids dependency on v4-mapped IPv6 sockets and
    // guarantees IPv4 QUIC (UDP/443) reaches the proxy.
    spawn_receiver(ipv4_socket.clone(), "ipv4");
    if let Some(ref ipv6_socket) = ipv6_socket {
        spawn_receiver(ipv6_socket.clone(), "ipv6");
    }
    
    Ok(())
}
