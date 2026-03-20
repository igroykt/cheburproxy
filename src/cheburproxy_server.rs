//! SOCKS5 Proxy Server Implementation
//!
//! A high-performance SOCKS5 proxy server with connection pooling,
//! authentication support, UDP forwarding, and UDP-over-TCP tunnel capabilities.

use std::env;
use std::process;
use toml::Value;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use env_logger;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use std::sync::Arc;
use std::collections::HashMap;
use std::collections::VecDeque;
use log::{debug, error, info, warn};
use std::sync::atomic::{AtomicBool, Ordering};

use std::time::Duration;
use tokio::time::timeout;
use std::fmt;
use std::io;

// UDP-over-TCP tunnel framing
mod udp_tunnel_frame;
use udp_tunnel_frame::{SOCKS5_CMD_UDP_TUNNEL, read_frame, write_frame};

// Configuration constants
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(30);
const UDP_ASSOCIATE_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes for idle UDP associate TCP keepalive
const MAX_UDP_MAP_SIZE: usize = 1000;

// Buffer sizes
const TCP_BUFFER_SIZE: usize = 8192;
const UDP_BUFFER_SIZE: usize = 65536;

// SOCKS5 protocol constants
const SOCKS_VERSION: u8 = 5;
const SOCKS_AUTH_NO_AUTH: u8 = 0;
const SOCKS_AUTH_USERNAME_PASSWORD: u8 = 2;
const SOCKS_AUTH_NO_ACCEPTABLE: u8 = 0xFF;
const SOCKS_CMD_CONNECT: u8 = 1;
const SOCKS_CMD_UDP_ASSOCIATE: u8 = 3;
const SOCKS_ATYP_IPV4: u8 = 1;
const SOCKS_ATYP_DOMAIN: u8 = 3;
const SOCKS_ATYP_IPV6: u8 = 4;
const SOCKS_REP_SUCCESS: u8 = 0;
const SOCKS_UDP_FRAGMENT: u8 = 0;

/// Specific error types for better error handling
#[derive(Debug)]
pub enum ProxyError {
    /// SOCKS protocol errors
    SocksProtocol(String),
    /// Authentication errors
    Authentication(String),
    /// DNS resolution errors
    DnsResolution(String),
    /// Connection errors
    Connection(String),
    /// Configuration errors
    Configuration(String),
    /// I/O errors
    Io(io::Error),
    /// Timeout errors
    Timeout(String),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::SocksProtocol(msg) => write!(f, "SOCKS protocol error: {}", msg),
            ProxyError::Authentication(msg) => write!(f, "Authentication error: {}", msg),
            ProxyError::DnsResolution(msg) => write!(f, "DNS resolution error: {}", msg),
            ProxyError::Connection(msg) => write!(f, "Connection error: {}", msg),
            ProxyError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            ProxyError::Io(err) => write!(f, "I/O error: {}", err),
            ProxyError::Timeout(msg) => write!(f, "Timeout error: {}", msg),
        }
    }
}

impl std::error::Error for ProxyError {}

impl From<io::Error> for ProxyError {
    fn from(err: io::Error) -> Self {
        ProxyError::Io(err)
    }
}

impl From<hickory_resolver::error::ResolveError> for ProxyError {
    fn from(err: hickory_resolver::error::ResolveError) -> Self {
        ProxyError::DnsResolution(err.to_string())
    }
}

impl From<anyhow::Error> for ProxyError {
    fn from(err: anyhow::Error) -> Self {
        ProxyError::Configuration(err.to_string())
    }
}

impl From<toml::de::Error> for ProxyError {
    fn from(err: toml::de::Error) -> Self {
        ProxyError::Configuration(format!("TOML parsing error: {}", err))
    }
}

type ProxyResult<T> = Result<T, ProxyError>;

/// Create a new connection with timeout
async fn create_new_connection(addr: SocketAddr) -> ProxyResult<TcpStream> {
    let connect_future = TcpStream::connect(addr);
    let stream = timeout(DEFAULT_CONNECT_TIMEOUT, connect_future).await
        .map_err(|_| ProxyError::Timeout(format!("Connection timeout to {}", addr)))?
        .map_err(|e| ProxyError::Connection(format!("Failed to connect to {}: {}", addr, e)))?;

    debug!("Created new connection to {}", addr);
    Ok(stream)
}



/// Configuration for server authentication
#[derive(Clone)]
struct ServerConfig {
    listen: String,
    port: u16,
    udp_port: Option<u16>,
    username: String,
    password: String,
    require_auth: bool,
}

impl ServerConfig {
    fn from_toml(value: &Value) -> anyhow::Result<Self> {
        let general = value.get("general")
            .ok_or(anyhow::anyhow!("Missing [general] section in config"))?;

        let listen = general.get("listen")
            .and_then(|v| v.as_str())
            .ok_or(anyhow::anyhow!("Missing or invalid 'listen' in [general]"))?
            .to_string();

        let port: u16 = general.get("port")
            .and_then(|v| v.as_integer())
            .map(|p| p as u16)
            .ok_or(anyhow::anyhow!("Missing or invalid 'port' in [general]"))?;

        if port == 0 || port > 65535 {
            return Err(anyhow::anyhow!("Invalid port: must be between 1 and 65535"));
        }

        let udp_port: Option<u16> = general.get("udp_port")
            .and_then(|v| v.as_integer())
            .map(|p| p as u16);

        if let Some(uport) = udp_port {
            if uport == 0 || uport > 65535 || uport == port {
                return Err(anyhow::anyhow!("Invalid udp_port: must be between 1 and 65535, different from port"));
            }
        }

        let username = general.get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let password = general.get("password")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let require_auth = !username.is_empty() && !password.is_empty();

        // cheburproxy-server always operates in SOCKS5 proxy mode

        // Validate listen address - support both IPv4 and IPv6
        // Try to parse as IpAddr first
        if listen != "0.0.0.0" && listen != "::" && !listen.is_empty() {
            listen.parse::<std::net::IpAddr>()
                .map_err(|_| anyhow::anyhow!("Invalid listen address '{}': must be a valid IPv4 or IPv6 address", listen))?;
        }

        Ok(ServerConfig {
            listen,
            port,
            udp_port,
            username,
            password,
            require_auth,
        })
    }

}

/// Handle SOCKS5 authentication with improved error handling and timeouts
async fn handle_socks5_auth(stream: &mut TcpStream, config: &ServerConfig) -> ProxyResult<()> {
    let mut buf = [0u8; 256];

    // Read authentication methods
    stream.read_exact(&mut buf[..2]).await?;
    if buf[0] != 5 {
        return Err(ProxyError::SocksProtocol("Only SOCKS5 supported".to_string()));
    }
    let nmethods = buf[1] as usize;
    stream.read_exact(&mut buf[..nmethods]).await?;

    let supports_no_auth = buf[..nmethods].contains(&0);
    let supports_username_password = buf[..nmethods].contains(&2);

    // Choose authentication method
    if config.require_auth {
        if supports_username_password {
            // Require username/password auth
            stream.write_all(&[5u8, 2u8][..]).await?;
        } else {
            // Client doesn't support username/password auth but we require it
            stream.write_all(&[5u8, 0xFFu8][..]).await?; // No acceptable methods
            return Err(ProxyError::Authentication("Username/password authentication required but not supported by client".to_string()));
        }

        // Read username/password auth request
        stream.read_exact(&mut buf[..2]).await?;
        if buf[0] != 1 { // Username/password auth version
            return Err(ProxyError::SocksProtocol("Invalid auth version".to_string()));
        }
        let ulen = buf[1] as usize;
        if ulen > 255 || ulen == 0 {
            return Err(ProxyError::SocksProtocol("Invalid username length".to_string()));
        }

        let mut username_buf = vec![0u8; ulen];
        stream.read_exact(&mut username_buf).await?;
        let username = String::from_utf8_lossy(&username_buf).to_string();

        let mut plen_buf = [0u8; 1];
        stream.read_exact(&mut plen_buf[..]).await?;
        let plen = plen_buf[0] as usize;
        if plen > 255 || plen == 0 {
            return Err(ProxyError::SocksProtocol("Invalid password length".to_string()));
        }

        let mut password_buf = vec![0u8; plen];
        stream.read_exact(&mut password_buf).await?;
        let password = String::from_utf8_lossy(&mut password_buf).to_string();

        if username != config.username || password != config.password {
            // Authentication failed
            stream.write_all(&[1u8, 1u8][..]).await?; // 1 = failure
            return Err(ProxyError::Authentication("Authentication failed".to_string()));
        }

        // Authentication successful
        stream.write_all(&[1u8, 0u8][..]).await?; // 0 = success
    } else {
        if supports_no_auth {
            // No authentication required
            stream.write_all(&[5u8, 0u8][..]).await?;
        } else {
            // Client requires auth but we don't support any
            stream.write_all(&[5u8, 0xFFu8][..]).await?; // No acceptable methods
            return Err(ProxyError::Authentication("No authentication method supported".to_string()));
        }
    }

    Ok(())
}

/// Returns a shared, lazily-initialized DNS resolver.
/// Using a singleton avoids spawning new background tasks and UDP sockets on every DNS call.
fn get_shared_resolver() -> &'static TokioAsyncResolver {
    use std::sync::OnceLock;
    static RESOLVER: OnceLock<TokioAsyncResolver> = OnceLock::new();
    RESOLVER.get_or_init(|| {
        let mut resolver_config = ResolverConfig::new();
        resolver_config.add_name_server(NameServerConfig {
            socket_addr: "8.8.8.8:53".parse().unwrap(),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            tls_config: None,
            bind_addr: None,
        });
        resolver_config.add_name_server(NameServerConfig {
            socket_addr: "1.1.1.1:53".parse().unwrap(),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            tls_config: None,
            bind_addr: None,
        });
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.ndots = 0;
        resolver_opts.timeout = DEFAULT_DNS_TIMEOUT;
        TokioAsyncResolver::tokio(resolver_config, resolver_opts)
    })
}

/// Resolve domain name to IP address without using system config
/// This prevents search domain appending from /etc/resolv.conf
async fn resolve_domain_to_ip(domain: String) -> ProxyResult<Option<std::net::IpAddr>> {
    let resolver = get_shared_resolver();

    // Normalize domain to FQDN if it has dots
    let normalized = if domain.contains('.') && !domain.ends_with('.') {
        format!("{}.", domain)
    } else {
        domain.clone()
    };

    debug!("Resolving domain '{}' (normalized: '{}')", domain, normalized);

    let lookup_future = resolver.lookup_ip(normalized);
    let response = timeout(DEFAULT_DNS_TIMEOUT, lookup_future).await
        .map_err(|_| ProxyError::Timeout("DNS lookup timeout".to_string()))?
        .map_err(|e| ProxyError::DnsResolution(format!("DNS resolution failed for {}: {}", domain, e)))?;

    Ok(response.iter().next())
}


/// Parse SOCKS5 CONNECT request after header has been read
async fn handle_socks5_connect_request_after_header(stream: &mut TcpStream, atyp: u8, config: &ServerConfig) -> ProxyResult<(TcpStream, SocketAddr)> {
    let mut buf = [0u8; 256];

    let target_addr = match atyp {
        1 => { // IPv4
            stream.read_exact(&mut buf[..6]).await?;
            let ip = std::net::Ipv4Addr::from([buf[0], buf[1], buf[2], buf[3]]);
            let port = ((buf[4] as u16) << 8) | buf[5] as u16;
            SocketAddr::new(std::net::IpAddr::V4(ip), port)
        }
        3 => { // Domain name
            stream.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            if len > 255 || len == 0 {
                return Err(ProxyError::SocksProtocol("Invalid domain length".to_string()));
            }
            let mut domain_buf = vec![0u8; len];
            stream.read_exact(&mut domain_buf).await?;
            let domain = String::from_utf8_lossy(&domain_buf).to_string();

            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf[..]).await?;
            let port = ((port_buf[0] as u16) << 8) | (port_buf[1] as u16);

            // Resolve domain to IP (reuse shared resolver — no new background tasks or sockets)
            let resolver = get_shared_resolver();

            // Normalize domain to FQDN
            let normalized_domain = if domain.contains('.') && !domain.ends_with('.') {
                format!("{}.", domain)
            } else {
                domain.clone()
            };

            let lookup_future = resolver.lookup_ip(normalized_domain);
            let response = timeout(DEFAULT_DNS_TIMEOUT, lookup_future).await
                .map_err(|_| ProxyError::Timeout("DNS lookup timeout".to_string()))?
                .map_err(|e| ProxyError::DnsResolution(format!("DNS resolution failed for {}: {}", domain, e)))?;
            let ip_addr = response.iter().next()
                .ok_or_else(|| ProxyError::DnsResolution(format!("No IP addresses found for domain: {}", domain)))?;
            SocketAddr::new(ip_addr, port)
        }
        4 => { // IPv6
            stream.read_exact(&mut buf[..18]).await?;
            let ip = std::net::Ipv6Addr::from([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]
            ]);
            let port = ((buf[16] as u16) << 8) | buf[17] as u16;
            SocketAddr::new(std::net::IpAddr::V6(ip), port)
        }
        _ => return Err(ProxyError::SocksProtocol("Unsupported address type".to_string())),
    };

    // Prevent connecting to self (loop prevention).
    // Check BOTH the destination IP and port; comparing only the port would block
    // legitimate connections to external services that happen to use the same port.
    let is_self_loop = if target_addr.port() == config.port {
        // Use the TCP connection's local address to determine which IP we are bound to.
        match stream.local_addr() {
            Ok(local) => target_addr.ip() == local.ip(),
            // If we cannot determine the local IP, conservatively allow the connection.
            Err(_) => false,
        }
    } else {
        false
    };
    if is_self_loop {
        // Send failure response
        stream.write_all(&[5u8, 1u8, 0u8, 1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8][..]).await?;
        return Err(ProxyError::Connection("Cannot connect to self (loop prevention)".to_string()));
    }

    // Send success response
    stream.write_all(&[5u8, 0u8, 0u8, 1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8][..]).await?;

    // Create new connection
    let target_stream = create_new_connection(target_addr).await?;
    debug!("Connected to target: {}", target_addr);

    Ok((target_stream, target_addr))
}

/// Classify whether an IO error is a normal data-plane event
/// (peer disconnect, broken pipe, connection reset) rather than a real infrastructure error.
fn is_data_plane_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionReset     // ECONNRESET (104)
        | io::ErrorKind::BrokenPipe        // EPIPE (32)
        | io::ErrorKind::ConnectionAborted  // ECONNABORTED (103)
        | io::ErrorKind::NotConnected       // ENOTCONN (107)
        | io::ErrorKind::UnexpectedEof      // EOF during read
    )
}

async fn forward_streams(client: TcpStream, target: TcpStream) -> ProxyResult<()> {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut target_read, mut target_write) = target.into_split();

    let client_to_target = tokio::spawn(async move {
        let result = tokio::io::copy(&mut client_read, &mut target_write).await;
        // Explicitly shutdown write half to send FIN and prevent CLOSE_WAIT leak
        let _ = target_write.shutdown().await;
        result
    });

    let target_to_client = tokio::spawn(async move {
        let result = tokio::io::copy(&mut target_read, &mut client_write).await;
        // Explicitly shutdown write half to send FIN and prevent CLOSE_WAIT leak
        let _ = client_write.shutdown().await;
        result
    });

    // Wait for BOTH directions (don't fail fast)
    let (c2t_result, t2c_result) = tokio::join!(client_to_target, target_to_client);

    let err1 = match c2t_result {
        Ok(Ok(_)) => None,
        Ok(Err(e)) => Some(e),
        Err(e) => return Err(ProxyError::Connection(format!("Task panicked: {}", e))),
    };
    let err2 = match t2c_result {
        Ok(Ok(_)) => None,
        Ok(Err(e)) => Some(e),
        Err(e) => return Err(ProxyError::Connection(format!("Task panicked: {}", e))),
    };

    // Classify errors: data-plane errors are normal and swallowed
    match (err1, err2) {
        (None, None) => Ok(()),
        (Some(e), None) | (None, Some(e)) => {
            if is_data_plane_error(&e) {
                debug!("Stream forwarding ended (peer disconnect): {}", e);
                Ok(())
            } else {
                Err(ProxyError::Io(e))
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
                (false, _) => Err(ProxyError::Io(e1)),
                (_, false) => Err(ProxyError::Io(e2)),
            }
        }
    }
}

async fn handle_tcp_connection(stream: TcpStream, config: Arc<ServerConfig>) -> ProxyResult<()> {
    let client_addr = stream.peer_addr()?;
    debug!("New TCP connection from: {}", client_addr);

    // Always expect SOCKS5 protocol
    let mut first_byte = [0u8; 1];
    match stream.peek(&mut first_byte[..]).await {
        Ok(1) => {
            if first_byte[0] == SOCKS_VERSION {
                // SOCKS5 protocol
                debug!("Handling SOCKS5 connection from {}", client_addr);
                handle_socks5_connection(stream, config).await
            } else {
                // Unexpected protocol
                debug!("Non-SOCKS5 connection from {}", client_addr);
                Err(ProxyError::SocksProtocol("Only SOCKS5 protocol supported".to_string()))
            }
        }
        Ok(_) => {
            // Not enough data
            debug!("Insufficient data for SOCKS5 detection from {}", client_addr);
            Err(ProxyError::SocksProtocol("Insufficient data for protocol detection".to_string()))
        }
        Err(e) => {
            error!("Failed to peek first byte from {}: {}", client_addr, e);
            Err(ProxyError::Io(e))
        }
    }
}


/// Handle SOCKS5 UDP associate request after header has been read
async fn handle_socks5_udp_associate_after_header(mut stream: TcpStream, atyp: u8, _config: &ServerConfig) -> ProxyResult<()> {
    let mut buf = [0u8; 256];

    let _dst_addr = match atyp {
        1 => { // IPv4
            stream.read_exact(&mut buf[..6]).await?;
            let ip = std::net::Ipv4Addr::from([buf[0], buf[1], buf[2], buf[3]]);
            let port = ((buf[4] as u16) << 8) | buf[5] as u16;
            SocketAddr::new(std::net::IpAddr::V4(ip), port)
        }
        3 => { // Domain
            stream.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            stream.read_exact(&mut buf[..len + 2]).await?;
            let port = ((buf[len] as u16) << 8) | buf[len + 1] as u16;
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), port)
        }
        4 => { // IPv6 — must consume all 16 address bytes + 2 port bytes (18 total)
            stream.read_exact(&mut buf[..18]).await?;
            let ip = std::net::Ipv6Addr::from([
                buf[0], buf[1], buf[2],  buf[3],  buf[4],  buf[5],  buf[6],  buf[7],
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]);
            let port = ((buf[16] as u16) << 8) | buf[17] as u16;
            SocketAddr::new(std::net::IpAddr::V6(ip), port)
        }
        _ => SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0)
    };

    // Bind UDP socket
    let udp_socket = UdpSocket::bind("[::]:0").await
        .map_err(|e| ProxyError::Connection(format!("Failed to bind UDP socket: {}", e)))?;
    let udp_addr = udp_socket.local_addr()
        .map_err(|e| ProxyError::Connection(format!("Failed to get UDP local addr: {}", e)))?;

    // FIX E: Replace wildcard bind address with the local IP from the TCP connection.
    // Per RFC 1928, the client uses this address to send UDP packets.
    // If we respond with 0.0.0.0 or ::, the client will send to localhost instead of us.
    let reply_addr = {
        let local_tcp_addr = stream.local_addr()
            .map_err(|e| ProxyError::Connection(format!("Failed to get TCP local addr: {}", e)))?;
        let udp_ip = udp_addr.ip();
        let is_wildcard = match udp_ip {
            std::net::IpAddr::V4(ip) => ip.is_unspecified(),
            std::net::IpAddr::V6(ip) => ip.is_unspecified(),
        };
        if is_wildcard {
            let fixed_addr = std::net::SocketAddr::new(local_tcp_addr.ip(), udp_addr.port());
            debug!("UDP ASSOCIATE: Replacing wildcard {} with TCP local IP: {}", udp_addr, fixed_addr);
            fixed_addr
        } else {
            udp_addr
        }
    };

    // Send success response with UDP address
    let (atyp, addr_bytes) = match reply_addr.ip() {
        std::net::IpAddr::V4(ip) => (SOCKS_ATYP_IPV4, ip.octets().to_vec()),
        std::net::IpAddr::V6(ip) => (SOCKS_ATYP_IPV6, ip.octets().to_vec()),
    };
    let port_bytes = reply_addr.port().to_be_bytes();
    let mut response = vec![
        5u8, 0, 0, atyp, // VER REP RSV ATYP
    ];
    response.extend_from_slice(&addr_bytes);
    response.extend_from_slice(&port_bytes);
    stream.write_all(&response).await?;

    // CRITICAL FIX: Use atomic flag to coordinate UDP handler exit with TCP keepalive
    let udp_active = Arc::new(AtomicBool::new(true));
    let udp_active_clone = udp_active.clone();
    
    // Spawn UDP handler
    tokio::spawn(async move {
        let mut buf = [0u8; UDP_BUFFER_SIZE];
        let mut target_to_client: std::collections::HashMap<SocketAddr, SocketAddr> = std::collections::HashMap::new();
        let mut udp_order: VecDeque<SocketAddr> = VecDeque::new();
        loop {
            match timeout(DEFAULT_UDP_TIMEOUT, udp_socket.recv_from(&mut buf)).await {
                Ok(Ok((size, recv_addr))) => {
                    if let Some((target_addr, payload)) = parse_udp_request_packet(&buf[..size]) {
                        // This is a request from client
                        if !target_to_client.contains_key(&target_addr) {
                            udp_order.push_back(target_addr);
                            if udp_order.len() > MAX_UDP_MAP_SIZE {
                                if let Some(old) = udp_order.pop_front() {
                                    target_to_client.remove(&old);
                                }
                            }
                        }
                        target_to_client.insert(target_addr, recv_addr);
                        if let Err(e) = udp_socket.send_to(payload, target_addr).await {
                            debug!("UDP forward error: {}", e);
                        }
                    } else {
                        // This is a response from target
                        if let Some(client_addr) = target_to_client.get(&recv_addr) {
                            // Wrap the response in SOCKS5 UDP header
                            let (atyp, addr_bytes) = match recv_addr.ip() {
                                std::net::IpAddr::V4(ip) => (SOCKS_ATYP_IPV4, ip.octets().to_vec()),
                                std::net::IpAddr::V6(ip) => (SOCKS_ATYP_IPV6, ip.octets().to_vec()),
                            };
                            let mut response = vec![0u8, 0, 0, atyp]; // RSV FRAG ATYP
                            response.extend_from_slice(&addr_bytes);
                            response.extend_from_slice(&recv_addr.port().to_be_bytes());
                            response.extend_from_slice(&buf[..size]);
                            if let Err(e) = udp_socket.send_to(&response, *client_addr).await {
                                debug!("UDP response forward error: {}", e);
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    debug!("UDP recv error: {}", e);
                    break;
                }
                Err(_) => {
                    debug!("UDP association timeout, ending session");
                    break;
                }
            }
        }
        // Signal that UDP handler has stopped
        udp_active_clone.store(false, Ordering::SeqCst);
        debug!("UDP handler stopped, signaling TCP keepalive");
    });

    // CRITICAL FIX: Keep TCP connection alive with timeout and coordination with UDP handler
    let mut buf = [0u8; 1];
    let mut last_check = std::time::Instant::now();
    
    loop {
        // Check periodically if UDP handler is still active
        match timeout(Duration::from_secs(10), stream.read(&mut buf[..])).await {
            Ok(Ok(0)) => {
                debug!("Client closed UDP associate TCP connection");
                break;
            }
            Ok(Ok(_)) => {
                // Received data, client is still active
                last_check = std::time::Instant::now();
                continue;
            }
            Ok(Err(e)) => {
                debug!("UDP associate TCP read error: {}", e);
                break;
            }
            Err(_) => {
                // Timeout - check if UDP handler is still active
                if !udp_active.load(Ordering::SeqCst) {
                    debug!("UDP handler stopped, closing TCP keepalive");
                    break;
                }
                // Check if we've exceeded maximum idle time
                if last_check.elapsed() > UDP_ASSOCIATE_KEEPALIVE_TIMEOUT {
                    debug!("UDP associate TCP keepalive idle timeout ({:?}), closing", UDP_ASSOCIATE_KEEPALIVE_TIMEOUT);
                    break;
                }
                // Otherwise continue waiting
            }
        }
    }

    Ok(())
}

/// Handle SOCKS5 UDP-over-TCP tunnel (CMD=0x04)
///
/// This custom extension tunnels UDP packets inside the TCP connection,
/// eliminating the need for a separate UDP channel. This is essential for
/// overlay networks like Yggdrasil/cheburnet where separate UDP channels
/// may be blocked by firewalls.
///
/// Protocol after SOCKS5 handshake:
/// 1. Client sends CMD=0x04, ATYP+ADDR+PORT (ignored, typically 0.0.0.0:0)
/// 2. Server replies with standard SOCKS5 success
/// 3. TCP stream carries framed UDP packets in both directions
async fn handle_socks5_udp_tunnel_after_header(stream: TcpStream, atyp: u8, _config: &ServerConfig) -> ProxyResult<()> {
    let client_addr = stream.peer_addr().ok();
    let client_label = client_addr.map(|a| a.to_string()).unwrap_or_else(|| "<unknown>".to_string());

    // Consume the address bytes (we don't use them for UDP tunnel)
    let mut stream = stream;
    let mut buf = [0u8; 256];
    match atyp {
        SOCKS_ATYP_IPV4 => {
            stream.read_exact(&mut buf[..6]).await?; // IPv4 + port
        }
        SOCKS_ATYP_DOMAIN => {
            stream.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            stream.read_exact(&mut buf[..len + 2]).await?;
        }
        SOCKS_ATYP_IPV6 => {
            stream.read_exact(&mut buf[..18]).await?; // IPv6 + port
        }
        _ => {
            // Skip unknown address type gracefully
            stream.read_exact(&mut buf[..6]).await?;
        }
    }

    // Send success response (0.0.0.0:0 as bind address since tunnel uses TCP)
    stream.write_all(&[
        SOCKS_VERSION, SOCKS_REP_SUCCESS, 0x00, SOCKS_ATYP_IPV4,
        0x00, 0x00, 0x00, 0x00, // 0.0.0.0
        0x00, 0x00,             // port 0
    ]).await?;

    info!("UDP tunnel established for client {}", client_label);

    // Create shared outbound UDP socket for forwarding
    let udp_socket = Arc::new(UdpSocket::bind("[::]:0").await
        .map_err(|e| ProxyError::Connection(format!("Failed to bind UDP tunnel socket: {}", e)))?);

    let udp_local = udp_socket.local_addr()
        .map_err(|e| ProxyError::Connection(format!("Failed to get UDP tunnel local addr: {}", e)))?;
    debug!("UDP tunnel outbound socket bound to {}", udp_local);

    // Split TCP stream for bidirectional framed I/O
    let (mut tcp_read, tcp_write) = stream.into_split();
    let tcp_write = Arc::new(tokio::sync::Mutex::new(tcp_write));

    // Map: target_addr -> timestamp (for cleanup and routing responses back)
    // We track which targets the client has sent to, so we know to forward responses
    let known_targets: Arc<dashmap::DashMap<SocketAddr, std::time::Instant>> = Arc::new(dashmap::DashMap::new());
    let known_targets_cleanup = known_targets.clone();

    // Task 1: Read framed UDP packets from TCP, send as real UDP
    let udp_send = udp_socket.clone();
    let known_targets_send = known_targets.clone();
    let client_label_send = client_label.clone();
    let send_task = tokio::spawn(async move {
        loop {
            match read_frame(&mut tcp_read).await {
                Ok((target, payload)) => {
                    // Track this target for response routing
                    known_targets_send.insert(target, std::time::Instant::now());

                    match udp_send.send_to(&payload, target).await {
                        Ok(_) => {
                            debug!("UDP tunnel: forwarded {} bytes to {} for client {}",
                                   payload.len(), target, client_label_send);
                        }
                        Err(e) => {
                            debug!("UDP tunnel: failed to send to {}: {}", target, e);
                        }
                    }
                }
                Err(e) => {
                    debug!("UDP tunnel: TCP read ended for client {}: {}", client_label_send, e);
                    break;
                }
            }
        }
    });

    // Task 2: Receive real UDP responses, frame them and send to client via TCP
    let udp_recv = udp_socket.clone();
    let tcp_write_recv = tcp_write.clone();
    let client_label_recv = client_label.clone();
    let recv_task = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        let mut last_cleanup = std::time::Instant::now();
        loop {
            match timeout(Duration::from_secs(60), udp_recv.recv_from(&mut buf)).await {
                Ok(Ok((size, from_addr))) => {
                    // Only forward responses from known targets
                    if known_targets.contains_key(&from_addr) {
                        let mut writer = tcp_write_recv.lock().await;
                        if let Err(e) = write_frame(&mut *writer, from_addr, &buf[..size]).await {
                            debug!("UDP tunnel: TCP write failed for client {}: {}", client_label_recv, e);
                            break;
                        }
                    } else {
                        debug!("UDP tunnel: ignoring response from unknown target {} for client {}",
                               from_addr, client_label_recv);
                    }
                }
                Ok(Err(e)) => {
                    debug!("UDP tunnel: UDP recv error for client {}: {}", client_label_recv, e);
                    break;
                }
                Err(_) => {
                    // Timeout - fall through to the cleanup block below
                }
            }

            let now = std::time::Instant::now();
            if now.duration_since(last_cleanup) >= Duration::from_secs(60) {
                last_cleanup = now;
                let active_count = known_targets.iter()
                    .filter(|entry| now.duration_since(*entry.value()) < Duration::from_secs(120))
                    .count();
                if active_count == 0 {
                    debug!("UDP tunnel: no active targets, closing for client {}", client_label_recv);
                    break;
                }
                // Clean up old entries
                known_targets.retain(|_, ts| now.duration_since(*ts) < Duration::from_secs(120));
            }
        }
    });

    // Wait for either task to finish (the other will be aborted)
    let send_abort = send_task.abort_handle();
    let recv_abort = recv_task.abort_handle();

    tokio::select! {
        _ = send_task => {
            debug!("UDP tunnel: send task ended for client {}", client_label);
            recv_abort.abort();
        }
        _ = recv_task => {
            debug!("UDP tunnel: recv task ended for client {}", client_label);
            send_abort.abort();
        }
    }

    // Clean up
    info!("UDP tunnel closed for client {}", client_label);
    Ok(())
}

async fn handle_socks5_connection(mut stream: TcpStream, config: Arc<ServerConfig>) -> ProxyResult<()> {
    let client_addr = stream.peer_addr()?;

    // SOCKS5 authentication
    handle_socks5_auth(&mut stream, &config).await?;

    // Check command
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf[..]).await?;
    if buf[0] != 5 {
        return Err(ProxyError::SocksProtocol("Invalid SOCKS5 request".to_string()));
    }
    let cmd = buf[1];
    let atyp = buf[3];

    match cmd {
        SOCKS_CMD_CONNECT => {
            // SOCKS5 CONNECT request - parse the rest of the request
            let (target_stream, target_addr) = handle_socks5_connect_request_after_header(&mut stream, atyp, &config).await?;

            // Forward data
            if let Err(e) = forward_streams(stream, target_stream).await {
                // Real errors only — data-plane errors already swallowed inside forward_streams()
                debug!("Stream forwarding ended for {}: {}", client_addr, e);
                return Err(e);
            }
        }
        SOCKS_CMD_UDP_ASSOCIATE => {
            // SOCKS5 UDP associate - parse the rest of the request
            handle_socks5_udp_associate_after_header(stream, atyp, &config).await?;
        }
        SOCKS5_CMD_UDP_TUNNEL => {
            // UDP-over-TCP tunnel - tunnels UDP packets inside TCP connection
            info!("UDP tunnel request from {}", client_addr);
            handle_socks5_udp_tunnel_after_header(stream, atyp, &config).await?;
        }
        _ => {
            return Err(ProxyError::SocksProtocol(format!("Unsupported command: 0x{:02x}", cmd)));
        }
    }

    debug!("SOCKS5 connection from {} processed successfully", client_addr);
    Ok(())
}



async fn run_udp_proxy(listen_addr: &str, port: u16, config: Arc<ServerConfig>) -> ProxyResult<()> {
    if config.require_auth {
        return Err(ProxyError::Configuration("UDP proxy does not support authentication. Disable authentication for UDP support.".to_string()));
    }

    let udp_socket = UdpSocket::bind((listen_addr, port)).await
        .map_err(|e| ProxyError::Connection(format!("Failed to bind UDP socket: {}", e)))?;

    info!("UDP proxy listening on {}:{}", listen_addr, port);

    let mut buf = [0u8; UDP_BUFFER_SIZE];
    let mut target_to_client: HashMap<SocketAddr, SocketAddr> = HashMap::new();
    let mut udp_order: VecDeque<SocketAddr> = VecDeque::new();

    loop {
        let recv_future = udp_socket.recv_from(&mut buf);
        match timeout(DEFAULT_UDP_TIMEOUT, recv_future).await {
            Ok(Ok((size, client_addr))) => {
                let packet = &buf[0..size];

                // Check if this is a SOCKS5 UDP request packet
                if let Some((target_addr, payload)) = parse_udp_request_packet(packet) {
                    debug!("UDP request from {} to {}", client_addr, target_addr);

                    // Manage the target to client mapping with size limits
                    if !target_to_client.contains_key(&target_addr) {
                        udp_order.push_back(target_addr);
                        if udp_order.len() > MAX_UDP_MAP_SIZE {
                            if let Some(old) = udp_order.pop_front() {
                                target_to_client.remove(&old);
                            }
                        }
                    }
                    target_to_client.insert(target_addr, client_addr);

                    // Forward payload to target
                    match udp_socket.send_to(payload, target_addr).await {
                        Ok(_) => {
                            debug!("UDP payload forwarded to {}", target_addr);
                        }
                        Err(e) => {
                            error!("Failed to forward UDP packet to {}: {}", target_addr, e);
                            continue;
                        }
                    }
                } else {
                    // Assume this is a response from a target
                    // Preserve the target's address before the if-let shadows `client_addr`
                    let target_addr = client_addr;
                    if let Some(dest_client_addr) = target_to_client.get(&target_addr) {
                        // Wrap the response in SOCKS5 UDP header.
                        // Per RFC 1928, ATYP/ADDR/PORT must reflect the remote target that
                        // sent the data, not the client's address.
                        let (atyp, addr_bytes) = match target_addr.ip() {
                            std::net::IpAddr::V4(ip) => (SOCKS_ATYP_IPV4, ip.octets().to_vec()),
                            std::net::IpAddr::V6(ip) => (SOCKS_ATYP_IPV6, ip.octets().to_vec()),
                        };
                        let port_bytes = target_addr.port().to_be_bytes();
                        let mut response = vec![0u8, 0, 0, atyp]; // RSV + FRAG + ATYP
                        response.extend_from_slice(&addr_bytes);
                        response.extend_from_slice(&port_bytes);
                        response.extend_from_slice(packet);

                        if let Err(e) = udp_socket.send_to(&response, *dest_client_addr).await {
                            debug!("UDP response forward error: {}", e);
                        } else {
                            debug!("UDP response forwarded to {}", *dest_client_addr);
                        }
                    } else {
                        debug!("Received UDP packet from unknown target {}", target_addr);
                    }
                }
            }
            Ok(Err(e)) => {
                error!("UDP recv error: {}", e);
            }
            Err(_) => {
                // Recv timeout, continue listening
                continue;
            }
        }
    }
}

/// Parse SOCKS5 UDP request packet and extract target address and payload
fn parse_udp_request_packet(packet: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if packet.len() < 10 {
        return None; // Packet too small
    }

    if packet[0] != 0 || packet[1] != 0 {
        return None; // Invalid RSV (reserved) field
    }

    let frag = packet[2];
    if frag != SOCKS_UDP_FRAGMENT {
        return None; // Fragmentation not supported
    }

    let atyp = packet[3];
    let target_addr = match atyp {
        SOCKS_ATYP_IPV4 => {
            if packet.len() < 10 {
                return None;
            }
            let ip = std::net::Ipv4Addr::from([packet[4], packet[5], packet[6], packet[7]]);
            let port = ((packet[8] as u16) << 8) | packet[9] as u16;
            SocketAddr::new(std::net::IpAddr::V4(ip), port)
        }
        SOCKS_ATYP_IPV6 => {
            if packet.len() < 22 {
                return None;
            }
            let ip = std::net::Ipv6Addr::from([
                packet[4], packet[5], packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
                packet[12], packet[13], packet[14], packet[15], packet[16], packet[17], packet[18], packet[19]
            ]);
            let port = ((packet[20] as u16) << 8) | packet[21] as u16;
            SocketAddr::new(std::net::IpAddr::V6(ip), port)
        }
        _ => return None
    };

    let header_size = if atyp == SOCKS_ATYP_IPV6 { 22 } else { 10 };
    if packet.len() <= header_size {
        return None; // No payload
    }

    Some((target_addr, &packet[header_size..]))
}

/// Monitor file descriptor usage and log warnings/errors
async fn monitor_file_descriptors() {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    
    loop {
        interval.tick().await;
        
        // Count open file descriptors on Linux
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            let count = entries.count();
            
            // Log at different levels based on usage (assuming 200000 limit)
            if count > 150000 {
                error!("CRITICAL: Very high FD usage: {}/200000 ({}%)", count, (count * 100) / 200000);
            } else if count > 100000 {
                warn!("WARNING: High FD usage: {}/200000 ({}%)", count, (count * 100) / 200000);
            } else if count > 50000 {
                info!("FD usage moderate: {}/200000 ({}%)", count, (count * 100) / 200000);
            } else {
                debug!("FD usage: {}/200000", count);
            }
        }
    }
}

#[tokio::main]
async fn main() -> ProxyResult<()> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 3 || args[1] != "-c" {
        error!("Usage: {} -c /path/to/config.toml", args[0]);
        process::exit(1);
    }

    let config_path = &args[2];
    let config_str = tokio::fs::read_to_string(config_path).await
        .map_err(|e| {
            error!("Error: Failed to read config file '{}': {}", config_path, e);
            e
        })?;

    let parsed: Value = toml::from_str(&config_str)
        .map_err(|e| {
            error!("Error: Failed to parse config file '{}': {}", config_path, e);
            e
        })?;

    let server_config = Arc::new(ServerConfig::from_toml(&parsed)?);
    
    // Parse listen address - support IPv4 and IPv6
    let bind_ip: std::net::IpAddr = if server_config.listen == "0.0.0.0" || server_config.listen.is_empty() {
        "::".parse().unwrap() // IPv6 any (supports IPv4 via dual-stack)
    } else {
        server_config.listen.parse()
            .unwrap_or_else(|e| {
                error!("Failed to parse listen address '{}': {}, falling back to ::", server_config.listen, e);
                "::".parse().unwrap()
            })
    };
    
    let tcp_listener = TcpListener::bind((bind_ip, server_config.port)).await
        .map_err(|e| {
            ProxyError::Configuration(format!("Failed to bind TCP listener to {}:{}: {}", bind_ip, server_config.port, e))
        })?;

    println!("Cheburproxy server v1.0");
    info!("Starting SOCKS5 proxy server");

    // Setup graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

    // Start UDP proxy separately
    let udp_port = server_config.udp_port.unwrap_or(server_config.port);
    
    // Parse UDP bind address (same logic as TCP)
    let udp_bind_ip: std::net::IpAddr = if server_config.listen == "0.0.0.0" || server_config.listen.is_empty() {
        "::".parse().unwrap()
    } else {
        server_config.listen.parse()
            .unwrap_or_else(|_| "::".parse().unwrap())
    };
    let udp_bind_addr_str = udp_bind_ip.to_string();
    
    let udp_config = server_config.clone();
    let udp_shutdown_tx = shutdown_tx.clone();

    tokio::spawn(async move {
        info!("Starting UDP proxy on {}:{}", udp_bind_ip, udp_port);
        if let Err(e) = run_udp_proxy(&udp_bind_addr_str, udp_port, udp_config).await {
            error!("UDP proxy error: {}", e);
            // Signal the main server loop to shut down when the UDP proxy fails.
            let _ = udp_shutdown_tx.send(()).await;
        }
    });

    // Spawn FD monitoring task
    tokio::spawn(monitor_file_descriptors());
    info!("File descriptor monitoring started");

    println!("Listening TCP on {}:{}", bind_ip, server_config.port);
    info!("SOCKS5 server started successfully on {}:{}", bind_ip, server_config.port);

    // Connection concurrency limit: prevent unbounded task creation under load or attack.
    // When all slots are occupied the accept loop blocks until a slot is freed, providing
    // natural back-pressure instead of spawning tasks without bound.
    const MAX_CONNECTIONS: usize = 4096;
    let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));

    // Main server loop with graceful shutdown
    loop {
        tokio::select! {
            accept_result = timeout(DEFAULT_ACCEPT_TIMEOUT, tcp_listener.accept()) => {
                match accept_result {
                    Ok(Ok((stream, client_addr))) => {
                        let config = server_config.clone();
                        info!("Accepted TCP connection from {}", client_addr);

                        // Acquire a connection slot before spawning; blocks when the limit
                        // is reached and releases automatically when the permit is dropped.
                        let permit = match connection_semaphore.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => {
                                warn!("Connection limit semaphore closed, dropping connection from {}", client_addr);
                                continue;
                            }
                        };

                        tokio::spawn(async move {
                            let _permit = permit; // held for duration of connection, released on drop
                            match handle_tcp_connection(stream, config).await {
                                Ok(_) => {
                                    debug!("TCP connection handled successfully");
                                }
                                Err(e) => {
                                    // Classify: data-plane IO errors are normal in proxy forwarding
                                    match &e {
                                        ProxyError::Io(io_err) if is_data_plane_error(io_err) => {
                                            debug!("TCP connection closed (peer disconnect): {}", io_err);
                                        }
                                        _ => {
                                            error!("TCP connection error: {}", e);
                                        }
                                    }
                                }
                            }
                        });
                    }
                    Ok(Err(e)) => {
                        error!("Failed to accept TCP connection: {}", e);
                    }
                    Err(_) => {
                        debug!("TCP accept timeout reached, continuing...");
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Shutdown signal received, stopping server...");
                break;
            }
        }
    }

    info!("Server shutdown complete");
    Ok(())
}