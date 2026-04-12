use std::fmt;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::sync::Once;
use nix::libc;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

// Standard socket options for Linux (defined as constants for better maintainability)
pub const IP_TRANSPARENT: i32 = 19;     // IP_TRANSPARENT (SOL_IP level)
pub const IPV6_TRANSPARENT: i32 = 75;   // IPV6_TRANSPARENT (SOL_IPV6 level)
pub const SO_REUSEPORT: i32 = 15;       // SO_REUSEPORT
pub const SO_MARK: i32 = 36;            // SO_MARK (to bypass TPROXY loops)
const SOL_IP: i32 = 0;                  // IPPROTO_IP — Linux protocol level for IPv4 options
const SOL_IPV6: i32 = 41;              // IPPROTO_IPV6 — Linux protocol level for IPv6 options
const IP_RECVORIGDSTADDR: i32 = 20;    // IP_RECVORIGDSTADDR (IPv4 original destination in ancdata)
const IPV6_RECVORIGDSTADDR: i32 = 74;  // IPV6_RECVORIGDSTADDR (IPv6 original destination in ancdata)

// Default socket configuration constants
const DEFAULT_LISTEN_BACKLOG: i32 = 128;
const DEFAULT_TRANSPARENT_VALUE: libc::c_int = 1;



/// Errors that can occur during transparent socket operations
#[derive(Debug)]
pub enum TransparentError {
    /// Invalid socket address provided
    InvalidAddress(String),
    /// Insufficient privileges for transparent proxying
    InsufficientPrivileges { uid: u32 },
    /// Socket creation failed
    SocketCreationFailed(String),
    /// Socket option setting failed
    SocketOptionFailed { option: String, error: String },
    /// Socket binding failed
    BindFailed(String),
    /// Socket listen failed
    ListenFailed(String),
    /// Fallback bind failed when transparent options failed
    FallbackBindFailed(String),
}

impl fmt::Display for TransparentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransparentError::InvalidAddress(addr) => {
                write!(f, "Invalid socket address: {}", addr)
            }
            TransparentError::InsufficientPrivileges { uid } => {
                write!(f, "Insufficient privileges (UID: {}). Transparent proxying requires root or CAP_NET_ADMIN/CAP_NET_RAW capabilities", uid)
            }
            TransparentError::SocketCreationFailed(msg) => {
                write!(f, "Failed to create socket: {}", msg)
            }
            TransparentError::SocketOptionFailed { option, error } => {
                write!(f, "Failed to set socket option '{}': {}", option, error)
            }
            TransparentError::BindFailed(msg) => {
                write!(f, "Failed to bind socket: {}", msg)
            }
            TransparentError::ListenFailed(msg) => {
                write!(f, "Failed to listen on socket: {}", msg)
            }
            TransparentError::FallbackBindFailed(msg) => {
                write!(f, "Fallback bind failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for TransparentError {}

/// Configuration for transparent socket creation
#[derive(Debug, Clone)]
pub struct TransparentSocketConfig {
    /// Socket listen backlog
    pub backlog: i32,
    /// Whether to enable SO_REUSEPORT
    pub reuse_port: bool,
    /// Whether to enable IP_TRANSPARENT
    pub transparent: bool,
    /// Whether to enable IP_RECVORIGDSTADDR
    pub recv_orig_dst: bool,
}

impl Default for TransparentSocketConfig {
    fn default() -> Self {
        Self {
            backlog: DEFAULT_LISTEN_BACKLOG,
            reuse_port: true,
            transparent: true,
            recv_orig_dst: true,
        }
    }
}

/// Check if the process has root privileges (required for transparent proxying)
fn check_root_privileges() -> Result<(), TransparentError> {
    static LOG_ONCE: Once = Once::new();

    let uid = unsafe { libc::getuid() };
    if uid == 0 {
        LOG_ONCE.call_once(|| {
            log::info!("Running with UID 0; transparent proxy capabilities available");
        });
        return Ok(());
    }

    // Check Linux capabilities (for systemd deployments with AmbientCapabilities)
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("CapEff:") {
                if let Some(hex) = line.split_whitespace().nth(1) {
                    if let Ok(caps) = u64::from_str_radix(hex.trim_start_matches("0x"), 16) {
                        let cap_net_admin = 1u64 << 12; // CAP_NET_ADMIN
                        let cap_net_raw = 1u64 << 13;   // CAP_NET_RAW
                        if caps & cap_net_admin != 0 && caps & cap_net_raw != 0 {
                            LOG_ONCE.call_once(|| {
                                log::info!("Running with CAP_NET_ADMIN and CAP_NET_RAW capabilities (non-root)");
                            });
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    LOG_ONCE.call_once(|| {
        log::warn!("Transparent mode requires root or CAP_NET_ADMIN/CAP_NET_RAW; current UID: {}", uid);
    });

    Err(TransparentError::InsufficientPrivileges { uid })
}

/// Safely set a socket option with proper error handling
fn set_socket_option(fd: libc::c_int, level: libc::c_int, optname: libc::c_int, val: libc::c_int, option_name: &str) -> Result<(), TransparentError> {
    let res = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        )
    };

    if res != 0 {
        let error = std::io::Error::last_os_error().to_string();
        Err(TransparentError::SocketOptionFailed {
            option: option_name.to_string(),
            error,
        })
    } else {
        Ok(())
    }
}



/// Establish a TCP connection to a target
///
/// This is used for all outgoing connections from the proxy (to upstream proxies or direct targets).
pub async fn connect_tcp<A: tokio::net::ToSocketAddrs>(addr: A) -> anyhow::Result<tokio::net::TcpStream> {
    let stream = tokio::net::TcpStream::connect(addr).await?;
    Ok(stream)
}

/// Establish a TCP connection with SO_MARK=0x2 set **before** the SYN is sent.
///
/// ## Why this matters
///
/// The iptables `TPROXY_MARK` chain in the `OUTPUT` hook inspects every packet that
/// leaves the proxy process.  Any packet whose destination port is in `PORTS_TCP` gets
/// `mark 0x1`, which policy-routes it to routing table 100 (`local 0.0.0.0/0 dev lo`) —
/// i.e. back to loopback.  If SO_MARK were set *after* `connect()`, the SYN would leave
/// without the mark, hit `TPROXY_MARK`, get mark 0x1, and loop back to the proxy.
///
/// By using `TcpSocket` (which exposes the raw fd before the connect syscall), we can
/// set SO_MARK=0x2 on the socket descriptor **before** any packet is sent.  The kernel
/// attaches the mark to the socket's routing metadata so every packet — including the
/// initial SYN — carries `fwmark 0x2`.  The `TPROXY_MARK` rule `-m mark --mark 0x2
/// -j RETURN` then skips the socket, preventing the loop.
///
/// ## Address resolution
///
/// `TcpSocket::connect()` requires a `SocketAddr`.  We resolve the generic
/// `ToSocketAddrs` argument with `lookup_host()` and try each resolved address in turn,
/// matching IPv4 destinations to IPv4 sockets and IPv6 destinations to IPv6 sockets.
/// This preserves the same semantics as the previous `TcpStream::connect()` call.
pub async fn connect_tcp_with_mark<A: tokio::net::ToSocketAddrs>(addr: A) -> anyhow::Result<TcpStream> {
    // Resolve the address (may be a SocketAddr, (&str, u16), or a hostname:port string).
    let mut addrs = tokio::net::lookup_host(addr).await?;
    let mut last_err: Option<anyhow::Error> = None;

    loop {
        let addr = match addrs.next() {
            Some(a) => a,
            None => {
                return Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no addresses resolved")));
            }
        };

        // Create a socket that matches the address family.
        let socket = match addr {
            SocketAddr::V4(_) => TcpSocket::new_v4(),
            SocketAddr::V6(_) => TcpSocket::new_v6(),
        };
        let socket = match socket {
            Ok(s) => s,
            Err(e) => { last_err = Some(e.into()); continue; }
        };

        // Set SO_MARK BEFORE connect so the SYN carries the mark and bypasses TPROXY_MARK.
        // Mark 0x2: proxy-originated traffic. Must differ from TPROXY mark (0x1).
        let mark: libc::c_int = 2;
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                SO_MARK,
                &mark as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            log::warn!(
                "connect_tcp_with_mark: failed to set SO_MARK on TCP socket: {}",
                std::io::Error::last_os_error()
            );
        }

        // Async connect — SYN goes out with SO_MARK=0x2 already set.
        match socket.connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => { last_err = Some(e.into()); continue; }
        }
    }
}

/// Bind a UDP socket and immediately set SO_MARK to bypass TPROXY iptables rules.
///
/// Plain DNS (UDP) sockets must carry this mark so that iptables TPROXY rules do not
/// redirect the outgoing DNS packets back into the proxy, which would create an infinite
/// resolution loop.  The mark value (2) matches the one used by `connect_tcp_with_mark`.
///
/// Returns a bound, non-blocking `tokio::net::UdpSocket` ready for async I/O.
pub async fn bind_udp_with_mark(addr: &str) -> anyhow::Result<UdpSocket> {
    let std_socket = std::net::UdpSocket::bind(addr)?;
    let fd = std_socket.as_raw_fd();
    let mark: libc::c_int = 2;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_MARK,
            &mark as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        log::warn!(
            "bind_udp_with_mark: failed to set SO_MARK on UDP socket: {}",
            std::io::Error::last_os_error()
        );
    }
    std_socket.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(std_socket)?)
}

/// Set SO_MARK on a raw file descriptor to bypass TPROXY routing rules.
///
/// This is used by UDP and DNS subsystems that need to mark their outgoing sockets
/// so that iptables TPROXY rules do not redirect the traffic back into the proxy.
pub fn set_socket_mark(fd: libc::c_int, mark: u32) -> std::io::Result<()> {
    let mark = mark as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_MARK,
            &mark as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}


/// Get the original destination address from a transparent proxy connection
///
/// This function extracts the original destination address that the client was trying to reach
/// before the connection was intercepted by the transparent proxy.
///
/// # Arguments
/// * `stream` - The TCP stream to get the original destination from
///
/// # Returns
/// * `Ok(SocketAddr)` - The original destination address
/// * `Err(TransparentError)` - If the address cannot be retrieved
///
/// # Note
/// This requires appropriate privileges (root or CAP_NET_ADMIN/CAP_NET_RAW) to work correctly.
pub fn get_original_dst(stream: &TcpStream) -> Result<SocketAddr, TransparentError> {
    // Check privileges and log warning if insufficient
    if let Err(ref e) = check_root_privileges() {
        log::warn!("Transparent mode may not work: {}", e);
    }

    // For TPROXY: local_addr() gives us the original destination
    match stream.local_addr() {
        Ok(addr) => {
            log::debug!("Original destination from local_addr (TPROXY mode): {}", addr);
            Ok(addr)
        }
        Err(e) => Err(TransparentError::SocketCreationFailed(
            format!("Failed to get original dst: {}", e)
        ))
    }
}

/// Create a transparent TCP socket listener with the specified configuration
///
/// This function creates a TCP listener that can intercept connections transparently.
/// If transparent options are not available (insufficient privileges or platform limitations),
/// it falls back to a regular TCP listener.
///
/// # Arguments
/// * `listen_addr` - IP address to listen on (e.g., "0.0.0.0" for all interfaces)
/// * `port` - Port number to listen on
/// * `config` - Socket configuration options
///
/// # Returns
/// * `Ok(TcpListener)` - Configured TCP listener ready to accept connections
/// * `Err(TransparentError)` - If socket creation, binding, or configuration fails
///
/// # Examples
/// ```rust,ignore
/// use std::net::TcpListener;
/// use crate::transparent::{create_transparent_tcp_socket, TransparentSocketConfig};
///
/// let config = TransparentSocketConfig::default();
/// let listener = create_transparent_tcp_socket("0.0.0.0", 8080, config)?;
/// ```
pub fn create_transparent_tcp_socket(
    listen_addr: &str,
    port: u16,
    config: TransparentSocketConfig,
) -> Result<std::net::TcpListener, TransparentError> {
    // Parse and validate the socket address early.
    // IPv6 addresses (containing ':') must be wrapped in brackets for socket address parsing.
    let socket_addr = {
        let addr_str = if listen_addr.contains(':') {
            format!("[{}]:{}", listen_addr, port)
        } else {
            format!("{}:{}", listen_addr, port)
        };
        addr_str.parse::<SocketAddr>()
            .map_err(|e| TransparentError::InvalidAddress(format!("{}: {}", addr_str, e)))?
    };

    // Check privileges first - this determines our strategy
    let has_privileges = check_root_privileges().is_ok();

    // If no privileges, fall back to regular listener
    if !has_privileges {
        log::warn!("No root privileges; falling back to non-transparent mode");
        return std::net::TcpListener::bind(&socket_addr)
            .map_err(|e| TransparentError::FallbackBindFailed(e.to_string()))
            .map(|listener| listener);
    }

    // Create the socket with proper error handling
    let domain = if socket_addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| TransparentError::SocketCreationFailed(e.to_string()))?;

    // For IPv6 sockets, disable IPV6_V6ONLY to enable dual-stack (accept IPv4-mapped addresses
    // as well). This MUST happen before bind(). See dns_proxy.rs for the same pattern.
    if socket_addr.is_ipv6() {
        socket.set_only_v6(false)
            .map_err(|e| TransparentError::SocketOptionFailed {
                option: "IPV6_V6ONLY=0".to_string(),
                error: e.to_string(),
            })?;
    }

    // Set basic socket options
    socket.set_reuse_address(true)
        .map_err(|e| TransparentError::SocketOptionFailed {
            option: "SO_REUSEADDR".to_string(),
            error: e.to_string(),
        })?;

    // Apply transparent socket options based on configuration
    let fd = socket.as_raw_fd();
    let val = DEFAULT_TRANSPARENT_VALUE;
    let mut transparent_options_failed = false;

    // SO_REUSEPORT (improves performance with multiple processes, but not required for transparent mode)
    if config.reuse_port {
        if let Err(e) = set_socket_option(fd, libc::SOL_SOCKET, SO_REUSEPORT, val, "SO_REUSEPORT") {
            log::warn!("SO_REUSEPORT unavailable (kernel < 3.9 or restricted environment); continuing without it: {}", e);
        }
    }

    // TRANSPARENT socket option: use IPV6_TRANSPARENT for IPv6 (including dual-stack)
    // and IP_TRANSPARENT for IPv4-only sockets.
    if config.transparent {
        if socket_addr.is_ipv6() {
            // IPV6_TRANSPARENT enables TPROXY for both native IPv6 and IPv4-mapped
            // addresses received on a dual-stack socket.
            if let Err(e) = set_socket_option(fd, SOL_IPV6, IPV6_TRANSPARENT, val, "IPV6_TRANSPARENT") {
                log::warn!("Failed to set IPV6_TRANSPARENT: {}", e);
                transparent_options_failed = true;
            }
        } else {
            if let Err(e) = set_socket_option(fd, SOL_IP, IP_TRANSPARENT, val, "IP_TRANSPARENT") {
                log::warn!("Failed to set IP_TRANSPARENT: {}", e);
                transparent_options_failed = true;
            }
        }
    }

    // RECVORIGDSTADDR: use the address-family-appropriate level.
    if config.recv_orig_dst {
        if socket_addr.is_ipv6() {
            if let Err(e) = set_socket_option(fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, val, "IPV6_RECVORIGDSTADDR") {
                log::warn!("Failed to set IPV6_RECVORIGDSTADDR: {}", e);
            }
        } else {
            if let Err(e) = set_socket_option(fd, SOL_IP, IP_RECVORIGDSTADDR, val, "IP_RECVORIGDSTADDR") {
                log::warn!("Failed to set IP_RECVORIGDSTADDR: {}", e);
            }
        }
    }

    // If critical transparent options failed, fall back to regular listener
    if transparent_options_failed && config.transparent {
        log::warn!("Critical transparent options failed; falling back to non-transparent mode");
        return std::net::TcpListener::bind(&socket_addr)
            .map_err(|e| TransparentError::FallbackBindFailed(e.to_string()));
    }

    // Configure the socket for listening
    socket.set_nonblocking(true)
        .map_err(|e| TransparentError::SocketOptionFailed {
            option: "O_NONBLOCK".to_string(),
            error: e.to_string(),
        })?;

    socket.bind(&socket_addr.into())
        .map_err(|e| TransparentError::BindFailed(e.to_string()))?;

    socket.listen(config.backlog)
        .map_err(|e| TransparentError::ListenFailed(e.to_string()))?;

    // Convert to standard TcpListener using the FromRawFd trait
    use std::os::unix::io::FromRawFd;
    Ok(unsafe { FromRawFd::from_raw_fd(socket.into_raw_fd()) })
}

/// Convenience function that creates a transparent TCP socket with default configuration
///
/// # Arguments
/// * `listen_addr` - IP address to listen on
/// * `port` - Port number to listen on
///
/// # Returns
/// * `Ok(TcpListener)` - Configured TCP listener
/// * `Err(TransparentError)` - If socket creation fails
pub fn create_transparent_tcp_socket_default(
    listen_addr: &str,
    port: u16,
) -> Result<std::net::TcpListener, TransparentError> {
    create_transparent_tcp_socket(listen_addr, port, TransparentSocketConfig::default())
}
