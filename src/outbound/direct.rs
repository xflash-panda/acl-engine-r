//! Direct outbound connection implementation.
//!
//! Connects directly to the target using the local network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use crate::error::{AclError, OutboundErrorKind, Result};

use super::{
    build_resolve_info, try_resolve_from_ip, Addr, Outbound, ResolveInfo, StdTcpConn, TcpConn,
    UdpConn, DEFAULT_DIALER_TIMEOUT,
};

#[cfg(feature = "async")]
use super::{AsyncOutbound, AsyncTcpConn, AsyncUdpConn, TokioTcpConn};
#[cfg(feature = "async")]
use async_trait::async_trait;
#[cfg(feature = "async")]
use tokio::net::{TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket};

/// IP version preference for direct connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DirectMode {
    /// Dual-stack "happy eyeballs"-like mode (default)
    #[default]
    Auto,
    /// Use IPv6 address when available, otherwise IPv4
    Prefer64,
    /// Use IPv4 address when available, otherwise IPv6
    Prefer46,
    /// Use IPv6 only, fail if not available
    Only6,
    /// Use IPv4 only, fail if not available
    Only4,
}

/// Options for creating a Direct outbound.
#[derive(Debug, Clone, Default)]
pub struct DirectOptions {
    /// IP version preference mode
    pub mode: DirectMode,
    /// Bind IPv4 address for outgoing connections
    pub bind_ip4: Option<Ipv4Addr>,
    /// Bind IPv6 address for outgoing connections
    pub bind_ip6: Option<Ipv6Addr>,
    /// Bind to a specific network device (Linux only, SO_BINDTODEVICE).
    /// Mutually exclusive with bind_ip4/bind_ip6.
    pub bind_device: Option<String>,
    /// Enable TCP Fast Open
    pub fast_open: bool,
    /// Connection timeout
    pub timeout: Option<Duration>,
}

/// Direct outbound that connects directly to the target.
///
/// It prefers to use ResolveInfo in Addr if available. But if it's None,
/// it will fall back to resolving Host using the system DNS resolver.
#[derive(Clone)]
pub struct Direct {
    mode: DirectMode,
    bind_ip4: Option<Ipv4Addr>,
    bind_ip6: Option<Ipv6Addr>,
    bind_device: Option<String>,
    fast_open: bool,
    timeout: Duration,
}

impl Direct {
    /// Create a new Direct outbound with default settings.
    pub fn new() -> Self {
        Self {
            mode: DirectMode::Auto,
            bind_ip4: None,
            bind_ip6: None,
            bind_device: None,
            fast_open: false,
            timeout: DEFAULT_DIALER_TIMEOUT,
        }
    }

    /// Create a new Direct outbound with the given mode.
    pub fn with_mode(mode: DirectMode) -> Self {
        Self {
            mode,
            bind_ip4: None,
            bind_ip6: None,
            bind_device: None,
            fast_open: false,
            timeout: DEFAULT_DIALER_TIMEOUT,
        }
    }

    /// Create a new Direct outbound with the given options.
    pub fn with_options(opts: DirectOptions) -> Result<Self> {
        if opts.bind_device.is_some() && (opts.bind_ip4.is_some() || opts.bind_ip6.is_some()) {
            return Err(AclError::ConfigError(
                "bind_device is mutually exclusive with bind_ip4/bind_ip6".to_string(),
            ));
        }
        Ok(Self {
            mode: opts.mode,
            bind_ip4: opts.bind_ip4,
            bind_ip6: opts.bind_ip6,
            bind_device: opts.bind_device,
            fast_open: opts.fast_open,
            timeout: opts.timeout.unwrap_or(DEFAULT_DIALER_TIMEOUT),
        })
    }

    /// Resolve the address using system DNS if ResolveInfo is not available.
    fn resolve(&self, addr: &mut Addr) {
        if try_resolve_from_ip(addr) {
            return;
        }

        match (addr.host.as_str(), 0u16).to_socket_addrs() {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                addr.resolve_info = Some(build_resolve_info(&ips));
            }
            Err(e) => {
                addr.resolve_info = Some(ResolveInfo::from_error(e.to_string()));
            }
        }
    }

    /// Check if we need to create a socket2::Socket for custom options.
    fn needs_custom_socket(&self, ip: &IpAddr) -> bool {
        self.get_bind_ip(ip).is_some() || self.bind_device.is_some() || self.fast_open
    }

    /// Create and configure a TCP socket2::Socket with all custom options.
    fn create_tcp_socket(&self, ip: &IpAddr) -> Result<socket2::Socket> {
        let domain = match ip {
            IpAddr::V4(_) => socket2::Domain::IPV4,
            IpAddr::V6(_) => socket2::Domain::IPV6,
        };
        let socket =
            socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
                .map_err(|e| AclError::OutboundError {
                    kind: OutboundErrorKind::Io,
                    message: format!("Failed to create socket: {}", e),
                })?;

        // Bind to IP address
        if let Some(bind_ip) = self.get_bind_ip(ip) {
            let bind_addr = SocketAddr::new(bind_ip, 0);
            socket
                .bind(&bind_addr.into())
                .map_err(|e| AclError::OutboundError {
                    kind: OutboundErrorKind::Io,
                    message: format!("Failed to bind: {}", e),
                })?;
        }

        // Bind to network device (Linux only)
        #[cfg(target_os = "linux")]
        if let Some(ref device) = self.bind_device {
            socket
                .bind_device(Some(device.as_bytes()))
                .map_err(|e| AclError::OutboundError {
                    kind: OutboundErrorKind::Io,
                    message: format!("Failed to bind device: {}", e),
                })?;
        }

        // Enable TCP Fast Open (client-side)
        if self.fast_open {
            set_tcp_fastopen(&socket)?;
        }

        Ok(socket)
    }

    /// Dial TCP to a specific IP address, checking a cancellation flag first.
    /// Returns `None` if cancelled (the caller should not attempt the connection).
    fn dial_tcp_ip_cancellable(
        &self,
        ip: IpAddr,
        port: u16,
        cancelled: &AtomicBool,
    ) -> Option<Result<TcpStream>> {
        if cancelled.load(Ordering::Relaxed) {
            return None;
        }
        Some(self.dial_tcp_ip(ip, port))
    }

    /// Dial TCP to a specific IP address.
    fn dial_tcp_ip(&self, ip: IpAddr, port: u16) -> Result<TcpStream> {
        let socket_addr = SocketAddr::new(ip, port);

        let stream = if self.needs_custom_socket(&ip) {
            let socket = self.create_tcp_socket(&ip)?;
            socket.set_nonblocking(false).ok();
            socket
                .connect_timeout(&socket_addr.into(), self.timeout)
                .map_err(|e| AclError::OutboundError {
                    kind: OutboundErrorKind::ConnectionFailed,
                    message: format!("Failed to connect: {}", e),
                })?;
            TcpStream::from(socket)
        } else {
            TcpStream::connect_timeout(&socket_addr, self.timeout)
                .map_err(|e| AclError::OutboundError {
                    kind: OutboundErrorKind::ConnectionFailed,
                    message: format!("Failed to connect: {}", e),
                })?
        };

        Ok(stream)
    }

    /// Get the bind IP for the given target IP.
    fn get_bind_ip(&self, target: &IpAddr) -> Option<IpAddr> {
        match target {
            IpAddr::V4(_) => self.bind_ip4.map(IpAddr::V4),
            IpAddr::V6(_) => self.bind_ip6.map(IpAddr::V6),
        }
    }

    /// Return the UDP bind address for the given IP version.
    fn udp_bind_addr(&self, use_ipv6: bool) -> SocketAddr {
        if use_ipv6 {
            self.bind_ip6
                .map(|ip| SocketAddr::new(IpAddr::V6(ip), 0))
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
        } else {
            self.bind_ip4
                .map(|ip| SocketAddr::new(IpAddr::V4(ip), 0))
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
    }

    /// Create a UDP socket with bind_device support via socket2.
    fn create_udp_socket_with_device(&self, use_ipv6: bool) -> Result<socket2::Socket> {
        let domain = if use_ipv6 {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let socket =
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
                .map_err(|e| AclError::OutboundError {
                    kind: OutboundErrorKind::Io,
                    message: format!("Failed to create UDP socket: {}", e),
                })?;

        let bind_addr = if use_ipv6 {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        socket
            .bind(&bind_addr.into())
            .map_err(|e| AclError::OutboundError {
                kind: OutboundErrorKind::Io,
                message: format!("Failed to bind UDP: {}", e),
            })?;

        #[cfg(target_os = "linux")]
        if let Some(ref device) = self.bind_device {
            socket
                .bind_device(Some(device.as_bytes()))
                .map_err(|e| AclError::OutboundError {
                    kind: OutboundErrorKind::Io,
                    message: format!("Failed to bind device: {}", e),
                })?;
        }

        Ok(socket)
    }

    /// Determine whether to use IPv6 for UDP based on mode and resolved addresses.
    fn should_use_ipv6(&self, info: Option<&ResolveInfo>) -> bool {
        match self.mode {
            DirectMode::Auto | DirectMode::Prefer46 => {
                info.and_then(|i| i.ipv4).is_none() && info.and_then(|i| i.ipv6).is_some()
            }
            DirectMode::Prefer64 => info.and_then(|i| i.ipv6).is_some(),
            DirectMode::Only6 => true,
            DirectMode::Only4 => false,
        }
    }

    /// Dual-stack dial TCP, racing IPv4 and IPv6 connections.
    ///
    /// Spawns two threads to race IPv4 and IPv6 connections. When the first
    /// succeeds, a shared cancellation flag is set so the other thread can
    /// skip its connection attempt if it hasn't started yet.
    ///
    /// Note: if the losing thread has already entered `connect_timeout`,
    /// the flag cannot interrupt the in-progress syscall — the thread will
    /// run until the OS connect times out. This is a limitation of
    /// std::thread (no cooperative cancellation). For full cancellation,
    /// use the async API which leverages `tokio::select!`.
    fn dual_stack_dial_tcp(&self, ipv4: Ipv4Addr, ipv6: Ipv6Addr, port: u16) -> Result<TcpStream> {
        let (tx, rx) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));

        let clone_v4 = self.clone();
        let tx_v4 = tx.clone();
        let ip_v4 = IpAddr::V4(ipv4);
        let cancelled_v4 = cancelled.clone();
        thread::spawn(move || {
            if let Some(result) = clone_v4.dial_tcp_ip_cancellable(ip_v4, port, &cancelled_v4) {
                let _ = tx_v4.send((ip_v4, result));
            }
        });

        let clone_v6 = self.clone();
        let ip_v6 = IpAddr::V6(ipv6);
        let cancelled_v6 = cancelled.clone();
        thread::spawn(move || {
            if let Some(result) = clone_v6.dial_tcp_ip_cancellable(ip_v6, port, &cancelled_v6) {
                let _ = tx.send((ip_v6, result));
            }
        });

        // Get first result
        let (first_ip, first) = rx
            .recv()
            .map_err(|_| AclError::OutboundError {
                kind: OutboundErrorKind::ConnectionFailed,
                message: "Channel error".to_string(),
            })?;

        if first.is_ok() {
            cancelled.store(true, Ordering::Relaxed);
            return first;
        }
        let first_err = first.unwrap_err();

        // First failed, try second
        let (second_ip, second) = rx
            .recv()
            .map_err(|_| AclError::OutboundError {
                kind: OutboundErrorKind::ConnectionFailed,
                message: "Channel error".to_string(),
            })?;

        if second.is_ok() {
            return second;
        }
        let second_err = second.unwrap_err();

        // Both failed — combine errors so the caller sees both attempts
        Err(AclError::OutboundError {
            kind: OutboundErrorKind::ConnectionFailed,
            message: format!(
                "dual-stack connection failed: {} ({}), {} ({})",
                first_ip, first_err, second_ip, second_err
            ),
        })
    }

    /// Async resolve the address using system DNS if ResolveInfo is not available.
    #[cfg(feature = "async")]
    async fn async_resolve(&self, addr: &mut Addr) {
        if try_resolve_from_ip(addr) {
            return;
        }

        match tokio::net::lookup_host(format!("{}:0", addr.host)).await {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                addr.resolve_info = Some(build_resolve_info(&ips));
            }
            Err(e) => {
                addr.resolve_info = Some(ResolveInfo::from_error(e.to_string()));
            }
        }
    }

    /// Async dial TCP to a specific IP address.
    #[cfg(feature = "async")]
    async fn async_dial_tcp_ip(&self, ip: IpAddr, port: u16) -> Result<TokioTcpStream> {
        let socket_addr = SocketAddr::new(ip, port);

        let stream = if self.needs_custom_socket(&ip) {
            let socket = self.create_tcp_socket(&ip)?;
            socket.set_nonblocking(true).ok();
            let std_stream: std::net::TcpStream = socket.into();
            let tokio_socket = tokio::net::TcpSocket::from_std_stream(std_stream);
            tokio::time::timeout(self.timeout, tokio_socket.connect(socket_addr))
                .await
                .map_err(|_| AclError::OutboundError {
                    kind: OutboundErrorKind::Io,
                    message: "Connection timeout".to_string(),
                })?
                .map_err(|e| AclError::OutboundError {
                    kind: OutboundErrorKind::ConnectionFailed,
                    message: format!("Failed to connect: {}", e),
                })?
        } else {
            tokio::time::timeout(self.timeout, TokioTcpStream::connect(socket_addr))
                .await
                .map_err(|_| AclError::OutboundError {
                    kind: OutboundErrorKind::Io,
                    message: "Connection timeout".to_string(),
                })?
                .map_err(|e| AclError::OutboundError {
                    kind: OutboundErrorKind::ConnectionFailed,
                    message: format!("Failed to connect: {}", e),
                })?
        };

        Ok(stream)
    }

    /// Async dual-stack dial TCP, racing IPv4 and IPv6 connections.
    #[cfg(feature = "async")]
    async fn async_dual_stack_dial_tcp(
        &self,
        ipv4: Ipv4Addr,
        ipv6: Ipv6Addr,
        port: u16,
    ) -> Result<TokioTcpStream> {
        let (first_ip, first_err, fallback_ip) = tokio::select! {
            result = self.async_dial_tcp_ip(IpAddr::V4(ipv4), port) => {
                if result.is_ok() {
                    return result;
                }
                (IpAddr::V4(ipv4), result.unwrap_err(), IpAddr::V6(ipv6))
            }
            result = self.async_dial_tcp_ip(IpAddr::V6(ipv6), port) => {
                if result.is_ok() {
                    return result;
                }
                (IpAddr::V6(ipv6), result.unwrap_err(), IpAddr::V4(ipv4))
            }
        };

        let fallback = self.async_dial_tcp_ip(fallback_ip, port).await;
        match fallback {
            Ok(stream) => Ok(stream),
            Err(second_err) => Err(AclError::OutboundError {
                kind: OutboundErrorKind::ConnectionFailed,
                message: format!(
                    "dual-stack connection failed: {} ({}), {} ({})",
                    first_ip, first_err, fallback_ip, second_err
                ),
            }),
        }
    }
}

impl Default for Direct {
    fn default() -> Self {
        Self::new()
    }
}

impl Outbound for Direct {
    fn dial_tcp(&self, addr: &mut Addr) -> Result<Box<dyn TcpConn>> {
        self.resolve(addr);

        let info = addr
            .resolve_info
            .as_ref()
            .ok_or_else(|| AclError::OutboundError {
                kind: OutboundErrorKind::DnsFailed,
                message: "No resolve info".to_string(),
            })?;

        if !info.has_address() {
            return Err(AclError::OutboundError {
                kind: OutboundErrorKind::DnsFailed,
                message: info.error
                    .clone()
                    .unwrap_or_else(|| "No address available".to_string()),
            });
        }

        let stream = if self.mode == DirectMode::Auto {
            if let (Some(ipv4), Some(ipv6)) = (info.ipv4, info.ipv6) {
                self.dual_stack_dial_tcp(ipv4, ipv6, addr.port)?
            } else {
                self.dial_tcp_ip(select_ip(self.mode, info)?, addr.port)?
            }
        } else {
            self.dial_tcp_ip(select_ip(self.mode, info)?, addr.port)?
        };

        Ok(Box::new(StdTcpConn::new(stream)))
    }

    fn dial_udp(&self, addr: &mut Addr) -> Result<Box<dyn UdpConn>> {
        self.resolve(addr);

        let use_ipv6 = self.should_use_ipv6(addr.resolve_info.as_ref());

        let socket = if self.bind_device.is_some() {
            UdpSocket::from(self.create_udp_socket_with_device(use_ipv6)?)
        } else {
            UdpSocket::bind(self.udp_bind_addr(use_ipv6))
                .map_err(|e| AclError::OutboundError {
                    kind: OutboundErrorKind::Io,
                    message: format!("Failed to bind UDP: {}", e),
                })?
        };

        Ok(Box::new(DirectUdpConn::new(socket, self.mode)))
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncOutbound for Direct {
    async fn dial_tcp(&self, addr: &mut Addr) -> Result<Box<dyn AsyncTcpConn>> {
        self.async_resolve(addr).await;

        let info = addr
            .resolve_info
            .as_ref()
            .ok_or_else(|| AclError::OutboundError {
                kind: OutboundErrorKind::DnsFailed,
                message: "No resolve info".to_string(),
            })?;

        if !info.has_address() {
            return Err(AclError::OutboundError {
                kind: OutboundErrorKind::DnsFailed,
                message: info.error
                    .clone()
                    .unwrap_or_else(|| "No address available".to_string()),
            });
        }

        let stream = if self.mode == DirectMode::Auto {
            if let (Some(ipv4), Some(ipv6)) = (info.ipv4, info.ipv6) {
                self.async_dual_stack_dial_tcp(ipv4, ipv6, addr.port)
                    .await?
            } else {
                self.async_dial_tcp_ip(select_ip(self.mode, info)?, addr.port)
                    .await?
            }
        } else {
            self.async_dial_tcp_ip(select_ip(self.mode, info)?, addr.port)
                .await?
        };

        Ok(Box::new(TokioTcpConn::new(stream)))
    }

    async fn dial_udp(&self, addr: &mut Addr) -> Result<Box<dyn AsyncUdpConn>> {
        self.async_resolve(addr).await;

        let use_ipv6 = self.should_use_ipv6(addr.resolve_info.as_ref());

        let socket = if self.bind_device.is_some() {
            let socket = self.create_udp_socket_with_device(use_ipv6)?;
            socket.set_nonblocking(true).map_err(|e| {
                AclError::OutboundError {
                    kind: OutboundErrorKind::Io,
                    message: format!("Failed to set nonblocking: {}", e),
                }
            })?;
            let std_socket: std::net::UdpSocket = socket.into();
            TokioUdpSocket::from_std(std_socket).map_err(|e| {
                AclError::OutboundError {
                    kind: OutboundErrorKind::Io,
                    message: format!("Failed to create UDP socket: {}", e),
                }
            })?
        } else {
            TokioUdpSocket::bind(self.udp_bind_addr(use_ipv6))
                .await
                .map_err(|e| AclError::OutboundError {
                    kind: OutboundErrorKind::Io,
                    message: format!("Failed to bind UDP: {}", e),
                })?
        };

        Ok(Box::new(AsyncDirectUdpConn::new(socket, self.mode)))
    }
}

/// Set TCP Fast Open on a socket.
///
/// - Linux: uses `TCP_FASTOPEN_CONNECT` (enables TFO for client connect() calls)
/// - macOS: uses `TCP_FASTOPEN`
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn set_tcp_fastopen(socket: &socket2::Socket) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    #[cfg(target_os = "linux")]
    const TFO_OPT: libc::c_int = 30; // TCP_FASTOPEN_CONNECT

    #[cfg(target_os = "macos")]
    const TFO_OPT: libc::c_int = libc::TCP_FASTOPEN;

    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            TFO_OPT,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(AclError::OutboundError {
            kind: OutboundErrorKind::Io,
            message: format!(
                "Failed to set TCP Fast Open: {}",
                std::io::Error::last_os_error()
            ),
        });
    }
    Ok(())
}

/// Stub for unsupported platforms.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn set_tcp_fastopen(_socket: &socket2::Socket) -> Result<()> {
    Err(AclError::ConfigError(
        "TCP Fast Open is not supported on this platform".to_string(),
    ))
}

/// Select an IP address based on DirectMode preference.
///
/// For Auto mode, behaves like Prefer46 (prefers IPv4, falls back to IPv6).
/// TCP callers should handle Auto's dual-stack case separately before calling this.
fn select_ip(mode: DirectMode, info: &ResolveInfo) -> Result<IpAddr> {
    match mode {
        DirectMode::Auto | DirectMode::Prefer46 => info
            .ipv4
            .map(IpAddr::V4)
            .or(info.ipv6.map(IpAddr::V6))
            .ok_or_else(|| AclError::OutboundError {
                kind: OutboundErrorKind::DnsFailed,
                message: "No address available".to_string(),
            }),
        DirectMode::Prefer64 => info
            .ipv6
            .map(IpAddr::V6)
            .or(info.ipv4.map(IpAddr::V4))
            .ok_or_else(|| AclError::OutboundError {
                kind: OutboundErrorKind::DnsFailed,
                message: "No address available".to_string(),
            }),
        DirectMode::Only6 => info
            .ipv6
            .map(IpAddr::V6)
            .ok_or_else(|| AclError::OutboundError {
                kind: OutboundErrorKind::DnsFailed,
                message: "No IPv6 address available".to_string(),
            }),
        DirectMode::Only4 => info
            .ipv4
            .map(IpAddr::V4)
            .ok_or_else(|| AclError::OutboundError {
                kind: OutboundErrorKind::DnsFailed,
                message: "No IPv4 address available".to_string(),
            }),
    }
}

/// Resolve UDP target address based on DirectMode preference.
fn resolve_udp_addr(mode: DirectMode, addr: &Addr) -> Result<SocketAddr> {
    if let Some(ref info) = addr.resolve_info {
        let ip = select_ip(mode, info)?;
        return Ok(SocketAddr::new(ip, addr.port));
    }

    // Fall back to parsing the address string
    addr.network_addr()
        .parse()
        .map_err(|e| AclError::OutboundError {
            kind: OutboundErrorKind::Io,
            message: format!("Invalid address: {}", e),
        })
}

/// Direct UDP connection with mode-aware address selection.
struct DirectUdpConn {
    socket: UdpSocket,
    mode: DirectMode,
}

impl DirectUdpConn {
    fn new(socket: UdpSocket, mode: DirectMode) -> Self {
        Self { socket, mode }
    }
}

impl UdpConn for DirectUdpConn {
    fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)> {
        let (n, addr) = self
            .socket
            .recv_from(buf)
            .map_err(|e| AclError::OutboundError {
                kind: OutboundErrorKind::Io,
                message: format!("UDP recv error: {}", e),
            })?;
        Ok((n, Addr::new(addr.ip().to_string(), addr.port())))
    }

    fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize> {
        let socket_addr = resolve_udp_addr(self.mode, addr)?;
        self.socket
            .send_to(buf, socket_addr)
            .map_err(|e| AclError::OutboundError {
                kind: OutboundErrorKind::Io,
                message: format!("UDP send error: {}", e),
            })
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Async direct UDP connection with mode-aware address selection.
#[cfg(feature = "async")]
struct AsyncDirectUdpConn {
    socket: TokioUdpSocket,
    mode: DirectMode,
}

#[cfg(feature = "async")]
impl AsyncDirectUdpConn {
    fn new(socket: TokioUdpSocket, mode: DirectMode) -> Self {
        Self { socket, mode }
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncUdpConn for AsyncDirectUdpConn {
    async fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)> {
        let (n, addr) = self
            .socket
            .recv_from(buf)
            .await
            .map_err(|e| AclError::OutboundError {
                kind: OutboundErrorKind::Io,
                message: format!("UDP recv error: {}", e),
            })?;
        Ok((n, Addr::new(addr.ip().to_string(), addr.port())))
    }

    async fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize> {
        let socket_addr = resolve_udp_addr(self.mode, addr)?;
        self.socket
            .send_to(buf, socket_addr)
            .await
            .map_err(|e| AclError::OutboundError {
                kind: OutboundErrorKind::Io,
                message: format!("UDP send error: {}", e),
            })
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_mode_default() {
        let mode = DirectMode::default();
        assert_eq!(mode, DirectMode::Auto);
    }

    #[test]
    fn test_direct_new() {
        let direct = Direct::new();
        assert_eq!(direct.mode, DirectMode::Auto);
        assert!(direct.bind_ip4.is_none());
        assert!(direct.bind_ip6.is_none());
        assert!(direct.bind_device.is_none());
        assert!(!direct.fast_open);
    }

    #[test]
    fn test_direct_with_options() {
        let opts = DirectOptions {
            mode: DirectMode::Prefer46,
            fast_open: true,
            ..Default::default()
        };
        let direct = Direct::with_options(opts).unwrap();
        assert_eq!(direct.mode, DirectMode::Prefer46);
        assert!(direct.fast_open);
    }

    #[test]
    fn test_bind_device_exclusive_with_bind_ip() {
        let opts = DirectOptions {
            bind_device: Some("eth0".to_string()),
            bind_ip4: Some(Ipv4Addr::new(1, 2, 3, 4)),
            ..Default::default()
        };
        assert!(Direct::with_options(opts).is_err());

        let opts = DirectOptions {
            bind_device: Some("eth0".to_string()),
            bind_ip6: Some(Ipv6Addr::LOCALHOST),
            ..Default::default()
        };
        assert!(Direct::with_options(opts).is_err());
    }

    #[test]
    fn test_bind_device_without_bind_ip() {
        let opts = DirectOptions {
            bind_device: Some("eth0".to_string()),
            ..Default::default()
        };
        let direct = Direct::with_options(opts).unwrap();
        assert_eq!(direct.bind_device.as_deref(), Some("eth0"));
    }

    #[test]
    fn test_resolve_ip_address() {
        let direct = Direct::new();
        let mut addr = Addr::new("127.0.0.1", 80);
        direct.resolve(&mut addr);

        assert!(addr.resolve_info.is_some());
        let info = addr.resolve_info.unwrap();
        assert_eq!(info.ipv4, Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(info.ipv6.is_none());
    }

    #[test]
    fn test_select_ip_auto_both_prefers_v4() {
        let info = ResolveInfo {
            ipv4: Some(Ipv4Addr::new(1, 2, 3, 4)),
            ipv6: Some(Ipv6Addr::LOCALHOST),
            error: None,
        };
        let ip = select_ip(DirectMode::Auto, &info).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn test_select_ip_auto_v4_only() {
        let info = ResolveInfo::from_ipv4(Ipv4Addr::new(10, 0, 0, 1));
        let ip = select_ip(DirectMode::Auto, &info).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_select_ip_auto_v6_only() {
        let info = ResolveInfo::from_ipv6(Ipv6Addr::LOCALHOST);
        let ip = select_ip(DirectMode::Auto, &info).unwrap();
        assert_eq!(ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_select_ip_auto_no_address() {
        let info = ResolveInfo::new();
        assert!(select_ip(DirectMode::Auto, &info).is_err());
    }

    #[test]
    fn test_select_ip_prefer64_both_prefers_v6() {
        let info = ResolveInfo {
            ipv4: Some(Ipv4Addr::new(1, 2, 3, 4)),
            ipv6: Some(Ipv6Addr::LOCALHOST),
            error: None,
        };
        let ip = select_ip(DirectMode::Prefer64, &info).unwrap();
        assert_eq!(ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_select_ip_prefer64_v4_fallback() {
        let info = ResolveInfo::from_ipv4(Ipv4Addr::new(1, 2, 3, 4));
        let ip = select_ip(DirectMode::Prefer64, &info).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn test_select_ip_prefer46_both_prefers_v4() {
        let info = ResolveInfo {
            ipv4: Some(Ipv4Addr::new(1, 2, 3, 4)),
            ipv6: Some(Ipv6Addr::LOCALHOST),
            error: None,
        };
        let ip = select_ip(DirectMode::Prefer46, &info).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn test_select_ip_only6_success() {
        let info = ResolveInfo::from_ipv6(Ipv6Addr::LOCALHOST);
        let ip = select_ip(DirectMode::Only6, &info).unwrap();
        assert_eq!(ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_select_ip_only6_fails_when_no_v6() {
        let info = ResolveInfo::from_ipv4(Ipv4Addr::new(1, 2, 3, 4));
        let err = select_ip(DirectMode::Only6, &info).unwrap_err();
        assert!(err.to_string().contains("IPv6"));
    }

    #[test]
    fn test_select_ip_only4_success() {
        let info = ResolveInfo::from_ipv4(Ipv4Addr::new(1, 2, 3, 4));
        let ip = select_ip(DirectMode::Only4, &info).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn test_select_ip_only4_fails_when_no_v4() {
        let info = ResolveInfo::from_ipv6(Ipv6Addr::LOCALHOST);
        let err = select_ip(DirectMode::Only4, &info).unwrap_err();
        assert!(err.to_string().contains("IPv4"));
    }

    #[test]
    fn test_select_ip_empty_resolve_info() {
        let info = ResolveInfo::new();
        assert!(select_ip(DirectMode::Prefer46, &info).is_err());
        assert!(select_ip(DirectMode::Prefer64, &info).is_err());
        assert!(select_ip(DirectMode::Only4, &info).is_err());
        assert!(select_ip(DirectMode::Only6, &info).is_err());
    }

    #[test]
    fn test_udp_bind_addr_ipv4_default() {
        let direct = Direct::new();
        let addr = direct.udp_bind_addr(false);
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    }

    #[test]
    fn test_udp_bind_addr_ipv6_default() {
        let direct = Direct::new();
        let addr = direct.udp_bind_addr(true);
        assert_eq!(addr, SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0));
    }

    #[test]
    fn test_udp_bind_addr_ipv4_custom() {
        let direct = Direct::with_options(DirectOptions {
            bind_ip4: Some(Ipv4Addr::new(192, 168, 1, 1)),
            ..Default::default()
        }).unwrap();
        let addr = direct.udp_bind_addr(false);
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 0));
    }

    #[test]
    fn test_udp_bind_addr_ipv6_custom() {
        let direct = Direct::with_options(DirectOptions {
            bind_ip6: Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            ..Default::default()
        }).unwrap();
        let addr = direct.udp_bind_addr(true);
        assert_eq!(addr, SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 0));
    }

    #[test]
    fn test_dial_tcp_ip_cancellable_skips_when_cancelled() {
        let direct = Direct::with_options(DirectOptions {
            timeout: Some(Duration::from_secs(1)),
            ..Default::default()
        })
        .unwrap();
        let cancelled = Arc::new(AtomicBool::new(true)); // Already cancelled

        // Should return None without attempting connection
        let result =
            direct.dial_tcp_ip_cancellable(IpAddr::V4(Ipv4Addr::LOCALHOST), 80, &cancelled);
        assert!(result.is_none(), "Should skip connection when cancelled");
    }

    #[test]
    fn test_dial_tcp_ip_cancellable_attempts_when_not_cancelled() {
        let direct = Direct::with_options(DirectOptions {
            timeout: Some(Duration::from_secs(1)),
            ..Default::default()
        })
        .unwrap();
        let cancelled = Arc::new(AtomicBool::new(false)); // Not cancelled

        // Should attempt connection (port 1 → connection refused)
        let result =
            direct.dial_tcp_ip_cancellable(IpAddr::V4(Ipv4Addr::LOCALHOST), 1, &cancelled);
        assert!(
            result.is_some(),
            "Should attempt connection when not cancelled"
        );
        assert!(result.unwrap().is_err(), "Port 1 should fail");
    }

    #[test]
    fn test_dual_stack_both_fail_error_includes_context() {
        // BUG B3: dual_stack_dial_tcp silently discards the first error.
        // When both v4 and v6 fail, the error should mention both attempts.
        use super::Outbound;

        let direct = Direct::with_options(DirectOptions {
            timeout: Some(Duration::from_secs(2)),
            ..Default::default()
        }).unwrap();
        let mut addr = Addr::new("test.invalid", 1);
        // Both loopback on port 1 → "connection refused"
        addr.resolve_info = Some(ResolveInfo {
            ipv4: Some(Ipv4Addr::LOCALHOST),
            ipv6: Some(Ipv6Addr::LOCALHOST),
            error: None,
        });

        let result = Outbound::dial_tcp(&direct, &mut addr);
        match result {
            Err(e) => {
                let err_msg = e.to_string();
                // After fix: error should contain both addresses so the dev
                // knows BOTH paths were tried and failed.
                assert!(
                    (err_msg.contains("127.0.0.1") && err_msg.contains("::1"))
                        || err_msg.contains("dual")
                        || err_msg.contains("both"),
                    "Dual-stack failure should mention both addresses, got: {}",
                    err_msg
                );
            }
            Ok(_) => panic!("Expected connection error on port 1"),
        }
    }

}

#[cfg(all(test, feature = "async"))]
mod async_tests {
    use super::*;

    #[tokio::test]
    async fn test_async_direct_resolve_ip() {
        let direct = Direct::new();
        let mut addr = Addr::new("127.0.0.1", 80);
        direct.async_resolve(&mut addr).await;

        assert!(addr.resolve_info.is_some());
        let info = addr.resolve_info.unwrap();
        assert_eq!(info.ipv4, Some(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[tokio::test]
    async fn test_async_direct_dial_tcp_localhost() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let direct = Direct::new();
        let mut addr = Addr::new("127.0.0.1", port);

        let accept_handle = tokio::spawn(async move { listener.accept().await.ok() });

        let result = AsyncOutbound::dial_tcp(&direct, &mut addr).await;
        assert!(result.is_ok());

        accept_handle.await.ok();
    }

    #[tokio::test]
    async fn test_async_direct_dial_tcp_connection_refused() {
        let direct = Direct::new();
        let mut addr = Addr::new("127.0.0.1", 59999);

        let result = AsyncOutbound::dial_tcp(&direct, &mut addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_direct_dial_udp() {
        let direct = Direct::new();
        let mut addr = Addr::new("127.0.0.1", 53);

        let result = AsyncOutbound::dial_udp(&direct, &mut addr).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_async_direct_modes() {
        let direct = Direct::with_mode(DirectMode::Only4);
        let mut addr = Addr::new("127.0.0.1", 80);
        addr.resolve_info = Some(ResolveInfo::from_ipv4(Ipv4Addr::new(127, 0, 0, 1)));

        direct.async_resolve(&mut addr).await;
        assert!(addr.resolve_info.is_some());
    }
}
