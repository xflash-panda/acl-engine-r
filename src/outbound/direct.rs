//! Direct outbound connection implementation.
//!
//! Connects directly to the target using the local network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::error::{AclError, Result};

use super::{
    split_ipv4_ipv6, Addr, Outbound, ResolveInfo, StdTcpConn, TcpConn, UdpConn,
    DEFAULT_DIALER_TIMEOUT,
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
    /// Connection timeout
    pub timeout: Option<Duration>,
}

/// Direct outbound that connects directly to the target.
///
/// It prefers to use ResolveInfo in Addr if available. But if it's None,
/// it will fall back to resolving Host using the system DNS resolver.
pub struct Direct {
    mode: DirectMode,
    bind_ip4: Option<Ipv4Addr>,
    bind_ip6: Option<Ipv6Addr>,
    timeout: Duration,
}

impl Direct {
    /// Create a new Direct outbound with default settings.
    pub fn new() -> Self {
        Self {
            mode: DirectMode::Auto,
            bind_ip4: None,
            bind_ip6: None,
            timeout: DEFAULT_DIALER_TIMEOUT,
        }
    }

    /// Create a new Direct outbound with the given mode.
    pub fn with_mode(mode: DirectMode) -> Self {
        Self {
            mode,
            bind_ip4: None,
            bind_ip6: None,
            timeout: DEFAULT_DIALER_TIMEOUT,
        }
    }

    /// Create a new Direct outbound with the given options.
    pub fn with_options(opts: DirectOptions) -> Result<Self> {
        Ok(Self {
            mode: opts.mode,
            bind_ip4: opts.bind_ip4,
            bind_ip6: opts.bind_ip6,
            timeout: opts.timeout.unwrap_or(DEFAULT_DIALER_TIMEOUT),
        })
    }

    /// Resolve the address using system DNS if ResolveInfo is not available.
    fn resolve(&self, addr: &mut Addr) {
        if addr.resolve_info.is_some() {
            return;
        }

        // Check if host is already an IP address
        if let Ok(ip) = addr.host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    addr.resolve_info = Some(ResolveInfo::from_ipv4(v4));
                }
                IpAddr::V6(v6) => {
                    addr.resolve_info = Some(ResolveInfo::from_ipv6(v6));
                }
            }
            return;
        }

        // Resolve using system DNS
        match (addr.host.as_str(), 0u16).to_socket_addrs() {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                let (ipv4, ipv6) = split_ipv4_ipv6(&ips);
                if ipv4.is_none() && ipv6.is_none() {
                    addr.resolve_info = Some(ResolveInfo::from_error("no address found"));
                } else {
                    addr.resolve_info = Some(ResolveInfo {
                        ipv4,
                        ipv6,
                        error: None,
                    });
                }
            }
            Err(e) => {
                addr.resolve_info = Some(ResolveInfo::from_error(e.to_string()));
            }
        }
    }

    /// Dial TCP to a specific IP address.
    fn dial_tcp_ip(&self, ip: IpAddr, port: u16) -> Result<TcpStream> {
        let socket_addr = SocketAddr::new(ip, port);

        let stream = if let Some(bind_ip) = self.get_bind_ip(&ip) {
            // Create socket with bind address
            let bind_addr = SocketAddr::new(bind_ip, 0);
            let socket = match ip {
                IpAddr::V4(_) => {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| {
                        AclError::OutboundError(format!("Failed to create socket: {}", e))
                    })?;
                    socket
                        .bind(&bind_addr.into())
                        .map_err(|e| AclError::OutboundError(format!("Failed to bind: {}", e)))?;
                    socket
                }
                IpAddr::V6(_) => {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV6,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| {
                        AclError::OutboundError(format!("Failed to create socket: {}", e))
                    })?;
                    socket
                        .bind(&bind_addr.into())
                        .map_err(|e| AclError::OutboundError(format!("Failed to bind: {}", e)))?;
                    socket
                }
            };
            socket.set_nonblocking(false).ok();
            socket
                .connect_timeout(&socket_addr.into(), self.timeout)
                .map_err(|e| AclError::OutboundError(format!("Failed to connect: {}", e)))?;
            TcpStream::from(socket)
        } else {
            TcpStream::connect_timeout(&socket_addr, self.timeout)
                .map_err(|e| AclError::OutboundError(format!("Failed to connect: {}", e)))?
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

    /// Dual-stack dial TCP, racing IPv4 and IPv6 connections.
    fn dual_stack_dial_tcp(&self, ipv4: Ipv4Addr, ipv6: Ipv6Addr, port: u16) -> Result<TcpStream> {
        let (tx, rx) = mpsc::channel();

        let self_clone_v4 = Direct {
            mode: self.mode,
            bind_ip4: self.bind_ip4,
            bind_ip6: self.bind_ip6,
            timeout: self.timeout,
        };
        let tx_v4 = tx.clone();
        thread::spawn(move || {
            let result = self_clone_v4.dial_tcp_ip(IpAddr::V4(ipv4), port);
            let _ = tx_v4.send(result);
        });

        let self_clone_v6 = Direct {
            mode: self.mode,
            bind_ip4: self.bind_ip4,
            bind_ip6: self.bind_ip6,
            timeout: self.timeout,
        };
        thread::spawn(move || {
            let result = self_clone_v6.dial_tcp_ip(IpAddr::V6(ipv6), port);
            let _ = tx.send(result);
        });

        // Get first result
        let first = rx
            .recv()
            .map_err(|_| AclError::OutboundError("Channel error".to_string()))?;

        if first.is_ok() {
            return first;
        }

        // First failed, try second
        rx.recv()
            .map_err(|_| AclError::OutboundError("Channel error".to_string()))?
    }

    /// Async resolve the address using system DNS if ResolveInfo is not available.
    #[cfg(feature = "async")]
    async fn async_resolve(&self, addr: &mut Addr) {
        if addr.resolve_info.is_some() {
            return;
        }

        if let Ok(ip) = addr.host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    addr.resolve_info = Some(ResolveInfo::from_ipv4(v4));
                }
                IpAddr::V6(v6) => {
                    addr.resolve_info = Some(ResolveInfo::from_ipv6(v6));
                }
            }
            return;
        }

        match tokio::net::lookup_host(format!("{}:0", addr.host)).await {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                let (ipv4, ipv6) = split_ipv4_ipv6(&ips);
                if ipv4.is_none() && ipv6.is_none() {
                    addr.resolve_info = Some(ResolveInfo::from_error("no address found"));
                } else {
                    addr.resolve_info = Some(ResolveInfo {
                        ipv4,
                        ipv6,
                        error: None,
                    });
                }
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

        let stream = if let Some(bind_ip) = self.get_bind_ip(&ip) {
            let bind_addr = SocketAddr::new(bind_ip, 0);
            let socket = match ip {
                IpAddr::V4(_) => {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| {
                        AclError::OutboundError(format!("Failed to create socket: {}", e))
                    })?;
                    socket
                        .bind(&bind_addr.into())
                        .map_err(|e| AclError::OutboundError(format!("Failed to bind: {}", e)))?;
                    socket.set_nonblocking(true).ok();
                    socket
                }
                IpAddr::V6(_) => {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV6,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| {
                        AclError::OutboundError(format!("Failed to create socket: {}", e))
                    })?;
                    socket
                        .bind(&bind_addr.into())
                        .map_err(|e| AclError::OutboundError(format!("Failed to bind: {}", e)))?;
                    socket.set_nonblocking(true).ok();
                    socket
                }
            };
            let std_stream: std::net::TcpStream = socket.into();
            let tokio_socket = tokio::net::TcpSocket::from_std_stream(std_stream);
            tokio::time::timeout(self.timeout, tokio_socket.connect(socket_addr))
                .await
                .map_err(|_| AclError::OutboundError("Connection timeout".to_string()))?
                .map_err(|e| AclError::OutboundError(format!("Failed to connect: {}", e)))?
        } else {
            tokio::time::timeout(self.timeout, TokioTcpStream::connect(socket_addr))
                .await
                .map_err(|_| AclError::OutboundError("Connection timeout".to_string()))?
                .map_err(|e| AclError::OutboundError(format!("Failed to connect: {}", e)))?
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
        tokio::select! {
            result = self.async_dial_tcp_ip(IpAddr::V4(ipv4), port) => {
                if result.is_ok() {
                    return result;
                }
                self.async_dial_tcp_ip(IpAddr::V6(ipv6), port).await
            }
            result = self.async_dial_tcp_ip(IpAddr::V6(ipv6), port) => {
                if result.is_ok() {
                    return result;
                }
                self.async_dial_tcp_ip(IpAddr::V4(ipv4), port).await
            }
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
            .ok_or_else(|| AclError::OutboundError("No resolve info".to_string()))?;

        if !info.has_address() {
            return Err(AclError::OutboundError(
                info.error
                    .clone()
                    .unwrap_or_else(|| "No address available".to_string()),
            ));
        }

        let stream = match self.mode {
            DirectMode::Auto => {
                if let (Some(ipv4), Some(ipv6)) = (info.ipv4, info.ipv6) {
                    self.dual_stack_dial_tcp(ipv4, ipv6, addr.port)?
                } else if let Some(ipv4) = info.ipv4 {
                    self.dial_tcp_ip(IpAddr::V4(ipv4), addr.port)?
                } else if let Some(ipv6) = info.ipv6 {
                    self.dial_tcp_ip(IpAddr::V6(ipv6), addr.port)?
                } else {
                    return Err(AclError::OutboundError("No address available".to_string()));
                }
            }
            DirectMode::Prefer64 => {
                if let Some(ipv6) = info.ipv6 {
                    self.dial_tcp_ip(IpAddr::V6(ipv6), addr.port)?
                } else if let Some(ipv4) = info.ipv4 {
                    self.dial_tcp_ip(IpAddr::V4(ipv4), addr.port)?
                } else {
                    return Err(AclError::OutboundError("No address available".to_string()));
                }
            }
            DirectMode::Prefer46 => {
                if let Some(ipv4) = info.ipv4 {
                    self.dial_tcp_ip(IpAddr::V4(ipv4), addr.port)?
                } else if let Some(ipv6) = info.ipv6 {
                    self.dial_tcp_ip(IpAddr::V6(ipv6), addr.port)?
                } else {
                    return Err(AclError::OutboundError("No address available".to_string()));
                }
            }
            DirectMode::Only6 => {
                if let Some(ipv6) = info.ipv6 {
                    self.dial_tcp_ip(IpAddr::V6(ipv6), addr.port)?
                } else {
                    return Err(AclError::OutboundError(
                        "No IPv6 address available".to_string(),
                    ));
                }
            }
            DirectMode::Only4 => {
                if let Some(ipv4) = info.ipv4 {
                    self.dial_tcp_ip(IpAddr::V4(ipv4), addr.port)?
                } else {
                    return Err(AclError::OutboundError(
                        "No IPv4 address available".to_string(),
                    ));
                }
            }
        };

        Ok(Box::new(StdTcpConn::new(stream)))
    }

    fn dial_udp(&self, addr: &mut Addr) -> Result<Box<dyn UdpConn>> {
        self.resolve(addr);

        let info = addr.resolve_info.as_ref();

        // Determine which address family to use
        let use_ipv6 = match self.mode {
            DirectMode::Auto | DirectMode::Prefer46 => {
                // Prefer IPv4 for maximum compatibility
                info.and_then(|i| i.ipv4).is_none() && info.and_then(|i| i.ipv6).is_some()
            }
            DirectMode::Prefer64 => info.and_then(|i| i.ipv6).is_some(),
            DirectMode::Only6 => true,
            DirectMode::Only4 => false,
        };

        let socket = if use_ipv6 {
            let bind_addr = self
                .bind_ip6
                .map(|ip| SocketAddr::new(IpAddr::V6(ip), 0))
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0));
            UdpSocket::bind(bind_addr)
                .map_err(|e| AclError::OutboundError(format!("Failed to bind UDP: {}", e)))?
        } else {
            let bind_addr = self
                .bind_ip4
                .map(|ip| SocketAddr::new(IpAddr::V4(ip), 0))
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
            UdpSocket::bind(bind_addr)
                .map_err(|e| AclError::OutboundError(format!("Failed to bind UDP: {}", e)))?
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
            .ok_or_else(|| AclError::OutboundError("No resolve info".to_string()))?;

        if !info.has_address() {
            return Err(AclError::OutboundError(
                info.error
                    .clone()
                    .unwrap_or_else(|| "No address available".to_string()),
            ));
        }

        let stream = match self.mode {
            DirectMode::Auto => {
                if let (Some(ipv4), Some(ipv6)) = (info.ipv4, info.ipv6) {
                    self.async_dual_stack_dial_tcp(ipv4, ipv6, addr.port)
                        .await?
                } else if let Some(ipv4) = info.ipv4 {
                    self.async_dial_tcp_ip(IpAddr::V4(ipv4), addr.port).await?
                } else if let Some(ipv6) = info.ipv6 {
                    self.async_dial_tcp_ip(IpAddr::V6(ipv6), addr.port).await?
                } else {
                    return Err(AclError::OutboundError("No address available".to_string()));
                }
            }
            DirectMode::Prefer64 => {
                if let Some(ipv6) = info.ipv6 {
                    self.async_dial_tcp_ip(IpAddr::V6(ipv6), addr.port).await?
                } else if let Some(ipv4) = info.ipv4 {
                    self.async_dial_tcp_ip(IpAddr::V4(ipv4), addr.port).await?
                } else {
                    return Err(AclError::OutboundError("No address available".to_string()));
                }
            }
            DirectMode::Prefer46 => {
                if let Some(ipv4) = info.ipv4 {
                    self.async_dial_tcp_ip(IpAddr::V4(ipv4), addr.port).await?
                } else if let Some(ipv6) = info.ipv6 {
                    self.async_dial_tcp_ip(IpAddr::V6(ipv6), addr.port).await?
                } else {
                    return Err(AclError::OutboundError("No address available".to_string()));
                }
            }
            DirectMode::Only6 => {
                if let Some(ipv6) = info.ipv6 {
                    self.async_dial_tcp_ip(IpAddr::V6(ipv6), addr.port).await?
                } else {
                    return Err(AclError::OutboundError(
                        "No IPv6 address available".to_string(),
                    ));
                }
            }
            DirectMode::Only4 => {
                if let Some(ipv4) = info.ipv4 {
                    self.async_dial_tcp_ip(IpAddr::V4(ipv4), addr.port).await?
                } else {
                    return Err(AclError::OutboundError(
                        "No IPv4 address available".to_string(),
                    ));
                }
            }
        };

        Ok(Box::new(TokioTcpConn::new(stream)))
    }

    async fn dial_udp(&self, addr: &mut Addr) -> Result<Box<dyn AsyncUdpConn>> {
        self.async_resolve(addr).await;

        let info = addr.resolve_info.as_ref();

        let use_ipv6 = match self.mode {
            DirectMode::Auto | DirectMode::Prefer46 => {
                info.and_then(|i| i.ipv4).is_none() && info.and_then(|i| i.ipv6).is_some()
            }
            DirectMode::Prefer64 => info.and_then(|i| i.ipv6).is_some(),
            DirectMode::Only6 => true,
            DirectMode::Only4 => false,
        };

        let socket = if use_ipv6 {
            let bind_addr = self
                .bind_ip6
                .map(|ip| SocketAddr::new(IpAddr::V6(ip), 0))
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0));
            TokioUdpSocket::bind(bind_addr)
                .await
                .map_err(|e| AclError::OutboundError(format!("Failed to bind UDP: {}", e)))?
        } else {
            let bind_addr = self
                .bind_ip4
                .map(|ip| SocketAddr::new(IpAddr::V4(ip), 0))
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
            TokioUdpSocket::bind(bind_addr)
                .await
                .map_err(|e| AclError::OutboundError(format!("Failed to bind UDP: {}", e)))?
        };

        Ok(Box::new(AsyncDirectUdpConn::new(socket, self.mode)))
    }
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

    fn resolve_addr(&self, addr: &Addr) -> Result<SocketAddr> {
        if let Some(ref info) = addr.resolve_info {
            let ip = match self.mode {
                DirectMode::Auto | DirectMode::Prefer46 => {
                    if let Some(ipv4) = info.ipv4 {
                        IpAddr::V4(ipv4)
                    } else if let Some(ipv6) = info.ipv6 {
                        IpAddr::V6(ipv6)
                    } else {
                        return Err(AclError::OutboundError("No address available".to_string()));
                    }
                }
                DirectMode::Prefer64 => {
                    if let Some(ipv6) = info.ipv6 {
                        IpAddr::V6(ipv6)
                    } else if let Some(ipv4) = info.ipv4 {
                        IpAddr::V4(ipv4)
                    } else {
                        return Err(AclError::OutboundError("No address available".to_string()));
                    }
                }
                DirectMode::Only6 => {
                    if let Some(ipv6) = info.ipv6 {
                        IpAddr::V6(ipv6)
                    } else {
                        return Err(AclError::OutboundError(
                            "No IPv6 address available".to_string(),
                        ));
                    }
                }
                DirectMode::Only4 => {
                    if let Some(ipv4) = info.ipv4 {
                        IpAddr::V4(ipv4)
                    } else {
                        return Err(AclError::OutboundError(
                            "No IPv4 address available".to_string(),
                        ));
                    }
                }
            };
            return Ok(SocketAddr::new(ip, addr.port));
        }

        // Fall back to parsing the address string
        addr.network_addr()
            .parse()
            .map_err(|e| AclError::OutboundError(format!("Invalid address: {}", e)))
    }
}

impl UdpConn for DirectUdpConn {
    fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)> {
        let (n, addr) = self
            .socket
            .recv_from(buf)
            .map_err(|e| AclError::OutboundError(format!("UDP recv error: {}", e)))?;
        Ok((n, Addr::new(addr.ip().to_string(), addr.port())))
    }

    fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize> {
        let socket_addr = self.resolve_addr(addr)?;
        self.socket
            .send_to(buf, socket_addr)
            .map_err(|e| AclError::OutboundError(format!("UDP send error: {}", e)))
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

    fn resolve_addr(&self, addr: &Addr) -> Result<SocketAddr> {
        if let Some(ref info) = addr.resolve_info {
            let ip = match self.mode {
                DirectMode::Auto | DirectMode::Prefer46 => {
                    if let Some(ipv4) = info.ipv4 {
                        IpAddr::V4(ipv4)
                    } else if let Some(ipv6) = info.ipv6 {
                        IpAddr::V6(ipv6)
                    } else {
                        return Err(AclError::OutboundError("No address available".to_string()));
                    }
                }
                DirectMode::Prefer64 => {
                    if let Some(ipv6) = info.ipv6 {
                        IpAddr::V6(ipv6)
                    } else if let Some(ipv4) = info.ipv4 {
                        IpAddr::V4(ipv4)
                    } else {
                        return Err(AclError::OutboundError("No address available".to_string()));
                    }
                }
                DirectMode::Only6 => {
                    if let Some(ipv6) = info.ipv6 {
                        IpAddr::V6(ipv6)
                    } else {
                        return Err(AclError::OutboundError(
                            "No IPv6 address available".to_string(),
                        ));
                    }
                }
                DirectMode::Only4 => {
                    if let Some(ipv4) = info.ipv4 {
                        IpAddr::V4(ipv4)
                    } else {
                        return Err(AclError::OutboundError(
                            "No IPv4 address available".to_string(),
                        ));
                    }
                }
            };
            return Ok(SocketAddr::new(ip, addr.port));
        }

        addr.network_addr()
            .parse()
            .map_err(|e| AclError::OutboundError(format!("Invalid address: {}", e)))
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
            .map_err(|e| AclError::OutboundError(format!("UDP recv error: {}", e)))?;
        Ok((n, Addr::new(addr.ip().to_string(), addr.port())))
    }

    async fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize> {
        let socket_addr = self.resolve_addr(addr)?;
        self.socket
            .send_to(buf, socket_addr)
            .await
            .map_err(|e| AclError::OutboundError(format!("UDP send error: {}", e)))
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
