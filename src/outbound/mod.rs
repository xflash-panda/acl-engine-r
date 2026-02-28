//! Outbound connection implementations.
//!
//! This module provides various outbound connection types:
//! - `Direct`: Direct connection with dual-stack support
//! - `Reject`: Reject all connections
//! - `Socks5`: SOCKS5 proxy connection
//! - `Http`: HTTP/HTTPS proxy connection (CONNECT method)

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use crate::error::{AclError, Result};

#[cfg(feature = "async")]
use async_trait::async_trait;
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

mod direct;
mod http;
mod reject;
mod socks5;

pub use direct::{Direct, DirectMode, DirectOptions};
pub use http::Http;
pub use reject::Reject;
pub use socks5::Socks5;

/// Default dialer timeout
pub const DEFAULT_DIALER_TIMEOUT: Duration = Duration::from_secs(10);

/// Network address with optional DNS resolution info.
#[derive(Debug, Clone)]
pub struct Addr {
    /// Hostname or IP address
    pub host: String,
    /// Port number
    pub port: u16,
    /// Optional DNS resolution result
    pub resolve_info: Option<ResolveInfo>,
}

impl Addr {
    /// Create a new Addr
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            resolve_info: None,
        }
    }

    /// Create an Addr from a SocketAddr, pre-populating resolve info.
    /// This avoids redundant DNS resolution for addresses from UDP recv_from.
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        let resolve_info = match addr.ip() {
            IpAddr::V4(v4) => ResolveInfo::from_ipv4(v4),
            IpAddr::V6(v6) => ResolveInfo::from_ipv6(v6),
        };
        Self {
            host: addr.ip().to_string(),
            port: addr.port(),
            resolve_info: Some(resolve_info),
        }
    }

    /// Create a new Addr with resolve info
    pub fn with_resolve_info(mut self, info: ResolveInfo) -> Self {
        self.resolve_info = Some(info);
        self
    }

    /// Get the address string in host:port format
    pub fn addr_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Get the network address for dialing.
    /// If ResolveInfo contains an IPv4 address, it returns that.
    /// Otherwise, if it contains an IPv6 address, it returns that.
    /// If no resolved address is available, it falls back to Host.
    pub fn network_addr(&self) -> String {
        if let Some(ref info) = self.resolve_info {
            if let Some(ipv4) = info.ipv4 {
                return SocketAddr::new(IpAddr::V4(ipv4), self.port).to_string();
            }
            if let Some(ipv6) = info.ipv6 {
                return SocketAddr::new(IpAddr::V6(ipv6), self.port).to_string();
            }
        }
        self.addr_string()
    }
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// DNS resolution results.
#[derive(Debug, Clone, Default)]
pub struct ResolveInfo {
    /// Resolved IPv4 address, if any
    pub ipv4: Option<std::net::Ipv4Addr>,
    /// Resolved IPv6 address, if any
    pub ipv6: Option<std::net::Ipv6Addr>,
    /// Error message that occurred during resolution, if any
    pub error: Option<String>,
}

impl ResolveInfo {
    /// Create a new empty ResolveInfo
    pub fn new() -> Self {
        Self::default()
    }

    /// Create ResolveInfo from IPv4 address
    pub fn from_ipv4(ipv4: std::net::Ipv4Addr) -> Self {
        Self {
            ipv4: Some(ipv4),
            ipv6: None,
            error: None,
        }
    }

    /// Create ResolveInfo from IPv6 address
    pub fn from_ipv6(ipv6: std::net::Ipv6Addr) -> Self {
        Self {
            ipv4: None,
            ipv6: Some(ipv6),
            error: None,
        }
    }

    /// Create ResolveInfo with error
    pub fn from_error(error: impl Into<String>) -> Self {
        Self {
            ipv4: None,
            ipv6: None,
            error: Some(error.into()),
        }
    }

    /// Check if any address is available
    pub fn has_address(&self) -> bool {
        self.ipv4.is_some() || self.ipv6.is_some()
    }
}

/// Outbound connection interface.
pub trait Outbound: Send + Sync {
    /// Establish a TCP connection to the given address.
    fn dial_tcp(&self, addr: &mut Addr) -> Result<Box<dyn TcpConn>>;

    /// Create a UDP connection for the given address.
    fn dial_udp(&self, addr: &mut Addr) -> Result<Box<dyn UdpConn>>;
}

/// Async outbound connection interface.
#[cfg(feature = "async")]
#[async_trait]
pub trait AsyncOutbound: Send + Sync {
    /// Establish an async TCP connection to the given address.
    async fn dial_tcp(&self, addr: &mut Addr) -> Result<Box<dyn AsyncTcpConn>>;

    /// Create an async UDP connection for the given address.
    async fn dial_udp(&self, addr: &mut Addr) -> Result<Box<dyn AsyncUdpConn>>;
}

/// TCP connection interface.
pub trait TcpConn: Read + Write + Send + Sync {
    /// Get the local address
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Get the peer address
    fn peer_addr(&self) -> io::Result<SocketAddr>;

    /// Set read timeout
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;

    /// Set write timeout
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()>;

    /// Shutdown the connection
    fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()>;
}

/// Async TCP connection interface.
#[cfg(feature = "async")]
pub trait AsyncTcpConn: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    /// Get the local address
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Get the peer address
    fn peer_addr(&self) -> io::Result<SocketAddr>;
}

/// Standard TcpStream wrapper implementing TcpConn
pub struct StdTcpConn {
    inner: TcpStream,
}

impl StdTcpConn {
    pub fn new(stream: TcpStream) -> Self {
        Self { inner: stream }
    }

    pub fn into_inner(self) -> TcpStream {
        self.inner
    }
}

impl Read for StdTcpConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for StdTcpConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TcpConn for StdTcpConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(dur)
    }

    fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }
}

/// UDP connection interface.
pub trait UdpConn: Send + Sync {
    /// Read from the UDP connection
    fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)>;

    /// Write to the UDP connection
    fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize>;

    /// Close the connection
    fn close(&self) -> Result<()>;
}

/// Async UDP connection interface.
#[cfg(feature = "async")]
#[async_trait]
pub trait AsyncUdpConn: Send + Sync {
    /// Read from the UDP connection
    async fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)>;

    /// Write to the UDP connection
    async fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize>;

    /// Close the connection
    async fn close(&self) -> Result<()>;
}

/// Standard UdpSocket wrapper implementing UdpConn
pub struct StdUdpConn {
    inner: UdpSocket,
}

impl StdUdpConn {
    pub fn new(socket: UdpSocket) -> Self {
        Self { inner: socket }
    }

    pub fn into_inner(self) -> UdpSocket {
        self.inner
    }
}

impl UdpConn for StdUdpConn {
    fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)> {
        let (n, addr) = self
            .inner
            .recv_from(buf)
            .map_err(|e| AclError::OutboundError(format!("UDP recv error: {}", e)))?;
        Ok((n, Addr::from_socket_addr(addr)))
    }

    fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize> {
        let socket_addr: SocketAddr = addr
            .network_addr()
            .parse()
            .map_err(|e| AclError::OutboundError(format!("Invalid address: {}", e)))?;
        self.inner
            .send_to(buf, socket_addr)
            .map_err(|e| AclError::OutboundError(format!("UDP send error: {}", e)))
    }

    fn close(&self) -> Result<()> {
        // UdpSocket doesn't have explicit close, it closes on drop
        Ok(())
    }
}

/// Tokio TcpStream wrapper implementing AsyncTcpConn
#[cfg(feature = "async")]
pub struct TokioTcpConn {
    inner: tokio::net::TcpStream,
}

#[cfg(feature = "async")]
impl TokioTcpConn {
    pub fn new(stream: tokio::net::TcpStream) -> Self {
        Self { inner: stream }
    }

    pub fn into_inner(self) -> tokio::net::TcpStream {
        self.inner
    }
}

#[cfg(feature = "async")]
impl AsyncRead for TokioTcpConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "async")]
impl AsyncWrite for TokioTcpConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(feature = "async")]
impl AsyncTcpConn for TokioTcpConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }
}

/// Tokio UdpSocket wrapper implementing AsyncUdpConn
#[cfg(feature = "async")]
pub struct TokioUdpConn {
    inner: tokio::net::UdpSocket,
}

#[cfg(feature = "async")]
impl TokioUdpConn {
    pub fn new(socket: tokio::net::UdpSocket) -> Self {
        Self { inner: socket }
    }

    pub fn into_inner(self) -> tokio::net::UdpSocket {
        self.inner
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncUdpConn for TokioUdpConn {
    async fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)> {
        let (n, addr) = self
            .inner
            .recv_from(buf)
            .await
            .map_err(|e| AclError::OutboundError(format!("UDP recv error: {}", e)))?;
        Ok((n, Addr::from_socket_addr(addr)))
    }

    async fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize> {
        let socket_addr: SocketAddr = addr
            .network_addr()
            .parse()
            .map_err(|e| AclError::OutboundError(format!("Invalid address: {}", e)))?;
        self.inner
            .send_to(buf, socket_addr)
            .await
            .map_err(|e| AclError::OutboundError(format!("UDP send error: {}", e)))
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Split IP addresses into IPv4 and IPv6
pub(crate) fn split_ipv4_ipv6(ips: &[IpAddr]) -> (Option<std::net::Ipv4Addr>, Option<std::net::Ipv6Addr>) {
    let mut ipv4 = None;
    let mut ipv6 = None;

    for ip in ips {
        match ip {
            IpAddr::V4(v4) if ipv4.is_none() => ipv4 = Some(*v4),
            IpAddr::V6(v6) if ipv6.is_none() => ipv6 = Some(*v6),
            _ => {}
        }
        if ipv4.is_some() && ipv6.is_some() {
            break;
        }
    }

    (ipv4, ipv6)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn test_addr_from_socket_addr_v4() {
        let sock_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let addr = Addr::from_socket_addr(sock_addr);

        assert_eq!(addr.host, "192.168.1.1");
        assert_eq!(addr.port, 8080);
        assert!(addr.resolve_info.is_some());
        let info = addr.resolve_info.unwrap();
        assert_eq!(info.ipv4, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(info.ipv6.is_none());
    }

    #[test]
    fn test_addr_from_socket_addr_v6() {
        let sock_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
        let addr = Addr::from_socket_addr(sock_addr);

        assert_eq!(addr.host, "::1");
        assert_eq!(addr.port, 443);
        assert!(addr.resolve_info.is_some());
        let info = addr.resolve_info.unwrap();
        assert!(info.ipv4.is_none());
        assert_eq!(info.ipv6, Some(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_addr_new_basic() {
        let addr = Addr::new("example.com", 80);
        assert_eq!(addr.host, "example.com");
        assert_eq!(addr.port, 80);
        assert!(addr.resolve_info.is_none());
    }

    #[test]
    fn test_addr_display() {
        let addr = Addr::new("example.com", 443);
        assert_eq!(format!("{}", addr), "example.com:443");
    }

    #[test]
    fn test_split_ipv4_ipv6_basic() {
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        let (v4, v6) = split_ipv4_ipv6(&ips);
        assert_eq!(v4, Some(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(v6, Some(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_split_ipv4_ipv6_empty() {
        let ips: Vec<IpAddr> = vec![];
        let (v4, v6) = split_ipv4_ipv6(&ips);
        assert!(v4.is_none());
        assert!(v6.is_none());
    }

    #[test]
    fn test_split_ipv4_ipv6_only_v4() {
        let ips = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        let (v4, v6) = split_ipv4_ipv6(&ips);
        assert_eq!(v4, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(v6.is_none());
    }

    #[test]
    fn test_split_ipv4_ipv6_takes_first() {
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        ];
        let (v4, v6) = split_ipv4_ipv6(&ips);
        assert_eq!(v4, Some(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(v6, Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    }
}
