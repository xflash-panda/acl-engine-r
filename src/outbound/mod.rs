//! Outbound connection implementations.
//!
//! This module provides various outbound connection types:
//! - `Direct`: Direct connection with dual-stack support
//! - `Reject`: Reject all connections
//! - `Socks5`: SOCKS5 proxy connection
//! - `Http`: HTTP/HTTPS proxy connection (CONNECT method)

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use crate::error::{AclError, OutboundErrorKind, Result};

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
///
/// Fields are crate-private to prevent bypassing input validation.
/// Use [`host()`](Self::host), [`port()`](Self::port), and
/// [`resolve_info()`](Self::resolve_info) for read access.
#[derive(Debug, Clone)]
pub struct Addr {
    /// Hostname or IP address
    pub(crate) host: String,
    /// Port number
    pub(crate) port: u16,
    /// Optional DNS resolution result
    pub(crate) resolve_info: Option<ResolveInfo>,
}

impl Addr {
    /// Create a new Addr.
    ///
    /// Control characters (bytes < 0x20 and 0x7F) are stripped from the host
    /// to prevent injection attacks in downstream protocols (HTTP CONNECT, SOCKS5).
    /// Use [`try_new`](Self::try_new) for strict validation that rejects bad input.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        let host: String = host
            .into()
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        Self {
            host,
            port,
            resolve_info: None,
        }
    }

    /// Create a new Addr with strict validation.
    ///
    /// Returns an error if:
    /// - host is empty
    /// - host contains control characters (bytes < 0x20 or 0x7F)
    pub fn try_new(host: impl Into<String>, port: u16) -> Result<Self> {
        let host = host.into();
        if host.is_empty() {
            return Err(AclError::InvalidAddress("host must not be empty".to_string()));
        }
        if host.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(AclError::InvalidAddress(
                "host contains control characters".to_string(),
            ));
        }
        Ok(Self {
            host,
            port,
            resolve_info: None,
        })
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

    /// Get the hostname or IP address.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the port number.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the optional DNS resolution info.
    pub fn resolve_info(&self) -> Option<&ResolveInfo> {
        self.resolve_info.as_ref()
    }

    /// Parse the network address into a SocketAddr.
    /// Returns an error if the address cannot be parsed (e.g. unresolved domain).
    pub fn to_socket_addr(&self) -> Result<SocketAddr> {
        self.network_addr()
            .parse()
            .map_err(|e| AclError::OutboundError {
                kind: OutboundErrorKind::InvalidInput,
                message: format!("Invalid address: {}", e),
            })
    }

    /// Get the network address for dialing.
    /// If ResolveInfo contains an IPv4 address, it returns that.
    /// Otherwise, if it contains an IPv6 address, it returns that.
    /// If no resolved address is available, it falls back to Host.
    ///
    /// Returns `"0.0.0.0:{port}"` if host is empty (defensive fallback).
    pub fn network_addr(&self) -> String {
        if let Some(ref info) = self.resolve_info {
            if let Some(ipv4) = info.ipv4 {
                return SocketAddr::new(IpAddr::V4(ipv4), self.port).to_string();
            }
            if let Some(ipv6) = info.ipv6 {
                return SocketAddr::new(IpAddr::V6(ipv6), self.port).to_string();
            }
        }
        if self.host.is_empty() {
            return SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), self.port)
                .to_string();
        }
        // If host is an IPv6 literal, format as [ip]:port via SocketAddr
        if let Ok(ipv6) = self.host.parse::<std::net::Ipv6Addr>() {
            return SocketAddr::new(IpAddr::V6(ipv6), self.port).to_string();
        }
        self.to_string()
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
            .map_err(|e| AclError::OutboundError {
                kind: OutboundErrorKind::Io,
                message: format!("UDP recv error: {}", e),
            })?;
        Ok((n, Addr::from_socket_addr(addr)))
    }

    async fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize> {
        self.inner
            .send_to(buf, addr.to_socket_addr()?)
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

/// Try to resolve the address from an IP literal.
/// Returns true if resolve_info is already set or was set from an IP literal.
/// Returns false if the host is a domain name that needs DNS resolution.
pub(crate) fn try_resolve_from_ip(addr: &mut Addr) -> bool {
    if addr.resolve_info.is_some() {
        return true;
    }

    if let Ok(ip) = addr.host.parse::<IpAddr>() {
        addr.resolve_info = Some(match ip {
            IpAddr::V4(v4) => ResolveInfo::from_ipv4(v4),
            IpAddr::V6(v6) => ResolveInfo::from_ipv6(v6),
        });
        return true;
    }

    false
}

/// Build ResolveInfo from a list of resolved IP addresses.
pub(crate) fn build_resolve_info(ips: &[IpAddr]) -> ResolveInfo {
    let (ipv4, ipv6) = split_ipv4_ipv6(ips);
    if ipv4.is_none() && ipv6.is_none() {
        ResolveInfo::from_error("no address found")
    } else {
        ResolveInfo {
            ipv4,
            ipv6,
            error: None,
        }
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

    #[test]
    fn test_addr_to_socket_addr_with_resolve_info() {
        let addr = Addr::new("example.com", 80)
            .with_resolve_info(ResolveInfo::from_ipv4(Ipv4Addr::new(1, 2, 3, 4)));
        let sock = addr.to_socket_addr().unwrap();
        assert_eq!(sock, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 80));
    }

    #[test]
    fn test_addr_to_socket_addr_domain_fails() {
        let addr = Addr::new("example.com", 80);
        assert!(addr.to_socket_addr().is_err());
    }

    // ========== Shared resolve helper tests ==========

    #[test]
    fn test_try_resolve_from_ip_v4() {
        let mut addr = Addr::new("10.0.0.1", 80);
        assert!(try_resolve_from_ip(&mut addr));
        let info = addr.resolve_info.unwrap();
        assert_eq!(info.ipv4, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(info.ipv6.is_none());
    }

    #[test]
    fn test_try_resolve_from_ip_v6() {
        let mut addr = Addr::new("::1", 443);
        assert!(try_resolve_from_ip(&mut addr));
        let info = addr.resolve_info.unwrap();
        assert!(info.ipv4.is_none());
        assert_eq!(info.ipv6, Some(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_try_resolve_from_ip_domain() {
        let mut addr = Addr::new("example.com", 80);
        assert!(!try_resolve_from_ip(&mut addr));
        assert!(addr.resolve_info.is_none());
    }

    #[test]
    fn test_try_resolve_from_ip_already_resolved() {
        let mut addr = Addr::new("10.0.0.1", 80);
        addr.resolve_info = Some(ResolveInfo::from_ipv6(Ipv6Addr::LOCALHOST));
        assert!(try_resolve_from_ip(&mut addr));
        // Should keep original, not overwrite
        assert_eq!(addr.resolve_info.unwrap().ipv6, Some(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_build_resolve_info_mixed() {
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        let info = build_resolve_info(&ips);
        assert_eq!(info.ipv4, Some(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(info.ipv6, Some(Ipv6Addr::LOCALHOST));
        assert!(info.error.is_none());
    }

    #[test]
    fn test_build_resolve_info_empty() {
        let info = build_resolve_info(&[]);
        assert!(info.ipv4.is_none());
        assert!(info.ipv6.is_none());
        assert!(info.error.is_some());
    }

    #[test]
    fn test_build_resolve_info_v4_only() {
        let ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))];
        let info = build_resolve_info(&ips);
        assert_eq!(info.ipv4, Some(Ipv4Addr::new(192, 168, 0, 1)));
        assert!(info.ipv6.is_none());
        assert!(info.error.is_none());
    }

    // ===== Bug verification tests =====

    #[test]
    fn test_addr_empty_host_network_addr_should_be_valid() {
        // P0-2: Addr::new("", 80) creates ":80" which is not a valid address.
        // network_addr() should produce a parseable SocketAddr or host:port.
        let addr = Addr::new("", 80);
        let network = addr.network_addr();
        // ":80" is not valid — this exposes the lack of validation
        assert_ne!(network, ":80", "empty host should not produce ':port' address");
    }

    #[test]
    fn test_addr_control_chars_in_host() {
        // P0-2: Addr accepts control chars in host, can cause injection downstream
        let addr = Addr::new("evil\r\nHost: injected\r\n", 80);
        // Host should not contain control characters
        assert!(
            !addr.host.bytes().any(|b| b < 0x20),
            "Addr should reject control characters in host"
        );
    }

    #[test]
    fn test_addr_to_socket_addr_ipv6_literal_without_resolve_info() {
        // BUG B1: Addr::new("::1", 80) without resolve_info
        // to_socket_addr() calls network_addr() which falls back to Display
        // Display produces "::1:80" which is NOT a valid SocketAddr.
        // Should produce "[::1]:80" instead.
        let addr = Addr::new("::1", 80);
        let result = addr.to_socket_addr();
        assert!(
            result.is_ok(),
            "to_socket_addr should parse IPv6 literal '::1' without resolve_info, got: {:?}",
            result
        );
        let sock = result.unwrap();
        assert_eq!(sock.port(), 80);
        assert!(sock.ip().is_loopback());
    }

    #[test]
    fn test_addr_host_getter_returns_filtered_value() {
        // S1: Addr fields should not be directly writable by third-party consumers.
        // Getters ensure the host value is always the validated one from construction.
        let addr = Addr::new("evil\r\nHost: injected\r\n", 80);
        assert!(
            !addr.host().bytes().any(|b| b < 0x20),
            "host() getter should return the filtered value"
        );
    }

    #[test]
    fn test_addr_port_getter() {
        let addr = Addr::new("example.com", 8080);
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_addr_resolve_info_getter() {
        let addr = Addr::new("example.com", 80);
        assert!(addr.resolve_info().is_none());

        let addr = Addr::from_socket_addr("1.2.3.4:80".parse().unwrap());
        assert!(addr.resolve_info().is_some());
        assert!(addr.resolve_info().unwrap().has_address());
    }

    #[test]
    fn test_addr_network_addr_ipv6_literal_without_resolve_info() {
        // BUG B1: network_addr() for IPv6 literal without resolve_info
        // falls back to self.to_string() = "::1:80" which is unparseable.
        let addr = Addr::new("2001:db8::1", 443);
        let network = addr.network_addr();
        // Must be parseable as a SocketAddr
        assert!(
            network.parse::<std::net::SocketAddr>().is_ok(),
            "network_addr for IPv6 literal should be parseable, got: {}",
            network
        );
    }
}
