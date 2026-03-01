//! SOCKS5 proxy outbound implementation.
//!
//! Connects to targets through a SOCKS5 proxy server.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::error::{AclError, OutboundErrorKind, Result};

use super::{Addr, Outbound, StdTcpConn, TcpConn, UdpConn, DEFAULT_DIALER_TIMEOUT};

#[cfg(feature = "async")]
use super::{AsyncOutbound, AsyncTcpConn, AsyncUdpConn, TokioTcpConn};
#[cfg(feature = "async")]
use async_trait::async_trait;
#[cfg(feature = "async")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "async")]
use tokio::net::{TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket};

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_AUTH_PASSWORD: u8 = 0x02;
const SOCKS5_AUTH_NO_ACCEPTABLE: u8 = 0xFF;

const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;

const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

const SOCKS5_REP_SUCCESS: u8 = 0x00;

const SOCKS5_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKS5_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum SOCKS5 UDP header overhead: 2 RSV + 1 FRAG + 1 ATYP + 256 addr + 2 port.
const SOCKS5_UDP_HEADER_MAX: usize = 262;

/// Convert SOCKS5 reply code to human-readable string.
fn socks5_rep_to_string(rep: u8) -> &'static str {
    match rep {
        0x00 => "succeeded",
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "undefined",
    }
}

/// Validate SOCKS5 response header fields.
fn validate_socks5_response(ver: u8, rep: u8) -> Result<()> {
    if ver != SOCKS5_VERSION {
        return Err(AclError::OutboundError {
            kind: OutboundErrorKind::Protocol,
            message: format!("Invalid SOCKS version in response: {}", ver),
        });
    }
    if rep != SOCKS5_REP_SUCCESS {
        return Err(AclError::OutboundError {
            kind: OutboundErrorKind::Protocol,
            message: format!("SOCKS5 request failed: {}", socks5_rep_to_string(rep)),
        });
    }
    Ok(())
}

/// Build a SOCKS5 request buffer: VER + CMD + RSV + ATYP + DST.ADDR + DST.PORT.
fn build_socks5_request(cmd: u8, addr: &Addr) -> Result<Vec<u8>> {
    let (atyp, dst_addr) = addr_to_socks5(&addr.host)?;
    let mut req = vec![SOCKS5_VERSION, cmd, 0x00, atyp];
    req.extend(&dst_addr);
    req.push((addr.port >> 8) as u8);
    req.push((addr.port & 0xFF) as u8);
    Ok(req)
}

/// Build a SOCKS5 username/password auth request (RFC 1929).
fn build_auth_request(username: &str, password: &str) -> Vec<u8> {
    let mut req = vec![0x01]; // auth sub-negotiation version
    req.push(username.len() as u8);
    req.extend(username.as_bytes());
    req.push(password.len() as u8);
    req.extend(password.as_bytes());
    req
}

/// Parse a SOCKS5 bound address from a byte buffer (after the 4-byte response header).
/// Returns (host, port, bytes_consumed).
fn parse_bound_addr(atyp: u8, data: &[u8]) -> Result<(String, u16, usize)> {
    match atyp {
        SOCKS5_ATYP_IPV4 => {
            if data.len() < 6 {
                return Err(AclError::OutboundError {
                    kind: OutboundErrorKind::Protocol,
                    message: "Truncated IPv4 bound address".to_string(),
                });
            }
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]));
            let port = u16::from_be_bytes([data[4], data[5]]);
            Ok((ip.to_string(), port, 6))
        }
        SOCKS5_ATYP_IPV6 => {
            if data.len() < 18 {
                return Err(AclError::OutboundError {
                    kind: OutboundErrorKind::Protocol,
                    message: "Truncated IPv6 bound address".to_string(),
                });
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[..16]);
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(octets));
            let port = u16::from_be_bytes([data[16], data[17]]);
            Ok((ip.to_string(), port, 18))
        }
        SOCKS5_ATYP_DOMAIN => {
            if data.is_empty() {
                return Err(AclError::OutboundError {
                    kind: OutboundErrorKind::Protocol,
                    message: "Truncated domain bound address".to_string(),
                });
            }
            let len = data[0] as usize;
            if data.len() < 1 + len + 2 {
                return Err(AclError::OutboundError {
                    kind: OutboundErrorKind::Protocol,
                    message: "Truncated domain bound address".to_string(),
                });
            }
            let domain = String::from_utf8_lossy(&data[1..1 + len]).to_string();
            let port = u16::from_be_bytes([data[1 + len], data[1 + len + 1]]);
            Ok((domain, port, 1 + len + 2))
        }
        _ => Err(AclError::OutboundError {
            kind: OutboundErrorKind::Protocol,
            message: format!("Unknown address type: {}", atyp),
        }),
    }
}

/// Compute the fixed byte count needed to read a SOCKS5 bound address for the given atyp.
/// Returns `None` for domain type (needs a length byte read first).
/// Returns `Some(Ok(n))` for fixed-size types (IPv4=6, IPv6=18).
/// Returns `Some(Err(...))` for unknown address types.
fn bound_addr_fixed_size(atyp: u8) -> Option<Result<usize>> {
    match atyp {
        SOCKS5_ATYP_IPV4 => Some(Ok(4 + 2)),
        SOCKS5_ATYP_IPV6 => Some(Ok(16 + 2)),
        SOCKS5_ATYP_DOMAIN => None,
        _ => Some(Err(AclError::OutboundError {
            kind: OutboundErrorKind::Protocol,
            message: format!("Unknown address type: {}", atyp),
        })),
    }
}

/// Convert address to SOCKS5 format (free function).
fn addr_to_socks5(host: &str) -> Result<(u8, Vec<u8>)> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => Ok((SOCKS5_ATYP_IPV4, v4.octets().to_vec())),
            IpAddr::V6(v6) => Ok((SOCKS5_ATYP_IPV6, v6.octets().to_vec())),
        }
    } else {
        let domain = host.as_bytes();
        if domain.len() > 255 {
            return Err(AclError::OutboundError {
                kind: OutboundErrorKind::InvalidInput,
                message: format!("Domain name too long for SOCKS5: {} bytes (max 255)", domain.len()),
            });
        }
        let mut addr = vec![domain.len() as u8];
        addr.extend(domain);
        Ok((SOCKS5_ATYP_DOMAIN, addr))
    }
}

/// SOCKS5 proxy outbound.
///
/// Since SOCKS5 supports using either IP or domain name as the target address,
/// it will ignore ResolveInfo in Addr and always only use Host.
pub struct Socks5 {
    /// Proxy server address
    addr: String,
    /// Username for authentication
    username: Option<String>,
    /// Password for authentication
    password: Option<String>,
    /// Connection timeout
    timeout: Duration,
}

impl Socks5 {
    /// Create a new SOCKS5 outbound.
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            username: None,
            password: None,
            timeout: DEFAULT_DIALER_TIMEOUT,
        }
    }

    /// Create a new SOCKS5 outbound with authentication.
    ///
    /// Returns an error if username or password exceeds 255 bytes (RFC 1929 limit).
    pub fn with_auth(
        addr: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self> {
        let username = username.into();
        let password = password.into();
        if username.len() > 255 {
            return Err(AclError::OutboundError {
                kind: OutboundErrorKind::InvalidInput,
                message: format!("SOCKS5 username too long: {} bytes (max 255)", username.len()),
            });
        }
        if password.len() > 255 {
            return Err(AclError::OutboundError {
                kind: OutboundErrorKind::InvalidInput,
                message: format!("SOCKS5 password too long: {} bytes (max 255)", password.len()),
            });
        }
        Ok(Self {
            addr: addr.into(),
            username: Some(username),
            password: Some(password),
            timeout: DEFAULT_DIALER_TIMEOUT,
        })
    }

    /// Deprecated: Use [`with_auth`](Self::with_auth) instead (same signature now).
    #[deprecated(since = "0.3.3", note = "Use with_auth() instead, which now returns Result")]
    pub fn try_with_auth(
        addr: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self> {
        Self::with_auth(addr, username, password)
    }

    /// Set connection timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Connect to the proxy and perform negotiation.
    fn dial_and_negotiate(&self) -> Result<TcpStream> {
        let addr: SocketAddr = self
            .addr
            .to_socket_addrs()
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::DnsFailed, message: format!("Failed to resolve proxy address: {}", e) })?
            .next()
            .ok_or_else(|| AclError::OutboundError { kind: OutboundErrorKind::DnsFailed, message: "No address resolved for proxy".to_string() })?;

        let mut stream = TcpStream::connect_timeout(&addr, self.timeout)
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::ConnectionFailed, message: format!("Failed to connect to proxy: {}", e) })?;

        stream
            .set_read_timeout(Some(SOCKS5_NEGOTIATION_TIMEOUT))
            .ok();
        stream
            .set_write_timeout(Some(SOCKS5_NEGOTIATION_TIMEOUT))
            .ok();

        // Send negotiation request
        let auth_methods = if self.username.is_some() && self.password.is_some() {
            vec![SOCKS5_AUTH_NONE, SOCKS5_AUTH_PASSWORD]
        } else {
            vec![SOCKS5_AUTH_NONE]
        };

        let mut req = vec![SOCKS5_VERSION, auth_methods.len() as u8];
        req.extend(&auth_methods);
        stream
            .write_all(&req)
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to send negotiation: {}", e) })?;

        // Read negotiation response
        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).map_err(|e| {
            AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to read negotiation response: {}", e) }
        })?;

        if resp[0] != SOCKS5_VERSION {
            return Err(AclError::OutboundError {
                kind: OutboundErrorKind::Protocol,
                message: format!("Invalid SOCKS version: {}", resp[0]),
            });
        }

        match resp[1] {
            SOCKS5_AUTH_NONE => {
                // No authentication required
            }
            SOCKS5_AUTH_PASSWORD => {
                // Username/password authentication
                let username = self.username.as_ref().ok_or_else(|| {
                    AclError::OutboundError {
                        kind: OutboundErrorKind::AuthFailed,
                        message: "Server requires authentication but no credentials provided".to_string(),
                    }
                })?;
                let password = self.password.as_ref().ok_or_else(|| {
                    AclError::OutboundError {
                        kind: OutboundErrorKind::AuthFailed,
                        message: "Server requires authentication but no credentials provided".to_string(),
                    }
                })?;

                // Send auth request
                let auth_req = build_auth_request(username, password);
                stream
                    .write_all(&auth_req)
                    .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to send auth: {}", e) })?;

                // Read auth response
                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).map_err(|e| {
                    AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to read auth response: {}", e) }
                })?;

                if auth_resp[1] != 0x00 {
                    return Err(AclError::OutboundError {
                        kind: OutboundErrorKind::AuthFailed,
                        message: "SOCKS5 authentication failed".to_string(),
                    });
                }
            }
            SOCKS5_AUTH_NO_ACCEPTABLE => {
                return Err(AclError::OutboundError {
                    kind: OutboundErrorKind::AuthFailed,
                    message: "No acceptable authentication method".to_string(),
                });
            }
            method => {
                return Err(AclError::OutboundError {
                    kind: OutboundErrorKind::AuthFailed,
                    message: format!("Unsupported authentication method: {}", method),
                });
            }
        }

        // Reset timeout
        stream.set_read_timeout(None).ok();
        stream.set_write_timeout(None).ok();

        Ok(stream)
    }

    /// Send a SOCKS5 request and get the response.
    fn request(&self, stream: &mut TcpStream, cmd: u8, addr: &Addr) -> Result<(String, u16)> {
        stream.set_read_timeout(Some(SOCKS5_REQUEST_TIMEOUT)).ok();
        stream.set_write_timeout(Some(SOCKS5_REQUEST_TIMEOUT)).ok();

        let req = build_socks5_request(cmd, addr)?;
        stream
            .write_all(&req)
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to send request: {}", e) })?;

        // Read response header
        let mut resp_header = [0u8; 4];
        stream
            .read_exact(&mut resp_header)
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to read response: {}", e) })?;

        validate_socks5_response(resp_header[0], resp_header[1])?;

        // Read bound address bytes and parse
        let max_bound = 1 + 256 + 2;
        let mut bound_buf = vec![0u8; max_bound];
        let needed = match bound_addr_fixed_size(resp_header[3]) {
            Some(r) => r?,
            None => {
                stream.read_exact(&mut bound_buf[..1]).map_err(|e| {
                    AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to read domain length: {}", e) }
                })?;
                1 + bound_buf[0] as usize + 2
            }
        };

        let start = if bound_addr_fixed_size(resp_header[3]).is_none() { 1 } else { 0 };
        stream
            .read_exact(&mut bound_buf[start..needed])
            .map_err(|e| {
                AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to read bound address: {}", e) }
            })?;

        let (bound_host, bound_port, _) = parse_bound_addr(resp_header[3], &bound_buf[..needed])?;

        // Reset timeout
        stream.set_read_timeout(None).ok();
        stream.set_write_timeout(None).ok();

        Ok((bound_host, bound_port))
    }

    /// Resolve the SOCKS5 bound address for UDP.
    /// When the server returns an unspecified address (0.0.0.0 or ::),
    /// replaces it with the proxy server's host address.
    fn resolve_bound_addr(&self, bound_host: &str, bound_port: u16) -> String {
        let is_unspecified = matches!(
            bound_host.parse::<IpAddr>(),
            Ok(ip) if ip.is_unspecified()
        );

        if is_unspecified {
            // Extract host from self.addr (formats: "host:port" or "[ipv6]:port")
            let proxy_host = if let Some(bracket_end) = self.addr.rfind(']') {
                // IPv6 format: [::1]:port → [::1]
                &self.addr[..bracket_end + 1]
            } else if let Some(colon_pos) = self.addr.rfind(':') {
                &self.addr[..colon_pos]
            } else {
                &self.addr
            };
            format!("{}:{}", proxy_host, bound_port)
        } else if bound_host.contains(':') {
            // IPv6 address: wrap in brackets for valid socket address
            format!("[{}]:{}", bound_host, bound_port)
        } else {
            format!("{}:{}", bound_host, bound_port)
        }
    }

    /// Async: Connect to the proxy and perform negotiation.
    /// Uses tokio async DNS to avoid blocking the runtime.
    #[cfg(feature = "async")]
    async fn async_dial_and_negotiate(&self) -> Result<TokioTcpStream> {
        let addr: SocketAddr = tokio::net::lookup_host(&self.addr)
            .await
            .map_err(|e| {
                AclError::OutboundError { kind: OutboundErrorKind::DnsFailed, message: format!("Failed to resolve proxy address: {}", e) }
            })?
            .next()
            .ok_or_else(|| AclError::OutboundError { kind: OutboundErrorKind::DnsFailed, message: "No address resolved for proxy".to_string() })?;

        let mut stream = tokio::time::timeout(self.timeout, TokioTcpStream::connect(addr))
            .await
            .map_err(|_| AclError::OutboundError { kind: OutboundErrorKind::Timeout, message: "Connection timeout".to_string() })?
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::ConnectionFailed, message: format!("Failed to connect to proxy: {}", e) })?;

        let auth_methods = if self.username.is_some() && self.password.is_some() {
            vec![SOCKS5_AUTH_NONE, SOCKS5_AUTH_PASSWORD]
        } else {
            vec![SOCKS5_AUTH_NONE]
        };

        let mut req = vec![SOCKS5_VERSION, auth_methods.len() as u8];
        req.extend(&auth_methods);

        tokio::time::timeout(SOCKS5_NEGOTIATION_TIMEOUT, stream.write_all(&req))
            .await
            .map_err(|_| AclError::OutboundError { kind: OutboundErrorKind::Timeout, message: "Negotiation timeout".to_string() })?
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to send negotiation: {}", e) })?;

        let mut resp = [0u8; 2];
        tokio::time::timeout(SOCKS5_NEGOTIATION_TIMEOUT, stream.read_exact(&mut resp))
            .await
            .map_err(|_| AclError::OutboundError { kind: OutboundErrorKind::Timeout, message: "Negotiation timeout".to_string() })?
            .map_err(|e| {
                AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to read negotiation response: {}", e) }
            })?;

        if resp[0] != SOCKS5_VERSION {
            return Err(AclError::OutboundError {
                kind: OutboundErrorKind::Protocol,
                message: format!("Invalid SOCKS version: {}", resp[0]),
            });
        }

        match resp[1] {
            SOCKS5_AUTH_NONE => {}
            SOCKS5_AUTH_PASSWORD => {
                let username = self.username.as_ref().ok_or_else(|| {
                    AclError::OutboundError {
                        kind: OutboundErrorKind::AuthFailed,
                        message: "Server requires authentication but no credentials provided".to_string(),
                    }
                })?;
                let password = self.password.as_ref().ok_or_else(|| {
                    AclError::OutboundError {
                        kind: OutboundErrorKind::AuthFailed,
                        message: "Server requires authentication but no credentials provided".to_string(),
                    }
                })?;

                let auth_req = build_auth_request(username, password);
                tokio::time::timeout(SOCKS5_NEGOTIATION_TIMEOUT, stream.write_all(&auth_req))
                    .await
                    .map_err(|_| AclError::OutboundError { kind: OutboundErrorKind::Timeout, message: "Auth send timeout".to_string() })?
                    .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to send auth: {}", e) })?;

                let mut auth_resp = [0u8; 2];
                tokio::time::timeout(SOCKS5_NEGOTIATION_TIMEOUT, stream.read_exact(&mut auth_resp))
                    .await
                    .map_err(|_| AclError::OutboundError { kind: OutboundErrorKind::Timeout, message: "Auth response timeout".to_string() })?
                    .map_err(|e| {
                        AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to read auth response: {}", e) }
                    })?;

                if auth_resp[1] != 0x00 {
                    return Err(AclError::OutboundError {
                        kind: OutboundErrorKind::AuthFailed,
                        message: "SOCKS5 authentication failed".to_string(),
                    });
                }
            }
            SOCKS5_AUTH_NO_ACCEPTABLE => {
                return Err(AclError::OutboundError {
                    kind: OutboundErrorKind::AuthFailed,
                    message: "No acceptable authentication method".to_string(),
                });
            }
            method => {
                return Err(AclError::OutboundError {
                    kind: OutboundErrorKind::AuthFailed,
                    message: format!("Unsupported authentication method: {}", method),
                });
            }
        }

        Ok(stream)
    }

    /// Async: Send a SOCKS5 request and get the response.
    #[cfg(feature = "async")]
    async fn async_request(
        &self,
        stream: &mut TokioTcpStream,
        cmd: u8,
        addr: &Addr,
    ) -> Result<(String, u16)> {
        let req = build_socks5_request(cmd, addr)?;

        tokio::time::timeout(SOCKS5_REQUEST_TIMEOUT, stream.write_all(&req))
            .await
            .map_err(|_| AclError::OutboundError { kind: OutboundErrorKind::Timeout, message: "Request timeout".to_string() })?
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to send request: {}", e) })?;

        let mut resp_header = [0u8; 4];
        tokio::time::timeout(SOCKS5_REQUEST_TIMEOUT, stream.read_exact(&mut resp_header))
            .await
            .map_err(|_| AclError::OutboundError { kind: OutboundErrorKind::Timeout, message: "Request timeout".to_string() })?
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to read response: {}", e) })?;

        validate_socks5_response(resp_header[0], resp_header[1])?;

        // Read bound address bytes and parse
        let max_bound = 1 + 256 + 2;
        let mut bound_buf = vec![0u8; max_bound];
        let needed = match bound_addr_fixed_size(resp_header[3]) {
            Some(r) => r?,
            None => {
                stream.read_exact(&mut bound_buf[..1]).await.map_err(|e| {
                    AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to read domain length: {}", e) }
                })?;
                1 + bound_buf[0] as usize + 2
            }
        };

        let start = if bound_addr_fixed_size(resp_header[3]).is_none() { 1 } else { 0 };
        stream
            .read_exact(&mut bound_buf[start..needed])
            .await
            .map_err(|e| {
                AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("Failed to read bound address: {}", e) }
            })?;

        let (bound_host, bound_port, _) = parse_bound_addr(resp_header[3], &bound_buf[..needed])?;

        Ok((bound_host, bound_port))
    }
}

impl Outbound for Socks5 {
    fn dial_tcp(&self, addr: &mut Addr) -> Result<Box<dyn TcpConn>> {
        let mut stream = self.dial_and_negotiate()?;
        self.request(&mut stream, SOCKS5_CMD_CONNECT, addr)?;
        Ok(Box::new(StdTcpConn::new(stream)))
    }

    fn dial_udp(&self, addr: &mut Addr) -> Result<Box<dyn UdpConn>> {
        let mut stream = self.dial_and_negotiate()?;
        let (bound_host, bound_port) = self.request(&mut stream, SOCKS5_CMD_UDP_ASSOCIATE, addr)?;

        // Connect to the bound address (resolve unspecified 0.0.0.0 to proxy host)
        let udp_addr = self.resolve_bound_addr(&bound_host, bound_port);

        // Bind UDP socket matching the address family of the bound address
        let bind_addr = if udp_addr.contains('[') || bound_host.contains(':') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let udp_socket = UdpSocket::bind(bind_addr)
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::ConnectionFailed, message: format!("Failed to bind UDP: {}", e) })?;

        udp_socket
            .connect(&udp_addr)
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::ConnectionFailed, message: format!("Failed to connect UDP: {}", e) })?;

        Ok(Box::new(Socks5UdpConn::new(stream, udp_socket)))
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncOutbound for Socks5 {
    async fn dial_tcp(&self, addr: &mut Addr) -> Result<Box<dyn AsyncTcpConn>> {
        let mut stream = self.async_dial_and_negotiate().await?;
        self.async_request(&mut stream, SOCKS5_CMD_CONNECT, addr)
            .await?;
        Ok(Box::new(TokioTcpConn::new(stream)))
    }

    async fn dial_udp(&self, addr: &mut Addr) -> Result<Box<dyn AsyncUdpConn>> {
        let mut stream = self.async_dial_and_negotiate().await?;
        let (bound_host, bound_port) = self
            .async_request(&mut stream, SOCKS5_CMD_UDP_ASSOCIATE, addr)
            .await?;

        // Resolve unspecified 0.0.0.0/:: to proxy host
        let udp_addr = self.resolve_bound_addr(&bound_host, bound_port);

        // Bind UDP socket matching the address family of the bound address
        let bind_addr = if udp_addr.contains('[') || bound_host.contains(':') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let udp_socket = TokioUdpSocket::bind(bind_addr)
            .await
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::ConnectionFailed, message: format!("Failed to bind UDP: {}", e) })?;

        udp_socket
            .connect(&udp_addr)
            .await
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::ConnectionFailed, message: format!("Failed to connect UDP: {}", e) })?;

        Ok(Box::new(AsyncSocks5UdpConn::new(stream, udp_socket)))
    }
}

/// SOCKS5 UDP connection wrapper.
/// Encode an address into SOCKS5 UDP datagram header format.
/// Returns: RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT(2).
fn socks5_udp_encode_addr(addr: &Addr) -> Result<Vec<u8>> {
    let mut data = Vec::new();

    // RSV (2 bytes) + FRAG (1 byte)
    data.extend(&[0x00, 0x00, 0x00]);

    // Address type and address
    if let Ok(ip) = addr.host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                data.push(SOCKS5_ATYP_IPV4);
                data.extend(&v4.octets());
            }
            IpAddr::V6(v6) => {
                data.push(SOCKS5_ATYP_IPV6);
                data.extend(&v6.octets());
            }
        }
    } else {
        let domain = addr.host.as_bytes();
        if domain.len() > 255 {
            return Err(AclError::OutboundError {
                kind: OutboundErrorKind::InvalidInput,
                message: format!("Domain name too long for SOCKS5: {} bytes (max 255)", domain.len()),
            });
        }
        data.push(SOCKS5_ATYP_DOMAIN);
        data.push(domain.len() as u8);
        data.extend(domain);
    }

    // Port
    data.push((addr.port >> 8) as u8);
    data.push((addr.port & 0xFF) as u8);

    Ok(data)
}

/// Decode a SOCKS5 UDP datagram header, returning the address and header length.
/// Parses: RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT(2) from a byte slice.
fn socks5_udp_decode_addr(data: &[u8]) -> Result<(Addr, usize)> {
    if data.len() < 4 {
        return Err(AclError::OutboundError {
            kind: OutboundErrorKind::Protocol,
            message: "Invalid SOCKS5 datagram".to_string(),
        });
    }

    // Skip RSV (2 bytes) + FRAG (1 byte)
    let atyp = data[3];
    let mut offset = 4;

    let (host, port) = match atyp {
        SOCKS5_ATYP_IPV4 => {
            if data.len() < offset + 6 {
                return Err(AclError::OutboundError { kind: OutboundErrorKind::Protocol, message: "Invalid IPv4 datagram".to_string() });
            }
            let ip = std::net::Ipv4Addr::new(
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            );
            offset += 4;
            let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            (ip.to_string(), port)
        }
        SOCKS5_ATYP_IPV6 => {
            if data.len() < offset + 18 {
                return Err(AclError::OutboundError { kind: OutboundErrorKind::Protocol, message: "Invalid IPv6 datagram".to_string() });
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[offset..offset + 16]);
            let ip = std::net::Ipv6Addr::from(octets);
            offset += 16;
            let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            (ip.to_string(), port)
        }
        SOCKS5_ATYP_DOMAIN => {
            if data.len() < offset + 1 {
                return Err(AclError::OutboundError {
                    kind: OutboundErrorKind::Protocol,
                    message: "Invalid domain datagram".to_string(),
                });
            }
            let len = data[offset] as usize;
            offset += 1;
            if data.len() < offset + len + 2 {
                return Err(AclError::OutboundError {
                    kind: OutboundErrorKind::Protocol,
                    message: "Invalid domain datagram".to_string(),
                });
            }
            let domain = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
            offset += len;
            let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            (domain, port)
        }
        _ => {
            return Err(AclError::OutboundError {
                kind: OutboundErrorKind::Protocol,
                message: format!("Unknown address type: {}", atyp),
            });
        }
    };

    Ok((Addr::new(host, port), offset))
}

struct Socks5UdpConn {
    _tcp_conn: TcpStream, // Keep TCP connection alive
    udp_socket: UdpSocket,
}

impl Socks5UdpConn {
    fn new(tcp_conn: TcpStream, udp_socket: UdpSocket) -> Self {
        Self {
            _tcp_conn: tcp_conn,
            udp_socket,
        }
    }
}

impl UdpConn for Socks5UdpConn {
    fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)> {
        let recv_buf_size = buf.len().saturating_add(SOCKS5_UDP_HEADER_MAX).min(65536);
        let mut recv_buf = vec![0u8; recv_buf_size];
        let n = self
            .udp_socket
            .recv(&mut recv_buf)
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("UDP recv error: {}", e) })?;

        let (addr, header_len) = socks5_udp_decode_addr(&recv_buf[..n])?;
        let data_len = n - header_len;
        let copy_len = data_len.min(buf.len());
        buf[..copy_len].copy_from_slice(&recv_buf[header_len..header_len + copy_len]);

        Ok((copy_len, addr))
    }

    fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize> {
        let mut packet = socks5_udp_encode_addr(addr)?;
        packet.extend(buf);

        self.udp_socket
            .send(&packet)
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("UDP send error: {}", e) })?;

        Ok(buf.len())
    }

}

/// Async SOCKS5 UDP connection wrapper.
#[cfg(feature = "async")]
struct AsyncSocks5UdpConn {
    _tcp_conn: TokioTcpStream,
    udp_socket: TokioUdpSocket,
}

#[cfg(feature = "async")]
impl AsyncSocks5UdpConn {
    fn new(tcp_conn: TokioTcpStream, udp_socket: TokioUdpSocket) -> Self {
        Self {
            _tcp_conn: tcp_conn,
            udp_socket,
        }
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncUdpConn for AsyncSocks5UdpConn {
    async fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)> {
        let recv_buf_size = buf.len().saturating_add(SOCKS5_UDP_HEADER_MAX).min(65536);
        let mut recv_buf = vec![0u8; recv_buf_size];
        let n = self
            .udp_socket
            .recv(&mut recv_buf)
            .await
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("UDP recv error: {}", e) })?;

        let (addr, header_len) = socks5_udp_decode_addr(&recv_buf[..n])?;
        let data_len = n - header_len;
        let copy_len = data_len.min(buf.len());
        buf[..copy_len].copy_from_slice(&recv_buf[header_len..header_len + copy_len]);

        Ok((copy_len, addr))
    }

    async fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize> {
        let mut packet = socks5_udp_encode_addr(addr)?;
        packet.extend(buf);

        self.udp_socket
            .send(&packet)
            .await
            .map_err(|e| AclError::OutboundError { kind: OutboundErrorKind::Io, message: format!("UDP send error: {}", e) })?;

        Ok(buf.len())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_new() {
        let socks5 = Socks5::new("127.0.0.1:1080");
        assert_eq!(socks5.addr, "127.0.0.1:1080");
        assert!(socks5.username.is_none());
        assert!(socks5.password.is_none());
    }

    #[test]
    fn test_socks5_with_auth() {
        let socks5 = Socks5::with_auth("127.0.0.1:1080", "user", "pass").unwrap();
        assert_eq!(socks5.addr, "127.0.0.1:1080");
        assert_eq!(socks5.username, Some("user".to_string()));
        assert_eq!(socks5.password, Some("pass".to_string()));
    }

    #[test]
    fn test_addr_to_socks5_ipv4() {
        let (atyp, addr) = addr_to_socks5("192.168.1.1").unwrap();
        assert_eq!(atyp, SOCKS5_ATYP_IPV4);
        assert_eq!(addr, vec![192, 168, 1, 1]);
    }

    #[test]
    fn test_addr_to_socks5_domain() {
        let (atyp, addr) = addr_to_socks5("example.com").unwrap();
        assert_eq!(atyp, SOCKS5_ATYP_DOMAIN);
        assert_eq!(addr[0], 11); // length of "example.com"
        assert_eq!(&addr[1..], b"example.com");
    }

    #[test]
    fn test_socks5_auth_username_too_long() {
        let long_user = "a".repeat(256);
        let result = Socks5::try_with_auth("127.0.0.1:1080", &long_user, "pass");
        assert!(result.is_err(), "username >255 bytes should be rejected");
        match result {
            Err(e) => assert!(
                e.to_string().contains("too long"),
                "error should mention 'too long', got: {}",
                e
            ),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn test_socks5_auth_password_too_long() {
        let long_pass = "b".repeat(256);
        let result = Socks5::try_with_auth("127.0.0.1:1080", "user", &long_pass);
        assert!(result.is_err(), "password >255 bytes should be rejected");
    }

    #[test]
    fn test_socks5_auth_max_length_ok() {
        let max_user = "a".repeat(255);
        let max_pass = "b".repeat(255);
        let result = Socks5::try_with_auth("127.0.0.1:1080", &max_user, &max_pass);
        assert!(result.is_ok(), "255-byte credentials should be accepted");
    }

    #[test]
    fn test_with_auth_returns_error_on_oversized_username() {
        let long_user = "a".repeat(256);
        let result = Socks5::with_auth("127.0.0.1:1080", &long_user, "pass");
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("too long")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn test_with_auth_returns_error_on_oversized_password() {
        let long_pass = "b".repeat(256);
        let result = Socks5::with_auth("127.0.0.1:1080", "user", &long_pass);
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("too long")),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn test_with_auth_accepts_max_length_credentials() {
        // 255 bytes is the RFC 1929 maximum
        let max_user = "a".repeat(255);
        let max_pass = "b".repeat(255);
        let socks5 = Socks5::with_auth("127.0.0.1:1080", &max_user, &max_pass).unwrap();
        assert_eq!(socks5.username.as_ref().unwrap().len(), 255);
        assert_eq!(socks5.password.as_ref().unwrap().len(), 255);
    }

    // ========== SOCKS5 UDP free function tests ==========

    #[test]
    fn test_socks5_udp_encode_ipv4() {
        let addr = Addr::new("192.168.1.1", 80);
        let data = socks5_udp_encode_addr(&addr).unwrap();
        // RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2) = 10 bytes
        assert_eq!(data.len(), 10);
        assert_eq!(&data[0..3], &[0x00, 0x00, 0x00]);
        assert_eq!(data[3], SOCKS5_ATYP_IPV4);
        assert_eq!(&data[4..8], &[192, 168, 1, 1]);
        assert_eq!(u16::from_be_bytes([data[8], data[9]]), 80);
    }

    #[test]
    fn test_socks5_udp_encode_ipv6() {
        let addr = Addr::new("::1", 443);
        let data = socks5_udp_encode_addr(&addr).unwrap();
        // RSV(2) + FRAG(1) + ATYP(1) + IPv6(16) + PORT(2) = 22 bytes
        assert_eq!(data.len(), 22);
        assert_eq!(data[3], SOCKS5_ATYP_IPV6);
        assert_eq!(u16::from_be_bytes([data[20], data[21]]), 443);
    }

    #[test]
    fn test_socks5_udp_encode_domain() {
        let addr = Addr::new("example.com", 53);
        let data = socks5_udp_encode_addr(&addr).unwrap();
        // RSV(2) + FRAG(1) + ATYP(1) + LEN(1) + "example.com"(11) + PORT(2) = 18 bytes
        assert_eq!(data.len(), 18);
        assert_eq!(data[3], SOCKS5_ATYP_DOMAIN);
        assert_eq!(data[4], 11);
        assert_eq!(&data[5..16], b"example.com");
        assert_eq!(u16::from_be_bytes([data[16], data[17]]), 53);
    }

    #[test]
    fn test_socks5_udp_encode_domain_too_long() {
        let long_domain = "a".repeat(256);
        let addr = Addr::new(long_domain, 80);
        let result = socks5_udp_encode_addr(&addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_socks5_udp_decode_ipv4_roundtrip() {
        let addr = Addr::new("10.0.0.1", 8080);
        let data = socks5_udp_encode_addr(&addr).unwrap();
        let (decoded, offset) = socks5_udp_decode_addr(&data).unwrap();
        assert_eq!(decoded.host, "10.0.0.1");
        assert_eq!(decoded.port, 8080);
        assert_eq!(offset, data.len());
    }

    #[test]
    fn test_socks5_udp_decode_ipv6_roundtrip() {
        let addr = Addr::new("::1", 443);
        let data = socks5_udp_encode_addr(&addr).unwrap();
        let (decoded, offset) = socks5_udp_decode_addr(&data).unwrap();
        assert_eq!(decoded.host, "::1");
        assert_eq!(decoded.port, 443);
        assert_eq!(offset, data.len());
    }

    #[test]
    fn test_socks5_udp_decode_domain_roundtrip() {
        let addr = Addr::new("test.example.com", 53);
        let data = socks5_udp_encode_addr(&addr).unwrap();
        let (decoded, offset) = socks5_udp_decode_addr(&data).unwrap();
        assert_eq!(decoded.host, "test.example.com");
        assert_eq!(decoded.port, 53);
        assert_eq!(offset, data.len());
    }

    #[test]
    fn test_socks5_udp_decode_truncated() {
        let result = socks5_udp_decode_addr(&[0x00, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_socks5_udp_decode_unknown_atyp() {
        let data = [0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00];
        let result = socks5_udp_decode_addr(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_socks5_resolve_bound_addr_unspecified_ipv4() {
        // Bug: When SOCKS5 server returns 0.0.0.0 as bound address for UDP,
        // dial_udp uses "0.0.0.0:port" as destination which is invalid.
        // Should replace unspecified address with proxy server host.
        let socks5 = Socks5::new("1.2.3.4:1080");
        let addr = socks5.resolve_bound_addr("0.0.0.0", 12345);
        assert_eq!(addr, "1.2.3.4:12345");
    }

    #[test]
    fn test_socks5_resolve_bound_addr_unspecified_ipv6() {
        let socks5 = Socks5::new("[::1]:1080");
        let addr = socks5.resolve_bound_addr("::", 12345);
        assert_eq!(addr, "[::1]:12345");
    }

    #[test]
    fn test_socks5_resolve_bound_addr_specified() {
        // When server returns a real address, should keep it as-is
        let socks5 = Socks5::new("1.2.3.4:1080");
        let addr = socks5.resolve_bound_addr("5.6.7.8", 12345);
        assert_eq!(addr, "5.6.7.8:12345");
    }

    #[test]
    fn test_socks5_resolve_bound_addr_domain_proxy() {
        // When proxy address is a domain name, should extract host correctly
        let socks5 = Socks5::new("proxy.example.com:1080");
        let addr = socks5.resolve_bound_addr("0.0.0.0", 12345);
        assert_eq!(addr, "proxy.example.com:12345");
    }

    #[test]
    fn test_socks5_dial_tcp_domain_name_proxy() {
        // Bug: Socks5::dial_and_negotiate() uses SocketAddr::parse() which rejects domain names.
        // Using a domain name proxy address should resolve and attempt connection,
        // not fail with "Invalid proxy address".
        let socks5 = Socks5::new("localhost:59996");
        let mut addr = Addr::new("example.com", 80);
        let result = Outbound::dial_tcp(&socks5, &mut addr);
        match result {
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    !err_msg.contains("Invalid proxy address"),
                    "Domain name proxy should be resolved, got address parse error: {}",
                    err_msg
                );
            }
            Ok(_) => panic!("Expected connection error for non-listening port"),
        }
    }

    #[test]
    fn test_socks5_resolve_bound_addr_specified_ipv6() {
        // BUG #1: When SOCKS5 server returns a specified (non-unspecified) IPv6
        // bound address for UDP, resolve_bound_addr formats it as "addr:port"
        // without brackets, producing an unparseable address string like
        // "2001:db8::1:12345" instead of "[2001:db8::1]:12345".
        let socks5 = Socks5::new("1.2.3.4:1080");
        let addr = socks5.resolve_bound_addr("2001:db8::1", 12345);
        // The result must be parseable as a socket address
        assert!(
            addr.parse::<std::net::SocketAddr>().is_ok()
                || addr.to_socket_addrs().is_ok(),
            "IPv6 bound address should be parseable, got: {}",
            addr
        );
        assert_eq!(addr, "[2001:db8::1]:12345");
    }

    #[test]
    fn test_socks5_udp_bind_should_support_ipv6() {
        // BUG #2: dial_udp hardcodes UdpSocket::bind("0.0.0.0:0") which creates
        // an IPv4-only socket. If the SOCKS5 proxy returns an IPv6 bound address,
        // the UDP socket cannot connect to it.
        //
        // Directly demonstrate: IPv4-bound socket CANNOT connect to IPv6 address.
        use std::net::UdpSocket;
        let ipv4_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let connect_result = ipv4_socket.connect("[::1]:12345");
        // This proves the bug: an IPv4 socket can't connect to IPv6.
        // The fix should bind to "::" or match the address family.
        assert!(
            connect_result.is_err(),
            "IPv4-bound UDP socket should NOT be able to connect to IPv6, proving the bug exists"
        );

        // Now verify that an IPv6 socket CAN connect to IPv6
        let ipv6_socket = UdpSocket::bind("[::]:0").unwrap();
        let connect_result = ipv6_socket.connect("[::1]:12345");
        assert!(
            connect_result.is_ok(),
            "IPv6-bound UDP socket should connect to IPv6 address"
        );
    }

    #[test]
    fn test_validate_socks5_response_success() {
        assert!(validate_socks5_response(0x05, 0x00).is_ok());
    }

    #[test]
    fn test_validate_socks5_response_bad_version() {
        let err = validate_socks5_response(0x04, 0x00).unwrap_err();
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn test_validate_socks5_response_refused() {
        let err = validate_socks5_response(0x05, 0x05).unwrap_err();
        assert!(err.to_string().contains("refused"));
    }

    #[test]
    fn test_validate_socks5_response_all_error_codes() {
        for rep in 1..=8u8 {
            let err = validate_socks5_response(0x05, rep).unwrap_err();
            assert!(
                !err.to_string().is_empty(),
                "rep={} should produce an error message",
                rep
            );
        }
    }

    #[test]
    fn test_socks5_rep_to_string_known() {
        assert_eq!(socks5_rep_to_string(0x00), "succeeded");
        assert_eq!(socks5_rep_to_string(0x05), "connection refused");
    }

    #[test]
    fn test_socks5_rep_to_string_undefined() {
        assert_eq!(socks5_rep_to_string(0xFF), "undefined");
    }

    // ========== Extracted helper function tests ==========

    #[test]
    fn test_build_socks5_request_connect_ipv4() {
        let addr = Addr::new("192.168.1.1", 80);
        let req = build_socks5_request(SOCKS5_CMD_CONNECT, &addr).unwrap();
        assert_eq!(req[0], SOCKS5_VERSION);
        assert_eq!(req[1], SOCKS5_CMD_CONNECT);
        assert_eq!(req[2], 0x00); // reserved
        assert_eq!(req[3], SOCKS5_ATYP_IPV4);
        assert_eq!(&req[4..8], &[192, 168, 1, 1]);
        assert_eq!(u16::from_be_bytes([req[8], req[9]]), 80);
        assert_eq!(req.len(), 10);
    }

    #[test]
    fn test_build_socks5_request_udp_associate_domain() {
        let addr = Addr::new("example.com", 443);
        let req = build_socks5_request(SOCKS5_CMD_UDP_ASSOCIATE, &addr).unwrap();
        assert_eq!(req[0], SOCKS5_VERSION);
        assert_eq!(req[1], SOCKS5_CMD_UDP_ASSOCIATE);
        assert_eq!(req[2], 0x00);
        assert_eq!(req[3], SOCKS5_ATYP_DOMAIN);
        assert_eq!(req[4], 11); // "example.com" length
        assert_eq!(&req[5..16], b"example.com");
        assert_eq!(u16::from_be_bytes([req[16], req[17]]), 443);
    }

    #[test]
    fn test_build_socks5_request_ipv6() {
        let addr = Addr::new("::1", 8080);
        let req = build_socks5_request(SOCKS5_CMD_CONNECT, &addr).unwrap();
        assert_eq!(req[3], SOCKS5_ATYP_IPV6);
        // VER(1) + CMD(1) + RSV(1) + ATYP(1) + IPv6(16) + PORT(2) = 22
        assert_eq!(req.len(), 22);
        assert_eq!(u16::from_be_bytes([req[20], req[21]]), 8080);
    }

    #[test]
    fn test_build_auth_request_basic() {
        let req = build_auth_request("user", "pass");
        assert_eq!(req[0], 0x01); // auth version
        assert_eq!(req[1], 4); // username length
        assert_eq!(&req[2..6], b"user");
        assert_eq!(req[6], 4); // password length
        assert_eq!(&req[7..11], b"pass");
        assert_eq!(req.len(), 11);
    }

    #[test]
    fn test_build_auth_request_empty_credentials() {
        let req = build_auth_request("", "");
        assert_eq!(req[0], 0x01);
        assert_eq!(req[1], 0); // empty username
        assert_eq!(req[2], 0); // empty password
        assert_eq!(req.len(), 3);
    }

    #[test]
    fn test_build_auth_request_max_length() {
        let user = "u".repeat(255);
        let pass = "p".repeat(255);
        let req = build_auth_request(&user, &pass);
        assert_eq!(req[0], 0x01);
        assert_eq!(req[1], 255);
        assert_eq!(req.len(), 1 + 1 + 255 + 1 + 255);
    }

    #[test]
    fn test_parse_bound_addr_ipv4() {
        // Simulate: ATYP=IPv4, then 4 addr bytes + 2 port bytes
        let data = [
            192, 168, 1, 1, // IPv4 addr
            0x1F, 0x90,     // port 8080
        ];
        let (host, port, consumed) = parse_bound_addr(SOCKS5_ATYP_IPV4, &data).unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 8080);
        assert_eq!(consumed, 6);
    }

    #[test]
    fn test_parse_bound_addr_ipv6() {
        let mut data = [0u8; 18];
        // ::1 in bytes
        data[15] = 1;
        // port 443
        data[16] = 0x01;
        data[17] = 0xBB;
        let (host, port, consumed) = parse_bound_addr(SOCKS5_ATYP_IPV6, &data).unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 443);
        assert_eq!(consumed, 18);
    }

    #[test]
    fn test_parse_bound_addr_domain() {
        let mut data = Vec::new();
        data.push(7); // domain length
        data.extend(b"foo.com");
        data.push(0x00); // port 80
        data.push(0x50);
        let (host, port, consumed) = parse_bound_addr(SOCKS5_ATYP_DOMAIN, &data).unwrap();
        assert_eq!(host, "foo.com");
        assert_eq!(port, 80);
        assert_eq!(consumed, 10);
    }

    #[test]
    fn test_parse_bound_addr_unknown_atyp() {
        let data = [0u8; 10];
        let result = parse_bound_addr(0xFF, &data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown address type"));
    }

    #[test]
    fn test_parse_bound_addr_truncated_ipv4() {
        let data = [192, 168, 1]; // only 3 bytes, need 4+2
        let result = parse_bound_addr(SOCKS5_ATYP_IPV4, &data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bound_addr_truncated_ipv6() {
        let data = [0u8; 10]; // need 16+2
        let result = parse_bound_addr(SOCKS5_ATYP_IPV6, &data);
        assert!(result.is_err());
    }

    // ========== bound_addr_fixed_size tests ==========

    #[test]
    fn test_bound_addr_fixed_size_ipv4() {
        // IPv4: 4 addr bytes + 2 port bytes = 6
        assert_eq!(bound_addr_fixed_size(SOCKS5_ATYP_IPV4).unwrap().unwrap(), 6);
    }

    #[test]
    fn test_bound_addr_fixed_size_ipv6() {
        // IPv6: 16 addr bytes + 2 port bytes = 18
        assert_eq!(bound_addr_fixed_size(SOCKS5_ATYP_IPV6).unwrap().unwrap(), 18);
    }

    #[test]
    fn test_bound_addr_fixed_size_domain() {
        // Domain: needs length byte first, so returns None
        assert!(bound_addr_fixed_size(SOCKS5_ATYP_DOMAIN).is_none());
    }

    #[test]
    fn test_bound_addr_fixed_size_unknown() {
        let result = bound_addr_fixed_size(0xFF);
        assert!(result.is_some());
        assert!(result.unwrap().is_err());
    }

    // ===== Bug verification tests =====

    #[test]
    fn test_with_auth_long_username_returns_result_not_panic() {
        // P0-1 fix: with_auth now returns Result instead of panicking
        let long_user = "a".repeat(256);
        let result = Socks5::with_auth("127.0.0.1:1080", long_user, "pass");
        assert!(result.is_err(), "with_auth should return Err for long credentials");
    }

    #[test]
    fn test_with_auth_long_password_returns_result_not_panic() {
        let long_pass = "b".repeat(256);
        let result = Socks5::with_auth("127.0.0.1:1080", "user", long_pass);
        assert!(result.is_err(), "with_auth should return Err for long credentials");
    }
}

#[cfg(all(test, feature = "async"))]
mod async_tests {
    use super::*;

    #[tokio::test]
    async fn test_async_socks5_new() {
        let socks5 = Socks5::new("127.0.0.1:1080");
        assert_eq!(socks5.addr, "127.0.0.1:1080");
        assert!(socks5.username.is_none());
    }

    #[tokio::test]
    async fn test_async_socks5_with_auth() {
        let socks5 = Socks5::with_auth("127.0.0.1:1080", "user", "pass").unwrap();
        assert_eq!(socks5.username, Some("user".to_string()));
        assert_eq!(socks5.password, Some("pass".to_string()));
    }

    #[tokio::test]
    async fn test_async_socks5_dial_tcp_connection_refused() {
        let socks5 = Socks5::new("127.0.0.1:59998");
        let mut addr = Addr::new("example.com", 80);
        let result = AsyncOutbound::dial_tcp(&socks5, &mut addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_socks5_addr_to_socks5_ipv4() {
        let (atyp, addr) = addr_to_socks5("192.168.1.1").unwrap();
        assert_eq!(atyp, SOCKS5_ATYP_IPV4);
        assert_eq!(addr, vec![192, 168, 1, 1]);
    }

    #[tokio::test]
    async fn test_async_socks5_addr_to_socks5_domain() {
        let (atyp, addr) = addr_to_socks5("example.com").unwrap();
        assert_eq!(atyp, SOCKS5_ATYP_DOMAIN);
        assert_eq!(addr[0], 11);
        assert_eq!(&addr[1..], b"example.com");
    }

    #[tokio::test]
    async fn test_async_socks5_auth_exchange_timeout() {
        // Bug: async_dial_and_negotiate wraps initial negotiation with timeout
        // but the auth exchange (write_all + read_exact for credentials) has
        // no timeout. A malicious server can hang after receiving credentials.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Read negotiation request
            let mut buf = [0u8; 16];
            let _ = stream.read(&mut buf).await;
            // Reply: require username/password auth
            stream.write_all(&[0x05, 0x02]).await.unwrap();
            // Read auth request from client
            let mut auth_buf = [0u8; 512];
            let _ = stream.read(&mut auth_buf).await;
            // Hang: never send auth response
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let socks5 = Socks5::with_auth(format!("127.0.0.1:{}", port), "user", "pass")
            .unwrap()
            .with_timeout(Duration::from_secs(5));

        // The auth exchange should timeout, not hang forever.
        // We use an outer timeout larger than SOCKS5_NEGOTIATION_TIMEOUT to detect
        // if the internal timeout is working.
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            socks5.async_dial_and_negotiate(),
        )
        .await;

        // After fix: internal timeout fires first, result is Ok(Err(AclError))
        // Before fix: outer timeout fires, result is Err(Elapsed)
        assert!(
            result.is_ok(),
            "async_dial_and_negotiate should not hang forever - auth exchange needs timeout"
        );
        assert!(
            result.unwrap().is_err(),
            "auth exchange should fail with timeout error"
        );

        server.abort();
    }

    #[tokio::test]
    async fn test_async_socks5_dial_tcp_domain_name_proxy() {
        // Bug: Socks5::async_dial_and_negotiate() uses SocketAddr::parse() which rejects domain names.
        let socks5 = Socks5::new("localhost:59996");
        let mut addr = Addr::new("example.com", 80);
        let result = AsyncOutbound::dial_tcp(&socks5, &mut addr).await;
        match result {
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    !err_msg.contains("Invalid proxy address"),
                    "Domain name proxy should be resolved, got address parse error: {}",
                    err_msg
                );
            }
            Ok(_) => panic!("Expected connection error for non-listening port"),
        }
    }

}
