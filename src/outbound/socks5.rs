//! SOCKS5 proxy outbound implementation.
//!
//! Connects to targets through a SOCKS5 proxy server.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use crate::error::{AclError, Result};

use super::{Addr, Outbound, StdTcpConn, TcpConn, UdpConn, DEFAULT_DIALER_TIMEOUT};

#[cfg(feature = "async")]
use async_trait::async_trait;
#[cfg(feature = "async")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "async")]
use tokio::net::{TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket};
#[cfg(feature = "async")]
use super::{AsyncOutbound, AsyncTcpConn, AsyncUdpConn, TokioTcpConn};

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
    pub fn with_auth(
        addr: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            addr: addr.into(),
            username: Some(username.into()),
            password: Some(password.into()),
            timeout: DEFAULT_DIALER_TIMEOUT,
        }
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
            .parse()
            .map_err(|e| AclError::OutboundError(format!("Invalid proxy address: {}", e)))?;

        let mut stream = TcpStream::connect_timeout(&addr, self.timeout)
            .map_err(|e| AclError::OutboundError(format!("Failed to connect to proxy: {}", e)))?;

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
            .map_err(|e| AclError::OutboundError(format!("Failed to send negotiation: {}", e)))?;

        // Read negotiation response
        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).map_err(|e| {
            AclError::OutboundError(format!("Failed to read negotiation response: {}", e))
        })?;

        if resp[0] != SOCKS5_VERSION {
            return Err(AclError::OutboundError(format!(
                "Invalid SOCKS version: {}",
                resp[0]
            )));
        }

        match resp[1] {
            SOCKS5_AUTH_NONE => {
                // No authentication required
            }
            SOCKS5_AUTH_PASSWORD => {
                // Username/password authentication
                let username = self.username.as_ref().ok_or_else(|| {
                    AclError::OutboundError(
                        "Server requires authentication but no credentials provided".to_string(),
                    )
                })?;
                let password = self.password.as_ref().ok_or_else(|| {
                    AclError::OutboundError(
                        "Server requires authentication but no credentials provided".to_string(),
                    )
                })?;

                // Send auth request
                let mut auth_req = vec![0x01]; // Version 1
                auth_req.push(username.len() as u8);
                auth_req.extend(username.as_bytes());
                auth_req.push(password.len() as u8);
                auth_req.extend(password.as_bytes());

                stream
                    .write_all(&auth_req)
                    .map_err(|e| AclError::OutboundError(format!("Failed to send auth: {}", e)))?;

                // Read auth response
                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).map_err(|e| {
                    AclError::OutboundError(format!("Failed to read auth response: {}", e))
                })?;

                if auth_resp[1] != 0x00 {
                    return Err(AclError::OutboundError(
                        "SOCKS5 authentication failed".to_string(),
                    ));
                }
            }
            SOCKS5_AUTH_NO_ACCEPTABLE => {
                return Err(AclError::OutboundError(
                    "No acceptable authentication method".to_string(),
                ));
            }
            method => {
                return Err(AclError::OutboundError(format!(
                    "Unsupported authentication method: {}",
                    method
                )));
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

        // Build request
        let (atyp, dst_addr) = self.addr_to_socks5(&addr.host);
        let mut req = vec![SOCKS5_VERSION, cmd, 0x00, atyp];
        req.extend(&dst_addr);
        req.push((addr.port >> 8) as u8);
        req.push((addr.port & 0xFF) as u8);

        stream
            .write_all(&req)
            .map_err(|e| AclError::OutboundError(format!("Failed to send request: {}", e)))?;

        // Read response header
        let mut resp_header = [0u8; 4];
        stream
            .read_exact(&mut resp_header)
            .map_err(|e| AclError::OutboundError(format!("Failed to read response: {}", e)))?;

        if resp_header[0] != SOCKS5_VERSION {
            return Err(AclError::OutboundError(format!(
                "Invalid SOCKS version in response: {}",
                resp_header[0]
            )));
        }

        if resp_header[1] != SOCKS5_REP_SUCCESS {
            return Err(AclError::OutboundError(format!(
                "SOCKS5 request failed: {}",
                self.rep_to_string(resp_header[1])
            )));
        }

        // Read bound address
        let (bound_host, bound_port) = match resp_header[3] {
            SOCKS5_ATYP_IPV4 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).map_err(|e| {
                    AclError::OutboundError(format!("Failed to read IPv4 address: {}", e))
                })?;
                let ip = IpAddr::V4(std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]));
                let mut port_buf = [0u8; 2];
                stream
                    .read_exact(&mut port_buf)
                    .map_err(|e| AclError::OutboundError(format!("Failed to read port: {}", e)))?;
                let port = u16::from_be_bytes(port_buf);
                (ip.to_string(), port)
            }
            SOCKS5_ATYP_IPV6 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).map_err(|e| {
                    AclError::OutboundError(format!("Failed to read IPv6 address: {}", e))
                })?;
                let ip = IpAddr::V6(std::net::Ipv6Addr::from(addr));
                let mut port_buf = [0u8; 2];
                stream
                    .read_exact(&mut port_buf)
                    .map_err(|e| AclError::OutboundError(format!("Failed to read port: {}", e)))?;
                let port = u16::from_be_bytes(port_buf);
                (ip.to_string(), port)
            }
            SOCKS5_ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).map_err(|e| {
                    AclError::OutboundError(format!("Failed to read domain length: {}", e))
                })?;
                let len = len_buf[0] as usize;
                let mut domain = vec![0u8; len];
                stream.read_exact(&mut domain).map_err(|e| {
                    AclError::OutboundError(format!("Failed to read domain: {}", e))
                })?;
                let mut port_buf = [0u8; 2];
                stream
                    .read_exact(&mut port_buf)
                    .map_err(|e| AclError::OutboundError(format!("Failed to read port: {}", e)))?;
                let port = u16::from_be_bytes(port_buf);
                (String::from_utf8_lossy(&domain).to_string(), port)
            }
            atyp => {
                return Err(AclError::OutboundError(format!(
                    "Unknown address type: {}",
                    atyp
                )));
            }
        };

        // Reset timeout
        stream.set_read_timeout(None).ok();
        stream.set_write_timeout(None).ok();

        Ok((bound_host, bound_port))
    }

    /// Convert address to SOCKS5 format.
    fn addr_to_socks5(&self, host: &str) -> (u8, Vec<u8>) {
        if let Ok(ip) = host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => (SOCKS5_ATYP_IPV4, v4.octets().to_vec()),
                IpAddr::V6(v6) => (SOCKS5_ATYP_IPV6, v6.octets().to_vec()),
            }
        } else {
            let domain = host.as_bytes();
            let mut addr = vec![domain.len() as u8];
            addr.extend(domain);
            (SOCKS5_ATYP_DOMAIN, addr)
        }
    }

    /// Convert reply code to string.
    fn rep_to_string(&self, rep: u8) -> &'static str {
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

    /// Async: Connect to the proxy and perform negotiation.
    #[cfg(feature = "async")]
    async fn async_dial_and_negotiate(&self) -> Result<TokioTcpStream> {
        let addr: SocketAddr = self
            .addr
            .parse()
            .map_err(|e| AclError::OutboundError(format!("Invalid proxy address: {}", e)))?;

        let mut stream = tokio::time::timeout(self.timeout, TokioTcpStream::connect(addr))
            .await
            .map_err(|_| AclError::OutboundError("Connection timeout".to_string()))?
            .map_err(|e| AclError::OutboundError(format!("Failed to connect to proxy: {}", e)))?;

        let auth_methods = if self.username.is_some() && self.password.is_some() {
            vec![SOCKS5_AUTH_NONE, SOCKS5_AUTH_PASSWORD]
        } else {
            vec![SOCKS5_AUTH_NONE]
        };

        let mut req = vec![SOCKS5_VERSION, auth_methods.len() as u8];
        req.extend(&auth_methods);

        tokio::time::timeout(SOCKS5_NEGOTIATION_TIMEOUT, stream.write_all(&req))
            .await
            .map_err(|_| AclError::OutboundError("Negotiation timeout".to_string()))?
            .map_err(|e| AclError::OutboundError(format!("Failed to send negotiation: {}", e)))?;

        let mut resp = [0u8; 2];
        tokio::time::timeout(SOCKS5_NEGOTIATION_TIMEOUT, stream.read_exact(&mut resp))
            .await
            .map_err(|_| AclError::OutboundError("Negotiation timeout".to_string()))?
            .map_err(|e| {
                AclError::OutboundError(format!("Failed to read negotiation response: {}", e))
            })?;

        if resp[0] != SOCKS5_VERSION {
            return Err(AclError::OutboundError(format!(
                "Invalid SOCKS version: {}",
                resp[0]
            )));
        }

        match resp[1] {
            SOCKS5_AUTH_NONE => {}
            SOCKS5_AUTH_PASSWORD => {
                let username = self.username.as_ref().ok_or_else(|| {
                    AclError::OutboundError(
                        "Server requires authentication but no credentials provided".to_string(),
                    )
                })?;
                let password = self.password.as_ref().ok_or_else(|| {
                    AclError::OutboundError(
                        "Server requires authentication but no credentials provided".to_string(),
                    )
                })?;

                let mut auth_req = vec![0x01];
                auth_req.push(username.len() as u8);
                auth_req.extend(username.as_bytes());
                auth_req.push(password.len() as u8);
                auth_req.extend(password.as_bytes());

                stream
                    .write_all(&auth_req)
                    .await
                    .map_err(|e| AclError::OutboundError(format!("Failed to send auth: {}", e)))?;

                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await.map_err(|e| {
                    AclError::OutboundError(format!("Failed to read auth response: {}", e))
                })?;

                if auth_resp[1] != 0x00 {
                    return Err(AclError::OutboundError(
                        "SOCKS5 authentication failed".to_string(),
                    ));
                }
            }
            SOCKS5_AUTH_NO_ACCEPTABLE => {
                return Err(AclError::OutboundError(
                    "No acceptable authentication method".to_string(),
                ));
            }
            method => {
                return Err(AclError::OutboundError(format!(
                    "Unsupported authentication method: {}",
                    method
                )));
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
        let (atyp, dst_addr) = self.addr_to_socks5(&addr.host);
        let mut req = vec![SOCKS5_VERSION, cmd, 0x00, atyp];
        req.extend(&dst_addr);
        req.push((addr.port >> 8) as u8);
        req.push((addr.port & 0xFF) as u8);

        tokio::time::timeout(SOCKS5_REQUEST_TIMEOUT, stream.write_all(&req))
            .await
            .map_err(|_| AclError::OutboundError("Request timeout".to_string()))?
            .map_err(|e| AclError::OutboundError(format!("Failed to send request: {}", e)))?;

        let mut resp_header = [0u8; 4];
        tokio::time::timeout(SOCKS5_REQUEST_TIMEOUT, stream.read_exact(&mut resp_header))
            .await
            .map_err(|_| AclError::OutboundError("Request timeout".to_string()))?
            .map_err(|e| AclError::OutboundError(format!("Failed to read response: {}", e)))?;

        if resp_header[0] != SOCKS5_VERSION {
            return Err(AclError::OutboundError(format!(
                "Invalid SOCKS version in response: {}",
                resp_header[0]
            )));
        }

        if resp_header[1] != SOCKS5_REP_SUCCESS {
            return Err(AclError::OutboundError(format!(
                "SOCKS5 request failed: {}",
                self.rep_to_string(resp_header[1])
            )));
        }

        let (bound_host, bound_port) = match resp_header[3] {
            SOCKS5_ATYP_IPV4 => {
                let mut addr_buf = [0u8; 4];
                stream.read_exact(&mut addr_buf).await.map_err(|e| {
                    AclError::OutboundError(format!("Failed to read IPv4 address: {}", e))
                })?;
                let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                    addr_buf[0],
                    addr_buf[1],
                    addr_buf[2],
                    addr_buf[3],
                ));
                let mut port_buf = [0u8; 2];
                stream
                    .read_exact(&mut port_buf)
                    .await
                    .map_err(|e| AclError::OutboundError(format!("Failed to read port: {}", e)))?;
                (ip.to_string(), u16::from_be_bytes(port_buf))
            }
            SOCKS5_ATYP_IPV6 => {
                let mut addr_buf = [0u8; 16];
                stream.read_exact(&mut addr_buf).await.map_err(|e| {
                    AclError::OutboundError(format!("Failed to read IPv6 address: {}", e))
                })?;
                let ip = IpAddr::V6(std::net::Ipv6Addr::from(addr_buf));
                let mut port_buf = [0u8; 2];
                stream
                    .read_exact(&mut port_buf)
                    .await
                    .map_err(|e| AclError::OutboundError(format!("Failed to read port: {}", e)))?;
                (ip.to_string(), u16::from_be_bytes(port_buf))
            }
            SOCKS5_ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await.map_err(|e| {
                    AclError::OutboundError(format!("Failed to read domain length: {}", e))
                })?;
                let len = len_buf[0] as usize;
                let mut domain = vec![0u8; len];
                stream
                    .read_exact(&mut domain)
                    .await
                    .map_err(|e| AclError::OutboundError(format!("Failed to read domain: {}", e)))?;
                let mut port_buf = [0u8; 2];
                stream
                    .read_exact(&mut port_buf)
                    .await
                    .map_err(|e| AclError::OutboundError(format!("Failed to read port: {}", e)))?;
                (
                    String::from_utf8_lossy(&domain).to_string(),
                    u16::from_be_bytes(port_buf),
                )
            }
            atyp => {
                return Err(AclError::OutboundError(format!(
                    "Unknown address type: {}",
                    atyp
                )));
            }
        };

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

        // Create UDP socket
        let udp_socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| AclError::OutboundError(format!("Failed to bind UDP: {}", e)))?;

        // Connect to the bound address
        let udp_addr = format!("{}:{}", bound_host, bound_port);
        udp_socket
            .connect(&udp_addr)
            .map_err(|e| AclError::OutboundError(format!("Failed to connect UDP: {}", e)))?;

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

        let udp_socket = TokioUdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| AclError::OutboundError(format!("Failed to bind UDP: {}", e)))?;

        let udp_addr = format!("{}:{}", bound_host, bound_port);
        udp_socket
            .connect(&udp_addr)
            .await
            .map_err(|e| AclError::OutboundError(format!("Failed to connect UDP: {}", e)))?;

        Ok(Box::new(AsyncSocks5UdpConn::new(stream, udp_socket)))
    }
}

/// SOCKS5 UDP connection wrapper.
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

    fn addr_to_socks5(&self, addr: &Addr) -> Vec<u8> {
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
            data.push(SOCKS5_ATYP_DOMAIN);
            data.push(domain.len() as u8);
            data.extend(domain);
        }

        // Port
        data.push((addr.port >> 8) as u8);
        data.push((addr.port & 0xFF) as u8);

        data
    }

    fn parse_socks5_addr(&self, data: &[u8]) -> Result<(Addr, usize)> {
        if data.len() < 4 {
            return Err(AclError::OutboundError(
                "Invalid SOCKS5 datagram".to_string(),
            ));
        }

        // Skip RSV (2 bytes) + FRAG (1 byte)
        let atyp = data[3];
        let mut offset = 4;

        let (host, port) = match atyp {
            SOCKS5_ATYP_IPV4 => {
                if data.len() < offset + 6 {
                    return Err(AclError::OutboundError("Invalid IPv4 datagram".to_string()));
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
                    return Err(AclError::OutboundError("Invalid IPv6 datagram".to_string()));
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
                    return Err(AclError::OutboundError(
                        "Invalid domain datagram".to_string(),
                    ));
                }
                let len = data[offset] as usize;
                offset += 1;
                if data.len() < offset + len + 2 {
                    return Err(AclError::OutboundError(
                        "Invalid domain datagram".to_string(),
                    ));
                }
                let domain = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
                offset += len;
                let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;
                (domain, port)
            }
            _ => {
                return Err(AclError::OutboundError(format!(
                    "Unknown address type: {}",
                    atyp
                )));
            }
        };

        Ok((Addr::new(host, port), offset))
    }
}

impl UdpConn for Socks5UdpConn {
    fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)> {
        let mut recv_buf = vec![0u8; 65536];
        let n = self
            .udp_socket
            .recv(&mut recv_buf)
            .map_err(|e| AclError::OutboundError(format!("UDP recv error: {}", e)))?;

        let (addr, header_len) = self.parse_socks5_addr(&recv_buf[..n])?;
        let data_len = n - header_len;
        let copy_len = data_len.min(buf.len());
        buf[..copy_len].copy_from_slice(&recv_buf[header_len..header_len + copy_len]);

        Ok((copy_len, addr))
    }

    fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize> {
        let mut packet = self.addr_to_socks5(addr);
        packet.extend(buf);

        self.udp_socket
            .send(&packet)
            .map_err(|e| AclError::OutboundError(format!("UDP send error: {}", e)))?;

        Ok(buf.len())
    }

    fn close(&self) -> Result<()> {
        Ok(())
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

    fn addr_to_socks5(&self, addr: &Addr) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend(&[0x00, 0x00, 0x00]);

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
            data.push(SOCKS5_ATYP_DOMAIN);
            data.push(domain.len() as u8);
            data.extend(domain);
        }

        data.push((addr.port >> 8) as u8);
        data.push((addr.port & 0xFF) as u8);
        data
    }

    fn parse_socks5_addr(&self, data: &[u8]) -> Result<(Addr, usize)> {
        if data.len() < 4 {
            return Err(AclError::OutboundError(
                "Invalid SOCKS5 datagram".to_string(),
            ));
        }

        let atyp = data[3];
        let mut offset = 4;

        let (host, port) = match atyp {
            SOCKS5_ATYP_IPV4 => {
                if data.len() < offset + 6 {
                    return Err(AclError::OutboundError("Invalid IPv4 datagram".to_string()));
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
                    return Err(AclError::OutboundError("Invalid IPv6 datagram".to_string()));
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
                    return Err(AclError::OutboundError(
                        "Invalid domain datagram".to_string(),
                    ));
                }
                let len = data[offset] as usize;
                offset += 1;
                if data.len() < offset + len + 2 {
                    return Err(AclError::OutboundError(
                        "Invalid domain datagram".to_string(),
                    ));
                }
                let domain = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
                offset += len;
                let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;
                (domain, port)
            }
            _ => {
                return Err(AclError::OutboundError(format!(
                    "Unknown address type: {}",
                    atyp
                )));
            }
        };

        Ok((Addr::new(host, port), offset))
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncUdpConn for AsyncSocks5UdpConn {
    async fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)> {
        let mut recv_buf = vec![0u8; 65536];
        let n = self
            .udp_socket
            .recv(&mut recv_buf)
            .await
            .map_err(|e| AclError::OutboundError(format!("UDP recv error: {}", e)))?;

        let (addr, header_len) = self.parse_socks5_addr(&recv_buf[..n])?;
        let data_len = n - header_len;
        let copy_len = data_len.min(buf.len());
        buf[..copy_len].copy_from_slice(&recv_buf[header_len..header_len + copy_len]);

        Ok((copy_len, addr))
    }

    async fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize> {
        let mut packet = self.addr_to_socks5(addr);
        packet.extend(buf);

        self.udp_socket
            .send(&packet)
            .await
            .map_err(|e| AclError::OutboundError(format!("UDP send error: {}", e)))?;

        Ok(buf.len())
    }

    async fn close(&self) -> Result<()> {
        Ok(())
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
        let socks5 = Socks5::with_auth("127.0.0.1:1080", "user", "pass");
        assert_eq!(socks5.addr, "127.0.0.1:1080");
        assert_eq!(socks5.username, Some("user".to_string()));
        assert_eq!(socks5.password, Some("pass".to_string()));
    }

    #[test]
    fn test_addr_to_socks5_ipv4() {
        let socks5 = Socks5::new("127.0.0.1:1080");
        let (atyp, addr) = socks5.addr_to_socks5("192.168.1.1");
        assert_eq!(atyp, SOCKS5_ATYP_IPV4);
        assert_eq!(addr, vec![192, 168, 1, 1]);
    }

    #[test]
    fn test_addr_to_socks5_domain() {
        let socks5 = Socks5::new("127.0.0.1:1080");
        let (atyp, addr) = socks5.addr_to_socks5("example.com");
        assert_eq!(atyp, SOCKS5_ATYP_DOMAIN);
        assert_eq!(addr[0], 11); // length of "example.com"
        assert_eq!(&addr[1..], b"example.com");
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
        let socks5 = Socks5::with_auth("127.0.0.1:1080", "user", "pass");
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
        let socks5 = Socks5::new("127.0.0.1:1080");
        let (atyp, addr) = socks5.addr_to_socks5("192.168.1.1");
        assert_eq!(atyp, SOCKS5_ATYP_IPV4);
        assert_eq!(addr, vec![192, 168, 1, 1]);
    }

    #[tokio::test]
    async fn test_async_socks5_addr_to_socks5_domain() {
        let socks5 = Socks5::new("127.0.0.1:1080");
        let (atyp, addr) = socks5.addr_to_socks5("example.com");
        assert_eq!(atyp, SOCKS5_ATYP_DOMAIN);
        assert_eq!(addr[0], 11);
        assert_eq!(&addr[1..], b"example.com");
    }
}
