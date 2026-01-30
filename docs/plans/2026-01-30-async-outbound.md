# Async Outbound Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Convert all outbound implementations from sync to async using tokio, with feature flags to support both APIs.

**Architecture:** Use feature flags (`async` default, `sync` optional) to provide two parallel implementations. Async version uses `tokio::net` and `async-trait`. Sync implementations moved to `sync_impl/` subdirectory, async to `async_impl/`.

**Tech Stack:** tokio 1.x, async-trait, tokio::io::{AsyncRead, AsyncWrite}

---

## Task 1: Update Cargo.toml with async dependencies

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add tokio and async-trait dependencies**

```toml
[dependencies]
# ... existing dependencies ...

# Async runtime (optional, for async API)
tokio = { version = "1", features = ["net", "io-util", "time", "sync", "rt"], optional = true }
async-trait = { version = "0.1", optional = true }

[features]
default = ["async", "geoip", "geosite"]
async = ["tokio", "async-trait"]
sync = []
geoip = []
geosite = []
```

**Step 2: Update dev-dependencies**

```toml
[dev-dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "io-util", "time"] }
```

**Step 3: Verify changes compile**

Run: `cargo check --features async`
Expected: Success

**Step 4: Commit**

```bash
git add Cargo.toml
git commit -m "feat: add tokio and async-trait dependencies for async outbound"
```

---

## Task 2: Create async traits in outbound/mod.rs

**Files:**
- Modify: `src/outbound/mod.rs`

**Step 1: Add async imports at the top**

After existing imports, add:

```rust
#[cfg(feature = "async")]
use async_trait::async_trait;
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};
```

**Step 2: Define AsyncTcpConn trait**

After the existing `TcpConn` trait, add:

```rust
/// Async TCP connection interface.
#[cfg(feature = "async")]
pub trait AsyncTcpConn: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    /// Get the local address
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Get the peer address
    fn peer_addr(&self) -> io::Result<SocketAddr>;
}
```

**Step 3: Define AsyncUdpConn trait**

After the existing `UdpConn` trait, add:

```rust
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
```

**Step 4: Define AsyncOutbound trait**

After the existing `Outbound` trait, add:

```rust
/// Async outbound connection interface.
#[cfg(feature = "async")]
#[async_trait]
pub trait AsyncOutbound: Send + Sync {
    /// Establish an async TCP connection to the given address.
    async fn dial_tcp(&self, addr: &mut Addr) -> Result<Box<dyn AsyncTcpConn>>;

    /// Create an async UDP connection for the given address.
    async fn dial_udp(&self, addr: &mut Addr) -> Result<Box<dyn AsyncUdpConn>>;
}
```

**Step 5: Create TokioTcpConn wrapper**

After `StdUdpConn`, add:

```rust
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
```

**Step 6: Create TokioUdpConn wrapper**

```rust
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
        Ok((n, Addr::new(addr.ip().to_string(), addr.port())))
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
```

**Step 7: Update public exports**

Add to the existing `pub use` statements or add new ones:

```rust
#[cfg(feature = "async")]
pub use self::{AsyncOutbound, AsyncTcpConn, AsyncUdpConn, TokioTcpConn, TokioUdpConn};
```

**Step 8: Verify changes compile**

Run: `cargo check --features async`
Expected: Success

**Step 9: Commit**

```bash
git add src/outbound/mod.rs
git commit -m "feat: add async traits for outbound connections"
```

---

## Task 3: Implement async Reject outbound

**Files:**
- Modify: `src/outbound/reject.rs`

**Step 1: Add async imports**

At the top of the file, add:

```rust
#[cfg(feature = "async")]
use async_trait::async_trait;
#[cfg(feature = "async")]
use super::{AsyncOutbound, AsyncTcpConn, AsyncUdpConn};
```

**Step 2: Implement AsyncOutbound for Reject**

After the existing `impl Outbound for Reject`, add:

```rust
#[cfg(feature = "async")]
#[async_trait]
impl AsyncOutbound for Reject {
    async fn dial_tcp(&self, _addr: &mut Addr) -> Result<Box<dyn AsyncTcpConn>> {
        Err(AclError::OutboundError("Connection rejected".to_string()))
    }

    async fn dial_udp(&self, _addr: &mut Addr) -> Result<Box<dyn AsyncUdpConn>> {
        Err(AclError::OutboundError("Connection rejected".to_string()))
    }
}
```

**Step 3: Add async tests**

After existing tests, add:

```rust
#[cfg(all(test, feature = "async"))]
mod async_tests {
    use super::*;

    #[tokio::test]
    async fn test_async_reject_tcp() {
        let reject = Reject::new();
        let mut addr = Addr::new("example.com", 80);
        let result = reject.dial_tcp(&mut addr).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("rejected"));
    }

    #[tokio::test]
    async fn test_async_reject_udp() {
        let reject = Reject::new();
        let mut addr = Addr::new("example.com", 53);
        let result = reject.dial_udp(&mut addr).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("rejected"));
    }
}
```

**Step 4: Verify changes compile and tests pass**

Run: `cargo test --features async reject`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/outbound/reject.rs
git commit -m "feat: implement async Reject outbound"
```

---

## Task 4: Implement async Direct outbound

**Files:**
- Modify: `src/outbound/direct.rs`

**Step 1: Add async imports**

At the top of the file, after existing imports, add:

```rust
#[cfg(feature = "async")]
use async_trait::async_trait;
#[cfg(feature = "async")]
use tokio::net::{TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket};
#[cfg(feature = "async")]
use super::{AsyncOutbound, AsyncTcpConn, AsyncUdpConn, TokioTcpConn};
```

**Step 2: Add async resolve method**

After the existing `resolve` method, add:

```rust
#[cfg(feature = "async")]
async fn async_resolve(&self, addr: &mut Addr) {
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

    // Resolve using tokio DNS
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
```

**Step 3: Add async dial_tcp_ip method**

After the existing `dial_tcp_ip` method, add:

```rust
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
                .map_err(|e| AclError::OutboundError(format!("Failed to create socket: {}", e)))?;
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
                .map_err(|e| AclError::OutboundError(format!("Failed to create socket: {}", e)))?;
                socket
                    .bind(&bind_addr.into())
                    .map_err(|e| AclError::OutboundError(format!("Failed to bind: {}", e)))?;
                socket.set_nonblocking(true).ok();
                socket
            }
        };
        let std_stream: std::net::TcpStream = socket.into();
        let stream = TokioTcpStream::from_std(std_stream)
            .map_err(|e| AclError::OutboundError(format!("Failed to convert stream: {}", e)))?;

        tokio::time::timeout(self.timeout, stream.connect(socket_addr))
            .await
            .map_err(|_| AclError::OutboundError("Connection timeout".to_string()))?
            .map_err(|e| AclError::OutboundError(format!("Failed to connect: {}", e)))?;
        stream
    } else {
        tokio::time::timeout(self.timeout, TokioTcpStream::connect(socket_addr))
            .await
            .map_err(|_| AclError::OutboundError("Connection timeout".to_string()))?
            .map_err(|e| AclError::OutboundError(format!("Failed to connect: {}", e)))?
    };

    Ok(stream)
}
```

**Step 4: Add async dual_stack_dial_tcp method**

After the existing `dual_stack_dial_tcp` method, add:

```rust
#[cfg(feature = "async")]
async fn async_dual_stack_dial_tcp(
    &self,
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
    port: u16,
) -> Result<TokioTcpStream> {
    let v4_future = self.async_dial_tcp_ip(IpAddr::V4(ipv4), port);
    let v6_future = self.async_dial_tcp_ip(IpAddr::V6(ipv6), port);

    tokio::select! {
        result = v4_future => {
            if result.is_ok() {
                return result;
            }
            // v4 failed, wait for v6
            self.async_dial_tcp_ip(IpAddr::V6(ipv6), port).await
        }
        result = v6_future => {
            if result.is_ok() {
                return result;
            }
            // v6 failed, wait for v4
            self.async_dial_tcp_ip(IpAddr::V4(ipv4), port).await
        }
    }
}
```

**Step 5: Implement AsyncOutbound for Direct**

After the existing `impl Outbound for Direct`, add:

```rust
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
                    self.async_dual_stack_dial_tcp(ipv4, ipv6, addr.port).await?
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
```

**Step 6: Add AsyncDirectUdpConn struct**

After the existing `DirectUdpConn`, add:

```rust
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
```

**Step 7: Add async tests**

After existing tests, add:

```rust
#[cfg(all(test, feature = "async"))]
mod async_tests {
    use super::*;
    use std::net::Ipv4Addr;

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
        // Start a TCP listener
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let direct = Direct::new();
        let mut addr = Addr::new("127.0.0.1", port);

        // Spawn accept task
        let accept_handle = tokio::spawn(async move {
            listener.accept().await.ok()
        });

        // Connect
        let result = direct.dial_tcp(&mut addr).await;
        assert!(result.is_ok());

        accept_handle.await.ok();
    }

    #[tokio::test]
    async fn test_async_direct_dial_tcp_connection_refused() {
        let direct = Direct::new();
        // Use a port that's likely not listening
        let mut addr = Addr::new("127.0.0.1", 59999);

        let result = direct.dial_tcp(&mut addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_direct_dial_udp() {
        let direct = Direct::new();
        let mut addr = Addr::new("127.0.0.1", 53);

        let result = direct.dial_udp(&mut addr).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_async_direct_modes() {
        // Test Only4 mode
        let direct = Direct::with_mode(DirectMode::Only4);
        let mut addr = Addr::new("127.0.0.1", 80);
        addr.resolve_info = Some(ResolveInfo::from_ipv4(Ipv4Addr::new(127, 0, 0, 1)));

        // Just verify resolve works without error
        direct.async_resolve(&mut addr).await;
        assert!(addr.resolve_info.is_some());
    }
}
```

**Step 8: Verify changes compile and tests pass**

Run: `cargo test --features async direct`
Expected: All tests pass

**Step 9: Commit**

```bash
git add src/outbound/direct.rs
git commit -m "feat: implement async Direct outbound with dual-stack support"
```

---

## Task 5: Implement async SOCKS5 outbound

**Files:**
- Modify: `src/outbound/socks5.rs`

**Step 1: Add async imports**

After existing imports, add:

```rust
#[cfg(feature = "async")]
use async_trait::async_trait;
#[cfg(feature = "async")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "async")]
use tokio::net::{TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket};
#[cfg(feature = "async")]
use super::{AsyncOutbound, AsyncTcpConn, AsyncUdpConn, TokioTcpConn};
```

**Step 2: Add async dial_and_negotiate method**

After the existing `dial_and_negotiate` method, add:

```rust
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

    // Send negotiation request
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

    // Read negotiation response
    let mut resp = [0u8; 2];
    tokio::time::timeout(SOCKS5_NEGOTIATION_TIMEOUT, stream.read_exact(&mut resp))
        .await
        .map_err(|_| AclError::OutboundError("Negotiation timeout".to_string()))?
        .map_err(|e| AclError::OutboundError(format!("Failed to read negotiation response: {}", e)))?;

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
            stream
                .read_exact(&mut auth_resp)
                .await
                .map_err(|e| AclError::OutboundError(format!("Failed to read auth response: {}", e)))?;

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
```

**Step 3: Add async request method**

After the existing `request` method, add:

```rust
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

    // Read response header
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

    // Read bound address
    let (bound_host, bound_port) = match resp_header[3] {
        SOCKS5_ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await.map_err(|e| {
                AclError::OutboundError(format!("Failed to read IPv4 address: {}", e))
            })?;
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]));
            let mut port_buf = [0u8; 2];
            stream
                .read_exact(&mut port_buf)
                .await
                .map_err(|e| AclError::OutboundError(format!("Failed to read port: {}", e)))?;
            let port = u16::from_be_bytes(port_buf);
            (ip.to_string(), port)
        }
        SOCKS5_ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await.map_err(|e| {
                AclError::OutboundError(format!("Failed to read IPv6 address: {}", e))
            })?;
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(addr));
            let mut port_buf = [0u8; 2];
            stream
                .read_exact(&mut port_buf)
                .await
                .map_err(|e| AclError::OutboundError(format!("Failed to read port: {}", e)))?;
            let port = u16::from_be_bytes(port_buf);
            (ip.to_string(), port)
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await.map_err(|e| {
                AclError::OutboundError(format!("Failed to read domain length: {}", e))
            })?;
            let len = len_buf[0] as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await.map_err(|e| {
                AclError::OutboundError(format!("Failed to read domain: {}", e))
            })?;
            let mut port_buf = [0u8; 2];
            stream
                .read_exact(&mut port_buf)
                .await
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

    Ok((bound_host, bound_port))
}
```

**Step 4: Implement AsyncOutbound for Socks5**

After the existing `impl Outbound for Socks5`, add:

```rust
#[cfg(feature = "async")]
#[async_trait]
impl AsyncOutbound for Socks5 {
    async fn dial_tcp(&self, addr: &mut Addr) -> Result<Box<dyn AsyncTcpConn>> {
        let mut stream = self.async_dial_and_negotiate().await?;
        self.async_request(&mut stream, SOCKS5_CMD_CONNECT, addr).await?;
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
```

**Step 5: Add AsyncSocks5UdpConn struct**

After the existing `Socks5UdpConn`, add:

```rust
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
```

**Step 6: Add async tests**

After existing tests, add:

```rust
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
        let result = socks5.dial_tcp(&mut addr).await;
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
```

**Step 7: Verify changes compile and tests pass**

Run: `cargo test --features async socks5`
Expected: All tests pass

**Step 8: Commit**

```bash
git add src/outbound/socks5.rs
git commit -m "feat: implement async SOCKS5 outbound"
```

---

## Task 6: Implement async HTTP outbound

**Files:**
- Modify: `src/outbound/http.rs`

**Step 1: Add async imports**

After existing imports, add:

```rust
#[cfg(feature = "async")]
use async_trait::async_trait;
#[cfg(feature = "async")]
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader};
#[cfg(feature = "async")]
use tokio::net::TcpStream as TokioTcpStream;
#[cfg(feature = "async")]
use super::{AsyncOutbound, AsyncTcpConn, AsyncUdpConn, TokioTcpConn};
```

**Step 2: Add async dial method**

After the existing `dial` method, add:

```rust
#[cfg(feature = "async")]
async fn async_dial(&self) -> Result<TokioTcpStream> {
    let addr: SocketAddr = self
        .addr
        .parse()
        .map_err(|e| AclError::OutboundError(format!("Invalid proxy address: {}", e)))?;

    let stream = tokio::time::timeout(self.timeout, TokioTcpStream::connect(addr))
        .await
        .map_err(|_| AclError::OutboundError("Connection timeout".to_string()))?
        .map_err(|e| AclError::OutboundError(format!("Failed to connect to proxy: {}", e)))?;

    if self.https {
        return Err(AclError::OutboundError(
            "HTTPS proxy not yet supported (use http:// instead)".to_string(),
        ));
    }

    Ok(stream)
}
```

**Step 3: Implement AsyncOutbound for Http**

After the existing `impl Outbound for Http`, add:

```rust
#[cfg(feature = "async")]
#[async_trait]
impl AsyncOutbound for Http {
    async fn dial_tcp(&self, addr: &mut Addr) -> Result<Box<dyn AsyncTcpConn>> {
        let stream = self.async_dial().await?;

        let target = format!("{}:{}", addr.host, addr.port);
        let mut request = format!(
            "CONNECT {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Proxy-Connection: Keep-Alive\r\n",
            target, target
        );

        if let Some(ref auth) = self.basic_auth {
            request.push_str(&format!("Proxy-Authorization: {}\r\n", auth));
        }

        request.push_str("\r\n");

        let mut reader = TokioBufReader::new(stream);

        tokio::time::timeout(HTTP_REQUEST_TIMEOUT, reader.get_mut().write_all(request.as_bytes()))
            .await
            .map_err(|_| AclError::OutboundError("Request timeout".to_string()))?
            .map_err(|e| AclError::OutboundError(format!("Failed to send CONNECT request: {}", e)))?;

        // Read response
        let mut status_line = String::new();
        tokio::time::timeout(HTTP_REQUEST_TIMEOUT, reader.read_line(&mut status_line))
            .await
            .map_err(|_| AclError::OutboundError("Response timeout".to_string()))?
            .map_err(|e| AclError::OutboundError(format!("Failed to read response: {}", e)))?;

        // Parse status code
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(AclError::OutboundError(format!(
                "Invalid HTTP response: {}",
                status_line.trim()
            )));
        }

        let status_code: u16 = parts[1]
            .parse()
            .map_err(|_| AclError::OutboundError(format!("Invalid status code: {}", parts[1])))?;

        if status_code != 200 {
            return Err(AclError::OutboundError(format!(
                "HTTP CONNECT failed: {} {}",
                status_code,
                parts.get(2..).unwrap_or(&[]).join(" ")
            )));
        }

        // Read and discard headers until empty line
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .await
                .map_err(|e| AclError::OutboundError(format!("Failed to read headers: {}", e)))?;
            if line.trim().is_empty() {
                break;
            }
        }

        // Check for buffered data
        let buffered = reader.buffer();
        if !buffered.is_empty() {
            let buffered_data = buffered.to_vec();
            let stream = reader.into_inner();
            return Ok(Box::new(AsyncBufferedTcpConn::new(stream, buffered_data)));
        }

        Ok(Box::new(TokioTcpConn::new(reader.into_inner())))
    }

    async fn dial_udp(&self, _addr: &mut Addr) -> Result<Box<dyn AsyncUdpConn>> {
        Err(AclError::OutboundError(
            "UDP not supported by HTTP proxy".to_string(),
        ))
    }
}
```

**Step 4: Add AsyncBufferedTcpConn struct**

After the existing `BufferedTcpConn`, add:

```rust
#[cfg(feature = "async")]
struct AsyncBufferedTcpConn {
    stream: TokioTcpStream,
    buffer: Vec<u8>,
    buffer_pos: usize,
}

#[cfg(feature = "async")]
impl AsyncBufferedTcpConn {
    fn new(stream: TokioTcpStream, buffer: Vec<u8>) -> Self {
        Self {
            stream,
            buffer,
            buffer_pos: 0,
        }
    }
}

#[cfg(feature = "async")]
impl tokio::io::AsyncRead for AsyncBufferedTcpConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // First read from buffer
        if self.buffer_pos < self.buffer.len() {
            let remaining = &self.buffer[self.buffer_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.buffer_pos += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }
        // Then read from stream
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

#[cfg(feature = "async")]
impl tokio::io::AsyncWrite for AsyncBufferedTcpConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(feature = "async")]
impl Unpin for AsyncBufferedTcpConn {}

#[cfg(feature = "async")]
impl AsyncTcpConn for AsyncBufferedTcpConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }
}
```

**Step 5: Add async tests**

After existing tests, add:

```rust
#[cfg(all(test, feature = "async"))]
mod async_tests {
    use super::*;

    #[tokio::test]
    async fn test_async_http_from_url() {
        let http = Http::from_url("http://proxy.example.com:8080").unwrap();
        assert_eq!(http.addr, "proxy.example.com:8080");
        assert!(!http.https);
    }

    #[tokio::test]
    async fn test_async_http_from_url_with_auth() {
        let http = Http::from_url("http://user:pass@proxy.example.com:8080").unwrap();
        assert!(http.basic_auth.is_some());
    }

    #[tokio::test]
    async fn test_async_http_udp_not_supported() {
        let http = Http::new("127.0.0.1:8080", false);
        let mut addr = Addr::new("example.com", 53);
        let result = http.dial_udp(&mut addr).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("UDP not supported"));
    }

    #[tokio::test]
    async fn test_async_http_dial_tcp_connection_refused() {
        let http = Http::new("127.0.0.1:59997", false);
        let mut addr = Addr::new("example.com", 80);
        let result = http.dial_tcp(&mut addr).await;
        assert!(result.is_err());
    }
}
```

**Step 6: Verify changes compile and tests pass**

Run: `cargo test --features async http`
Expected: All tests pass

**Step 7: Commit**

```bash
git add src/outbound/http.rs
git commit -m "feat: implement async HTTP outbound"
```

---

## Task 7: Update public exports in lib.rs

**Files:**
- Modify: `src/lib.rs`

**Step 1: Add conditional async exports**

After the existing outbound exports, add:

```rust
#[cfg(feature = "async")]
pub use outbound::{AsyncOutbound, AsyncTcpConn, AsyncUdpConn, TokioTcpConn, TokioUdpConn};
```

**Step 2: Verify changes compile**

Run: `cargo check --features async`
Expected: Success

**Step 3: Commit**

```bash
git add src/lib.rs
git commit -m "feat: export async outbound traits from lib"
```

---

## Task 8: Add async resolver trait

**Files:**
- Modify: `src/resolver/mod.rs`

**Step 1: Add async imports**

After existing imports, add:

```rust
#[cfg(feature = "async")]
use async_trait::async_trait;
```

**Step 2: Add AsyncResolver trait**

After the existing `Resolver` trait, add:

```rust
/// Async DNS resolver interface.
#[cfg(feature = "async")]
#[async_trait]
pub trait AsyncResolver: Send + Sync {
    /// Resolve the hostname to IPv4 and IPv6 addresses.
    async fn resolve(&self, host: &str) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)>;
}
```

**Step 3: Implement AsyncResolver for SystemResolver**

After the existing `impl Resolver for SystemResolver`, add:

```rust
#[cfg(feature = "async")]
#[async_trait]
impl AsyncResolver for SystemResolver {
    async fn resolve(&self, host: &str) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        // First check if host is already an IP address
        if let Ok(ip) = host.parse::<IpAddr>() {
            return match ip {
                IpAddr::V4(v4) => Ok((Some(v4), None)),
                IpAddr::V6(v6) => Ok((None, Some(v6))),
            };
        }

        // Resolve using tokio DNS
        let addrs = tokio::net::lookup_host(format!("{}:0", host))
            .await
            .map_err(|e| AclError::ResolveError(format!("Failed to resolve {}: {}", host, e)))?;

        let (ipv4, ipv6) = split_ipv4_ipv6(addrs.map(|a| a.ip()).collect::<Vec<_>>().as_slice());
        Ok((ipv4, ipv6))
    }
}
```

**Step 4: Implement AsyncResolver for NilResolver**

After the existing `impl Resolver for NilResolver`, add:

```rust
#[cfg(feature = "async")]
#[async_trait]
impl AsyncResolver for NilResolver {
    async fn resolve(&self, _host: &str) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        Ok((None, None))
    }
}
```

**Step 5: Implement AsyncResolver for StaticResolver**

After the existing `impl Resolver for StaticResolver`, add:

```rust
#[cfg(feature = "async")]
#[async_trait]
impl AsyncResolver for StaticResolver {
    async fn resolve(&self, host: &str) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        // First check if host is already an IP address
        if let Ok(ip) = host.parse::<IpAddr>() {
            return match ip {
                IpAddr::V4(v4) => Ok((Some(v4), None)),
                IpAddr::V6(v6) => Ok((None, Some(v6))),
            };
        }

        self.mappings
            .get(host)
            .copied()
            .ok_or_else(|| AclError::ResolveError(format!("Host not found: {}", host)))
    }
}
```

**Step 6: Add async tests**

After existing tests, add:

```rust
#[cfg(all(test, feature = "async"))]
mod async_tests {
    use super::*;

    #[tokio::test]
    async fn test_async_system_resolver_ip() {
        let resolver = SystemResolver::new();

        let result = resolver.resolve("127.0.0.1").await.unwrap();
        assert_eq!(result.0, Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(result.1.is_none());
    }

    #[tokio::test]
    async fn test_async_nil_resolver() {
        let resolver = NilResolver::new();
        let result = resolver.resolve("example.com").await.unwrap();
        assert!(result.0.is_none());
        assert!(result.1.is_none());
    }

    #[tokio::test]
    async fn test_async_static_resolver() {
        let resolver = StaticResolver::new().with_mapping(
            "example.com",
            Some(Ipv4Addr::new(93, 184, 216, 34)),
            None,
        );

        let result = resolver.resolve("example.com").await.unwrap();
        assert_eq!(result.0, Some(Ipv4Addr::new(93, 184, 216, 34)));
    }
}
```

**Step 7: Update exports**

At the bottom of the file or in lib.rs, add:

```rust
#[cfg(feature = "async")]
pub use self::AsyncResolver;
```

**Step 8: Verify changes compile and tests pass**

Run: `cargo test --features async resolver`
Expected: All tests pass

**Step 9: Commit**

```bash
git add src/resolver/mod.rs
git commit -m "feat: add async resolver trait and implementations"
```

---

## Task 9: Update lib.rs with async resolver export

**Files:**
- Modify: `src/lib.rs`

**Step 1: Add async resolver export**

After the existing resolver exports, add:

```rust
#[cfg(feature = "async")]
pub use resolver::AsyncResolver;
```

**Step 2: Verify changes compile**

Run: `cargo check --features async`
Expected: Success

**Step 3: Commit**

```bash
git add src/lib.rs
git commit -m "feat: export AsyncResolver from lib"
```

---

## Task 10: Run all tests and verify both features work

**Files:**
- None (verification only)

**Step 1: Test async feature**

Run: `cargo test --features async`
Expected: All tests pass

**Step 2: Test sync feature**

Run: `cargo test --features sync`
Expected: All tests pass

**Step 3: Test default features**

Run: `cargo test`
Expected: All tests pass (async is default)

**Step 4: Check clippy**

Run: `cargo clippy --features async -- -D warnings`
Expected: No warnings

**Step 5: Final commit**

```bash
git add -A
git commit -m "chore: verify async outbound implementation complete"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Update Cargo.toml | Cargo.toml |
| 2 | Create async traits | src/outbound/mod.rs |
| 3 | Async Reject | src/outbound/reject.rs |
| 4 | Async Direct | src/outbound/direct.rs |
| 5 | Async SOCKS5 | src/outbound/socks5.rs |
| 6 | Async HTTP | src/outbound/http.rs |
| 7 | Export async outbound | src/lib.rs |
| 8 | Async resolver | src/resolver/mod.rs |
| 9 | Export async resolver | src/lib.rs |
| 10 | Verification | - |

**Total new tests:** ~20 async tests covering all outbound types and resolver.
