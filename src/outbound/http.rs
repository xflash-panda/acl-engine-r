//! HTTP/HTTPS proxy outbound implementation.
//!
//! Connects to targets through an HTTP proxy using the CONNECT method.
//! Note: HTTP proxies don't support UDP by design.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::error::{AclError, Result};

use super::{Addr, Outbound, TcpConn, UdpConn, DEFAULT_DIALER_TIMEOUT};

#[cfg(feature = "async")]
use super::{AsyncOutbound, AsyncTcpConn, AsyncUdpConn, TokioTcpConn};
#[cfg(feature = "async")]
use async_trait::async_trait;
#[cfg(feature = "async")]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
#[cfg(feature = "async")]
use tokio::net::TcpStream as TokioTcpStream;

const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum number of response headers to read before aborting.
/// Prevents memory exhaustion from malicious proxies sending infinite headers.
const MAX_RESPONSE_HEADERS: usize = 100;

/// HTTP/HTTPS proxy outbound.
///
/// Uses the HTTP CONNECT method to tunnel TCP connections.
/// Since HTTP proxies support using either IP or domain name as the target
/// address, it will ignore ResolveInfo in Addr and always only use Host.
///
/// Note: UDP is not supported by HTTP proxies.
pub struct Http {
    /// Proxy server address
    addr: String,
    /// Use HTTPS connection to proxy
    https: bool,
    /// Skip TLS certificate verification
    insecure: bool,
    /// Basic auth header value (base64 encoded)
    basic_auth: Option<String>,
    /// Connection timeout
    timeout: Duration,
}

impl Http {
    /// Create a new HTTP proxy outbound from URL.
    ///
    /// URL format: `http://[user:pass@]host:port` or `https://[user:pass@]host:port`
    pub fn from_url(url: &str) -> Result<Self> {
        Self::from_url_with_options(url, false)
    }

    /// Create a new HTTP proxy outbound from URL with options.
    pub fn from_url_with_options(url: &str, insecure: bool) -> Result<Self> {
        // Simple URL parsing
        let url = url.trim();

        let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(AclError::OutboundError(
                "Unsupported scheme for HTTP proxy (use http:// or https://)".to_string(),
            ));
        };

        // Parse auth and host
        let (auth, host_port) = if let Some(at_pos) = rest.rfind('@') {
            let auth_part = &rest[..at_pos];
            let host_part = &rest[at_pos + 1..];
            (Some(auth_part), host_part)
        } else {
            (None, rest)
        };

        // Handle default ports
        let addr = if host_port.contains(':') {
            host_port.to_string()
        } else if scheme {
            format!("{}:443", host_port)
        } else {
            format!("{}:80", host_port)
        };

        // Build basic auth header
        let basic_auth = auth.map(|a| {
            use base64::Engine;
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(a)
            )
        });

        Ok(Self {
            addr,
            https: scheme,
            insecure,
            basic_auth,
            timeout: DEFAULT_DIALER_TIMEOUT,
        })
    }

    /// Create a new HTTP proxy outbound with direct address.
    pub fn new(addr: impl Into<String>, https: bool) -> Self {
        Self {
            addr: addr.into(),
            https,
            insecure: false,
            basic_auth: None,
            timeout: DEFAULT_DIALER_TIMEOUT,
        }
    }

    /// Set basic authentication.
    pub fn with_auth(mut self, username: &str, password: &str) -> Self {
        use base64::Engine;
        let credentials = format!("{}:{}", username, password);
        self.basic_auth = Some(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credentials)
        ));
        self
    }

    /// Set connection timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set insecure mode (skip TLS verification).
    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// Connect to the proxy server.
    fn dial(&self) -> Result<TcpStream> {
        let addr: SocketAddr = self
            .addr
            .to_socket_addrs()
            .map_err(|e| AclError::OutboundError(format!("Failed to resolve proxy address: {}", e)))?
            .next()
            .ok_or_else(|| AclError::OutboundError("No address resolved for proxy".to_string()))?;

        let stream = TcpStream::connect_timeout(&addr, self.timeout)
            .map_err(|e| AclError::OutboundError(format!("Failed to connect to proxy: {}", e)))?;

        // Note: For HTTPS proxies, we would need to wrap with TLS here.
        // This is a simplified implementation that only supports HTTP proxies.
        if self.https {
            return Err(AclError::OutboundError(
                "HTTPS proxy not yet supported (use http:// instead)".to_string(),
            ));
        }

        Ok(stream)
    }

    /// Connect to the proxy server asynchronously.
    #[cfg(feature = "async")]
    async fn async_dial(&self) -> Result<TokioTcpStream> {
        let addr: SocketAddr = self
            .addr
            .to_socket_addrs()
            .map_err(|e| AclError::OutboundError(format!("Failed to resolve proxy address: {}", e)))?
            .next()
            .ok_or_else(|| AclError::OutboundError("No address resolved for proxy".to_string()))?;

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
}

impl Outbound for Http {
    fn dial_tcp(&self, addr: &mut Addr) -> Result<Box<dyn TcpConn>> {
        let mut stream = self.dial()?;

        stream.set_read_timeout(Some(HTTP_REQUEST_TIMEOUT)).ok();
        stream.set_write_timeout(Some(HTTP_REQUEST_TIMEOUT)).ok();

        // Build CONNECT request
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

        // Send request
        stream.write_all(request.as_bytes()).map_err(|e| {
            AclError::OutboundError(format!("Failed to send CONNECT request: {}", e))
        })?;

        // Read response
        let mut reader = BufReader::new(&stream);
        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
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
        let mut header_count = 0;
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .map_err(|e| AclError::OutboundError(format!("Failed to read headers: {}", e)))?;
            if line.trim().is_empty() {
                break;
            }
            header_count += 1;
            if header_count > MAX_RESPONSE_HEADERS {
                return Err(AclError::OutboundError(format!(
                    "Too many response headers (>{MAX_RESPONSE_HEADERS})"
                )));
            }
        }

        // Reset timeout
        stream.set_read_timeout(None).ok();
        stream.set_write_timeout(None).ok();

        // Check if there's buffered data
        let buffered = reader.buffer();
        if !buffered.is_empty() {
            // Wrap connection with buffered data
            let buffered_data = buffered.to_vec();
            let stream = reader.into_inner();
            return Ok(Box::new(BufferedTcpConn::new(
                stream.try_clone().map_err(|e| {
                    AclError::OutboundError(format!("Failed to clone stream: {}", e))
                })?,
                buffered_data,
            )));
        }

        Ok(Box::new(HttpTcpConn::new(stream.try_clone().map_err(
            |e| AclError::OutboundError(format!("Failed to clone stream: {}", e)),
        )?)))
    }

    fn dial_udp(&self, _addr: &mut Addr) -> Result<Box<dyn UdpConn>> {
        Err(AclError::OutboundError(
            "UDP not supported by HTTP proxy".to_string(),
        ))
    }
}

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

        tokio::time::timeout(
            HTTP_REQUEST_TIMEOUT,
            reader.get_mut().write_all(request.as_bytes()),
        )
        .await
        .map_err(|_| AclError::OutboundError("Request timeout".to_string()))?
        .map_err(|e| AclError::OutboundError(format!("Failed to send CONNECT request: {}", e)))?;

        let mut status_line = String::new();
        tokio::time::timeout(HTTP_REQUEST_TIMEOUT, reader.read_line(&mut status_line))
            .await
            .map_err(|_| AclError::OutboundError("Response timeout".to_string()))?
            .map_err(|e| AclError::OutboundError(format!("Failed to read response: {}", e)))?;

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

        tokio::time::timeout(HTTP_REQUEST_TIMEOUT, async {
            let mut header_count = 0;
            loop {
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .await
                    .map_err(|e| {
                        AclError::OutboundError(format!("Failed to read headers: {}", e))
                    })?;
                if line.trim().is_empty() {
                    break;
                }
                header_count += 1;
                if header_count > MAX_RESPONSE_HEADERS {
                    return Err(AclError::OutboundError(format!(
                        "Too many response headers (>{MAX_RESPONSE_HEADERS})"
                    )));
                }
            }
            Ok::<_, AclError>(())
        })
        .await
        .map_err(|_| AclError::OutboundError("Header read timeout".to_string()))??;

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

/// HTTP proxy TCP connection wrapper.
struct HttpTcpConn {
    stream: TcpStream,
}

impl HttpTcpConn {
    fn new(stream: TcpStream) -> Self {
        Self { stream }
    }
}

impl Read for HttpTcpConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for HttpTcpConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl TcpConn for HttpTcpConn {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_write_timeout(dur)
    }

    fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        self.stream.shutdown(how)
    }
}

/// TCP connection with buffered data from initial response.
struct BufferedTcpConn {
    stream: TcpStream,
    buffer: Vec<u8>,
    buffer_pos: usize,
}

impl BufferedTcpConn {
    fn new(stream: TcpStream, buffer: Vec<u8>) -> Self {
        Self {
            stream,
            buffer,
            buffer_pos: 0,
        }
    }
}

impl Read for BufferedTcpConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // First read from buffer
        if self.buffer_pos < self.buffer.len() {
            let remaining = &self.buffer[self.buffer_pos..];
            let to_copy = remaining.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&remaining[..to_copy]);
            self.buffer_pos += to_copy;
            return Ok(to_copy);
        }
        // Then read from stream
        self.stream.read(buf)
    }
}

impl Write for BufferedTcpConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl TcpConn for BufferedTcpConn {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_write_timeout(dur)
    }

    fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        self.stream.shutdown(how)
    }
}

/// Async TCP connection with buffered data from initial response.
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
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.buffer_pos < self.buffer.len() {
            let remaining = &self.buffer[self.buffer_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.buffer_pos += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

#[cfg(feature = "async")]
impl tokio::io::AsyncWrite for AsyncBufferedTcpConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(feature = "async")]
impl Unpin for AsyncBufferedTcpConn {}

#[cfg(feature = "async")]
impl AsyncTcpConn for AsyncBufferedTcpConn {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.peer_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_from_url() {
        let http = Http::from_url("http://proxy.example.com:8080").unwrap();
        assert_eq!(http.addr, "proxy.example.com:8080");
        assert!(!http.https);
        assert!(http.basic_auth.is_none());
    }

    #[test]
    fn test_http_from_url_with_auth() {
        let http = Http::from_url("http://user:pass@proxy.example.com:8080").unwrap();
        assert_eq!(http.addr, "proxy.example.com:8080");
        assert!(!http.https);
        assert!(http.basic_auth.is_some());
    }

    #[test]
    fn test_http_from_url_default_port() {
        let http = Http::from_url("http://proxy.example.com").unwrap();
        assert_eq!(http.addr, "proxy.example.com:80");
    }

    #[test]
    fn test_http_udp_not_supported() {
        let http = Http::new("127.0.0.1:8080", false);
        let mut addr = Addr::new("example.com", 53);
        let result = Outbound::dial_udp(&http, &mut addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_http_max_response_headers_constant() {
        // The MAX_RESPONSE_HEADERS constant must exist and be reasonable
        assert!(
            MAX_RESPONSE_HEADERS > 0 && MAX_RESPONSE_HEADERS <= 200,
            "MAX_RESPONSE_HEADERS should be between 1 and 200, got {}",
            MAX_RESPONSE_HEADERS
        );
    }

    #[test]
    fn test_http_sync_dial_tcp_too_many_headers() {
        // A malicious proxy that sends valid status line + excessive headers
        // should be rejected by the header count limit.
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Read the CONNECT request
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            // Send valid status line
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n")
                .unwrap();
            // Send way more headers than MAX_RESPONSE_HEADERS
            for i in 0..200 {
                let header = format!("X-Spam-{}: value{}\r\n", i, i);
                if stream.write_all(header.as_bytes()).is_err() {
                    break;
                }
            }
            // Never send the terminating empty line
            std::thread::sleep(Duration::from_secs(5));
        });

        let http = Http::new(format!("127.0.0.1:{}", port), false);
        let mut addr = Addr::new("example.com", 80);
        let result = Outbound::dial_tcp(&http, &mut addr);

        // Should fail with too many headers error, not hang or succeed
        match result {
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("Too many") || err_msg.contains("too many"),
                    "Error should mention too many headers, got: {}",
                    err_msg
                );
            }
            Ok(_) => panic!("Should reject excessive headers"),
        }

        server.join().ok();
    }

    #[test]
    fn test_http_dial_tcp_domain_name_proxy() {
        // Bug: Http::dial() uses SocketAddr::parse() which rejects domain names.
        // Using a domain name proxy address should resolve and attempt connection,
        // not fail with "Invalid proxy address".
        let http = Http::new("localhost:59996", false);
        let mut addr = Addr::new("example.com", 80);
        let result = Outbound::dial_tcp(&http, &mut addr);
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
        let result = AsyncOutbound::dial_udp(&http, &mut addr).await;
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("UDP not supported")),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[tokio::test]
    async fn test_async_http_dial_tcp_connection_refused() {
        let http = Http::new("127.0.0.1:59997", false);
        let mut addr = Addr::new("example.com", 80);
        let result = AsyncOutbound::dial_tcp(&http, &mut addr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_http_dial_tcp_domain_name_proxy() {
        // Bug: Http::async_dial() uses SocketAddr::parse() which rejects domain names.
        let http = Http::new("localhost:59996", false);
        let mut addr = Addr::new("example.com", 80);
        let result = AsyncOutbound::dial_tcp(&http, &mut addr).await;
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

    #[tokio::test]
    async fn test_async_http_dial_tcp_too_many_headers() {
        // A malicious proxy that sends valid status line + excessive headers
        // should be rejected by the header count limit, even within timeout.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            // Send valid status line
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n")
                .await
                .unwrap();
            // Send excessive headers quickly
            for i in 0..200 {
                let header = format!("X-Spam-{}: value{}\r\n", i, i);
                if stream.write_all(header.as_bytes()).await.is_err() {
                    break;
                }
            }
            // Keep alive
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let http = Http::new(format!("127.0.0.1:{}", port), false);
        let mut addr = Addr::new("example.com", 80);
        let result = AsyncOutbound::dial_tcp(&http, &mut addr).await;

        // Should fail with too many headers error
        match result {
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("Too many") || err_msg.contains("too many"),
                    "Error should mention too many headers, got: {}",
                    err_msg
                );
            }
            Ok(_) => panic!("Should reject excessive headers"),
        }

        server.abort();
    }

    #[tokio::test]
    async fn test_async_http_header_read_timeout() {
        // Bug: async dial_tcp has no timeout on header-reading loop.
        // A proxy that sends status line but never finishes headers should timeout,
        // not hang forever.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Mock proxy: accepts, reads request, sends status line, then hangs
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            // Send valid status line but never send terminating empty header line
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n")
                .await
                .unwrap();
            // Keep connection open indefinitely
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let http = Http::new(format!("127.0.0.1:{}", port), false);
        let mut addr = Addr::new("example.com", 80);

        // Outer timeout: must be larger than HTTP_REQUEST_TIMEOUT (10s)
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            AsyncOutbound::dial_tcp(&http, &mut addr),
        )
        .await;

        // If dial_tcp hangs forever, the outer timeout fires and result is Err(Elapsed).
        // After fix, internal timeout fires first and dial_tcp returns Err(AclError).
        assert!(
            result.is_ok(),
            "dial_tcp should not hang forever - header read needs internal timeout"
        );
        assert!(result.unwrap().is_err());

        server.abort();
    }
}
