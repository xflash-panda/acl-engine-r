//! Reject outbound implementation.
//!
//! Rejects all connection attempts.

use crate::error::{AclError, OutboundErrorKind, Result};

#[cfg(feature = "async")]
use super::{AsyncOutbound, AsyncTcpConn, AsyncUdpConn};
#[cfg(feature = "async")]
use async_trait::async_trait;

use super::{Addr, Outbound, TcpConn, UdpConn};

/// Reject outbound that rejects all connections.
pub struct Reject;

impl Reject {
    /// Create a new Reject outbound.
    pub fn new() -> Self {
        Self
    }
}

impl Default for Reject {
    fn default() -> Self {
        Self::new()
    }
}

impl Outbound for Reject {
    fn dial_tcp(&self, _addr: &mut Addr) -> Result<Box<dyn TcpConn>> {
        Err(AclError::OutboundError { kind: OutboundErrorKind::Unsupported, message: "Connection rejected".to_string() })
    }

    fn dial_udp(&self, _addr: &mut Addr) -> Result<Box<dyn UdpConn>> {
        Err(AclError::OutboundError { kind: OutboundErrorKind::Unsupported, message: "Connection rejected".to_string() })
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncOutbound for Reject {
    async fn dial_tcp(&self, _addr: &mut Addr) -> Result<Box<dyn AsyncTcpConn>> {
        Err(AclError::OutboundError { kind: OutboundErrorKind::Unsupported, message: "Connection rejected".to_string() })
    }

    async fn dial_udp(&self, _addr: &mut Addr) -> Result<Box<dyn AsyncUdpConn>> {
        Err(AclError::OutboundError { kind: OutboundErrorKind::Unsupported, message: "Connection rejected".to_string() })
    }
}

#[cfg(test)]
mod tests {
    use super::{Addr, Outbound, Reject};

    #[test]
    fn test_reject_tcp() {
        let reject = Reject::new();
        let mut addr = Addr::new("example.com", 80);
        let result = reject.dial_tcp(&mut addr);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_udp() {
        let reject = Reject::new();
        let mut addr = Addr::new("example.com", 53);
        let result = reject.dial_udp(&mut addr);
        assert!(result.is_err());
    }
}

#[cfg(all(test, feature = "async"))]
mod async_tests {
    use super::{Addr, AsyncOutbound, Reject};

    #[tokio::test]
    async fn test_async_reject_tcp() {
        let reject = Reject::new();
        let mut addr = Addr::new("example.com", 80);
        let result = reject.dial_tcp(&mut addr).await;
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("rejected")),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[tokio::test]
    async fn test_async_reject_udp() {
        let reject = Reject::new();
        let mut addr = Addr::new("example.com", 53);
        let result = reject.dial_udp(&mut addr).await;
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("rejected")),
            Ok(_) => panic!("Expected error"),
        }
    }
}
