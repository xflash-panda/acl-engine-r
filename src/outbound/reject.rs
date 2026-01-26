//! Reject outbound implementation.
//!
//! Rejects all connection attempts.

use crate::error::{AclError, Result};

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
        Err(AclError::OutboundError("Connection rejected".to_string()))
    }

    fn dial_udp(&self, _addr: &mut Addr) -> Result<Box<dyn UdpConn>> {
        Err(AclError::OutboundError("Connection rejected".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
