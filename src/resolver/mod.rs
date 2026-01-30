//! DNS resolver module.
//!
//! Provides interfaces and implementations for DNS resolution.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use crate::error::{AclError, Result};

#[cfg(feature = "async")]
use async_trait::async_trait;

/// DNS resolver interface.
pub trait Resolver: Send + Sync {
    /// Resolve the hostname to IPv4 and IPv6 addresses.
    ///
    /// Either or both of the returned IPs can be None if no address is found.
    /// Returns an error if the resolution fails completely.
    fn resolve(&self, host: &str) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)>;
}

/// Async DNS resolver interface.
#[cfg(feature = "async")]
#[async_trait]
pub trait AsyncResolver: Send + Sync {
    /// Resolve the hostname to IPv4 and IPv6 addresses asynchronously.
    ///
    /// Either or both of the returned IPs can be None if no address is found.
    /// Returns an error if the resolution fails completely.
    async fn resolve(&self, host: &str) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)>;
}

/// System DNS resolver using the OS resolver.
pub struct SystemResolver;

impl SystemResolver {
    /// Create a new system resolver.
    pub fn new() -> Self {
        Self
    }
}

impl Default for SystemResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        // First check if host is already an IP address
        if let Ok(ip) = host.parse::<IpAddr>() {
            return match ip {
                IpAddr::V4(v4) => Ok((Some(v4), None)),
                IpAddr::V6(v6) => Ok((None, Some(v6))),
            };
        }

        // Resolve using system DNS
        let addrs = (host, 0u16)
            .to_socket_addrs()
            .map_err(|e| AclError::ResolveError(format!("Failed to resolve {}: {}", host, e)))?;

        let (ipv4, ipv6) = split_ipv4_ipv6(addrs.map(|a| a.ip()).collect::<Vec<_>>().as_slice());
        Ok((ipv4, ipv6))
    }
}

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

        // Use tokio's DNS resolution
        let host_owned = host.to_string();
        let addrs = tokio::net::lookup_host(format!("{}:0", host_owned))
            .await
            .map_err(|e| AclError::ResolveError(format!("Failed to resolve {}: {}", host, e)))?;

        let (ipv4, ipv6) = split_ipv4_ipv6(addrs.map(|a| a.ip()).collect::<Vec<_>>().as_slice());
        Ok((ipv4, ipv6))
    }
}

/// Nil resolver that always returns no addresses.
pub struct NilResolver;

impl NilResolver {
    /// Create a new nil resolver.
    pub fn new() -> Self {
        Self
    }
}

impl Default for NilResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver for NilResolver {
    fn resolve(&self, _host: &str) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        Ok((None, None))
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncResolver for NilResolver {
    async fn resolve(&self, _host: &str) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        Ok((None, None))
    }
}

/// Static resolver with predefined mappings.
pub struct StaticResolver {
    mappings: std::collections::HashMap<String, (Option<Ipv4Addr>, Option<Ipv6Addr>)>,
}

impl StaticResolver {
    /// Create a new empty static resolver.
    pub fn new() -> Self {
        Self {
            mappings: std::collections::HashMap::new(),
        }
    }

    /// Add a mapping for a hostname.
    pub fn add(&mut self, host: impl Into<String>, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) {
        self.mappings.insert(host.into(), (ipv4, ipv6));
    }

    /// Add a mapping and return self for chaining.
    pub fn with_mapping(
        mut self,
        host: impl Into<String>,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) -> Self {
        self.add(host, ipv4, ipv6);
        self
    }
}

impl Default for StaticResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver for StaticResolver {
    fn resolve(&self, host: &str) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
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

#[cfg(feature = "async")]
#[async_trait]
impl AsyncResolver for StaticResolver {
    async fn resolve(&self, host: &str) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        // Reuse sync implementation since it's non-blocking
        Resolver::resolve(self, host)
    }
}

/// Split IP addresses into first IPv4 and first IPv6.
fn split_ipv4_ipv6(ips: &[IpAddr]) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
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

    #[test]
    fn test_system_resolver_ip() {
        let resolver = SystemResolver::new();

        // Test IPv4
        let result = Resolver::resolve(&resolver, "127.0.0.1").unwrap();
        assert_eq!(result.0, Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(result.1.is_none());

        // Test IPv6
        let result = Resolver::resolve(&resolver, "::1").unwrap();
        assert!(result.0.is_none());
        assert_eq!(result.1, Some(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_nil_resolver() {
        let resolver = NilResolver::new();
        let result = Resolver::resolve(&resolver, "example.com").unwrap();
        assert!(result.0.is_none());
        assert!(result.1.is_none());
    }

    #[test]
    fn test_static_resolver() {
        let resolver = StaticResolver::new().with_mapping(
            "example.com",
            Some(Ipv4Addr::new(93, 184, 216, 34)),
            None,
        );

        let result = Resolver::resolve(&resolver, "example.com").unwrap();
        assert_eq!(result.0, Some(Ipv4Addr::new(93, 184, 216, 34)));
        assert!(result.1.is_none());

        // Unknown host
        let result = Resolver::resolve(&resolver, "unknown.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_static_resolver_ip_passthrough() {
        let resolver = StaticResolver::new();
        let result = Resolver::resolve(&resolver, "192.168.1.1").unwrap();
        assert_eq!(result.0, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }
}

#[cfg(all(test, feature = "async"))]
mod async_tests {
    use super::*;

    #[tokio::test]
    async fn test_async_system_resolver_ip() {
        let resolver = SystemResolver::new();

        // Test IPv4
        let result = AsyncResolver::resolve(&resolver, "127.0.0.1").await.unwrap();
        assert_eq!(result.0, Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(result.1.is_none());

        // Test IPv6
        let result = AsyncResolver::resolve(&resolver, "::1").await.unwrap();
        assert!(result.0.is_none());
        assert_eq!(result.1, Some(Ipv6Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn test_async_nil_resolver() {
        let resolver = NilResolver::new();
        let result = AsyncResolver::resolve(&resolver, "example.com").await.unwrap();
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

        let result = AsyncResolver::resolve(&resolver, "example.com").await.unwrap();
        assert_eq!(result.0, Some(Ipv4Addr::new(93, 184, 216, 34)));
        assert!(result.1.is_none());

        // Unknown host
        let result = AsyncResolver::resolve(&resolver, "unknown.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_static_resolver_ip_passthrough() {
        let resolver = StaticResolver::new();
        let result = AsyncResolver::resolve(&resolver, "192.168.1.1").await.unwrap();
        assert_eq!(result.0, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }
}
