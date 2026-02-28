use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Network protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    TCP,
    UDP,
    Both,
}

impl Protocol {
    /// Check if this protocol matches the given protocol
    pub fn matches(&self, other: Protocol) -> bool {
        match self {
            Protocol::Both => true,
            Protocol::TCP => matches!(other, Protocol::TCP | Protocol::Both),
            Protocol::UDP => matches!(other, Protocol::UDP | Protocol::Both),
        }
    }
}

/// Host information for matching
#[derive(Debug, Clone, Default)]
pub struct HostInfo {
    /// Hostname (domain name)
    pub name: String,
    /// Resolved IPv4 address
    pub ipv4: Option<Ipv4Addr>,
    /// Resolved IPv6 address
    pub ipv6: Option<Ipv6Addr>,
}

impl HostInfo {
    /// Create a new HostInfo with just a name
    pub fn from_name(name: impl Into<String>) -> Self {
        Self {
            name: name.into().to_lowercase(),
            ipv4: None,
            ipv6: None,
        }
    }

    /// Create a new HostInfo with name and IPs
    pub fn new(
        name: impl Into<String>,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
    ) -> Self {
        Self {
            name: name.into().to_lowercase(),
            ipv4,
            ipv6,
        }
    }

    /// Create a HostInfo from an IP address
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self {
                name: String::new(),
                ipv4: Some(v4),
                ipv6: None,
            },
            IpAddr::V6(v6) => Self {
                name: String::new(),
                ipv4: None,
                ipv6: Some(v6),
            },
        }
    }
}

/// Parsed text rule before compilation
#[derive(Debug, Clone)]
pub struct TextRule {
    /// Outbound name
    pub outbound: String,
    /// Address pattern
    pub address: String,
    /// Protocol/port specification (e.g., "tcp/443", "udp/53", "*/80-90")
    pub proto_port: Option<String>,
    /// Hijack address
    pub hijack_address: Option<String>,
    /// Line number in the original text (for error reporting)
    pub line_num: usize,
}

/// Match result from the ACL engine
#[derive(Debug, Clone)]
pub struct MatchResult<O> {
    /// The matched outbound
    pub outbound: O,
    /// Hijack IP address (if any)
    pub hijack_ip: Option<IpAddr>,
}

/// Cache key for LRU cache.
/// Lightweight u64 hash — does NOT clone the hostname string on construction.
/// Hash collision safety is handled by storing verification data in the cache
/// entry (see `CacheEntry` in compile.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey(u64);

impl CacheKey {
    /// Compute a cache key hash from host info, protocol, and port.
    /// Zero-allocation: does not clone the hostname string.
    pub fn compute(host: &HostInfo, protocol: Protocol, port: u16) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        host.name.hash(&mut hasher);
        host.ipv4.hash(&mut hasher);
        host.ipv6.hash(&mut hasher);
        protocol.hash(&mut hasher);
        port.hash(&mut hasher);
        Self(hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostinfo_typed_ip_fields() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        // HostInfo.ipv4 should be Option<Ipv4Addr>, not Option<IpAddr>
        // HostInfo.ipv6 should be Option<Ipv6Addr>, not Option<IpAddr>
        // This ensures the compiler prevents putting IPv6 into ipv4 or vice versa.
        let v4 = Ipv4Addr::new(192, 168, 1, 1);
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let host = HostInfo::new("example.com", Some(v4), Some(v6));
        assert_eq!(host.ipv4, Some(v4));
        assert_eq!(host.ipv6, Some(v6));
    }

    #[test]
    fn test_hostinfo_from_ip_typed() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        let host = HostInfo::from_ip(v4);
        assert_eq!(host.ipv4, Some(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(host.ipv6.is_none());

        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let host = HostInfo::from_ip(v6);
        assert!(host.ipv4.is_none());
        assert_eq!(
            host.ipv6,
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn test_cache_key_deterministic() {
        let host = HostInfo::from_name("example.com");
        let key1 = CacheKey::compute(&host, Protocol::TCP, 443);
        let key2 = CacheKey::compute(&host, Protocol::TCP, 443);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_key_different_for_different_inputs() {
        let host = HostInfo::from_name("example.com");

        // Different protocol
        let key_tcp = CacheKey::compute(&host, Protocol::TCP, 443);
        let key_udp = CacheKey::compute(&host, Protocol::UDP, 443);
        assert_ne!(key_tcp, key_udp);

        // Different port
        let key_443 = CacheKey::compute(&host, Protocol::TCP, 443);
        let key_80 = CacheKey::compute(&host, Protocol::TCP, 80);
        assert_ne!(key_443, key_80);

        // Different host
        let host2 = HostInfo::from_name("other.com");
        let key_other = CacheKey::compute(&host2, Protocol::TCP, 443);
        assert_ne!(key_tcp, key_other);
    }

    #[test]
    fn test_cache_key_with_ip() {
        let host_no_ip = HostInfo::from_name("example.com");
        let host_with_ip = HostInfo::new(
            "example.com",
            Some("1.2.3.4".parse().unwrap()),
            None,
        );

        let key1 = CacheKey::compute(&host_no_ip, Protocol::TCP, 443);
        let key2 = CacheKey::compute(&host_with_ip, Protocol::TCP, 443);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_is_lightweight_hash() {
        // CacheKey should be a lightweight u64 hash, NOT a full copy of
        // HostInfo fields. This avoids cloning the hostname String on
        // every cache lookup. Hash collision safety is handled by storing
        // verification data in the cache entry (see compile.rs CacheEntry).
        let key_size = std::mem::size_of::<CacheKey>();
        assert_eq!(
            key_size,
            std::mem::size_of::<u64>(),
            "CacheKey should be a u64 hash to avoid String clone on lookup (actual size={})",
            key_size
        );
    }

    #[test]
    fn test_cache_key_is_copy() {
        let host = HostInfo::from_name("example.com");
        let key = CacheKey::compute(&host, Protocol::TCP, 443);
        let key_copy = key; // Copy, not move
        assert_eq!(key, key_copy);
    }
}
