use std::net::IpAddr;

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
    pub ipv4: Option<IpAddr>,
    /// Resolved IPv6 address
    pub ipv6: Option<IpAddr>,
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
    pub fn new(name: impl Into<String>, ipv4: Option<IpAddr>, ipv6: Option<IpAddr>) -> Self {
        Self {
            name: name.into().to_lowercase(),
            ipv4,
            ipv6,
        }
    }

    /// Create a HostInfo from an IP address
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self {
                name: String::new(),
                ipv4: Some(ip),
                ipv6: None,
            },
            IpAddr::V6(_) => Self {
                name: String::new(),
                ipv4: None,
                ipv6: Some(ip),
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
/// Uses a pre-computed u64 hash to avoid cloning the host name string on every lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey(pub u64);

impl CacheKey {
    /// Compute cache key hash from host info without allocating.
    pub fn from_host(host: &HostInfo, protocol: Protocol, port: u16) -> Self {
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
    fn test_cache_key_deterministic() {
        let host = HostInfo::from_name("example.com");
        let key1 = CacheKey::from_host(&host, Protocol::TCP, 443);
        let key2 = CacheKey::from_host(&host, Protocol::TCP, 443);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_key_different_for_different_inputs() {
        let host = HostInfo::from_name("example.com");

        // Different protocol
        let key_tcp = CacheKey::from_host(&host, Protocol::TCP, 443);
        let key_udp = CacheKey::from_host(&host, Protocol::UDP, 443);
        assert_ne!(key_tcp, key_udp);

        // Different port
        let key_443 = CacheKey::from_host(&host, Protocol::TCP, 443);
        let key_80 = CacheKey::from_host(&host, Protocol::TCP, 80);
        assert_ne!(key_443, key_80);

        // Different host
        let host2 = HostInfo::from_name("other.com");
        let key_other = CacheKey::from_host(&host2, Protocol::TCP, 443);
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

        let key1 = CacheKey::from_host(&host_no_ip, Protocol::TCP, 443);
        let key2 = CacheKey::from_host(&host_with_ip, Protocol::TCP, 443);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_is_copy() {
        // Verify CacheKey is Copy (no heap allocation)
        let host = HostInfo::from_name("example.com");
        let key = CacheKey::from_host(&host, Protocol::TCP, 443);
        let key_copy = key; // Copy, not move
        assert_eq!(key, key_copy);
    }
}
