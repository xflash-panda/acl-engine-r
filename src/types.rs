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

/// Cache key for LRU cache
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey {
    pub name: String,
    pub ipv4: Option<IpAddr>,
    pub ipv6: Option<IpAddr>,
    pub protocol: Protocol,
    pub port: u16,
}

impl CacheKey {
    pub fn from_host(host: &HostInfo, protocol: Protocol, port: u16) -> Self {
        Self {
            name: host.name.clone(), // already lowercased in HostInfo constructors
            ipv4: host.ipv4,
            ipv6: host.ipv6,
            protocol,
            port,
        }
    }
}
