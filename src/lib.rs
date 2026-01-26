//! ACL Engine - A high-performance Access Control List (ACL) engine for Rust
//!
//! This library provides flexible rule-based routing with support for:
//! - IP and CIDR matching
//! - Domain matching (exact, wildcard, suffix)
//! - GeoIP matching (MaxMind MMDB format)
//! - GeoSite matching (domain lists)
//! - Protocol and port filtering
//! - LRU caching for high performance
//!
//! # Example
//!
//! ```rust
//! use std::collections::HashMap;
//! use acl_engine::{parse_rules, compile, Protocol, HostInfo};
//! use acl_engine::geo::NilGeoLoader;
//!
//! let rules_text = "
//! direct(192.168.0.0/16)  # Private networks
//! direct(10.0.0.0/8)
//! proxy(*.google.com)     # Google domains
//! proxy(suffix:youtube.com)
//! reject(all, udp/443)    # Block QUIC
//! proxy(all)              # Default
//! ";
//!
//! // Parse rules
//! let rules = parse_rules(rules_text).unwrap();
//!
//! // Define outbounds
//! let mut outbounds = HashMap::new();
//! outbounds.insert("direct".to_string(), "DIRECT");
//! outbounds.insert("proxy".to_string(), "PROXY");
//! outbounds.insert("reject".to_string(), "REJECT");
//!
//! // Compile rules
//! let compiled = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();
//!
//! // Match traffic
//! let host = HostInfo::from_name("www.google.com");
//! if let Some(result) = compiled.match_host(&host, Protocol::TCP, 443) {
//!     println!("Outbound: {:?}", result.outbound);
//! }
//! ```
//!
//! # Rule Syntax
//!
//! Rules follow the format:
//! ```text
//! outbound(address[, protoPort][, hijackAddress])
//! ```
//!
//! ## Address Types
//!
//! | Type | Example | Description |
//! |------|---------|-------------|
//! | IP | `1.2.3.4` | Single IP address |
//! | CIDR | `192.168.0.0/16` | CIDR range |
//! | Domain | `example.com` | Exact domain match |
//! | Wildcard | `*.example.com` | Wildcard domain match |
//! | Suffix | `suffix:example.com` | Domain and all subdomains |
//! | GeoIP | `geoip:cn` | Country-based IP matching |
//! | GeoSite | `geosite:google` | Domain list matching |
//! | All | `all` or `*` | Match everything |
//!
//! ## Protocol/Port Specification
//!
//! - `tcp/443` - TCP port 443
//! - `udp/53` - UDP port 53
//! - `*/80` - Any protocol, port 80
//! - `tcp/8000-9000` - TCP port range

pub mod compile;
pub mod error;
pub mod geo;
pub mod matcher;
pub mod outbound;
pub mod parser;
pub mod resolver;
pub mod router;
pub mod types;

// Re-export commonly used items
pub use compile::{compile, CompiledRule, CompiledRuleSet};
pub use error::{AclError, Result};
pub use geo::{
    AutoGeoLoader, FileGeoLoader, GeoIpFormat, GeoLoader, GeoSiteFormat, MemoryGeoLoader,
    NilGeoLoader, DEFAULT_UPDATE_INTERVAL,
};
pub use matcher::{
    AllMatcher, CidrMatcher, DomainEntry, DomainMatcher, DomainType, GeoIpMatcher, GeoSiteMatcher,
    HostMatcher, IpMatcher, Matcher,
};
pub use parser::{parse_proto_port, parse_rules};
pub use types::{HostInfo, MatchResult, Protocol, TextRule};

// Re-export outbound types
pub use outbound::{
    Addr, Direct, DirectMode, DirectOptions, Http, Outbound, Reject, ResolveInfo, Socks5, TcpConn,
    UdpConn, DEFAULT_DIALER_TIMEOUT,
};

// Re-export resolver types
pub use resolver::{NilResolver, Resolver, StaticResolver, SystemResolver};

// Re-export router types
pub use router::{OutboundEntry, Router, RouterOptions, DEFAULT_CACHE_SIZE};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_full_workflow() {
        let rules_text = r#"
# Direct connection for private networks
direct(192.168.0.0/16)
direct(10.0.0.0/8)

# Proxy for specific domains
proxy(*.google.com)
proxy(suffix:youtube.com)

# Block QUIC
reject(all, udp/443)

# Default rule
proxy(all)
"#;

        // Parse rules
        let rules = parse_rules(rules_text).unwrap();
        assert_eq!(rules.len(), 6);

        // Define outbounds
        let mut outbounds = HashMap::new();
        outbounds.insert("direct".to_string(), "DIRECT");
        outbounds.insert("proxy".to_string(), "PROXY");
        outbounds.insert("reject".to_string(), "REJECT");

        // Compile rules
        let compiled = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();
        assert_eq!(compiled.rule_count(), 6);

        // Test private IP -> direct
        let host = HostInfo::new("", Some("192.168.1.1".parse().unwrap()), None);
        let result = compiled.match_host(&host, Protocol::TCP, 80);
        assert_eq!(result.unwrap().outbound, "DIRECT");

        // Test Google -> proxy
        let host = HostInfo::from_name("www.google.com");
        let result = compiled.match_host(&host, Protocol::TCP, 443);
        assert_eq!(result.unwrap().outbound, "PROXY");

        // Test YouTube -> proxy (suffix match)
        let host = HostInfo::from_name("www.youtube.com");
        let result = compiled.match_host(&host, Protocol::TCP, 443);
        assert_eq!(result.unwrap().outbound, "PROXY");

        // Test QUIC -> reject
        let host = HostInfo::from_name("example.com");
        let result = compiled.match_host(&host, Protocol::UDP, 443);
        assert_eq!(result.unwrap().outbound, "REJECT");

        // Test unknown -> proxy (fallback)
        let host = HostInfo::from_name("unknown.com");
        let result = compiled.match_host(&host, Protocol::TCP, 80);
        assert_eq!(result.unwrap().outbound, "PROXY");
    }
}
