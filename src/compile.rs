use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroUsize;

use parking_lot::Mutex;

use ipnet::IpNet;
use lru::LruCache;

use crate::error::{AclError, Result};
use crate::geo::GeoLoader;
use crate::matcher::{AllMatcher, CidrMatcher, DomainMatcher, HostMatcher, IpMatcher, Matcher};
use crate::parser::parse_proto_port;
use crate::types::{CacheKey, HostInfo, MatchResult, Protocol, TextRule};

/// Cache value type: outbound and optional hijacked IP
type CacheValue<O> = Option<(O, Option<IpAddr>)>;

/// A compiled rule ready for matching
pub struct CompiledRule<O> {
    /// The outbound for this rule
    pub outbound: O,
    /// Host matcher
    pub matcher: Matcher,
    /// Protocol to match
    pub protocol: Protocol,
    /// Start port (inclusive)
    pub start_port: u16,
    /// End port (inclusive)
    pub end_port: u16,
    /// Hijack IP address
    pub hijack_ip: Option<IpAddr>,
}

impl<O> CompiledRule<O> {
    /// Check if this rule matches the given host, protocol, and port
    pub fn matches(&self, host: &HostInfo, proto: Protocol, port: u16) -> bool {
        // Check protocol
        if !self.protocol.matches(proto) {
            return false;
        }

        // Check port
        if port < self.start_port || port > self.end_port {
            return false;
        }

        // Check host
        self.matcher.matches(host)
    }
}

/// Compiled rule set with LRU caching
pub struct CompiledRuleSet<O: Clone> {
    rules: Vec<CompiledRule<O>>,
    cache: Mutex<LruCache<CacheKey, CacheValue<O>>>,
}

impl<O: Clone> CompiledRuleSet<O> {
    /// Create a new compiled rule set
    pub fn new(rules: Vec<CompiledRule<O>>, cache_size: usize) -> Self {
        let cache_size = NonZeroUsize::new(cache_size).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            rules,
            cache: Mutex::new(LruCache::new(cache_size)),
        }
    }

    /// Match a host against the rule set
    pub fn match_host(
        &self,
        host: &HostInfo,
        proto: Protocol,
        port: u16,
    ) -> Option<MatchResult<O>> {
        // Ensure hostname is lowercase for matching.
        // HostInfo constructors guarantee lowercase, but direct struct construction
        // (e.g., in Router::match_outbound) may not. Normalize defensively, only
        // allocating when uppercase bytes are detected.
        let normalized;
        let host = if host.name.as_bytes().iter().any(|b| b.is_ascii_uppercase()) {
            normalized = HostInfo {
                name: host.name.to_lowercase(),
                ipv4: host.ipv4,
                ipv6: host.ipv6,
            };
            &normalized
        } else {
            host
        };

        let key = CacheKey::from_host(host, proto, port);

        let mut cache = self.cache.lock();

        // Check cache first
        if let Some(cached) = cache.get(&key) {
            return cached.clone().map(|(outbound, hijack_ip)| MatchResult {
                outbound,
                hijack_ip,
            });
        }

        // Cache miss — compute result while holding the lock.
        // This prevents cache stampede (multiple threads computing the same key).
        // The matching itself is CPU-only (no I/O), so holding the lock is acceptable.
        let result = self.find_match(host, proto, port);

        cache.put(
            key,
            result.as_ref().map(|r| (r.outbound.clone(), r.hijack_ip)),
        );

        result
    }

    /// Find a matching rule without caching
    fn find_match(&self, host: &HostInfo, proto: Protocol, port: u16) -> Option<MatchResult<O>> {
        for rule in &self.rules {
            if rule.matches(host, proto, port) {
                return Some(MatchResult {
                    outbound: rule.outbound.clone(),
                    hijack_ip: rule.hijack_ip,
                });
            }
        }
        None
    }

    /// Get the number of rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Clear the cache
    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock();
        cache.clear();
    }
}

/// Compile text rules into a CompiledRuleSet
pub fn compile<O: Clone>(
    rules: &[TextRule],
    outbounds: &HashMap<String, O>,
    cache_size: usize,
    geo_loader: &dyn GeoLoader,
) -> Result<CompiledRuleSet<O>> {
    let mut compiled_rules = Vec::with_capacity(rules.len());

    for rule in rules {
        let compiled = compile_rule(rule, outbounds, geo_loader)?;
        compiled_rules.push(compiled);
    }

    Ok(CompiledRuleSet::new(compiled_rules, cache_size))
}

/// Compile a single rule
fn compile_rule<O: Clone>(
    rule: &TextRule,
    outbounds: &HashMap<String, O>,
    geo_loader: &dyn GeoLoader,
) -> Result<CompiledRule<O>> {
    // Resolve outbound (case-insensitive: Router lowercases map keys)
    let outbound_key = rule.outbound.to_lowercase();
    let outbound = outbounds
        .get(&outbound_key)
        .cloned()
        .ok_or_else(|| AclError::UnknownOutbound(rule.outbound.clone()))?;

    // Compile host matcher
    let matcher = compile_matcher(&rule.address, geo_loader)?;

    // Parse protocol/port
    let (protocol, start_port, end_port) = if let Some(ref pp) = rule.proto_port {
        parse_proto_port(pp)?
    } else {
        (Protocol::Both, 0, u16::MAX)
    };

    // Parse hijack address
    let hijack_ip = if let Some(ref addr) = rule.hijack_address {
        Some(
            addr.parse::<IpAddr>()
                .map_err(|_| AclError::InvalidIp(addr.clone()))?,
        )
    } else {
        None
    };

    Ok(CompiledRule {
        outbound,
        matcher,
        protocol,
        start_port,
        end_port,
        hijack_ip,
    })
}

/// Compile a host matcher from an address string
fn compile_matcher(address: &str, geo_loader: &dyn GeoLoader) -> Result<Matcher> {
    let address = address.trim().to_lowercase();

    // Check for special patterns
    if address == "all" || address == "*" {
        return Ok(Matcher::All(AllMatcher));
    }

    // Check for GeoIP pattern
    if let Some(country_code) = address.strip_prefix("geoip:") {
        let matcher = geo_loader.load_geoip(country_code)?;
        return Ok(Matcher::GeoIp(matcher));
    }

    // Check for GeoSite pattern
    if let Some(site_name) = address.strip_prefix("geosite:") {
        let matcher = geo_loader.load_geosite(site_name)?;
        return Ok(Matcher::GeoSite(matcher));
    }

    // Try to parse as IP address
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Ok(Matcher::Ip(IpMatcher::new(ip)));
    }

    // Try to parse as CIDR
    if let Ok(cidr) = address.parse::<IpNet>() {
        return Ok(Matcher::Cidr(CidrMatcher::new(cidr)));
    }

    // Treat as domain pattern
    Ok(Matcher::Domain(DomainMatcher::new(&address)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geo::NilGeoLoader;
    use crate::parser::parse_rules;

    #[test]
    fn test_compile_simple_rules() {
        let text = r#"
direct(192.168.0.0/16)
proxy(*.google.com)
proxy(all)
"#;
        let rules = parse_rules(text).unwrap();

        let mut outbounds = HashMap::new();
        outbounds.insert("direct".to_string(), "DIRECT");
        outbounds.insert("proxy".to_string(), "PROXY");

        let compiled = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();
        assert_eq!(compiled.rule_count(), 3);
    }

    #[test]
    fn test_match_ip() {
        let text = "direct(192.168.0.0/16)\nproxy(all)";
        let rules = parse_rules(text).unwrap();

        let mut outbounds = HashMap::new();
        outbounds.insert("direct".to_string(), "DIRECT");
        outbounds.insert("proxy".to_string(), "PROXY");

        let compiled = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();

        // Match private IP
        let host = HostInfo::new("", Some("192.168.1.1".parse().unwrap()), None);
        let result = compiled.match_host(&host, Protocol::TCP, 80);
        assert!(result.is_some());
        assert_eq!(result.unwrap().outbound, "DIRECT");

        // Match public IP (falls through to all)
        let host = HostInfo::new("", Some("8.8.8.8".parse().unwrap()), None);
        let result = compiled.match_host(&host, Protocol::TCP, 80);
        assert!(result.is_some());
        assert_eq!(result.unwrap().outbound, "PROXY");
    }

    #[test]
    fn test_match_domain() {
        let text = r#"
direct(example.com)
proxy(*.google.com)
proxy(suffix:youtube.com)
block(all)
"#;
        let rules = parse_rules(text).unwrap();

        let mut outbounds = HashMap::new();
        outbounds.insert("direct".to_string(), "DIRECT");
        outbounds.insert("proxy".to_string(), "PROXY");
        outbounds.insert("block".to_string(), "BLOCK");

        let compiled = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();

        // Exact match
        let host = HostInfo::from_name("example.com");
        let result = compiled.match_host(&host, Protocol::TCP, 443);
        assert_eq!(result.unwrap().outbound, "DIRECT");

        // Wildcard match
        let host = HostInfo::from_name("www.google.com");
        let result = compiled.match_host(&host, Protocol::TCP, 443);
        assert_eq!(result.unwrap().outbound, "PROXY");

        // Suffix match
        let host = HostInfo::from_name("www.youtube.com");
        let result = compiled.match_host(&host, Protocol::TCP, 443);
        assert_eq!(result.unwrap().outbound, "PROXY");

        // Suffix match (exact)
        let host = HostInfo::from_name("youtube.com");
        let result = compiled.match_host(&host, Protocol::TCP, 443);
        assert_eq!(result.unwrap().outbound, "PROXY");

        // Fall through
        let host = HostInfo::from_name("unknown.com");
        let result = compiled.match_host(&host, Protocol::TCP, 443);
        assert_eq!(result.unwrap().outbound, "BLOCK");
    }

    #[test]
    fn test_match_port() {
        let text = r#"
block(all, udp/443)
direct(all, tcp/80-90)
proxy(all)
"#;
        let rules = parse_rules(text).unwrap();

        let mut outbounds = HashMap::new();
        outbounds.insert("block".to_string(), "BLOCK");
        outbounds.insert("direct".to_string(), "DIRECT");
        outbounds.insert("proxy".to_string(), "PROXY");

        let compiled = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();

        // Block UDP 443
        let host = HostInfo::from_name("example.com");
        let result = compiled.match_host(&host, Protocol::UDP, 443);
        assert_eq!(result.unwrap().outbound, "BLOCK");

        // TCP 443 goes to proxy
        let result = compiled.match_host(&host, Protocol::TCP, 443);
        assert_eq!(result.unwrap().outbound, "PROXY");

        // TCP 80-90 goes to direct
        let result = compiled.match_host(&host, Protocol::TCP, 85);
        assert_eq!(result.unwrap().outbound, "DIRECT");
    }

    #[test]
    fn test_hijack() {
        let text = "direct(all, udp/53, 127.0.0.1)";
        let rules = parse_rules(text).unwrap();

        let mut outbounds = HashMap::new();
        outbounds.insert("direct".to_string(), "DIRECT");

        let compiled = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();

        let host = HostInfo::from_name("dns.google");
        let result = compiled.match_host(&host, Protocol::UDP, 53);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.outbound, "DIRECT");
        assert_eq!(result.hijack_ip, Some("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_cache() {
        let text = "proxy(all)";
        let rules = parse_rules(text).unwrap();

        let mut outbounds = HashMap::new();
        outbounds.insert("proxy".to_string(), "PROXY");

        let compiled = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();

        // First call - populates cache
        let host = HostInfo::from_name("example.com");
        let result1 = compiled.match_host(&host, Protocol::TCP, 443);
        assert!(result1.is_some());

        // Second call - should hit cache
        let result2 = compiled.match_host(&host, Protocol::TCP, 443);
        assert!(result2.is_some());

        // Both results should be the same
        assert_eq!(result1.unwrap().outbound, result2.unwrap().outbound);
    }

    #[test]
    fn test_cache_none_result() {
        let text = "proxy(example.com)";
        let rules = parse_rules(text).unwrap();

        let mut outbounds = HashMap::new();
        outbounds.insert("proxy".to_string(), "PROXY");

        let compiled = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();

        let host = HostInfo::from_name("unknown.com");
        let result1 = compiled.match_host(&host, Protocol::TCP, 443);
        assert!(result1.is_none());

        let result2 = compiled.match_host(&host, Protocol::TCP, 443);
        assert!(result2.is_none());
    }

    #[test]
    fn test_cache_different_keys() {
        let text = "proxy(example.com)\ndirect(all)";
        let rules = parse_rules(text).unwrap();

        let mut outbounds = HashMap::new();
        outbounds.insert("proxy".to_string(), "PROXY");
        outbounds.insert("direct".to_string(), "DIRECT");

        let compiled = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();

        let host1 = HostInfo::from_name("example.com");
        let r1 = compiled.match_host(&host1, Protocol::TCP, 443);
        assert_eq!(r1.unwrap().outbound, "PROXY");

        let host2 = HostInfo::from_name("other.com");
        let r2 = compiled.match_host(&host2, Protocol::TCP, 443);
        assert_eq!(r2.unwrap().outbound, "DIRECT");

        let r3 = compiled.match_host(&host1, Protocol::UDP, 443);
        assert_eq!(r3.unwrap().outbound, "PROXY");

        let r4 = compiled.match_host(&host1, Protocol::TCP, 80);
        assert_eq!(r4.unwrap().outbound, "PROXY");
    }

    #[test]
    fn test_match_domain_mixed_case_direct_construction() {
        // Bug: Router constructs HostInfo directly without lowercasing.
        // Domain matching must work even when HostInfo.name is mixed-case.
        let text = "proxy(*.google.com)\nblock(all)";
        let rules = parse_rules(text).unwrap();

        let mut outbounds = HashMap::new();
        outbounds.insert("proxy".to_string(), "PROXY");
        outbounds.insert("block".to_string(), "BLOCK");

        let compiled = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();

        // Direct construction with mixed-case (simulates Router's match_outbound)
        let host = HostInfo {
            name: "WWW.GOOGLE.COM".to_string(),
            ipv4: None,
            ipv6: None,
        };
        let result = compiled.match_host(&host, Protocol::TCP, 443);
        assert_eq!(
            result.unwrap().outbound, "PROXY",
            "Mixed-case hostname should match domain rules"
        );
    }

    #[test]
    fn test_match_suffix_mixed_case_direct_construction() {
        let text = "proxy(suffix:youtube.com)\nblock(all)";
        let rules = parse_rules(text).unwrap();

        let mut outbounds = HashMap::new();
        outbounds.insert("proxy".to_string(), "PROXY");
        outbounds.insert("block".to_string(), "BLOCK");

        let compiled = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();

        let host = HostInfo {
            name: "WWW.YouTube.COM".to_string(),
            ipv4: None,
            ipv6: None,
        };
        let result = compiled.match_host(&host, Protocol::TCP, 443);
        assert_eq!(
            result.unwrap().outbound, "PROXY",
            "Mixed-case hostname should match suffix rules"
        );
    }

    #[test]
    fn test_cache_clear() {
        let text = "proxy(all)";
        let rules = parse_rules(text).unwrap();

        let mut outbounds = HashMap::new();
        outbounds.insert("proxy".to_string(), "PROXY");

        let compiled = compile(&rules, &outbounds, 2, &NilGeoLoader).unwrap();

        let host = HostInfo::from_name("a.com");
        compiled.match_host(&host, Protocol::TCP, 80);

        compiled.clear_cache();

        let result = compiled.match_host(&host, Protocol::TCP, 80);
        assert_eq!(result.unwrap().outbound, "PROXY");
    }
}
