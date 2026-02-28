//! Router module.
//!
//! Routes connections to different outbounds based on ACL rules.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;

use crate::compile::{compile, CompiledRuleSet};
use crate::error::{AclError, Result};
use crate::geo::GeoLoader;
use crate::outbound::{
    split_ipv4_ipv6, Addr, Direct, DirectMode, Outbound, Reject, ResolveInfo, TcpConn, UdpConn,
};
use crate::parser::parse_rules;
use crate::types::Protocol;

#[cfg(feature = "async")]
use crate::outbound::{AsyncOutbound, AsyncTcpConn, AsyncUdpConn};
#[cfg(feature = "async")]
use async_trait::async_trait;

/// Default LRU cache size
pub const DEFAULT_CACHE_SIZE: usize = 1024;

/// Generic router that routes connections to outbounds based on ACL rules.
///
/// Use the type aliases `Router` (sync) and `AsyncRouter` (async) for concrete usage.
pub struct RouterInner<T: ?Sized> {
    rule_set: CompiledRuleSet<Arc<T>>,
    default_outbound: Arc<T>,
}

/// Sync router type alias (backward compatible).
pub type Router = RouterInner<dyn Outbound>;

/// Async router type alias (backward compatible).
#[cfg(feature = "async")]
pub type AsyncRouter = RouterInner<dyn AsyncOutbound>;

/// Named outbound entry, generic over the outbound trait.
///
/// The default type parameter is `dyn Outbound`, so `OutboundEntry` without
/// explicit generic is the sync version (backward compatible).
pub struct OutboundEntry<T: ?Sized = dyn Outbound> {
    /// Name of the outbound (used in ACL rules)
    pub name: String,
    /// The outbound implementation
    pub outbound: Arc<T>,
}

impl<T: ?Sized> OutboundEntry<T> {
    /// Create a new outbound entry.
    pub fn new(name: impl Into<String>, outbound: Arc<T>) -> Self {
        Self {
            name: name.into(),
            outbound,
        }
    }
}

/// Router builder options.
pub struct RouterOptions {
    /// LRU cache size for rule matching results
    pub cache_size: usize,
}

impl Default for RouterOptions {
    fn default() -> Self {
        Self {
            cache_size: DEFAULT_CACHE_SIZE,
        }
    }
}

impl RouterOptions {
    /// Create new router options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set cache size.
    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
        self
    }
}

/// Shared implementation for both sync and async routers.
#[allow(private_bounds)]
impl<T: ?Sized + DefaultOutbounds> RouterInner<T> {
    /// Create a new router from ACL rules string.
    pub fn new(
        rules: &str,
        outbounds: Vec<OutboundEntry<T>>,
        geo_loader: &dyn GeoLoader,
        options: RouterOptions,
    ) -> Result<Self> {
        let text_rules = parse_rules(rules)?;
        let ob_map = entries_to_map(outbounds);
        let rule_set = compile(&text_rules, &ob_map, options.cache_size, geo_loader)?;

        let default_outbound = ob_map
            .get("default")
            .cloned()
            .unwrap_or_else(T::direct);

        Ok(Self {
            rule_set,
            default_outbound,
        })
    }

    /// Create a new router from an ACL rules file.
    pub fn from_file(
        path: impl AsRef<Path>,
        outbounds: Vec<OutboundEntry<T>>,
        geo_loader: &dyn GeoLoader,
        options: RouterOptions,
    ) -> Result<Self> {
        let rules = fs::read_to_string(path.as_ref())
            .map_err(|e| AclError::ParseError(format!("Failed to read rules file: {}", e)))?;
        Self::new(&rules, outbounds, geo_loader, options)
    }

    /// Match the address against ACL rules and return the outbound.
    fn match_outbound(&self, addr: &mut Addr, proto: Protocol) -> Arc<T> {
        let host_info = crate::types::HostInfo {
            name: addr.host.to_lowercase(),
            ipv4: addr.resolve_info.as_ref().and_then(|i| i.ipv4),
            ipv6: addr.resolve_info.as_ref().and_then(|i| i.ipv6),
        };

        if let Some(result) = self.rule_set.match_host(&host_info, proto, addr.port) {
            if let Some(hijack_ip) = result.hijack_ip {
                addr.host = hijack_ip.to_string();
                match hijack_ip {
                    IpAddr::V4(v4) => {
                        addr.resolve_info = Some(ResolveInfo::from_ipv4(v4));
                    }
                    IpAddr::V6(v6) => {
                        addr.resolve_info = Some(ResolveInfo::from_ipv6(v6));
                    }
                }
            }
            result.outbound
        } else {
            self.default_outbound.clone()
        }
    }
}

/// Try to resolve the address from an IP literal. Returns true if the host is
/// already an IP address (and sets resolve_info), false if it's a domain name.
fn try_resolve_from_ip(addr: &mut Addr) -> bool {
    if let Ok(ip) = addr.host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                addr.resolve_info = Some(ResolveInfo::from_ipv4(v4));
            }
            IpAddr::V6(v6) => {
                addr.resolve_info = Some(ResolveInfo::from_ipv6(v6));
            }
        }
        true
    } else {
        false
    }
}

/// Build a ResolveInfo from a list of resolved IPs.
/// Sets an error if the list is empty.
fn build_resolve_info(ips: &[IpAddr]) -> ResolveInfo {
    let (ipv4, ipv6) = split_ipv4_ipv6(ips);
    if ipv4.is_none() && ipv6.is_none() {
        ResolveInfo::from_error("no address found")
    } else {
        ResolveInfo {
            ipv4,
            ipv6,
            error: None,
        }
    }
}

impl Router {
    /// Resolve the address using system DNS.
    fn resolve(&self, addr: &mut Addr) {
        if try_resolve_from_ip(addr) {
            return;
        }
        match (addr.host.as_str(), 0u16).to_socket_addrs() {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                addr.resolve_info = Some(build_resolve_info(&ips));
            }
            Err(e) => {
                addr.resolve_info = Some(ResolveInfo::from_error(e.to_string()));
            }
        }
    }
}

impl Outbound for Router {
    fn dial_tcp(&self, addr: &mut Addr) -> Result<Box<dyn TcpConn>> {
        if self.rule_set.needs_ip_matching() {
            self.resolve(addr);
        }
        let outbound = self.match_outbound(addr, Protocol::TCP);
        outbound.dial_tcp(addr)
    }

    fn dial_udp(&self, addr: &mut Addr) -> Result<Box<dyn UdpConn>> {
        if self.rule_set.needs_ip_matching() {
            self.resolve(addr);
        }
        let outbound = self.match_outbound(addr, Protocol::UDP);
        outbound.dial_udp(addr)
    }
}

/// Named async outbound entry (type alias for `OutboundEntry<dyn AsyncOutbound>`).
#[cfg(feature = "async")]
pub type AsyncOutboundEntry = OutboundEntry<dyn AsyncOutbound>;

#[cfg(feature = "async")]
impl AsyncRouter {
    /// Async resolve the address using tokio DNS.
    async fn resolve(&self, addr: &mut Addr) {
        if try_resolve_from_ip(addr) {
            return;
        }
        match tokio::net::lookup_host(format!("{}:0", addr.host)).await {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                addr.resolve_info = Some(build_resolve_info(&ips));
            }
            Err(e) => {
                addr.resolve_info = Some(ResolveInfo::from_error(e.to_string()));
            }
        }
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncOutbound for AsyncRouter {
    async fn dial_tcp(&self, addr: &mut Addr) -> Result<Box<dyn AsyncTcpConn>> {
        if self.rule_set.needs_ip_matching() {
            self.resolve(addr).await;
        }
        let outbound = self.match_outbound(addr, Protocol::TCP);
        outbound.dial_tcp(addr).await
    }

    async fn dial_udp(&self, addr: &mut Addr) -> Result<Box<dyn AsyncUdpConn>> {
        if self.rule_set.needs_ip_matching() {
            self.resolve(addr).await;
        }
        let outbound = self.match_outbound(addr, Protocol::UDP);
        outbound.dial_udp(addr).await
    }
}

/// Trait for creating default outbound entries (Direct and Reject).
trait DefaultOutbounds {
    fn direct() -> Arc<Self>;
    fn reject() -> Arc<Self>;
}

impl DefaultOutbounds for dyn Outbound {
    fn direct() -> Arc<Self> {
        Arc::new(Direct::with_mode(DirectMode::Auto))
    }
    fn reject() -> Arc<Self> {
        Arc::new(Reject::new())
    }
}

#[cfg(feature = "async")]
impl DefaultOutbounds for dyn AsyncOutbound {
    fn direct() -> Arc<Self> {
        Arc::new(Direct::with_mode(DirectMode::Auto))
    }
    fn reject() -> Arc<Self> {
        Arc::new(Reject::new())
    }
}

/// Convert outbound entries to a map with built-in defaults.
fn entries_to_map<T: ?Sized + DefaultOutbounds>(
    outbounds: Vec<OutboundEntry<T>>,
) -> HashMap<String, Arc<T>> {
    let mut map: HashMap<String, Arc<T>> = HashMap::with_capacity(outbounds.len() + 3);

    let first_outbound = outbounds.first().map(|e| e.outbound.clone());

    for entry in outbounds {
        map.insert(entry.name.to_lowercase(), entry.outbound);
    }

    if !map.contains_key("direct") {
        map.insert("direct".to_string(), T::direct());
    }
    if !map.contains_key("reject") {
        map.insert("reject".to_string(), T::reject());
    }

    if !map.contains_key("default") {
        if let Some(first) = first_outbound {
            map.insert("default".to_string(), first);
        } else {
            map.insert("default".to_string(), T::direct());
        }
    }

    map
}

#[cfg(all(test, feature = "async"))]
mod async_tests {
    use super::*;
    use crate::geo::NilGeoLoader;
    use crate::outbound::AsyncOutbound;

    #[tokio::test]
    async fn test_async_router_new() {
        let rules = r#"
            direct(*.google.com)
            reject(10.0.0.0/8)
            direct(all)
        "#;

        let outbounds = vec![];
        let geo_loader = NilGeoLoader;
        let options = RouterOptions::new();

        let router = AsyncRouter::new(rules, outbounds, &geo_loader, options);
        assert!(router.is_ok());
    }

    #[tokio::test]
    async fn test_async_router_routes_tcp() {
        // AsyncRouter should implement AsyncOutbound and route correctly
        let rules = r#"
            reject(*.blocked.com)
            direct(all)
        "#;

        let outbounds: Vec<AsyncOutboundEntry> = vec![];
        let geo_loader = NilGeoLoader;
        let options = RouterOptions::new();

        let router = AsyncRouter::new(rules, outbounds, &geo_loader, options).unwrap();

        // dial_tcp to a blocked domain should return reject error
        let mut addr = crate::outbound::Addr::new("test.blocked.com", 443);
        let result = AsyncOutbound::dial_tcp(&router, &mut addr).await;
        assert!(result.is_err(), "blocked domain should be rejected");
        match result {
            Err(e) => assert!(
                e.to_string().contains("rejected"),
                "error should indicate rejection, got: {}",
                e
            ),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[tokio::test]
    async fn test_async_router_routes_udp() {
        let rules = r#"
            reject(*.blocked.com)
            direct(all)
        "#;

        let outbounds: Vec<AsyncOutboundEntry> = vec![];
        let geo_loader = NilGeoLoader;
        let options = RouterOptions::new();

        let router = AsyncRouter::new(rules, outbounds, &geo_loader, options).unwrap();

        let mut addr = crate::outbound::Addr::new("test.blocked.com", 53);
        let result = AsyncOutbound::dial_udp(&router, &mut addr).await;
        assert!(result.is_err(), "blocked domain should be rejected");
    }

    #[tokio::test]
    async fn test_async_router_skips_dns_for_domain_only_rules() {
        let rules = r#"
            reject(*.blocked.com)
            direct(all)
        "#;

        let outbounds: Vec<AsyncOutboundEntry> = vec![];
        let geo_loader = NilGeoLoader;
        let options = RouterOptions::new();

        let router = AsyncRouter::new(rules, outbounds, &geo_loader, options).unwrap();

        assert!(
            !router.rule_set.needs_ip_matching(),
            "Domain-only rules should not require IP matching"
        );
    }

    #[tokio::test]
    async fn test_async_router_outbound_entry() {
        // AsyncOutboundEntry should work like OutboundEntry but with AsyncOutbound
        let entry = AsyncOutboundEntry::new("proxy", Arc::new(Reject::new()) as Arc<dyn AsyncOutbound>);
        assert_eq!(entry.name, "proxy");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geo::NilGeoLoader;

    #[test]
    fn test_entries_to_map_inserts_defaults() {
        let outbounds = vec![OutboundEntry::new("proxy", Arc::new(Direct::new()) as Arc<dyn Outbound>)];
        let map = entries_to_map(outbounds);
        assert!(map.contains_key("proxy"));
        assert!(map.contains_key("direct"));
        assert!(map.contains_key("reject"));
        assert!(map.contains_key("default"));
    }

    #[test]
    fn test_entries_to_map_empty_outbounds_no_panic() {
        // Empty outbounds should safely produce defaults without panicking.
        // "default" should fall back to "direct" via T::direct(), not via map lookup.
        let outbounds: Vec<OutboundEntry<dyn Outbound>> = vec![];
        let map = entries_to_map(outbounds);
        assert!(map.contains_key("direct"));
        assert!(map.contains_key("reject"));
        assert!(map.contains_key("default"));
    }

    #[test]
    fn test_entries_to_map_preserves_custom() {
        let custom_direct = Arc::new(Reject::new()) as Arc<dyn Outbound>;
        let outbounds = vec![
            OutboundEntry::new("direct", custom_direct),
            OutboundEntry::new("proxy", Arc::new(Direct::new()) as Arc<dyn Outbound>),
        ];
        let map = entries_to_map(outbounds);
        // "direct" should NOT be overwritten by the default
        assert!(map.contains_key("direct"));
        assert!(map.contains_key("proxy"));
        assert!(map.contains_key("reject"));
        // "default" should be the first entry ("direct")
        assert!(map.contains_key("default"));
    }

    #[test]
    fn test_router_skips_dns_for_domain_only_rules() {
        // When rules only use domain matchers (no IP/CIDR/GeoIP),
        // Router should NOT resolve DNS — the outbound (e.g., proxy)
        // will handle resolution itself.
        let rules = r#"
            proxy(*.google.com)
            proxy(suffix:youtube.com)
            direct(all)
        "#;

        let outbounds = vec![OutboundEntry::new("proxy", Arc::new(Reject::new()) as Arc<dyn Outbound>)];
        let geo_loader = NilGeoLoader;
        let options = RouterOptions::new();

        let router = Router::new(rules, outbounds, &geo_loader, options).unwrap();

        assert!(
            !router.rule_set.needs_ip_matching(),
            "Domain-only rules should not require IP matching"
        );
    }

    #[test]
    fn test_router_needs_dns_for_ip_rules() {
        // When rules include IP/CIDR matchers, needs_ip_matching() should be true
        let rules = r#"
            direct(192.168.0.0/16)
            proxy(all)
        "#;

        let outbounds = vec![OutboundEntry::new("proxy", Arc::new(Reject::new()) as Arc<dyn Outbound>)];
        let geo_loader = NilGeoLoader;
        let options = RouterOptions::new();

        let router = Router::new(rules, outbounds, &geo_loader, options).unwrap();

        assert!(
            router.rule_set.needs_ip_matching(),
            "Rules with CIDR matcher should require IP matching"
        );
    }

    #[test]
    fn test_router_new() {
        let rules = r#"
            direct(192.168.0.0/16)
            reject(10.0.0.0/8)
            direct(all)
        "#;

        let outbounds = vec![];
        let geo_loader = NilGeoLoader;
        let options = RouterOptions::new();

        let router = Router::new(rules, outbounds, &geo_loader, options);
        assert!(router.is_ok());
    }

    #[test]
    fn test_try_resolve_from_ip_v4() {
        let mut addr = Addr::new("1.2.3.4", 80);
        assert!(try_resolve_from_ip(&mut addr));
        let info = addr.resolve_info.unwrap();
        assert_eq!(info.ipv4, Some("1.2.3.4".parse().unwrap()));
        assert!(info.ipv6.is_none());
        assert!(info.error.is_none());
    }

    #[test]
    fn test_try_resolve_from_ip_v6() {
        let mut addr = Addr::new("::1", 80);
        assert!(try_resolve_from_ip(&mut addr));
        let info = addr.resolve_info.unwrap();
        assert!(info.ipv4.is_none());
        assert_eq!(info.ipv6, Some("::1".parse().unwrap()));
        assert!(info.error.is_none());
    }

    #[test]
    fn test_try_resolve_from_ip_domain() {
        let mut addr = Addr::new("example.com", 80);
        assert!(!try_resolve_from_ip(&mut addr));
        assert!(addr.resolve_info.is_none());
    }

    #[test]
    fn test_build_resolve_info_both() {
        let ips = vec![
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            "::1".parse::<IpAddr>().unwrap(),
        ];
        let info = build_resolve_info(&ips);
        assert_eq!(info.ipv4, Some("1.2.3.4".parse().unwrap()));
        assert_eq!(info.ipv6, Some("::1".parse().unwrap()));
        assert!(info.error.is_none());
    }

    #[test]
    fn test_build_resolve_info_empty() {
        let ips: Vec<IpAddr> = vec![];
        let info = build_resolve_info(&ips);
        assert!(info.ipv4.is_none());
        assert!(info.ipv6.is_none());
        assert!(info.error.is_some());
    }
}
