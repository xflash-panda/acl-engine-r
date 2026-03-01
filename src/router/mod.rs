//! Router module.
//!
//! Routes connections to different outbounds based on ACL rules.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::net::{IpAddr, ToSocketAddrs};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use crate::compile::{compile, CompiledRuleSet};
use crate::error::{AclError, Result};
use crate::geo::GeoLoader;
use crate::outbound::{
    build_resolve_info, try_resolve_from_ip, Addr, Direct, DirectMode, Outbound, Reject,
    ResolveInfo, TcpConn, UdpConn,
};
use crate::parser::parse_rules;
use crate::types::Protocol;

#[cfg(feature = "async")]
use crate::outbound::{AsyncOutbound, AsyncTcpConn, AsyncUdpConn};
#[cfg(feature = "async")]
use async_trait::async_trait;

/// Default LRU cache size
pub const DEFAULT_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

/// Generic router that routes connections to outbounds based on ACL rules.
///
/// Use the type aliases `Router` (sync) and `AsyncRouter` (async) for concrete usage.
///
/// Not `Clone` because it contains a compiled rule set with an LRU cache.
/// Share via `Arc<Router>` or `Arc<AsyncRouter>` instead.
pub struct RouterInner<T: ?Sized> {
    rule_set: CompiledRuleSet<Arc<T>>,
    default_outbound: Arc<T>,
}

impl<T: ?Sized> fmt::Debug for RouterInner<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Router")
            .field("rule_count", &self.rule_set.rule_count())
            .field("needs_ip_matching", &self.rule_set.needs_ip_matching())
            .finish()
    }
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

impl<T: ?Sized> Clone for OutboundEntry<T> {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            outbound: self.outbound.clone(),
        }
    }
}

impl<T: ?Sized> fmt::Debug for OutboundEntry<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundEntry")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
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
#[derive(Debug, Clone)]
pub struct RouterOptions {
    /// LRU cache size for rule matching results
    pub cache_size: NonZeroUsize,
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
    pub fn with_cache_size(mut self, size: NonZeroUsize) -> Self {
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

        let default_outbound = ob_map.get("default").cloned().unwrap_or_else(T::direct);

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
        let rules = fs::read_to_string(path.as_ref()).map_err(|e| AclError::ParseError {
            line: None,
            message: format!("Failed to read rules file: {}", e),
        })?;
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
        let entry =
            AsyncOutboundEntry::new("proxy", Arc::new(Reject::new()) as Arc<dyn AsyncOutbound>);
        assert_eq!(entry.name, "proxy");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geo::NilGeoLoader;

    #[test]
    fn test_entries_to_map_inserts_defaults() {
        let outbounds = vec![OutboundEntry::new(
            "proxy",
            Arc::new(Direct::new()) as Arc<dyn Outbound>,
        )];
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

        let outbounds = vec![OutboundEntry::new(
            "proxy",
            Arc::new(Reject::new()) as Arc<dyn Outbound>,
        )];
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

        let outbounds = vec![OutboundEntry::new(
            "proxy",
            Arc::new(Reject::new()) as Arc<dyn Outbound>,
        )];
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

    // P1-8 verified: DNS error stored in ResolveInfo is by-design (router continues to default outbound)

    #[test]
    fn test_outbound_entry_debug() {
        let entry = OutboundEntry::new("proxy", Arc::new(Direct::new()) as Arc<dyn Outbound>);
        let debug_str = format!("{:?}", entry);
        assert!(
            debug_str.contains("OutboundEntry"),
            "Debug should contain type name, got: {}",
            debug_str
        );
        assert!(
            debug_str.contains("proxy"),
            "Debug should contain outbound name, got: {}",
            debug_str
        );
    }

    #[test]
    fn test_outbound_entry_clone() {
        let entry = OutboundEntry::new("proxy", Arc::new(Direct::new()) as Arc<dyn Outbound>);
        let cloned = entry.clone();
        assert_eq!(cloned.name, "proxy");
        assert!(Arc::ptr_eq(&entry.outbound, &cloned.outbound));
    }

    #[test]
    fn test_router_debug() {
        let rules = "direct(all)";
        let outbounds = vec![];
        let geo_loader = NilGeoLoader;
        let options = RouterOptions::new();
        let router = Router::new(rules, outbounds, &geo_loader, options).unwrap();
        let debug_str = format!("{:?}", router);
        assert!(
            debug_str.contains("Router"),
            "Debug should contain type name, got: {}",
            debug_str
        );
    }

    #[test]
    fn test_router_options_debug_clone() {
        let options = RouterOptions::new();
        let debug_str = format!("{:?}", options);
        assert!(
            debug_str.contains("RouterOptions"),
            "Debug should contain type name, got: {}",
            debug_str
        );

        let cloned = options.clone();
        assert_eq!(cloned.cache_size, DEFAULT_CACHE_SIZE);
    }
}
