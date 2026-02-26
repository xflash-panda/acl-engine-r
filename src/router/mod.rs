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

/// Default LRU cache size
pub const DEFAULT_CACHE_SIZE: usize = 1024;

/// Router routes connections to different outbounds based on ACL rules.
///
/// It implements the Outbound interface, allowing it to be used as an outbound itself.
/// DNS resolution uses the system resolver.
pub struct Router {
    rule_set: CompiledRuleSet<Arc<dyn Outbound>>,
    default_outbound: Arc<dyn Outbound>,
}

/// Named outbound entry.
pub struct OutboundEntry {
    /// Name of the outbound (used in ACL rules)
    pub name: String,
    /// The outbound implementation
    pub outbound: Arc<dyn Outbound>,
}

impl OutboundEntry {
    /// Create a new outbound entry.
    pub fn new(name: impl Into<String>, outbound: Arc<dyn Outbound>) -> Self {
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

impl Router {
    /// Create a new router from ACL rules string.
    pub fn new(
        rules: &str,
        outbounds: Vec<OutboundEntry>,
        geo_loader: &dyn GeoLoader,
        options: RouterOptions,
    ) -> Result<Self> {
        let text_rules = parse_rules(rules)?;
        let ob_map = outbounds_to_map(outbounds);
        let rule_set = compile(&text_rules, &ob_map, options.cache_size, geo_loader)?;

        let default_outbound = ob_map
            .get("default")
            .cloned()
            .unwrap_or_else(|| Arc::new(Direct::new()) as Arc<dyn Outbound>);

        Ok(Self {
            rule_set,
            default_outbound,
        })
    }

    /// Create a new router from an ACL rules file.
    pub fn from_file(
        path: impl AsRef<Path>,
        outbounds: Vec<OutboundEntry>,
        geo_loader: &dyn GeoLoader,
        options: RouterOptions,
    ) -> Result<Self> {
        let rules = fs::read_to_string(path.as_ref())
            .map_err(|e| AclError::ParseError(format!("Failed to read rules file: {}", e)))?;
        Self::new(&rules, outbounds, geo_loader, options)
    }

    /// Resolve the address using system DNS.
    fn resolve(&self, addr: &mut Addr) {
        // Check if host is already an IP address
        if let Ok(ip) = addr.host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    addr.resolve_info = Some(ResolveInfo::from_ipv4(v4));
                }
                IpAddr::V6(v6) => {
                    addr.resolve_info = Some(ResolveInfo::from_ipv6(v6));
                }
            }
            return;
        }

        // Resolve using system DNS
        match (addr.host.as_str(), 0u16).to_socket_addrs() {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                let (ipv4, ipv6) = split_ipv4_ipv6(&ips);
                if ipv4.is_none() && ipv6.is_none() {
                    addr.resolve_info = Some(ResolveInfo::from_error("no address found"));
                } else {
                    addr.resolve_info = Some(ResolveInfo {
                        ipv4,
                        ipv6,
                        error: None,
                    });
                }
            }
            Err(e) => {
                addr.resolve_info = Some(ResolveInfo::from_error(e.to_string()));
            }
        }
    }

    /// Match the address against ACL rules and return the outbound.
    fn match_outbound(&self, addr: &mut Addr, proto: Protocol) -> Arc<dyn Outbound> {
        let host_info = crate::types::HostInfo {
            name: addr.host.clone(),
            ipv4: addr
                .resolve_info
                .as_ref()
                .and_then(|i| i.ipv4.map(IpAddr::V4)),
            ipv6: addr
                .resolve_info
                .as_ref()
                .and_then(|i| i.ipv6.map(IpAddr::V6)),
        };

        if let Some(result) = self.rule_set.match_host(&host_info, proto, addr.port) {
            // Handle hijack IP
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

impl Outbound for Router {
    fn dial_tcp(&self, addr: &mut Addr) -> Result<Box<dyn TcpConn>> {
        self.resolve(addr);
        let outbound = self.match_outbound(addr, Protocol::TCP);
        outbound.dial_tcp(addr)
    }

    fn dial_udp(&self, addr: &mut Addr) -> Result<Box<dyn UdpConn>> {
        self.resolve(addr);
        let outbound = self.match_outbound(addr, Protocol::UDP);
        outbound.dial_udp(addr)
    }
}

/// Convert outbound entries to a map.
fn outbounds_to_map(outbounds: Vec<OutboundEntry>) -> HashMap<String, Arc<dyn Outbound>> {
    let mut map: HashMap<String, Arc<dyn Outbound>> = HashMap::new();

    for entry in &outbounds {
        map.insert(entry.name.to_lowercase(), entry.outbound.clone());
    }

    // Add built-in outbounds if not overridden
    if !map.contains_key("direct") {
        map.insert(
            "direct".to_string(),
            Arc::new(Direct::with_mode(DirectMode::Auto)),
        );
    }
    if !map.contains_key("reject") {
        map.insert("reject".to_string(), Arc::new(Reject::new()));
    }

    // Set default outbound
    if !map.contains_key("default") {
        if !outbounds.is_empty() {
            map.insert("default".to_string(), outbounds[0].outbound.clone());
        } else {
            map.insert("default".to_string(), map.get("direct").unwrap().clone());
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geo::NilGeoLoader;

    #[test]
    fn test_outbounds_to_map() {
        let outbounds = vec![OutboundEntry::new("proxy", Arc::new(Direct::new()))];

        let map = outbounds_to_map(outbounds);

        assert!(map.contains_key("proxy"));
        assert!(map.contains_key("direct"));
        assert!(map.contains_key("reject"));
        assert!(map.contains_key("default"));
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
}
