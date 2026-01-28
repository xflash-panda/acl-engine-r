pub mod domain;
mod domain_simple;
mod geoip;
mod geosite;
mod ip;

pub use domain::SuccinctMatcher;
pub use domain_simple::DomainMatcher;
pub use geoip::GeoIpMatcher;
pub use geosite::{DomainEntry, DomainType, GeoSiteMatcher};
pub use ip::{CidrMatcher, IpMatcher};

use crate::types::HostInfo;

/// Trait for host matchers
pub trait HostMatcher: Send + Sync {
    /// Check if the host matches this matcher
    fn matches(&self, host: &HostInfo) -> bool;
}

/// All matcher - matches everything
#[derive(Debug, Clone)]
pub struct AllMatcher;

impl HostMatcher for AllMatcher {
    fn matches(&self, _host: &HostInfo) -> bool {
        true
    }
}

/// Enum wrapper for all matcher types
#[derive(Debug)]
pub enum Matcher {
    All(AllMatcher),
    Ip(IpMatcher),
    Cidr(CidrMatcher),
    Domain(DomainMatcher),
    GeoIp(GeoIpMatcher),
    GeoSite(GeoSiteMatcher),
}

impl HostMatcher for Matcher {
    fn matches(&self, host: &HostInfo) -> bool {
        match self {
            Matcher::All(m) => m.matches(host),
            Matcher::Ip(m) => m.matches(host),
            Matcher::Cidr(m) => m.matches(host),
            Matcher::Domain(m) => m.matches(host),
            Matcher::GeoIp(m) => m.matches(host),
            Matcher::GeoSite(m) => m.matches(host),
        }
    }
}
