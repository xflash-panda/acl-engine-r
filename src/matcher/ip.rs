use std::net::IpAddr;

use ipnet::IpNet;

use super::HostMatcher;
use crate::types::HostInfo;

/// IP address matcher - matches exact IP addresses
#[derive(Debug, Clone)]
pub struct IpMatcher {
    ip: IpAddr,
}

impl IpMatcher {
    pub fn new(ip: IpAddr) -> Self {
        Self { ip }
    }
}

impl HostMatcher for IpMatcher {
    fn matches(&self, host: &HostInfo) -> bool {
        match self.ip {
            IpAddr::V4(_) => host.ipv4 == Some(self.ip),
            IpAddr::V6(_) => host.ipv6 == Some(self.ip),
        }
    }
}

/// CIDR matcher - matches IP addresses within a CIDR range
#[derive(Debug, Clone)]
pub struct CidrMatcher {
    network: IpNet,
}

impl CidrMatcher {
    pub fn new(network: IpNet) -> Self {
        Self { network }
    }
}

impl HostMatcher for CidrMatcher {
    fn matches(&self, host: &HostInfo) -> bool {
        match self.network {
            IpNet::V4(_) => host.ipv4.is_some_and(|ip| self.network.contains(&ip)),
            IpNet::V6(_) => host.ipv6.is_some_and(|ip| self.network.contains(&ip)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn test_ip_matcher() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let matcher = IpMatcher::new(ip);

        let host = HostInfo::new("", Some(ip), None);
        assert!(matcher.matches(&host));

        let other_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let host2 = HostInfo::new("", Some(other_ip), None);
        assert!(!matcher.matches(&host2));
    }

    #[test]
    fn test_cidr_matcher() {
        let network: IpNet = "192.168.0.0/16".parse().unwrap();
        let matcher = CidrMatcher::new(network);

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let host1 = HostInfo::new("", Some(ip1), None);
        assert!(matcher.matches(&host1));

        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255));
        let host2 = HostInfo::new("", Some(ip2), None);
        assert!(matcher.matches(&host2));

        let ip3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let host3 = HostInfo::new("", Some(ip3), None);
        assert!(!matcher.matches(&host3));
    }

    #[test]
    fn test_ipv6_cidr_matcher() {
        let network: IpNet = "2001:db8::/32".parse().unwrap();
        let matcher = CidrMatcher::new(network);

        let ip1 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let host1 = HostInfo::new("", None, Some(ip1));
        assert!(matcher.matches(&host1));

        let ip2 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1));
        let host2 = HostInfo::new("", None, Some(ip2));
        assert!(!matcher.matches(&host2));
    }
}
