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
            IpAddr::V4(v4) => host.ipv4 == Some(v4),
            IpAddr::V6(v6) => host.ipv6 == Some(v6),
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
            IpNet::V4(_) => host
                .ipv4
                .is_some_and(|ip| self.network.contains(&IpAddr::V4(ip))),
            IpNet::V6(_) => host
                .ipv6
                .is_some_and(|ip| self.network.contains(&IpAddr::V6(ip))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn test_ip_matcher() {
        let v4 = Ipv4Addr::new(192, 168, 1, 1);
        let matcher = IpMatcher::new(IpAddr::V4(v4));

        let host = HostInfo::new("", Some(v4), None);
        assert!(matcher.matches(&host));

        let other_v4 = Ipv4Addr::new(192, 168, 1, 2);
        let host2 = HostInfo::new("", Some(other_v4), None);
        assert!(!matcher.matches(&host2));
    }

    #[test]
    fn test_cidr_matcher() {
        let network: IpNet = "192.168.0.0/16".parse().unwrap();
        let matcher = CidrMatcher::new(network);

        let host1 = HostInfo::new("", Some(Ipv4Addr::new(192, 168, 1, 1)), None);
        assert!(matcher.matches(&host1));

        let host2 = HostInfo::new("", Some(Ipv4Addr::new(192, 168, 255, 255)), None);
        assert!(matcher.matches(&host2));

        let host3 = HostInfo::new("", Some(Ipv4Addr::new(10, 0, 0, 1)), None);
        assert!(!matcher.matches(&host3));
    }

    #[test]
    fn test_ipv6_cidr_matcher() {
        let network: IpNet = "2001:db8::/32".parse().unwrap();
        let matcher = CidrMatcher::new(network);

        let v6_1 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let host1 = HostInfo::new("", None, Some(v6_1));
        assert!(matcher.matches(&host1));

        let v6_2 = Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1);
        let host2 = HostInfo::new("", None, Some(v6_2));
        assert!(!matcher.matches(&host2));
    }
}
