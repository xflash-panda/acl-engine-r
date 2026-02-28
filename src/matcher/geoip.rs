use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use ipnet::IpNet;
use serde::Deserialize;

use super::HostMatcher;
use crate::error::{AclError, Result};
use crate::types::HostInfo;

/// A single address-family CIDR list sorted by network address, with a
/// precomputed prefix-max broadcast array for efficient early termination.
#[derive(Debug)]
struct SortedCidrList {
    /// CIDRs sorted by network address.
    cidrs: Vec<IpNet>,
    /// `max_broadcast[i]` = max broadcast address of cidrs[0..=i].
    /// Used to safely terminate backward scans: if max_broadcast[i] < ip,
    /// then no CIDR at index <= i can contain ip.
    max_broadcast: Vec<IpAddr>,
}

impl SortedCidrList {
    fn from_cidrs(mut cidrs: Vec<IpNet>) -> Self {
        cidrs.sort_by_key(|c| c.network());
        let mut max_broadcast = Vec::with_capacity(cidrs.len());
        let mut current_max: Option<IpAddr> = None;
        for cidr in &cidrs {
            let bcast = cidr.broadcast();
            let new_max = match current_max {
                Some(m) if bcast > m => bcast,
                Some(m) => m,
                None => bcast,
            };
            current_max = Some(new_max);
            max_broadcast.push(new_max);
        }
        Self {
            cidrs,
            max_broadcast,
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        if self.cidrs.is_empty() {
            return false;
        }

        // Binary search: find the rightmost CIDR whose network address <= ip.
        let idx = self.cidrs.partition_point(|c| c.network() <= ip);

        // Scan backwards through candidates with network address <= ip.
        for i in (0..idx).rev() {
            if self.cidrs[i].contains(&ip) {
                return true;
            }
            // max_broadcast[i] is the maximum broadcast of cidrs[0..=i].
            // If it is less than ip, no CIDR at index <= i can contain ip.
            if self.max_broadcast[i] < ip {
                break;
            }
        }

        false
    }
}

/// Sorted CIDR collection for binary search lookup.
///
/// CIDRs are split by address family (v4/v6) and sorted by network address,
/// enabling O(log n) lookup via `partition_point` instead of linear scan.
#[derive(Debug)]
pub struct SortedCidrs {
    v4: SortedCidrList,
    v6: SortedCidrList,
}

impl SortedCidrs {
    fn new(cidrs: Vec<IpNet>) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for cidr in cidrs {
            match cidr {
                IpNet::V4(_) => v4.push(cidr),
                IpNet::V6(_) => v6.push(cidr),
            }
        }
        Self {
            v4: SortedCidrList::from_cidrs(v4),
            v6: SortedCidrList::from_cidrs(v6),
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.v4.contains(ip),
            IpAddr::V6(_) => self.v6.contains(ip),
        }
    }
}

/// GeoIP data source
#[derive(Debug)]
pub enum GeoIpData {
    /// MaxMind MMDB format
    Mmdb(Arc<maxminddb::Reader<Vec<u8>>>),
    /// V2Ray DAT format (protobuf) - sorted CIDRs per country
    Dat(SortedCidrs),
}

/// GeoIP matcher - matches IP addresses by country code
#[derive(Debug)]
pub struct GeoIpMatcher {
    country_code: String,
    data: GeoIpData,
    inverse: bool,
}

impl GeoIpMatcher {
    /// Create a new GeoIP matcher from MMDB file
    pub fn from_mmdb(path: impl AsRef<Path>, country_code: &str) -> Result<Self> {
        let reader = maxminddb::Reader::open_readfile(path.as_ref())
            .map_err(|e| AclError::GeoIpError(format!("Failed to open MMDB file: {}", e)))?;

        Ok(Self {
            country_code: country_code.to_uppercase(),
            data: GeoIpData::Mmdb(Arc::new(reader)),
            inverse: false,
        })
    }

    /// Create a new GeoIP matcher from MMDB reader (shared)
    pub fn from_mmdb_reader(reader: Arc<maxminddb::Reader<Vec<u8>>>, country_code: &str) -> Self {
        Self {
            country_code: country_code.to_uppercase(),
            data: GeoIpData::Mmdb(reader),
            inverse: false,
        }
    }

    /// Create a new GeoIP matcher from a list of CIDRs
    pub fn from_cidrs(country_code: &str, cidrs: Vec<IpNet>) -> Self {
        Self {
            country_code: country_code.to_uppercase(),
            data: GeoIpData::Dat(SortedCidrs::new(cidrs)),
            inverse: false,
        }
    }

    /// Set inverse matching (match if NOT in the country)
    pub fn set_inverse(&mut self, inverse: bool) {
        self.inverse = inverse;
    }

    /// Check if an IP matches using MMDB
    fn matches_mmdb(&self, reader: &maxminddb::Reader<Vec<u8>>, ip: IpAddr) -> bool {
        #[derive(Deserialize)]
        struct Country {
            country: Option<CountryInfo>,
        }

        #[derive(Deserialize)]
        struct CountryInfo {
            iso_code: Option<String>,
        }

        let matches = reader
            .lookup(ip)
            .ok()
            .and_then(|result| result.decode::<Country>().ok()?)
            .and_then(|record| record.country)
            .and_then(|c| c.iso_code)
            .map(|code| code.to_uppercase() == self.country_code)
            .unwrap_or(false);
        if self.inverse {
            !matches
        } else {
            matches
        }
    }

    /// Check if an IP matches using sorted CIDR list (binary search)
    fn matches_cidrs(&self, sorted: &SortedCidrs, ip: IpAddr) -> bool {
        let matches = sorted.contains(ip);
        if self.inverse {
            !matches
        } else {
            matches
        }
    }
}

impl HostMatcher for GeoIpMatcher {
    fn matches(&self, host: &HostInfo) -> bool {
        match &self.data {
            GeoIpData::Mmdb(reader) => {
                let v4_match = host.ipv4.is_some_and(|ip| self.matches_mmdb(reader, ip));
                let v6_match = host.ipv6.is_some_and(|ip| self.matches_mmdb(reader, ip));
                v4_match || v6_match
            }
            GeoIpData::Dat(sorted) => {
                let v4_match = host.ipv4.is_some_and(|ip| self.matches_cidrs(sorted, ip));
                let v6_match = host.ipv6.is_some_and(|ip| self.matches_cidrs(sorted, ip));
                v4_match || v6_match
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_geoip_from_cidrs() {
        let cidrs = vec![
            "192.168.0.0/16".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        let matcher = GeoIpMatcher::from_cidrs("PRIVATE", cidrs);

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let host1 = HostInfo::new("", Some(ip1), None);
        assert!(matcher.matches(&host1));

        let ip2 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let host2 = HostInfo::new("", Some(ip2), None);
        assert!(!matcher.matches(&host2));
    }

    #[test]
    fn test_geoip_inverse() {
        let cidrs = vec!["192.168.0.0/16".parse().unwrap()];
        let mut matcher = GeoIpMatcher::from_cidrs("PRIVATE", cidrs);
        matcher.set_inverse(true);

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let host1 = HostInfo::new("", Some(ip1), None);
        assert!(!matcher.matches(&host1));

        let ip2 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let host2 = HostInfo::new("", Some(ip2), None);
        assert!(matcher.matches(&host2));
    }

    #[test]
    fn test_geoip_sorted_cidrs_correctness() {
        let cidrs: Vec<IpNet> = vec![
            "10.0.0.0/8".parse().unwrap(),
            "172.16.0.0/12".parse().unwrap(),
            "192.168.0.0/16".parse().unwrap(),
            "100.64.0.0/10".parse().unwrap(),
            "169.254.0.0/16".parse().unwrap(),
        ];
        let matcher = GeoIpMatcher::from_cidrs("PRIVATE", cidrs);

        let cases_match = vec![
            "10.1.2.3", "10.255.255.255", "172.16.0.1", "172.31.255.255",
            "192.168.1.1", "192.168.255.255", "100.64.0.1", "100.127.255.255",
            "169.254.1.1",
        ];
        for ip_str in &cases_match {
            let ip: IpAddr = ip_str.parse().unwrap();
            let host = HostInfo::new("", Some(ip), None);
            assert!(matcher.matches(&host), "expected match for {}", ip_str);
        }

        let cases_no_match = vec![
            "8.8.8.8", "1.1.1.1", "172.32.0.1", "192.167.255.255",
            "100.128.0.1", "169.253.255.255", "11.0.0.0",
        ];
        for ip_str in &cases_no_match {
            let ip: IpAddr = ip_str.parse().unwrap();
            let host = HostInfo::new("", Some(ip), None);
            assert!(!matcher.matches(&host), "expected no match for {}", ip_str);
        }
    }

    #[test]
    fn test_geoip_overlapping_cidrs() {
        let cidrs: Vec<IpNet> = vec![
            "10.0.0.0/8".parse().unwrap(),
            "10.0.0.0/24".parse().unwrap(),
            "10.0.1.0/24".parse().unwrap(),
        ];
        let matcher = GeoIpMatcher::from_cidrs("TEST", cidrs);

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let host = HostInfo::new("", Some(ip), None);
        assert!(matcher.matches(&host));

        let ip: IpAddr = "10.1.0.1".parse().unwrap();
        let host = HostInfo::new("", Some(ip), None);
        assert!(matcher.matches(&host));

        let ip: IpAddr = "11.0.0.1".parse().unwrap();
        let host = HostInfo::new("", Some(ip), None);
        assert!(!matcher.matches(&host));
    }

    #[test]
    fn test_geoip_empty_cidrs() {
        let matcher = GeoIpMatcher::from_cidrs("EMPTY", vec![]);
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        let host = HostInfo::new("", Some(ip), None);
        assert!(!matcher.matches(&host));
    }

    #[test]
    fn test_geoip_ipv6_cidrs() {
        let cidrs: Vec<IpNet> = vec![
            "2001:db8::/32".parse().unwrap(),
            "fd00::/8".parse().unwrap(),
        ];
        let matcher = GeoIpMatcher::from_cidrs("V6TEST", cidrs);

        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let host = HostInfo::new("", None, Some(ip));
        assert!(matcher.matches(&host));

        let ip: IpAddr = "fd12::1".parse().unwrap();
        let host = HostInfo::new("", None, Some(ip));
        assert!(matcher.matches(&host));

        let ip: IpAddr = "2001:db9::1".parse().unwrap();
        let host = HostInfo::new("", None, Some(ip));
        assert!(!matcher.matches(&host));
    }
}
