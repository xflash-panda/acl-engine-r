use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use ipnet::IpNet;
use serde::Deserialize;

use super::HostMatcher;
use crate::error::{AclError, Result};
use crate::types::HostInfo;

/// GeoIP data source
#[derive(Debug)]
pub enum GeoIpData {
    /// MaxMind MMDB format
    Mmdb(Arc<maxminddb::Reader<Vec<u8>>>),
    /// V2Ray DAT format (protobuf) - list of CIDRs per country
    Dat(Vec<IpNet>),
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
            data: GeoIpData::Dat(cidrs),
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

        match reader.lookup::<Country>(ip) {
            Ok(result) => {
                let matches = result
                    .country
                    .and_then(|c| c.iso_code)
                    .map(|code| code.to_uppercase() == self.country_code)
                    .unwrap_or(false);
                if self.inverse {
                    !matches
                } else {
                    matches
                }
            }
            Err(_) => self.inverse,
        }
    }

    /// Check if an IP matches using CIDR list (binary search)
    fn matches_cidrs(&self, cidrs: &[IpNet], ip: IpAddr) -> bool {
        let matches = cidrs.iter().any(|cidr| cidr.contains(&ip));
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
            GeoIpData::Dat(cidrs) => {
                let v4_match = host.ipv4.is_some_and(|ip| self.matches_cidrs(cidrs, ip));
                let v6_match = host.ipv6.is_some_and(|ip| self.matches_cidrs(cidrs, ip));
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
}
