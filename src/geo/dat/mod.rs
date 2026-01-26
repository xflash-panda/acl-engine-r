use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use ipnet::IpNet;
use prost::Message;

use crate::error::{AclError, Result};
use crate::matcher::{DomainEntry, DomainType};

// Include the generated protobuf code
pub mod geodat {
    include!(concat!(env!("OUT_DIR"), "/geodat.rs"));
}

/// Load GeoIP data from V2Ray DAT format
pub fn load_geoip(path: impl AsRef<Path>) -> Result<HashMap<String, Vec<IpNet>>> {
    let data = fs::read(path.as_ref())
        .map_err(|e| AclError::GeoIpError(format!("Failed to read DAT file: {}", e)))?;

    let list = geodat::GeoIpList::decode(&data[..])
        .map_err(|e| AclError::GeoIpError(format!("Failed to decode GeoIP DAT: {}", e)))?;

    let mut result = HashMap::new();

    for entry in list.entry {
        let code = entry.country_code.to_lowercase();
        let mut cidrs = Vec::new();

        for cidr in entry.cidr {
            if let Some(net) = cidr_to_ipnet(&cidr) {
                cidrs.push(net);
            }
        }

        result.insert(code, cidrs);
    }

    Ok(result)
}

/// Load GeoSite data from V2Ray DAT format
pub fn load_geosite(path: impl AsRef<Path>) -> Result<HashMap<String, Vec<DomainEntry>>> {
    let data = fs::read(path.as_ref())
        .map_err(|e| AclError::GeoSiteError(format!("Failed to read DAT file: {}", e)))?;

    let list = geodat::GeoSiteList::decode(&data[..])
        .map_err(|e| AclError::GeoSiteError(format!("Failed to decode GeoSite DAT: {}", e)))?;

    let mut result = HashMap::new();

    for entry in list.entry {
        let code = entry.country_code.to_lowercase();
        let mut domains = Vec::new();

        for domain in entry.domain {
            if let Some(entry) = domain_to_entry(&domain) {
                domains.push(entry);
            }
        }

        result.insert(code, domains);
    }

    Ok(result)
}

/// Convert protobuf CIDR to IpNet
fn cidr_to_ipnet(cidr: &geodat::Cidr) -> Option<IpNet> {
    let ip = &cidr.ip;
    let prefix = cidr.prefix as u8;

    if ip.len() == 4 {
        // IPv4
        let addr = IpAddr::V4(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]));
        IpNet::new(addr, prefix).ok()
    } else if ip.len() == 16 {
        // IPv6
        let mut octets = [0u8; 16];
        octets.copy_from_slice(ip);
        let addr = IpAddr::V6(std::net::Ipv6Addr::from(octets));
        IpNet::new(addr, prefix).ok()
    } else {
        None
    }
}

/// Convert protobuf Domain to DomainEntry
fn domain_to_entry(domain: &geodat::Domain) -> Option<DomainEntry> {
    use geodat::domain::Type;

    let value = domain.value.to_lowercase();
    let domain_type = match Type::try_from(domain.r#type) {
        Ok(Type::Plain) => DomainType::Plain(value),
        Ok(Type::Regex) => match regex::Regex::new(&value) {
            Ok(re) => DomainType::Regex(re),
            Err(_) => return None,
        },
        Ok(Type::RootDomain) => DomainType::RootDomain(value),
        Ok(Type::Full) => DomainType::Full(value),
        Err(_) => return None,
    };

    let mut entry = DomainEntry {
        domain_type,
        attributes: HashMap::new(),
    };

    // Parse attributes
    for attr in &domain.attribute {
        entry.attributes.insert(attr.key.clone(), String::new());
    }

    Some(entry)
}

/// Verify DAT file integrity by attempting to load it
pub fn verify_geoip(path: impl AsRef<Path>) -> Result<()> {
    load_geoip(path)?;
    Ok(())
}

/// Verify DAT file integrity by attempting to load it
pub fn verify_geosite(path: impl AsRef<Path>) -> Result<()> {
    load_geosite(path)?;
    Ok(())
}
