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
    let max_prefix = if ip.len() == 4 { 32 } else if ip.len() == 16 { 128 } else { return None };

    if cidr.prefix > max_prefix {
        return None;
    }
    let prefix = cidr.prefix as u8;

    if ip.len() == 4 {
        let addr = IpAddr::V4(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]));
        IpNet::new(addr, prefix).ok()
    } else {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(ip);
        let addr = IpAddr::V6(std::net::Ipv6Addr::from(octets));
        IpNet::new(addr, prefix).ok()
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
        Ok(Type::RootDomain) => {
            let dot_pattern = format!(".{}", value);
            DomainType::RootDomain(value, dot_pattern)
        }
        Ok(Type::Full) => DomainType::Full(value),
        Err(_) => return None,
    };

    // Parse attributes with their typed values
    let attributes: Vec<(String, String)> = domain
        .attribute
        .iter()
        .map(|attr| {
            let value = match &attr.typed_value {
                Some(geodat::domain::attribute::TypedValue::BoolValue(b)) => b.to_string(),
                Some(geodat::domain::attribute::TypedValue::IntValue(i)) => i.to_string(),
                None => String::new(),
            };
            (attr.key.clone(), value)
        })
        .collect();

    Some(DomainEntry {
        domain_type,
        attributes,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_prefix_not_truncated() {
        // BUG #4: cidr_to_ipnet uses `cidr.prefix as u8` which truncates u32.
        // A prefix of 256 (0x100) becomes 0 after `as u8`, creating a /0 CIDR
        // that matches ALL traffic — a catastrophic security bug.
        //
        // Valid prefix range: 0-32 for IPv4, 0-128 for IPv6.
        // Any value > 128 is invalid and should be rejected (return None).
        let invalid_cidr = geodat::Cidr {
            ip: vec![10, 0, 0, 0], // 10.0.0.0
            prefix: 256,           // invalid: truncates to 0 via `as u8`
        };

        let result = cidr_to_ipnet(&invalid_cidr);
        // Should be None because 256 is not a valid prefix length
        assert!(
            result.is_none(),
            "prefix 256 should be rejected, got: {:?}",
            result
        );
    }

    #[test]
    fn test_cidr_valid_prefix_works() {
        let valid_cidr = geodat::Cidr {
            ip: vec![10, 0, 0, 0],
            prefix: 8,
        };
        let result = cidr_to_ipnet(&valid_cidr);
        assert!(result.is_some());
        assert_eq!(result.unwrap().to_string(), "10.0.0.0/8");
    }

    #[test]
    fn test_domain_attribute_values_preserved() {
        // BUG #5: domain_to_entry maps attribute values to String::new()
        // instead of using the actual attribute value from the protobuf.
        // This means attribute value-based filtering (e.g., @region=asia) is broken.
        let domain = geodat::Domain {
            r#type: 2, // RootDomain
            value: "google.com".to_string(),
            attribute: vec![geodat::domain::Attribute {
                key: "region".to_string(),
                typed_value: Some(geodat::domain::attribute::TypedValue::BoolValue(true)),
            }],
        };

        let entry = domain_to_entry(&domain).expect("should parse domain");

        // The attribute key should be present
        assert!(!entry.attributes.is_empty(), "attributes should not be empty");

        // BUG: The value is always empty string instead of the actual typed value.
        // For bool_value=true, we expect some non-empty representation (e.g., "true").
        // At minimum, if the proto has a typed_value, the value should not be blank.
        let (_key, value) = &entry.attributes[0];
        assert!(
            !value.is_empty(),
            "attribute value should not be empty when typed_value is set, got empty string"
        );
    }
}
