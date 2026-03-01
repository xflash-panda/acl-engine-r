use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use ipnet::IpNet;
use serde::Deserialize;

use crate::error::{AclError, GeoErrorKind, Result};

/// MMDB record structure for GeoIP lookup
#[derive(Deserialize)]
struct MmdbRecord {
    country: Option<CountryInfo>,
}

#[derive(Deserialize)]
struct CountryInfo {
    iso_code: Option<String>,
}

/// Load GeoIP data from MaxMind MMDB format
/// Note: This creates a shared reader for efficient lookups rather than
/// pre-loading all networks (which is memory-intensive for large databases)
pub fn load_geoip(path: impl AsRef<Path>) -> Result<HashMap<String, Vec<IpNet>>> {
    // For MMDB, we don't pre-load all networks because:
    // 1. MMDB files can be very large (millions of networks)
    // 2. The maxminddb crate is optimized for on-demand lookups
    // 3. Pre-loading would consume significant memory
    //
    // Instead, we return an empty HashMap and use the MMDB reader directly
    // for lookups in the GeoIpMatcher.

    // Verify the file is valid
    verify(path)?;

    // Return empty map - actual lookups will use the MMDB reader directly
    Ok(HashMap::new())
}

/// Verify MMDB file integrity
pub fn verify(path: impl AsRef<Path>) -> Result<()> {
    maxminddb::Reader::open_readfile(path.as_ref()).map_err(|e| AclError::GeoIpError {
        kind: GeoErrorKind::FileError,
        message: format!("Failed to verify MMDB: {}", e),
    })?;
    Ok(())
}

/// Open a shared MMDB reader
pub fn open_shared(path: impl AsRef<Path>) -> Result<Arc<maxminddb::Reader<Vec<u8>>>> {
    let reader =
        maxminddb::Reader::open_readfile(path.as_ref()).map_err(|e| AclError::GeoIpError {
            kind: GeoErrorKind::FileError,
            message: format!("Failed to open MMDB: {}", e),
        })?;
    Ok(Arc::new(reader))
}

/// Lookup country code for an IP address
pub fn lookup_ip(reader: &maxminddb::Reader<Vec<u8>>, ip: IpAddr) -> Option<String> {
    let result = reader.lookup(ip).ok()?;
    let record: MmdbRecord = result.decode().ok()??;
    record.country.and_then(|c| c.iso_code)
}
