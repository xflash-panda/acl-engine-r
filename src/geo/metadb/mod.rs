use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use ipnet::IpNet;
use serde::Deserialize;

use crate::error::{AclError, Result};

/// MetaDB database types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseType {
    /// Standard MaxMind GeoIP2
    MaxMind,
    /// sing-geoip format
    Sing,
    /// Meta-geoip0 format
    MetaV0,
    /// Unknown format
    Unknown,
}

impl DatabaseType {
    fn from_str(s: &str) -> Self {
        match s {
            "MaxMind" | "GeoIP2-Country" | "GeoLite2-Country" | "DBIP-Country-Lite" => {
                DatabaseType::MaxMind
            }
            "sing-geoip" => DatabaseType::Sing,
            "Meta-geoip0" => DatabaseType::MetaV0,
            _ => DatabaseType::Unknown,
        }
    }
}

/// MetaDB reader wrapper
pub struct MetaDbReader {
    reader: maxminddb::Reader<Vec<u8>>,
    db_type: DatabaseType,
}

impl MetaDbReader {
    /// Open a MetaDB file
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let reader = maxminddb::Reader::open_readfile(path.as_ref())
            .map_err(|e| AclError::GeoIpError(format!("Failed to open MetaDB: {}", e)))?;

        let db_type = DatabaseType::from_str(&reader.metadata.database_type);

        Ok(Self { reader, db_type })
    }

    /// Get database type
    pub fn database_type(&self) -> DatabaseType {
        self.db_type
    }

    /// Lookup country codes for an IP
    pub fn lookup_codes(&self, ip: IpAddr) -> Vec<String> {
        match self.db_type {
            DatabaseType::MaxMind => {
                #[derive(Deserialize)]
                struct Country {
                    country: Option<CountryInfo>,
                }
                #[derive(Deserialize)]
                struct CountryInfo {
                    iso_code: Option<String>,
                }

                match self.reader.lookup::<Country>(ip) {
                    Ok(record) => {
                        if let Some(code) = record.country.and_then(|c| c.iso_code) {
                            vec![code]
                        } else {
                            vec![]
                        }
                    }
                    Err(_) => vec![],
                }
            }
            DatabaseType::Sing => match self.reader.lookup::<String>(ip) {
                Ok(code) if !code.is_empty() => vec![code],
                _ => vec![],
            },
            DatabaseType::MetaV0 => {
                // MetaV0 can return multiple codes
                #[derive(Deserialize)]
                #[serde(untagged)]
                enum MetaV0Result {
                    Single(String),
                    Multiple(Vec<String>),
                }

                match self.reader.lookup::<MetaV0Result>(ip) {
                    Ok(MetaV0Result::Single(code)) if !code.is_empty() => vec![code],
                    Ok(MetaV0Result::Multiple(codes)) => {
                        codes.into_iter().filter(|c| !c.is_empty()).collect()
                    }
                    _ => vec![],
                }
            }
            DatabaseType::Unknown => vec![],
        }
    }
}

/// Load GeoIP data from MetaDB format
/// Note: MetaDB files are optimized for on-demand lookups, not pre-loading
pub fn load_geoip(path: impl AsRef<Path>) -> Result<HashMap<String, Vec<IpNet>>> {
    // Verify the file is valid
    verify(path)?;

    // Return empty map - actual lookups will use the MetaDB reader directly
    Ok(HashMap::new())
}

/// Verify MetaDB file integrity
pub fn verify(path: impl AsRef<Path>) -> Result<()> {
    maxminddb::Reader::open_readfile(path.as_ref())
        .map_err(|e| AclError::GeoIpError(format!("Failed to verify MetaDB: {}", e)))?;
    Ok(())
}

/// Create a shared MetaDB reader
pub fn open_shared(path: impl AsRef<Path>) -> Result<Arc<maxminddb::Reader<Vec<u8>>>> {
    let reader = maxminddb::Reader::open_readfile(path.as_ref())
        .map_err(|e| AclError::GeoIpError(format!("Failed to open MetaDB: {}", e)))?;
    Ok(Arc::new(reader))
}
