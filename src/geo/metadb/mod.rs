use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use ipnet::IpNet;
use lru::LruCache;
use serde::Deserialize;

use crate::error::{AclError, Result};

/// Default cache size for CachedMetaDbReader
pub const DEFAULT_CACHE_SIZE: usize = 1024;

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

/// Cached MetaDB reader with LRU cache for IP lookups.
///
/// Provides significant performance improvements for hot IP addresses
/// that are looked up repeatedly.
pub struct CachedMetaDbReader {
    reader: MetaDbReader,
    cache: Mutex<LruCache<IpAddr, Vec<String>>>,
}

impl CachedMetaDbReader {
    /// Create a new cached reader with default cache size (1024 entries)
    pub fn new(reader: MetaDbReader) -> Self {
        Self::with_cache_size(reader, DEFAULT_CACHE_SIZE)
    }

    /// Create a new cached reader with custom cache size
    pub fn with_cache_size(reader: MetaDbReader, cache_size: usize) -> Self {
        Self {
            reader,
            cache: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(cache_size)
                    .unwrap_or(std::num::NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap()),
            )),
        }
    }

    /// Open a MetaDB file with caching enabled (default cache size)
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let reader = MetaDbReader::open(path)?;
        Ok(Self::new(reader))
    }

    /// Open a MetaDB file with custom cache size
    pub fn open_with_cache_size(path: impl AsRef<Path>, cache_size: usize) -> Result<Self> {
        let reader = MetaDbReader::open(path)?;
        Ok(Self::with_cache_size(reader, cache_size))
    }

    /// Lookup country codes for an IP with caching
    pub fn lookup_codes(&self, ip: IpAddr) -> Vec<String> {
        // Check cache first
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(codes) = cache.get(&ip) {
                return codes.clone();
            }
        }

        // Cache miss, lookup from database
        let codes = self.reader.lookup_codes(ip);

        // Store in cache
        {
            let mut cache = self.cache.lock().unwrap();
            cache.put(ip, codes.clone());
        }

        codes
    }

    /// Get database type
    pub fn database_type(&self) -> DatabaseType {
        self.reader.database_type()
    }

    /// Clear the LRU cache
    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }

    /// Get the number of items in the cache
    pub fn cache_len(&self) -> usize {
        let cache = self.cache.lock().unwrap();
        cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_database_type_from_str() {
        assert_eq!(DatabaseType::from_str("MaxMind"), DatabaseType::MaxMind);
        assert_eq!(
            DatabaseType::from_str("GeoIP2-Country"),
            DatabaseType::MaxMind
        );
        assert_eq!(DatabaseType::from_str("sing-geoip"), DatabaseType::Sing);
        assert_eq!(DatabaseType::from_str("Meta-geoip0"), DatabaseType::MetaV0);
        assert_eq!(DatabaseType::from_str("unknown"), DatabaseType::Unknown);
    }

    #[test]
    fn test_cached_reader_cache_operations() {
        // We can't test with a real DB file in unit tests, but we can test cache operations
        // by creating a mock scenario

        // Test cache size configuration
        let cache_size = 100;
        let cache: LruCache<IpAddr, Vec<String>> =
            LruCache::new(std::num::NonZeroUsize::new(cache_size).unwrap());
        assert_eq!(cache.len(), 0);

        // Test IP address as cache key
        let ip1 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let ip2 = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
        assert_ne!(ip1, ip2);
    }
}
