use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;

use ipnet::IpNet;

use crate::error::{AclError, GeoErrorKind, Result};
use crate::matcher::{DomainEntry, GeoIpMatcher, GeoSiteMatcher};

use super::format::{GeoIpFormat, GeoSiteFormat};
use super::{dat, metadb, mmdb, singsite};

/// Default update interval: 7 days
pub const DEFAULT_UPDATE_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(7 * 24 * 60 * 60);

/// Trait for loading GeoIP and GeoSite data
pub trait GeoLoader: Send + Sync {
    /// Load GeoIP matcher for a country code
    fn load_geoip(&self, country_code: &str) -> Result<GeoIpMatcher>;

    /// Load GeoSite matcher for a site name
    fn load_geosite(&self, site_name: &str) -> Result<GeoSiteMatcher>;
}

/// File-based GeoLoader with format auto-detection
pub struct FileGeoLoader {
    geoip_path: Option<PathBuf>,
    geosite_path: Option<PathBuf>,
    geoip_format: Option<GeoIpFormat>,
    geosite_format: Option<GeoSiteFormat>,

    // Cached data for DAT format (pre-loaded CIDRs)
    geoip_data: RwLock<Option<HashMap<String, Vec<IpNet>>>>,
    // Cached MMDB/MetaDB reader for on-demand IP lookups
    mmdb_reader: RwLock<Option<Arc<maxminddb::Reader<Vec<u8>>>>>,
    geosite_data: RwLock<Option<HashMap<String, Vec<DomainEntry>>>>,
}

impl FileGeoLoader {
    /// Create a new FileGeoLoader
    pub fn new() -> Self {
        Self {
            geoip_path: None,
            geosite_path: None,
            geoip_format: None,
            geosite_format: None,
            geoip_data: RwLock::new(None),
            mmdb_reader: RwLock::new(None),
            geosite_data: RwLock::new(None),
        }
    }

    /// Set the GeoIP file path
    pub fn with_geoip_path(mut self, path: impl AsRef<Path>) -> Self {
        self.geoip_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set the GeoSite file path
    pub fn with_geosite_path(mut self, path: impl AsRef<Path>) -> Self {
        self.geosite_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set explicit GeoIP format (overrides auto-detection)
    pub fn with_geoip_format(mut self, format: GeoIpFormat) -> Self {
        self.geoip_format = Some(format);
        self
    }

    /// Set explicit GeoSite format (overrides auto-detection)
    pub fn with_geosite_format(mut self, format: GeoSiteFormat) -> Self {
        self.geosite_format = Some(format);
        self
    }

    /// Get GeoIP format (explicit or detected from path)
    fn get_geoip_format(&self) -> Option<GeoIpFormat> {
        self.geoip_format
            .or_else(|| self.geoip_path.as_ref().and_then(GeoIpFormat::detect))
    }

    /// Get GeoSite format (explicit or detected from path)
    fn get_geosite_format(&self) -> Option<GeoSiteFormat> {
        self.geosite_format
            .or_else(|| self.geosite_path.as_ref().and_then(GeoSiteFormat::detect))
    }

    /// Load and cache GeoIP CIDR data (for DAT format)
    fn ensure_geoip_loaded(&self) -> Result<()> {
        if self.geoip_data.read().is_some() {
            return Ok(());
        }

        let path = self
            .geoip_path
            .as_ref()
            .ok_or_else(|| AclError::GeoIpError {
                kind: GeoErrorKind::NotConfigured,
                message: "GeoIP path not configured, call with_geoip_path() to set it".to_string(),
            })?;

        let data = dat::load_geoip(path)?;

        *self.geoip_data.write() = Some(data);
        Ok(())
    }

    /// Open and cache a shared MMDB/MetaDB reader (for MMDB and MetaDB formats)
    fn ensure_mmdb_reader(&self) -> Result<Arc<maxminddb::Reader<Vec<u8>>>> {
        {
            let guard = self.mmdb_reader.read();
            if let Some(ref reader) = *guard {
                return Ok(reader.clone());
            }
        }

        let path = self
            .geoip_path
            .as_ref()
            .ok_or_else(|| AclError::GeoIpError {
                kind: GeoErrorKind::NotConfigured,
                message: "GeoIP path not configured, call with_geoip_path() to set it".to_string(),
            })?;

        let reader =
            Arc::new(
                maxminddb::Reader::open_readfile(path).map_err(|e| AclError::GeoIpError {
                    kind: GeoErrorKind::FileError,
                    message: format!("Failed to open MMDB/MetaDB: {}", e),
                })?,
            );

        *self.mmdb_reader.write() = Some(reader.clone());
        Ok(reader)
    }

    /// Load and cache GeoSite data
    fn ensure_geosite_loaded(&self) -> Result<()> {
        // Check if already loaded
        if self.geosite_data.read().is_some() {
            return Ok(());
        }

        let path = self
            .geosite_path
            .as_ref()
            .ok_or_else(|| AclError::GeoSiteError {
                kind: GeoErrorKind::NotConfigured,
                message: "GeoSite path not configured, call with_geosite_path() to set it"
                    .to_string(),
            })?;

        let format = self
            .get_geosite_format()
            .ok_or_else(|| AclError::GeoSiteError {
                kind: GeoErrorKind::InvalidData,
                message: format!(
                    "Cannot detect GeoSite format from '{}', supported extensions: .dat, .db",
                    path.display()
                ),
            })?;

        let data = load_geosite_file(path, format)?;

        *self.geosite_data.write() = Some(data);
        Ok(())
    }
}

impl Default for FileGeoLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoLoader for FileGeoLoader {
    fn load_geoip(&self, country_code: &str) -> Result<GeoIpMatcher> {
        let format = self.get_geoip_format().ok_or_else(|| match &self.geoip_path {
            None => AclError::GeoIpError { kind: GeoErrorKind::NotConfigured, message: "GeoIP path not configured, call with_geoip_path() to set it".to_string() },
            Some(p) => AclError::GeoIpError { kind: GeoErrorKind::InvalidData, message: format!("Cannot detect GeoIP format from '{}', supported extensions: .dat, .mmdb, .metadb", p.display()) },
        })?;

        let code = country_code.to_lowercase();

        match format {
            GeoIpFormat::Dat => {
                // DAT: pre-load all CIDRs, lookup by country code
                self.ensure_geoip_loaded()?;
                let guard = self.geoip_data.read();
                let data = guard.as_ref().ok_or_else(|| AclError::GeoIpError {
                    kind: GeoErrorKind::NotLoaded,
                    message: "GeoIP data not loaded".to_string(),
                })?;
                let cidrs = data.get(&code).cloned().unwrap_or_default();
                Ok(GeoIpMatcher::from_cidrs(&code, cidrs))
            }
            GeoIpFormat::Mmdb | GeoIpFormat::MetaDb => {
                // MMDB/MetaDB: on-demand lookup via shared reader
                let reader = self.ensure_mmdb_reader()?;
                Ok(GeoIpMatcher::from_mmdb_reader(reader, &code))
            }
        }
    }

    fn load_geosite(&self, site_name: &str) -> Result<GeoSiteMatcher> {
        self.ensure_geosite_loaded()?;

        let (name, attrs) = GeoSiteMatcher::parse_pattern(site_name);
        let guard = self.geosite_data.read();
        let data = guard.as_ref().ok_or_else(|| AclError::GeoSiteError {
            kind: GeoErrorKind::NotLoaded,
            message: "GeoSite data not loaded".to_string(),
        })?;

        let domains = data.get(&name).cloned().unwrap_or_default();
        Ok(GeoSiteMatcher::new(&name, domains).with_attributes(attrs))
    }
}

/// Nil GeoLoader - returns errors for all operations
pub struct NilGeoLoader;

impl GeoLoader for NilGeoLoader {
    fn load_geoip(&self, country_code: &str) -> Result<GeoIpMatcher> {
        Err(AclError::GeoIpError {
            kind: GeoErrorKind::NotLoaded,
            message: format!("GeoIP not available (requested: {})", country_code),
        })
    }

    fn load_geosite(&self, site_name: &str) -> Result<GeoSiteMatcher> {
        Err(AclError::GeoSiteError {
            kind: GeoErrorKind::NotLoaded,
            message: format!("GeoSite not available (requested: {})", site_name),
        })
    }
}

/// In-memory GeoLoader for testing
pub struct MemoryGeoLoader {
    geoip_data: HashMap<String, Vec<IpNet>>,
    geosite_data: HashMap<String, Vec<DomainEntry>>,
}

impl MemoryGeoLoader {
    pub fn new() -> Self {
        Self {
            geoip_data: HashMap::new(),
            geosite_data: HashMap::new(),
        }
    }

    pub fn add_geoip(&mut self, country_code: &str, cidrs: Vec<IpNet>) {
        self.geoip_data.insert(country_code.to_lowercase(), cidrs);
    }

    pub fn add_geosite(&mut self, site_name: &str, domains: Vec<DomainEntry>) {
        self.geosite_data.insert(site_name.to_lowercase(), domains);
    }
}

impl Default for MemoryGeoLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoLoader for MemoryGeoLoader {
    fn load_geoip(&self, country_code: &str) -> Result<GeoIpMatcher> {
        let code = country_code.to_lowercase();
        let cidrs = self.geoip_data.get(&code).cloned().unwrap_or_default();
        Ok(GeoIpMatcher::from_cidrs(&code, cidrs))
    }

    fn load_geosite(&self, site_name: &str) -> Result<GeoSiteMatcher> {
        let (name, attrs) = GeoSiteMatcher::parse_pattern(site_name);
        let domains = self.geosite_data.get(&name).cloned().unwrap_or_default();
        Ok(GeoSiteMatcher::new(&name, domains).with_attributes(attrs))
    }
}

// Helper functions

/// Load GeoSite data from file based on format
fn load_geosite_file(
    path: &Path,
    format: GeoSiteFormat,
) -> Result<HashMap<String, Vec<DomainEntry>>> {
    match format {
        GeoSiteFormat::Dat => dat::load_geosite(path),
        GeoSiteFormat::Sing => singsite::load_geosite(path),
    }
}

/// Verify GeoIP file integrity
pub(crate) fn verify_geoip_file(path: &Path, format: GeoIpFormat) -> Result<()> {
    match format {
        GeoIpFormat::Dat => dat::verify_geoip(path),
        GeoIpFormat::Mmdb => mmdb::verify(path),
        GeoIpFormat::MetaDb => metadb::verify(path),
    }
}

/// Verify GeoSite file integrity
pub(crate) fn verify_geosite_file(path: &Path, format: GeoSiteFormat) -> Result<()> {
    match format {
        GeoSiteFormat::Dat => dat::verify_geosite(path),
        GeoSiteFormat::Sing => singsite::verify(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_geoloader() {
        let mut loader = MemoryGeoLoader::new();
        loader.add_geoip("cn", vec!["223.0.0.0/8".parse().unwrap()]);
        loader.add_geosite("google", vec![DomainEntry::new_root_domain("google.com")]);

        let _geoip = loader.load_geoip("cn").unwrap();
        let geosite = loader.load_geosite("google").unwrap();

        assert_eq!(geosite.site_name(), "google");
    }

    #[test]
    fn test_nil_geoloader() {
        let loader = NilGeoLoader;

        assert!(loader.load_geoip("cn").is_err());
        assert!(loader.load_geosite("google").is_err());
    }

    #[test]
    fn test_memory_geoloader_caching() {
        let mut loader = MemoryGeoLoader::new();
        loader.add_geosite(
            "google",
            vec![
                DomainEntry::new_root_domain("google.com"),
                DomainEntry::new_root_domain("googleapis.com"),
            ],
        );

        // Load twice - second call should use cached data
        let matcher1 = loader.load_geosite("google").unwrap();
        let matcher2 = loader.load_geosite("google").unwrap();

        assert_eq!(matcher1.site_name(), "google");
        assert_eq!(matcher2.site_name(), "google");
    }

    #[test]
    fn test_memory_geoloader_with_attributes() {
        let mut loader = MemoryGeoLoader::new();
        loader.add_geosite(
            "google",
            vec![
                DomainEntry::new_root_domain("google.com").with_attribute("cn", ""),
                DomainEntry::new_root_domain("google.cn"),
            ],
        );

        // Load with attribute filter
        let matcher = loader.load_geosite("google@cn").unwrap();
        assert_eq!(matcher.site_name(), "google");
    }

    #[test]
    fn test_geoip_not_configured_error_includes_hint() {
        let loader = FileGeoLoader::new();
        let err = loader.load_geoip("cn").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("with_geoip_path"),
            "error should hint at with_geoip_path(), got: {}",
            msg
        );
    }

    #[test]
    fn test_geosite_not_configured_error_includes_hint() {
        let loader = FileGeoLoader::new();
        let err = loader.load_geosite("google").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("with_geosite_path"),
            "error should hint at with_geosite_path(), got: {}",
            msg
        );
    }

    #[test]
    fn test_geoip_format_detection_error_includes_path_and_formats() {
        let loader = FileGeoLoader::new().with_geoip_path("/tmp/geoip.txt");
        let err = loader.load_geoip("cn").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("geoip.txt"),
            "error should include the path, got: {}",
            msg
        );
        assert!(
            msg.contains(".dat") && msg.contains(".mmdb") && msg.contains(".metadb"),
            "error should list supported extensions, got: {}",
            msg
        );
    }

    #[test]
    fn test_geosite_format_detection_error_includes_path_and_formats() {
        let loader = FileGeoLoader::new().with_geosite_path("/tmp/geosite.txt");
        let err = loader.load_geosite("google").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("geosite.txt"),
            "error should include the path, got: {}",
            msg
        );
        assert!(
            msg.contains(".dat") && msg.contains(".db"),
            "error should list supported extensions, got: {}",
            msg
        );
    }

    #[test]
    fn test_format_detection() {
        assert_eq!(GeoIpFormat::detect("geoip.dat"), Some(GeoIpFormat::Dat));
        assert_eq!(GeoIpFormat::detect("geoip.mmdb"), Some(GeoIpFormat::Mmdb));
        assert_eq!(
            GeoIpFormat::detect("geoip.metadb"),
            Some(GeoIpFormat::MetaDb)
        );
        assert_eq!(GeoIpFormat::detect("geoip.txt"), None);

        assert_eq!(
            GeoSiteFormat::detect("geosite.dat"),
            Some(GeoSiteFormat::Dat)
        );
        assert_eq!(
            GeoSiteFormat::detect("geosite.db"),
            Some(GeoSiteFormat::Sing)
        );
        assert_eq!(GeoSiteFormat::detect("geosite.txt"), None);
    }
}
