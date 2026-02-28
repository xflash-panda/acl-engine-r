use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use parking_lot::{Mutex, RwLock};

use ipnet::IpNet;

use crate::error::{AclError, Result};
use crate::matcher::{DomainEntry, GeoIpMatcher, GeoSiteMatcher};

use super::dat;
use super::format::{GeoIpFormat, GeoSiteFormat};
use super::loader::{verify_geoip_file, verify_geosite_file, GeoLoader, DEFAULT_UPDATE_INTERVAL};
use super::singsite::{self, SingSiteReader};

/// Logger callback type for logging geo data updates
type LoggerCallback = Box<dyn Fn(&str) + Send + Sync>;

/// Auto GeoLoader with download support and lazy loading
pub struct AutoGeoLoader {
    // Paths
    pub geoip_path: Option<PathBuf>,
    pub geosite_path: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,

    // Formats
    pub geoip_format: Option<GeoIpFormat>,
    pub geosite_format: Option<GeoSiteFormat>,

    // Download URLs
    pub geoip_url: Option<String>,
    pub geosite_url: Option<String>,

    // Update interval
    pub update_interval: Duration,

    // Logger
    pub logger: Option<LoggerCallback>,

    // Cached data for DAT format (pre-loaded CIDRs)
    geoip_data: RwLock<Option<HashMap<String, Vec<IpNet>>>>,
    // Cached MMDB/MetaDB reader for on-demand IP lookups
    mmdb_reader: RwLock<Option<Arc<maxminddb::Reader<Vec<u8>>>>>,
    // Lazy-loaded geosite data: only loads requested codes
    geosite_cache: RwLock<HashMap<String, Vec<DomainEntry>>>,
    // Persistent reader for sing-geosite format (opened once, reused for all reads)
    geosite_reader: Mutex<Option<SingSiteReader>>,
    download_lock: Mutex<()>,
}

impl AutoGeoLoader {
    /// Create a new AutoGeoLoader
    pub fn new() -> Self {
        Self {
            geoip_path: None,
            geosite_path: None,
            data_dir: None,
            geoip_format: None,
            geosite_format: None,
            geoip_url: None,
            geosite_url: None,
            update_interval: DEFAULT_UPDATE_INTERVAL,
            logger: None,
            geoip_data: RwLock::new(None),
            mmdb_reader: RwLock::new(None),
            geosite_cache: RwLock::new(HashMap::new()),
            geosite_reader: Mutex::new(None),
            download_lock: Mutex::new(()),
        }
    }

    /// Set data directory
    pub fn with_data_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.data_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Set GeoIP configuration
    pub fn with_geoip(mut self, format: GeoIpFormat) -> Self {
        self.geoip_format = Some(format);
        self.geoip_url = Some(format.default_url().to_string());
        self
    }

    /// Set GeoSite configuration
    pub fn with_geosite(mut self, format: GeoSiteFormat) -> Self {
        self.geosite_format = Some(format);
        self.geosite_url = Some(format.default_url().to_string());
        self
    }

    /// Set custom GeoIP URL
    pub fn with_geoip_url(mut self, url: impl Into<String>) -> Self {
        self.geoip_url = Some(url.into());
        self
    }

    /// Set custom GeoSite URL
    pub fn with_geosite_url(mut self, url: impl Into<String>) -> Self {
        self.geosite_url = Some(url.into());
        self
    }

    /// Set update interval for checking file freshness
    /// Default is 7 days (DEFAULT_UPDATE_INTERVAL)
    pub fn with_update_interval(mut self, interval: Duration) -> Self {
        self.update_interval = interval;
        self
    }

    /// Set logger
    pub fn with_logger<F>(mut self, logger: F) -> Self
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        self.logger = Some(Box::new(logger));
        self
    }

    fn log(&self, msg: &str) {
        if let Some(ref logger) = self.logger {
            logger(msg);
        }
    }

    /// Get GeoIP file path
    fn get_geoip_path(&self) -> Option<PathBuf> {
        if let Some(ref path) = self.geoip_path {
            return Some(path.clone());
        }

        let format = self.geoip_format?;
        let filename = format.default_filename();

        if let Some(ref dir) = self.data_dir {
            Some(dir.join(filename))
        } else {
            Some(PathBuf::from(filename))
        }
    }

    /// Get GeoSite file path
    fn get_geosite_path(&self) -> Option<PathBuf> {
        if let Some(ref path) = self.geosite_path {
            return Some(path.clone());
        }

        let format = self.geosite_format?;
        let filename = format.default_filename();

        if let Some(ref dir) = self.data_dir {
            Some(dir.join(filename))
        } else {
            Some(PathBuf::from(filename))
        }
    }

    /// Check if file needs download
    fn should_download(&self, path: &Path) -> bool {
        match fs::metadata(path) {
            Ok(meta) => {
                if meta.len() == 0 {
                    return true;
                }
                match meta.modified() {
                    Ok(mtime) => SystemTime::now()
                        .duration_since(mtime)
                        .map(|d| d > self.update_interval)
                        .unwrap_or(true),
                    Err(_) => true,
                }
            }
            Err(_) => true,
        }
    }

    /// Download file from URL
    fn download(
        &self,
        path: &Path,
        url: &str,
        verify_fn: impl Fn(&Path) -> Result<()>,
    ) -> Result<()> {
        let _lock = self.download_lock.lock();

        // Double-check after acquiring lock
        if !self.should_download(path) {
            return Ok(());
        }

        self.log(&format!("Downloading {} from {}", path.display(), url));

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(AclError::IoError)?;
        }

        // Download to temporary file
        let tmp_path = path.with_extension("tmp");

        let response = ureq::get(url)
            .call()
            .map_err(|e| AclError::GeoIpError(format!("Download failed: {}", e)))?;

        let mut file = fs::File::create(&tmp_path)?;
        let (_, body) = response.into_parts();
        let mut reader = body.into_reader();
        std::io::copy(&mut reader, &mut file)?;
        file.flush()?;
        drop(file);

        // Verify the downloaded file
        if let Err(e) = verify_fn(&tmp_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(AclError::GeoIpError(format!("Verification failed: {}", e)));
        }

        // Move to final location
        fs::rename(&tmp_path, path)?;

        self.log(&format!("Downloaded {} successfully", path.display()));
        Ok(())
    }

    /// Ensure geoip file is downloaded and available
    fn ensure_geoip_downloaded(&self) -> Result<PathBuf> {
        let format = self
            .geoip_format
            .ok_or_else(|| AclError::GeoIpError("GeoIP format not configured".to_string()))?;

        let path = self
            .get_geoip_path()
            .ok_or_else(|| AclError::GeoIpError("GeoIP path not configured".to_string()))?;

        self.log(&format!("Checking geoip file: {}", path.display()));

        if self.should_download(&path) {
            self.log("File needs download/update");
            if let Some(ref url) = self.geoip_url {
                self.log(&format!("Downloading from: {}", url));
                let verify = |p: &Path| verify_geoip_file(p, format);
                if let Err(e) = self.download(&path, url, verify) {
                    if !path.exists() {
                        return Err(e);
                    }
                    self.log(&format!("Download failed, using existing file: {}", e));
                }
            }
        }

        Ok(path)
    }

    /// Load GeoIP CIDR data with auto-download (for DAT format)
    fn ensure_geoip_loaded(&self) -> Result<()> {
        if self.geoip_data.read().is_some() {
            return Ok(());
        }

        let path = self.ensure_geoip_downloaded()?;
        let data = dat::load_geoip(&path)?;
        *self.geoip_data.write() = Some(data);
        Ok(())
    }

    /// Open and cache a shared MMDB/MetaDB reader with auto-download
    fn ensure_mmdb_reader(&self) -> Result<Arc<maxminddb::Reader<Vec<u8>>>> {
        {
            let guard = self.mmdb_reader.read();
            if let Some(ref reader) = *guard {
                return Ok(reader.clone());
            }
        }

        let path = self.ensure_geoip_downloaded()?;
        let reader = Arc::new(
            maxminddb::Reader::open_readfile(&path)
                .map_err(|e| AclError::GeoIpError(format!("Failed to open MMDB/MetaDB: {}", e)))?,
        );

        *self.mmdb_reader.write() = Some(reader.clone());
        Ok(reader)
    }

    /// Ensure geosite reader is initialized (opens file once)
    fn ensure_geosite_reader(&self) -> Result<()> {
        let mut reader_guard = self.geosite_reader.lock();
        if reader_guard.is_some() {
            return Ok(());
        }

        let format = self
            .geosite_format
            .ok_or_else(|| AclError::GeoSiteError("GeoSite format not configured".to_string()))?;

        // Currently only Sing format supports lazy loading
        if format != GeoSiteFormat::Sing {
            return Err(AclError::GeoSiteError(
                "Lazy loading only supported for Sing format".to_string(),
            ));
        }

        let path = self
            .get_geosite_path()
            .ok_or_else(|| AclError::GeoSiteError("GeoSite path not configured".to_string()))?;

        // Try to download if needed
        if self.should_download(&path) {
            if let Some(ref url) = self.geosite_url {
                let verify = |p: &Path| verify_geosite_file(p, format);
                if let Err(e) = self.download(&path, url, verify) {
                    if !path.exists() {
                        return Err(e);
                    }
                    self.log(&format!("Download failed, using existing file: {}", e));
                }
            }
        }

        let (reader, _codes) = SingSiteReader::open(&path)?;
        *reader_guard = Some(reader);
        Ok(())
    }

    /// Pre-load all geosite data from DAT format into cache.
    fn ensure_dat_geosite_loaded(&self) -> Result<()> {
        // Fast path: already loaded
        if !self.geosite_cache.read().is_empty() {
            return Ok(());
        }

        let path = self
            .get_geosite_path()
            .ok_or_else(|| AclError::GeoSiteError("GeoSite path not configured".to_string()))?;

        // Try to download if needed
        if self.should_download(&path) {
            if let Some(ref url) = self.geosite_url {
                let verify = |p: &Path| verify_geosite_file(p, GeoSiteFormat::Dat);
                if let Err(e) = self.download(&path, url, verify) {
                    if !path.exists() {
                        return Err(e);
                    }
                    self.log(&format!("Download failed, using existing file: {}", e));
                }
            }
        }

        let data = dat::load_geosite(&path)?;

        let mut cache = self.geosite_cache.write();
        for (code, domains) in data {
            cache.insert(code, domains);
        }
        Ok(())
    }

    /// Load a single geosite code lazily
    fn load_geosite_code(&self, code: &str) -> Result<Vec<DomainEntry>> {
        let code_lower = code.to_lowercase();

        // Try read lock first (fast path)
        {
            let cache = self.geosite_cache.read();
            if let Some(domains) = cache.get(&code_lower) {
                return Ok(domains.clone());
            }
        }

        let format = self
            .geosite_format
            .ok_or_else(|| AclError::GeoSiteError("GeoSite format not configured".to_string()))?;

        match format {
            GeoSiteFormat::Dat => {
                // DAT format: pre-load all data, then look up
                self.ensure_dat_geosite_loaded()?;
                let cache = self.geosite_cache.read();
                Ok(cache.get(&code_lower).cloned().unwrap_or_default())
            }
            GeoSiteFormat::Sing => {
                // Sing format: lazy load per code
                self.ensure_geosite_reader()?;

                let mut cache = self.geosite_cache.write();

                // Double-check: another thread may have populated the cache
                if let Some(domains) = cache.get(&code_lower) {
                    return Ok(domains.clone());
                }

                // Load from reader
                let domains = {
                    let mut reader_guard = self.geosite_reader.lock();
                    let reader = reader_guard.as_mut().unwrap();
                    let items = reader.read(&code_lower)?;
                    singsite::convert_items_to_entries(items)
                };

                cache.insert(code_lower, domains.clone());
                Ok(domains)
            }
        }
    }
}

impl Default for AutoGeoLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoLoader for AutoGeoLoader {
    fn load_geoip(&self, country_code: &str) -> Result<GeoIpMatcher> {
        let format = self
            .geoip_format
            .ok_or_else(|| AclError::GeoIpError("GeoIP format not configured".to_string()))?;

        let code = country_code.to_lowercase();

        match format {
            GeoIpFormat::Dat => {
                self.ensure_geoip_loaded()?;
                let guard = self.geoip_data.read();
                let data = guard.as_ref().unwrap();
                let cidrs = data.get(&code).cloned().unwrap_or_default();
                Ok(GeoIpMatcher::from_cidrs(&code, cidrs))
            }
            GeoIpFormat::Mmdb | GeoIpFormat::MetaDb => {
                let reader = self.ensure_mmdb_reader()?;
                Ok(GeoIpMatcher::from_mmdb_reader(reader, &code))
            }
        }
    }

    fn load_geosite(&self, site_name: &str) -> Result<GeoSiteMatcher> {
        let (name, attrs) = GeoSiteMatcher::parse_pattern(site_name);

        // Use lazy loading - only load the requested code
        let domains = self.load_geosite_code(&name)?;
        Ok(GeoSiteMatcher::new(&name, domains).with_attributes(attrs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_geoloader_builder_pattern() {
        let loader = AutoGeoLoader::new()
            .with_data_dir("/tmp/test")
            .with_geoip(GeoIpFormat::Mmdb)
            .with_geosite(GeoSiteFormat::Sing)
            .with_geoip_url("http://example.com/geoip.mmdb")
            .with_geosite_url("http://example.com/geosite.db")
            .with_update_interval(std::time::Duration::from_secs(3600));

        assert_eq!(loader.geoip_format, Some(GeoIpFormat::Mmdb));
        assert_eq!(loader.geosite_format, Some(GeoSiteFormat::Sing));
        assert!(loader.geoip_url.is_some());
        assert!(loader.geosite_url.is_some());
        assert!(loader.data_dir.is_some());
    }

    #[test]
    fn test_auto_geoloader_dat_format_geosite() {
        use prost::Message;
        use std::io::Write;

        // Create a minimal valid DAT geosite file using protobuf
        let site_list = crate::geo::dat::geodat::GeoSiteList {
            entry: vec![crate::geo::dat::geodat::GeoSite {
                country_code: "GOOGLE".to_string(),
                domain: vec![crate::geo::dat::geodat::Domain {
                    r#type: 2, // RootDomain
                    value: "google.com".to_string(),
                    attribute: vec![],
                }],
                resource_hash: vec![],
                code: String::new(),
            }],
        };

        let dir = std::env::temp_dir().join("acl_engine_test_auto_dat");
        let _ = fs::create_dir_all(&dir);
        let dat_path = dir.join("geosite.dat");
        let mut file = fs::File::create(&dat_path).unwrap();
        file.write_all(&site_list.encode_to_vec()).unwrap();
        drop(file);

        // Configure AutoGeoLoader with DAT format
        let loader = AutoGeoLoader::new()
            .with_geosite(GeoSiteFormat::Dat)
            .with_data_dir(&dir);

        // This should succeed, not fail with "Lazy loading only supported for Sing format"
        let result = loader.load_geosite("google");
        assert!(
            result.is_ok(),
            "AutoGeoLoader with DAT format should load geosite data, got error: {:?}",
            result.err()
        );

        let matcher = result.unwrap();
        assert_eq!(matcher.site_name(), "google");

        // Verify the loaded data works correctly
        use crate::matcher::HostMatcher;
        assert!(matcher.matches(&crate::types::HostInfo::from_name("google.com")));
        assert!(matcher.matches(&crate::types::HostInfo::from_name("www.google.com")));
        assert!(!matcher.matches(&crate::types::HostInfo::from_name("example.com")));

        // Cleanup
        let _ = fs::remove_file(&dat_path);
        let _ = fs::remove_dir(&dir);
    }
}
