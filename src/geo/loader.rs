use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use parking_lot::Mutex;

use ipnet::IpNet;

use crate::error::{AclError, Result};
use crate::matcher::{DomainEntry, GeoIpMatcher, GeoSiteMatcher};

use super::format::{GeoIpFormat, GeoSiteFormat};
use super::singsite::SingSiteReader;
use super::{dat, metadb, mmdb, singsite};

/// Logger callback type for logging geo data updates
type LoggerCallback = Box<dyn Fn(&str) + Send + Sync>;

/// Default update interval: 7 days
pub const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

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
        if self.geoip_data.read().unwrap().is_some() {
            return Ok(());
        }

        let path = self
            .geoip_path
            .as_ref()
            .ok_or_else(|| AclError::GeoIpError("GeoIP path not configured".to_string()))?;

        let data = dat::load_geoip(path)?;

        *self.geoip_data.write().unwrap() = Some(data);
        Ok(())
    }

    /// Open and cache a shared MMDB/MetaDB reader (for MMDB and MetaDB formats)
    fn ensure_mmdb_reader(&self) -> Result<Arc<maxminddb::Reader<Vec<u8>>>> {
        {
            let guard = self.mmdb_reader.read().unwrap();
            if let Some(ref reader) = *guard {
                return Ok(reader.clone());
            }
        }

        let path = self
            .geoip_path
            .as_ref()
            .ok_or_else(|| AclError::GeoIpError("GeoIP path not configured".to_string()))?;

        let reader = Arc::new(
            maxminddb::Reader::open_readfile(path)
                .map_err(|e| AclError::GeoIpError(format!("Failed to open MMDB/MetaDB: {}", e)))?,
        );

        *self.mmdb_reader.write().unwrap() = Some(reader.clone());
        Ok(reader)
    }

    /// Load and cache GeoSite data
    fn ensure_geosite_loaded(&self) -> Result<()> {
        // Check if already loaded
        if self.geosite_data.read().unwrap().is_some() {
            return Ok(());
        }

        let path = self
            .geosite_path
            .as_ref()
            .ok_or_else(|| AclError::GeoSiteError("GeoSite path not configured".to_string()))?;

        let format = self
            .get_geosite_format()
            .ok_or_else(|| AclError::GeoSiteError("Cannot detect GeoSite format".to_string()))?;

        let data = load_geosite_file(path, format)?;

        *self.geosite_data.write().unwrap() = Some(data);
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
        let format = self
            .get_geoip_format()
            .ok_or_else(|| AclError::GeoIpError("Cannot detect GeoIP format".to_string()))?;

        let code = country_code.to_lowercase();

        match format {
            GeoIpFormat::Dat => {
                // DAT: pre-load all CIDRs, lookup by country code
                self.ensure_geoip_loaded()?;
                let guard = self.geoip_data.read().unwrap();
                let data = guard.as_ref().unwrap();
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
        let guard = self.geosite_data.read().unwrap();
        let data = guard.as_ref().unwrap();

        let domains = data.get(&name).cloned().unwrap_or_default();
        Ok(GeoSiteMatcher::new(&name, domains).with_attributes(attrs))
    }
}

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

        eprintln!("[geoip] Checking geoip file: {}", path.display());

        if self.should_download(&path) {
            eprintln!("[geoip] File needs download/update");
            if let Some(ref url) = self.geoip_url {
                eprintln!("[geoip] Downloading from: {}", url);
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
        if self.geoip_data.read().unwrap().is_some() {
            return Ok(());
        }

        let path = self.ensure_geoip_downloaded()?;
        let data = dat::load_geoip(&path)?;
        *self.geoip_data.write().unwrap() = Some(data);
        Ok(())
    }

    /// Open and cache a shared MMDB/MetaDB reader with auto-download
    fn ensure_mmdb_reader(&self) -> Result<Arc<maxminddb::Reader<Vec<u8>>>> {
        {
            let guard = self.mmdb_reader.read().unwrap();
            if let Some(ref reader) = *guard {
                return Ok(reader.clone());
            }
        }

        let path = self.ensure_geoip_downloaded()?;
        let reader = Arc::new(
            maxminddb::Reader::open_readfile(&path)
                .map_err(|e| AclError::GeoIpError(format!("Failed to open MMDB/MetaDB: {}", e)))?,
        );

        *self.mmdb_reader.write().unwrap() = Some(reader.clone());
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

    /// Load a single geosite code lazily
    fn load_geosite_code(&self, code: &str) -> Result<Vec<DomainEntry>> {
        let code_lower = code.to_lowercase();

        // Try read lock first (fast path)
        {
            let cache = self.geosite_cache.read().unwrap();
            if let Some(domains) = cache.get(&code_lower) {
                return Ok(domains.clone());
            }
        }

        // Cache miss — ensure reader is ready, then load under write lock
        self.ensure_geosite_reader()?;

        let mut cache = self.geosite_cache.write().unwrap();

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
                let guard = self.geoip_data.read().unwrap();
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

/// Nil GeoLoader - returns errors for all operations
pub struct NilGeoLoader;

impl GeoLoader for NilGeoLoader {
    fn load_geoip(&self, country_code: &str) -> Result<GeoIpMatcher> {
        Err(AclError::GeoIpError(format!(
            "GeoIP not available (requested: {})",
            country_code
        )))
    }

    fn load_geosite(&self, site_name: &str) -> Result<GeoSiteMatcher> {
        Err(AclError::GeoSiteError(format!(
            "GeoSite not available (requested: {})",
            site_name
        )))
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

/// Load GeoIP data from file based on format
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
fn verify_geoip_file(path: &Path, format: GeoIpFormat) -> Result<()> {
    match format {
        GeoIpFormat::Dat => dat::verify_geoip(path),
        GeoIpFormat::Mmdb => mmdb::verify(path),
        GeoIpFormat::MetaDb => metadb::verify(path),
    }
}

/// Verify GeoSite file integrity
fn verify_geosite_file(path: &Path, format: GeoSiteFormat) -> Result<()> {
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
