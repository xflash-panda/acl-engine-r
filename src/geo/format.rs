use std::path::Path;

/// GeoIP file format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoIpFormat {
    /// V2Ray DAT format (protobuf)
    Dat,
    /// MaxMind MMDB format
    Mmdb,
    /// Clash Meta MetaDB format
    MetaDb,
}

impl GeoIpFormat {
    /// Detect format from file extension
    pub fn detect(path: impl AsRef<Path>) -> Option<Self> {
        let ext = path.as_ref().extension()?.to_str()?.to_lowercase();
        match ext.as_str() {
            "dat" => Some(GeoIpFormat::Dat),
            "mmdb" => Some(GeoIpFormat::Mmdb),
            "metadb" => Some(GeoIpFormat::MetaDb),
            _ => None,
        }
    }

    /// Get default filename for this format
    pub fn default_filename(&self) -> &'static str {
        match self {
            GeoIpFormat::Dat => "geoip.dat",
            GeoIpFormat::Mmdb => "geoip.mmdb",
            GeoIpFormat::MetaDb => "geoip.metadb",
        }
    }

    /// Get default CDN URL for this format
    pub fn default_url(&self) -> &'static str {
        match self {
            GeoIpFormat::Dat => {
                "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
            }
            GeoIpFormat::Mmdb => {
                "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"
            }
            GeoIpFormat::MetaDb => {
                "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb"
            }
        }
    }
}

/// GeoSite file format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoSiteFormat {
    /// V2Ray DAT format (protobuf)
    Dat,
    /// sing-geosite DB format
    Sing,
}

impl GeoSiteFormat {
    /// Detect format from file extension
    pub fn detect(path: impl AsRef<Path>) -> Option<Self> {
        let ext = path.as_ref().extension()?.to_str()?.to_lowercase();
        match ext.as_str() {
            "dat" => Some(GeoSiteFormat::Dat),
            "db" => Some(GeoSiteFormat::Sing),
            _ => None,
        }
    }

    /// Get default filename for this format
    pub fn default_filename(&self) -> &'static str {
        match self {
            GeoSiteFormat::Dat => "geosite.dat",
            GeoSiteFormat::Sing => "geosite.db",
        }
    }

    /// Get default CDN URL for this format
    pub fn default_url(&self) -> &'static str {
        match self {
            GeoSiteFormat::Dat => {
                "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
            }
            GeoSiteFormat::Sing => {
                "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.db"
            }
        }
    }
}
