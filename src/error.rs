use thiserror::Error;

/// ACL Engine error types
#[derive(Error, Debug)]
pub enum AclError {
    #[error("Parse error at line {line}: {message}")]
    ParseErrorAtLine { line: usize, message: String },

    #[error("Invalid rule format: {0}")]
    InvalidRuleFormat(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid protocol/port: {0}")]
    InvalidProtoPort(String),

    #[error("Unknown outbound: {0}")]
    UnknownOutbound(String),

    #[error("Invalid CIDR: {0}")]
    InvalidCidr(String),

    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    #[error("GeoIP error: {0}")]
    GeoIpError(String),

    #[error("GeoSite error: {0}")]
    GeoSiteError(String),

    #[error("Config error: {0}")]
    ConfigError(String),

    #[error("Outbound error: {0}")]
    OutboundError(String),

    #[error("Resolve error: {0}")]
    ResolveError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
}

pub type Result<T> = std::result::Result<T, AclError>;
