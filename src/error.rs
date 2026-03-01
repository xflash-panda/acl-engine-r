use thiserror::Error;

/// Classifies outbound connection errors for programmatic matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundErrorKind {
    /// Connection to the remote host failed
    ConnectionFailed,
    /// Operation timed out
    Timeout,
    /// DNS resolution failed
    DnsFailed,
    /// Authentication failed or was rejected
    AuthFailed,
    /// Protocol-level error (invalid response, unsupported version, etc.)
    Protocol,
    /// I/O error during data transfer
    Io,
    /// Input validation failed (bad host, oversized field, etc.)
    InvalidInput,
    /// Feature not supported (e.g., UDP over HTTP proxy)
    Unsupported,
}

/// Classifies GeoIP/GeoSite errors for programmatic matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoErrorKind {
    /// Required path or format not configured
    NotConfigured,
    /// File open/read failure
    FileError,
    /// Data format or decoding error (corrupt file, wrong version, etc.)
    InvalidData,
    /// Resource not loaded or initialized
    NotLoaded,
    /// Download or verification failure
    DownloadFailed,
}

/// ACL Engine error types
#[derive(Error, Debug)]
pub enum AclError {
    #[error("{}", match line {
        Some(l) => format!("Parse error at line {}: {}", l, message),
        None => format!("Parse error: {}", message),
    })]
    ParseError {
        line: Option<usize>,
        message: String,
    },

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

    #[error("GeoIP error: {message}")]
    GeoIpError {
        kind: GeoErrorKind,
        message: String,
    },

    #[error("GeoSite error: {message}")]
    GeoSiteError {
        kind: GeoErrorKind,
        message: String,
    },

    #[error("Config error: {0}")]
    ConfigError(String),

    #[error("Outbound error: {message}")]
    OutboundError {
        kind: OutboundErrorKind,
        message: String,
    },

    #[error("Resolve error: {0}")]
    ResolveError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
}

pub type Result<T> = std::result::Result<T, AclError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outbound_error_kind_is_matchable() {
        // D2: Consumers should be able to programmatically match error sub-types
        // instead of parsing error message strings.
        let err = AclError::OutboundError {
            kind: OutboundErrorKind::Timeout,
            message: "Connection timeout".into(),
        };
        match &err {
            AclError::OutboundError { kind, .. } => {
                assert!(matches!(kind, OutboundErrorKind::Timeout));
            }
            _ => panic!("expected OutboundError"),
        }
    }

    #[test]
    fn test_outbound_error_kind_connection_failed() {
        let err = AclError::OutboundError {
            kind: OutboundErrorKind::ConnectionFailed,
            message: "Failed to connect to proxy: connection refused".into(),
        };
        match &err {
            AclError::OutboundError { kind, .. } => {
                assert!(matches!(kind, OutboundErrorKind::ConnectionFailed));
            }
            _ => panic!("expected OutboundError"),
        }
    }

    #[test]
    fn test_outbound_error_kind_auth_failed() {
        let err = AclError::OutboundError {
            kind: OutboundErrorKind::AuthFailed,
            message: "SOCKS5 authentication failed".into(),
        };
        match &err {
            AclError::OutboundError { kind, .. } => {
                assert!(matches!(kind, OutboundErrorKind::AuthFailed));
            }
            _ => panic!("expected OutboundError"),
        }
    }

    #[test]
    fn test_outbound_error_display_includes_message() {
        let err = AclError::OutboundError {
            kind: OutboundErrorKind::Timeout,
            message: "Connection timeout".into(),
        };
        let display = format!("{}", err);
        assert!(display.contains("Connection timeout"), "got: {}", display);
    }

    #[test]
    fn test_geo_error_kind_is_matchable() {
        let err = AclError::GeoIpError {
            kind: GeoErrorKind::NotConfigured,
            message: "GeoIP path not configured".into(),
        };
        match &err {
            AclError::GeoIpError { kind, .. } => {
                assert!(matches!(kind, GeoErrorKind::NotConfigured));
            }
            _ => panic!("expected GeoIpError"),
        }
    }

    #[test]
    fn test_geo_error_kind_file_error() {
        let err = AclError::GeoSiteError {
            kind: GeoErrorKind::FileError,
            message: "Failed to open file".into(),
        };
        match &err {
            AclError::GeoSiteError { kind, .. } => {
                assert!(matches!(kind, GeoErrorKind::FileError));
            }
            _ => panic!("expected GeoSiteError"),
        }
    }

    #[test]
    fn test_geo_error_kind_invalid_data() {
        let err = AclError::GeoSiteError {
            kind: GeoErrorKind::InvalidData,
            message: "Invalid regex pattern".into(),
        };
        match &err {
            AclError::GeoSiteError { kind, .. } => {
                assert!(matches!(kind, GeoErrorKind::InvalidData));
            }
            _ => panic!("expected GeoSiteError"),
        }
    }

    // D6: Unified ParseError — consumers match a single variant for all parse errors
    #[test]
    fn test_parse_error_with_line_number() {
        let err = AclError::ParseError {
            line: Some(42),
            message: "Invalid rule format".into(),
        };
        match &err {
            AclError::ParseError { line, message } => {
                assert_eq!(*line, Some(42));
                assert!(message.contains("Invalid rule format"));
            }
            _ => panic!("expected ParseError"),
        }
        let display = format!("{}", err);
        assert!(display.contains("line 42"), "got: {}", display);
        assert!(display.contains("Invalid rule format"), "got: {}", display);
    }

    #[test]
    fn test_parse_error_without_line_number() {
        let err = AclError::ParseError {
            line: None,
            message: "Failed to read rules file".into(),
        };
        match &err {
            AclError::ParseError { line, message } => {
                assert_eq!(*line, None);
                assert!(message.contains("Failed to read rules file"));
            }
            _ => panic!("expected ParseError"),
        }
        let display = format!("{}", err);
        assert!(!display.contains("line"), "got: {}", display);
        assert!(display.contains("Failed to read rules file"), "got: {}", display);
    }

    #[test]
    fn test_parse_error_single_match_handles_both() {
        // D6: consumers only need to match ONE variant for all parse errors
        let with_line = AclError::ParseError {
            line: Some(1),
            message: "bad".into(),
        };
        let without_line = AclError::ParseError {
            line: None,
            message: "bad".into(),
        };
        // Both match the same pattern — no need for two arms
        for err in [&with_line, &without_line] {
            assert!(matches!(err, AclError::ParseError { .. }));
        }
    }
}
