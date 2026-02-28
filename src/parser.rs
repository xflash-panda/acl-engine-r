use once_cell::sync::Lazy;
use regex::Regex;
use std::fs;
use std::path::Path;

use crate::error::{AclError, Result};
use crate::types::{Protocol, TextRule};

/// Regex pattern for parsing ACL rules
/// Format: outbound(address[, protoPort][, hijackAddress])
static RULE_PATTERN: Lazy<Regex> =
    Lazy::new(|| {
        Regex::new(r"^([\w.\-]+)\s*\(([^,]+)(?:,\s*([^,]+))?(?:,\s*([^,]+))?\)$")
            .expect("RULE_PATTERN: hardcoded regex is invalid")
    });

/// Maximum nesting depth for `file:` include directives.
const MAX_INCLUDE_DEPTH: usize = 10;

/// Parse ACL rules from text.
///
/// Supports `file: /path/to/rules.acl` directive to include rules from an external file.
pub fn parse_rules(text: &str) -> Result<Vec<TextRule>> {
    parse_rules_inner(text, 0)
}

fn parse_rules_inner(text: &str, depth: usize) -> Result<Vec<TextRule>> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(AclError::ParseError(format!(
            "file include depth exceeds maximum ({MAX_INCLUDE_DEPTH}), possible circular include"
        )));
    }

    let mut rules = Vec::new();

    for (line_num, line) in text.lines().enumerate() {
        let line_num = line_num + 1; // 1-based line numbers

        // Remove comments and trim whitespace
        let line = if let Some(comment_pos) = line.find('#') {
            &line[..comment_pos]
        } else {
            line
        };
        let line = line.trim();

        // Skip empty lines
        if line.is_empty() {
            continue;
        }

        // Handle file include directive
        if let Some(path) = line.strip_prefix("file:") {
            let path = path.trim();
            let file_rules = parse_rules_from_file_inner(path, depth + 1)?;
            rules.extend(file_rules);
            continue;
        }

        // Parse the rule
        let rule = parse_single_rule(line, line_num)?;
        rules.push(rule);
    }

    Ok(rules)
}

/// Parse ACL rules from a file.
pub fn parse_rules_from_file(path: impl AsRef<Path>) -> Result<Vec<TextRule>> {
    parse_rules_from_file_inner(path, 0)
}

fn parse_rules_from_file_inner(path: impl AsRef<Path>, depth: usize) -> Result<Vec<TextRule>> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).map_err(|e| {
        AclError::ParseError(format!(
            "Failed to read rules file '{}': {}",
            path.display(),
            e
        ))
    })?;
    parse_rules_inner(&text, depth)
}

/// Parse a single rule line
fn parse_single_rule(line: &str, line_num: usize) -> Result<TextRule> {
    let captures = RULE_PATTERN
        .captures(line)
        .ok_or_else(|| AclError::ParseErrorAtLine {
            line: line_num,
            message: format!("Invalid rule format: {}", line),
        })?;

    let outbound = captures.get(1).unwrap().as_str().to_string();
    let address = captures.get(2).unwrap().as_str().trim().to_string();
    if address.is_empty() {
        return Err(AclError::ParseErrorAtLine {
            line: line_num,
            message: "Empty address".to_string(),
        });
    }
    let proto_port = captures.get(3).map(|m| m.as_str().trim().to_string());
    let hijack_address = captures.get(4).map(|m| m.as_str().trim().to_string());

    Ok(TextRule {
        outbound,
        address,
        proto_port,
        hijack_address,
        line_num,
    })
}

/// Parse protocol/port specification
/// Examples: "tcp/443", "udp/53", "*/80-90", "tcp/8000-9000"
pub fn parse_proto_port(spec: &str) -> Result<(Protocol, u16, u16)> {
    let spec = spec.trim().to_lowercase();

    // Split by '/' using split_once to avoid Vec allocation
    let (proto_str, port_spec) = spec.split_once('/').ok_or_else(|| {
        AclError::InvalidProtoPort(format!("Invalid format: {}", spec))
    })?;

    // Parse protocol
    let protocol = match proto_str {
        "tcp" => Protocol::TCP,
        "udp" => Protocol::UDP,
        "*" => Protocol::Both,
        _ => {
            return Err(AclError::InvalidProtoPort(format!(
                "Unknown protocol: {}",
                proto_str
            )))
        }
    };

    // Parse port(s)
    let (start_port, end_port) = if let Some((start_str, end_str)) = port_spec.split_once('-') {
        // Port range
        let start: u16 = start_str
            .parse()
            .map_err(|_| AclError::InvalidProtoPort(format!("Invalid port: {}", port_spec)))?;
        let end: u16 = end_str
            .parse()
            .map_err(|_| AclError::InvalidProtoPort(format!("Invalid port: {}", port_spec)))?;
        if start > end {
            return Err(AclError::InvalidProtoPort(format!(
                "Invalid port range: {} > {}",
                start, end
            )));
        }
        (start, end)
    } else {
        // Single port
        let port: u16 = port_spec
            .parse()
            .map_err(|_| AclError::InvalidProtoPort(format!("Invalid port: {}", port_spec)))?;
        (port, port)
    };

    Ok((protocol, start_port, end_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_pattern_regex_compiles() {
        // Verify the static RULE_PATTERN regex initializes without panic.
        // Forces Lazy evaluation; if the pattern is invalid, this panics
        // with the expect message rather than an opaque unwrap.
        assert!(RULE_PATTERN.is_match("direct(all)"));
    }

    #[test]
    fn test_parse_simple_rule() {
        let text = "direct(192.168.0.0/16)";
        let rules = parse_rules(text).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].outbound, "direct");
        assert_eq!(rules[0].address, "192.168.0.0/16");
        assert!(rules[0].proto_port.is_none());
        assert!(rules[0].hijack_address.is_none());
    }

    #[test]
    fn test_parse_rule_with_port() {
        let text = "reject(all, udp/443)";
        let rules = parse_rules(text).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].outbound, "reject");
        assert_eq!(rules[0].address, "all");
        assert_eq!(rules[0].proto_port, Some("udp/443".to_string()));
    }

    #[test]
    fn test_parse_rule_with_hijack() {
        let text = "direct(all, udp/53, 127.0.0.1)";
        let rules = parse_rules(text).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].outbound, "direct");
        assert_eq!(rules[0].address, "all");
        assert_eq!(rules[0].proto_port, Some("udp/53".to_string()));
        assert_eq!(rules[0].hijack_address, Some("127.0.0.1".to_string()));
    }

    #[test]
    fn test_parse_multiple_rules() {
        let text = r#"
# Private networks
direct(192.168.0.0/16)
direct(10.0.0.0/8)

# Proxy for specific domains
proxy(*.google.com)
proxy(suffix:youtube.com)

# Block QUIC
reject(all, udp/443)

# Default
proxy(all)
"#;
        let rules = parse_rules(text).unwrap();
        assert_eq!(rules.len(), 6);
    }

    #[test]
    fn test_parse_proto_port() {
        let (proto, start, end) = parse_proto_port("tcp/443").unwrap();
        assert_eq!(proto, Protocol::TCP);
        assert_eq!(start, 443);
        assert_eq!(end, 443);

        let (proto, start, end) = parse_proto_port("udp/53").unwrap();
        assert_eq!(proto, Protocol::UDP);
        assert_eq!(start, 53);
        assert_eq!(end, 53);

        let (proto, start, end) = parse_proto_port("*/80-90").unwrap();
        assert_eq!(proto, Protocol::Both);
        assert_eq!(start, 80);
        assert_eq!(end, 90);

        let (proto, start, end) = parse_proto_port("TCP/8000-9000").unwrap();
        assert_eq!(proto, Protocol::TCP);
        assert_eq!(start, 8000);
        assert_eq!(end, 9000);
    }

    #[test]
    fn test_parse_invalid_rule() {
        let text = "invalid rule format";
        let result = parse_rules(text);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_inline_comment() {
        let text = "direct(192.168.0.0/16) # local network";
        let rules = parse_rules(text).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].address, "192.168.0.0/16");
    }

    #[test]
    fn test_parse_file_directive() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("acl_engine_test");
        let _ = fs::create_dir_all(&dir);
        let file_path = dir.join("test_rules.acl");
        let mut f = fs::File::create(&file_path).unwrap();
        writeln!(f, "proxy(*.google.com)").unwrap();
        writeln!(f, "direct(10.0.0.0/8)").unwrap();
        drop(f);

        let text = format!(
            "direct(192.168.0.0/16)\nfile: {}\nreject(all)",
            file_path.display()
        );
        let rules = parse_rules(&text).unwrap();
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].address, "192.168.0.0/16");
        assert_eq!(rules[1].address, "*.google.com");
        assert_eq!(rules[2].address, "10.0.0.0/8");
        assert_eq!(rules[3].address, "all");

        let _ = fs::remove_file(&file_path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_parse_file_directive_not_found() {
        let text = "file: /nonexistent/path/rules.acl";
        let result = parse_rules(text);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_proto_port_no_slash() {
        // split_once should handle missing '/' correctly
        let result = parse_proto_port("tcp443");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_proto_port_multiple_slashes() {
        // split_once splits at first '/', rest goes to port_spec which should fail
        let result = parse_proto_port("tcp/443/extra");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_proto_port_invalid_range() {
        let result = parse_proto_port("tcp/9000-8000");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_file_circular_include() {
        // Bug: file A includes file B, file B includes file A → stack overflow.
        // Should return an error instead of crashing.
        use std::io::Write;
        let dir = std::env::temp_dir().join("acl_engine_test_circular");
        let _ = fs::create_dir_all(&dir);

        let file_a = dir.join("a.acl");
        let file_b = dir.join("b.acl");

        // A includes B
        let mut f = fs::File::create(&file_a).unwrap();
        writeln!(f, "direct(10.0.0.0/8)").unwrap();
        writeln!(f, "file: {}", file_b.display()).unwrap();
        drop(f);

        // B includes A
        let mut f = fs::File::create(&file_b).unwrap();
        writeln!(f, "proxy(*.google.com)").unwrap();
        writeln!(f, "file: {}", file_a.display()).unwrap();
        drop(f);

        let result = parse_rules_from_file(&file_a);
        assert!(result.is_err(), "Circular file include should return error");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("include") || err_msg.contains("depth") || err_msg.contains("recursive"),
            "Error should mention include depth issue, got: {}",
            err_msg
        );

        let _ = fs::remove_file(&file_a);
        let _ = fs::remove_file(&file_b);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_parse_file_deep_nesting_limit() {
        // Even without circular refs, deeply nested includes should be rejected.
        use std::io::Write;
        let dir = std::env::temp_dir().join("acl_engine_test_deep");
        let _ = fs::create_dir_all(&dir);

        // Create a chain: file_0 includes file_1, file_1 includes file_2, ... file_19 includes file_20
        let depth = 21;
        let mut paths = Vec::new();
        for i in 0..depth {
            paths.push(dir.join(format!("depth_{}.acl", i)));
        }

        for i in 0..depth {
            let mut f = fs::File::create(&paths[i]).unwrap();
            writeln!(f, "direct(10.{}.0.0/16)", i).unwrap();
            if i + 1 < depth {
                writeln!(f, "file: {}", paths[i + 1].display()).unwrap();
            }
            drop(f);
        }

        let result = parse_rules_from_file(&paths[0]);
        assert!(result.is_err(), "Deeply nested includes should return error");

        for p in &paths {
            let _ = fs::remove_file(p);
        }
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_parse_rejects_empty_address() {
        // BUG: whitespace-only address like "direct(   )" should be rejected,
        // not silently create a rule that never matches anything.
        let text = "direct(   )";
        let result = parse_rules(text);
        assert!(
            result.is_err(),
            "Whitespace-only address should be rejected"
        );
    }

    #[test]
    fn test_parse_rejects_whitespace_only_fields() {
        // "direct(  , tcp/443)" — empty address with valid proto_port
        let text = "direct(  , tcp/443)";
        let result = parse_rules(text);
        assert!(
            result.is_err(),
            "Whitespace-only address with proto_port should be rejected"
        );
    }

    #[test]
    fn test_parse_proto_port_edge_ports() {
        let (proto, start, end) = parse_proto_port("tcp/0").unwrap();
        assert_eq!(proto, Protocol::TCP);
        assert_eq!(start, 0);
        assert_eq!(end, 0);

        let (proto, start, end) = parse_proto_port("tcp/65535").unwrap();
        assert_eq!(proto, Protocol::TCP);
        assert_eq!(start, 65535);
        assert_eq!(end, 65535);

        let (proto, start, end) = parse_proto_port("tcp/0-65535").unwrap();
        assert_eq!(proto, Protocol::TCP);
        assert_eq!(start, 0);
        assert_eq!(end, 65535);
    }

    #[test]
    fn test_parse_hyphenated_outbound_name() {
        // BUG #4: Outbound names with hyphens (e.g. "my-proxy") are rejected
        // because the regex uses \w+ which only matches [a-zA-Z0-9_].
        // Hyphenated names are common in proxy configurations.
        let text = "my-proxy(*.google.com)";
        let rules = parse_rules(text).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].outbound, "my-proxy");
        assert_eq!(rules[0].address, "*.google.com");
    }

    #[test]
    fn test_parse_dotted_outbound_name() {
        // Outbound names with dots (e.g. "us.west") should also work.
        let text = "us.west(10.0.0.0/8)";
        let rules = parse_rules(text).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].outbound, "us.west");
        assert_eq!(rules[0].address, "10.0.0.0/8");
    }
}
