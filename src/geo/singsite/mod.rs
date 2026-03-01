use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{AclError, GeoErrorKind, Result};
use crate::matcher::{DomainEntry, DomainType};

/// Item types in sing-geosite format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ItemType {
    Domain = 0,        // Exact domain match
    DomainSuffix = 1,  // Domain suffix match
    DomainKeyword = 2, // Domain keyword (substring) match
    DomainRegex = 3,   // Domain regex match
}

impl TryFrom<u8> for ItemType {
    type Error = ();

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(ItemType::Domain),
            1 => Ok(ItemType::DomainSuffix),
            2 => Ok(ItemType::DomainKeyword),
            3 => Ok(ItemType::DomainRegex),
            _ => Err(()),
        }
    }
}

/// Domain item in sing-geosite format
#[derive(Debug, Clone)]
pub struct DomainItem {
    pub item_type: ItemType,
    pub value: String,
}

/// Sing-geosite reader
pub struct SingSiteReader {
    reader: BufReader<File>,
    domain_offset: HashMap<String, u64>,
    domain_length: HashMap<String, usize>,
}

impl SingSiteReader {
    /// Open a sing-geosite database file
    pub fn open(path: impl AsRef<Path>) -> Result<(Self, Vec<String>)> {
        let file = File::open(path.as_ref()).map_err(|e| AclError::GeoSiteError {
            kind: GeoErrorKind::FileError,
            message: format!("Failed to open sing-geosite file: {}", e),
        })?;

        let mut reader = BufReader::new(file);

        // Read version (must be 0)
        let version = read_byte(&mut reader)?;
        if version != 0 {
            return Err(AclError::GeoSiteError {
                kind: GeoErrorKind::InvalidData,
                message: format!("Unknown sing-geosite version: {}", version),
            });
        }

        // Read entry count
        let entry_count = read_uvarint(&mut reader)? as usize;

        // Parse metadata: collect codes and their item counts in file order
        let mut codes = Vec::with_capacity(entry_count);
        let mut code_lengths: Vec<(String, usize)> = Vec::with_capacity(entry_count);

        for _ in 0..entry_count {
            let code = read_vstring(&mut reader)?;
            let _code_index = read_uvarint(&mut reader)?;
            let code_length = read_uvarint(&mut reader)? as usize;
            codes.push(code.clone());
            code_lengths.push((code, code_length));
        }

        // Single sequential pass through data section to compute byte offsets
        let mut domain_offset = HashMap::with_capacity(entry_count);
        let mut domain_length = HashMap::with_capacity(entry_count);

        for (code, length) in &code_lengths {
            let offset = reader
                .stream_position()
                .map_err(|e| AclError::GeoSiteError {
                    kind: GeoErrorKind::FileError,
                    message: format!("Failed to get stream position: {}", e),
                })?;
            let lower_code = code.to_lowercase();
            domain_offset.insert(lower_code.clone(), offset);
            domain_length.insert(lower_code, *length);

            // Skip this code's items to advance to the next code
            for _ in 0..*length {
                let _ = read_byte(&mut reader)?;
                let _ = read_vstring(&mut reader)?;
            }
        }

        Ok((
            Self {
                reader,
                domain_offset,
                domain_length,
            },
            codes,
        ))
    }

    /// Read domains for a specific code
    pub fn read(&mut self, code: &str) -> Result<Vec<DomainItem>> {
        let code = code.to_lowercase();
        let offset =
            self.domain_offset
                .get(&code)
                .copied()
                .ok_or_else(|| AclError::GeoSiteError {
                    kind: GeoErrorKind::InvalidData,
                    message: format!("Code not found: {}", code),
                })?;

        let length = self.domain_length.get(&code).copied().unwrap_or(0);

        // Seek directly to this code's data
        self.reader
            .seek(SeekFrom::Start(offset))
            .map_err(|e| AclError::GeoSiteError {
                kind: GeoErrorKind::FileError,
                message: format!("Failed to seek: {}", e),
            })?;

        // Read the items for this code
        let mut items = Vec::with_capacity(length);
        for _ in 0..length {
            let item_type_byte = read_byte(&mut self.reader)?;
            let item_type =
                ItemType::try_from(item_type_byte).map_err(|_| AclError::GeoSiteError {
                    kind: GeoErrorKind::InvalidData,
                    message: format!("Unknown item type: {}", item_type_byte),
                })?;

            let value = read_vstring(&mut self.reader)?;

            items.push(DomainItem { item_type, value });
        }

        Ok(items)
    }
}

/// Load GeoSite data from sing-geosite format (loads ALL codes)
pub fn load_geosite(path: impl AsRef<Path>) -> Result<HashMap<String, Vec<DomainEntry>>> {
    let (mut reader, codes) = SingSiteReader::open(path)?;

    let mut result = HashMap::new();

    for code in &codes {
        let items = reader.read(code)?;
        let domains = convert_items_to_entries(items)?;
        result.insert(code.to_lowercase(), domains);
    }

    Ok(result)
}

/// Load a single GeoSite code from sing-geosite format (fast - lazy loading)
pub fn load_geosite_code(path: impl AsRef<Path>, code: &str) -> Result<Vec<DomainEntry>> {
    let (mut reader, _codes) = SingSiteReader::open(path)?;
    let items = reader.read(&code.to_lowercase())?;
    convert_items_to_entries(items)
}

/// Convert DomainItems to DomainEntries.
///
/// Returns `Err` if any regex pattern is invalid.
pub fn convert_items_to_entries(items: Vec<DomainItem>) -> Result<Vec<DomainEntry>> {
    let mut domains = Vec::with_capacity(items.len());

    for item in items {
        let domain_type = match item.item_type {
            ItemType::Domain => DomainType::Full(item.value.to_lowercase()),
            ItemType::DomainSuffix => {
                // sing-geosite stores suffix with leading dot, remove it
                let value = item.value.trim_start_matches('.').to_lowercase();
                let dot_pattern = format!(".{}", value);
                DomainType::RootDomain(value, dot_pattern)
            }
            ItemType::DomainKeyword => DomainType::Plain(item.value.to_lowercase()),
            ItemType::DomainRegex => match regex::Regex::new(&item.value) {
                Ok(re) => DomainType::Regex(re),
                Err(e) => {
                    return Err(AclError::GeoSiteError {
                        kind: GeoErrorKind::InvalidData,
                        message: format!("Invalid regex pattern '{}': {}", item.value, e),
                    });
                }
            },
        };

        domains.push(DomainEntry {
            domain_type,
            attributes: Vec::new(),
        });
    }

    Ok(domains)
}

/// Verify sing-geosite file integrity
pub fn verify(path: impl AsRef<Path>) -> Result<()> {
    let _ = SingSiteReader::open(path)?;
    Ok(())
}

// Helper functions for reading varint-encoded data

fn read_byte<R: Read>(reader: &mut R) -> Result<u8> {
    let mut buf = [0u8; 1];
    reader
        .read_exact(&mut buf)
        .map_err(|e| AclError::GeoSiteError {
            kind: GeoErrorKind::FileError,
            message: format!("Failed to read byte: {}", e),
        })?;
    Ok(buf[0])
}

fn read_uvarint<R: Read>(reader: &mut R) -> Result<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;

    loop {
        let byte = read_byte(reader)?;
        result |= ((byte & 0x7f) as u64) << shift;

        if byte & 0x80 == 0 {
            break;
        }

        shift += 7;
        if shift >= 64 {
            return Err(AclError::GeoSiteError {
                kind: GeoErrorKind::InvalidData,
                message: "Varint overflow".to_string(),
            });
        }
    }

    Ok(result)
}

/// Maximum allowed string length in sing-geosite format (10 MB).
/// Prevents OOM from malicious files with absurdly large varint lengths.
const MAX_VSTRING_LENGTH: usize = 10 * 1024 * 1024;

fn read_vstring<R: Read>(reader: &mut R) -> Result<String> {
    let length = read_uvarint(reader)? as usize;
    if length > MAX_VSTRING_LENGTH {
        return Err(AclError::GeoSiteError {
            kind: GeoErrorKind::InvalidData,
            message: format!(
                "String length {} exceeds limit of {} bytes",
                length, MAX_VSTRING_LENGTH
            ),
        });
    }
    let mut buf = vec![0u8; length];
    reader
        .read_exact(&mut buf)
        .map_err(|e| AclError::GeoSiteError {
            kind: GeoErrorKind::FileError,
            message: format!("Failed to read string: {}", e),
        })?;

    String::from_utf8(buf).map_err(|e| AclError::GeoSiteError {
        kind: GeoErrorKind::InvalidData,
        message: format!("Invalid UTF-8 string: {}", e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_vstring_rejects_huge_allocation() {
        // BUG #3: read_vstring reads a varint length and immediately allocates
        // vec![0u8; length] without bounds checking. A malicious file can encode
        // a varint with a huge value (e.g. 1GB+), causing OOM.
        //
        // The fix should add a maximum string length constant (e.g., 10MB)
        // and reject lengths exceeding it BEFORE allocation.
        //
        // Craft a varint encoding 100MB (0x6400000 = 104857600):
        // We provide enough backing data so read_exact would succeed if allocation happens.
        // The test verifies the function rejects based on LENGTH, not read failure.
        let length: u64 = 100 * 1024 * 1024; // 100MB

        // Encode as varint
        let mut varint_bytes = Vec::new();
        let mut val = length;
        while val >= 0x80 {
            varint_bytes.push((val as u8) | 0x80);
            val >>= 7;
        }
        varint_bytes.push(val as u8);

        // Add minimal trailing data (not 100MB — we want the length check to reject first)
        varint_bytes.extend_from_slice(b"short");

        let mut cursor = Cursor::new(varint_bytes);

        let result = read_vstring(&mut cursor);
        // Currently: allocates 100MB then read_exact fails because cursor is short.
        // After fix: should reject with error mentioning length limit BEFORE allocating.
        assert!(result.is_err(), "read_vstring should reject huge length");

        // Verify the error message mentions the length limit, not just IO failure
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("exceeds")
                || err_msg.contains("limit")
                || err_msg.contains("too large"),
            "Error should mention length limit, not just IO failure. Got: {}",
            err_msg
        );
    }

    #[test]
    fn test_read_vstring_normal_length_ok() {
        // Normal-length string should still work
        // varint 5 = 0x05, then "hello"
        let data: &[u8] = &[0x05, b'h', b'e', b'l', b'l', b'o'];
        let mut cursor = Cursor::new(data);
        let result = read_vstring(&mut cursor);
        assert_eq!(result.unwrap(), "hello");
    }

    /// Helper: encode u64 as varint bytes
    fn encode_uvarint(mut val: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        while val >= 0x80 {
            buf.push((val as u8) | 0x80);
            val >>= 7;
        }
        buf.push(val as u8);
        buf
    }

    /// Helper: encode a string as varint-length-prefixed bytes
    fn encode_vstring(s: &str) -> Vec<u8> {
        let mut buf = encode_uvarint(s.len() as u64);
        buf.extend_from_slice(s.as_bytes());
        buf
    }

    /// Helper: build a minimal sing-geosite binary file in memory
    fn build_singsite_file(entries: &[(&str, &[(&str, u8)])]) -> Vec<u8> {
        let mut data = Vec::new();
        // Version = 0
        data.push(0u8);
        // Entry count
        data.extend(encode_uvarint(entries.len() as u64));
        // Metadata: code, code_index, code_length for each entry
        for (i, (code, items)) in entries.iter().enumerate() {
            data.extend(encode_vstring(code));
            data.extend(encode_uvarint(i as u64)); // code_index
            data.extend(encode_uvarint(items.len() as u64));
        }
        // Data: items for each entry
        for (_code, items) in entries {
            for (value, item_type) in *items {
                data.push(*item_type);
                data.extend(encode_vstring(value));
            }
        }
        data
    }

    #[test]
    fn test_singsite_case_insensitive_lookup() {
        // BUG #9: SingSiteReader stores codes as-is from file (e.g. "GOOGLE"),
        // but load_geosite_code() calls reader.read(&code.to_lowercase()),
        // looking up "google" which doesn't exist in the map.
        let dir = std::env::temp_dir().join("acl_engine_test_singsite_case");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("test_case.srs");

        // Build a file with UPPERCASE code "GOOGLE"
        let file_data = build_singsite_file(&[
            ("GOOGLE", &[("google.com", 0)]), // uppercase code
        ]);
        std::fs::write(&file_path, &file_data).unwrap();

        // load_geosite_code lowercases the code, so it should find "google" → "GOOGLE"
        let result = load_geosite_code(&file_path, "google");
        assert!(
            result.is_ok(),
            "Lowercase lookup of UPPERCASE code should succeed, got: {:?}",
            result.err()
        );
        let entries = result.unwrap();
        assert_eq!(entries.len(), 1);

        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_singsite_mixed_case_lookup() {
        let dir = std::env::temp_dir().join("acl_engine_test_singsite_mixed");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("test_mixed.srs");

        // Build with mixed-case code "Google"
        let file_data =
            build_singsite_file(&[("Google", &[("google.com", 0), (".google.com", 1)])]);
        std::fs::write(&file_path, &file_data).unwrap();

        // Should find via lowercase
        let result = load_geosite_code(&file_path, "google");
        assert!(
            result.is_ok(),
            "Lowercase lookup of mixed-case code should succeed, got: {:?}",
            result.err()
        );

        // Should also find via uppercase
        let result = load_geosite_code(&file_path, "GOOGLE");
        assert!(
            result.is_ok(),
            "Uppercase lookup of mixed-case code should succeed, got: {:?}",
            result.err()
        );

        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_convert_items_returns_error_on_invalid_regex() {
        // B1: convert_items_to_entries should return Err for invalid regex,
        // not silently skip it.
        let items = vec![
            DomainItem {
                item_type: ItemType::Domain,
                value: "good.com".to_string(),
            },
            DomainItem {
                item_type: ItemType::DomainRegex,
                value: "[invalid(regex".to_string(),
            },
        ];

        let result = convert_items_to_entries(items);
        assert!(
            result.is_err(),
            "invalid regex should return Err, not silently skip"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("[invalid(regex"),
            "error should mention the bad pattern, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_convert_items_valid_regex_succeeds() {
        let items = vec![DomainItem {
            item_type: ItemType::DomainRegex,
            value: r"^google\.com$".to_string(),
        }];

        let result = convert_items_to_entries(items);
        assert!(result.is_ok(), "valid regex should succeed");
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_load_geosite_code_returns_error_on_invalid_regex() {
        // B1: load_geosite_code should propagate invalid regex errors.
        let dir = std::env::temp_dir().join("acl_engine_test_singsite_regex");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("test_bad_regex.srs");

        // item_type 3 = DomainRegex
        let file_data = build_singsite_file(&[("test", &[("good.com", 0), ("[broken(regex", 3)])]);
        std::fs::write(&file_path, &file_data).unwrap();

        let result = load_geosite_code(&file_path, "test");
        assert!(
            result.is_err(),
            "load_geosite_code should return error for invalid regex, not silently skip"
        );

        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir(&dir);
    }
}
