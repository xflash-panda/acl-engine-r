use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{AclError, Result};
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
        let file = File::open(path.as_ref()).map_err(|e| {
            AclError::GeoSiteError(format!("Failed to open sing-geosite file: {}", e))
        })?;

        let mut reader = BufReader::new(file);

        // Read version (must be 0)
        let version = read_byte(&mut reader)?;
        if version != 0 {
            return Err(AclError::GeoSiteError(format!(
                "Unknown sing-geosite version: {}",
                version
            )));
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
            let offset = reader.stream_position().map_err(|e| {
                AclError::GeoSiteError(format!("Failed to get stream position: {}", e))
            })?;
            domain_offset.insert(code.clone(), offset);
            domain_length.insert(code.clone(), *length);

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
        let offset = self
            .domain_offset
            .get(code)
            .copied()
            .ok_or_else(|| AclError::GeoSiteError(format!("Code not found: {}", code)))?;

        let length = self.domain_length.get(code).copied().unwrap_or(0);

        // Seek directly to this code's data
        self.reader
            .seek(SeekFrom::Start(offset))
            .map_err(|e| AclError::GeoSiteError(format!("Failed to seek: {}", e)))?;

        // Read the items for this code
        let mut items = Vec::with_capacity(length);
        for _ in 0..length {
            let item_type_byte = read_byte(&mut self.reader)?;
            let item_type = ItemType::try_from(item_type_byte).map_err(|_| {
                AclError::GeoSiteError(format!("Unknown item type: {}", item_type_byte))
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
        let domains = convert_items_to_entries(items);
        result.insert(code.to_lowercase(), domains);
    }

    Ok(result)
}

/// Load a single GeoSite code from sing-geosite format (fast - lazy loading)
pub fn load_geosite_code(path: impl AsRef<Path>, code: &str) -> Result<Vec<DomainEntry>> {
    let (mut reader, _codes) = SingSiteReader::open(path)?;
    let items = reader.read(&code.to_lowercase())?;
    Ok(convert_items_to_entries(items))
}

/// Convert DomainItems to DomainEntries
pub fn convert_items_to_entries(items: Vec<DomainItem>) -> Vec<DomainEntry> {
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
                Err(_) => continue,
            },
        };

        domains.push(DomainEntry {
            domain_type,
            attributes: Vec::new(),
        });
    }

    domains
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
        .map_err(|e| AclError::GeoSiteError(format!("Failed to read byte: {}", e)))?;
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
            return Err(AclError::GeoSiteError("Varint overflow".to_string()));
        }
    }

    Ok(result)
}

fn read_vstring<R: Read>(reader: &mut R) -> Result<String> {
    let length = read_uvarint(reader)? as usize;
    let mut buf = vec![0u8; length];
    reader
        .read_exact(&mut buf)
        .map_err(|e| AclError::GeoSiteError(format!("Failed to read string: {}", e)))?;

    String::from_utf8(buf)
        .map_err(|e| AclError::GeoSiteError(format!("Invalid UTF-8 string: {}", e)))
}
