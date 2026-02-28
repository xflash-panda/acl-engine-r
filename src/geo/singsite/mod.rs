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
    domain_index: HashMap<String, usize>,
    domain_length: HashMap<String, usize>,
    data_offset: u64,
}

impl SingSiteReader {
    /// Open a sing-geosite database file
    pub fn open(path: impl AsRef<Path>) -> Result<(Self, Vec<String>)> {
        let file = File::open(path.as_ref()).map_err(|e| {
            AclError::GeoSiteError(format!("Failed to open sing-geosite file: {}", e))
        })?;

        let mut reader = BufReader::new(file);
        let codes = Self::load_metadata(&mut reader)?;

        // Record the data offset after metadata (unused, we re-parse below)
        let _data_offset = reader
            .stream_position()
            .map_err(|e| AclError::GeoSiteError(format!("Failed to get stream position: {}", e)))?;

        let mut domain_index = HashMap::new();
        let mut domain_length = HashMap::new();

        // The metadata already parsed index and length info
        // We need to re-parse to get this info
        let file = reader.into_inner();
        let mut reader = BufReader::new(file);
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| AclError::GeoSiteError(format!("Failed to seek: {}", e)))?;

        // Skip version
        let _ = read_byte(&mut reader)?;

        // Read entry count
        let entry_count = read_uvarint(&mut reader)?;

        let mut current_index = 0usize;
        for _ in 0..entry_count {
            let code = read_vstring(&mut reader)?;
            let _code_index = read_uvarint(&mut reader)?;
            let code_length = read_uvarint(&mut reader)?;

            domain_index.insert(code.clone(), current_index);
            domain_length.insert(code.clone(), code_length as usize);
            current_index += code_length as usize;
        }

        let data_offset = reader
            .stream_position()
            .map_err(|e| AclError::GeoSiteError(format!("Failed to get stream position: {}", e)))?;

        Ok((
            Self {
                reader,
                domain_index,
                domain_length,
                data_offset,
            },
            codes,
        ))
    }

    /// Load metadata from the file
    fn load_metadata(reader: &mut BufReader<File>) -> Result<Vec<String>> {
        // Read version (must be 0)
        let version = read_byte(reader)?;
        if version != 0 {
            return Err(AclError::GeoSiteError(format!(
                "Unknown sing-geosite version: {}",
                version
            )));
        }

        // Read entry count
        let entry_count = read_uvarint(reader)?;

        let mut codes = Vec::with_capacity(entry_count as usize);

        for _ in 0..entry_count {
            let code = read_vstring(reader)?;
            let _code_index = read_uvarint(reader)?;
            let _code_length = read_uvarint(reader)?;
            codes.push(code);
        }

        Ok(codes)
    }

    /// Read domains for a specific code
    pub fn read(&mut self, code: &str) -> Result<Vec<DomainItem>> {
        let index = self
            .domain_index
            .get(code)
            .copied()
            .ok_or_else(|| AclError::GeoSiteError(format!("Code not found: {}", code)))?;

        let length = self.domain_length.get(code).copied().unwrap_or(0);

        // Seek to the start of data section
        self.reader
            .seek(SeekFrom::Start(self.data_offset))
            .map_err(|e| AclError::GeoSiteError(format!("Failed to seek: {}", e)))?;

        // Skip to the correct index by reading previous items
        for _ in 0..index {
            let _ = read_byte(&mut self.reader)?;
            let _ = read_vstring(&mut self.reader)?;
        }

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

/// Load GeoSite data from sing-geosite format (loads ALL codes - slow!)
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
