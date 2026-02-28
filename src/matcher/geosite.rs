use std::collections::HashMap;

use regex::Regex;

use super::domain::SuccinctMatcher;
use super::HostMatcher;
use crate::types::HostInfo;

/// Domain type in GeoSite
#[derive(Debug, Clone)]
pub enum DomainType {
    /// Plain text substring match
    Plain(String),
    /// Regex pattern match
    Regex(Regex),
    /// Exact domain match (full match)
    Full(String),
    /// Root domain match (domain + all subdomains).
    /// Stores (pattern, dot_pattern) where dot_pattern = ".{pattern}" pre-computed.
    RootDomain(String, String),
}

/// A domain entry with optional attributes.
/// Uses Vec instead of HashMap for attributes since most entries have 0-1 attributes.
#[derive(Debug, Clone)]
pub struct DomainEntry {
    pub domain_type: DomainType,
    pub attributes: Vec<(String, String)>,
}

impl DomainEntry {
    pub fn new_plain(domain: &str) -> Self {
        Self {
            domain_type: DomainType::Plain(domain.to_lowercase()),
            attributes: Vec::new(),
        }
    }

    pub fn new_regex(pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            domain_type: DomainType::Regex(Regex::new(pattern)?),
            attributes: Vec::new(),
        })
    }

    pub fn new_full(domain: &str) -> Self {
        Self {
            domain_type: DomainType::Full(domain.to_lowercase()),
            attributes: Vec::new(),
        }
    }

    pub fn new_root_domain(domain: &str) -> Self {
        let pattern = domain.to_lowercase();
        let dot_pattern = format!(".{}", pattern);
        Self {
            domain_type: DomainType::RootDomain(pattern, dot_pattern),
            attributes: Vec::new(),
        }
    }

    pub fn with_attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.push((key.to_string(), value.to_string()));
        self
    }

    /// Check if the domain matches this entry.
    /// Assumes `name` is already lowercased (as guaranteed by HostInfo constructors).
    pub fn matches(&self, name: &str) -> bool {
        match &self.domain_type {
            DomainType::Plain(pattern) => name.contains(pattern),
            DomainType::Regex(re) => re.is_match(name),
            DomainType::Full(pattern) => name == *pattern,
            DomainType::RootDomain(pattern, dot_pattern) => {
                name == *pattern || name.ends_with(dot_pattern.as_str())
            }
        }
    }

    /// Check if this entry has all required attributes
    pub fn has_attributes(&self, required: &HashMap<String, Option<String>>) -> bool {
        for (key, value) in required {
            let found = self.attributes.iter().find(|(k, _)| k == key);
            match (found, value) {
                (None, _) => return false,
                (Some((_, v)), Some(expected)) if v != expected => return false,
                _ => {}
            }
        }
        true
    }
}

/// GeoSite matcher - matches domain names against a site list
///
/// Uses a hybrid matching strategy:
/// - `Full` and `RootDomain` types use Succinct Trie for O(domain_length) matching
/// - `Plain` and `Regex` types fall back to linear scanning
#[derive(Debug)]
pub struct GeoSiteMatcher {
    site_name: String,
    /// Succinct Trie for Full/RootDomain types (fast path)
    succinct: Option<SuccinctMatcher>,
    /// Fallback entries for Plain/Regex types (slow path)
    fallback_domains: Vec<DomainEntry>,
    /// All domains (only kept when attribute filtering may be needed via with_attributes)
    all_domains: Option<Vec<DomainEntry>>,
}

impl GeoSiteMatcher {
    /// Create a new GeoSite matcher with optimized domain matching
    pub fn new(site_name: &str, domains: Vec<DomainEntry>) -> Self {
        let mut exact_domains: Vec<String> = Vec::new();
        let mut suffix_domains: Vec<String> = Vec::new();
        let mut fallback_domains: Vec<DomainEntry> = Vec::new();

        // Separate domains by type
        for entry in &domains {
            match &entry.domain_type {
                DomainType::Full(domain) => {
                    exact_domains.push(domain.clone());
                }
                DomainType::RootDomain(domain, _) => {
                    suffix_domains.push(domain.clone());
                }
                DomainType::Plain(_) | DomainType::Regex(_) => {
                    fallback_domains.push(entry.clone());
                }
            }
        }

        // Build Succinct Trie if we have domains for it
        let succinct = if exact_domains.is_empty() && suffix_domains.is_empty() {
            None
        } else {
            Some(SuccinctMatcher::new(&exact_domains, &suffix_domains))
        };

        Self {
            site_name: site_name.to_lowercase(),
            succinct,
            fallback_domains,
            all_domains: Some(domains),
        }
    }

    /// Parse a GeoSite pattern like "google@cn" or "netflix"
    pub fn parse_pattern(pattern: &str) -> (String, HashMap<String, Option<String>>) {
        let parts: Vec<&str> = pattern.split('@').collect();
        let site_name = parts[0].to_lowercase();
        let mut attrs = HashMap::new();

        for attr in parts.iter().skip(1) {
            // Attribute can be "key" or "key=value"
            if let Some(eq_pos) = attr.find('=') {
                let key = &attr[..eq_pos];
                let value = &attr[eq_pos + 1..];
                attrs.insert(key.to_string(), Some(value.to_string()));
            } else {
                attrs.insert(attr.to_string(), None);
            }
        }

        (site_name, attrs)
    }

    /// Set required attributes for matching.
    /// Consumes all_domains to rebuild filtered matchers, then drops it to free memory.
    pub fn with_attributes(mut self, attrs: HashMap<String, Option<String>>) -> Self {
        if !attrs.is_empty() {
            if let Some(all_domains) = self.all_domains.take() {
                // Pre-filter: only keep domains that have the required attributes
                let mut exact_domains: Vec<String> = Vec::new();
                let mut suffix_domains: Vec<String> = Vec::new();
                let mut fallback: Vec<DomainEntry> = Vec::new();

                for entry in &all_domains {
                    if !entry.has_attributes(&attrs) {
                        continue;
                    }

                    match &entry.domain_type {
                        DomainType::Full(domain) => {
                            exact_domains.push(domain.clone());
                        }
                        DomainType::RootDomain(domain, _) => {
                            suffix_domains.push(domain.clone());
                        }
                        DomainType::Plain(_) | DomainType::Regex(_) => {
                            fallback.push(entry.clone());
                        }
                    }
                }

                // Rebuild succinct matcher with filtered domains
                self.succinct = if exact_domains.is_empty() && suffix_domains.is_empty() {
                    None
                } else {
                    Some(SuccinctMatcher::new(&exact_domains, &suffix_domains))
                };

                self.fallback_domains = fallback;
            }
        }

        // Drop all_domains to free memory — filtering is done
        self.all_domains = None;
        self
    }

    /// Get the site name
    pub fn site_name(&self) -> &str {
        &self.site_name
    }
}

impl HostMatcher for GeoSiteMatcher {
    fn matches(&self, host: &HostInfo) -> bool {
        if host.name.is_empty() {
            return false;
        }

        let name = &host.name;

        // Fast path: use Succinct Trie for Full/RootDomain (when no attributes required)
        if let Some(ref succinct) = self.succinct {
            if succinct.matches(name) {
                return true;
            }
        }

        // Slow path: linear scan for Plain/Regex types
        for entry in &self.fallback_domains {
            if entry.matches(name) {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_entry_plain() {
        let entry = DomainEntry::new_plain("google");
        assert!(entry.matches("google.com"));
        assert!(entry.matches("www.google.com"));
        assert!(entry.matches("mail.google.co.uk"));
        assert!(!entry.matches("example.com"));
    }

    #[test]
    fn test_domain_entry_full() {
        let entry = DomainEntry::new_full("google.com");
        assert!(entry.matches("google.com"));
        assert!(!entry.matches("www.google.com"));
        assert!(!entry.matches("google.co.uk"));
    }

    #[test]
    fn test_domain_entry_root_domain() {
        let entry = DomainEntry::new_root_domain("google.com");
        assert!(entry.matches("google.com"));
        assert!(entry.matches("www.google.com"));
        assert!(entry.matches("mail.google.com"));
        assert!(!entry.matches("google.co.uk"));
    }

    #[test]
    fn test_domain_entry_regex() {
        let entry = DomainEntry::new_regex(r"^[a-z]+\.google\.com$").unwrap();
        assert!(entry.matches("www.google.com"));
        assert!(entry.matches("mail.google.com"));
        assert!(!entry.matches("www.sub.google.com"));
    }

    #[test]
    fn test_geosite_matcher() {
        let domains = vec![
            DomainEntry::new_root_domain("google.com"),
            DomainEntry::new_root_domain("youtube.com"),
            DomainEntry::new_full("googleapis.com"),
        ];
        let matcher = GeoSiteMatcher::new("google", domains);

        assert!(matcher.matches(&HostInfo::from_name("google.com")));
        assert!(matcher.matches(&HostInfo::from_name("www.google.com")));
        assert!(matcher.matches(&HostInfo::from_name("youtube.com")));
        assert!(matcher.matches(&HostInfo::from_name("googleapis.com")));
        assert!(!matcher.matches(&HostInfo::from_name("www.googleapis.com")));
        assert!(!matcher.matches(&HostInfo::from_name("example.com")));
    }

    #[test]
    fn test_geosite_with_attributes() {
        let domains = vec![
            DomainEntry::new_root_domain("google.com").with_attribute("cn", ""),
            DomainEntry::new_root_domain("google.cn"),
        ];
        let mut attrs = HashMap::new();
        attrs.insert("cn".to_string(), None);

        let matcher = GeoSiteMatcher::new("google", domains).with_attributes(attrs);

        // Only matches domains with @cn attribute
        assert!(matcher.matches(&HostInfo::from_name("google.com")));
        assert!(!matcher.matches(&HostInfo::from_name("google.cn"))); // No @cn attribute
    }

    #[test]
    fn test_parse_pattern() {
        let (name, attrs) = GeoSiteMatcher::parse_pattern("google@cn");
        assert_eq!(name, "google");
        assert!(attrs.contains_key("cn"));
        assert_eq!(attrs.get("cn"), Some(&None));

        let (name, attrs) = GeoSiteMatcher::parse_pattern("netflix@region=us");
        assert_eq!(name, "netflix");
        assert_eq!(attrs.get("region"), Some(&Some("us".to_string())));
    }

    #[test]
    fn test_geosite_with_plain_and_regex() {
        let domains = vec![
            DomainEntry::new_root_domain("google.com"),
            DomainEntry::new_plain("facebook"),
            DomainEntry::new_regex(r".*\.twitter\.com$").unwrap(),
        ];
        let matcher = GeoSiteMatcher::new("social", domains);

        // RootDomain via Succinct Trie
        assert!(matcher.matches(&HostInfo::from_name("google.com")));
        assert!(matcher.matches(&HostInfo::from_name("www.google.com")));

        // Plain via fallback
        assert!(matcher.matches(&HostInfo::from_name("facebook.com")));
        assert!(matcher.matches(&HostInfo::from_name("www.facebook.com")));

        // Regex via fallback
        assert!(matcher.matches(&HostInfo::from_name("api.twitter.com")));
        assert!(!matcher.matches(&HostInfo::from_name("twitter.com"))); // Regex requires subdomain
    }

    #[test]
    fn test_geosite_empty() {
        let matcher = GeoSiteMatcher::new("empty", vec![]);
        assert!(!matcher.matches(&HostInfo::from_name("google.com")));
    }

    #[test]
    fn test_geosite_attribute_filtering_only_matching() {
        // Create domains where only some have the "cn" attribute
        let domains = vec![
            DomainEntry::new_root_domain("google.com").with_attribute("cn", ""),
            DomainEntry::new_root_domain("google.co.jp"), // no cn attribute
            DomainEntry::new_full("special.google.com").with_attribute("cn", ""),
            DomainEntry::new_plain("facebook").with_attribute("cn", ""),
            DomainEntry::new_root_domain("youtube.com"), // no cn attribute
        ];

        let mut attrs = HashMap::new();
        attrs.insert("cn".to_string(), None);

        let matcher = GeoSiteMatcher::new("test", domains).with_attributes(attrs);

        // Should match: has @cn attribute
        assert!(matcher.matches(&HostInfo::from_name("google.com")));
        assert!(matcher.matches(&HostInfo::from_name("www.google.com")));
        assert!(matcher.matches(&HostInfo::from_name("special.google.com")));
        assert!(matcher.matches(&HostInfo::from_name("facebook.com")));

        // Should NOT match: no @cn attribute
        assert!(!matcher.matches(&HostInfo::from_name("google.co.jp")));
        assert!(!matcher.matches(&HostInfo::from_name("youtube.com")));
        assert!(!matcher.matches(&HostInfo::from_name("www.youtube.com")));
    }

    #[test]
    fn test_geosite_no_attributes_uses_succinct() {
        // Without attributes, Full/RootDomain should use the fast succinct path
        let domains = vec![
            DomainEntry::new_root_domain("google.com"),
            DomainEntry::new_full("exact.example.com"),
            DomainEntry::new_plain("facebook"),
        ];

        let matcher = GeoSiteMatcher::new("test", domains);

        // Succinct path (RootDomain)
        assert!(matcher.matches(&HostInfo::from_name("google.com")));
        assert!(matcher.matches(&HostInfo::from_name("www.google.com")));

        // Succinct path (Full)
        assert!(matcher.matches(&HostInfo::from_name("exact.example.com")));
        assert!(!matcher.matches(&HostInfo::from_name("other.example.com")));

        // Fallback path (Plain)
        assert!(matcher.matches(&HostInfo::from_name("facebook.com")));
    }

    #[test]
    fn test_root_domain_precomputed_dot_pattern() {
        // Verify RootDomain pre-computes dot_pattern (no format! per match)
        let entry = DomainEntry::new_root_domain("example.com");
        match &entry.domain_type {
            DomainType::RootDomain(pattern, dot_pattern) => {
                assert_eq!(pattern, "example.com");
                assert_eq!(dot_pattern, ".example.com");
            }
            _ => panic!("expected RootDomain"),
        }
        // Verify matching still works correctly
        assert!(entry.matches("example.com"));
        assert!(entry.matches("sub.example.com"));
        assert!(entry.matches("deep.sub.example.com"));
        assert!(!entry.matches("notexample.com"));
        assert!(!entry.matches("example.org"));
    }

    #[test]
    fn test_domain_entry_matches_no_redundant_lowercase() {
        // DomainEntry::matches assumes input is already lowercased
        // Patterns are stored lowercased at construction time
        let plain = DomainEntry::new_plain("Google");
        assert!(plain.matches("google.com")); // pattern stored as "google"

        let full = DomainEntry::new_full("Google.COM");
        assert!(full.matches("google.com")); // pattern stored as "google.com"

        let root = DomainEntry::new_root_domain("Google.COM");
        assert!(root.matches("google.com"));
        assert!(root.matches("sub.google.com"));
    }

    #[test]
    fn test_domain_entry_vec_attributes() {
        // Verify Vec-based attributes work correctly
        let entry = DomainEntry::new_root_domain("google.com")
            .with_attribute("cn", "")
            .with_attribute("region", "asia");

        assert_eq!(entry.attributes.len(), 2);

        let mut required = HashMap::new();
        required.insert("cn".to_string(), None);
        assert!(entry.has_attributes(&required));

        let mut required2 = HashMap::new();
        required2.insert("region".to_string(), Some("asia".to_string()));
        assert!(entry.has_attributes(&required2));

        let mut required3 = HashMap::new();
        required3.insert("region".to_string(), Some("europe".to_string()));
        assert!(!entry.has_attributes(&required3));

        let mut required4 = HashMap::new();
        required4.insert("missing".to_string(), None);
        assert!(!entry.has_attributes(&required4));
    }

    #[test]
    fn test_all_domains_dropped_after_with_attributes() {
        let domains = vec![
            DomainEntry::new_root_domain("google.com").with_attribute("cn", ""),
            DomainEntry::new_root_domain("youtube.com"),
        ];

        // Before with_attributes: all_domains is Some
        let matcher = GeoSiteMatcher::new("test", domains);
        assert!(matcher.all_domains.is_some());

        // After with_attributes: all_domains is None (memory freed)
        let mut attrs = HashMap::new();
        attrs.insert("cn".to_string(), None);
        let matcher = matcher.with_attributes(attrs);
        assert!(matcher.all_domains.is_none());

        // Matching still works
        assert!(matcher.matches(&HostInfo::from_name("google.com")));
        assert!(!matcher.matches(&HostInfo::from_name("youtube.com")));
    }

    #[test]
    fn test_all_domains_dropped_with_empty_attributes() {
        let domains = vec![DomainEntry::new_root_domain("google.com")];
        let matcher = GeoSiteMatcher::new("test", domains).with_attributes(HashMap::new());

        // Even with empty attrs, all_domains should be dropped
        assert!(matcher.all_domains.is_none());
        assert!(matcher.matches(&HostInfo::from_name("google.com")));
    }
}
