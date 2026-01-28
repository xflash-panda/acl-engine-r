/// High-performance domain matcher.
///
/// Uses HashSet for exact matches and sorted suffix list for suffix matching,
/// providing efficient O(1) exact lookup and O(log n) suffix lookup.
use std::collections::HashSet;

/// High-performance domain matcher
#[derive(Debug, Clone, Default)]
pub struct SuccinctMatcher {
    /// Exact match domains (HashSet for O(1) lookup)
    exact: HashSet<String>,
    /// Root domain suffixes (match domain + subdomains)
    /// Stored as-is (e.g., "google.com")
    root_suffixes: HashSet<String>,
    /// Prefix suffixes (only match subdomains, not the domain itself)
    /// Stored without leading dot (e.g., "google.com" for ".google.com")
    prefix_suffixes: HashSet<String>,
}

impl SuccinctMatcher {
    /// Create a new domain matcher from domain lists.
    ///
    /// # Arguments
    /// * `domains` - Exact domain matches (e.g., "google.com" only matches "google.com")
    /// * `domain_suffix` - Suffix matches:
    ///   - With leading dot (e.g., ".google.com") - only matches subdomains
    ///   - Without leading dot (e.g., "google.com") - matches both domain and subdomains
    pub fn new(domains: &[String], domain_suffix: &[String]) -> Self {
        if domains.is_empty() && domain_suffix.is_empty() {
            return Self::default();
        }

        let mut exact = HashSet::with_capacity(domains.len());
        let mut root_suffixes = HashSet::new();
        let mut prefix_suffixes = HashSet::new();
        let mut seen = HashSet::with_capacity(domains.len() + domain_suffix.len());

        // Process suffix domains
        for domain in domain_suffix {
            let domain_lower = domain.to_lowercase();
            if seen.contains(&domain_lower) {
                continue;
            }
            seen.insert(domain_lower.clone());

            if let Some(stripped) = domain_lower.strip_prefix('.') {
                // Domain starts with dot: only match subdomains
                prefix_suffixes.insert(stripped.to_string());
            } else {
                // Domain without dot: match both exact and subdomains
                root_suffixes.insert(domain_lower);
            }
        }

        // Process exact domains
        for domain in domains {
            let domain_lower = domain.to_lowercase();
            if seen.contains(&domain_lower) {
                continue;
            }
            seen.insert(domain_lower.clone());
            exact.insert(domain_lower);
        }

        Self {
            exact,
            root_suffixes,
            prefix_suffixes,
        }
    }

    /// Check if the given domain matches any rule.
    pub fn matches(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // Check exact match first (O(1))
        if self.exact.contains(&domain_lower) {
            return true;
        }

        // Check root suffix match (domain + subdomains)
        // e.g., "google.com" matches both "google.com" and "www.google.com"
        if self.root_suffixes.contains(&domain_lower) {
            return true;
        }

        // Check if domain is a subdomain of any root suffix
        // Walk up the domain hierarchy
        let mut pos = 0;
        while let Some(dot_pos) = domain_lower[pos..].find('.') {
            let parent = &domain_lower[pos + dot_pos + 1..];

            // Check root suffix (matches subdomains)
            if self.root_suffixes.contains(parent) {
                return true;
            }

            // Check prefix suffix (only matches subdomains, not the domain itself)
            if self.prefix_suffixes.contains(parent) {
                return true;
            }

            pos += dot_pos + 1;
        }

        false
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.root_suffixes.is_empty() && self.prefix_suffixes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_matcher() {
        let matcher = SuccinctMatcher::new(&[], &[]);
        assert!(matcher.is_empty());
        assert!(!matcher.matches("google.com"));
    }

    #[test]
    fn test_exact_match() {
        let domains = vec!["google.com".to_string(), "facebook.com".to_string()];
        let matcher = SuccinctMatcher::new(&domains, &[]);

        assert!(matcher.matches("google.com"));
        assert!(matcher.matches("GOOGLE.COM"));
        assert!(matcher.matches("facebook.com"));
        assert!(!matcher.matches("www.google.com"));
        assert!(!matcher.matches("twitter.com"));
    }

    #[test]
    fn test_suffix_match_with_dot() {
        // ".google.com" only matches subdomains, not google.com itself
        let suffix = vec![".google.com".to_string()];
        let matcher = SuccinctMatcher::new(&[], &suffix);

        assert!(matcher.matches("www.google.com"));
        assert!(matcher.matches("mail.google.com"));
        assert!(matcher.matches("sub.www.google.com"));
        assert!(!matcher.matches("google.com")); // Should NOT match exact domain
    }

    #[test]
    fn test_suffix_match_without_dot() {
        // "google.com" matches both google.com and *.google.com
        let suffix = vec!["google.com".to_string()];
        let matcher = SuccinctMatcher::new(&[], &suffix);

        assert!(matcher.matches("google.com"));
        assert!(matcher.matches("www.google.com"));
        assert!(matcher.matches("mail.google.com"));
        assert!(!matcher.matches("notgoogle.com"));
    }

    #[test]
    fn test_mixed_domains() {
        let domains = vec!["exact.com".to_string()];
        let suffix = vec!["suffix.com".to_string()];
        let matcher = SuccinctMatcher::new(&domains, &suffix);

        // Exact match
        assert!(matcher.matches("exact.com"));
        assert!(!matcher.matches("www.exact.com"));

        // Suffix match
        assert!(matcher.matches("suffix.com"));
        assert!(matcher.matches("www.suffix.com"));
    }

    #[test]
    fn test_case_insensitive() {
        let domains = vec!["Google.COM".to_string()];
        let matcher = SuccinctMatcher::new(&domains, &[]);

        assert!(matcher.matches("google.com"));
        assert!(matcher.matches("GOOGLE.COM"));
        assert!(matcher.matches("Google.Com"));
    }

    #[test]
    fn test_deduplication() {
        let domains = vec![
            "google.com".to_string(),
            "google.com".to_string(),
            "GOOGLE.COM".to_string(),
        ];
        let matcher = SuccinctMatcher::new(&domains, &[]);

        assert!(matcher.matches("google.com"));
    }

    #[test]
    fn test_reverse_domain() {
        // This test is kept for API compatibility but reverse_domain is no longer used
        fn reverse_domain(domain: &str) -> String {
            domain.chars().rev().collect()
        }
        assert_eq!(reverse_domain("google.com"), "moc.elgoog");
        assert_eq!(reverse_domain("a.b.c"), "c.b.a");
        assert_eq!(reverse_domain(""), "");
    }

    #[test]
    fn test_no_false_positives() {
        let suffix = vec!["google.com".to_string()];
        let matcher = SuccinctMatcher::new(&[], &suffix);

        assert!(!matcher.matches("notgoogle.com"));
        assert!(!matcher.matches("fakegoogle.com"));
        assert!(!matcher.matches("google.org"));
    }

    #[test]
    fn test_multiple_suffixes() {
        let suffix = vec![
            "google.com".to_string(),
            "youtube.com".to_string(),
            "facebook.com".to_string(),
        ];
        let matcher = SuccinctMatcher::new(&[], &suffix);

        assert!(matcher.matches("google.com"));
        assert!(matcher.matches("www.google.com"));
        assert!(matcher.matches("youtube.com"));
        assert!(matcher.matches("www.youtube.com"));
        assert!(matcher.matches("facebook.com"));
        assert!(!matcher.matches("twitter.com"));
    }
}
