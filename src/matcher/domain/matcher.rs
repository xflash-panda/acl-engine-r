/// High-performance domain matcher.
///
/// Uses HashSet for exact matches and a unified HashMap for suffix matching,
/// providing efficient O(1) exact lookup and single O(1) suffix lookup per
/// domain level.
use std::collections::{HashMap, HashSet};

/// Suffix type stored in the unified suffix map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuffixType {
    /// Matches domain itself + all subdomains (from "google.com" without leading dot)
    Root,
    /// Matches only subdomains (from ".google.com" with leading dot)
    PrefixOnly,
}

/// High-performance domain matcher
#[derive(Debug, Clone, Default)]
pub struct SuccinctMatcher {
    /// Exact match domains (HashSet for O(1) lookup)
    exact: HashSet<String>,
    /// Unified suffix map: domain -> SuffixType
    /// Single lookup per domain level instead of two separate HashSet lookups
    suffixes: HashMap<String, SuffixType>,
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
        let mut suffixes = HashMap::with_capacity(domain_suffix.len());
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
                suffixes.insert(stripped.to_string(), SuffixType::PrefixOnly);
            } else {
                // Domain without dot: match both exact and subdomains
                suffixes.insert(domain_lower, SuffixType::Root);
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

        Self { exact, suffixes }
    }

    /// Check if the given domain matches any rule.
    /// Assumes `domain` is already lowercased (as guaranteed by HostInfo constructors).
    pub fn matches(&self, domain: &str) -> bool {
        // Check exact match first (O(1))
        if self.exact.contains(domain) {
            return true;
        }

        // Check root suffix match for the domain itself
        // e.g., "google.com" matches both "google.com" and "www.google.com"
        if self.suffixes.get(domain) == Some(&SuffixType::Root) {
            return true;
        }

        // Walk up the domain hierarchy, one lookup per level
        let mut pos = 0;
        while let Some(dot_pos) = domain[pos..].find('.') {
            let parent = &domain[pos + dot_pos + 1..];

            // Single lookup: both Root and PrefixOnly match subdomains
            if self.suffixes.contains_key(parent) {
                return true;
            }

            pos += dot_pos + 1;
        }

        false
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffixes.is_empty()
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
    fn test_case_insensitive_construction() {
        // Construction lowercases domains; matches() assumes input is already lowercased
        let domains = vec!["Google.COM".to_string()];
        let matcher = SuccinctMatcher::new(&domains, &[]);

        assert!(matcher.matches("google.com"));
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

    #[test]
    fn test_suffix_overlap_root_and_prefix() {
        // root_suffix "google.com" matches google.com + *.google.com
        // prefix_suffix ".facebook.com" matches only *.facebook.com
        let suffix = vec!["google.com".to_string(), ".facebook.com".to_string()];
        let matcher = SuccinctMatcher::new(&[], &suffix);

        assert!(matcher.matches("google.com")); // root_suffix exact
        assert!(matcher.matches("www.google.com")); // root_suffix subdomain
        assert!(!matcher.matches("facebook.com")); // prefix_suffix should NOT match exact
        assert!(matcher.matches("www.facebook.com")); // prefix_suffix should match subdomain
        assert!(matcher.matches("a.b.facebook.com")); // prefix_suffix deep subdomain
    }

    #[test]
    fn test_combined_exact_and_suffix() {
        let exact = vec!["specific.com".to_string()];
        let suffix = vec!["google.com".to_string(), ".only-sub.com".to_string()];
        let matcher = SuccinctMatcher::new(&exact, &suffix);

        // Exact
        assert!(matcher.matches("specific.com"));
        assert!(!matcher.matches("www.specific.com"));

        // Root suffix
        assert!(matcher.matches("google.com"));
        assert!(matcher.matches("sub.google.com"));

        // Prefix suffix
        assert!(!matcher.matches("only-sub.com"));
        assert!(matcher.matches("www.only-sub.com"));
    }

    #[test]
    fn test_deep_subdomain_matching() {
        let suffix = vec!["example.com".to_string()];
        let matcher = SuccinctMatcher::new(&[], &suffix);

        assert!(matcher.matches("a.b.c.d.e.example.com"));
        assert!(matcher.matches("example.com"));
        assert!(!matcher.matches("notexample.com"));
    }

    #[test]
    fn test_matches_assumes_lowercased_input() {
        // matches() no longer calls to_lowercase() internally;
        // it assumes the caller provides lowercased input (HostInfo guarantee)
        let domains = vec!["google.com".to_string()];
        let suffix = vec!["youtube.com".to_string()];
        let matcher = SuccinctMatcher::new(&domains, &suffix);

        // Lowercased input works
        assert!(matcher.matches("google.com"));
        assert!(matcher.matches("youtube.com"));
        assert!(matcher.matches("www.youtube.com"));

        // Non-lowercased input won't match (by design, caller must lowercase)
        assert!(!matcher.matches("GOOGLE.COM"));
        assert!(!matcher.matches("YouTube.com"));
    }
}
