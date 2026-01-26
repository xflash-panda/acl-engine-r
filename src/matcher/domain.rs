use super::HostMatcher;
use crate::types::HostInfo;

/// Domain matching mode
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainMatchMode {
    /// Exact match: "example.com" matches only "example.com"
    Exact,
    /// Wildcard match: "*.example.com" matches "foo.example.com", "bar.foo.example.com", etc.
    Wildcard,
    /// Suffix match: "suffix:example.com" matches "example.com" and "foo.example.com"
    Suffix,
}

/// Domain matcher - matches domain names
#[derive(Debug, Clone)]
pub struct DomainMatcher {
    pattern: String,
    mode: DomainMatchMode,
}

impl DomainMatcher {
    /// Create a new domain matcher from a pattern
    pub fn new(pattern: &str) -> Self {
        let pattern = pattern.to_lowercase();

        if let Some(suffix) = pattern.strip_prefix("suffix:") {
            Self {
                pattern: suffix.to_string(),
                mode: DomainMatchMode::Suffix,
            }
        } else if pattern.contains('*') {
            Self {
                pattern,
                mode: DomainMatchMode::Wildcard,
            }
        } else {
            Self {
                pattern,
                mode: DomainMatchMode::Exact,
            }
        }
    }

    /// Create a domain matcher with explicit mode
    pub fn with_mode(pattern: &str, mode: DomainMatchMode) -> Self {
        Self {
            pattern: pattern.to_lowercase(),
            mode,
        }
    }

    /// Wildcard matching using recursive backtracking
    /// Matches '*' against any sequence of characters
    fn wildcard_match(s: &str, pattern: &str) -> bool {
        let s_chars: Vec<char> = s.chars().collect();
        let p_chars: Vec<char> = pattern.chars().collect();
        Self::deep_match_chars(&s_chars, &p_chars)
    }

    fn deep_match_chars(s: &[char], p: &[char]) -> bool {
        if p.is_empty() {
            return s.is_empty();
        }

        match p[0] {
            '*' => {
                // Try skipping '*' first, then matching one character at a time
                Self::deep_match_chars(s, &p[1..])
                    || (!s.is_empty() && Self::deep_match_chars(&s[1..], p))
            }
            c => {
                if s.is_empty() || s[0] != c {
                    false
                } else {
                    Self::deep_match_chars(&s[1..], &p[1..])
                }
            }
        }
    }
}

impl HostMatcher for DomainMatcher {
    fn matches(&self, host: &HostInfo) -> bool {
        if host.name.is_empty() {
            return false;
        }

        let name = host.name.to_lowercase();

        match self.mode {
            DomainMatchMode::Exact => name == self.pattern,
            DomainMatchMode::Wildcard => Self::wildcard_match(&name, &self.pattern),
            DomainMatchMode::Suffix => {
                // Matches if:
                // 1. name == pattern
                // 2. name ends with ".pattern"
                name == self.pattern || name.ends_with(&format!(".{}", self.pattern))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let matcher = DomainMatcher::new("example.com");

        assert!(matcher.matches(&HostInfo::from_name("example.com")));
        assert!(matcher.matches(&HostInfo::from_name("EXAMPLE.COM")));
        assert!(!matcher.matches(&HostInfo::from_name("www.example.com")));
        assert!(!matcher.matches(&HostInfo::from_name("example.org")));
    }

    #[test]
    fn test_wildcard_match() {
        let matcher = DomainMatcher::new("*.example.com");

        assert!(matcher.matches(&HostInfo::from_name("www.example.com")));
        assert!(matcher.matches(&HostInfo::from_name("foo.bar.example.com")));
        assert!(!matcher.matches(&HostInfo::from_name("example.com")));
    }

    #[test]
    fn test_suffix_match() {
        let matcher = DomainMatcher::new("suffix:example.com");

        assert!(matcher.matches(&HostInfo::from_name("example.com")));
        assert!(matcher.matches(&HostInfo::from_name("www.example.com")));
        assert!(matcher.matches(&HostInfo::from_name("foo.bar.example.com")));
        assert!(!matcher.matches(&HostInfo::from_name("notexample.com")));
        assert!(!matcher.matches(&HostInfo::from_name("example.org")));
    }

    #[test]
    fn test_complex_wildcard() {
        let matcher = DomainMatcher::new("*.google.*");

        assert!(matcher.matches(&HostInfo::from_name("www.google.com")));
        assert!(matcher.matches(&HostInfo::from_name("mail.google.co.uk")));
        assert!(!matcher.matches(&HostInfo::from_name("google.com")));
    }

    #[test]
    fn test_empty_name() {
        let matcher = DomainMatcher::new("example.com");
        assert!(!matcher.matches(&HostInfo::default()));
    }
}
