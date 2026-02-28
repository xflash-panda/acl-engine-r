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
    /// Pre-computed ".{pattern}" for suffix matching (avoids format! per call)
    dot_pattern: String,
    mode: DomainMatchMode,
}

impl DomainMatcher {
    /// Create a new domain matcher from a pattern
    pub fn new(pattern: &str) -> Self {
        let pattern = pattern.to_lowercase();

        if let Some(suffix) = pattern.strip_prefix("suffix:") {
            let dot_pattern = format!(".{}", suffix);
            Self {
                pattern: suffix.to_string(),
                dot_pattern,
                mode: DomainMatchMode::Suffix,
            }
        } else if pattern.contains('*') {
            Self {
                dot_pattern: format!(".{}", pattern),
                pattern,
                mode: DomainMatchMode::Wildcard,
            }
        } else {
            Self {
                dot_pattern: format!(".{}", pattern),
                pattern,
                mode: DomainMatchMode::Exact,
            }
        }
    }

    /// Create a domain matcher with explicit mode
    pub fn with_mode(pattern: &str, mode: DomainMatchMode) -> Self {
        let pattern = pattern.to_lowercase();
        let dot_pattern = format!(".{}", pattern);
        Self {
            pattern,
            dot_pattern,
            mode,
        }
    }

    /// Iterative wildcard matching using greedy two-pointer algorithm.
    /// Time complexity: O(s * p) worst case, typically O(s + p).
    /// '*' matches any sequence of characters (including empty).
    fn wildcard_match(s: &str, pattern: &str) -> bool {
        let s = s.as_bytes();
        let p = pattern.as_bytes();
        let (slen, plen) = (s.len(), p.len());

        let mut si = 0;
        let mut pi = 0;
        let mut star_pi = usize::MAX;
        let mut star_si = 0;

        while si < slen {
            if pi < plen && p[pi] == b'*' {
                star_pi = pi;
                star_si = si;
                pi += 1;
            } else if pi < plen && p[pi] == s[si] {
                si += 1;
                pi += 1;
            } else if star_pi != usize::MAX {
                star_si += 1;
                si = star_si;
                pi = star_pi + 1;
            } else {
                return false;
            }
        }

        while pi < plen && p[pi] == b'*' {
            pi += 1;
        }

        pi == plen
    }
}

impl HostMatcher for DomainMatcher {
    fn matches(&self, host: &HostInfo) -> bool {
        if host.name.is_empty() {
            return false;
        }

        // host.name is already lowercased by HostInfo constructors
        let name = &host.name;

        match self.mode {
            DomainMatchMode::Exact => *name == self.pattern,
            DomainMatchMode::Wildcard => Self::wildcard_match(name, &self.pattern),
            DomainMatchMode::Suffix => {
                *name == self.pattern || name.ends_with(&self.dot_pattern)
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

    #[test]
    fn test_wildcard_no_exponential_backtracking() {
        let matcher = DomainMatcher::new("*a*b*c*d*e*");
        let host_match = HostInfo::from_name("aXbXcXdXe");
        assert!(matcher.matches(&host_match));

        let host_no_match = HostInfo::from_name("aXbXcXdXf");
        assert!(!matcher.matches(&host_no_match));
    }

    #[test]
    fn test_wildcard_greedy_correctness() {
        let m = DomainMatcher::new("*.com");
        assert!(m.matches(&HostInfo::from_name("example.com")));
        assert!(m.matches(&HostInfo::from_name("a.b.c.com")));
        assert!(!m.matches(&HostInfo::from_name("com")));

        let m2 = DomainMatcher::new("a.*.c");
        assert!(m2.matches(&HostInfo::from_name("a.b.c")));
        assert!(m2.matches(&HostInfo::from_name("a.x.y.c")));
        assert!(!m2.matches(&HostInfo::from_name("a.b.d")));

        let m3 = DomainMatcher::new("**.example.com");
        assert!(m3.matches(&HostInfo::from_name("www.example.com")));
        assert!(m3.matches(&HostInfo::from_name("a.b.example.com")));
    }

    #[test]
    fn test_wildcard_edge_cases() {
        let m = DomainMatcher::new("*");
        assert!(m.matches(&HostInfo::from_name("anything.com")));
        assert!(m.matches(&HostInfo::from_name("x")));

        let m2 = DomainMatcher::new("*.com");
        assert!(!m2.matches(&HostInfo::default()));

        let m3 = DomainMatcher::new("exact.com");
        assert!(m3.matches(&HostInfo::from_name("exact.com")));
        assert!(!m3.matches(&HostInfo::from_name("www.exact.com")));
    }

    #[test]
    fn test_suffix_no_allocation_per_call() {
        // Suffix matching should work correctly without per-call format! allocation
        let matcher = DomainMatcher::new("suffix:example.com");

        // Multiple calls should all work (verifies pre-computed suffix)
        for _ in 0..100 {
            assert!(matcher.matches(&HostInfo::from_name("example.com")));
            assert!(matcher.matches(&HostInfo::from_name("www.example.com")));
            assert!(matcher.matches(&HostInfo::from_name("deep.sub.example.com")));
            assert!(!matcher.matches(&HostInfo::from_name("notexample.com")));
        }
    }

    #[test]
    fn test_matches_already_lowercase() {
        // HostInfo already lowercases, verify matcher works without re-lowering
        let matcher = DomainMatcher::new("EXAMPLE.COM"); // pattern is lowercased in new()

        // HostInfo::from_name lowercases the input
        assert!(matcher.matches(&HostInfo::from_name("EXAMPLE.COM")));
        assert!(matcher.matches(&HostInfo::from_name("example.com")));
        assert!(matcher.matches(&HostInfo::from_name("Example.Com")));
    }
}
