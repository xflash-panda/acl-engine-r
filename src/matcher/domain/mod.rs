//! High-performance domain matching module.
//!
//! This module provides efficient domain matching with:
//! - O(1) exact match lookup using HashSet
//! - O(k) suffix matching where k is the number of domain levels
//!
//! ## Example
//!
//! ```
//! use acl_engine_r::matcher::domain::SuccinctMatcher;
//!
//! let exact = vec!["example.com".to_string()];
//! let suffix = vec!["google.com".to_string()];
//! let matcher = SuccinctMatcher::new(&exact, &suffix);
//!
//! assert!(matcher.matches("example.com"));    // exact match
//! assert!(matcher.matches("google.com"));      // suffix match (root)
//! assert!(matcher.matches("www.google.com"));  // suffix match (subdomain)
//! ```

mod matcher;

pub use matcher::SuccinctMatcher;

// Note: SuccinctSet is kept for potential future use with true succinct trie implementation
#[allow(dead_code)]
mod succinct;
