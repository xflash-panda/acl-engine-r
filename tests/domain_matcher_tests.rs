//! Integration tests for SuccinctMatcher using real rules from acl-o.yaml

use acl_engine_r::matcher::domain::SuccinctMatcher;
use acl_engine_r::matcher::{DomainEntry, GeoSiteMatcher, HostMatcher};
use acl_engine_r::types::HostInfo;

/// Mining pool domains from acl-o.yaml (857 suffix rules)
fn get_mining_pool_suffixes() -> Vec<String> {
    vec![
        "011data.com",
        "0769.it",
        "0xpool.me",
        "1pool.org",
        "1square.net",
        "2acoin.org",
        "2ch-pool.com",
        "2mars.biz",
        "2miners.com",
        "4assets.digital",
        "4minerspool.com",
        "51pool.online",
        "666pool.com",
        "6block.com",
        "acc-pool.pw",
        "acemining.co",
        "acepool.top",
        "acidpool.co.uk",
        "advtech.group",
        "aikapool.com",
        "aionmine.org",
        "aionpool.tech",
        "antpool.com",
        "binance.com",
        "btc.com",
        "ethermine.org",
        "f2pool.com",
        "flexpool.io",
        "hashvault.pro",
        "herominers.com",
        "hiveon.net",
        "litecoinpool.org",
        "minergate.com",
        "miningpoolhub.com",
        "nanopool.org",
        "nicehash.com",
        "poolin.com",
        "slushpool.com",
        "sparkpool.com",
        "viabtc.com",
        "woolypooly.com",
        "google.com", // Also in the rules
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

#[test]
fn test_mining_pool_suffix_matching() {
    let suffixes = get_mining_pool_suffixes();
    let matcher = SuccinctMatcher::new(&[], &suffixes);

    // Test exact domain matches (root suffix)
    assert!(matcher.matches("antpool.com"), "antpool.com should match");
    assert!(matcher.matches("binance.com"), "binance.com should match");
    assert!(matcher.matches("google.com"), "google.com should match");
    assert!(matcher.matches("ethermine.org"), "ethermine.org should match");
    assert!(matcher.matches("f2pool.com"), "f2pool.com should match");

    // Test subdomain matches
    assert!(
        matcher.matches("www.antpool.com"),
        "www.antpool.com should match"
    );
    assert!(
        matcher.matches("api.binance.com"),
        "api.binance.com should match"
    );
    assert!(
        matcher.matches("www.google.com"),
        "www.google.com should match"
    );
    assert!(
        matcher.matches("mail.google.com"),
        "mail.google.com should match"
    );
    assert!(
        matcher.matches("us1.ethermine.org"),
        "us1.ethermine.org should match"
    );
    assert!(
        matcher.matches("eth.f2pool.com"),
        "eth.f2pool.com should match"
    );

    // Test deep subdomain matches
    assert!(
        matcher.matches("api.v2.binance.com"),
        "api.v2.binance.com should match"
    );
    assert!(
        matcher.matches("sub.sub.sub.google.com"),
        "sub.sub.sub.google.com should match"
    );

    // Test non-matches
    assert!(
        !matcher.matches("notantpool.com"),
        "notantpool.com should NOT match"
    );
    assert!(
        !matcher.matches("fakebinance.com"),
        "fakebinance.com should NOT match"
    );
    assert!(
        !matcher.matches("google.org"),
        "google.org should NOT match"
    );
    assert!(
        !matcher.matches("antpool.org"),
        "antpool.org should NOT match"
    );
    assert!(
        !matcher.matches("example.com"),
        "example.com should NOT match"
    );
}

#[test]
fn test_case_insensitive_matching() {
    let suffixes = vec!["Google.COM".to_string(), "BinAnce.Com".to_string()];
    let matcher = SuccinctMatcher::new(&[], &suffixes);

    // All case variations should match
    assert!(matcher.matches("google.com"));
    assert!(matcher.matches("GOOGLE.COM"));
    assert!(matcher.matches("Google.Com"));
    assert!(matcher.matches("WWW.GOOGLE.COM"));
    assert!(matcher.matches("api.BINANCE.com"));
}

#[test]
fn test_prefix_suffix_only_subdomains() {
    // With leading dot, only subdomains should match
    let suffixes = vec![".google.com".to_string()];
    let matcher = SuccinctMatcher::new(&[], &suffixes);

    // Subdomains should match
    assert!(
        matcher.matches("www.google.com"),
        "www.google.com should match"
    );
    assert!(
        matcher.matches("mail.google.com"),
        "mail.google.com should match"
    );
    assert!(
        matcher.matches("a.b.c.google.com"),
        "a.b.c.google.com should match"
    );

    // Exact domain should NOT match
    assert!(
        !matcher.matches("google.com"),
        "google.com should NOT match (prefix suffix)"
    );
}

#[test]
fn test_mixed_exact_and_suffix() {
    let exact = vec!["exact.example.com".to_string()];
    let suffixes = vec!["suffix.example.com".to_string()];
    let matcher = SuccinctMatcher::new(&exact, &suffixes);

    // Exact match
    assert!(matcher.matches("exact.example.com"));
    assert!(!matcher.matches("www.exact.example.com")); // No subdomain for exact

    // Suffix match
    assert!(matcher.matches("suffix.example.com"));
    assert!(matcher.matches("www.suffix.example.com")); // Subdomain allowed
    assert!(matcher.matches("api.suffix.example.com"));
}

#[test]
fn test_large_suffix_list_performance() {
    // Simulate a large list like mining pools (800+ domains)
    let suffixes: Vec<String> = (0..1000)
        .map(|i| format!("domain{}.example.com", i))
        .collect();

    let matcher = SuccinctMatcher::new(&[], &suffixes);

    // Test various positions in the list
    assert!(matcher.matches("domain0.example.com"));
    assert!(matcher.matches("domain500.example.com"));
    assert!(matcher.matches("domain999.example.com"));
    assert!(matcher.matches("www.domain500.example.com"));

    // Non-matches
    assert!(!matcher.matches("domain1000.example.com"));
    assert!(!matcher.matches("other.example.com"));
}

#[test]
fn test_no_false_positives_similar_domains() {
    let suffixes = vec!["pool.com".to_string(), "mining.org".to_string()];
    let matcher = SuccinctMatcher::new(&[], &suffixes);

    // Should match
    assert!(matcher.matches("pool.com"));
    assert!(matcher.matches("my.pool.com"));
    assert!(matcher.matches("mining.org"));
    assert!(matcher.matches("bitcoin.mining.org"));

    // Should NOT match - similar but different domains
    assert!(!matcher.matches("carpool.com")); // "pool.com" is substring but not suffix
    assert!(!matcher.matches("notpool.com"));
    assert!(!matcher.matches("pool.org")); // Different TLD
    assert!(!matcher.matches("mining.com")); // Different TLD
    assert!(!matcher.matches("datamining.org")); // "mining.org" is substring but not suffix
}

#[test]
fn test_empty_matcher() {
    let matcher = SuccinctMatcher::new(&[], &[]);

    assert!(matcher.is_empty());
    assert!(!matcher.matches("google.com"));
    assert!(!matcher.matches("anything.com"));
}

#[test]
fn test_deduplication() {
    let suffixes = vec![
        "google.com".to_string(),
        "google.com".to_string(),
        "GOOGLE.COM".to_string(),
        "Google.Com".to_string(),
    ];
    let matcher = SuccinctMatcher::new(&[], &suffixes);

    // Should still work correctly despite duplicates
    assert!(matcher.matches("google.com"));
    assert!(matcher.matches("www.google.com"));
}

#[test]
fn test_special_tlds() {
    let suffixes = vec![
        "example.co.uk".to_string(),
        "example.com.cn".to_string(),
        "example.net.au".to_string(),
    ];
    let matcher = SuccinctMatcher::new(&[], &suffixes);

    // Should match compound TLDs correctly
    assert!(matcher.matches("example.co.uk"));
    assert!(matcher.matches("www.example.co.uk"));
    assert!(matcher.matches("example.com.cn"));
    assert!(matcher.matches("shop.example.com.cn"));

    // Should NOT match partial
    assert!(!matcher.matches("co.uk")); // Not a suffix we added
    assert!(!matcher.matches("other.co.uk"));
}

#[test]
fn test_real_acl_rules_sample() {
    // Sample of actual rules from acl-o.yaml
    let suffixes = vec![
        "antpool.com".to_string(),
        "binance.com".to_string(),
        "ethermine.org".to_string(),
        "f2pool.com".to_string(),
        "flexpool.io".to_string(),
        "herominers.com".to_string(),
        "hiveon.net".to_string(),
        "nanopool.org".to_string(),
        "nicehash.com".to_string(),
        "slushpool.com".to_string(),
        "google.com".to_string(),
        "ping0.cc".to_string(),
    ];
    let matcher = SuccinctMatcher::new(&[], &suffixes);

    // Real-world test cases
    assert!(matcher.matches("stratum.antpool.com"));
    assert!(matcher.matches("api.binance.com"));
    assert!(matcher.matches("us1.ethermine.org"));
    assert!(matcher.matches("eth.f2pool.com"));
    assert!(matcher.matches("eth.flexpool.io"));
    assert!(matcher.matches("pool.herominers.com"));
    assert!(matcher.matches("eth.hiveon.net"));
    assert!(matcher.matches("eth.nanopool.org"));
    assert!(matcher.matches("stratum.nicehash.com"));
    assert!(matcher.matches("stratum.slushpool.com"));
    assert!(matcher.matches("www.google.com"));
    assert!(matcher.matches("api.ping0.cc"));

    // Non-mining domains should not match
    assert!(!matcher.matches("github.com"));
    assert!(!matcher.matches("stackoverflow.com"));
    assert!(!matcher.matches("twitter.com"));
}

#[test]
fn test_geosite_matcher_with_succinct() {
    // Create GeoSiteMatcher with RootDomain entries (uses SuccinctMatcher internally)
    let domains = vec![
        DomainEntry::new_root_domain("google.com"),
        DomainEntry::new_root_domain("youtube.com"),
        DomainEntry::new_root_domain("googleapis.com"),
        DomainEntry::new_full("exact.example.com"),
        DomainEntry::new_plain("facebook"), // Fallback to linear scan
    ];

    let matcher = GeoSiteMatcher::new("test", domains);

    // RootDomain matches via SuccinctMatcher
    assert!(matcher.matches(&HostInfo::from_name("google.com")));
    assert!(matcher.matches(&HostInfo::from_name("www.google.com")));
    assert!(matcher.matches(&HostInfo::from_name("mail.google.com")));
    assert!(matcher.matches(&HostInfo::from_name("youtube.com")));
    assert!(matcher.matches(&HostInfo::from_name("www.youtube.com")));
    assert!(matcher.matches(&HostInfo::from_name("googleapis.com")));
    assert!(matcher.matches(&HostInfo::from_name("api.googleapis.com")));

    // Full match via SuccinctMatcher
    assert!(matcher.matches(&HostInfo::from_name("exact.example.com")));
    assert!(!matcher.matches(&HostInfo::from_name("www.exact.example.com"))); // Full match only

    // Plain match via fallback linear scan
    assert!(matcher.matches(&HostInfo::from_name("facebook.com")));
    assert!(matcher.matches(&HostInfo::from_name("www.facebook.com")));
    assert!(matcher.matches(&HostInfo::from_name("m.facebook.com")));

    // Non-matches
    assert!(!matcher.matches(&HostInfo::from_name("twitter.com")));
    assert!(!matcher.matches(&HostInfo::from_name("github.com")));
}

#[test]
fn test_geosite_matcher_large_list() {
    // Simulate a large geosite list (like mining-pools with 800+ domains)
    let domains: Vec<DomainEntry> = (0..1000)
        .map(|i| DomainEntry::new_root_domain(&format!("pool{}.mining.com", i)))
        .collect();

    let matcher = GeoSiteMatcher::new("mining-pools", domains);

    // Test matching across the list
    assert!(matcher.matches(&HostInfo::from_name("pool0.mining.com")));
    assert!(matcher.matches(&HostInfo::from_name("pool500.mining.com")));
    assert!(matcher.matches(&HostInfo::from_name("pool999.mining.com")));
    assert!(matcher.matches(&HostInfo::from_name("stratum.pool500.mining.com")));

    // Non-matches
    assert!(!matcher.matches(&HostInfo::from_name("pool1000.mining.com")));
    assert!(!matcher.matches(&HostInfo::from_name("other.mining.com")));
}
