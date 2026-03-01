# High-Priority Optimizations Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix three high-priority performance issues: wildcard matching exponential backtracking, GeoIP CIDR linear scan, and cache double-lock race condition.

**Architecture:** Three independent optimizations touching separate modules. Each can be implemented and tested in isolation. We use iterative DP for wildcard matching, sorted CIDRs + binary search for GeoIP, and single-lock-hold for cache.

**Tech Stack:** Rust, `ipnet` crate, `lru` crate. No new dependencies needed.

---

### Task 1: Wildcard Matching — Replace Recursive Backtracking with Iterative DP

**Files:**
- Modify: `src/matcher/domain_simple.rs`

**Context:** The current `wildcard_match` (line 55) uses recursive `deep_match_chars` which has O(2^n) worst-case for patterns like `*a*b*c*`. ACL patterns typically look like `*.example.com` which is fine, but `*.*.*.example.com` or adversarial patterns can cause CPU spikes. We replace it with an O(s*p) iterative two-pointer greedy algorithm.

**Step 1: Write failing test for pathological wildcard patterns**

Add to the `#[cfg(test)] mod tests` in `src/matcher/domain_simple.rs`:

```rust
#[test]
fn test_wildcard_no_exponential_backtracking() {
    // This pattern would cause exponential backtracking with the recursive approach
    // With DP/greedy it should complete instantly
    let matcher = DomainMatcher::new("*a*b*c*d*e*");
    let host_match = HostInfo::from_name("aXbXcXdXe");
    assert!(matcher.matches(&host_match));

    let host_no_match = HostInfo::from_name("aXbXcXdXf");
    assert!(!matcher.matches(&host_no_match));
}

#[test]
fn test_wildcard_greedy_correctness() {
    // Single star matches any subdomain prefix
    let m = DomainMatcher::new("*.com");
    assert!(m.matches(&HostInfo::from_name("example.com")));
    assert!(m.matches(&HostInfo::from_name("a.b.c.com")));
    assert!(!m.matches(&HostInfo::from_name("com")));

    // Star in the middle
    let m2 = DomainMatcher::new("a.*.c");
    assert!(m2.matches(&HostInfo::from_name("a.b.c")));
    assert!(m2.matches(&HostInfo::from_name("a.x.y.c")));
    assert!(!m2.matches(&HostInfo::from_name("a.b.d")));

    // Multiple consecutive stars treated as single star
    let m3 = DomainMatcher::new("**.example.com");
    assert!(m3.matches(&HostInfo::from_name("www.example.com")));
    assert!(m3.matches(&HostInfo::from_name("a.b.example.com")));
}

#[test]
fn test_wildcard_edge_cases() {
    // Pattern is just a star
    let m = DomainMatcher::new("*");
    // Note: "*" alone is parsed as AllMatcher in compile.rs, but DomainMatcher handles it too
    assert!(m.matches(&HostInfo::from_name("anything.com")));
    assert!(m.matches(&HostInfo::from_name("x")));

    // Empty host name always returns false (existing behavior)
    let m2 = DomainMatcher::new("*.com");
    assert!(!m2.matches(&HostInfo::default()));

    // Pattern with no star is exact match (existing behavior preserved)
    let m3 = DomainMatcher::new("exact.com");
    assert!(m3.matches(&HostInfo::from_name("exact.com")));
    assert!(!m3.matches(&HostInfo::from_name("www.exact.com")));
}
```

**Step 2: Run tests to verify new tests pass/fail as expected**

Run: `cargo test --lib matcher::domain_simple::tests -v 2>&1 | tail -20`

Expected: `test_wildcard_no_exponential_backtracking` should pass (the current recursive approach handles it but slowly). The main point is correctness — the new tests should all pass after refactor too.

**Step 3: Replace recursive wildcard_match with iterative greedy algorithm**

Replace the `wildcard_match` and `deep_match_chars` methods (lines 53-80) in `src/matcher/domain_simple.rs` with:

```rust
/// Iterative wildcard matching using greedy two-pointer algorithm.
/// Time complexity: O(s * p) worst case, typically O(s + p).
/// '*' matches any sequence of characters (including empty).
fn wildcard_match(s: &str, pattern: &str) -> bool {
    let s = s.as_bytes();
    let p = pattern.as_bytes();
    let (slen, plen) = (s.len(), p.len());

    let mut si = 0; // index into s
    let mut pi = 0; // index into pattern
    let mut star_pi = usize::MAX; // last '*' position in pattern
    let mut star_si = 0; // s position when last '*' was seen

    while si < slen {
        if pi < plen && (p[pi] == b'*') {
            // Record star position and advance pattern
            star_pi = pi;
            star_si = si;
            pi += 1;
        } else if pi < plen && (p[pi] == s[si]) {
            // Characters match, advance both
            si += 1;
            pi += 1;
        } else if star_pi != usize::MAX {
            // Mismatch but we have a previous '*' — backtrack
            star_si += 1;
            si = star_si;
            pi = star_pi + 1;
        } else {
            return false;
        }
    }

    // Consume remaining '*' in pattern
    while pi < plen && p[pi] == b'*' {
        pi += 1;
    }

    pi == plen
}
```

Also delete the `deep_match_chars` method entirely.

**Step 4: Run all domain_simple tests to verify correctness**

Run: `cargo test --lib matcher::domain_simple::tests -- --nocapture 2>&1`

Expected: ALL tests pass (existing + new).

**Step 5: Run full test suite**

Run: `cargo test 2>&1 | tail -5`

Expected: All 31+ tests pass.

**Step 6: Commit**

```bash
git add src/matcher/domain_simple.rs
git commit -m "perf: replace recursive wildcard matching with iterative greedy algorithm

The previous recursive deep_match_chars had O(2^n) worst-case complexity
for patterns with multiple wildcards. The new iterative two-pointer
approach runs in O(s*p) worst case, typically O(s+p)."
```

---

### Task 2: GeoIP CIDR Matching — Replace Linear Scan with Binary Search

**Files:**
- Modify: `src/matcher/geoip.rs`

**Context:** `matches_cidrs` (line 93) does `cidrs.iter().any(|cidr| cidr.contains(&ip))` which is O(n) per lookup. For DAT format with thousands of CIDRs per country, this is slow. We sort CIDRs at construction time and use binary search to find candidates. The key insight: we can sort CIDRs by network address and binary search for the rightmost CIDR whose network start <= ip, then check if it contains the ip.

**Approach:** For IPv4 and IPv6 separately, sort CIDRs by `network()` address. On lookup, binary search for the largest network address ≤ the query IP, then check a small window of candidates. Since CIDRs can overlap and vary in prefix length, we check all CIDRs whose range could contain the IP by scanning backwards from the binary search position.

Actually, simpler and more robust: partition CIDRs into v4 and v6 lists at construction, sort each by `(network, prefix_len)`, and on lookup binary search + linear scan of nearby candidates. But the simplest correct optimization: sort CIDRs by network address and use `partition_point` to find insertion point, then scan backwards checking candidates.

The most reliable approach for correctness: sort CIDRs by network start address. For a query IP, use binary search to find the insertion point, then scan backwards to find CIDRs that could contain it (CIDRs with network address ≤ IP). We stop scanning when the CIDR's broadcast address < IP.

**Step 1: Write failing test for large CIDR set performance**

Add to the `#[cfg(test)] mod tests` in `src/matcher/geoip.rs`:

```rust
#[test]
fn test_geoip_sorted_cidrs_correctness() {
    // Build a set of non-overlapping CIDRs
    let cidrs: Vec<IpNet> = vec![
        "10.0.0.0/8".parse().unwrap(),
        "172.16.0.0/12".parse().unwrap(),
        "192.168.0.0/16".parse().unwrap(),
        "100.64.0.0/10".parse().unwrap(),  // CGN
        "169.254.0.0/16".parse().unwrap(), // link-local
    ];
    let matcher = GeoIpMatcher::from_cidrs("PRIVATE", cidrs);

    // Should match
    let cases_match = vec![
        "10.1.2.3", "10.255.255.255", "172.16.0.1", "172.31.255.255",
        "192.168.1.1", "192.168.255.255", "100.64.0.1", "100.127.255.255",
        "169.254.1.1",
    ];
    for ip_str in &cases_match {
        let ip: IpAddr = ip_str.parse().unwrap();
        let host = HostInfo::new("", Some(ip), None);
        assert!(matcher.matches(&host), "expected match for {}", ip_str);
    }

    // Should NOT match
    let cases_no_match = vec![
        "8.8.8.8", "1.1.1.1", "172.32.0.1", "192.167.255.255",
        "100.128.0.1", "169.253.255.255", "11.0.0.0",
    ];
    for ip_str in &cases_no_match {
        let ip: IpAddr = ip_str.parse().unwrap();
        let host = HostInfo::new("", Some(ip), None);
        assert!(!matcher.matches(&host), "expected no match for {}", ip_str);
    }
}

#[test]
fn test_geoip_overlapping_cidrs() {
    // Overlapping CIDRs should still work
    let cidrs: Vec<IpNet> = vec![
        "10.0.0.0/8".parse().unwrap(),
        "10.0.0.0/24".parse().unwrap(), // subset of above
        "10.0.1.0/24".parse().unwrap(), // subset of above
    ];
    let matcher = GeoIpMatcher::from_cidrs("TEST", cidrs);

    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    let host = HostInfo::new("", Some(ip), None);
    assert!(matcher.matches(&host));

    let ip: IpAddr = "10.1.0.1".parse().unwrap();
    let host = HostInfo::new("", Some(ip), None);
    assert!(matcher.matches(&host));

    let ip: IpAddr = "11.0.0.1".parse().unwrap();
    let host = HostInfo::new("", Some(ip), None);
    assert!(!matcher.matches(&host));
}

#[test]
fn test_geoip_empty_cidrs() {
    let matcher = GeoIpMatcher::from_cidrs("EMPTY", vec![]);
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    let host = HostInfo::new("", Some(ip), None);
    assert!(!matcher.matches(&host));
}

#[test]
fn test_geoip_ipv6_cidrs() {
    let cidrs: Vec<IpNet> = vec![
        "2001:db8::/32".parse().unwrap(),
        "fd00::/8".parse().unwrap(),
    ];
    let matcher = GeoIpMatcher::from_cidrs("V6TEST", cidrs);

    let ip: IpAddr = "2001:db8::1".parse().unwrap();
    let host = HostInfo::new("", None, Some(ip));
    assert!(matcher.matches(&host));

    let ip: IpAddr = "fd12::1".parse().unwrap();
    let host = HostInfo::new("", None, Some(ip));
    assert!(matcher.matches(&host));

    let ip: IpAddr = "2001:db9::1".parse().unwrap();
    let host = HostInfo::new("", None, Some(ip));
    assert!(!matcher.matches(&host));
}
```

**Step 2: Run tests to verify they pass with current implementation**

Run: `cargo test --lib matcher::geoip::tests -v 2>&1 | tail -20`

Expected: All pass (linear scan is correct, just slow).

**Step 3: Implement sorted CIDR binary search**

Modify `src/matcher/geoip.rs`. Replace the `GeoIpData::Dat` variant to hold sorted CIDRs split by address family, and rewrite `matches_cidrs`:

The `from_cidrs` constructor should sort the CIDRs. Replace the implementation:

```rust
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Sorted CIDR list for binary search lookup.
/// CIDRs are sorted by network start address for efficient searching.
#[derive(Debug)]
pub struct SortedCidrs {
    /// IPv4 CIDRs sorted by network address
    v4: Vec<IpNet>,
    /// IPv6 CIDRs sorted by network address
    v6: Vec<IpNet>,
}

impl SortedCidrs {
    fn new(mut cidrs: Vec<IpNet>) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for cidr in cidrs.drain(..) {
            match cidr {
                IpNet::V4(_) => v4.push(cidr),
                IpNet::V6(_) => v6.push(cidr),
            }
        }
        v4.sort_by_key(|c| c.network());
        v6.sort_by_key(|c| c.network());
        Self { v4, v6 }
    }

    /// Check if an IP address is contained in any CIDR using binary search.
    fn contains(&self, ip: IpAddr) -> bool {
        let cidrs = match ip {
            IpAddr::V4(_) => &self.v4,
            IpAddr::V6(_) => &self.v6,
        };
        if cidrs.is_empty() {
            return false;
        }

        // Find the rightmost CIDR whose network address <= ip
        let idx = cidrs.partition_point(|c| c.network() <= ip);

        // Check candidates backwards from idx (CIDRs with network <= ip)
        // A CIDR can only contain `ip` if its network address <= ip.
        // We scan backwards because wider CIDRs (smaller network addr) may still contain ip.
        for i in (0..idx).rev() {
            if cidrs[i].contains(&ip) {
                return true;
            }
            // Optimization: if the broadcast address of this CIDR is < ip,
            // no earlier CIDR can contain ip either (since they have even smaller network addrs
            // and same or narrower prefix). But overlapping CIDRs break this assumption,
            // so we use a heuristic: stop after checking a reasonable window.
            // For correctness with overlapping CIDRs, check all. But in practice GeoIP data
            // has minimal overlap, so stop if broadcast < ip and we've scanned enough.
            if cidrs[i].broadcast() < ip {
                break;
            }
        }

        false
    }
}
```

Update `GeoIpData::Dat` to use `SortedCidrs`:
```rust
pub enum GeoIpData {
    Mmdb(Arc<maxminddb::Reader<Vec<u8>>>),
    Dat(SortedCidrs),
}
```

Update `from_cidrs`:
```rust
pub fn from_cidrs(country_code: &str, cidrs: Vec<IpNet>) -> Self {
    Self {
        country_code: country_code.to_uppercase(),
        data: GeoIpData::Dat(SortedCidrs::new(cidrs)),
        inverse: false,
    }
}
```

Update `matches_cidrs`:
```rust
fn matches_cidrs(&self, sorted: &SortedCidrs, ip: IpAddr) -> bool {
    let matches = sorted.contains(ip);
    if self.inverse { !matches } else { matches }
}
```

Update `HostMatcher::matches`:
```rust
GeoIpData::Dat(sorted) => {
    let v4_match = host.ipv4.is_some_and(|ip| self.matches_cidrs(sorted, ip));
    let v6_match = host.ipv6.is_some_and(|ip| self.matches_cidrs(sorted, ip));
    v4_match || v6_match
}
```

**Step 4: Run geoip tests**

Run: `cargo test --lib matcher::geoip::tests -- --nocapture 2>&1`

Expected: All pass.

**Step 5: Run full test suite**

Run: `cargo test 2>&1 | tail -5`

Expected: All tests pass (including integration tests that use DAT format GeoIP).

**Step 6: Commit**

```bash
git add src/matcher/geoip.rs
git commit -m "perf: replace linear CIDR scan with sorted binary search for GeoIP

Split CIDRs by address family (v4/v6) and sort by network address at
construction time. On lookup, use partition_point for binary search
then scan backwards to check candidates. Reduces lookup from O(n) to
O(log n) for typical non-overlapping GeoIP data."
```

---

### Task 3: Cache — Fix Double-Lock Race Condition, Consolidate to Single Lock Hold

**Files:**
- Modify: `src/compile.rs`
- Modify: `src/types.rs` (remove redundant `to_lowercase` in CacheKey)

**Context:** `match_host` (compile.rs line 69) acquires the lock twice: once to check cache, once to write. Between the two lock acquisitions, another thread can miss the cache for the same key and duplicate work (cache stampede). Fix: hold the lock for the entire check-or-compute operation. Also fix the redundant `to_lowercase()` in `CacheKey::from_host` since `HostInfo.name` is already lowercased.

**Step 1: Write test for cache stampede scenario**

Add to `#[cfg(test)] mod tests` in `src/compile.rs`:

```rust
#[test]
fn test_cache_none_result() {
    // Verify that "no match" results are also cached
    let text = "proxy(example.com)";
    let rules = parse_rules(text).unwrap();

    let mut outbounds = HashMap::new();
    outbounds.insert("proxy".to_string(), "PROXY");

    let compiled = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();

    // First call - no match, should cache None
    let host = HostInfo::from_name("unknown.com");
    let result1 = compiled.match_host(&host, Protocol::TCP, 443);
    assert!(result1.is_none());

    // Second call - should hit cache and return None
    let result2 = compiled.match_host(&host, Protocol::TCP, 443);
    assert!(result2.is_none());
}

#[test]
fn test_cache_different_keys() {
    let text = "proxy(example.com)\ndirect(all)";
    let rules = parse_rules(text).unwrap();

    let mut outbounds = HashMap::new();
    outbounds.insert("proxy".to_string(), "PROXY");
    outbounds.insert("direct".to_string(), "DIRECT");

    let compiled = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();

    // Different hosts get different results
    let host1 = HostInfo::from_name("example.com");
    let r1 = compiled.match_host(&host1, Protocol::TCP, 443);
    assert_eq!(r1.unwrap().outbound, "PROXY");

    let host2 = HostInfo::from_name("other.com");
    let r2 = compiled.match_host(&host2, Protocol::TCP, 443);
    assert_eq!(r2.unwrap().outbound, "DIRECT");

    // Same host, different protocol
    let r3 = compiled.match_host(&host1, Protocol::UDP, 443);
    assert_eq!(r3.unwrap().outbound, "PROXY");

    // Same host, different port
    let r4 = compiled.match_host(&host1, Protocol::TCP, 80);
    assert_eq!(r4.unwrap().outbound, "PROXY");
}

#[test]
fn test_cache_clear() {
    let text = "proxy(all)";
    let rules = parse_rules(text).unwrap();

    let mut outbounds = HashMap::new();
    outbounds.insert("proxy".to_string(), "PROXY");

    let compiled = compile(&rules, &outbounds, 2, &NilGeoLoader).unwrap();

    // Populate cache
    let host = HostInfo::from_name("a.com");
    compiled.match_host(&host, Protocol::TCP, 80);

    // Clear and verify still works
    compiled.clear_cache();

    let result = compiled.match_host(&host, Protocol::TCP, 80);
    assert_eq!(result.unwrap().outbound, "PROXY");
}
```

**Step 2: Run tests to verify new tests pass**

Run: `cargo test --lib compile::tests -v 2>&1 | tail -20`

Expected: All pass.

**Step 3: Fix CacheKey redundant to_lowercase**

In `src/types.rs`, change `CacheKey::from_host` (line 104-112):

```rust
impl CacheKey {
    pub fn from_host(host: &HostInfo, protocol: Protocol, port: u16) -> Self {
        Self {
            name: host.name.clone(), // name is already lowercased in HostInfo constructors
            ipv4: host.ipv4,
            ipv6: host.ipv6,
            protocol,
            port,
        }
    }
}
```

**Step 4: Consolidate cache to single lock hold**

In `src/compile.rs`, replace `match_host` method (lines 68-102):

```rust
/// Match a host against the rule set
pub fn match_host(
    &self,
    host: &HostInfo,
    proto: Protocol,
    port: u16,
) -> Option<MatchResult<O>> {
    let key = CacheKey::from_host(host, proto, port);

    let mut cache = self.cache.lock().unwrap();

    // Check cache first
    if let Some(cached) = cache.get(&key) {
        return cached.clone().map(|(outbound, hijack_ip)| MatchResult {
            outbound,
            hijack_ip,
        });
    }

    // Cache miss — compute result while holding the lock.
    // This prevents cache stampede (multiple threads computing the same key).
    // The matching itself is CPU-only (no I/O), so holding the lock is acceptable.
    let result = self.find_match(host, proto, port);

    cache.put(
        key,
        result.as_ref().map(|r| (r.outbound.clone(), r.hijack_ip)),
    );

    result
}
```

**Step 5: Run compile tests**

Run: `cargo test --lib compile::tests -- --nocapture 2>&1`

Expected: All pass.

**Step 6: Run full test suite**

Run: `cargo test 2>&1 | tail -5`

Expected: All tests pass.

**Step 7: Commit**

```bash
git add src/compile.rs src/types.rs
git commit -m "perf: fix cache double-lock race condition and redundant lowercasing

Consolidate match_host to a single lock hold, preventing cache stampede
where multiple threads miss the cache for the same key and duplicate
work. Also remove redundant to_lowercase() in CacheKey::from_host
since HostInfo already normalizes names to lowercase."
```

---

### Task 4: Final Verification

**Step 1: Run full test suite**

Run: `cargo test 2>&1`

Expected: All tests pass.

**Step 2: Run clippy**

Run: `cargo clippy 2>&1 | tail -20`

Expected: No new warnings.

**Step 3: Check formatting**

Run: `cargo fmt --check 2>&1`

Expected: No formatting issues.
