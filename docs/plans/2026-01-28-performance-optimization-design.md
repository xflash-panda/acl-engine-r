# Performance Optimization Design

Align with Go acl-engine `feat/performance-optimize-domain-matcher` branch.

## Overview

| Optimization | Implementation | Expected Improvement |
|--------------|----------------|----------------------|
| Succinct Trie Domain Matcher | New `matcher/domain/` module, used by `GeoSiteMatcher` | 5-15x faster matching, 80% memory reduction |
| MetaDB LRU Cache | New `CachedMetaDbReader` wrapper | 9x faster IP lookups |

## 1. Succinct Trie Domain Matcher

### File Structure

```
src/matcher/
├── domain/
│   ├── mod.rs        # Module entry, exports SuccinctMatcher
│   ├── succinct.rs   # Succinct Trie data structure
│   └── matcher.rs    # Domain matcher using Succinct Trie
├── domain.rs         # Existing DomainMatcher (unchanged)
└── geosite.rs        # Modified: uses SuccinctMatcher internally
```

### Core Types

```rust
// succinct.rs
pub struct SuccinctSet {
    leaves: Vec<u64>,       // Leaf node bitmap
    label_bitmap: Vec<u64>, // Node boundary bitmap
    labels: Vec<u8>,        // Edge character labels
    ranks: Vec<i32>,        // Rank index for fast bit counting
    selects: Vec<i32>,      // Select index for fast position lookup
}

// matcher.rs
pub struct SuccinctMatcher {
    set: SuccinctSet,
}

impl SuccinctMatcher {
    pub fn new(domains: &[String], domain_suffix: &[String]) -> Self;
    pub fn matches(&self, domain: &str) -> bool;
}
```

### GeoSiteMatcher Changes

```rust
pub struct GeoSiteMatcher {
    site_name: String,
    // New: Succinct Trie for Full/RootDomain types
    succinct: Option<SuccinctMatcher>,
    // Kept: Linear scan for Plain/Regex types
    fallback_domains: Vec<DomainEntry>,
    required_attributes: HashMap<String, Option<String>>,
}
```

### Matching Strategy

- `Full` / `RootDomain` → Succinct Trie (O(domain_length))
- `Plain` / `Regex` → Linear scan (O(n))

Most GeoSite entries are RootDomain type, so overall performance gain is significant.

### Algorithm

1. **Construction**:
   - Reverse domain strings (`google.com` → `moc.elgoog`)
   - Sort all domains lexicographically
   - Build Succinct Trie using BFS
   - Generate rank/select indices

2. **Matching**:
   - Reverse input domain
   - Traverse trie using bitmap navigation
   - Use special labels (`\r` for prefix, `\n` for root) for suffix matching

## 2. MetaDB LRU Cache

### Changes to `src/geo/metadb/mod.rs`

```rust
const DEFAULT_CACHE_SIZE: usize = 1024;

pub struct CachedMetaDbReader {
    reader: MetaDbReader,
    cache: Mutex<LruCache<IpAddr, Vec<String>>>,
}

impl CachedMetaDbReader {
    // Constructors
    pub fn new(reader: MetaDbReader) -> Self;
    pub fn with_cache_size(reader: MetaDbReader, size: usize) -> Self;
    pub fn open(path: impl AsRef<Path>) -> Result<Self>;
    pub fn open_with_cache_size(path: impl AsRef<Path>, size: usize) -> Result<Self>;

    // Cached lookup
    pub fn lookup_codes(&self, ip: IpAddr) -> Vec<String>;

    // Delegation
    pub fn database_type(&self) -> DatabaseType;

    // Cache management
    pub fn clear_cache(&self);
    pub fn cache_len(&self) -> usize;
}
```

### Cache Logic

```rust
pub fn lookup_codes(&self, ip: IpAddr) -> Vec<String> {
    // 1. Check cache first
    if let Some(codes) = self.cache.lock().unwrap().get(&ip) {
        return codes.clone();
    }
    // 2. Cache miss, query database
    let codes = self.reader.lookup_codes(ip);
    // 3. Store in cache
    self.cache.lock().unwrap().put(ip, codes.clone());
    codes
}
```

## Files Changed

- **New**: `src/matcher/domain/mod.rs`
- **New**: `src/matcher/domain/succinct.rs`
- **New**: `src/matcher/domain/matcher.rs`
- **Modified**: `src/matcher/mod.rs` (export new module)
- **Modified**: `src/matcher/geosite.rs` (use SuccinctMatcher)
- **Modified**: `src/geo/metadb/mod.rs` (add CachedMetaDbReader)

## Reference

- Go implementation: `github.com/xflash-panda/acl-engine` branch `feat/performance-optimize-domain-matcher`
- Commits: `51c0345` (Succinct Trie), `e5729ab` (MetaDB Cache)
