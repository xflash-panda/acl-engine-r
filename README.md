# ACL Engine for Rust

高性能访问控制列表 (ACL) 引擎，从 [Hysteria](https://github.com/apernet/hysteria) 项目提取并移植到 Rust。

## 功能特性

- **IP/CIDR 匹配**: 支持单个 IP 和 CIDR 范围匹配
- **域名匹配**: 精确匹配、通配符匹配 (`*.example.com`)、后缀匹配 (`suffix:example.com`)
- **GeoIP 匹配**: 支持多种格式 (DAT, MMDB, MetaDB)
- **GeoSite 匹配**: 支持多种格式 (DAT, sing-geosite)，域名列表匹配，支持属性过滤
- **自动下载**: AutoGeoLoader 支持自动下载和更新 GeoIP/GeoSite 数据文件
- **协议/端口过滤**: TCP/UDP 协议和端口范围过滤
- **高性能缓存**: LRU 缓存加速重复查询
- **线程安全**: 支持多线程并发访问
- **出口连接**: 支持 Direct、Reject、SOCKS5、HTTP 代理
- **DNS 解析**: 可配置的 DNS 解析器
- **路由器**: 整合 ACL + Resolver + Outbound 的完整路由解决方案

## 安装

在 `Cargo.toml` 中添加依赖：

```toml
[dependencies]
acl-engine = { git = "https://github.com/xflash-panda/acl-engine-r" }
```

## 快速开始

```rust
use std::collections::HashMap;
use acl_engine::{parse_rules, compile, Protocol, HostInfo};
use acl_engine::geo::NilGeoLoader;

fn main() {
    // 1. 定义规则
    let rules_text = "
        direct(192.168.0.0/16)       # 私有网络直连
        direct(10.0.0.0/8)
        proxy(*.google.com)          # Google 走代理
        proxy(suffix:youtube.com)    # YouTube 及子域名走代理
        reject(all, udp/443)         # 阻止 QUIC
        proxy(all)                   # 默认走代理
    ";

    // 2. 解析规则
    let rules = parse_rules(rules_text).unwrap();

    // 3. 定义出口
    let mut outbounds = HashMap::new();
    outbounds.insert("direct".to_string(), "DIRECT");
    outbounds.insert("proxy".to_string(), "PROXY");
    outbounds.insert("reject".to_string(), "REJECT");

    // 4. 编译规则 (缓存大小: 1024)
    let engine = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();

    // 5. 匹配流量
    let host = HostInfo::from_name("www.google.com");
    if let Some(result) = engine.match_host(&host, Protocol::TCP, 443) {
        println!("Outbound: {:?}", result.outbound); // 输出: "PROXY"
    }
}
```

## 规则语法

### 基本格式

```
出口名(地址[, 协议/端口][, 劫持地址])
```

### 地址类型

| 类型 | 示例 | 说明 |
|------|------|------|
| IP | `1.2.3.4` | 单个 IP 地址 |
| CIDR | `192.168.0.0/16` | IP 范围 |
| 域名 | `example.com` | 精确匹配 |
| 通配符 | `*.example.com` | 匹配所有子域名 |
| 后缀 | `suffix:example.com` | 匹配域名及其所有子域名 |
| GeoIP | `geoip:cn` | 按国家匹配 IP |
| GeoSite | `geosite:google` | 域名列表匹配 |
| 全部 | `all` 或 `*` | 匹配所有流量 |

### 协议/端口规格

| 格式 | 说明 |
|------|------|
| `tcp/443` | TCP 端口 443 |
| `udp/53` | UDP 端口 53 |
| `*/80` | 所有协议，端口 80 |
| `tcp/8000-9000` | TCP 端口范围 8000-9000 |

### 规则示例

```
# 私有网络直连
direct(192.168.0.0/16)
direct(10.0.0.0/8)
direct(172.16.0.0/12)

# 国内 IP 直连
direct(geoip:cn)

# 特定域名走代理
proxy(*.google.com)
proxy(*.youtube.com)
proxy(geosite:netflix)

# 阻止 QUIC 协议
reject(all, udp/443)

# DNS 劫持到本地
direct(all, udp/53, 127.0.0.1)

# 默认规则 (放在最后)
proxy(all)
```

## 高级用法

### GeoIP/GeoSite 格式支持

本库支持与 Go 版本完全对齐的 GeoIP/GeoSite 数据格式：

| 类型 | 格式 | 扩展名 | 说明 |
|------|------|--------|------|
| GeoIP | V2Ray DAT | `.dat` | Protobuf 格式 |
| GeoIP | MaxMind MMDB | `.mmdb` | MaxMind 数据库格式 |
| GeoIP | Clash MetaDB | `.metadb` | Clash Meta 专用格式 |
| GeoSite | V2Ray DAT | `.dat` | Protobuf 格式 |
| GeoSite | sing-geosite | `.db` | sing-box 二进制格式 |

### 使用 FileGeoLoader

```rust
use acl_engine::geo::FileGeoLoader;

// 根据文件扩展名自动检测格式
let geo_loader = FileGeoLoader::new()
    .with_geoip_path("/path/to/geoip.dat")      // 或 .mmdb, .metadb
    .with_geosite_path("/path/to/geosite.dat"); // 或 .db

let engine = compile(&rules, &outbounds, 1024, &geo_loader).unwrap();
```

### 使用 AutoGeoLoader (自动下载)

```rust
use acl_engine::geo::{AutoGeoLoader, GeoIpFormat, GeoSiteFormat};
use std::time::Duration;

// 创建自动下载的 GeoLoader
let geo_loader = AutoGeoLoader::new("/path/to/data/dir")
    .with_geoip_format(GeoIpFormat::Dat)       // 可选: Dat, Mmdb, MetaDb
    .with_geosite_format(GeoSiteFormat::Sing)  // 可选: Dat, Sing
    .with_update_interval(Duration::from_secs(7 * 24 * 3600)); // 7天更新

// 预下载数据文件 (可选)
geo_loader.ensure_files()?;

let engine = compile(&rules, &outbounds, 1024, &geo_loader).unwrap();
```

AutoGeoLoader 特性：
- 自动从 CDN 下载 GeoIP/GeoSite 数据文件
- 支持自定义下载 URL
- 支持定期更新检查
- 文件完整性验证

### 使用 IP 地址匹配

```rust
use std::net::IpAddr;

// 创建带 IP 的 HostInfo
let ip: IpAddr = "8.8.8.8".parse().unwrap();
let host = HostInfo::new("dns.google", Some(ip), None);

let result = engine.match_host(&host, Protocol::UDP, 53);
```

### 自定义出口类型

```rust
#[derive(Clone, Debug)]
enum MyOutbound {
    Direct,
    Proxy(String),
    Reject,
}

let mut outbounds = HashMap::new();
outbounds.insert("direct".to_string(), MyOutbound::Direct);
outbounds.insert("proxy".to_string(), MyOutbound::Proxy("server1".into()));
outbounds.insert("reject".to_string(), MyOutbound::Reject);

let engine = compile(&rules, &outbounds, 1024, &NilGeoLoader).unwrap();
```

## API 参考

### 主要类型

- `TextRule`: 解析后的文本规则
- `CompiledRuleSet<O>`: 编译后的规则集
- `HostInfo`: 主机信息 (域名 + IP)
- `MatchResult<O>`: 匹配结果
- `Protocol`: 协议类型 (TCP/UDP/Both)

### 主要函数

- `parse_rules(text: &str) -> Result<Vec<TextRule>>`: 解析规则文本
- `compile(rules, outbounds, cache_size, geo_loader) -> Result<CompiledRuleSet<O>>`: 编译规则
- `CompiledRuleSet::match_host(host, protocol, port) -> Option<MatchResult<O>>`: 匹配主机

### GeoLoader 特征

```rust
pub trait GeoLoader: Send + Sync {
    fn load_geoip(&self, country_code: &str) -> Result<GeoIpMatcher>;
    fn load_geosite(&self, site_name: &str) -> Result<GeoSiteMatcher>;
}
```

### Geo 格式枚举

```rust
use acl_engine::geo::{GeoIpFormat, GeoSiteFormat};

// GeoIP 格式
pub enum GeoIpFormat {
    Dat,     // V2Ray DAT (protobuf)
    Mmdb,    // MaxMind MMDB
    MetaDb,  // Clash MetaDB
}

// GeoSite 格式
pub enum GeoSiteFormat {
    Dat,   // V2Ray DAT (protobuf)
    Sing,  // sing-geosite DB
}
```

## Outbound 出口

本库提供与 Go 版本对齐的出口连接实现：

### Direct (直连)

```rust
use acl_engine::{Direct, DirectMode, Outbound, Addr};

// 创建直连出口
let direct = Direct::new();

// 指定模式 (Auto, Prefer64, Prefer46, Only6, Only4)
let direct = Direct::with_mode(DirectMode::Prefer46);

// 使用出口
let mut addr = Addr::new("example.com", 80);
let conn = direct.dial_tcp(&mut addr)?;
```

### Reject (拒绝)

```rust
use acl_engine::{Reject, Outbound};

let reject = Reject::new();
// 所有连接都会被拒绝
```

### SOCKS5 代理

```rust
use acl_engine::{Socks5, Outbound, Addr};

// 无认证
let socks5 = Socks5::new("127.0.0.1:1080");

// 带认证
let socks5 = Socks5::with_auth("127.0.0.1:1080", "user", "pass");

let mut addr = Addr::new("example.com", 80);
let conn = socks5.dial_tcp(&mut addr)?;
```

### HTTP 代理

```rust
use acl_engine::{Http, Outbound, Addr};

// 从 URL 创建 (支持 http:// 和 https://)
let http = Http::from_url("http://proxy.example.com:8080")?;

// 带认证
let http = Http::from_url("http://user:pass@proxy.example.com:8080")?;

let mut addr = Addr::new("example.com", 80);
let conn = http.dial_tcp(&mut addr)?;
// 注意: HTTP 代理不支持 UDP
```

## Router 路由器

Router 整合了 ACL 规则、DNS 解析和出口连接：

```rust
use std::sync::Arc;
use acl_engine::{
    Router, RouterOptions, OutboundEntry,
    Direct, Socks5, SystemResolver,
    NilGeoLoader,
};

// 定义出口
let outbounds = vec![
    OutboundEntry::new("direct", Arc::new(Direct::new())),
    OutboundEntry::new("proxy", Arc::new(Socks5::new("127.0.0.1:1080"))),
];

// ACL 规则
let rules = r#"
    direct(192.168.0.0/16)
    direct(geoip:cn)
    proxy(geosite:google)
    proxy(all)
"#;

// 创建路由器
let router = Router::new(
    rules,
    outbounds,
    &NilGeoLoader,
    RouterOptions::new()
        .with_cache_size(1024)
        .with_resolver(SystemResolver::new()),
)?;

// 路由连接
let mut addr = Addr::new("www.google.com", 443);
let conn = router.dial_tcp(&mut addr)?;
```

## Resolver DNS 解析器

```rust
use acl_engine::{SystemResolver, StaticResolver, NilResolver, Resolver};

// 系统解析器 (使用 OS DNS)
let resolver = SystemResolver::new();

// 静态解析器 (预定义映射)
let resolver = StaticResolver::new()
    .with_mapping("example.com", Some("93.184.216.34".parse().unwrap()), None);

// 空解析器 (不解析)
let resolver = NilResolver::new();
```

## 性能优化

1. **LRU 缓存**: 缓存匹配结果，避免重复计算
2. **静态分发**: 使用 `enum Matcher` 代替 trait object
3. **惰性加载**: GeoIP/GeoSite 数据按需加载
4. **零拷贝**: 尽可能使用字符串切片

## 与 Go 版本的兼容性

本库与 [acl-engine](https://github.com/xflash-panda/acl-engine) (Go 版本) 完全兼容：

- **规则语法**: 100% 兼容，配置文件可以直接复用
- **GeoIP 格式**: 支持 DAT、MMDB、MetaDB (与 Go 版本对齐)
- **GeoSite 格式**: 支持 DAT、sing-geosite (与 Go 版本对齐)
- **AutoGeoLoader**: 自动下载功能，与 Go 版本行为一致
- **Outbound**: Direct、Reject、SOCKS5、HTTP (与 Go 版本对齐)
- **Resolver**: DNS 解析器接口 (与 Go 版本对齐)
- **Router**: 完整路由器实现 (与 Go 版本对齐)

### 默认 CDN 源

| 格式 | URL |
|------|-----|
| geoip.dat | `https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat` |
| geoip.mmdb | `https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb` |
| geoip.metadb | `https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb` |
| geosite.dat | `https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat` |
| geosite.db | `https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.db` |

## 许可证

MIT License
    