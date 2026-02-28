//! Integration tests for GeoIP and GeoSite with real data files.

use std::net::IpAddr;
use std::path::PathBuf;

use acl_engine_r::geo::{dat, mmdb, singsite, GeoIpFormat, GeoSiteFormat};
use acl_engine_r::geo::{FileGeoLoader, GeoLoader};
use acl_engine_r::matcher::{GeoIpMatcher, GeoSiteMatcher, HostMatcher};
use acl_engine_r::HostInfo;

fn testdata_path(filename: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("testdata");
    path.push(filename);
    path
}

mod geoip_dat_tests {
    use super::*;

    #[test]
    fn test_load_geoip_dat() {
        let path = testdata_path("geoip.dat");
        if !path.exists() {
            eprintln!("Skipping test: geoip.dat not found");
            return;
        }

        let result = dat::load_geoip(&path);
        assert!(
            result.is_ok(),
            "Failed to load geoip.dat: {:?}",
            result.err()
        );

        let data = result.unwrap();
        assert!(!data.is_empty(), "GeoIP data should not be empty");

        // Check for common country codes
        assert!(data.contains_key("cn"), "Should contain CN");
        assert!(data.contains_key("us"), "Should contain US");
        assert!(data.contains_key("jp"), "Should contain JP");
    }

    #[test]
    fn test_geoip_dat_cn_lookup() {
        let path = testdata_path("geoip.dat");
        if !path.exists() {
            eprintln!("Skipping test: geoip.dat not found");
            return;
        }

        let data = dat::load_geoip(&path).unwrap();
        let cn_cidrs = data.get("cn").expect("CN should exist");

        // Create matcher
        let matcher = GeoIpMatcher::from_cidrs("cn", cn_cidrs.clone());

        // Test some known Chinese IPs
        let chinese_ips = [
            "114.114.114.114", // Chinese DNS
            "223.5.5.5",       // Alibaba DNS
            "119.29.29.29",    // Tencent DNS
        ];

        for ip_str in &chinese_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            let host = HostInfo::from_ip(ip);
            assert!(matcher.matches(&host), "IP {} should be in CN", ip_str);
        }

        // Test non-Chinese IPs
        let non_chinese_ips = [
            "8.8.8.8", // Google DNS
            "1.1.1.1", // Cloudflare DNS
        ];

        for ip_str in &non_chinese_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            let host = HostInfo::from_ip(ip);
            assert!(!matcher.matches(&host), "IP {} should NOT be in CN", ip_str);
        }
    }

    #[test]
    fn test_geoip_dat_us_lookup() {
        let path = testdata_path("geoip.dat");
        if !path.exists() {
            eprintln!("Skipping test: geoip.dat not found");
            return;
        }

        let data = dat::load_geoip(&path).unwrap();
        let us_cidrs = data.get("us").expect("US should exist");
        let matcher = GeoIpMatcher::from_cidrs("us", us_cidrs.clone());

        // Test known US IPs
        let us_ips = [
            "8.8.8.8", // Google DNS
            "8.8.4.4", // Google DNS
        ];

        for ip_str in &us_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            let host = HostInfo::from_ip(ip);
            assert!(matcher.matches(&host), "IP {} should be in US", ip_str);
        }
    }
}

mod geoip_mmdb_tests {
    use super::*;

    #[test]
    fn test_mmdb_verify() {
        let path = testdata_path("country.mmdb");
        if !path.exists() {
            eprintln!("Skipping test: country.mmdb not found");
            return;
        }

        let result = mmdb::verify(&path);
        assert!(
            result.is_ok(),
            "Failed to verify country.mmdb: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_mmdb_lookup() {
        let path = testdata_path("country.mmdb");
        if !path.exists() {
            eprintln!("Skipping test: country.mmdb not found");
            return;
        }

        let reader = mmdb::open_shared(&path).unwrap();

        // Test US IP (note: MetaCubeX MMDB may return organization codes like "GOOGLE" for Google IPs)
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let code = mmdb::lookup_ip(&reader, ip);
        assert!(code.is_some(), "8.8.8.8 should have a code");

        // Test CN IP
        let ip: IpAddr = "114.114.114.114".parse().unwrap();
        let code = mmdb::lookup_ip(&reader, ip);
        assert_eq!(code, Some("CN".to_string()), "114.114.114.114 should be CN");
    }
}

mod geoip_metadb_tests {
    use super::*;
    use acl_engine_r::geo::metadb;

    #[test]
    fn test_metadb_verify() {
        let path = testdata_path("geoip.metadb");
        if !path.exists() {
            eprintln!("Skipping test: geoip.metadb not found");
            return;
        }

        let result = metadb::verify(&path);
        assert!(
            result.is_ok(),
            "Failed to verify geoip.metadb: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_metadb_reader() {
        let path = testdata_path("geoip.metadb");
        if !path.exists() {
            eprintln!("Skipping test: geoip.metadb not found");
            return;
        }

        let reader = metadb::MetaDbReader::open(&path).unwrap();

        // Check database type
        let db_type = reader.database_type();
        assert_ne!(
            db_type,
            metadb::DatabaseType::Unknown,
            "Should detect database type"
        );

        // Test CN IP lookup
        let ip: IpAddr = "114.114.114.114".parse().unwrap();
        let codes = reader.lookup_codes(ip);
        assert!(!codes.is_empty(), "114.114.114.114 should have codes");
        assert!(
            codes.iter().any(|c| c.to_uppercase() == "CN"),
            "114.114.114.114 should be in CN, got: {:?}",
            codes
        );

        // Test US IP lookup
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let codes = reader.lookup_codes(ip);
        assert!(!codes.is_empty(), "8.8.8.8 should have codes");
    }

    #[test]
    fn test_metadb_load_geoip() {
        let path = testdata_path("geoip.metadb");
        if !path.exists() {
            eprintln!("Skipping test: geoip.metadb not found");
            return;
        }

        // MetaDB returns empty map (uses on-demand lookup)
        let result = metadb::load_geoip(&path);
        assert!(
            result.is_ok(),
            "Failed to load geoip.metadb: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_metadb_open_shared() {
        let path = testdata_path("geoip.metadb");
        if !path.exists() {
            eprintln!("Skipping test: geoip.metadb not found");
            return;
        }

        let reader = metadb::open_shared(&path);
        assert!(
            reader.is_ok(),
            "Failed to open shared MetaDB reader: {:?}",
            reader.err()
        );
    }
}

mod geosite_dat_tests {
    use super::*;

    #[test]
    fn test_load_geosite_dat() {
        let path = testdata_path("geosite.dat");
        if !path.exists() {
            eprintln!("Skipping test: geosite.dat not found");
            return;
        }

        let result = dat::load_geosite(&path);
        assert!(
            result.is_ok(),
            "Failed to load geosite.dat: {:?}",
            result.err()
        );

        let data = result.unwrap();
        assert!(!data.is_empty(), "GeoSite data should not be empty");

        // Check for common categories
        assert!(data.contains_key("google"), "Should contain google");
        assert!(data.contains_key("cn"), "Should contain cn");
    }

    #[test]
    fn test_geosite_dat_google() {
        let path = testdata_path("geosite.dat");
        if !path.exists() {
            eprintln!("Skipping test: geosite.dat not found");
            return;
        }

        let data = dat::load_geosite(&path).unwrap();
        let google_entries = data.get("google").expect("google should exist");

        let matcher = GeoSiteMatcher::new("google", google_entries.clone());

        // Test Google domains
        let google_domains = [
            "google.com",
            "www.google.com",
            "mail.google.com",
            "youtube.com",
            "www.youtube.com",
        ];

        for domain in &google_domains {
            let host = HostInfo::from_name(*domain);
            assert!(
                matcher.matches(&host),
                "Domain {} should match google geosite",
                domain
            );
        }

        // Test non-Google domains
        let non_google_domains = ["baidu.com", "example.com", "microsoft.com"];

        for domain in &non_google_domains {
            let host = HostInfo::from_name(*domain);
            assert!(
                !matcher.matches(&host),
                "Domain {} should NOT match google geosite",
                domain
            );
        }
    }

    #[test]
    fn test_geosite_dat_cn() {
        let path = testdata_path("geosite.dat");
        if !path.exists() {
            eprintln!("Skipping test: geosite.dat not found");
            return;
        }

        let data = dat::load_geosite(&path).unwrap();
        let cn_entries = data.get("cn").expect("cn should exist");

        let matcher = GeoSiteMatcher::new("cn", cn_entries.clone());

        // Test Chinese domains
        let cn_domains = ["baidu.com", "www.baidu.com", "taobao.com", "qq.com"];

        for domain in &cn_domains {
            let host = HostInfo::from_name(*domain);
            assert!(
                matcher.matches(&host),
                "Domain {} should match cn geosite",
                domain
            );
        }
    }
}

mod geosite_sing_tests {
    use super::*;

    #[test]
    fn test_load_geosite_sing() {
        let path = testdata_path("geosite.db");
        if !path.exists() {
            eprintln!("Skipping test: geosite.db not found");
            return;
        }

        let result = singsite::load_geosite(&path);
        assert!(
            result.is_ok(),
            "Failed to load geosite.db: {:?}",
            result.err()
        );

        let data = result.unwrap();
        assert!(!data.is_empty(), "GeoSite data should not be empty");

        // Check for common categories
        assert!(data.contains_key("google"), "Should contain google");
    }

    #[test]
    fn test_geosite_sing_google() {
        let path = testdata_path("geosite.db");
        if !path.exists() {
            eprintln!("Skipping test: geosite.db not found");
            return;
        }

        let data = singsite::load_geosite(&path).unwrap();
        let google_entries = data.get("google").expect("google should exist");

        let matcher = GeoSiteMatcher::new("google", google_entries.clone());

        // Test Google domains
        assert!(matcher.matches(&HostInfo::from_name("google.com")));
        assert!(matcher.matches(&HostInfo::from_name("www.google.com")));
        assert!(matcher.matches(&HostInfo::from_name("youtube.com")));
    }

    #[test]
    fn test_singsite_reader() {
        let path = testdata_path("geosite.db");
        if !path.exists() {
            eprintln!("Skipping test: geosite.db not found");
            return;
        }

        let (mut reader, codes) = singsite::SingSiteReader::open(&path).unwrap();

        assert!(!codes.is_empty(), "Should have country codes");
        assert!(
            codes.iter().any(|c| c.to_lowercase() == "google"),
            "Should have google"
        );

        // Read specific code
        let items = reader.read("google").unwrap();
        assert!(!items.is_empty(), "google should have entries");
    }
}

mod file_geo_loader_tests {
    use super::*;

    #[test]
    fn test_file_geo_loader_dat() {
        let geoip_path = testdata_path("geoip.dat");
        let geosite_path = testdata_path("geosite.dat");

        if !geoip_path.exists() || !geosite_path.exists() {
            eprintln!("Skipping test: test data files not found");
            return;
        }

        let loader = FileGeoLoader::new()
            .with_geoip_path(&geoip_path)
            .with_geosite_path(&geosite_path);

        // Test GeoIP loading
        let geoip_matcher = loader.load_geoip("cn");
        assert!(
            geoip_matcher.is_ok(),
            "Failed to load geoip:cn: {:?}",
            geoip_matcher.err()
        );

        let matcher = geoip_matcher.unwrap();
        let ip: IpAddr = "114.114.114.114".parse().unwrap();
        let host = HostInfo::from_ip(ip);
        assert!(matcher.matches(&host), "114.114.114.114 should be in CN");

        // Test GeoSite loading
        let geosite_matcher = loader.load_geosite("google");
        assert!(
            geosite_matcher.is_ok(),
            "Failed to load geosite:google: {:?}",
            geosite_matcher.err()
        );

        let matcher = geosite_matcher.unwrap();
        let host = HostInfo::from_name("google.com");
        assert!(matcher.matches(&host), "google.com should match");
    }

    #[test]
    fn test_file_geo_loader_mmdb() {
        let geoip_path = testdata_path("country.mmdb");

        if !geoip_path.exists() {
            eprintln!("Skipping test: country.mmdb not found");
            return;
        }

        let loader = FileGeoLoader::new().with_geoip_path(&geoip_path);

        let matcher = loader.load_geoip("cn").unwrap();

        // Bug: MMDB load_geoip returns empty HashMap, so matcher never matches.
        // Verify that MMDB GeoIP actually matches known Chinese IPs.
        let ip: IpAddr = "114.114.114.114".parse().unwrap();
        let host = HostInfo::from_ip(ip);
        assert!(
            matcher.matches(&host),
            "114.114.114.114 should be in CN via MMDB FileGeoLoader"
        );
    }

    #[test]
    fn test_file_geo_loader_metadb() {
        let geoip_path = testdata_path("geoip.metadb");

        if !geoip_path.exists() {
            eprintln!("Skipping test: geoip.metadb not found");
            return;
        }

        let loader = FileGeoLoader::new().with_geoip_path(&geoip_path);

        let matcher = loader.load_geoip("cn").unwrap();

        // Bug: MetaDB load_geoip returns empty HashMap, so matcher never matches.
        // Verify that MetaDB GeoIP actually matches known Chinese IPs.
        let ip: IpAddr = "114.114.114.114".parse().unwrap();
        let host = HostInfo::from_ip(ip);
        assert!(
            matcher.matches(&host),
            "114.114.114.114 should be in CN via MetaDB FileGeoLoader"
        );
    }

    #[test]
    fn test_file_geo_loader_sing() {
        let geosite_path = testdata_path("geosite.db");

        if !geosite_path.exists() {
            eprintln!("Skipping test: geosite.db not found");
            return;
        }

        let loader = FileGeoLoader::new().with_geosite_path(&geosite_path);

        let matcher = loader.load_geosite("google").unwrap();
        let host1 = HostInfo::from_name("google.com");
        let host2 = HostInfo::from_name("youtube.com");
        assert!(matcher.matches(&host1), "google.com should match");
        assert!(matcher.matches(&host2), "youtube.com should match");
    }
}

mod format_detection_tests {
    use super::*;

    #[test]
    fn test_geoip_format_detection() {
        assert_eq!(GeoIpFormat::detect("geoip.dat"), Some(GeoIpFormat::Dat));
        assert_eq!(GeoIpFormat::detect("country.mmdb"), Some(GeoIpFormat::Mmdb));
        assert_eq!(
            GeoIpFormat::detect("geoip.metadb"),
            Some(GeoIpFormat::MetaDb)
        );
        assert_eq!(GeoIpFormat::detect("unknown.txt"), None);
    }

    #[test]
    fn test_geosite_format_detection() {
        assert_eq!(
            GeoSiteFormat::detect("geosite.dat"),
            Some(GeoSiteFormat::Dat)
        );
        assert_eq!(
            GeoSiteFormat::detect("geosite.db"),
            Some(GeoSiteFormat::Sing)
        );
        assert_eq!(GeoSiteFormat::detect("unknown.txt"), None);
    }

    #[test]
    fn test_format_default_filenames() {
        assert_eq!(GeoIpFormat::Dat.default_filename(), "geoip.dat");
        assert_eq!(GeoIpFormat::Mmdb.default_filename(), "geoip.mmdb");
        assert_eq!(GeoIpFormat::MetaDb.default_filename(), "geoip.metadb");

        assert_eq!(GeoSiteFormat::Dat.default_filename(), "geosite.dat");
        assert_eq!(GeoSiteFormat::Sing.default_filename(), "geosite.db");
    }
}

mod router_tests {
    use super::*;
    use acl_engine_r::outbound::Outbound;
    use acl_engine_r::{Direct, OutboundEntry, Reject, Router, RouterOptions};
    use std::sync::Arc;

    #[test]
    fn test_router_with_geoip_rules() {
        let geoip_path = testdata_path("geoip.dat");
        let geosite_path = testdata_path("geosite.dat");

        if !geoip_path.exists() || !geosite_path.exists() {
            eprintln!("Skipping test: test data files not found");
            return;
        }

        let geo_loader = FileGeoLoader::new()
            .with_geoip_path(&geoip_path)
            .with_geosite_path(&geosite_path);

        let rules = r#"
            direct(geoip:cn)
            proxy(geoip:us)
            direct(all)
        "#;

        let outbounds: Vec<OutboundEntry> = vec![
            OutboundEntry::new("direct", Arc::new(Direct::new()) as Arc<dyn Outbound>),
            OutboundEntry::new("proxy", Arc::new(Direct::new()) as Arc<dyn Outbound>),
        ];

        let options: RouterOptions = RouterOptions::new().with_cache_size(1024);

        let router = Router::new(rules, outbounds, &geo_loader, options);
        assert!(
            router.is_ok(),
            "Failed to create router: {:?}",
            router.err()
        );
    }

    #[test]
    fn test_router_with_geosite_rules() {
        let geoip_path = testdata_path("geoip.dat");
        let geosite_path = testdata_path("geosite.dat");

        if !geoip_path.exists() || !geosite_path.exists() {
            eprintln!("Skipping test: test data files not found");
            return;
        }

        let geo_loader = FileGeoLoader::new()
            .with_geoip_path(&geoip_path)
            .with_geosite_path(&geosite_path);

        let rules = r#"
            proxy(geosite:google)
            proxy(geosite:youtube)
            direct(geosite:cn)
            direct(all)
        "#;

        let outbounds: Vec<OutboundEntry> = vec![
            OutboundEntry::new("direct", Arc::new(Direct::new()) as Arc<dyn Outbound>),
            OutboundEntry::new("proxy", Arc::new(Direct::new()) as Arc<dyn Outbound>),
        ];

        let options: RouterOptions = RouterOptions::new().with_cache_size(1024);

        let router = Router::new(rules, outbounds, &geo_loader, options);
        assert!(
            router.is_ok(),
            "Failed to create router: {:?}",
            router.err()
        );
    }

    #[test]
    fn test_router_mixed_rules() {
        let geoip_path = testdata_path("geoip.dat");
        let geosite_path = testdata_path("geosite.dat");

        if !geoip_path.exists() || !geosite_path.exists() {
            eprintln!("Skipping test: test data files not found");
            return;
        }

        let geo_loader = FileGeoLoader::new()
            .with_geoip_path(&geoip_path)
            .with_geosite_path(&geosite_path);

        // Complex rules mixing IP, domain, geoip, geosite
        let rules = r#"
            # Private networks
            direct(192.168.0.0/16)
            direct(10.0.0.0/8)
            direct(172.16.0.0/12)

            # Block QUIC
            reject(all, udp/443)

            # Chinese IPs direct
            direct(geoip:cn)

            # Google services via proxy
            proxy(geosite:google)

            # Chinese sites direct
            direct(geosite:cn)

            # Default proxy
            proxy(all)
        "#;

        let outbounds: Vec<OutboundEntry> = vec![
            OutboundEntry::new("direct", Arc::new(Direct::new()) as Arc<dyn Outbound>),
            OutboundEntry::new("proxy", Arc::new(Direct::new()) as Arc<dyn Outbound>),
            OutboundEntry::new("reject", Arc::new(Reject::new()) as Arc<dyn Outbound>),
        ];

        let options: RouterOptions = RouterOptions::new().with_cache_size(2048);

        let router = Router::new(rules, outbounds, &geo_loader, options);
        assert!(
            router.is_ok(),
            "Failed to create router with mixed rules: {:?}",
            router.err()
        );
    }

    #[test]
    fn test_router_with_sing_geosite() {
        let geoip_path = testdata_path("geoip.dat");
        let geosite_path = testdata_path("geosite.db");

        if !geoip_path.exists() || !geosite_path.exists() {
            eprintln!("Skipping test: test data files not found");
            return;
        }

        let geo_loader = FileGeoLoader::new()
            .with_geoip_path(&geoip_path)
            .with_geosite_path(&geosite_path);

        let rules = r#"
            proxy(geosite:google)
            direct(all)
        "#;

        let outbounds: Vec<OutboundEntry> = vec![
            OutboundEntry::new("direct", Arc::new(Direct::new()) as Arc<dyn Outbound>),
            OutboundEntry::new("proxy", Arc::new(Direct::new()) as Arc<dyn Outbound>),
        ];

        let options: RouterOptions = RouterOptions::new();

        let router = Router::new(rules, outbounds, &geo_loader, options);
        assert!(
            router.is_ok(),
            "Failed to create router with sing-geosite: {:?}",
            router.err()
        );
    }

    #[test]
    fn test_router_with_mmdb() {
        let geoip_path = testdata_path("country.mmdb");
        let geosite_path = testdata_path("geosite.dat");

        if !geoip_path.exists() || !geosite_path.exists() {
            eprintln!("Skipping test: test data files not found");
            return;
        }

        let geo_loader = FileGeoLoader::new()
            .with_geoip_path(&geoip_path)
            .with_geosite_path(&geosite_path);

        // Note: MMDB doesn't support pre-loading country data
        // This test verifies router creation doesn't panic
        let rules = r#"
            direct(192.168.0.0/16)
            proxy(geosite:google)
            direct(all)
        "#;

        let outbounds: Vec<OutboundEntry> = vec![
            OutboundEntry::new("direct", Arc::new(Direct::new()) as Arc<dyn Outbound>),
            OutboundEntry::new("proxy", Arc::new(Direct::new()) as Arc<dyn Outbound>),
        ];

        let options: RouterOptions = RouterOptions::new();

        let router = Router::new(rules, outbounds, &geo_loader, options);
        assert!(
            router.is_ok(),
            "Failed to create router with MMDB: {:?}",
            router.err()
        );
    }
}

mod compiled_ruleset_tests {
    use super::*;
    use acl_engine_r::{compile, parse_rules, Protocol};

    #[test]
    fn test_compiled_ruleset_with_real_geoip() {
        let geoip_path = testdata_path("geoip.dat");
        let geosite_path = testdata_path("geosite.dat");

        if !geoip_path.exists() || !geosite_path.exists() {
            eprintln!("Skipping test: test data files not found");
            return;
        }

        let geo_loader = FileGeoLoader::new()
            .with_geoip_path(&geoip_path)
            .with_geosite_path(&geosite_path);

        let rules_text = r#"
            direct(geoip:cn)
            proxy(all)
        "#;

        let rules = parse_rules(rules_text).unwrap();

        let mut outbounds = std::collections::HashMap::new();
        outbounds.insert("direct".to_string(), "DIRECT".to_string());
        outbounds.insert("proxy".to_string(), "PROXY".to_string());

        let ruleset = compile(&rules, &outbounds, 1024, &geo_loader);
        assert!(
            ruleset.is_ok(),
            "Failed to compile rules: {:?}",
            ruleset.err()
        );

        let ruleset = ruleset.unwrap();

        // Test Chinese IP
        let host = HostInfo::from_ip("114.114.114.114".parse().unwrap());
        let result = ruleset.match_host(&host, Protocol::TCP, 443);
        assert!(result.is_some());
        assert_eq!(result.unwrap().outbound, "DIRECT");

        // Test US IP
        let host = HostInfo::from_ip("8.8.8.8".parse().unwrap());
        let result = ruleset.match_host(&host, Protocol::TCP, 443);
        assert!(result.is_some());
        assert_eq!(result.unwrap().outbound, "PROXY");
    }

    #[test]
    fn test_compiled_ruleset_with_real_geosite() {
        let geoip_path = testdata_path("geoip.dat");
        let geosite_path = testdata_path("geosite.dat");

        if !geoip_path.exists() || !geosite_path.exists() {
            eprintln!("Skipping test: test data files not found");
            return;
        }

        let geo_loader = FileGeoLoader::new()
            .with_geoip_path(&geoip_path)
            .with_geosite_path(&geosite_path);

        let rules_text = r#"
            proxy(geosite:google)
            direct(geosite:cn)
            reject(all)
        "#;

        let rules = parse_rules(rules_text).unwrap();

        let mut outbounds = std::collections::HashMap::new();
        outbounds.insert("direct".to_string(), "DIRECT".to_string());
        outbounds.insert("proxy".to_string(), "PROXY".to_string());
        outbounds.insert("reject".to_string(), "REJECT".to_string());

        let ruleset = compile(&rules, &outbounds, 1024, &geo_loader);
        assert!(
            ruleset.is_ok(),
            "Failed to compile rules: {:?}",
            ruleset.err()
        );

        let ruleset = ruleset.unwrap();

        // Test Google domain
        let host = HostInfo::from_name("www.google.com");
        let result = ruleset.match_host(&host, Protocol::TCP, 443);
        assert!(result.is_some());
        assert_eq!(result.unwrap().outbound, "PROXY");

        // Test YouTube domain (part of google geosite)
        let host = HostInfo::from_name("youtube.com");
        let result = ruleset.match_host(&host, Protocol::TCP, 443);
        assert!(result.is_some());
        assert_eq!(result.unwrap().outbound, "PROXY");

        // Test Chinese domain
        let host = HostInfo::from_name("baidu.com");
        let result = ruleset.match_host(&host, Protocol::TCP, 443);
        assert!(result.is_some());
        assert_eq!(result.unwrap().outbound, "DIRECT");

        // Test unknown domain (should reject)
        let host = HostInfo::from_name("example.org");
        let result = ruleset.match_host(&host, Protocol::TCP, 443);
        assert!(result.is_some());
        assert_eq!(result.unwrap().outbound, "REJECT");
    }

    #[test]
    fn test_compiled_ruleset_protocol_port_filter() {
        let geoip_path = testdata_path("geoip.dat");
        let geosite_path = testdata_path("geosite.dat");

        if !geoip_path.exists() || !geosite_path.exists() {
            eprintln!("Skipping test: test data files not found");
            return;
        }

        let geo_loader = FileGeoLoader::new()
            .with_geoip_path(&geoip_path)
            .with_geosite_path(&geosite_path);

        let rules_text = r#"
            reject(all, udp/443)
            direct(geoip:cn)
            proxy(all)
        "#;

        let rules = parse_rules(rules_text).unwrap();

        let mut outbounds = std::collections::HashMap::new();
        outbounds.insert("direct".to_string(), "DIRECT".to_string());
        outbounds.insert("proxy".to_string(), "PROXY".to_string());
        outbounds.insert("reject".to_string(), "REJECT".to_string());

        let ruleset = compile(&rules, &outbounds, 1024, &geo_loader).unwrap();

        // Test UDP 443 (QUIC) should be rejected
        let host = HostInfo::from_name("www.google.com");
        let result = ruleset.match_host(&host, Protocol::UDP, 443);
        assert!(result.is_some());
        assert_eq!(result.unwrap().outbound, "REJECT");

        // Test TCP 443 should not be rejected
        let result = ruleset.match_host(&host, Protocol::TCP, 443);
        assert!(result.is_some());
        assert_eq!(result.unwrap().outbound, "PROXY");

        // Test Chinese IP with UDP 443 should be rejected (reject rule comes first)
        let host = HostInfo::from_ip("114.114.114.114".parse().unwrap());
        let result = ruleset.match_host(&host, Protocol::UDP, 443);
        assert!(result.is_some());
        assert_eq!(result.unwrap().outbound, "REJECT");

        // Test Chinese IP with TCP 443 should be direct
        let result = ruleset.match_host(&host, Protocol::TCP, 443);
        assert!(result.is_some());
        assert_eq!(result.unwrap().outbound, "DIRECT");
    }
}
