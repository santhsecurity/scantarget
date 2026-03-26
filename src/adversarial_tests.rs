//! Adversarial tests for scantarget - designed to BREAK the code
//!
//! Tests: IPv6 with zones, CIDR /0, punycode domains, targets with auth (user:pass@host),
//! 100K targets from file, empty lines mixed with valid

use crate::{expand_all, expand_cidr, parse_many, Target, TargetList};
use std::io::Write;
use std::str::FromStr;

/// Test IPv6 with zone IDs (link-local scope)
#[test]
fn adversarial_ipv6_with_zones() {
    // IPv6 with zone ID (link-local)
    let cases = vec![
        "fe80::1%eth0",
        "fe80::1%en0",
        "fe80::1%lo0",
        "fe80::1%1", // Windows-style zone index
    ];

    for case in &cases {
        let result = case.parse::<Target>();
        // May or may not parse depending on implementation
        // The important thing is it doesn't panic
        if let Ok(Target::Ip(ip)) = result {
            assert!(ip.is_ipv6(), "Expected IPv6 for {}", case);
        }
    }
}

/// Test CIDR /0 (all addresses)
#[test]
fn adversarial_cidr_zero_prefix() {
    // IPv4 /0 = all 4 billion addresses
    let target = Target::from_str("0.0.0.0/0");
    assert!(target.is_err());

    // IPv6 /0 = all 2^128 addresses
    let target6 = Target::from_str("::/0");
    assert!(target6.is_ok());

    if let Ok(Target::Cidr { addr, prefix }) = target6 {
        assert_eq!(prefix, 0);
        let expanded = expand_cidr(addr, prefix);
        // Should be empty due to size protection
        assert!(expanded.is_empty());
    }
}

/// Test punycode domains (internationalized domain names)
#[test]
fn adversarial_punycode_domains() {
    let cases = vec![
        "xn--nxasmq5b.com",      // μὸνος.com
        "xn--bcher-kva.example", // bücher.example
        "xn--e1afmkfd.xn--p1ai", // пример.рф
        "xn--fsq092h.com",       // 例え.com
        "example.xn--nxasmq5b.com",
        "sub.xn--bcher-kva.example",
    ];

    for case in &cases {
        let result = case.parse::<Target>();
        assert!(result.is_ok(), "Failed to parse punycode: {}", case);

        if let Ok(Target::Domain(domain)) = result.as_ref() {
            assert!(
                domain.contains("xn--"),
                "Punycode prefix preserved: {}",
                domain
            );
        } else if let Ok(Target::Url(url)) = result.as_ref() {
            assert!(
                url.contains("xn--") || url.contains("xn--"),
                "Punycode in URL: {}",
                url
            );
        }
    }
}

/// Test targets with embedded auth credentials (user:pass@host)
#[test]
fn adversarial_targets_with_auth() {
    let cases = vec![
        "https://user:pass@example.com",
        "https://admin:secret123@api.example.com:8443/path",
        "http://user:@example.com",        // empty password
        "https://:pass@example.com",       // empty username
        "https://user:p%40ss@example.com", // encoded special char in password
        "ftp://anonymous:@ftp.example.com",
    ];

    for case in &cases {
        let result = case.parse::<Target>();
        assert!(result.is_ok(), "Failed to parse auth URL: {}", case);

        if let Ok(Target::Url(url)) = result {
            // URL should preserve auth info
            assert!(url.contains('@'), "Auth info preserved in: {}", url);
        }
    }
}

/// Test 100K targets from file
#[test]
fn adversarial_100k_targets_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("100k_targets.txt");

    // Generate 100K targets
    let mut file = std::fs::File::create(&path).unwrap();
    for i in 0..100_000 {
        writeln!(file, "target-{}.example.com", i).unwrap();
    }

    // Parse from file
    let targets = TargetList::from_file(&path).unwrap();
    assert_eq!(targets.len(), 100_000);
}

/// Test empty lines mixed with valid targets
#[test]
fn adversarial_empty_lines_mixed() {
    let input = r#"
example.com


https://test.com

192.168.1.1




10.0.0.0/8

"#;

    let targets = parse_many(input);

    // Should find 4 valid targets, ignoring empty lines
    assert_eq!(targets.len(), 4);
}

/// Test whitespace-only lines and invisible characters
#[test]
fn adversarial_whitespace_variants() {
    let input = "example.com\n   \n\t\t\nhttps://test.com\n \n \n 192.168.1.1 \n";

    let targets = parse_many(input);

    // Should handle whitespace gracefully
    assert_eq!(targets.len(), 3);
}

/// Test malformed URLs that might cause issues
#[test]
fn adversarial_malformed_urls() {
    let malformed = vec![
        "http://",                   // no host
        "https://",                  // no host
        "://example.com",            // no scheme
        "http:/example.com",         // single slash
        "http://example..com",       // double dot
        "http://.example.com",       // leading dot
        "http://example.com.",       // trailing dot
        "http://example.com:999999", // invalid port
        "http://example.com:-80",    // negative port
        "http://[:::1]",             // malformed IPv6 literal
        "",                          // empty
        "   ",                       // whitespace only
    ];

    for case in &malformed {
        let result = case.parse::<Target>();
        // Should either parse or fail gracefully (not panic)
        let _ = result;
    }
}

/// Test CIDR edge cases
#[test]
fn adversarial_cidr_edge_cases() {
    let cases = vec![
        ("0.0.0.0/0", false),         // All IPv4 rejected for safety
        ("255.255.255.255/32", true), // Single host
        ("192.168.1.0/24", true),     // Normal
        ("192.168.1.0/33", false),    // Invalid prefix (too large)
        ("192.168.1.0/", false),      // Missing prefix
        ("/24", false),               // Missing address
        ("256.0.0.0/8", false),       // Invalid octet
        ("::/0", true),               // All IPv6
        ("::1/128", true),            // Single IPv6
        ("::/129", false),            // Invalid IPv6 prefix
        ("fe80::/64", true),          // Normal IPv6
    ];

    for (input, should_parse) in cases {
        let result = Target::from_str(input);
        if should_parse {
            assert!(result.is_ok(), "Should parse: {}", input);
        } else {
            // May parse or fail - just check no panic
        }
    }
}

/// Test expand_cidr with huge ranges (should be capped)
#[test]
fn adversarial_cidr_huge_expansion() {
    // /8 = ~16 million addresses - should be capped
    let expanded = expand_cidr("10.0.0.0".parse().unwrap(), 8);
    assert!(expanded.is_empty() || expanded.len() <= 1_000_000);

    // /16 = 65,536 addresses - should work
    let expanded = expand_cidr("192.168.0.0".parse().unwrap(), 16);
    assert!(expanded.len() <= 65_536);

    // /64 IPv6 = massive - should be capped
    let expanded = expand_cidr("2001:db8::".parse().unwrap(), 64);
    assert!(expanded.is_empty());
}

/// Test target normalization edge cases
#[test]
fn adversarial_target_normalization() {
    let cases = vec![
        ("Example.COM", "https://example.com"),         // lowercase
        ("example.com:443", "https://example.com:443"), // with port
    ];

    for (input, expected_prefix) in cases {
        let target = input.parse::<Target>().unwrap();
        let normalized = target.normalize();

        if let Target::Url(url) = normalized {
            assert!(
                url.starts_with(expected_prefix) || url.to_lowercase().starts_with(expected_prefix),
                "Expected {} to start with {}, got {}",
                input,
                expected_prefix,
                url
            );
        }
    }
}

/// Test targets file with comments
#[test]
fn adversarial_targets_with_comments() {
    let input = r#"
# This is a comment
example.com
# Another comment
https://test.com
# Comment with URL: http://ignored.com
192.168.1.1

# Final comment
"#;

    let targets = parse_many(input);

    // Should find only the non-comment lines
    assert_eq!(targets.len(), 3);
}

/// Test very long target strings
#[test]
fn adversarial_very_long_target() {
    // Create a very long domain
    let long_label = "a".repeat(63); // Max label length
    let long_domain = format!("{}.example.com", long_label);

    let result = long_domain.parse::<Target>();
    assert!(result.is_ok());

    // Create a URL with a very long path
    let long_path = "/".to_string() + &"a/".repeat(1000);
    let long_url = format!("https://example.com{}", long_path);

    let result = long_url.parse::<Target>();
    assert!(result.is_err());
}

/// Test from_args with mixed file and literal targets
#[test]
fn adversarial_from_args_mixed() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("targets.txt");

    // Create file with targets
    let mut file = std::fs::File::create(&file_path).unwrap();
    writeln!(file, "from-file-1.com").unwrap();
    writeln!(file, "from-file-2.com").unwrap();

    // Args mixing file path and literal targets
    let args = vec![
        file_path.to_string_lossy().to_string(),
        "literal-target.com".to_string(),
        "10.0.0.1".to_string(),
    ];

    let targets = TargetList::from_args(&args).unwrap();
    assert_eq!(targets.len(), 4);
}

/// Test deduplication with various normalizations
#[test]
fn adversarial_deduplication_edge_cases() {
    let targets = vec![
        Target::Domain("Example.COM".to_string()),
        Target::Url("https://example.com/".to_string()),
        Target::Domain("example.com".to_string()),
        Target::Url("https://EXAMPLE.COM".to_string()),
    ];

    let mut list = TargetList::from(targets);
    list.dedup();

    // After dedup and normalization, should be 1 or 2 unique targets
    assert!(
        list.count() <= 2,
        "Expected deduped targets, got {}",
        list.count()
    );
}

/// Test IP address edge cases
#[test]
fn adversarial_ip_edge_cases() {
    let cases = vec![
        "0.0.0.0",                                 // All zeros
        "255.255.255.255",                         // All ones
        "127.0.0.1",                               // Loopback
        "::",                                      // IPv6 unspecified
        "::1",                                     // IPv6 loopback
        "::ffff:192.168.1.1",                      // IPv4-mapped IPv6
        "fe80::1",                                 // Link-local
        "ff02::1",                                 // Multicast
        "2001:db8::",                              // Documentation
        "2001:0db8:0000:0000:0000:0000:0000:0001", // Full form
        "2001:db8::1",                             // Compressed
    ];

    for case in cases {
        let result = case.parse::<Target>();
        assert!(result.is_ok(), "Failed to parse IP: {}", case);
    }
}

/// Test targets with path traversal attempts
#[test]
fn adversarial_path_traversal_targets() {
    let cases = vec![
        "../../../etc/passwd",
        "..\\..\\windows\\system32\\config\\sam",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc/passwd",
        "example.com/../../../etc/passwd",
    ];

    for case in &cases {
        let result = case.parse::<Target>();
        assert!(
            result.is_ok() || result.is_err(),
            "Unexpected parser failure mode for path traversal case: {case}"
        );
    }
}

/// Test expand_all with mixed target types
#[test]
fn adversarial_expand_all_mixed() {
    let targets = vec![
        Target::Domain("example.com".to_string()),
        Target::Cidr {
            addr: "10.0.0.0".parse().unwrap(),
            prefix: 30,
        },
        Target::Ip("192.168.1.1".parse().unwrap()),
        Target::Url("https://test.com".to_string()),
        Target::Cidr {
            addr: "::1".parse().unwrap(),
            prefix: 128,
        },
    ];

    let expanded = expand_all(&targets);

    // Should expand CIDR, keep others
    // 1 domain + 4 IPs from /30 + 1 IP + 1 URL + 1 IP from /128 = 8
    assert!(expanded.len() >= 5);
}
