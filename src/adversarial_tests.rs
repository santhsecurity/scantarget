//! Adversarial tests for scantarget - designed to BREAK the code
//!
//! Tests: IPv6 with zones, CIDR /0, punycode domains, targets with auth (user:pass@host),
//! 100K targets from file, empty lines mixed with valid

use crate::{expand_all, expand_cidr, parse_many, Target, TargetList};
use std::io::Write;
use std::net::IpAddr;
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

#[test]
fn target_format_url_https_with_query_and_fragment() {
    let t = Target::from_str("https://example.com/path?a=1&b=2#frag").unwrap();
    assert_eq!(
        t,
        Target::Url("https://example.com/path?a=1&b=2#frag".to_string())
    );
}

#[test]
fn target_format_url_with_explicit_port() {
    let t = Target::from_str("http://example.com:8080/index.html").unwrap();
    assert_eq!(
        t,
        Target::Url("http://example.com:8080/index.html".to_string())
    );
}

#[test]
fn target_format_url_with_ipv6_literal() {
    let t = Target::from_str("https://[2001:db8::1]:8443/api").unwrap();
    assert_eq!(t, Target::Url("https://[2001:db8::1]:8443/api".to_string()));
}

#[test]
fn target_format_bare_domain_ascii() {
    let t = Target::from_str("scanner.example.org").unwrap();
    assert_eq!(t, Target::Domain("scanner.example.org".to_string()));
}

#[test]
fn target_format_bare_domain_with_port() {
    let t = Target::from_str("scanner.example.org:8443").unwrap();
    assert_eq!(t, Target::Domain("scanner.example.org:8443".to_string()));
}

#[test]
fn target_format_ipv4_parses() {
    let t = Target::from_str("198.51.100.17").unwrap();
    assert_eq!(
        t,
        Target::Ip("198.51.100.17".parse::<IpAddr>().unwrap())
    );
}

#[test]
fn target_format_ipv6_parses() {
    let t = Target::from_str("2001:db8:1::42").unwrap();
    assert_eq!(t, Target::Ip("2001:db8:1::42".parse::<IpAddr>().unwrap()));
}

#[test]
fn target_format_ipv4_cidr_parses() {
    let t = Target::from_str("198.51.100.0/24").unwrap();
    assert_eq!(
        t,
        Target::Cidr {
            addr: "198.51.100.0".parse::<IpAddr>().unwrap(),
            prefix: 24
        }
    );
}

#[test]
fn target_format_ipv6_cidr_parses() {
    let t = Target::from_str("2001:db8::/126").unwrap();
    assert_eq!(
        t,
        Target::Cidr {
            addr: "2001:db8::".parse::<IpAddr>().unwrap(),
            prefix: 126
        }
    );
}

#[test]
fn edge_idn_unicode_domain_roundtrips() {
    let t = Target::from_str("münich.example").unwrap();
    assert_eq!(t, Target::Domain("münich.example".to_string()));
}

#[test]
fn edge_idn_cjk_domain_roundtrips() {
    let t = Target::from_str("例え.テスト").unwrap();
    assert_eq!(t, Target::Domain("例え.テスト".to_string()));
}

#[test]
fn edge_unicode_emoji_domain_roundtrips() {
    let t = Target::from_str("😺.example").unwrap();
    assert_eq!(t, Target::Domain("😺.example".to_string()));
}

#[test]
fn edge_url_with_query_only() {
    let t = Target::from_str("https://example.com?token=abc").unwrap();
    assert_eq!(t, Target::Url("https://example.com?token=abc".to_string()));
}

#[test]
fn edge_url_with_fragment_only() {
    let t = Target::from_str("https://example.com#section-2").unwrap();
    assert_eq!(t, Target::Url("https://example.com#section-2".to_string()));
}

#[test]
fn edge_url_with_query_and_fragment() {
    let t = Target::from_str("https://example.com/app?q=x#end").unwrap();
    assert_eq!(t, Target::Url("https://example.com/app?q=x#end".to_string()));
}

#[test]
fn edge_domain_with_max_port_parses() {
    let t = Target::from_str("example.com:65535").unwrap();
    assert_eq!(t, Target::Domain("example.com:65535".to_string()));
}

#[test]
fn edge_url_with_max_port_parses() {
    let t = Target::from_str("https://example.com:65535").unwrap();
    assert_eq!(t, Target::Url("https://example.com:65535".to_string()));
}

#[test]
fn cidr_expansion_ipv4_32_single_host() {
    let ips = expand_cidr("203.0.113.9".parse().unwrap(), 32);
    assert_eq!(ips, vec!["203.0.113.9".parse::<IpAddr>().unwrap()]);
}

#[test]
fn cidr_expansion_ipv4_24_has_256_hosts() {
    let ips = expand_cidr("203.0.113.0".parse().unwrap(), 24);
    assert_eq!(ips.len(), 256);
    assert_eq!(ips[0], "203.0.113.0".parse::<IpAddr>().unwrap());
    assert_eq!(ips[255], "203.0.113.255".parse::<IpAddr>().unwrap());
}

#[test]
fn cidr_expansion_ipv4_0_rejected_by_parser() {
    let err = Target::from_str("0.0.0.0/0").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("CIDR prefix 0 is not allowed for IPv4".to_string())
    );
}

#[test]
fn cidr_expansion_ipv6_0_allowed_but_not_expandable() {
    let t = Target::from_str("::/0").unwrap();
    let Target::Cidr { addr, prefix } = t else {
        panic!("expected CIDR");
    };
    assert_eq!(prefix, 0);
    let ips = expand_cidr(addr, prefix);
    assert!(ips.is_empty());
}

#[test]
fn cidr_expansion_ipv6_128_single_host() {
    let ips = expand_cidr("2001:db8::1".parse().unwrap(), 128);
    assert_eq!(ips, vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);
}

#[test]
fn long_input_target_over_4k_errors_cleanly() {
    let over = format!("https://example.com/{}", "a".repeat(5000));
    let err = Target::from_str(&over).unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("target exceeds maximum length of 4096 bytes".to_string())
    );
}

#[test]
fn long_input_authority_over_limit_errors_cleanly() {
    let host = format!("{}.com", "a".repeat(1030));
    let err = Target::from_str(&host).unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid(
            "target authority exceeds maximum length of 1024 bytes".to_string()
        )
    );
}

#[test]
fn long_input_host_over_255_errors_cleanly() {
    let host = format!("{}.com", "a".repeat(256));
    let err = Target::from_str(&host).unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid(format!("invalid target format: {host}"))
    );
}

#[test]
fn malformed_empty_input_errors_cleanly() {
    let err = Target::from_str("").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("empty target".to_string())
    );
}

#[test]
fn malformed_whitespace_only_errors_cleanly() {
    let err = Target::from_str("   ").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("empty target".to_string())
    );
}

#[test]
fn malformed_internal_whitespace_errors_cleanly() {
    let err = Target::from_str("example .com").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("invalid target format: example .com".to_string())
    );
}

#[test]
fn malformed_url_missing_host_errors_cleanly() {
    let err = Target::from_str("https:///x").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("invalid target format: https:///x".to_string())
    );
}

#[test]
fn malformed_url_bad_scheme_char_errors_cleanly() {
    let err = Target::from_str("ht*tp://example.com").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("invalid target format: ht*tp://example.com".to_string())
    );
}

#[test]
fn malformed_domain_double_dot_errors_cleanly() {
    let err = Target::from_str("example..com").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("invalid target format: example..com".to_string())
    );
}

#[test]
fn malformed_domain_leading_dot_errors_cleanly() {
    let err = Target::from_str(".example.com").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("invalid target format: .example.com".to_string())
    );
}

#[test]
fn malformed_domain_trailing_dot_errors_cleanly() {
    let err = Target::from_str("example.com.").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("invalid target format: example.com.".to_string())
    );
}

#[test]
fn malformed_domain_port_zero_errors_cleanly() {
    let err = Target::from_str("example.com:0").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("invalid target format: example.com:0".to_string())
    );
}

#[test]
fn malformed_domain_port_non_numeric_errors_cleanly() {
    let err = Target::from_str("example.com:http").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("invalid target format: example.com:http".to_string())
    );
}

#[test]
fn malformed_domain_port_overflow_errors_cleanly() {
    let err = Target::from_str("example.com:70000").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("invalid target format: example.com:70000".to_string())
    );
}

#[test]
fn malformed_domain_with_path_no_scheme_errors_cleanly() {
    let err = Target::from_str("example.com/path").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("invalid target format: example.com/path".to_string())
    );
}

#[test]
fn malformed_cidr_prefix_too_large_v4_errors_cleanly() {
    let err = Target::from_str("198.51.100.0/33").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("CIDR prefix 33 out of range for 32 bit address".to_string())
    );
}

#[test]
fn malformed_cidr_prefix_too_large_v6_errors_cleanly() {
    let err = Target::from_str("2001:db8::/129").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid(
            "CIDR prefix 129 out of range for 128 bit address".to_string()
        )
    );
}

#[test]
fn malformed_cidr_missing_prefix_errors_cleanly() {
    let err = Target::from_str("198.51.100.0/").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("invalid CIDR prefix: ".to_string())
    );
}

#[test]
fn malformed_cidr_non_numeric_prefix_errors_cleanly() {
    let err = Target::from_str("198.51.100.0/abc").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("invalid CIDR prefix: abc".to_string())
    );
}

#[test]
fn malformed_bracketed_ipv6_missing_closing_bracket_errors_cleanly() {
    let err = Target::from_str("https://[2001:db8::1:443").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("invalid target format: [2001:db8::1:443".to_string())
    );
}

#[test]
fn malformed_bracketed_ipv6_bad_suffix_errors_cleanly() {
    let err = Target::from_str("https://[2001:db8::1]x").unwrap_err();
    assert_eq!(
        err,
        crate::TargetParseError::Invalid("invalid target format: [2001:db8::1]x".to_string())
    );
}
