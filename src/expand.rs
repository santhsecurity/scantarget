//! CIDR expansion utilities.

use crate::Target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_EXPANDED_IPS: u128 = 1_000_000;

/// Expand a CIDR notation into individual IP addresses.
///
/// Returns an empty vector if the expansion would exceed 1,000,000 addresses
/// (to prevent memory exhaustion from huge ranges like /0).
///
/// Example:
/// ```rust
/// use std::net::IpAddr;
/// use scantarget::expand_cidr;
///
/// let ips = expand_cidr("203.0.113.0".parse::<IpAddr>().unwrap(), 30);
/// assert_eq!(ips.len(), 4);
/// ```
#[must_use]
pub fn expand_cidr(addr: IpAddr, prefix: u8) -> Vec<IpAddr> {
    match addr {
        IpAddr::V4(addr) => expand_ipv4(addr, prefix),
        IpAddr::V6(addr) => expand_ipv6(addr, prefix),
    }
}

fn expand_ipv4(addr: Ipv4Addr, prefix: u8) -> Vec<IpAddr> {
    if prefix > 32 || prefix == 0 {
        return vec![];
    }
    let host_bits = 32 - u32::from(prefix);
    let total = 1u128 << host_bits;
    if total > MAX_EXPANDED_IPS {
        return Vec::new();
    }
    let mask = if prefix == 0 { 0 } else { (!0u32) << host_bits };
    let start = u32::from(addr) & mask;
    let mut out = Vec::with_capacity(total as usize);
    for i in 0..total {
        let ip = Ipv4Addr::from(start + (i as u32));
        out.push(IpAddr::V4(ip));
    }
    out
}

fn expand_ipv6(addr: Ipv6Addr, prefix: u8) -> Vec<IpAddr> {
    if prefix > 128 {
        return vec![];
    }
    let host_bits = 128 - u128::from(prefix);
    let total = if host_bits == 128 {
        u128::MAX
    } else {
        1u128 << host_bits
    };
    if total > MAX_EXPANDED_IPS {
        return Vec::new();
    }
    let mask = if prefix == 0 {
        0u128
    } else {
        (!0u128) << host_bits
    };
    let addr_num = u128::from(addr);
    let start = addr_num & mask;
    let mut out = Vec::with_capacity(std::cmp::min(total as usize, usize::MAX));
    for i in 0..total {
        out.push(IpAddr::V6(Ipv6Addr::from(start + i)));
    }
    out
}

/// Expand all CIDR targets in a slice into individual IP targets.
///
/// Non-CIDR targets are passed through unchanged.
///
/// Example:
/// ```rust
/// use scantarget::{expand_all, Target};
///
/// let expanded = expand_all(&[
///     "198.51.100.0/31".parse::<Target>().unwrap(),
///     "https://example.com".parse::<Target>().unwrap(),
/// ]);
/// assert_eq!(expanded.len(), 3);
/// ```
#[must_use]
pub fn expand_all(targets: &[Target]) -> Vec<Target> {
    let mut out = Vec::new();
    for target in targets {
        match target {
            Target::Cidr { addr, prefix } => {
                let expanded = expand_cidr(*addr, *prefix);
                out.extend(expanded.into_iter().map(Target::Ip));
            }
            other => out.push(other.clone()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::expand_all;
    use super::expand_cidr;
    use crate::Target;
    use std::net::IpAddr;

    #[test]
    fn expand_ipv4_cidr_small() {
        let cidr = Target::Cidr {
            addr: "203.0.113.0".parse().unwrap(),
            prefix: 30,
        };
        let full = expand_cidr("203.0.113.0".parse().unwrap(), 0);
        let list = expand_all(std::slice::from_ref(&cidr));
        assert_eq!(
            list,
            vec![
                Target::Ip(IpAddr::from([203, 0, 113, 0])),
                Target::Ip(IpAddr::from([203, 0, 113, 1])),
                Target::Ip(IpAddr::from([203, 0, 113, 2])),
                Target::Ip(IpAddr::from([203, 0, 113, 3])),
            ]
        );
        assert_eq!(full.len(), 0);
    }

    #[test]
    fn expand_single_host() {
        let ips = expand_cidr("10.0.0.5".parse().unwrap(), 32);
        assert_eq!(ips, vec!["10.0.0.5".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn expand_mixed_targets() {
        let targets = vec![
            Target::Ip("198.51.100.1".parse().unwrap()),
            Target::Cidr {
                addr: "198.51.100.10".parse().unwrap(),
                prefix: 31,
            },
            Target::Domain("example.com".to_string()),
        ];

        let expanded = expand_all(&targets);
        assert_eq!(
            expanded,
            vec![
                Target::Ip("198.51.100.1".parse().unwrap()),
                Target::Ip("198.51.100.10".parse().unwrap()),
                Target::Ip("198.51.100.11".parse().unwrap()),
                Target::Domain("example.com".to_string()),
            ]
        );
    }

    #[test]
    fn expand_cidr_rejects_invalid_prefix() {
        let bad = expand_cidr("10.0.0.1".parse().unwrap(), 33);
        assert!(bad.is_empty());
    }
}
