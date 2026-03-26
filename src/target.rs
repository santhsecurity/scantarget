use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, str::FromStr};
use thiserror::Error;

const MAX_TARGET_LENGTH: usize = 4 * 1024;
const MAX_HOST_LENGTH: usize = 255;
const MAX_AUTHORITY_LENGTH: usize = 1024;

/// A parsed target for security scanning.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Target {
    /// A URL target (e.g., `https://example.com/path`).
    Url(String),
    /// A domain name (e.g., `example.com`).
    Domain(String),
    /// An IP address (IPv4 or IPv6).
    Ip(IpAddr),
    /// A CIDR network range.
    Cidr {
        /// The network address.
        addr: IpAddr,
        /// The prefix length (0-32 for IPv4, 0-128 for IPv6).
        prefix: u8,
    },
}

/// Error type for target parsing failures.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Error)]
pub enum TargetParseError {
    /// The target string is invalid.
    #[error("invalid target '{0}'. Fix: pass a full URL like `https://example.com`, a bare host like `example.com`, an IP like `203.0.113.10`, or a CIDR like `203.0.113.0/24`.")]
    Invalid(String),
}

impl Target {
    /// Normalize the target for deduplication.
    ///
    /// - URLs: strip trailing slashes
    /// - Domains: convert to lowercase and prepend `https://`
    #[must_use]
    pub fn normalize(self) -> Self {
        match self {
            Target::Url(url) => Target::Url(url.trim_end_matches('/').to_string()),
            Target::Domain(domain) => {
                let domain = domain.trim_end_matches('/').to_lowercase();
                if domain.contains("://") {
                    Target::Url(domain)
                } else {
                    Target::Url(format!("https://{domain}"))
                }
            }
            other => other,
        }
    }
}

impl From<IpAddr> for Target {
    fn from(value: IpAddr) -> Self {
        Self::Ip(value)
    }
}

impl From<(IpAddr, u8)> for Target {
    fn from((addr, prefix): (IpAddr, u8)) -> Self {
        Self::Cidr { addr, prefix }
    }
}

impl TryFrom<&str> for Target {
    type Error = TargetParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<String> for Target {
    type Error = TargetParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Url(url) => write!(f, "{url}"),
            Target::Domain(domain) => write!(f, "{domain}"),
            Target::Ip(ip) => write!(f, "{ip}"),
            Target::Cidr { addr, prefix } => write!(f, "{addr}/{prefix}"),
        }
    }
}

impl FromStr for Target {
    type Err = TargetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let token = s.trim();
        if token.is_empty() {
            return Err(TargetParseError::Invalid("empty target".to_string()));
        }
        if token.len() > MAX_TARGET_LENGTH {
            return Err(TargetParseError::Invalid(format!(
                "target exceeds maximum length of {MAX_TARGET_LENGTH} bytes"
            )));
        }

        if token.chars().any(char::is_whitespace) {
            return Err(TargetParseError::Invalid(format!(
                "invalid target format: {token}"
            )));
        }

        if token.contains("://") {
            validate_url_target(token)?;
            return Ok(Target::Url(token.to_string()));
        }

        if let Some((addr_str, prefix_str)) = token.split_once('/') {
            if let Ok(addr) = addr_str.parse::<IpAddr>() {
                let prefix = prefix_str.parse::<u8>().map_err(|_| {
                    TargetParseError::Invalid(format!("invalid CIDR prefix: {prefix_str}"))
                })?;
                let max_prefix = match addr {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                if matches!(addr, IpAddr::V4(_)) && prefix == 0 {
                    return Err(TargetParseError::Invalid(
                        "CIDR prefix 0 is not allowed for IPv4".to_string(),
                    ));
                }
                if prefix > max_prefix {
                    return Err(TargetParseError::Invalid(format!(
                        "CIDR prefix {prefix} out of range for {max_prefix} bit address"
                    )));
                }
                return Ok(Target::Cidr { addr, prefix });
            }
            // If the left side is not an IP, it's a domain with a path but no scheme
            return Err(TargetParseError::Invalid(format!(
                "invalid target format: {token}"
            )));
        }

        if token.contains('/') {
            return Err(TargetParseError::Invalid(format!(
                "invalid target format: {token}"
            )));
        }

        if let Ok(ip) = token.parse::<IpAddr>() {
            return Ok(Target::Ip(ip));
        }

        validate_domain_target(token)?;

        Ok(Target::Domain(token.to_string()))
    }
}

fn validate_url_target(token: &str) -> Result<(), TargetParseError> {
    let mut parts = token.splitn(2, "://");
    let scheme = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("");
    if scheme.is_empty() || rest.is_empty() || rest.starts_with('/') {
        return Err(TargetParseError::Invalid(format!(
            "invalid target format: {token}"
        )));
    }
    if rest.len() > MAX_AUTHORITY_LENGTH {
        return Err(TargetParseError::Invalid(format!(
            "URL authority exceeds maximum length of {MAX_AUTHORITY_LENGTH} bytes"
        )));
    }
    if !scheme
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
    {
        return Err(TargetParseError::Invalid(format!(
            "invalid target format: {token}"
        )));
    }

    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    validate_authority(authority, token)
}

fn validate_domain_target(token: &str) -> Result<(), TargetParseError> {
    if token.len() > MAX_AUTHORITY_LENGTH {
        return Err(TargetParseError::Invalid(format!(
            "target authority exceeds maximum length of {MAX_AUTHORITY_LENGTH} bytes"
        )));
    }
    validate_authority(token, token)
}

fn validate_authority(authority: &str, token: &str) -> Result<(), TargetParseError> {
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if host_port.is_empty() {
        return Err(TargetParseError::Invalid(format!(
            "invalid target format: {token}"
        )));
    }

    let (host, port) = split_host_and_port(host_port)?;
    if host.is_empty() || host.len() > MAX_HOST_LENGTH {
        return Err(TargetParseError::Invalid(format!(
            "invalid target format: {token}"
        )));
    }
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return Err(TargetParseError::Invalid(format!(
            "invalid target format: {token}"
        )));
    }
    if let Some(port) = port {
        let parsed_port = port
            .parse::<u16>()
            .map_err(|_| TargetParseError::Invalid(format!("invalid target format: {token}")))?;
        if parsed_port == 0 {
            return Err(TargetParseError::Invalid(format!(
                "invalid target format: {token}"
            )));
        }
    }
    Ok(())
}

fn split_host_and_port(host_port: &str) -> Result<(&str, Option<&str>), TargetParseError> {
    if let Some(stripped) = host_port.strip_prefix('[') {
        let end = stripped.find(']').ok_or_else(|| {
            TargetParseError::Invalid(format!("invalid target format: {host_port}"))
        })?;
        let host = &stripped[..end];
        let rest = &stripped[end + 1..];
        if rest.is_empty() {
            return Ok((host, None));
        }
        if let Some(port) = rest.strip_prefix(':') {
            return Ok((host, Some(port)));
        }
        return Err(TargetParseError::Invalid(format!(
            "invalid target format: {host_port}"
        )));
    }

    match host_port.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Ok((host, Some(port))),
        _ => Ok((host_port, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::{Target, TargetParseError};
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn parse_url() {
        let target = Target::from_str("https://example.com/path/").expect("parse URL");
        assert_eq!(target, Target::Url("https://example.com/path/".to_string()));
        let target =
            Target::from_str("https://example.com:8443/path/").expect("parse URL with port");
        assert_eq!(
            target,
            Target::Url("https://example.com:8443/path/".to_string())
        );
        let target = Target::from_str("http://例え.テスト/").expect("parse IDN URL");
        assert_eq!(target, Target::Url("http://例え.テスト/".to_string()));
    }

    #[test]
    fn parse_domain() {
        let target = Target::from_str("example.com").expect("parse domain");
        assert_eq!(target, Target::Domain("example.com".to_string()));
        let target = Target::from_str("例え.テスト").expect("parse unicode domain");
        assert_eq!(target, Target::Domain("例え.テスト".to_string()));
        let target = Target::from_str("example.com:8443").expect("parse domain with port");
        assert_eq!(target, Target::Domain("example.com:8443".to_string()));
    }

    #[test]
    fn parse_ip() {
        let target = Target::from_str("203.0.113.10").expect("parse IP");
        assert_eq!(
            target,
            Target::Ip("203.0.113.10".parse::<IpAddr>().unwrap())
        );
        let target = Target::from_str("2001:db8::1").expect("parse IPv6");
        assert_eq!(target, Target::Ip("2001:db8::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn parse_malformed_urls_rejected() {
        let err = Target::from_str("https:///path").unwrap_err();
        assert_eq!(
            err,
            TargetParseError::Invalid("invalid target format: https:///path".to_string())
        );
        let err = Target::from_str("http://").unwrap_err();
        assert_eq!(
            err,
            TargetParseError::Invalid("invalid target format: http://".to_string())
        );
    }

    #[test]
    fn parse_cidr() {
        let target = Target::from_str("198.51.100.0/24").expect("parse CIDR");
        assert_eq!(
            target,
            Target::Cidr {
                addr: "198.51.100.0".parse::<IpAddr>().unwrap(),
                prefix: 24
            }
        );
    }

    #[test]
    fn normalize_domain_adds_https_and_strips_trailing_slash() {
        let domain = Target::Domain("example.com/".to_string()).normalize();
        assert_eq!(domain, Target::Url("https://example.com".to_string()));
    }

    #[test]
    fn normalize_url_strips_trailing_slash() {
        let url = Target::Url("https://example.com/path/".to_string()).normalize();
        assert_eq!(url, Target::Url("https://example.com/path".to_string()));
    }

    #[test]
    fn normalize_ip_noop() {
        let ip = Target::Ip("127.0.0.1".parse().unwrap());
        assert_eq!(ip.normalize(), Target::Ip("127.0.0.1".parse().unwrap()));
    }
}
