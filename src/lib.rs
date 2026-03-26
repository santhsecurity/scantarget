//! Universal target parsing for security scanners.
//!
//! # Quick Start
//!
//! ```rust
//! use scantarget::Target;
//!
//! let target: Target = "https://example.com".parse().unwrap();
//! assert!(matches!(target, Target::Url(_)));
//!
//! let domain: Target = "example.com".parse().unwrap();
//! assert!(matches!(domain, Target::Domain(_)));
//! ```

#![warn(missing_docs)]
#![forbid(unsafe_code)]

/// CIDR expansion utilities.
pub mod expand;
/// Target list loading and management.
pub mod list;
/// Target parsing and representation.
pub mod target;

pub use crate::expand::{expand_all, expand_cidr};
pub use crate::list::{TargetList, TargetListError};
pub use crate::target::{Target, TargetParseError};

/// Trait for any source of scan targets.
///
/// Implement this for custom target sources (APIs, databases, queues).
pub trait TargetSource {
    /// Get all targets.
    fn targets(&self) -> Vec<target::Target>;
    /// Number of targets.
    ///
    /// Example:
    /// ```rust
    /// use scantarget::{Target, TargetSource};
    ///
    /// struct StaticSource(Vec<Target>);
    ///
    /// impl TargetSource for StaticSource {
    ///     fn targets(&self) -> Vec<Target> {
    ///         self.0.clone()
    ///     }
    /// }
    ///
    /// let source = StaticSource(vec!["https://example.com".parse::<Target>().unwrap()]);
    /// assert_eq!(source.count(), 1);
    /// ```
    fn count(&self) -> usize {
        self.targets().len()
    }
}

/// Parse a single target string.
///
/// Convenience wrapper around `Target::from_str`.
///
/// Example:
/// ```rust
/// use scantarget::{parse, Target};
///
/// assert_eq!(parse("https://example.com"), "https://example.com".parse::<Target>().ok());
/// assert!(parse("http://").is_none());
/// ```
#[must_use]
pub fn parse(s: &str) -> Option<target::Target> {
    s.parse().ok()
}

/// Parse multiple targets from a newline-separated string.
///
/// Blank lines and lines starting with `#` are skipped.
///
/// Example:
/// ```rust
/// use scantarget::{parse_many, Target};
///
/// let targets = parse_many("https://example.com\n# comment\n203.0.113.10");
/// assert_eq!(
///     targets,
///     vec!["https://example.com".parse::<Target>().unwrap(), "203.0.113.10".parse::<Target>().unwrap()]
/// );
/// ```
#[must_use]
pub fn parse_many(s: &str) -> Vec<target::Target> {
    s.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

#[cfg(test)]
mod adversarial_tests;
