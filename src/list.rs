use crate::Target;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::{
    collections::HashSet,
    fs::File,
    io::{self, Read},
    path::Path,
};
use thiserror::Error;

/// A collection of targets with deduplication support.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetList {
    /// The list of targets.
    pub targets: Vec<Target>,
}

impl From<Vec<Target>> for TargetList {
    fn from(targets: Vec<Target>) -> Self {
        Self { targets }
    }
}

/// Error type for target list operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
pub enum TargetListError {
    /// An I/O error occurred.
    #[error("{0}. Fix: verify the target file exists, is readable, or pipe valid target lines into stdin.")]
    Io(String),
    /// An invalid target was found.
    #[error("invalid target '{0}' in target list. Fix: use a full URL, bare host, IP, or CIDR entry on each line or in the TOML `targets` array.")]
    InvalidTarget(String),
    /// Failed to parse TOML configuration.
    #[error("target list TOML parse error: {0}. Fix: use `targets = [\"https://example.com\", \"203.0.113.10\"]` at the top level.")]
    TomlParse(String),
}

impl From<io::Error> for TargetListError {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<toml::de::Error> for TargetListError {
    fn from(value: toml::de::Error) -> Self {
        Self::TomlParse(value.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct TomlTargetList {
    targets: Vec<String>,
}

impl TargetList {
    /// Load targets from a text file (one per line, comma-separated also accepted).
    ///
    /// Example:
    /// ```rust
    /// use scantarget::{Target, TargetList};
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let path = dir.path().join("targets.txt");
    /// std::fs::write(&path, "https://example.com\n203.0.113.10").unwrap();
    ///
    /// let parsed = TargetList::from_file(&path).unwrap();
    /// assert_eq!(parsed, vec!["https://example.com".parse::<Target>().unwrap(), "203.0.113.10".parse::<Target>().unwrap()]);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Vec<Target>, TargetListError> {
        let mut file = File::open(path.as_ref())?;
        parse_targets_from_reader(&mut file)
    }

    /// Load targets from a TOML file with a `targets = [...]` array.
    ///
    /// Invalid entries are rejected to avoid silent config failures.
    ///
    /// Example:
    /// ```rust
    /// use scantarget::{Target, TargetList};
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let path = dir.path().join("targets.toml");
    /// std::fs::write(&path, "targets = [\"https://example.com\", \"198.51.100.0/31\"]").unwrap();
    ///
    /// let parsed = TargetList::from_toml_file(&path).unwrap();
    /// assert_eq!(parsed[0], "https://example.com".parse::<Target>().unwrap());
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or TOML parsing fails.
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Vec<Target>, TargetListError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml(&content)
    }

    /// Parse targets from TOML text.
    ///
    /// Expected format:
    /// `targets = ["https://example.com", "example.org", "203.0.113.1/30"]`
    ///
    /// # Errors
    ///
    /// Returns an error if TOML parsing fails or any target is invalid.
    ///
    /// Example:
    /// ```rust
    /// use scantarget::{Target, TargetList};
    ///
    /// let parsed = TargetList::from_toml("targets = [\"example.com\", \"203.0.113.10\"]").unwrap();
    /// assert_eq!(parsed, vec!["example.com".parse::<Target>().unwrap(), "203.0.113.10".parse::<Target>().unwrap()]);
    /// ```
    pub fn from_toml(toml_str: &str) -> Result<Vec<Target>, TargetListError> {
        let config: TomlTargetList = toml::from_str(toml_str)?;
        config
            .targets
            .into_iter()
            .map(|token| {
                Target::from_str(&token).map_err(|_| TargetListError::InvalidTarget(token))
            })
            .collect()
    }

    /// Read targets from standard input.
    ///
    /// # Errors
    ///
    /// Returns an error if stdin cannot be read.
    ///
    /// Example:
    /// ```rust,no_run
    /// use scantarget::TargetList;
    ///
    /// let _targets = TargetList::from_stdin()?;
    /// # Ok::<(), scantarget::TargetListError>(())
    /// ```
    pub fn from_stdin() -> Result<Vec<Target>, TargetListError> {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        Ok(parse_targets_checked(&input))
    }

    /// Parse targets from a string.
    ///
    /// Comma-separated and newline-separated input are both supported.
    ///
    /// Example:
    /// ```rust
    /// use scantarget::{Target, TargetList};
    ///
    /// let parsed = TargetList::parse_str("example.com,https://scan.test");
    /// assert_eq!(parsed, vec!["example.com".parse::<Target>().unwrap(), "https://scan.test".parse::<Target>().unwrap()]);
    /// ```
    #[must_use]
    pub fn parse_str(s: &str) -> Vec<Target> {
        let mut targets = Vec::new();
        for token in split_targets(s) {
            if token.is_empty() || token.starts_with('#') {
                continue;
            }
            if let Ok(target) = token.parse::<Target>() {
                targets.push(target);
            }
        }
        targets
    }

    /// Parse targets from command line arguments.
    ///
    /// `-` means read from stdin. Arguments that are file paths are loaded
    /// from those files. Otherwise, the argument is parsed as a literal target
    /// or comma-separated target list.
    ///
    /// # Errors
    ///
    /// Returns an error if a file cannot be read or stdin fails.
    ///
    /// Example:
    /// ```rust
    /// use scantarget::{Target, TargetList};
    ///
    /// let parsed = TargetList::from_args(&["example.com,203.0.113.10".to_string()]).unwrap();
    /// assert_eq!(parsed, vec!["example.com".parse::<Target>().unwrap(), "203.0.113.10".parse::<Target>().unwrap()]);
    /// ```
    pub fn from_args(args: &[String]) -> Result<Vec<Target>, TargetListError> {
        let mut targets = Vec::new();

        for arg in args {
            let trimmed = arg.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed == "-" {
                targets.extend(Self::from_stdin()?);
                continue;
            }

            if Path::new(trimmed).is_file() {
                targets.extend(Self::from_file(trimmed)?);
                continue;
            }

            targets.extend(Self::parse_str(trimmed));
        }

        Ok(targets)
    }

    /// Deduplicate targets, preserving order.
    ///
    /// Targets are normalized before deduplication.
    ///
    /// Example:
    /// ```rust
    /// use scantarget::{Target, TargetList};
    ///
    /// let mut list = TargetList {
    ///     targets: vec!["example.com".parse::<Target>().unwrap(), "https://example.com/".parse::<Target>().unwrap()],
    /// };
    /// list.dedup();
    /// assert_eq!(list.count(), 1);
    /// ```
    pub fn dedup(&mut self) {
        let mut seen = HashSet::new();
        let mut deduped = Vec::new();
        for target in self.targets.drain(..) {
            let target = target.normalize();
            if seen.insert(target.clone()) {
                deduped.push(target);
            }
        }
        self.targets = deduped;
    }

    /// Returns the number of targets in the list.
    ///
    /// Example:
    /// ```rust
    /// use scantarget::{Target, TargetList};
    ///
    /// let list = TargetList { targets: vec!["example.com".parse::<Target>().unwrap()] };
    /// assert_eq!(list.count(), 1);
    /// ```
    #[must_use]
    pub fn count(&self) -> usize {
        self.targets.len()
    }
}

fn parse_targets_from_reader(reader: &mut dyn Read) -> Result<Vec<Target>, TargetListError> {
    let mut input = String::new();
    reader.read_to_string(&mut input)?;
    Ok(parse_targets_checked(&input))
}

fn split_targets(s: &str) -> impl Iterator<Item = &str> {
    s.split([',', '\n']).map(str::trim)
}

fn parse_targets_checked(s: &str) -> Vec<Target> {
    let mut targets = Vec::new();
    for token in split_targets(s) {
        if token.is_empty() || token.starts_with('#') {
            continue;
        }
        if let Ok(target) = token.parse::<Target>() {
            targets.push(target);
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::{TargetList, TargetListError};
    use crate::Target;
    use std::io::Write;

    #[test]
    fn parse_targets_from_comma_and_newline() {
        let list =
            TargetList::parse_str("example.com,https://a.test/,203.0.113.10\n198.51.100.0/30");
        assert_eq!(
            list,
            vec![
                Target::Domain("example.com".to_string()),
                Target::Url("https://a.test/".to_string()),
                Target::Ip("203.0.113.10".parse().unwrap()),
                Target::Cidr {
                    addr: "198.51.100.0".parse().unwrap(),
                    prefix: 30
                }
            ]
        );
    }

    #[test]
    fn parse_file_skips_comments_and_empty_lines() {
        let path = std::env::temp_dir().join("santh-target-list.txt");
        {
            let mut file = std::fs::File::create(&path).expect("create temp list file");
            writeln!(file, "# comment").expect("write");
            writeln!(file).expect("write empty");
            writeln!(file, "example.com,https://scan.test/path/").expect("write");
            writeln!(file, "2001:db8::1").expect("write");
            writeln!(file, "http://").expect("write malformed");
            writeln!(file, "https://example.com:8443").expect("write");
            writeln!(file, "例え.テスト").expect("write");
            writeln!(file, "198.51.100.5").expect("write");
        }

        assert_eq!(
            TargetList::from_file(&path).expect("parse file"),
            [
                Target::Domain("example.com".to_string()),
                Target::Url("https://scan.test/path/".to_string()),
                Target::Ip("2001:db8::1".parse().unwrap()),
                Target::Url("https://example.com:8443".to_string()),
                Target::Domain("例え.テスト".to_string()),
                Target::Ip("198.51.100.5".parse().unwrap())
            ]
        );
    }

    #[test]
    fn parse_stdin_input_simulation() {
        use crate::list::parse_targets_from_reader;
        use std::io::Cursor;

        let mut cursor = Cursor::new(
            "example.org\nhttps://edge.example:8443/path/\n\n#comment\n例え.テスト,malformed://",
        );
        let parsed = parse_targets_from_reader(&mut cursor).expect("parse simulated stdin");
        assert_eq!(
            parsed,
            vec![
                Target::Domain("example.org".to_string()),
                Target::Url("https://edge.example:8443/path/".to_string()),
                Target::Domain("例え.テスト".to_string())
            ]
        );
    }

    #[test]
    fn from_args_concurrent_access() {
        use std::env;
        use std::thread;

        let path = env::temp_dir().join("santh-target-concurrent.txt");
        {
            let mut file = std::fs::File::create(&path).expect("create args file");
            writeln!(file, "203.0.113.1").expect("write");
        }
        let args = vec![
            path.to_string_lossy().to_string(),
            "example.org,198.51.100.0/31".to_string(),
        ];

        let mut handles = Vec::new();
        for _ in 0..8 {
            let args = args.clone();
            handles.push(thread::spawn(move || TargetList::from_args(&args).unwrap()));
        }
        for h in handles {
            let parsed: Vec<Target> = h.join().expect("join");
            assert_eq!(
                parsed,
                vec![
                    Target::Ip("203.0.113.1".parse().unwrap()),
                    Target::Domain("example.org".to_string()),
                    Target::Cidr {
                        addr: "198.51.100.0".parse().unwrap(),
                        prefix: 31
                    }
                ]
            );
        }
    }

    #[test]
    fn parse_from_args_detects_file_and_literal() {
        let path = std::env::temp_dir().join("santh-target-args.txt");
        {
            let mut file = std::fs::File::create(&path).expect("create args file");
            writeln!(file, "203.0.113.1").expect("write");
        }

        let args = vec![
            path.to_string_lossy().to_string(),
            "example.org,198.51.100.0/31".to_string(),
        ];
        let list = TargetList::from_args(&args).unwrap();
        assert_eq!(
            list,
            vec![
                Target::Ip("203.0.113.1".parse().unwrap()),
                Target::Domain("example.org".to_string()),
                Target::Cidr {
                    addr: "198.51.100.0".parse().unwrap(),
                    prefix: 31
                }
            ]
        );
    }

    #[test]
    fn dedup_preserves_order() {
        let mut list = TargetList {
            targets: vec![
                Target::Domain("Example.com/".to_string()),
                Target::Url("https://example.com/".to_string()),
                Target::Url("https://example.com/".to_string()),
                Target::Ip("203.0.113.1".parse().unwrap()),
                Target::Ip("203.0.113.1".parse().unwrap()),
            ],
        };
        list.dedup();
        assert_eq!(
            list.targets,
            vec![
                Target::Url("https://example.com".to_string()),
                Target::Ip("203.0.113.1".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn from_toml_file_parses_targets() {
        let dir = std::env::temp_dir().join("santh-target-toml-file");
        let path = dir.join("targets.toml");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &path,
            r#"targets=["https://example.com", "example.org", "203.0.113.1/30"]"#,
        )
        .unwrap();
        let targets = TargetList::from_toml_file(&path).unwrap();
        assert_eq!(
            targets,
            vec![
                Target::Url("https://example.com".to_string()),
                Target::Domain("example.org".to_string()),
                Target::Cidr {
                    addr: "203.0.113.1".parse().unwrap(),
                    prefix: 30
                }
            ]
        );
    }

    #[test]
    fn from_toml_rejects_bad_target() {
        let parsed = TargetList::from_toml(r#"targets=["http://", "example.com"]"#);
        assert!(matches!(parsed, Err(TargetListError::InvalidTarget(_))));
    }

    #[test]
    fn from_toml_accepts_empty_list() {
        let targets = TargetList::from_toml("targets=[]").unwrap();
        assert!(targets.is_empty());
    }
}
