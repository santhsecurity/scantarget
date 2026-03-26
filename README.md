# scantarget

Parse scan targets from strings, files, or stdin. Handles URLs, bare domains, IP addresses, and CIDR ranges. Deduplicates and normalizes.

```rust
use scantarget::Target;

let t: Target = "https://example.com".parse().unwrap();
let t: Target = "192.168.1.0/24".parse().unwrap();
let t: Target = "example.com".parse().unwrap();
```

## From a file

```rust
use scantarget::TargetList;

let targets = TargetList::from_file("targets.txt").unwrap();
// One target per line. Empty lines and #comments are skipped.
```

## From a string

```rust
use scantarget::parse_many;

let targets = parse_many("
    https://a.com
    https://b.com
    # this is a comment
    192.168.1.0/24
");
```

## CIDR expansion

```rust
use scantarget::expand_cidr;

let ips = expand_cidr("10.0.0.0".parse().unwrap(), 24);
// Returns 256 IP addresses
```

## Why not just use url::Url?

url::Url handles URLs. scantarget handles the messy reality of target lists: bare domains that need https:// prepended, IP addresses, CIDR ranges, mixed formats in one file, comment lines, deduplication. One crate, every format.

## Contributing

Pull requests are welcome. There is no such thing as a perfect crate. If you find a bug, a better API, or just a rough edge, open a PR. We review quickly.

## License

MIT. Copyright 2026 CORUM COLLECTIVE LLC.

[![crates.io](https://img.shields.io/crates/v/scantarget.svg)](https://crates.io/crates/scantarget)
[![docs.rs](https://docs.rs/scantarget/badge.svg)](https://docs.rs/scantarget)
