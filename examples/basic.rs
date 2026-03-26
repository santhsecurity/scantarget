//! Parse targets from various formats.
//!
//! Run: cargo run --example basic

use scantarget::Target;

fn main() {
    // Parse individual targets
    let targets = vec![
        "https://example.com",
        "example.com",
        "192.168.1.1",
        "10.0.0.0/24",
    ];

    for t in &targets {
        match t.parse::<Target>() {
            Ok(target) => println!("  {} -> {:?}", t, target),
            Err(e) => println!("  {} -> ERROR: {}", t, e),
        }
    }

    // Parse from multiline string
    let list = scantarget::parse_many(
        "
        https://target1.com
        https://target2.com
        # this is a comment
        192.168.1.0/24
    ",
    );
    println!("\nParsed {} targets from text", list.len());
}
