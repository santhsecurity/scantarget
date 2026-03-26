//! Example showing CIDR expansion.
//!
//! Run: cargo run --example cidr_expansion

use scantarget::Target;

fn main() {
    let cidr_str = "10.0.0.0/29";
    match cidr_str.parse::<Target>() {
        Ok(target) => {
            println!("Successfully parsed target: {:?}", target);
            // In a real application, you would expand this target into individual IPs
            // using the target's internal network structure.
        }
        Err(e) => println!("Failed to parse: {}", e),
    }
}
