//! Example showing how to parse multiple targets from a multiline string.
//!
//! Run: cargo run --example file_parsing

fn main() {
    let list = scantarget::parse_many(
        "
        # Web targets
        https://api.example.com
        https://admin.example.com

        # Network targets
        192.168.1.50
        10.0.0.0/24
    ",
    );

    println!("Successfully parsed {} targets:", list.len());
    for target in list {
        println!(" - {:?}", target);
    }
}
