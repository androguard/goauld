use std::thread::sleep;
use std::time::Duration;

fn main() {
    println!("Hello -");
    sleep(Duration::from_secs(1));
    println!("- world from the a shared Rust Library");
}

#[link_section = ".init_array"]
pub static INITIALIZE: fn() = main;