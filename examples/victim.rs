use std::thread::sleep;
use std::time::Duration;

fn main() {
    loop {
        println!("[VICTIM] Still running...");
        sleep(Duration::from_secs(1));
    }
}