use std::alloc::{alloc, dealloc, Layout};
use std::thread::sleep;
use std::time::Duration;

fn main() {
    loop {
        println!("[VICTIM] Still running with forced alloc...");
        unsafe {
            let layout = Layout::new::<u16>();
            let ptr = alloc(layout);

            *(ptr as *mut u16) = 42;
            assert_eq!(*(ptr as *mut u16), 42);

            dealloc(ptr, layout);
        }
        sleep(Duration::from_secs(1));
    }
}