use std::alloc::{alloc, dealloc, Layout};
use std::thread::sleep;
use std::time::Duration;

use debugoff;

fn main() {
    loop {
        println!("Still running...");
        unsafe {
            let layout = Layout::new::<u16>();
            let ptr = alloc(layout);

            *(ptr as *mut u16) = 42;
            assert_eq!(*(ptr as *mut u16), 42);

            dealloc(ptr, layout);
        }
        debugoff::multi_ptraceme_or_die();
        sleep(Duration::from_secs(1));
    }
}