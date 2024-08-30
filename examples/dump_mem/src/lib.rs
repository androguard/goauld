use std::thread::sleep;
use std::time::Duration;

use process_vm_io::ProcessVirtualMemoryIO;
use std::io::Read;

fn main() {
    println!("Dumping Memory");

    let process_id = std::process::id();
    let address_of_pid = &process_id as *const _ as u64;
    let mut process_io = unsafe { ProcessVirtualMemoryIO::new(process_id, address_of_pid) }.unwrap();
    
    // Read the stack of this current thread.
    let mut buffer = [0u8; std::mem::size_of::<u32>()];
    process_io.read_exact(&mut buffer).unwrap();
    let also_pid = u32::from_ne_bytes(buffer);
    println!("PID {} {}", process_id, also_pid);
}


#[link_section = ".init_array"]
pub static INITIALIZE: fn() = main;