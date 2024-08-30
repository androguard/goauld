use std::{fs::{File, OpenOptions}, os::unix::fs::FileExt};

use crate::error::InjectionError;

#[derive(Debug)]
pub struct Mem {
    fd: File,
}

impl Mem {
    pub fn new(pid: i32) -> Result<Self, InjectionError> {
        let mem_path: String = format!("/proc/{}/mem", pid);
        debug!("Opening {}", mem_path);

        // open file in read-write mode
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&mem_path)
            .map_err(|_| InjectionError::OpenMemoryError)?;

        Ok(Self { fd })
    }

    pub fn read(&mut self, addr: usize, len: usize) -> Result<Vec<u8>, InjectionError> {
        debug!(
            "reading from remote memory: addr: 0x{:x}, len: {}",
            addr,
            len
        );

        // Create return value
        let mut ret = vec![0; len];
        self.fd.read_exact_at(&mut ret, addr as u64).map_err(|_x| InjectionError::ReadMemoryError)?;
        Ok(ret)
    }

    pub fn write(&mut self, addr: usize, buf: &Vec<u8>) -> Result<(), InjectionError> {
        debug!(
            "writing into remote memory: addr: 0x{:x}, len: {}",
            addr,
            buf.len()
        );

        self.fd.write_all_at(buf, addr as u64).map_err(|_x| InjectionError::WriteMemoryError)
    }
}