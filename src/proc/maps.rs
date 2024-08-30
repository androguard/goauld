use proc_maps::{get_process_maps, MapRange, Pid};


use crate::utils::resolv::RemoteModule;

use crate::error::InjectionError;

use super::mem::Mem;

pub struct Maps {
    pid: i32,
    mem: Mem,
}

impl Maps {
    pub fn new(pid: i32, mem: Mem) -> Result<Self, InjectionError> {
        Ok(Self { pid, mem })
    }

    fn maps(&self) -> Result<Vec<MapRange>, InjectionError> {
        get_process_maps(self.pid as Pid).map_err(|_| InjectionError::RemoteProcessError)
    }

    fn maps_by_name(&self, name: &str) -> Result<Vec<MapRange>, InjectionError> {
        let maps = self.maps()?;
        let mut maps_by_name: Vec<MapRange> = Vec::new();
        for map in maps {              
            match map.filename() {
                None => continue,
                Some(filename) => {
                    let file_name = filename.file_name();
                    match file_name {
                        None => continue,
                        Some(file_name) => {
                            if file_name.to_str().unwrap().starts_with(name) {
                                maps_by_name.push(map);
                            }
                        }
                    }

                }
            }
        }

        if maps_by_name.is_empty() {
            return Err(InjectionError::ModuleNotFound);
        }

        Ok(maps_by_name)
    }

    fn module_bytes(&mut self, module_name: &str) -> Result<Vec<u8>, InjectionError> {
        let maps = self.maps_by_name(module_name)?;
        let mut module_bytes: Vec<u8> = Vec::new();

        for map in maps {
            module_bytes.resize(map.offset, 0);
            let mut buf = self.mem.read(map.start(), map.size())?;
            module_bytes.append(&mut buf);
        }

        Ok(module_bytes)
    }

    pub fn module(&mut self, module_name: &str) -> Result<RemoteModule, InjectionError> {
        let maps = self.maps_by_name(module_name)?;
        Ok(RemoteModule::new(
            maps[0].filename().unwrap().to_str().unwrap(),
            maps[0].start(),
            self.module_bytes(module_name)?,
        ))
    }
}