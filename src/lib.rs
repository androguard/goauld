use std::collections::HashMap;

#[macro_use]
extern crate log;

pub mod error;
pub mod payloads;
pub mod proc;
pub mod utils;

use std::ops::Not;

use crate::error::InjectionError;
use crate::proc::Proc;
use crate::utils::ptrace::PtraceScope;
use crate::utils::resolv::RemoteModule;

pub struct Injector {
    remote_proc: proc::Proc,
    file_path: String,
    target_func_sym_name: String,
    target_func_sym_addr: usize,
    target_var_sym_name: String,
    target_var_sym_addr: usize,
    module_cache: HashMap<String, RemoteModule>,
    sym_cache: HashMap<String, usize>,
}

impl Injector {
    pub fn new(pid: i32) -> Result<Injector, InjectionError> {
        info!("[GOAULD][NEW] injector for pid: {}", pid);

        let proc = Proc::new(pid).ok_or(InjectionError::ProcessNotRunning)?;

        match PtraceScope::current() {
            // We must be superuser if the target is superuser
            PtraceScope::All => proc.privileged().not() || Proc::current().privileged(),
            // We must be superuser
            PtraceScope::Restricted | PtraceScope::Admin => Proc::current().privileged(),
            // There's nothing we can do about this
            PtraceScope::None => false,
        }
        .then_some(())
        .ok_or(InjectionError::InsufficientPriviliges)?;

        Ok(Injector {
            remote_proc: proc,
            file_path: String::new(),
            target_func_sym_name: String::new(),
            target_func_sym_addr: 0,
            target_var_sym_name: String::new(),
            target_var_sym_addr: 0,
            module_cache: HashMap::new(),
            sym_cache: HashMap::new(),
        })
    }

    pub fn set_file_path(&mut self, file_path: String) -> Result<&mut Self, InjectionError> {
        let file = std::fs::File::open(&file_path);
        if file.is_err() {
            error!("File not found: {}", file_path);
            return Err(InjectionError::FileError);
        }

        self.file_path = file_path;
        Ok(self)
    }

    #[cfg(not(target_os = "android"))]
    fn prepare_file(&self) -> Result<String, InjectionError> {
        utils::verify_elf_file(self.file_path.as_str())?;

        let tmp_file_path = utils::copy_file_to_tmp(self.file_path.as_str())?;
        Ok(tmp_file_path)
    }

    #[cfg(target_os = "android")]
    fn prepare_file(&self) -> Result<String, InjectionError> {
        utils::verify_elf_file(self.file_path.as_str())?;

        let tmp_file_path = utils::copy_file_to_tmp(self.file_path.as_str())?;
        utils::fix_file_context(tmp_file_path.as_str())?;
        utils::fix_file_permissions(tmp_file_path.as_str())?;
        utils::print_file_hexdump(tmp_file_path.as_str())?;
        Ok(tmp_file_path)
    }

    fn add_sym(&mut self, module_name: &str, sym_name: &str) -> Result<usize, InjectionError> {
        debug!("add_sym: {}!{}", module_name, sym_name);

        if !self.module_cache.contains_key(module_name) {
            let module = self.remote_proc.maps()?.module(module_name)?;
            self.module_cache.insert(module_name.to_string(), module);
        }

        let module = self.module_cache.get(module_name).unwrap();
        debug!("add_sym: {} 0x{:x}", module_name, module.vm_addr);

        if !self.sym_cache.contains_key(sym_name) {
            let sym = module.dlsym_from_fs(sym_name)?;
            self.sym_cache.insert(sym_name.to_string(), sym);
        }

        debug!(
            "add_sym: {} 0x{:x}",
            sym_name,
            self.sym_cache.get(sym_name).unwrap()
        );
        Ok(*self.sym_cache.get(sym_name).unwrap())
    }

    pub fn set_func_sym(
        &mut self,
        module_name: &str,
        sym_name: &str,
    ) -> Result<&mut Self, InjectionError> {
        let sym_addr = self.add_sym(module_name, sym_name)?;
        self.target_func_sym_name = sym_name.to_string();
        self.target_func_sym_addr = sym_addr;
        debug!("set_func_sym: {} 0x{:x}", sym_name, sym_addr);
        Ok(self)
    }

    pub fn set_var_sym(
        &mut self,
        module_name: &str,
        sym_name: &str,
    ) -> Result<&mut Self, InjectionError> {
        let sym_addr = self.add_sym(module_name, sym_name)?;
        self.target_var_sym_name = sym_name.to_string();
        self.target_var_sym_addr = sym_addr;
        debug!("set_var_sym: {} 0x{:x}", sym_name, sym_addr);
        Ok(self)
    }

    pub fn set_default_syms(&mut self) -> Result<&mut Self, InjectionError> {
        self.set_func_sym("libc.so", "malloc")?;
        self.set_var_sym("libc.so", "timezone")?;
        Ok(self)
    }

    pub fn use_raw_dlopen(&mut self) -> Result<&mut Self, InjectionError> {
        self.set_func_sym(&utils::get_dlopen_lib_name(), "dlopen")?;
        Ok(self)
    }

    pub fn restart_app_and_get_pid(package_name: &str) -> Result<u32, InjectionError> {
        let pid = utils::restart_app_and_get_pid(package_name);
        if pid > 0 {
            Ok(pid)
        } else {
            Err(InjectionError::PidNotFound)
        }
    }

    pub fn inject(&mut self) -> Result<(), InjectionError> {
        let file_path = self.prepare_file()?;

        if self.target_func_sym_name.is_empty() || self.target_var_sym_name.is_empty() {
            warn!("target_func_sym or target_var_sym is empty, using defaults");
            self.set_default_syms()?;
        }

        let class = self
            .remote_proc
            .class()
            .ok_or(InjectionError::UnsupportedArch)?;

        info!("Building second stage shellcode");
        let second_stage = payloads::raw_dlopen_shellcode(
            &class,
            *self.sym_cache.get("dlopen").unwrap(),
            file_path,
            self.target_func_sym_addr,
        )?;

        info!("Building first stage shellcode");
        //let first_stage = payloads::first_shellcode(&class, self.target_var_sym_addr, second_stage.len()).unwrap();
        let first_stage = payloads::first_shellcode(&class, self.target_var_sym_addr, 4028)?;

        let mut mem = self.remote_proc.mem()?;

        info!("read original bytes");
        let func_original_bytes = mem.read(self.target_func_sym_addr, first_stage.len())?;
        let var_original_bytes = mem.read(self.target_var_sym_addr, 0x8)?;

        info!("write first stage shellcode");
        mem.write(self.target_var_sym_addr, &vec![0x0; 0x8])?;
        mem.write(self.target_func_sym_addr, &first_stage)?;

        info!("wait for shellcode to trigger");
        let mut new_map: u64;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(1));
            let data = mem.read(self.target_var_sym_addr, 0x8)?;
            //debug!("Waiting ... {:?}", data);

            // u64 from val
            new_map = u64::from_le_bytes(data[0..8].try_into().unwrap());
            if (new_map & 0x1 != 0) && (new_map & 0xffff_ffff_ffff_fff0 != 0) {
                info!("Boom ... 0x{:x}", new_map);
                break;
            }
        }

        new_map &= 0xffff_ffff_ffff_fff0;
        info!("new map: 0x{:x}", new_map);

        #[cfg(any(target_arch = "aarch64"))]
        {
            info!("overwrite malloc with loop");
            let self_jmp_stage = payloads::self_jmp()?;
            mem.write(self.target_func_sym_addr, &self_jmp_stage)?;
        }

        std::thread::sleep(std::time::Duration::from_millis(1000));

        info!("restore original bytes");
        mem.write(self.target_func_sym_addr, &func_original_bytes)?;
        mem.write(self.target_var_sym_addr, &var_original_bytes)?;

        info!("overwrite new map");
        mem.write(new_map as usize, &second_stage)?;

        info!("injection done.");
        Ok(())
    }
}
