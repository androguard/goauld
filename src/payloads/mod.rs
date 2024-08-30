use crate::error::InjectionError;
use crate::proc::class::ProcClass;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;
#[cfg(target_arch = "x86_64")]
mod x86_64;


pub(crate) fn first_shellcode(class: &ProcClass, var_addr: usize, alloc_len: usize) -> Result<Vec<u8>, InjectionError> {
    match class {
        #[cfg(any(target_arch = "aarch64"))]
        ProcClass::ThirtyTwo => aarch64::first_shellcode(var_addr, alloc_len),
        #[cfg(any(target_arch = "aarch64"))]
        ProcClass::SixtyFour => aarch64::first_shellcode(var_addr, alloc_len),
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        ProcClass::ThirtyTwo => x86::first_shellcode(var_addr, alloc_len),
        #[cfg(target_arch = "x86")]
        ProcClass::SixtyFour => unimplemented!(),
        #[cfg(target_arch = "x86_64")]
        ProcClass::SixtyFour => x86_64::first_shellcode(var_addr, alloc_len),
    }
}

pub(crate) fn raw_dlopen_shellcode(class: &ProcClass, dlopen_addr: usize, dlopen_path: String, jmp_addr: usize) -> Result<Vec<u8>, InjectionError> {
    match class {
        #[cfg(any(target_arch = "aarch64"))]
        ProcClass::ThirtyTwo => aarch64::raw_dlopen_shellcode(dlopen_addr, dlopen_path, jmp_addr),
        #[cfg(any(target_arch = "aarch64"))]
        ProcClass::SixtyFour => aarch64::raw_dlopen_shellcode(dlopen_addr, dlopen_path, jmp_addr),
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        ProcClass::ThirtyTwo => x86::raw_dlopen_shellcode(dlopen_addr, dlopen_path, jmp_addr),
        #[cfg(target_arch = "x86")]
        ProcClass::SixtyFour => unimplemented!(),
        #[cfg(target_arch = "x86_64")]
        ProcClass::SixtyFour => x86_64::raw_dlopen_shellcode(dlopen_addr, dlopen_path, jmp_addr),
    }
}

pub(crate) fn self_jmp() -> Result<Vec<u8>, InjectionError> {
    #[cfg(any(target_arch = "aarch64"))]
    return aarch64::self_jmp();

    unimplemented!()
}