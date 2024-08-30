use crate::error::InjectionError;

use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};

use dynasmrt::x86::X86Relocation;
use dynasmrt::VecAssembler;

pub fn first_shellcode(var_addr: usize, alloc_len: usize) -> Result<Vec<u8>, InjectionError> {
    debug!("Creating first_shellcode x86...");

    let mut ops = dynasmrt::x86::Assembler::new().unwrap();
    dynasm!(ops
        ; .arch x86

        // Sync other threads to avoid the code to be executed multiple time
        ; ->start:
        ; push ebx
        ; mov ebx, var_addr as _
        ; lock bts WORD [ebx], 0x0i8
        ; jc ->start
        ; pop ebx

        // Save registers
        ; pushad

        // mmap2 call
        ; mov ebx, 0x0                     // addr     = 0
        ; mov ecx, alloc_len as _          // length   = alloc_len
        ; mov edx, 0x7                     // prot     = PROT_READ | PROT_WRITE | PROT_EXEC
        ; mov esi, 0x22                    // flags    = MAP_PRIVATE | MAP_ANON
        ; mov edi, -1                      // fd       = NULL
        ; mov ebp, 0x0                     // offset   = 0
        ; mov eax, 0xc0                    // __NR_mmap2
        ; int 0x80u8 as _

        // Turn on the control variable bit
        ; or al, 0x1

        // move mmap addr value to our variable
        ; mov ebx, var_addr as _
        ; mov [ebx], eax

        // turn off the control variable bit
        ; xor al, al

        // Write a self jmp to the new allocated code
        ; mov DWORD [eax], 0xfeeb
        // Jump to it
        ; jmp eax

        ; .align 4
        ; ->var_addr:
        ; .qword var_addr as _

        ; .align 4
        ; ->alloc_len:
        ; .qword alloc_len as _ 
    );

    match ops.finalize() {
        Ok(shellcode) => Ok(shellcode.to_vec()),
        Err(_) => Err(InjectionError::ShellcodeError),
    }
}

pub fn raw_dlopen_shellcode(dlopen_addr: usize, dlopen_path: String, origin_hijack_addr: usize) -> Result<Vec<u8>, InjectionError> {
    debug!("Creating raw_dlopen_shellcode x86 0x{:x} ...", origin_hijack_addr);

    // dlopen flags RTLD_NOW
    let dlopen_flags: usize = 0x2;
    let mut ops = VecAssembler::<X86Relocation>::new(0);

    dynasm!(ops
        ; .arch x86

        // Get EIP value
        ; call 0x0u8 as _
        ; pop ebx

        // Get the address of the lib to use for dlopen
        ; lea eax, [->dlopen_path_addr]
        ; add ebx, eax
        ; add ebx, -0x5
        ; mov eax, dlopen_addr as _

        // Make a new call frame
        ; push ebp
        ; mov ebp, esp

        // Push the dlopen flags + path addr
        ; push dlopen_flags as _
        ; push ebx

        // Call dlopen
        ; call eax

        // Restore the call frame
        ; mov esp, ebp
        ; pop ebp

        // Restore the registers
        ; popad
        
        // Jump back to the original hijack addr
        ; push origin_hijack_addr as _
        ; ret

        ; .align 4
        ; ->dlopen_flags:
        ; .qword dlopen_flags as _

        ; ->dlopen_path_addr:
        ; .bytes dlopen_path.as_bytes()
        ; .bytes [0x0]

        ; .align 4
        ; ->dlopen:
        ; .qword dlopen_addr as _

        ; .align 4
        ; ->origin_hijack_addr:
        ; .qword origin_hijack_addr as _
    );

    match ops.finalize() {
        Ok(shellcode) => Ok(shellcode.to_vec()),
        Err(_) => Err(InjectionError::ShellcodeError),
    }
}
