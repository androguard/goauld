use crate::error::InjectionError;

use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};

pub fn first_shellcode(var_addr: usize, alloc_len: usize) -> Result<Vec<u8>, InjectionError> {
    debug!("creating first_shellcode x64");

    let mut ops = dynasmrt::x64::Assembler::new().unwrap();
    dynasm!(ops
        ; .arch x64

        ; ->start:
        ; push rax
        ; mov rax, [->var_addr]
        ; lock bts DWORD [rax], 0x0
        ; jc ->start
        ; pop rax

        // Save registers
        ; push rax
        ; push rbx
        ; push rcx
        ; push rdx
        ; push rbp
        ; push rsi
        ; push rdi
        ; push r8
        ; push r9
        ; push r10
        ; push r11
        ; push r12
        ; push r13
        ; push r14
        ; push r15

        // mmap call
        ; mov rax, 0x9                  // __NR_mmap
        ; mov rdi, 0                    // addr     = 0
        ; mov rsi, alloc_len as _       // length   = alloc_len
        ; mov rdx, 0x7                  // prot     = PROT_READ | PROT_WRITE | PROT_EXEC
        ; mov r10, 0x22                 // flags    = MAP_PRIVATE | MAP_ANON
        ; mov r8, 0                     // fd       = NULL
        ; mov r9, 0                     // offset   = 0
        ; syscall

        // Turn on the control variable bit
        ; or al, 0x1

        // move mmap addr value to our variable
        ; mov rbx, [->var_addr]
        ; mov [rbx], rax

        // turn off the control variable bit
        ; xor al, al

        // Write a self jmp to the new allocated code
        ; mov DWORD [rax], 0xfeeb
        // Jump to it
        ; jmp rax

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

pub fn raw_dlopen_shellcode(
    dlopen_addr: usize,
    dlopen_path: String,
    origin_hijack_addr: usize,
) -> Result<Vec<u8>, InjectionError> {
    debug!(
        "raw_dlopen_shellcode x64 0x{:x}, 0x{:x}",
        dlopen_addr, origin_hijack_addr
    );

    // dlopen flags RTLD_NOW
    let dlopen_flags: usize = 0x2;

    let mut ops = dynasmrt::x64::Assembler::new().unwrap();
    dynasm!(ops
        ; .arch x64

        // Call dlopen with 2 arguments
        ; mov rsi, dlopen_flags as _
        ; lea rdi, [->dlopen_path_addr]

        ; mov rax, QWORD dlopen_addr as _
        ; call rax

        // Restore the registers
        ; pop r15
        ; pop r14
        ; pop r13
        ; pop r12
        ; pop r11
        ; pop r10
        ; pop r9
        ; pop r8
        ; pop rdi
        ; pop rsi
        ; pop rbp
        ; pop rdx
        ; pop rcx
        ; pop rbx
        ; pop rax

        // Jump back to the original hijack addr
        ; push QWORD [->origin_hijack_addr]
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
