use crate::error::InjectionError;

use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};

pub fn first_shellcode(var_addr: usize, alloc_len: usize) -> Result<Vec<u8>, InjectionError> {
    debug!("first_shellcode aarch64");

    let mut ops = dynasmrt::aarch64::Assembler::new().unwrap();
    dynasm!(ops
        ; .arch aarch64

        ; ->start:
        // check if the bit is set
        ; ldr x6, ->var_addr
        ; ldxrb w1, [x6]
        ; cbnz w1, ->start

        // set the bit
        ; mov w2, 0x1
        ; stxrb w1, w2, [x6]
        ; cbnz w1, ->start

        // save the registers
        ; sub sp, sp, #0x100
        ; stp x0, x1, [sp, #0x0]
        ; stp x2, x3, [sp, #0x10]
        ; stp x4, x5, [sp, #0x20]
        ; stp x6, x7, [sp, #0x30]
        ; stp x8, x9, [sp, #0x40]
        ; stp x10, x11, [sp, #0x50]
        ; stp x12, x13, [sp, #0x60]
        ; stp x14, x15, [sp, #0x70]
        ; stp x16, x17, [sp, #0x80]
        ; stp x18, x19, [sp, #0x90]
        ; stp x20, x21, [sp, #0xa0]
        ; stp x22, x23, [sp, #0xb0]
        ; stp x24, x25, [sp, #0xc0]
        ; stp x26, x27, [sp, #0xd0]
        ; stp x28, x29, [sp, #0xe0]
        ; stp x30, xzr, [sp, #0xf0]

        // mmap call
        ; mov x0, #0x0                  // addr       (NULL)
        ; mov x1, alloc_len as _        // len        (0x1000)
        ; mov x2, #0x7                  // prot       (RWX)
        ; mov x3, #0x22                 // flags      (MAP_PRIVATE | MAP_ANONYMOUS)
        ; mvn x4, xzr                   // fd         (-1)
        ; mov x5, #0x0                  // offset     (ignored)
        ; mov x8, #0xde                 // syscall no (mmap)
        ; svc #0x0                      // syscall

        // write self loop instruction to the new map
        ; ldr w1, ->self_jmp
        ; str w1, [x0]

        // flush cache
        // https://chromium.googlesource.com/v8/v8/+/9405fcfdd1984341ea06a192b3b08bdb6069db15/src/arm64/cpu-arm64.cc
        // ; dc civac, x0
        // ; dsb ish
        // ; ic ivau, x0
        ; dsb ish
        ; isb

        // save mmap addr (with bit set to keep the other threads spinning)
        ; orr x0, x0, #0x1
        ; str x0, [x6, #0x0]

        // turn off the bit
        ; eor x0, x0, #0x1

        // jump to the new map
        ; br x0

        ; .align 4
        ; ->minus_one:
        ; .qword -1 as _

        ; .align 4
        ; ->var_addr:
        ; .qword var_addr as _

        ; .align 4
        ; ->alloc_len:
        ; .qword alloc_len as _

        ; .align 4
        ; ->self_jmp:
        ; b ->self_jmp
    );

    match ops.finalize() {
        Ok(shellcode) => Ok(shellcode.to_vec()),
        Err(_) => Err(InjectionError::ShellcodeError),
    }
}

pub fn raw_dlopen_shellcode(
    dlopen_addr: usize,
    dlopen_path: String,
    jmp_addr: usize,
) -> Result<Vec<u8>, InjectionError> {
    debug!("raw_dlopen_shellcode aarch64");

    let mut ops = dynasmrt::aarch64::Assembler::new().unwrap();

    // dlopen flags RTLD_NOW
    let dlopen_flags: usize = 0x2;
    let dlopen_path_bytes: &[u8] = dlopen_path.as_bytes();

    dynasm!(ops
        ; .arch aarch64

        // for testing
        // ; brk #0x1

        // load args
        ; adr x0, ->dlopen_path
        ; ldr x1, ->dlopen_flags

        // call dlopen
        ; ldr x8, ->dlopen
        ; blr x8

        // if dlopen fails, crash
        ; cbz x0, ->crash

        // load the original args
        ; ldp x0, x1, [sp, #0x0]
        ; ldp x2, x3, [sp, #0x10]
        ; ldp x4, x5, [sp, #0x20]
        ; ldp x6, x7, [sp, #0x30]
        ; ldp x8, x9, [sp, #0x40]
        ; ldp x10, x11, [sp, #0x50]
        ; ldp x12, x13, [sp, #0x60]
        ; ldp x14, x15, [sp, #0x70]
        ; ldp x16, x17, [sp, #0x80]
        ; ldp x18, x19, [sp, #0x90]
        ; ldp x20, x21, [sp, #0xa0]
        ; ldp x22, x23, [sp, #0xb0]
        ; ldp x24, x25, [sp, #0xc0]
        ; ldp x26, x27, [sp, #0xd0]
        ; ldp x28, x29, [sp, #0xe0]
        ; ldp x30, xzr, [sp, #0xf0]
        ; add sp, sp, #0x100

        // jump to the original function
        ; ldr x8, ->oldfun
        ; br x8

        ; ->crash:
        ; brk #0x1

        ; .align 4
        ; ->dlopen_path:
        ; .bytes dlopen_path_bytes
        ; .bytes [0x0]

        ; .align 4
        ; ->dlopen_flags:
        ; .qword dlopen_flags as _

        ; .align 4
        ; ->dlopen:
        ; .qword dlopen_addr as _

        ; .align 4
        ; ->oldfun:
        ; .qword jmp_addr as _
    );
    match ops.finalize() {
        Ok(shellcode) => Ok(shellcode.to_vec()),
        Err(_) => Err(InjectionError::ShellcodeError),
    }
}

pub fn self_jmp() -> Result<Vec<u8>, InjectionError> {
    debug!("self_jmp aarch64");

    let mut ops = dynasmrt::aarch64::Assembler::new().unwrap();

    dynasm!(ops
        ; .arch aarch64
        ; ->self_jmp:
        ; b ->self_jmp
    );

    match ops.finalize() {
        Ok(shellcode) => Ok(shellcode.to_vec()),
        Err(_) => Err(InjectionError::ShellcodeError),
    }
}
