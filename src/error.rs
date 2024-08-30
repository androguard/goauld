use std::io::Error as IoError;

/// The errors may occurr.
#[derive(Debug)]
pub enum InjectionError {
    RemoteProcessError,
    OpenMemoryError,
    ReadMemoryError,
    WriteMemoryError,
    RemoteModuleError,
    ModuleNotFound,
    FileError,
    CommandError,
    ShellcodeError,
    PidNotFound,
    /// It occurs when the `dlopen` library (`libc-x.xx.so` on Linux, `libdl.so` on Android)
    /// is not found in the `/proc/<id>/maps` file of the target process. This either means that library has not been loaded - which
    /// is kind of impossible - or `/proc/<id>/maps` was improperly parsed.
    LibraryNotFound(String),
    /// It occurs when `dlopen` symbol name (`__libc_dlopen_mode`/`dlopen` on Linux, `dlopen` on Android)
    /// was not found in the expected library.
    SymbolNotFound(String),
    /// It occurs when the instruction pointer of the target process couldn't be retrieved. This either means there's a lack of priviliges,
    /// `/proc/<id>/syscall` is missing or was improperly parsed, or none of the process thread was blocked when the intruduction
    /// was attempted.
    InstructionPointerNotFound,
    /// It occurs when the target process architecture is not supported.
    UnsupportedArch,
    /// It occurs when the target process is not running - e.g. `/proc/<id>` doesn't exist.
    ProcessNotRunning,
    /// It occurs when the intruducer process lacks of sufficient priviliges. This typically depends on `/proc/sys/kernel/yama/ptrace_scope`
    /// value on Linux.
    InsufficientPriviliges,
    /// It occurs when a I/O error occurred.
    Io(IoError),
}

impl From<IoError> for InjectionError {
    fn from(err: IoError) -> Self {
        InjectionError::Io(err)
    }
}