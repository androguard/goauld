use std::fs::read_to_string;

/// A enum that represents the content of `/proc/sys/kernel/yama/ptrace_scope`.
///
/// Even if we do not use `ptrace`, `/proc/<pid>/` readability depends on this value.
///
/// Source: https://man7.org/linux/man-pages/man2/ptrace.2.html
pub enum PtraceScope {
    // 0
    All,
    // 1
    Restricted,
    // 2
    Admin,
    // 3
    None,
}

impl PtraceScope {
    /// Gets the content of `/proc/sys/kernel/yama/ptrace_scope`, which determines whether we can read `/proc/<pid>` or not.
    /// If the file doesn't exists, we assume the kernel was not built with the Yama Linux Security Module.
    pub fn current() -> Self {
        if let Ok(scope) = read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
            match scope.trim() {
                "0" => PtraceScope::All,
                "1" => PtraceScope::Restricted,
                "2" => PtraceScope::Admin,
                "3" => PtraceScope::None,
                _ => unreachable!(),
            }
        } else {
            PtraceScope::All
        }
    }
}