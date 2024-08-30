pub mod class;
pub mod maps;
pub mod mem;


use std::{
    fs::{File, ReadDir},
    io::Error as IoError,
    io::Read,
    os::unix::prelude::MetadataExt,
    path::PathBuf,
};
use goblin::elf::Elf;
use goblin::elf::header::{EM_386, EM_ARM, EM_AARCH64, EM_X86_64};

use crate::error::InjectionError;
use class::ProcClass;
use maps::Maps;

pub type Gid = u32;
pub type Uid = u32;

/// A newtype that references the [`/proc/<id>`](https://man7.org/linux/man-pages/man5/proc.5.html) directory.
pub struct Proc {
    pub path: PathBuf,
    pub pid: i32,
}

/// A extension trait for [`PathBuf`].
pub(crate) trait PathBufExt {
    /// Gets the root [`PathBuf`].
    fn root() -> Self;
}

impl PathBufExt for PathBuf {
    fn root() -> Self {
        "/".into()
    }
}

impl Proc {
    /// Creates a new [`Proc`] that references the host process.
    pub fn current() -> Self {
        Proc{ 
            path: PathBuf::root().join("proc").join("self"), 
            pid: 0,   
        }
    }

    /// Creates a new [`Proc`] that references the task identified by `id`.
    ///
    /// Returns [`None`] if the path `/proc/<id>` does not exist.
    pub fn new(pid: i32) -> Option<Self> {
        let path = PathBuf::root().join("proc").join(pid.to_string());
        path.exists().then_some(Proc{ path, pid })
    }

    /// Gets the owner of the current [`Proc`].
    pub fn owner(&self) -> Result<(Uid, Gid), IoError> {
        let metadata = self.path.metadata()?;
        Ok((metadata.uid(), metadata.gid()))
    }

    /// Reads `/proc/<id>/exe` of the current [`Proc`].
    pub fn exe(&self) -> Result<File, IoError> {
        File::open(self.path.join("exe"))
    }

    /// Reads `/proc/<id>/maps` of the current [`Proc`].
    pub fn maps(&self) -> Result<Maps, InjectionError> {
        maps::Maps::new(self.pid, mem::Mem::new(self.pid).unwrap())
    }

    /// Reads `/proc/<id>/mem` of the current [`Proc`].
    pub fn mem(&self) -> Result<mem::Mem, InjectionError> {
        mem::Mem::new(self.pid)
    }

    /// Reads `/proc/<id>/syscall` of the current [`Proc`].
    pub fn syscall(&self) -> Result<File, IoError> {
        File::open(self.path.join("syscall"))
    }

    /// Reads `/proc/<id>/task` of the current [`Proc`].
    pub fn task(&self) -> Result<ReadDir, IoError> {
        std::fs::read_dir(self.path.join("task"))
    }

    /// Return the class type of the executable to inject
    pub fn class(&self) -> Option<ProcClass> {
        let mut header = [0_u8; 0x40];
        self.exe().ok()?.read_exact(&mut header).ok()?;

        let header = Elf::parse_header(&header).ok()?;

        match header.e_machine {
            #[cfg(target_arch = "aarch64")]
            EM_ARM => Some(ProcClass::ThirtyTwo),
            #[cfg(target_arch = "aarch64")]
            EM_AARCH64 => Some(ProcClass::SixtyFour),
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            EM_386 => Some(ProcClass::ThirtyTwo),
            #[cfg(target_arch = "x86_64")]
            EM_X86_64 => Some(ProcClass::SixtyFour),
            _ => None,
        }
    }

    /// Is it a root process ?
    pub fn privileged(&self) -> bool {
        self.owner().unwrap().0 == 0
    }
}