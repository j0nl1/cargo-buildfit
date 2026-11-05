#[cfg(unix)]
mod unix {
    use anyhow::{Result, bail};
    use std::{
        fs::{File, OpenOptions},
        os::fd::AsRawFd,
        path::Path,
    };

    pub struct Lock(File);
    impl Lock {
        pub fn acquire(path: &Path, create: bool) -> Result<Self> {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(create)
                .truncate(false)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                bail!("maintenance or Cargo lock busy: {}", path.display());
            }
            // Darwin flock and record locks share the conflict domain. Holding both
            // would conflict with our own lock; Linux requires both namespaces.
            #[cfg(target_os = "linux")]
            {
                let mut record: libc::flock = unsafe { std::mem::zeroed() };
                record.l_type = libc::F_WRLCK as _;
                record.l_whence = libc::SEEK_SET as _;
                if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &record) } != 0 {
                    bail!("Cargo record lock busy or unsupported: {}", path.display());
                }
            }
            Ok(Self(file))
        }
    }
    use std::os::unix::fs::OpenOptionsExt;
    impl Drop for Lock {
        fn drop(&mut self) {
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}
#[cfg(unix)]
pub use unix::Lock;

#[cfg(windows)]
mod windows {
    use anyhow::Result;
    use std::{fs::File, os::windows::io::AsRawHandle, path::Path};
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE},
        Storage::FileSystem::*,
        System::IO::OVERLAPPED,
    };
    pub struct Lock(File);
    impl Lock {
        pub fn acquire(path: &Path, create: bool) -> Result<Self> {
            let file = crate::windows::file::open(
                path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                create,
            )?;
            let mut overlap: OVERLAPPED = unsafe { std::mem::zeroed() };
            if unsafe {
                LockFileEx(
                    file.as_raw_handle(),
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlap,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(Self(file))
        }
    }
    impl Drop for Lock {
        fn drop(&mut self) {
            let mut overlap: OVERLAPPED = unsafe { std::mem::zeroed() };
            unsafe {
                UnlockFileEx(self.0.as_raw_handle(), 0, u32::MAX, u32::MAX, &mut overlap);
            }
        }
    }
}
#[cfg(windows)]
pub use windows::Lock;
