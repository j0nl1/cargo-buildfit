use anyhow::Result;
#[cfg(target_os = "linux")]
use std::fs;

#[cfg(target_os = "linux")]
pub const READ_FLAGS: i32 = libc::O_NOATIME | libc::O_NOFOLLOW;
#[cfg(target_os = "macos")]
pub const READ_FLAGS: i32 = libc::O_NOFOLLOW;

#[cfg(target_os = "linux")]
pub fn start_time(pid: u32) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)
        .map(str::to_owned)
}
#[cfg(target_os = "linux")]
pub fn parent_pid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}
#[cfg(target_os = "linux")]
pub fn boot_identity() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?)
}

#[cfg(target_os = "macos")]
pub fn bsd_info(pid: u32) -> std::io::Result<libc::proc_bsdinfo> {
    let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
    let size = std::mem::size_of_val(&info) as i32;
    if unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    } != size
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(info)
}
#[cfg(target_os = "macos")]
pub fn start_time(pid: u32) -> Option<String> {
    let info = bsd_info(pid).ok()?;
    Some(format!(
        "{}-{}",
        info.pbi_start_tvsec, info.pbi_start_tvusec
    ))
}
#[cfg(target_os = "macos")]
pub fn parent_pid(pid: u32) -> Option<u32> {
    Some(bsd_info(pid).ok()?.pbi_ppid)
}
#[cfg(target_os = "macos")]
pub fn boot_identity() -> Result<String> {
    let mut bytes = [0u8; 128];
    let mut size = bytes.len();
    if unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if size < 2 || size > bytes.len() || bytes[size - 1] != 0 {
        anyhow::bail!("invalid boot session identity");
    }
    Ok(std::str::from_utf8(&bytes[..size - 1])?.to_owned())
}

// Only read-only, task-owned inspection helpers use this bounded subprocess path.
#[cfg(any(target_os = "macos", windows))]
pub fn output(command: &mut std::process::Command) -> Result<std::process::Output> {
    use std::{
        io::Read,
        process::Stdio,
        time::{Duration, Instant},
    };
    fn read(pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
        std::thread::spawn(move || {
            let mut data = Vec::new();
            pipe.take(16 * 1024 * 1024 + 1).read_to_end(&mut data)?;
            Ok(data)
        })
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = read(child.stdout.take().unwrap());
    let stderr = read(child.stderr.take().unwrap());
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > Duration::from_secs(15) {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("consumer inspection helper timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout
        .join()
        .map_err(|_| anyhow::anyhow!("inspection reader failed"))??;
    let stderr = stderr
        .join()
        .map_err(|_| anyhow::anyhow!("inspection reader failed"))??;
    if stdout.len() > 16 * 1024 * 1024 || stderr.len() > 16 * 1024 * 1024 {
        anyhow::bail!("consumer inspection output limit reached");
    }
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

#[derive(Clone, Debug)]
pub struct FileInfo {
    pub device: u64,
    pub inode: u128,
    pub size: u64,
    pub allocated: u64,
    pub mtime: i64,
    pub mtime_ns: i64,
    pub atime: i64,
    pub links: u64,
    pub regular: bool,
    pub directory: bool,
    pub reparse: bool,
}
#[cfg(unix)]
pub fn file_info(path: &std::path::Path) -> Result<FileInfo> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path)?;
    Ok(FileInfo {
        device: m.dev(),
        inode: u128::from(m.ino()),
        size: m.len(),
        allocated: m.blocks() * 512,
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        atime: m.atime(),
        links: m.nlink(),
        regular: m.is_file(),
        directory: m.is_dir(),
        reparse: m.file_type().is_symlink(),
    })
}
#[cfg(windows)]
pub use crate::windows::file::{file_info, open_read};
#[cfg(windows)]
pub use crate::windows::process::{boot_identity, parent_pid, start_time};
#[cfg(unix)]
pub fn open_read(path: &std::path::Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(READ_FLAGS)
        .open(path)?)
}
pub fn metadata_is_link(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        metadata.file_type().is_symlink()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
}
pub fn os_from_git(bytes: &[u8]) -> Result<std::ffi::OsString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(std::ffi::OsString::from_vec(bytes.to_vec()))
    }
    #[cfg(windows)]
    {
        Ok(std::ffi::OsString::from(std::str::from_utf8(bytes)?))
    }
}

pub fn replace_file(from: &std::path::Path, to: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        Ok(std::fs::rename(from, to)?)
    }
    #[cfg(windows)]
    {
        crate::windows::file::replace_file(from, to)
    }
}
pub fn busy_error(error: &anyhow::Error) -> bool {
    #[cfg(unix)]
    {
        let _ = error;
        false
    }
    #[cfg(windows)]
    {
        error
            .downcast_ref::<std::io::Error>()
            .and_then(|e| e.raw_os_error())
            .is_some_and(|e| [5, 32, 33, 1224].contains(&e))
    }
}
