use crate::{
    artifacts::{Candidate, Identity},
    platform::FileInfo,
};
use anyhow::{Result, bail};
use std::{
    fs::File,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE},
    Storage::FileSystem::*,
};

pub fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
pub fn open(path: &Path, access: u32, share: u32, create: bool) -> Result<File> {
    let handle = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            access,
            share,
            std::ptr::null(),
            if create { OPEN_ALWAYS } else { OPEN_EXISTING },
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_handle(handle) };
    if info(&file)?.reparse {
        bail!("reparse point retained: {}", path.display());
    }
    Ok(file)
}
fn query<T>(file: &File, class: FILE_INFO_BY_HANDLE_CLASS) -> Result<T> {
    let mut value = unsafe { std::mem::zeroed::<T>() };
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            (&mut value as *mut T).cast(),
            std::mem::size_of::<T>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(value)
}
pub fn info(file: &File) -> Result<FileInfo> {
    let id: FILE_ID_INFO = query(file, FileIdInfo)?;
    let basic: FILE_BASIC_INFO = query(file, FileBasicInfo)?;
    let standard: FILE_STANDARD_INFO = query(file, FileStandardInfo)?;
    let ticks = basic.LastWriteTime - 116444736000000000;
    Ok(FileInfo {
        device: id.VolumeSerialNumber,
        inode: u128::from_le_bytes(id.FileId.Identifier),
        size: standard.EndOfFile.max(0) as u64,
        allocated: standard.AllocationSize.max(0) as u64,
        mtime: ticks.div_euclid(10000000),
        mtime_ns: ticks.rem_euclid(10000000) * 100,
        atime: (basic.LastAccessTime - 116444736000000000).div_euclid(10000000),
        links: u64::from(standard.NumberOfLinks),
        regular: !standard.Directory,
        directory: standard.Directory,
        reparse: basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
    })
}
pub fn file_info(path: &Path) -> Result<FileInfo> {
    // Metadata-only access neither follows the leaf reparse point nor vetoes busy outputs.
    let handle = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    info(&unsafe { File::from_raw_handle(handle) })
}
pub fn open_read(path: &Path) -> Result<File> {
    open(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        false,
    )
}
pub fn reject_reparse_components(path: &Path) -> Result<()> {
    let _parents = hold_parents(path)?;
    if file_info(path)?.reparse {
        bail!("reparse output retained");
    }
    Ok(())
}
fn hold_parents(path: &Path) -> Result<Vec<File>> {
    use std::path::{Component, Prefix};
    if !path.is_absolute() {
        bail!("absolute local output path required");
    }
    let mut current = PathBuf::new();
    let mut held = Vec::new();
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("output parent unavailable"))?;
    for part in parent.components() {
        match part {
            Component::Prefix(p)
                if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) =>
            {
                current.push(part.as_os_str())
            }
            Component::RootDir => current.push(part.as_os_str()),
            Component::Normal(_) => current.push(part.as_os_str()),
            _ => bail!("unsupported or nonlocal output path"),
        }
        if current.is_absolute() && !matches!(part, Component::Prefix(_)) {
            let directory = open(
                &current,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                false,
            )?;
            if !info(&directory)?.directory {
                bail!("non-directory output ancestor");
            }
            held.push(directory);
        }
    }
    Ok(held)
}
pub fn available(path: &Path) -> Result<u64> {
    let mut available = 0u64;
    if unsafe {
        GetDiskFreeSpaceExW(
            wide(path).as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(available)
}
pub fn unlink_verified(candidate: &Candidate) -> Result<()> {
    let _parents = hold_parents(&candidate.path)?;
    // No sharing and classic delete disposition let Windows veto live handles,
    // executable images and mapped sections. Never force POSIX delete semantics.
    let file = open(&candidate.path, GENERIC_READ | DELETE, 0, false)?;
    let actual = info(&file)?;
    let expected = Identity {
        device: actual.device,
        inode: actual.inode,
        size: actual.size,
        allocated: actual.allocated,
        mtime: actual.mtime,
        mtime_ns: actual.mtime_ns,
        links: actual.links,
    };
    if actual.directory || actual.reparse || actual.links != 1 || expected != candidate.identity {
        bail!("output changed before handle deletion");
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of_val(&disposition) as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    drop(file);
    if candidate.path.exists() {
        bail!("output deletion did not complete");
    }
    Ok(())
}
pub fn replace_file(from: &Path, to: &Path) -> Result<()> {
    if unsafe {
        MoveFileExW(
            wide(from).as_ptr(),
            wide(to).as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
