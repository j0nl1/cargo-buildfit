use anyhow::{Result, bail};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::{
    Foundation::{FILETIME, INVALID_HANDLE_VALUE},
    System::{Diagnostics::ToolHelp::*, Threading::*},
};

pub fn start_time(pid: u32) -> Option<String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    let mut created: FILETIME = unsafe { std::mem::zeroed() };
    let mut exit = created;
    let mut kernel = created;
    let mut user = created;
    if unsafe {
        GetProcessTimes(
            handle.as_raw_handle(),
            &mut created,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return None;
    }
    Some(((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime)).to_string())
}
pub fn parent_pid(pid: u32) -> Option<u32> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return None;
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of_val(&entry) as u32;
    let mut ok = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) };
    while ok != 0 {
        if entry.th32ProcessID == pid {
            return Some(entry.th32ParentProcessID);
        }
        ok = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) };
    }
    None
}
pub fn powershell(script: &str) -> Result<std::process::Output> {
    // Pass script text as a single argument; do not use a shell or interpolate paths.
    let output = crate::platform::output(std::process::Command::new("powershell.exe").args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        script,
    ]))?;
    if !output.status.success() || !output.stderr.is_empty() {
        bail!("Windows read-only inspection failed");
    }
    Ok(output)
}
pub fn boot_identity() -> Result<String> {
    static BOOT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    if let Some(value) = BOOT.get() {
        return Ok(value.clone());
    }
    let output = powershell(
        "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')",
    )?;
    let value = std::str::from_utf8(&output.stdout)?.trim().to_owned();
    if value.is_empty() {
        bail!("Windows boot identity unavailable");
    }
    let _ = BOOT.set(value.clone());
    Ok(value)
}
