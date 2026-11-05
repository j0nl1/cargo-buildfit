use crate::consumers::Snapshot;
use anyhow::Result;
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Inventory {
    busy: bool,
    incomplete: Vec<String>,
    installed: Vec<String>,
    homes: Vec<PathBuf>,
}
fn normalized(value: &str) -> String {
    value
        .replace("\\\\?\\", "")
        .replace('\\', "/")
        .to_lowercase()
}
fn reference(value: &str, roots: &[PathBuf], out: &mut Snapshot) {
    let normalized = normalized(value);
    for root in roots {
        if normalized.contains(&normalized_path(root)) {
            out.broad_roots.insert(root.clone());
            out.busy
                .entry(root.clone())
                .or_default()
                .push("installed Windows entry".into());
        }
    }
    // Resolve quoted command paths and short-name/junction aliases before comparison.
    let arguments = arguments(value);
    for i in 0..arguments.len().min(32) {
        let mut candidate = String::new();
        for argument in arguments.iter().skip(i).take(16) {
            if !candidate.is_empty() {
                candidate.push(' ');
            }
            candidate.push_str(argument);
            if let Ok(path) = Path::new(&candidate).canonicalize() {
                for root in roots {
                    if path.starts_with(root) {
                        out.broad_roots.insert(root.clone());
                        out.busy
                            .entry(root.clone())
                            .or_default()
                            .push("resolved installed Windows entry".into());
                    }
                }
            }
        }
    }
}
fn normalized_path(path: &Path) -> String {
    normalized(&path.to_string_lossy())
}
fn arguments(value: &str) -> Vec<String> {
    use windows_sys::Win32::{Foundation::LocalFree, UI::Shell::CommandLineToArgvW};
    let value = super::file::wide(Path::new(value));
    let mut count = 0;
    let args = unsafe { CommandLineToArgvW(value.as_ptr(), &mut count) };
    if args.is_null() {
        return Vec::new();
    }
    let mut result = Vec::new();
    for i in 0..count.min(512) {
        let ptr = unsafe { *args.offset(i as isize) };
        let mut len = 0;
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        result.push(String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(ptr, len)
        }));
    }
    unsafe {
        LocalFree(args.cast());
    }
    result
}
pub fn inspect(roots: &[PathBuf], owner: u32) -> Snapshot {
    let mut out = Snapshot {
        precise_process_paths: true,
        ..Default::default()
    };
    let result = (|| -> Result<()> {
        let output = crate::platform::output(
            std::process::Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    include_str!("inspect.ps1"),
                ])
                .env("BUILDFIT_PROBE_ROOTS", serde_json::to_string(roots)?)
                .env("BUILDFIT_PROBE_OWNER", owner.to_string()),
        )?;
        if !output.status.success() || !output.stderr.is_empty() {
            anyhow::bail!("Windows installed/consumer inspection unavailable");
        }
        let inventory: Inventory = serde_json::from_slice(&output.stdout)?;
        out.incomplete.extend(inventory.incomplete);
        if inventory.busy {
            out.broad_roots.extend(roots.iter().cloned());
            for root in roots {
                out.busy
                    .entry(root.clone())
                    .or_default()
                    .push("active Windows compiler/check; output scope uncertain".into());
            }
        }
        for value in inventory.installed {
            reference(&value, roots, &mut out);
        }
        let mut remaining = 100_000;
        let mut seen = BTreeSet::new();
        for home in inventory.homes {
            for suffix in [".local/bin", ".cargo/bin", ".native"] {
                scan(
                    &home.join(suffix),
                    roots,
                    &mut out,
                    &mut remaining,
                    &mut seen,
                    0,
                )?;
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        out.incomplete.push(error.to_string());
    }
    out
}
fn scan(
    path: &Path,
    roots: &[PathBuf],
    out: &mut Snapshot,
    budget: &mut usize,
    seen: &mut BTreeSet<PathBuf>,
    depth: usize,
) -> Result<()> {
    if *budget == 0 || depth > 12 {
        anyhow::bail!("Windows installed symlink scan limit reached");
    }
    *budget -= 1;
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if !seen.insert(path.to_owned()) {
        return Ok(());
    }
    if crate::platform::metadata_is_link(&m) {
        let resolved = path.canonicalize()?;
        reference(&resolved.to_string_lossy(), roots, out);
        return Ok(());
    }
    if m.is_dir() {
        for item in fs::read_dir(path)? {
            scan(&item?.path(), roots, out, budget, seen, depth + 1)?;
        }
    } else if m.len() <= 1024 * 1024
        && path
            .extension()
            .is_some_and(|x| x == "cmd" || x == "bat" || x == "ps1")
    {
        reference(&fs::read_to_string(path)?, roots, out);
    }
    Ok(())
}
