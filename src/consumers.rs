use anyhow::Result;
#[cfg(unix)]
use anyhow::bail;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::io;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
#[cfg(unix)]
use std::{fs, process::Command};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub busy: BTreeMap<PathBuf, Vec<String>>,
    pub incomplete: Vec<String>,
    #[serde(default)]
    pub referenced_paths: BTreeSet<PathBuf>,
    #[serde(default)]
    pub broad_roots: BTreeSet<PathBuf>,
    #[serde(default)]
    pub precise_process_paths: bool,
}

impl Snapshot {
    #[cfg(unix)]
    fn reference(&mut self, roots: &[PathBuf], value: &Path, why: &str) {
        for root in roots {
            if value.starts_with(root) {
                self.referenced_paths.insert(value.to_owned());
                let reasons = self.busy.entry(root.clone()).or_default();
                if reasons.len() < 8 && !reasons.iter().any(|x| x == why) {
                    reasons.push(why.to_owned());
                }
            }
        }
    }
    #[cfg(unix)]
    fn error(&mut self, where_: &Path, error: &io::Error) {
        if error.kind() != io::ErrorKind::NotFound && self.incomplete.len() < 24 {
            self.incomplete
                .push(format!("{}: {error}", where_.display()));
        }
    }
    pub fn protected(&self, root: &Path) -> bool {
        !self.incomplete.is_empty()
            || self.broad_roots.contains(root)
            || !self.precise_process_paths && self.busy.contains_key(root)
    }
    pub fn protects_candidate(&self, root: &Path, path: &Path) -> bool {
        self.protected(root)
            || self
                .referenced_paths
                .iter()
                .any(|p| path.starts_with(p) || p.starts_with(path))
    }
}

pub fn snapshot(roots: &[PathBuf], privileged: bool) -> Result<Snapshot> {
    if roots.is_empty() {
        return Ok(Snapshot::default());
    }
    #[cfg(unix)]
    if privileged && unsafe { libc::geteuid() } != 0 {
        let out = Command::new("sudo")
            .args(["-n", "--"])
            .arg(std::env::current_exe()?)
            .arg("internal-probe")
            .arg(serde_json::to_string(roots)?)
            .arg(std::process::id().to_string())
            .output()?;
        if !out.status.success() {
            bail!("privileged consumer visibility unavailable; pruning skipped");
        }
        return Ok(serde_json::from_slice(&out.stdout)?);
    }
    #[cfg(windows)]
    let _ = privileged;
    Ok(inspect(roots, std::process::id()))
}

#[cfg(target_os = "linux")]
pub fn inspect(roots: &[PathBuf], owner_pid: u32) -> Snapshot {
    let mut out = Snapshot {
        precise_process_paths: true,
        ..Snapshot::default()
    };
    let entries = match fs::read_dir("/proc") {
        Ok(v) => v,
        Err(e) => {
            out.error(Path::new("/proc"), &e);
            return out;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(v) => v,
            Err(e) => {
                out.error(Path::new("/proc"), &e);
                continue;
            }
        };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid == std::process::id() || pid == owner_pid {
            continue;
        }
        let base = entry.path();
        let name = fs::read_to_string(base.join("comm")).unwrap_or_default();
        let reason = format!("process {pid} {}", name.trim());
        for field in ["exe", "cwd"] {
            let path = base.join(field);
            match fs::read_link(&path) {
                Ok(value) => {
                    out.reference(roots, &value, &reason);
                    if field == "cwd"
                        && ["cargo", "rustc", "cargo-nextest", "xtask", "rust-analyzer"]
                            .contains(&name.trim())
                    {
                        for root in roots {
                            if root.parent().is_some_and(|p| value.starts_with(p)) {
                                out.busy
                                    .entry(root.clone())
                                    .or_default()
                                    .push(format!("active build/check {pid}"));
                                out.broad_roots.insert(root.clone());
                            }
                        }
                    }
                }
                Err(e) => out.error(&path, &e),
            }
        }
        let fd_dir = base.join("fd");
        match fs::read_dir(&fd_dir) {
            Ok(fds) => {
                for fd in fds {
                    match fd {
                        Ok(fd) => match fs::read_link(fd.path()) {
                            Ok(value) => out.reference(roots, &value, &reason),
                            Err(e) => out.error(&fd.path(), &e),
                        },
                        Err(e) => out.error(&fd_dir, &e),
                    }
                }
            }
            Err(e) => out.error(&fd_dir, &e),
        }
        let maps = base.join("maps");
        match fs::read_to_string(&maps) {
            Ok(text) => {
                for line in text.lines() {
                    if let Some(i) = line.find('/') {
                        out.reference(
                            roots,
                            Path::new(line[i..].trim_end_matches(" (deleted)")),
                            &reason,
                        );
                    }
                }
            }
            Err(e) => out.error(&maps, &e),
        }
    }
    let mut locations: Vec<PathBuf> = [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
        "/etc/systemd/user",
        "/usr/lib/systemd/user",
        "/run/systemd/user",
        "/etc/xdg/autostart",
        "/usr/share/applications",
        "/usr/local/bin",
        "/usr/bin",
        "/opt",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let cols: Vec<_> = line.split(':').collect();
            if cols.len() >= 6
                && cols[2]
                    .parse::<u32>()
                    .is_ok_and(|uid| uid == 0 || (1000..65534).contains(&uid))
            {
                for suffix in [
                    ".config/systemd/user",
                    ".config/autostart",
                    ".local/share/applications",
                    ".local/share/systemd/user",
                    ".local/bin",
                    ".native",
                ] {
                    locations.push(Path::new(cols[5]).join(suffix));
                }
            }
        }
    } else {
        out.incomplete
            .push("installed user entry discovery unavailable".into());
    }
    let mut remaining = 100_000usize;
    for location in locations {
        installed(&location, roots, &mut out, &mut remaining, 0);
    }
    out
}

#[cfg(unix)]
fn installed(
    path: &Path,
    roots: &[PathBuf],
    out: &mut Snapshot,
    remaining: &mut usize,
    depth: usize,
) {
    if *remaining == 0 || depth > 16 {
        out.incomplete
            .push("installed entry scan limit reached".into());
        return;
    }
    *remaining -= 1;
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            out.error(path, &e);
            return;
        }
    };
    if m.file_type().is_symlink() {
        if let Ok(target) = fs::read_link(path) {
            let resolved = if target.is_absolute() {
                target
            } else {
                path.parent().unwrap_or(Path::new("/")).join(target)
            };
            out.reference(
                roots,
                &resolved,
                &format!("installed symlink {}", path.display()),
            );
        }
        match fs::canonicalize(path) {
            Ok(target) => out.reference(
                roots,
                &target,
                &format!("installed symlink {}", path.display()),
            ),
            Err(error) => out.error(path, &error),
        }
        // Do not recurse through directory symlinks.
    } else if m.is_dir() {
        match fs::read_dir(path) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(e) => installed(&e.path(), roots, out, remaining, depth + 1),
                        Err(e) => out.error(path, &e),
                    }
                }
            }
            Err(e) => out.error(path, &e),
        }
    }
    // Symlinks to scripts are entry points too: inspect their resolved file contents.
    let readable_metadata = if m.file_type().is_symlink() {
        fs::metadata(path).ok()
    } else {
        Some(m)
    };
    if readable_metadata.is_some_and(|m| m.is_file() && m.len() <= 1024 * 1024) {
        match fs::read(path) {
            Ok(data) => {
                #[cfg(target_os = "macos")]
                let data = if path.extension().is_some_and(|e| e == "plist") {
                    match crate::plist_macos::strings(&data) {
                        Ok(data) => data,
                        Err(error) => {
                            out.incomplete
                                .push(format!("installed plist {}: {error}", path.display()));
                            return;
                        }
                    }
                } else {
                    data
                };
                if let Ok(text) = std::str::from_utf8(&data) {
                    for root in roots {
                        if text.contains(&root.to_string_lossy().to_string()) {
                            out.broad_roots.insert(root.clone());
                            out.busy
                                .entry(root.clone())
                                .or_default()
                                .push(format!("installed entry {}", path.display()));
                        }
                    }
                }
            }
            Err(e) => out.error(path, &e),
        }
    }
}

#[cfg(all(test, unix))]
pub fn inspect_installed_fixture(entry: &Path, roots: &[PathBuf]) -> Snapshot {
    let mut result = Snapshot::default();
    installed(entry, roots, &mut result, &mut 1000, 0);
    result
}

#[cfg(any(target_os = "macos", all(test, unix)))]
#[path = "consumers_macos.rs"]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::inspect;

#[cfg(all(test, unix))]
mod macos_tests {
    use super::*;
    #[test]
    fn macos_lsof_paths_preserve_spaces_newlines_and_runtime_scope() {
        let root = PathBuf::from("/not-present/source/target");
        let path = root.join("old test\nname");
        let data = format!("p123\0cfixture\0\nf4\0tREG\0n{}\0\n", path.display());
        let mut out = Snapshot {
            precise_process_paths: true,
            ..Default::default()
        };
        let seen = macos::parse(data.as_bytes(), std::slice::from_ref(&root), 999, &mut out);
        assert!(seen.contains(&123));
        assert!(out.protects_candidate(&root, &path));
        assert!(!out.protects_candidate(&root, &root.join("other")));
        assert!(out.incomplete.is_empty());
    }
    #[test]
    fn macos_unreadable_descriptors_protect_all_output() {
        let mut out = Snapshot::default();
        macos::parse(b"p123\0cfixture\0\nfNOFD\0", &[], 999, &mut out);
        assert!(out.protected(Path::new("/any")));
    }
}

#[cfg(windows)]
pub use crate::windows::consumers::inspect;
