use super::*;
use std::os::unix::ffi::OsStringExt;

// lsof -F0 keeps paths containing spaces and newlines unambiguous.
pub(super) fn parse(
    data: &[u8],
    roots: &[PathBuf],
    owner: u32,
    out: &mut Snapshot,
) -> BTreeSet<u32> {
    let mut seen = BTreeSet::new();
    let mut pid = 0;
    let mut name = String::new();
    let mut fd = Vec::new();
    for field in data.split(|b| *b == 0) {
        let field = field.strip_prefix(b"\n").unwrap_or(field);
        let Some((&tag, value)) = field.split_first() else {
            continue;
        };
        match tag {
            b'p' => {
                pid = std::str::from_utf8(value)
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                if pid != 0 {
                    seen.insert(pid);
                } else {
                    out.incomplete.push("invalid lsof process identity".into());
                }
            }
            b'c' => name = String::from_utf8_lossy(value).into_owned(),
            b'f' => {
                fd = value.to_vec();
                if value == b"NOFD" {
                    out.incomplete
                        .push(format!("process {pid} descriptors unavailable"));
                }
            }
            b'n' if pid != 0
                && pid != owner
                && pid != std::process::id()
                && value.starts_with(b"/") =>
            {
                let raw = PathBuf::from(std::ffi::OsString::from_vec(value.to_vec()));
                let path = raw.canonicalize().unwrap_or(raw);
                out.reference(roots, &path, &format!("process {pid} {name}"));
                if fd == b"cwd"
                    && ["cargo", "rustc", "cargo-nextest", "xtask", "rust-analyzer"]
                        .contains(&name.as_str())
                {
                    for root in roots {
                        if root.parent().is_some_and(|p| path.starts_with(p)) {
                            out.broad_roots.insert(root.clone());
                            out.busy
                                .entry(root.clone())
                                .or_default()
                                .push(format!("active build/check {pid}"));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    seen
}

#[cfg(target_os = "macos")]
fn pids() -> Result<BTreeSet<u32>> {
    let mut ids = vec![0i32; 131072];
    let count = unsafe {
        libc::proc_listallpids(
            ids.as_mut_ptr().cast(),
            (ids.len() * std::mem::size_of::<i32>()) as i32,
        )
    };
    if count <= 0 || count as usize >= ids.len() {
        bail!("process enumeration unavailable or truncated");
    }
    Ok(ids[..count as usize]
        .iter()
        .filter(|p| **p > 0)
        .map(|p| *p as u32)
        .collect())
}

#[cfg(target_os = "macos")]
pub fn inspect(roots: &[PathBuf], owner: u32) -> Snapshot {
    let mut out = Snapshot {
        precise_process_paths: true,
        ..Default::default()
    };
    let result = (|| -> Result<()> {
        let before = pids()?;
        let output = crate::platform::output(
            Command::new("/usr/sbin/lsof").args(["-nP", "-F0pcfnt", "-S2"]),
        )?;
        if !output.status.success() || !output.stderr.is_empty() {
            bail!("lsof reported incomplete consumer visibility");
        }
        let seen = parse(&output.stdout, roots, owner, &mut out);
        let after = pids()?;
        for pid in before.intersection(&after).copied() {
            if pid == owner || pid == std::process::id() {
                continue;
            }
            let info = match crate::platform::bsd_info(pid) {
                Ok(info) => info,
                Err(e) => {
                    if pids()?.contains(&pid) && !zombie(pid)? {
                        bail!("process {pid} identity inspection unavailable: {e}");
                    } else {
                        continue;
                    }
                }
            };
            if info.pbi_status == libc::SZOMB {
                continue;
            }
            if !seen.contains(&pid) {
                bail!("process {pid} missing from consumer inventory");
            }
            let mut buffer = [0u8; 4096];
            let n = unsafe {
                libc::proc_pidpath(pid as i32, buffer.as_mut_ptr().cast(), buffer.len() as u32)
            };
            if n <= 0 {
                if pids()?.contains(&pid) && !zombie(pid)? {
                    bail!("process {pid} executable visibility unavailable");
                }
            } else {
                let end = buffer.iter().position(|b| *b == 0).unwrap_or(buffer.len());
                let path = PathBuf::from(std::ffi::OsString::from_vec(buffer[..end].to_vec()));
                out.reference(roots, &path, &format!("process {pid} executable"));
            }
        }
        installed_entries(roots, &mut out)?;
        Ok(())
    })();
    if let Err(error) = result {
        out.incomplete.push(error.to_string());
    }
    out
}

#[cfg(target_os = "macos")]
fn installed_entries(roots: &[PathBuf], out: &mut Snapshot) -> Result<()> {
    let mut locations: Vec<PathBuf> = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        "/System/Library/LaunchDaemons",
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    let mut applications = vec![
        PathBuf::from("/Applications"),
        PathBuf::from("/System/Applications"),
    ];
    let homes = crate::platform::output(Command::new("/usr/bin/dscl").args([
        ".",
        "-list",
        "/Users",
        "NFSHomeDirectory",
    ]))?;
    if !homes.status.success() || !homes.stderr.is_empty() {
        bail!("installed user entry discovery unavailable");
    }
    for line in std::str::from_utf8(&homes.stdout)?.lines() {
        let Some(i) = line.find(char::is_whitespace) else {
            bail!("ambiguous user home entry");
        };
        let home = Path::new(line[i..].trim());
        if !home.is_absolute() {
            bail!("ambiguous user home path");
        }
        if home == Path::new("/var/empty") || home == Path::new("/dev/null") {
            continue;
        }
        for suffix in [
            "Library/LaunchAgents",
            "Library/LaunchDaemons",
            ".local/bin",
            ".native",
        ] {
            locations.push(home.join(suffix));
        }
        applications.push(home.join("Applications"));
    }
    let mut budget = 100_000;
    for location in locations {
        super::installed(&location, roots, out, &mut budget, 0);
    }
    for path in applications {
        application_entries(&path, roots, out, &mut budget, 0);
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn application_entries(
    path: &Path,
    roots: &[PathBuf],
    out: &mut Snapshot,
    budget: &mut usize,
    depth: usize,
) {
    if *budget == 0 || depth > 4 {
        out.incomplete
            .push("application entry scan limit reached".into());
        return;
    }
    *budget -= 1;
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            out.error(path, &e);
            return;
        }
    };
    if m.file_type().is_symlink() || m.is_file() {
        super::installed(path, roots, out, budget, 0);
        return;
    }
    if path.extension().is_some_and(|s| s == "app") {
        for suffix in ["Contents/Info.plist", "Contents/MacOS"] {
            super::installed(&path.join(suffix), roots, out, budget, 0);
        }
        return;
    }
    match fs::read_dir(path) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(e) => application_entries(&e.path(), roots, out, budget, depth + 1),
                    Err(e) => out.error(path, &e),
                }
            }
        }
        Err(e) => out.error(path, &e),
    }
}

#[cfg(target_os = "macos")]
fn zombie(pid: u32) -> Result<bool> {
    // Darwin returns ESRCH for BSD info on zombies still present in its PID list.
    // A verified zombie has released executable mappings and file descriptors.
    let output = crate::platform::output(Command::new("/bin/ps").args([
        "-p",
        &pid.to_string(),
        "-o",
        "stat=",
    ]))?;
    Ok(output.status.success()
        && output.stderr.is_empty()
        && std::str::from_utf8(&output.stdout)?.trim().starts_with('Z'))
}
