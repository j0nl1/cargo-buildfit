use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub use crate::platform::start_time;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lease {
    pub pid: u32,
    pub start: String,
    pub boot: String,
    pub roots: Vec<PathBuf>,
    pub expires: u64,
    pub reason: String,
    #[serde(default)]
    pub headroom_bytes: u64,
}
impl Lease {
    pub fn active(&self) -> bool {
        self.boot == crate::platform::boot_identity().unwrap_or_default()
            && (start_time(self.pid).as_deref() == Some(&self.start) || self.expires > now())
    }
}
pub struct OwnedLease {
    path: PathBuf,
}
impl OwnedLease {
    pub fn new(state: &Path, roots: Vec<PathBuf>) -> Result<Self> {
        let directory = state.join("leases");
        fs::create_dir_all(&directory)?;
        let pid = std::process::id();
        let lease = Lease {
            pid,
            start: start_time(pid)
                .ok_or_else(|| anyhow::anyhow!("process identity unavailable"))?,
            boot: crate::platform::boot_identity()?,
            roots,
            expires: 0,
            reason: "active Cargo pipeline".into(),
            headroom_bytes: 0,
        };
        let path = directory.join(format!("{pid}-{}.json", lease.start));
        let temp = path.with_extension("tmp");
        fs::write(&temp, serde_json::to_vec(&lease)?)?;
        crate::platform::replace_file(&temp, &path)?;
        Ok(Self { path })
    }

    pub fn admit(&self, bytes: u64) -> Result<()> {
        let mut lease: Lease = serde_json::from_slice(&fs::read(&self.path)?)?;
        lease.headroom_bytes = bytes;
        let temp = self.path.with_extension("tmp");
        fs::write(&temp, serde_json::to_vec(&lease)?)?;
        crate::platform::replace_file(&temp, &self.path)?;
        Ok(())
    }
}
impl Drop for OwnedLease {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn other_roots(state: &Path) -> Result<Vec<PathBuf>> {
    let mut roots = vec![];
    let directory = state.join("leases");
    if !directory.exists() {
        return Ok(roots);
    }
    for p in fs::read_dir(directory)? {
        let p = p?.path();
        if p.extension().is_none_or(|v| v != "json") {
            continue;
        }
        let lease: Lease = serde_json::from_slice(&fs::read(&p)?)
            .map_err(|_| anyhow::anyhow!("unreadable lease; pruning skipped"))?;
        if lease.pid != std::process::id() && lease.active() {
            roots.extend(lease.roots);
        }
    }
    Ok(roots)
}

pub fn reserved_bytes(state: &Path) -> Result<u64> {
    let dir = state.join("leases");
    if !dir.exists() {
        return Ok(0);
    }
    let mut bytes = 0u64;
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_none_or(|s| s != "json") {
            continue;
        }
        let data = match fs::read(path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let lease: Lease = serde_json::from_slice(&data)?;
        if lease.pid != std::process::id() && lease.active() {
            bytes = bytes.saturating_add(lease.headroom_bytes);
        }
    }
    Ok(bytes)
}

pub fn ancestor_reserved_bytes(state: &Path) -> Result<u64> {
    let mut ancestors = std::collections::BTreeSet::new();
    let mut pid = std::process::id();
    for _ in 0..128 {
        let Some(parent) = crate::platform::parent_pid(pid) else {
            break;
        };
        if parent == 0 || !ancestors.insert(parent) {
            break;
        }
        pid = parent;
    }
    let dir = state.join("leases");
    let mut bytes = 0u64;
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_none_or(|s| s != "json") {
            continue;
        }
        let data = match fs::read(path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let lease: Lease = serde_json::from_slice(&data)?;
        if ancestors.contains(&lease.pid) && lease.active() {
            bytes = bytes.saturating_add(lease.headroom_bytes);
        }
    }
    Ok(bytes)
}

pub fn reserve(state: &Path, root: PathBuf, seconds: u64, reason: String) -> Result<PathBuf> {
    if seconds == 0 || seconds > 86400 || reason.trim().is_empty() {
        bail!("reservation requires a reason and duration of 1..86400 seconds");
    }
    let root = fs::canonicalize(root)?;
    let dir = state.join("leases");
    fs::create_dir_all(&dir)?;
    let value = Lease {
        pid: 0,
        start: String::new(),
        boot: crate::platform::boot_identity()?,
        roots: vec![root],
        expires: now() + seconds,
        reason,
        headroom_bytes: 0,
    };
    let path = dir.join(format!("reservation-{}-{}.json", now(), std::process::id()));
    let temp = path.with_extension("tmp");
    fs::write(&temp, serde_json::to_vec(&value)?)?;
    crate::platform::replace_file(&temp, &path)?;
    Ok(path)
}
