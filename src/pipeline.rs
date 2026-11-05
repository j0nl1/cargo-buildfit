use crate::{
    artifacts::{self, Candidate, Identity},
    config::{Config, GIB},
    consumers,
    git::SourceGuard,
    lease,
    locks::Lock,
};
#[cfg(unix)]
use anyhow::Context;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

#[cfg(unix)]
pub fn available(path: &Path) -> Result<u64> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let path = CString::new(path.as_os_str().as_bytes())?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    #[cfg(target_os = "macos")]
    let blocks = u64::from(stat.f_bavail);
    #[cfg(target_os = "linux")]
    let blocks = stat.f_bavail;
    Ok(blocks.saturating_mul(stat.f_frsize))
}
pub fn admit(cfg: &Config, free: u64) -> Result<()> {
    if free < cfg.stop_below_gib.saturating_mul(GIB) {
        bail!(
            "only {:.2} GiB free, below the configured {} GiB admission floor; protected outputs were retained. No build started",
            free as f64 / GIB as f64,
            cfg.stop_below_gib
        );
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub time: u64,
    pub phase: String,
    pub dry_run: bool,
    pub pool_bytes_measured: u64,
    pub available_before: u64,
    pub available_after: u64,
    pub removed_allocated_bytes: u64,
    pub removed: Vec<Candidate>,
    pub eligible: Vec<PathBuf>,
    pub skips: BTreeMap<String, usize>,
    pub errors: Vec<String>,
    pub source_preserved: Option<bool>,
    pub source_guards_before: Vec<SourceGuard>,
    pub source_guards_after: Vec<SourceGuard>,
    pub elapsed_ms: u128,
}
#[derive(Serialize, Deserialize)]
struct Stamp {
    measured_at: u64,
    targets: Vec<PathBuf>,
    actual_pool_bytes: u64,
    #[serde(default)]
    available_bytes: u64,
}

fn skipped(receipt: &mut Receipt, message: &str) {
    *receipt.skips.entry(message.to_owned()).or_default() += 1;
}
fn fingerprint_same(c: &Candidate) -> bool {
    artifacts::read_fingerprint(&c.fingerprint)
        .is_ok_and(|b| format!("{:x}", Sha256::digest(b)) == c.fingerprint_sha256)
}
fn old_enough(c: &Candidate, min_age: u64, now: u64) -> bool {
    c.last_used <= now && now.saturating_sub(c.last_used) >= min_age
}
fn pinned(cfg: &Config, target: &Path, leases: &[PathBuf]) -> bool {
    cfg.pins
        .iter()
        .chain(leases)
        .any(|p| p.starts_with(target) || target.starts_with(p))
}

pub fn maintain(
    cfg: &Config,
    roots: &[(PathBuf, PathBuf)],
    phase: &str,
    dry_run: bool,
    force: bool,
) -> Result<Option<Receipt>> {
    if roots.is_empty() {
        return Ok(None);
    }
    fs::create_dir_all(&cfg.state_dir)?;
    if let Some(parent) = cfg.maintenance_lock.parent() {
        fs::create_dir_all(parent)?;
    }
    let _maintenance = match Lock::acquire(&cfg.maintenance_lock, true) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("buildfit: maintenance deferred: {error}");
            return Ok(None);
        }
    };
    let started = Instant::now();
    let free = available(&roots[0].0)?;
    let targets: Vec<PathBuf> = roots.iter().map(|x| x.0.clone()).collect();
    let stamp_path = cfg.state_dir.join(format!(
        "pool-{:x}.json",
        Sha256::digest(serde_json::to_vec(&targets)?)
    ));
    if !force
        && !dry_run
        && let Ok(data) = fs::read(&stamp_path)
        && let Ok(stamp) = serde_json::from_slice::<Stamp>(&data)
        && stamp.targets == targets
        && lease::now().saturating_sub(stamp.measured_at) < cfg.check_interval_seconds
        && free >= cfg.stop_below_gib.saturating_mul(GIB)
        && stamp.available_bytes.saturating_sub(free) < 20 * GIB
    {
        return Ok(None);
    }
    let pool = artifacts::measure(cfg, roots)?;
    let mut receipt = Receipt {
        time: lease::now(),
        phase: phase.into(),
        dry_run,
        pool_bytes_measured: pool.bytes,
        available_before: free,
        available_after: free,
        removed_allocated_bytes: 0,
        removed: vec![],
        eligible: vec![],
        skips: pool.skips.clone(),
        errors: vec![],
        source_preserved: None,
        source_guards_before: vec![],
        source_guards_after: vec![],
        elapsed_ms: 0,
    };
    let quota = cfg.quota_gib.saturating_mul(GIB);
    let goal = quota.saturating_mul(cfg.low_water_percent) / 100;
    let need = if pool.bytes > quota {
        pool.bytes.saturating_sub(goal)
    } else {
        0
    }
    .max(cfg.reserve_gib.saturating_mul(GIB).saturating_sub(free));
    if need == 0 && !force {
        return finish(cfg, receipt, &stamp_path, targets, started);
    }
    let mut candidates = vec![];
    for c in pool.candidates {
        if !old_enough(&c, cfg.min_age_seconds, lease::now()) {
            skipped(&mut receipt, "recent output");
            continue;
        }
        if pinned(cfg, &c.target, &lease::other_roots(&cfg.state_dir)?) {
            skipped(&mut receipt, "pinned or reserved output");
            continue;
        }
        candidates.push(c);
    }
    if candidates.is_empty() {
        return finish(cfg, receipt, &stamp_path, targets, started);
    }
    let before = consumers::snapshot(&targets, cfg.privileged_probe)?;
    let mut groups: BTreeMap<PathBuf, Vec<Candidate>> = BTreeMap::new();
    for c in candidates {
        if before.protected(&c.target) {
            skipped(&mut receipt, "current consumer or incomplete visibility");
        } else {
            groups.entry(c.target.clone()).or_default().push(c);
        }
    }
    if !before.incomplete.is_empty() {
        receipt.errors.extend(before.incomplete);
    }
    let cleaning = (|| -> Result<()> {
        for (target, candidates) in groups {
            if started.elapsed().as_secs() >= cfg.max_cleanup_seconds {
                skipped(&mut receipt, "maintenance time budget");
                break;
            }
            let source = candidates[0].source.clone();
            let guard = match SourceGuard::capture(&source, &target) {
                Ok(g) => g,
                Err(e) => {
                    skipped(&mut receipt, &format!("source reconstruction guard: {e}"));
                    continue;
                }
            };
            let mut lock_paths = std::collections::BTreeSet::new();
            for c in &candidates {
                for parent in [&target, &c.profile] {
                    for name in [".cargo-lock", ".cargo-build-lock", ".cargo-artifact-lock"] {
                        let p = parent.join(name);
                        if p.exists() {
                            lock_paths.insert(p);
                        }
                    }
                }
                if !c.profile.join(".cargo-lock").is_file() {
                    lock_paths.clear();
                    break;
                }
            }
            if lock_paths.is_empty() {
                skipped(&mut receipt, "missing Cargo lock identity");
                continue;
            }
            let locks: Result<Vec<_>> =
                lock_paths.iter().map(|p| Lock::acquire(p, false)).collect();
            let Ok(_locks) = locks else {
                skipped(&mut receipt, "Cargo locks busy or unsupported");
                continue;
            };
            if guard != SourceGuard::capture(&source, &target)? {
                skipped(&mut receipt, "source changed while acquiring locks");
                continue;
            }
            let refreshed = consumers::snapshot(&targets, cfg.privileged_probe)?;
            if refreshed.protected(&target)
                || pinned(cfg, &target, &lease::other_roots(&cfg.state_dir)?)
            {
                skipped(&mut receipt, "consumer appeared after locks");
                continue;
            }
            receipt.source_guards_before.push(guard.clone());
            for c in candidates {
                if started.elapsed().as_secs() >= cfg.max_cleanup_seconds {
                    skipped(&mut receipt, "maintenance time budget");
                    break;
                }
                if receipt.removed_allocated_bytes >= need && !dry_run {
                    break;
                }
                if receipt
                    .removed_allocated_bytes
                    .saturating_add(c.identity.allocated)
                    > cfg.max_remove_gib.saturating_mul(GIB)
                {
                    skipped(&mut receipt, "removal byte budget");
                    continue;
                }
                let fresh =
                    consumers::snapshot(std::slice::from_ref(&target), cfg.privileged_probe)?;
                if fresh.protected(&target)
                    || pinned(cfg, &target, &lease::other_roots(&cfg.state_dir)?)
                {
                    skipped(&mut receipt, "consumer appeared before deletion");
                    break;
                }
                if fresh.protects_candidate(&target, &c.path) {
                    skipped(&mut receipt, "candidate has a current consumer");
                    continue;
                }
                if !cfg.permitted(&c.path)
                    || c.path.canonicalize().ok().as_ref() != Some(&c.path)
                    || Identity::read(&c.path).ok().as_ref() != Some(&c.identity)
                    || !fingerprint_same(&c)
                {
                    skipped(&mut receipt, "output identity changed");
                    continue;
                }
                receipt.eligible.push(c.path.clone());
                if !dry_run {
                    if guard != SourceGuard::capture(&source, &target)? {
                        skipped(&mut receipt, "source changed before deletion");
                        break;
                    }
                    match unlink_verified(&c) {
                        Ok(()) => {
                            receipt.removed_allocated_bytes += c.identity.allocated;
                            receipt.removed.push(c);
                        }
                        Err(e) if crate::platform::busy_error(&e) => {
                            skipped(&mut receipt, "Windows file consumer or access restriction")
                        }
                        Err(e) => receipt.errors.push(e.to_string()),
                    }
                }
            }
            let after = SourceGuard::capture(&source, &target)?;
            let unchanged = guard == after;
            receipt.source_guards_after.push(after);
            receipt.source_preserved = Some(receipt.source_preserved.unwrap_or(true) && unchanged);
            if !unchanged {
                receipt.errors.push(
                    "source changed during guarded maintenance; investigate concurrent edits"
                        .into(),
                );
                break;
            }
        }
        Ok(())
    })();
    if let Err(error) = cleaning {
        receipt
            .errors
            .push(format!("maintenance stopped safely: {error:#}"));
    }
    finish(cfg, receipt, &stamp_path, targets, started)
}

fn finish(
    cfg: &Config,
    mut receipt: Receipt,
    stamp_path: &Path,
    targets: Vec<PathBuf>,
    started: Instant,
) -> Result<Option<Receipt>> {
    receipt.available_after = available(&targets[0])?;
    receipt.elapsed_ms = started.elapsed().as_millis();
    // Observation never changes the maintenance throttle. Only actual measurements/removals count.
    if !receipt.dry_run && receipt.errors.is_empty() {
        let stamp = Stamp {
            measured_at: lease::now(),
            targets,
            actual_pool_bytes: receipt
                .pool_bytes_measured
                .saturating_sub(receipt.removed_allocated_bytes),
            available_bytes: receipt.available_after,
        };
        atomic_json(stamp_path, &stamp)?;
    }
    fs::create_dir_all(&cfg.receipt_dir)?;
    let path = cfg.receipt_dir.join(format!(
        "{}-{}-{}-{}.json",
        receipt.time,
        std::process::id(),
        receipt.phase,
        started.elapsed().as_nanos()
    ));
    atomic_json(&path, &receipt)?;
    if receipt.removed_allocated_bytes > 0 {
        eprintln!(
            "buildfit: freed {:.2} GiB; {:.2} GiB available; receipt {}",
            receipt.removed_allocated_bytes as f64 / GIB as f64,
            receipt.available_after as f64 / GIB as f64,
            path.display()
        );
    }
    if !receipt.errors.is_empty() {
        eprintln!(
            "buildfit: protected outputs retained; {} inspection issue(s); receipt {}",
            receipt.errors.len(),
            path.display()
        );
    }
    Ok(Some(receipt))
}

fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    fs::write(&temp, serde_json::to_vec_pretty(value)?)?;
    crate::platform::replace_file(&temp, path)?;
    Ok(())
}

#[cfg(unix)]
pub fn unlink_verified(c: &Candidate) -> Result<()> {
    use std::{
        ffi::CString,
        fs::File,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        },
    };
    if c.identity.links != 1 {
        bail!("hard-linked output retained");
    }
    let parent = c.path.parent().context("output has no parent")?;
    // Open each component without following symlinks. Unlink only the final verified name.
    let mut dir = File::open("/")?;
    for component in parent.components() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        let name = CString::new(name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        dir = unsafe { File::from_raw_fd(fd) };
    }
    let leaf = CString::new(c.path.file_name().context("output has no name")?.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    if u128::from(m.ino()) != c.identity.inode
        || m.dev() != c.identity.device
        || m.len() != c.identity.size
        || m.mtime() != c.identity.mtime
        || m.mtime_nsec() != c.identity.mtime_ns
        || m.nlink() != 1
        || Identity::read(&c.path)? != c.identity
    {
        bail!("output changed before unlink");
    }
    if unsafe { libc::unlinkat(dir.as_raw_fd(), leaf.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(windows)]
pub use crate::windows::file::{available, unlink_verified};
