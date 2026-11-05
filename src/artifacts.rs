use crate::{config::Config, git};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub device: u64,
    pub inode: u128,
    pub size: u64,
    pub allocated: u64,
    pub mtime: i64,
    pub mtime_ns: i64,
    pub links: u64,
}
impl Identity {
    pub fn read(path: &Path) -> Result<Self> {
        let m = crate::platform::file_info(path)?;
        if !m.regular || m.directory || m.reparse {
            bail!("not a regular output");
        }

        Ok(Self {
            device: m.device,
            inode: m.inode,
            size: m.size,
            allocated: m.allocated,
            mtime: m.mtime,
            mtime_ns: m.mtime_ns,
            links: m.links,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub path: PathBuf,
    pub target: PathBuf,
    pub source: PathBuf,
    pub profile: PathBuf,
    pub fingerprint: PathBuf,
    pub fingerprint_sha256: String,
    pub key: String,
    pub identity: Identity,
    pub last_used: u64,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Pool {
    pub targets: Vec<PathBuf>,
    pub sources: BTreeMap<PathBuf, PathBuf>,
    pub bytes: u64,
    pub candidates: Vec<Candidate>,
    pub retained_latest: usize,
    pub skips: BTreeMap<String, usize>,
}

pub fn metadata(cfg: &Config, manifest: Option<&Path>, args: &[String]) -> Result<Value> {
    if flag(args, "--config").is_some() {
        bail!("explicit Cargo --config requires an explicitly qualified output layout");
    }
    let mut c = Command::new(&cfg.real_cargo);
    if let Some(t) = args.first().filter(|v| v.starts_with('+')) {
        c.arg(t);
    }
    c.args([
        "metadata",
        "--format-version",
        "1",
        "--no-deps",
        "--locked",
        "--offline",
    ]);
    if let Some(p) = manifest {
        c.arg("--manifest-path").arg(p);
    } else if let Some(p) = flag(args, "--manifest-path") {
        c.arg("--manifest-path").arg(p);
    }
    if let Some(p) = flag(args, "--target-dir") {
        c.env("CARGO_TARGET_DIR", p);
    }
    let out = c.output()?;
    if !out.status.success() {
        bail!("Cargo metadata unavailable (locked/offline); no output removed");
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}
pub fn flag(args: &[String], name: &str) -> Option<String> {
    let end = args.iter().position(|a| a == "--").unwrap_or(args.len());
    for (i, arg) in args[..end].iter().enumerate() {
        if arg == name {
            return args.get(i + 1).cloned();
        }
        if let Some(value) = arg.strip_prefix(&format!("{name}=")) {
            return Some(value.to_owned());
        }
    }
    None
}
pub fn discover(cfg: &Config, _args: &[String], first: &Value) -> Result<Vec<(PathBuf, PathBuf)>> {
    let source = PathBuf::from(
        first["workspace_root"]
            .as_str()
            .context("workspace root missing")?,
    )
    .canonicalize()?;
    let git_root =
        PathBuf::from(git::text(&source, &["rev-parse", "--show-toplevel"])?).canonicalize()?;
    let relative = source.strip_prefix(&git_root)?;
    let mut result = vec![];
    let worktrees = if cfg.worktrees {
        git::worktrees(&git_root)?
    } else {
        vec![git_root.clone()]
    };
    for root in worktrees {
        let workspace = root.join(relative);
        let m = if workspace == source {
            first.clone()
        } else {
            if !workspace.join("Cargo.toml").is_file() || !workspace.join("Cargo.lock").is_file() {
                continue;
            }
            // Do not ask Cargo to inspect unapproved checkouts.
            if !cfg.allowed_roots.is_empty()
                && !cfg.allowed_roots.iter().any(|p| workspace.starts_with(p))
            {
                continue;
            }
            match metadata(cfg, Some(&workspace.join("Cargo.toml")), &[]) {
                Ok(m) => m,
                Err(_) => continue,
            }
        };
        let target = PathBuf::from(
            m["target_directory"]
                .as_str()
                .context("target directory missing")?,
        );
        if !target.exists() {
            continue;
        }
        #[cfg(windows)]
        crate::windows::file::reject_reparse_components(&target)?;
        #[cfg(windows)]
        let target = target.canonicalize()?;
        if target.canonicalize()? != target || !cfg.permitted(&target) {
            continue;
        }
        if crate::platform::file_info(&target)?.device
            != crate::platform::file_info(&source)?.device
        {
            continue;
        }
        if !target.starts_with(&workspace)
            || target == workspace
            || !workspace.join("Cargo.lock").is_file()
        {
            continue;
        }
        // Dedicated target/build-dir layouts need a separately qualified policy.
        if let Some(build) = m["build_directory"].as_str()
            && Path::new(build).canonicalize().ok().as_ref() != Some(&target)
        {
            continue;
        }
        if result
            .iter()
            .any(|(t, _): &(PathBuf, PathBuf)| target.starts_with(t) || t.starts_with(&target))
        {
            continue;
        }
        result.push((target, workspace.canonicalize()?));
    }
    result.sort_by_key(|(_, root)| root != &source);
    if result.len() > 64 {
        bail!("worktree inspection limit reached");
    }
    Ok(result)
}

pub fn measure(cfg: &Config, roots: &[(PathBuf, PathBuf)]) -> Result<Pool> {
    let mut seen = BTreeSet::new();
    let mut remaining = cfg.max_scan_files;
    let mut bytes = 0;
    for (target, _) in roots {
        bytes += size(target, &mut seen, &mut remaining)?;
    }
    let mut all = vec![];
    let mut skips = BTreeMap::new();
    for (target, source) in roots {
        let mut profiles = vec![];
        profiles_in(target, 0, &mut profiles)?;
        for profile in profiles {
            let deps = profile.join("deps");
            if !deps.is_dir() {
                continue;
            }
            let mut by_hash: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
            for p in fs::read_dir(profile.join(".fingerprint"))? {
                let p = p?.path();
                if let Some((_, hash)) = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.rsplit_once('-'))
                    && is_hash(hash)
                    && !crate::platform::metadata_is_link(&fs::symlink_metadata(&p)?)
                {
                    by_hash.entry(hash.to_owned()).or_default().push(p);
                }
            }
            for p in fs::read_dir(&deps)? {
                let p = p?.path();
                match candidate(&p, target, source, &profile, &by_hash) {
                    Ok(Some(c)) => all.push(c),
                    Ok(None) => {}
                    Err(_) => {
                        *skips
                            .entry("unrecognized, linked or changing output".to_owned())
                            .or_default() += 1
                    }
                }
            }
        }
    }
    let (candidates, retained_latest) = superseded(all);
    Ok(Pool {
        targets: roots.iter().map(|x| x.0.clone()).collect(),
        sources: roots.iter().cloned().collect(),
        bytes,
        candidates,
        retained_latest,
        skips,
    })
}

fn is_hash(hash: &str) -> bool {
    hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(crate) fn read_fingerprint(path: &Path) -> Result<Vec<u8>> {
    let file = crate::platform::open_read(path)?;
    if file.metadata()?.len() > 1024 * 1024 {
        bail!("oversized Cargo fingerprint retained");
    }
    let mut data = vec![];
    file.take(1024 * 1024 + 1).read_to_end(&mut data)?;
    if data.len() > 1024 * 1024 {
        bail!("growing Cargo fingerprint retained");
    }
    Ok(data)
}
fn candidate(
    path: &Path,
    target: &Path,
    source: &Path,
    profile: &Path,
    hashes: &BTreeMap<String, Vec<PathBuf>>,
) -> Result<Option<Candidate>> {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Ok(None);
    };
    let name = if cfg!(windows) {
        name.strip_suffix(".exe").unwrap_or(name)
    } else {
        name
    };
    let Some((_, hash)) = name.rsplit_once('-') else {
        return Ok(None);
    };
    if !is_hash(hash) {
        return Ok(None);
    }
    let Some(dirs) = hashes.get(hash) else {
        return Ok(None);
    };
    if dirs.len() != 1 {
        bail!("ambiguous Cargo fingerprint");
    }
    let mut jsons = vec![];
    for p in fs::read_dir(&dirs[0])? {
        let p = p?.path();
        if p.file_name()
            .and_then(|x| x.to_str())
            .is_some_and(|n| n.starts_with("test-") && n.ends_with(".json"))
        {
            jsons.push(p);
        }
    }
    if jsons.len() != 1 {
        return Ok(None);
    }
    let identity = Identity::read(path)?;
    if identity.links != 1 || identity.allocated == 0 {
        bail!("linked or empty artifact");
    }
    if identity.device != crate::platform::file_info(target)?.device {
        bail!("cross-device output retained");
    }
    let file_meta = crate::platform::file_info(path)?;
    let fingerprint_meta = crate::platform::file_info(&jsons[0])?;
    if fingerprint_meta.directory || fingerprint_meta.reparse || fingerprint_meta.links != 1 {
        bail!("ambiguous fingerprint");
    }
    let last_used = [
        file_meta.mtime,
        file_meta.atime,
        fingerprint_meta.mtime,
        fingerprint_meta.atime,
    ]
    .into_iter()
    .max()
    .unwrap()
    .max(0) as u64;
    let mut executable = crate::platform::open_read(path)?;
    crate::executable::verify(&mut executable)?;
    let data = read_fingerprint(&jsons[0])?;
    let value: Value = serde_json::from_slice(&data)?;
    for name in ["features", "target", "profile", "rustc"] {
        if value.get(name).is_none() {
            bail!("incomplete Cargo identity");
        }
    }
    let package = dirs[0]
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap()
        .rsplit_once('-')
        .unwrap()
        .0;
    let fields: Vec<_> = [
        "features",
        "declared_features",
        "target",
        "profile",
        "rustc",
        "rustflags",
        "config",
        "compile_kind",
    ]
    .iter()
    .map(|k| (*k, value.get(*k).cloned()))
    .collect();
    // Keep a newest executable per source checkout AND full build configuration.
    let key = format!(
        "{}:{package}:{}:{}",
        source.display(),
        jsons[0].file_name().unwrap().to_string_lossy(),
        serde_json::to_string(&fields)?
    );
    use sha2::{Digest, Sha256};
    Ok(Some(Candidate {
        path: path.to_owned(),
        target: target.to_owned(),
        source: source.to_owned(),
        profile: profile.to_owned(),
        fingerprint: jsons[0].clone(),
        fingerprint_sha256: format!("{:x}", Sha256::digest(&data)),
        key,
        identity,
        last_used,
    }))
}

pub fn superseded(all: Vec<Candidate>) -> (Vec<Candidate>, usize) {
    let mut grouped: BTreeMap<String, Vec<Candidate>> = BTreeMap::new();
    for c in all {
        grouped.entry(c.key.clone()).or_default().push(c);
    }
    let retained = grouped.len();
    let mut candidates = vec![];
    for (_, mut group) in grouped {
        group.sort_by_key(|c| (c.identity.mtime, c.identity.mtime_ns, c.path.clone()));
        group.pop();
        candidates.extend(group);
    }
    candidates.sort_by_key(|c| (c.identity.mtime, c.identity.mtime_ns));
    (candidates, retained)
}

fn size(path: &Path, seen: &mut BTreeSet<(u64, u128)>, remaining: &mut usize) -> Result<u64> {
    if *remaining == 0 {
        bail!("bounded output inventory exceeded");
    }
    *remaining -= 1;
    let m = crate::platform::file_info(path)?;
    if !seen.insert((m.device, m.inode)) {
        return Ok(0);
    }
    let mut n = m.allocated;
    if m.directory && !m.reparse {
        for p in fs::read_dir(path)? {
            n += size(&p?.path(), seen, remaining)?;
        }
    }
    Ok(n)
}
fn profiles_in(path: &Path, depth: usize, profiles: &mut Vec<PathBuf>) -> Result<()> {
    if depth > 4 {
        return Ok(());
    }
    if path.join(".fingerprint").is_dir() {
        profiles.push(path.to_owned());
        return Ok(());
    }
    for p in fs::read_dir(path)? {
        let p = p?.path();
        let m = fs::symlink_metadata(&p)?;
        if m.is_dir() && !crate::platform::metadata_is_link(&m) {
            profiles_in(&p, depth + 1, profiles)?;
        }
    }
    Ok(())
}
