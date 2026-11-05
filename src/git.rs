use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

pub fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("git")
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()?;
    if !out.status.success() {
        bail!(
            "Git inspection failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(out.stdout)
}

pub fn text(root: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git(root, args)?)?.trim().to_owned())
}

pub fn worktrees(root: &Path) -> Result<Vec<PathBuf>> {
    let raw = git(root, &["worktree", "list", "--porcelain", "-z"])?;
    raw.split(|x| *x == 0)
        .filter_map(|s| s.strip_prefix(b"worktree "))
        .map(|s| {
            let path = PathBuf::from(crate::platform::os_from_git(s)?);
            Ok(path.canonicalize().unwrap_or(path))
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceGuard {
    pub root: PathBuf,
    pub head: String,
    pub branch: String,
    pub git_dir: String,
    pub status: String,
    pub index: String,
    pub hashes: BTreeMap<PathBuf, String>,
}

fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

pub(crate) fn hash_source_file(path: &Path, remaining: &mut u64) -> Result<String> {
    let mut file = fs::File::open(path)?;
    if file.metadata()?.len() > *remaining {
        bail!("source hash inspection budget exceeded; output retained");
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        if n as u64 > *remaining {
            bail!("source grew beyond hash inspection budget; output retained");
        }
        *remaining -= n as u64;
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

impl SourceGuard {
    pub fn capture(root: &Path, target: &Path) -> Result<Self> {
        if fs::canonicalize(root)? != root {
            bail!("source root is not canonical");
        }
        if !root.join("Cargo.toml").is_file() || !root.join("Cargo.lock").is_file() {
            bail!("source manifest and lockfile are required");
        }
        if !worktrees(root)?.iter().any(|p| p == root) {
            bail!("unregistered source worktree");
        }
        let mut hashes = BTreeMap::new();
        let mut remaining_hash_bytes = 1u64 << 30;
        for raw in git(
            root,
            &[
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
        )?
        .split(|b| *b == 0)
        {
            if raw.is_empty() {
                continue;
            }
            let relative = PathBuf::from(crate::platform::os_from_git(raw)?);
            if relative.is_absolute()
                || relative
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                bail!("unsafe source path");
            }
            let path = root.join(&relative);
            if path.starts_with(target) {
                bail!("compiler output contains Git-visible material");
            }
            let value = match fs::symlink_metadata(&path) {
                Ok(m) if crate::platform::metadata_is_link(&m) => {
                    format!("link:{}", fs::read_link(&path)?.display())
                }
                Ok(m) if m.is_file() => hash_source_file(&path, &mut remaining_hash_bytes)
                    .with_context(|| format!("hash source {}", path.display()))?,
                Ok(_) => bail!(
                    "unsupported source entry (including submodules): {}",
                    path.display()
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => "missing".into(),
                Err(e) => return Err(e.into()),
            };
            hashes.insert(relative, value);
        }
        // Ignored reconstruction inputs must still remain stable.
        for name in [
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain",
            "rust-toolchain.toml",
            ".cargo/config",
            ".cargo/config.toml",
        ] {
            let p = root.join(name);
            if p.is_file() {
                hashes.insert(
                    PathBuf::from(name),
                    hash_source_file(&p, &mut remaining_hash_bytes)?,
                );
            }
        }
        Ok(Self {
            root: root.to_owned(),
            head: text(root, &["rev-parse", "HEAD"])?,
            branch: text(root, &["symbolic-ref", "--quiet", "--short", "HEAD"]).unwrap_or_default(),
            git_dir: text(root, &["rev-parse", "--absolute-git-dir"])?,
            status: digest(&git(
                root,
                &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
            )?),
            index: digest(&git(root, &["ls-files", "--stage", "-z"])?),
            hashes,
        })
    }
}
