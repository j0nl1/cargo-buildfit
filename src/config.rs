use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{env, path::PathBuf};

pub const GIB: u64 = 1 << 30;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub real_cargo: PathBuf,
    pub state_dir: PathBuf,
    pub maintenance_lock: PathBuf,
    pub allowed_roots: Vec<PathBuf>,
    pub pins: Vec<PathBuf>,
    pub quota_gib: u64,
    pub low_water_percent: u64,
    pub reserve_gib: u64,
    pub stop_below_gib: u64,
    pub build_headroom_gib: u64,
    pub min_age_seconds: u64,
    pub max_remove_gib: u64,
    pub max_scan_files: usize,
    pub check_interval_seconds: u64,
    pub max_cleanup_seconds: u64,
    pub worktrees: bool,
    pub line_tables_only: bool,
    pub privileged_probe: bool,
    pub receipt_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        #[cfg(unix)]
        let home = env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        #[cfg(windows)]
        let home = env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .unwrap_or_default();
        #[cfg(unix)]
        let state = home.join(".local/state/cargo-buildfit");
        #[cfg(windows)]
        let state = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData/Local"))
            .join("cargo-buildfit");
        Self {
            real_cargo: home.join(if cfg!(windows) {
                ".cargo/bin/cargo.exe"
            } else {
                ".cargo/bin/cargo"
            }),
            maintenance_lock: state.join("maintenance.lock"),
            receipt_dir: state.join("receipts"),
            state_dir: state,
            allowed_roots: vec![],
            pins: vec![],
            quota_gib: 250,
            low_water_percent: 80,
            reserve_gib: 150,
            stop_below_gib: 30,
            build_headroom_gib: 20,
            min_age_seconds: 3600,
            max_remove_gib: 40,
            max_scan_files: 2_000_000,
            check_interval_seconds: 300,
            max_cleanup_seconds: 30,
            worktrees: true,
            line_tables_only: true,
            privileged_probe: true,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = env::var_os("CARGO_BUILDFIT_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                env::var_os("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        #[cfg(unix)]
                        let base =
                            PathBuf::from(env::var_os("HOME").unwrap_or_default()).join(".config");
                        #[cfg(windows)]
                        let base = PathBuf::from(env::var_os("APPDATA").unwrap_or_default());
                        base
                    })
                    .join("cargo-buildfit/config.toml")
            });
        let mut value: Self = if path.exists() {
            toml::from_str(&std::fs::read_to_string(&path)?)
                .context("invalid buildfit configuration")?
        } else {
            Self::default()
        };
        if value.stop_below_gib > value.reserve_gib
            || value.low_water_percent == 0
            || value.low_water_percent > 100
            || value.quota_gib == 0
            || value.max_scan_files == 0
            || value.max_remove_gib == 0
        {
            bail!("invalid thresholds or scan limits");
        }
        for p in [
            &value.real_cargo,
            &value.state_dir,
            &value.maintenance_lock,
            &value.receipt_dir,
        ] {
            if !p.is_absolute() {
                bail!("configuration paths must be absolute");
            }
        }
        if value
            .allowed_roots
            .iter()
            .chain(&value.pins)
            .any(|p| !p.is_absolute())
        {
            bail!("allowed roots and pins must be absolute");
        }
        for pin in value.pins.iter_mut().chain(value.allowed_roots.iter_mut()) {
            let mut ancestor = pin.clone();
            let mut tail = Vec::new();
            while !ancestor.exists() {
                tail.push(
                    ancestor
                        .file_name()
                        .ok_or_else(|| anyhow::anyhow!("invalid pin"))?
                        .to_owned(),
                );
                if !ancestor.pop() {
                    bail!("pin ancestor unavailable");
                }
            }
            let mut resolved = ancestor.canonicalize()?;
            for component in tail.into_iter().rev() {
                resolved.push(component);
            }
            *pin = resolved;
        }
        Ok(value)
    }

    pub fn permitted(&self, path: &std::path::Path) -> bool {
        self.allowed_roots.is_empty()
            || self
                .allowed_roots
                .iter()
                .any(|p| path.starts_with(p) && path != p)
    }

    pub fn apply_project(&mut self, metadata: &serde_json::Value) -> Result<()> {
        let workspace = metadata.get("metadata").map(policy).transpose()?.flatten();
        if let Some(value) = workspace {
            self.apply_values(value)?;
        }
        let root = metadata["workspace_root"].as_str().unwrap_or("");
        if let Some(packages) = metadata["packages"].as_array() {
            for package in packages {
                if package["manifest_path"].as_str().is_some_and(|s| {
                    std::path::Path::new(s).parent() == Some(std::path::Path::new(root))
                }) && let Some(value) =
                    package.get("metadata").map(policy).transpose()?.flatten()
                {
                    self.apply_values(value)?;
                }
            }
        }
        if self.stop_below_gib > self.reserve_gib
            || !(1..=100).contains(&self.low_water_percent)
            || self.quota_gib == 0
            || self.max_cleanup_seconds == 0
            || self.max_scan_files == 0
            || self.max_remove_gib == 0
        {
            bail!("invalid project buildfit policy");
        }
        Ok(())
    }

    fn apply_values(&mut self, value: &serde_json::Value) -> Result<()> {
        let values: ProjectPolicy = serde_json::from_value(value.clone())
            .context("invalid Cargo metadata.buildfit policy")?;
        macro_rules! assign { ($($key:ident),*) => { $(if let Some(v) = values.$key { self.$key = v; })* }; }
        assign!(
            quota_gib,
            low_water_percent,
            reserve_gib,
            stop_below_gib,
            build_headroom_gib,
            min_age_seconds,
            max_remove_gib,
            max_scan_files,
            check_interval_seconds,
            max_cleanup_seconds,
            line_tables_only,
            worktrees
        );
        Ok(())
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
struct ProjectPolicy {
    quota_gib: Option<u64>,
    low_water_percent: Option<u64>,
    reserve_gib: Option<u64>,
    stop_below_gib: Option<u64>,
    build_headroom_gib: Option<u64>,
    min_age_seconds: Option<u64>,
    max_remove_gib: Option<u64>,
    max_scan_files: Option<usize>,
    check_interval_seconds: Option<u64>,
    max_cleanup_seconds: Option<u64>,
    line_tables_only: Option<bool>,
    worktrees: Option<bool>,
}

fn policy(metadata: &serde_json::Value) -> Result<Option<&serde_json::Value>> {
    Ok(metadata.get("buildfit"))
}
