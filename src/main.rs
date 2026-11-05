#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!("cargo-buildfit supports Linux, macOS and Windows");

mod artifacts;
mod config;
mod consumers;
mod executable;
mod git;
mod lease;
mod locks;
mod pipeline;
mod platform;
#[cfg(target_os = "macos")]
mod plist_macos;
#[cfg(windows)]
mod windows;

use anyhow::{Context, Result, bail};
use config::{Config, GIB};
use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    match entry() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("buildfit: {error:#}");
            std::process::exit(75);
        }
    }
}

fn entry() -> Result<i32> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let program = env::args_os().next().map(PathBuf::from).unwrap_or_default();
    let proxy = program
        .file_name()
        .is_some_and(|n| n == "cargo" || n == "cargo.exe");
    if args.first().is_some_and(|a| a == "internal-probe") {
        if args.len() != 3 {
            bail!("invalid internal probe invocation");
        }
        let roots: Vec<PathBuf> = serde_json::from_str(&args[1])?;
        if roots.len() > 64 || roots.iter().any(|r| !r.is_absolute()) {
            bail!("invalid probe scope");
        }
        let snapshot = consumers::inspect(&roots, args[2].parse()?);
        println!("{}", serde_json::to_string(&snapshot)?);
        return Ok(0);
    }
    if !proxy && args.first().is_some_and(|a| a == "buildfit") {
        args.remove(0);
    }
    if !proxy && (args.is_empty() || ["help", "--help", "-h"].contains(&args[0].as_str())) {
        println!(
            "cargo-buildfit: automatic Cargo storage preflight and postflight\n\nInstall its cargo launcher earlier on PATH to keep using cargo build/test/check.\n\nCommands:\n  status [--manifest-path PATH]  inspect candidates without deleting\n  clean [--manifest-path PATH]   perform guarded maintenance\n  run -- CARGO_ARGS             run a complete Cargo pipeline\n  reserve TARGET SECONDS REASON reserve imminent output (maximum one day)\n  config                        show effective global configuration\n\nProject policy: [workspace.metadata.buildfit] or [package.metadata.buildfit]."
        );
        return Ok(0);
    }
    let mut cfg = Config::load()?;
    let cargo_path = fs::canonicalize(&cfg.real_cargo)?;
    if cargo_path == env::current_exe()?.canonicalize()? {
        bail!("real_cargo resolves to buildfit (recursive launcher)");
    }
    if !proxy && args[0] == "config" {
        println!("{}", toml::to_string_pretty(&cfg)?);
        return Ok(0);
    }
    if !proxy && args[0] == "reserve" {
        if args.len() != 4 {
            bail!("reserve requires TARGET SECONDS REASON");
        }
        let target = PathBuf::from(&args[1]).canonicalize()?;
        if !cfg.permitted(&target) {
            bail!("reservation target outside allowed roots");
        }
        println!(
            "{}",
            lease::reserve(&cfg.state_dir, target, args[2].parse()?, args[3].clone())?.display()
        );
        return Ok(0);
    }
    let diagnostic = !proxy && ["status", "clean"].contains(&args[0].as_str());
    let action = if diagnostic {
        args.remove(0)
    } else {
        "build".into()
    };
    if !proxy && !diagnostic {
        if args.first().is_none_or(|s| s != "run") {
            bail!("unknown command; use run -- CARGO_ARGS");
        }
        args.remove(0);
        if args.first().is_some_and(|s| s == "--") {
            args.remove(0);
        }
    }
    if !diagnostic && !build_command(&args) {
        return delegate(&cfg, &args, false);
    }
    // Configuration failures must not silently weaken a requested project policy.
    apply_manifest_policy(&mut cfg, &args)?;
    let cwd = env::current_dir()?;
    let mut build_volume = artifacts::flag(&args, "--target-dir")
        .map(PathBuf::from)
        .or_else(|| env::var_os("CARGO_TARGET_DIR").map(PathBuf::from))
        .unwrap_or_else(|| cwd.clone());
    if !build_volume.is_absolute() {
        build_volume = cwd.join(build_volume);
    }
    let roots = match artifacts::metadata(&cfg, None, &args) {
        Ok(meta) => {
            if let Some(path) = meta["target_directory"].as_str() {
                build_volume = PathBuf::from(path);
            }
            cfg.apply_project(&meta)?;
            match artifacts::discover(&cfg, &args, &meta) {
                Ok(roots) => roots,
                Err(error) => {
                    eprintln!("buildfit: output discovery deferred: {error}");
                    vec![]
                }
            }
        }
        Err(error) => {
            eprintln!("buildfit: {error}");
            vec![]
        }
    };
    fs::create_dir_all(&cfg.state_dir)?;
    if diagnostic {
        if let Some(receipt) = pipeline::maintain(&cfg, &roots, &action, action == "status", true)?
        {
            println!("{}", serde_json::to_string_pretty(&receipt)?);
            if !receipt.errors.is_empty() {
                return Ok(75);
            }
        } else {
            println!("No qualified Cargo output roots available, or maintenance is busy.");
        }
        return Ok(0);
    }
    let owned_lease =
        lease::OwnedLease::new(&cfg.state_dir, roots.iter().map(|r| r.0.clone()).collect())?;
    if let Err(error) = pipeline::maintain(&cfg, &roots, "preflight", false, false) {
        eprintln!("buildfit: maintenance skipped safely: {error:#}");
    }
    while !build_volume.exists() {
        if !build_volume.pop() {
            bail!("build volume unavailable");
        }
    }
    let admission_lock = locks::Lock::acquire(&cfg.state_dir.join("admission.lock"), true)
        .context("another build is being admitted; retry after its short admission checkpoint")?;
    let free = pipeline::available(&build_volume)?;
    let reserved = lease::reserved_bytes(&cfg.state_dir)?;
    let inherited = lease::ancestor_reserved_bytes(&cfg.state_dir)?;
    let own_headroom = cfg.build_headroom_gib.saturating_mul(GIB);
    pipeline::admit(&cfg, free.saturating_sub(reserved.saturating_sub(inherited)).saturating_sub(own_headroom))
        .with_context(||format!("{:.2} GiB physically free, {:.2} GiB reserved by active pipelines, {} GiB requested build headroom",free as f64/GIB as f64,reserved as f64/GIB as f64,cfg.build_headroom_gib))?;
    owned_lease.admit(own_headroom)?;
    drop(admission_lock);
    if free < cfg.reserve_gib.saturating_mul(GIB) {
        eprintln!(
            "buildfit: {:.2} GiB free (cleanup target {} GiB, admission floor {} GiB); retained consumers take priority",
            free as f64 / GIB as f64,
            cfg.reserve_gib,
            cfg.stop_below_gib
        );
    }
    let code = delegate(&cfg, &args, cfg.line_tables_only)?;
    if let Err(error) = pipeline::maintain(&cfg, &roots, "postflight", false, false) {
        eprintln!("buildfit: postflight deferred safely: {error:#}");
    }
    Ok(code)
}

fn delegate(cfg: &Config, args: &[String], line_tables: bool) -> Result<i32> {
    let mut command = Command::new(&cfg.real_cargo);
    command.args(args);
    if line_tables {
        for name in ["CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG"] {
            if env::var_os(name).is_none() {
                command.env(name, "line-tables-only");
            }
        }
    }
    let status = command.status()?;
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        Ok(status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)))
    }
    #[cfg(windows)]
    {
        Ok(status.code().unwrap_or(1))
    }
}

fn build_command(args: &[String]) -> bool {
    let mut skip = false;
    for arg in args {
        if skip {
            skip = false;
            continue;
        }
        if ["--color", "--config", "-Z"].contains(&arg.as_str()) {
            skip = true;
            continue;
        }
        if arg.starts_with('-') || arg.starts_with('+') {
            continue;
        }
        return ![
            "metadata",
            "locate-project",
            "pkgid",
            "read-manifest",
            "tree",
            "fetch",
            "update",
            "generate-lockfile",
            "search",
            "info",
            "version",
            "help",
            "login",
            "logout",
            "owner",
            "clean",
            "new",
            "init",
            "uninstall",
            "buildfit",
        ]
        .contains(&arg.as_str());
    }
    false
}

fn apply_manifest_policy(cfg: &mut Config, args: &[String]) -> Result<()> {
    let manifest = if let Some(p) = artifacts::flag(args, "--manifest-path") {
        PathBuf::from(p)
    } else {
        let mut dir = env::current_dir()?;
        loop {
            let candidate = dir.join("Cargo.toml");
            if candidate.is_file() {
                break candidate;
            }
            if !dir.pop() {
                return Ok(());
            }
        }
    };
    let manifest = manifest.canonicalize()?;
    // Include enclosing workspace metadata for first builds without Cargo.lock.
    let mut manifests = vec![manifest.clone()];
    for parent in manifest.parent().unwrap().ancestors().skip(1) {
        let p = parent.join("Cargo.toml");
        if p.is_file() {
            manifests.push(p);
        }
        if parent.join(".git").exists() {
            break;
        }
    }
    for path in manifests.iter().rev() {
        let document: toml::Value = toml::from_str(&fs::read_to_string(path)?)?;
        let workspace = document
            .get("workspace")
            .and_then(|w| w.get("metadata"))
            .cloned()
            .unwrap_or(toml::Value::Table(Default::default()));
        let package = document
            .get("package")
            .and_then(|w| w.get("metadata"))
            .cloned()
            .unwrap_or(toml::Value::Table(Default::default()));
        let root = path.parent().unwrap().to_string_lossy();
        cfg.apply_project(&serde_json::json!({"workspace_root":root,"metadata":workspace,"packages":[{"manifest_path":path,"metadata":package}]}))?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
#[cfg(all(test, windows))]
#[path = "tests_windows.rs"]
mod tests;
