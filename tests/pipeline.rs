#![cfg(unix)]
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture {
    root: PathBuf,
    config: PathBuf,
    cargo: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "cargo-guard-integration-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        let root = root.canonicalize().unwrap();
        let cargo = PathBuf::from(std::env::var_os("CARGO").unwrap());
        let config = root.with_extension("toml");
        let settings = format!(
            "real_cargo = {:?}\nstate_dir = {:?}\nreceipt_dir = {:?}\nmaintenance_lock = {:?}\nallowed_roots = [{:?}]\nreserve_gib = 0\nstop_below_gib = 0\nbuild_headroom_gib = 0\nmin_age_seconds = 0\ncheck_interval_seconds = 0\nmax_cleanup_seconds = 60\n",
            cargo,
            root.join("state"),
            root.join("receipts"),
            root.join("maintenance.lock"),
            root
        );
        fs::write(&config, settings).unwrap();
        fs::write(
            root.join(".gitignore"),
            "/target/\n/state/\n/receipts/\n/maintenance.lock\n",
        )
        .unwrap();
        fs::write(
            root.join("src/lib.rs"),
            "pub fn answer()->u32{42}\n#[test] fn answer_is_correct(){assert_eq!(answer(),42)}\n",
        )
        .unwrap();
        let f = Self {
            root,
            config,
            cargo,
        };
        f.manifest("0.1.0", 0, 0);
        f.git(&["init", "--quiet"]);
        f.git(&["add", "."]);
        f.git(&[
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "test: initialize fixture",
        ]);
        f
    }
    fn manifest(&self, version: &str, reserve: u64, stop: u64) {
        fs::write(self.root.join("Cargo.toml"),format!("[package]\nname='guard-fixture'\nversion='{version}'\nedition='2024'\n[package.metadata.buildfit]\nreserve-gib={reserve}\nstop-below-gib={stop}\nmin-age-seconds=0\ncheck-interval-seconds=0\nmax-cleanup-seconds=60\nline-tables-only=true\n")).unwrap();
    }
    fn git(&self, args: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&self.root)
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    fn command(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_cargo-buildfit"))
            .current_dir(&self.root)
            .env("CARGO_BUILDFIT_CONFIG", &self.config)
            .env_remove("CARGO_PROFILE_DEV_DEBUG")
            .env_remove("CARGO_PROFILE_TEST_DEBUG")
            .args(args)
            .output()
            .unwrap()
    }
    fn raw(&self, args: &[&str]) -> Output {
        Command::new(&self.cargo)
            .current_dir(&self.root)
            .args(args)
            .output()
            .unwrap()
    }
    fn executables(&self) -> Vec<PathBuf> {
        let mut paths = vec![];
        for p in fs::read_dir(self.root.join("target/debug/deps")).unwrap() {
            let p = p.unwrap().path();
            if p.extension().is_none() && p.is_file() {
                paths.push(p);
            }
        }
        paths.sort();
        paths
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_file(&self.config);
    }
}
fn success(out: &Output) {
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn first_build_reads_project_policy_and_sets_line_tables() {
    let f = Fixture::new();
    let out = f.command(&["run", "--", "build", "--offline", "--verbose"]);
    success(&out);
    let log = String::from_utf8_lossy(&out.stderr);
    assert!(log.contains("debuginfo=line-tables-only"), "{log}");
    assert!(f.root.join("target/debug").is_dir());
    assert_eq!(
        fs::read_dir(f.root.join("state/leases")).unwrap().count(),
        0
    );
}
#[test]
fn cargo_failure_code_and_diagnostics_are_preserved() {
    let f = Fixture::new();
    fs::write(
        f.root.join("src/lib.rs"),
        "this is intentionally invalid Rust",
    )
    .unwrap();
    let out = f.command(&["run", "--", "build", "--offline"]);
    assert_eq!(out.status.code(), Some(101));
    assert!(String::from_utf8_lossy(&out.stderr).contains("error:"));
}
#[test]
fn project_floor_blocks_before_compilation() {
    let f = Fixture::new();
    f.manifest("0.1.0", 1_000_000, 1_000_000);
    let out = f.command(&["run", "--", "build", "--offline"]);
    assert_eq!(out.status.code(), Some(75));
    assert!(!f.root.join("target").exists());
    assert!(String::from_utf8_lossy(&out.stderr).contains("No build started"));
}
#[test]
fn invalid_project_configuration_is_not_silently_ignored() {
    let f = Fixture::new();
    let p = f.root.join("Cargo.toml");
    let mut s = fs::read_to_string(&p).unwrap();
    s.push_str("unrecognized-setting=true\n");
    fs::write(p, s).unwrap();
    let out = f.command(&["run", "--", "build", "--offline"]);
    assert_eq!(out.status.code(), Some(75));
    assert!(!f.root.join("target").exists());
}
#[test]
fn normal_cargo_launcher_needs_no_extra_subcommand() {
    let f = Fixture::new();
    let bin = f.root.join("bin");
    fs::create_dir(&bin).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_cargo-buildfit"), bin.join("cargo")).unwrap();
    let out = Command::new(bin.join("cargo"))
        .current_dir(&f.root)
        .env("CARGO_BUILDFIT_CONFIG", &f.config)
        .args(["build", "--offline"])
        .output()
        .unwrap();
    success(&out);
    assert!(f.root.join("target/debug").exists());
}
#[test]
fn explicit_full_debug_override_is_preserved() {
    let f = Fixture::new();
    let out = Command::new(env!("CARGO_BIN_EXE_cargo-buildfit"))
        .current_dir(&f.root)
        .env("CARGO_BUILDFIT_CONFIG", &f.config)
        .env("CARGO_PROFILE_DEV_DEBUG", "full")
        .args(["run", "--", "build", "--offline", "--verbose"])
        .output()
        .unwrap();
    success(&out);
    assert!(String::from_utf8_lossy(&out.stderr).contains("debuginfo=2"));
}

#[test]
#[ignore = "requires passwordless sudo for all-user process visibility"]
fn completed_superseded_tests_are_removed_only_after_consumer_releases() {
    let f = Fixture::new();
    success(&f.raw(&["test", "--offline", "--no-run"]));
    let first = f.executables();
    assert_eq!(first.len(), 1);
    f.manifest("0.2.0", 0, 0);
    success(&f.raw(&["test", "--offline", "--no-run"]));
    let second = f.executables();
    assert_eq!(
        second.len(),
        2,
        "Cargo should retain different package versions"
    );
    fs::write(
        f.root.join("target/original-failure.txt"),
        "unique original failure",
    )
    .unwrap();
    f.manifest("0.2.0", 1_000_000, 0);
    let observation = f.command(&["status"]);
    success(&observation);
    assert!(first[0].exists(), "status cannot remove artifacts");
    assert!(
        !fs::read_dir(f.root.join("state")).unwrap().any(|p| p
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("pool-")),
        "status cannot write a maintenance throttle stamp"
    );
    let held = fs::File::open(&first[0]).unwrap();
    let out = f.command(&["clean"]);
    success(&out);
    assert!(first[0].exists(), "open descriptor must protect root");
    drop(held);
    // A memory mapping must remain visible after its original descriptor closes.
    use std::os::fd::AsRawFd;
    let mapped_file = fs::File::open(&first[0]).unwrap();
    let length = mapped_file.metadata().unwrap().len() as usize;
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            mapped_file.as_raw_fd(),
            0,
        )
    };
    assert_ne!(mapping, libc::MAP_FAILED);
    drop(mapped_file);
    let mapped_result = f.command(&["clean"]);
    let preserved = first[0].exists();
    assert_eq!(unsafe { libc::munmap(mapping, length) }, 0);
    success(&mapped_result);
    assert!(
        preserved,
        "mapped executable must survive after its descriptor closes"
    );
    let runtime_path = f.root.join("target/runtime-resource");
    fs::write(&runtime_path, "retained live runtime resource").unwrap();
    let _unrelated_runtime = fs::File::open(&runtime_path).unwrap();
    let before = f.raw(&[
        "metadata",
        "--format-version",
        "1",
        "--no-deps",
        "--offline",
    ]);
    success(&before);
    let out = f.command(&["clean"]);
    success(&out);
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["errors"], serde_json::json!([]), "{report}");
    assert!(
        !first[0].exists(),
        "superseded executable should be removed: {report}"
    );
    assert_eq!(f.executables().len(), 1);
    assert!(f.root.join("target/original-failure.txt").exists());
    assert!(runtime_path.exists());
    assert_eq!(report["source_preserved"], true);
}

#[test]
fn symlinked_target_is_never_qualified() {
    let f = Fixture::new();
    success(&f.raw(&["build", "--offline"]));
    fs::rename(f.root.join("target"), f.root.join("other-output")).unwrap();
    std::os::unix::fs::symlink("other-output", f.root.join("target")).unwrap();
    let out = f.command(&["status"]);
    success(&out);
    assert!(String::from_utf8_lossy(&out.stdout).contains("No qualified"));
    assert!(Path::new(&f.root.join("other-output")).exists());
}

#[test]
fn workspace_policy_applies_when_build_starts_in_member() {
    let f = Fixture::new();
    fs::create_dir_all(f.root.join("member/src")).unwrap();
    fs::write(
        f.root.join("member/Cargo.toml"),
        "[package]\nname='member'\nversion='0.1.0'\nedition='2024'\n",
    )
    .unwrap();
    fs::write(f.root.join("member/src/lib.rs"), "pub fn value()->u8{1}\n").unwrap();
    fs::write(f.root.join("Cargo.toml"),"[workspace]\nmembers=['member']\nresolver='3'\n[workspace.metadata.buildfit]\nreserve-gib=1000000\nstop-below-gib=1000000\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_cargo-buildfit"))
        .current_dir(f.root.join("member"))
        .env("CARGO_BUILDFIT_CONFIG", &f.config)
        .args(["run", "--", "build", "--offline"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(75));
    assert!(!f.root.join("target").exists());
}

#[test]
fn nested_cargo_pipeline_reuses_its_ancestors_admission_headroom() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    success(&f.raw(&["generate-lockfile", "--offline"]));
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(f.root.as_os_str().as_bytes()).unwrap();
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::statvfs(path.as_ptr(), &mut stat) }, 0);
    let free = stat.f_bavail as u64 * stat.f_frsize as u64;
    let headroom = (free / (1 << 30) * 6 / 10).max(1);
    f.manifest("0.1.0", 1, 1);
    let manifest = f.root.join("Cargo.toml");
    let mut text = fs::read_to_string(&manifest).unwrap();
    text.push_str(&format!("build-headroom-gib={headroom}\n"));
    fs::write(manifest, text).unwrap();
    let fake = f.root.join("fake-cargo");
    fs::write(&fake,format!("#!/bin/sh\ncase \"$1\" in\nmetadata) exec '{}' \"$@\";;\nbuild) exec cargo check --offline;;\ncheck) printf done > nested.done; exit 0;;\nesac\nexit 1\n",f.cargo.display())).unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    let mut cfg: toml::Value = toml::from_str(&fs::read_to_string(&f.config).unwrap()).unwrap();
    cfg["real_cargo"] = toml::Value::String(fake.to_string_lossy().into());
    fs::write(&f.config, toml::to_string(&cfg).unwrap()).unwrap();
    let bin = f.root.join("bin");
    fs::create_dir(&bin).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_cargo-buildfit"), bin.join("cargo")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_cargo-buildfit"))
        .current_dir(&f.root)
        .env("CARGO_BUILDFIT_CONFIG", &f.config)
        .env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        )
        .args(["run", "--", "build"])
        .output()
        .unwrap();
    success(&out);
    assert!(f.root.join("nested.done").is_file());
}
