use super::*;
use std::path::Path;
use std::{
    fs,
    os::unix::fs::symlink,
    time::{SystemTime, UNIX_EPOCH},
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = env::temp_dir().join(format!(
            "cargo-buildfit-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&p).unwrap();
        Self(p.canonicalize().unwrap())
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn config(temp: &Temp) -> Config {
    Config {
        state_dir: temp.0.join("state"),
        receipt_dir: temp.0.join("receipts"),
        maintenance_lock: temp.0.join("lock"),
        allowed_roots: vec![temp.0.clone()],
        ..Config::default()
    }
}
fn candidate(path: &Path, key: &str, mtime: i64) -> artifacts::Candidate {
    fs::write(path, b"disposable test output").unwrap();
    let mut identity = artifacts::Identity::read(path).unwrap();
    identity.mtime = mtime;
    artifacts::Candidate {
        path: path.into(),
        target: path.parent().unwrap().into(),
        source: path.parent().unwrap().into(),
        profile: path.parent().unwrap().into(),
        fingerprint: path.with_extension("json"),
        fingerprint_sha256: String::new(),
        key: key.into(),
        identity,
        last_used: mtime.max(0) as u64,
    }
}

#[test]
fn newest_per_configuration_and_checkout_is_retained() {
    let t = Temp::new();
    let a = candidate(&t.0.join("a"), "source-a:features-a", 1);
    let b = candidate(&t.0.join("b"), "source-a:features-a", 2);
    let c = candidate(&t.0.join("c"), "source-a:features-b", 1);
    let d = candidate(&t.0.join("d"), "source-b:features-a", 1);
    let (old, retained) = artifacts::superseded(vec![a, b, c, d]);
    assert_eq!(retained, 3);
    assert_eq!(old.len(), 1);
    assert_eq!(old[0].path, t.0.join("a"));
}
#[test]
fn unknown_consumer_visibility_protects_every_root() {
    let s = consumers::Snapshot {
        incomplete: vec!["permission denied".into()],
        ..Default::default()
    };
    assert!(s.protected(Path::new("/any/target")));
}
#[test]
fn consumer_reference_protects_only_its_target() {
    let mut s = consumers::Snapshot::default();
    s.busy
        .insert("/a/target".into(), vec!["mapped executable".into()]);
    assert!(s.protected(Path::new("/a/target")));
    assert!(!s.protected(Path::new("/b/target")));
}
#[test]
fn explicit_project_values_override_global_defaults() {
    let mut c = Config::default();
    c.apply_project(&serde_json::json!({"workspace_root":"/p","metadata":{"buildfit":{"quota-gib":123,"reserve-gib":100,"stop-below-gib":20,"line-tables-only":false}},"packages":[]})).unwrap();
    assert_eq!(c.quota_gib, 123);
    assert_eq!(c.reserve_gib, 100);
    assert_eq!(c.stop_below_gib, 20);
    assert!(!c.line_tables_only);
}
#[test]
fn package_values_override_workspace_values() {
    let mut c = Config::default();
    c.apply_project(&serde_json::json!({"workspace_root":"/p","metadata":{"buildfit":{"quota-gib":123}},"packages":[{"manifest_path":"/p/Cargo.toml","metadata":{"buildfit":{"quota-gib":45}}}]})).unwrap();
    assert_eq!(c.quota_gib, 45);
}
#[test]
fn project_cannot_inject_host_paths_or_privileged_settings() {
    for key in [
        "allowed-roots",
        "real-cargo",
        "privileged-probe",
        "maintenance-lock",
    ] {
        let mut c = Config::default();
        assert!(
            c.apply_project(&serde_json::json!({"metadata":{"buildfit":{key:"/tmp"}}}))
                .is_err()
        );
    }
}
#[test]
fn invalid_thresholds_fail_before_build() {
    let mut c = Config::default();
    assert!(
        c.apply_project(
            &serde_json::json!({"metadata":{"buildfit":{"reserve-gib":10,"stop-below-gib":20}}})
        )
        .is_err()
    );
}
#[test]
fn admission_uses_configured_hard_floor() {
    let t = Temp::new();
    let mut c = config(&t);
    c.stop_below_gib = 30;
    assert!(pipeline::admit(&c, 29 * GIB).is_err());
    assert!(pipeline::admit(&c, 30 * GIB).is_ok());
}
#[test]
fn free_space_query_is_live() {
    assert!(pipeline::available(Path::new("/")).unwrap() > 0);
}
#[test]
fn lock_is_nonblocking() {
    let t = Temp::new();
    let p = t.0.join("lock");
    let first = locks::Lock::acquire(&p, true).unwrap();
    assert!(locks::Lock::acquire(&p, false).is_err());
    drop(first);
    assert!(locks::Lock::acquire(&p, false).is_ok());
}
#[test]
fn symlink_lock_is_rejected() {
    let t = Temp::new();
    fs::write(t.0.join("real"), "").unwrap();
    symlink("real", t.0.join("link")).unwrap();
    assert!(locks::Lock::acquire(&t.0.join("link"), false).is_err());
}
#[test]
fn exact_single_link_output_can_be_removed() {
    let t = Temp::new();
    let p = t.0.join("old");
    let mut c = candidate(&p, "x", 0);
    c.identity = artifacts::Identity::read(&p).unwrap();
    pipeline::unlink_verified(&c).unwrap();
    assert!(!p.exists());
}
#[test]
fn changed_output_is_retained() {
    let t = Temp::new();
    let p = t.0.join("old");
    let mut c = candidate(&p, "x", 0);
    c.identity = artifacts::Identity::read(&p).unwrap();
    fs::write(&p, b"changed").unwrap();
    assert!(pipeline::unlink_verified(&c).is_err());
    assert!(p.exists());
}
#[test]
fn hard_link_is_retained() {
    let t = Temp::new();
    let p = t.0.join("old");
    let mut c = candidate(&p, "x", 0);
    fs::hard_link(&p, t.0.join("alias")).unwrap();
    c.identity = artifacts::Identity::read(&p).unwrap();
    assert!(pipeline::unlink_verified(&c).is_err());
    assert!(p.exists());
}
#[test]
fn replaced_parent_symlink_is_rejected() {
    let t = Temp::new();
    let dir = t.0.join("deps");
    fs::create_dir(&dir).unwrap();
    let p = dir.join("old");
    let mut c = candidate(&p, "x", 0);
    c.identity = artifacts::Identity::read(&p).unwrap();
    fs::rename(&dir, t.0.join("moved")).unwrap();
    symlink("moved", &dir).unwrap();
    assert!(pipeline::unlink_verified(&c).is_err());
    assert!(p.exists());
}
#[test]
fn changed_leaf_symlink_is_rejected() {
    let t = Temp::new();
    let p = t.0.join("old");
    let mut c = candidate(&p, "x", 0);
    c.identity = artifacts::Identity::read(&p).unwrap();
    fs::remove_file(&p).unwrap();
    fs::write(t.0.join("source"), b"preserve").unwrap();
    symlink("source", &p).unwrap();
    assert!(pipeline::unlink_verified(&c).is_err());
    assert_eq!(fs::read(t.0.join("source")).unwrap(), b"preserve");
}
#[test]
fn corrupt_lease_blocks_cleanup() {
    let t = Temp::new();
    fs::create_dir(t.0.join("leases")).unwrap();
    fs::write(t.0.join("leases/bad.json"), b"broken").unwrap();
    assert!(lease::other_roots(&t.0).is_err());
}
#[test]
fn reservation_survives_reserving_command() {
    let t = Temp::new();
    let p = lease::reserve(&t.0, t.0.clone(), 300, "pending verification".into()).unwrap();
    assert!(p.is_file());
    assert!(lease::other_roots(&t.0).unwrap().contains(&t.0));
}
#[test]
fn reservation_requires_bounded_duration_and_reason() {
    let t = Temp::new();
    assert!(lease::reserve(&t.0, t.0.clone(), 0, "x".into()).is_err());
    assert!(lease::reserve(&t.0, t.0.clone(), 90000, "x".into()).is_err());
    assert!(lease::reserve(&t.0, t.0.clone(), 10, "".into()).is_err());
}
#[test]
fn owned_lease_removed_at_pipeline_completion() {
    let t = Temp::new();
    {
        let _lease = lease::OwnedLease::new(&t.0, vec![t.0.join("target")]).unwrap();
        assert_eq!(fs::read_dir(t.0.join("leases")).unwrap().count(), 1);
    }
    assert_eq!(fs::read_dir(t.0.join("leases")).unwrap().count(), 0);
}
#[test]
fn cargo_arguments_after_separator_are_not_inspected() {
    assert_eq!(
        artifacts::flag(
            &[
                "test".into(),
                "--".into(),
                "--target-dir".into(),
                "/bad".into()
            ],
            "--target-dir"
        ),
        None
    );
}
#[test]
fn manifest_override_supports_both_forms() {
    for args in [
        vec!["--manifest-path".into(), "/p/Cargo.toml".into()],
        vec!["--manifest-path=/p/Cargo.toml".into()],
    ] {
        assert_eq!(
            artifacts::flag(&args, "--manifest-path"),
            Some("/p/Cargo.toml".into())
        );
    }
}
#[test]
fn aliases_and_toolchains_enter_pipeline() {
    assert!(build_command(&["+nightly".into(), "xtask".into()]));
    assert!(build_command(&["test".into()]));
    assert!(!build_command(&["metadata".into()]));
    assert!(!build_command(&["--version".into()]));
}
#[test]
fn output_size_deduplicates_hard_links_and_preserves_unknowns() {
    let t = Temp::new();
    let target = t.0.join("target");
    fs::create_dir(&target).unwrap();
    let p = target.join("failure-record.txt");
    fs::write(&p, b"preserve original failure").unwrap();
    fs::hard_link(&p, target.join("copy")).unwrap();
    let pool = artifacts::measure(&config(&t), &[(target, t.0.clone())]).unwrap();
    assert!(pool.candidates.is_empty());
    assert!(p.exists());
}
#[test]
fn source_guard_detects_tracked_and_untracked_edits() {
    let t = Temp::new();
    let r = &t.0;
    fs::write(
        r.join("Cargo.toml"),
        "[package]\nname='fixture'\nversion='0.1.0'\n",
    )
    .unwrap();
    fs::write(r.join("Cargo.lock"), "version = 4\n").unwrap();
    fs::write(r.join(".gitignore"), "/target/\n").unwrap();
    fs::write(r.join("tracked.rs"), "before").unwrap();
    for args in [
        vec!["init", "--quiet"],
        vec!["add", "."],
        vec![
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "user.name=fixture",
            "commit",
            "--quiet",
            "-m",
            "test: initialize fixture",
        ],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(r)
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    fs::write(r.join("untracked.rs"), "unique").unwrap();
    let a = git::SourceGuard::capture(r, &r.join("target")).unwrap();
    fs::write(r.join("tracked.rs"), "after").unwrap();
    let b = git::SourceGuard::capture(r, &r.join("target")).unwrap();
    assert_ne!(a, b);
    assert!(b.hashes.contains_key(Path::new("untracked.rs")));
}
#[test]
fn pin_prefix_policy_is_boundary_aware() {
    let t = Temp::new();
    let c = config(&t);
    assert!(c.permitted(&t.0.join("target")));
    assert!(!c.permitted(&PathBuf::from(format!("{}-other/target", t.0.display()))));
}

#[test]
fn structured_unknown_metadata_is_rejected() {
    let mut c = Config::default();
    let value = serde_json::json!({"metadata":{"buildfit":{"quota-gib":100,"typo":true}}});
    assert!(c.apply_project(&value).is_err());
}

#[test]
fn installed_symlink_to_wrapper_script_protects_its_consumer() {
    let t = Temp::new();
    let target = t.0.join("target");
    fs::create_dir(&target).unwrap();
    let script = t.0.join("wrapper");
    fs::write(
        &script,
        format!("#!/bin/sh\nexec {}/app\n", target.display()),
    )
    .unwrap();
    let entry = t.0.join("installed-entry");
    symlink(&script, &entry).unwrap();
    let snapshot = consumers::inspect_installed_fixture(&entry, std::slice::from_ref(&target));
    assert!(snapshot.protected(&target));
    assert!(snapshot.incomplete.is_empty());
}

#[test]
fn installed_direct_symlink_protects_target_even_when_output_is_missing() {
    let t = Temp::new();
    let target = t.0.join("target");
    let entry = t.0.join("installed-entry");
    symlink(target.join("app"), &entry).unwrap();
    assert!(
        consumers::inspect_installed_fixture(&entry, std::slice::from_ref(&target))
            .protected(&target)
    );
}

#[test]
fn unrelated_runtime_files_do_not_block_independent_superseded_test_output() {
    let target = PathBuf::from("/fixture/target");
    let mut snapshot = consumers::Snapshot {
        precise_process_paths: true,
        ..Default::default()
    };
    snapshot
        .busy
        .insert(target.clone(), vec!["running application".into()]);
    snapshot.referenced_paths.insert(target.join("desktop/app"));
    assert!(!snapshot.protected(&target));
    assert!(!snapshot.protects_candidate(&target, &target.join("debug/deps/old-test")));
    assert!(snapshot.protects_candidate(&target, &target.join("desktop/app")));
}

#[test]
fn active_build_headroom_is_reserved_and_released_by_process_identity() {
    let t = Temp::new();
    let mut child = Command::new("sh")
        .args(["-c", "read -r guard_test_input"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let value = lease::Lease {
        pid,
        start: lease::start_time(pid).unwrap(),
        boot: platform::boot_identity().unwrap(),
        roots: vec![t.0.join("target")],
        expires: 0,
        reason: "fixture active build".into(),
        headroom_bytes: 20 * GIB,
    };
    fs::create_dir(t.0.join("leases")).unwrap();
    fs::write(
        t.0.join("leases/child.json"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    assert_eq!(lease::reserved_bytes(&t.0).unwrap(), 20 * GIB);
    let mut cfg = config(&t);
    cfg.stop_below_gib = 30;
    assert!(
        pipeline::admit(
            &cfg,
            70 * GIB - lease::reserved_bytes(&t.0).unwrap() - 20 * GIB
        )
        .is_ok()
    );
    assert!(
        pipeline::admit(
            &cfg,
            69 * GIB - lease::reserved_bytes(&t.0).unwrap() - 20 * GIB
        )
        .is_err()
    );
    drop(child.stdin.take());
    child.wait().unwrap();
    assert_eq!(lease::reserved_bytes(&t.0).unwrap(), 0);
}

#[test]
fn source_hashing_is_streamed_and_refuses_oversized_inputs() {
    use sha2::{Digest, Sha256};
    let t = Temp::new();
    let p = t.0.join("source");
    let data = vec![42u8; 150000];
    fs::write(&p, &data).unwrap();
    let mut too_small = 149999;
    assert!(git::hash_source_file(&p, &mut too_small).is_err());
    let mut exact = 150000;
    assert_eq!(
        git::hash_source_file(&p, &mut exact).unwrap(),
        format!("{:x}", Sha256::digest(&data))
    );
    assert_eq!(exact, 0);
    assert!(p.exists());
}

#[test]
fn oversized_or_symlinked_cargo_fingerprint_is_retained() {
    let t = Temp::new();
    let p = t.0.join("fingerprint");
    let f = fs::File::create(&p).unwrap();
    f.set_len(1024 * 1024 + 1).unwrap();
    assert!(artifacts::read_fingerprint(&p).is_err());
    let link = t.0.join("link");
    symlink(&p, &link).unwrap();
    assert!(artifacts::read_fingerprint(&link).is_err());
    assert!(p.exists());
}

#[test]
fn process_identity_and_boot_identity_are_available() {
    assert!(platform::start_time(std::process::id()).is_some());
    assert!(platform::parent_pid(std::process::id()).is_some());
    assert!(!platform::boot_identity().unwrap().is_empty());
}
#[test]
fn mach_o_executable_headers_reject_dylibs_objects_and_truncation() {
    let t = Temp::new();
    let path = t.0.join("header");
    for magic in [
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
    ] {
        for kind in [1u32, 2, 6, 8, 10] {
            let mut bytes = vec![0u8; 64];
            bytes[..4].copy_from_slice(&magic);
            let field = if magic[0] == 0xfe {
                kind.to_be_bytes()
            } else {
                kind.to_le_bytes()
            };
            bytes[12..16].copy_from_slice(&field);
            fs::write(&path, bytes).unwrap();
            assert_eq!(
                executable::verify(&mut fs::File::open(&path).unwrap()).is_ok(),
                kind == 2
            );
        }
    }
    fs::write(&path, b"\xcf\xfa\xed\xfe").unwrap();
    assert!(executable::verify(&mut fs::File::open(&path).unwrap()).is_err());
}
#[test]
fn universal_mach_o_requires_every_nonoverlapping_slice_to_be_executable() {
    let t = Temp::new();
    let path = t.0.join("universal");
    let mut bytes = vec![0u8; 128];
    bytes[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    bytes[4..8].copy_from_slice(&2u32.to_be_bytes());
    bytes[16..20].copy_from_slice(&64u32.to_be_bytes());
    bytes[20..24].copy_from_slice(&32u32.to_be_bytes());
    bytes[36..40].copy_from_slice(&96u32.to_be_bytes());
    bytes[40..44].copy_from_slice(&32u32.to_be_bytes());
    for offset in [64, 96] {
        bytes[offset..offset + 4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        bytes[offset + 12..offset + 16].copy_from_slice(&2u32.to_le_bytes());
    }
    fs::write(&path, &bytes).unwrap();
    assert!(executable::verify(&mut fs::File::open(&path).unwrap()).is_ok());
    bytes[108..112].copy_from_slice(&6u32.to_le_bytes());
    fs::write(&path, &bytes).unwrap();
    assert!(executable::verify(&mut fs::File::open(&path).unwrap()).is_err());
    bytes[108..112].copy_from_slice(&2u32.to_le_bytes());
    bytes[36..40].copy_from_slice(&64u32.to_be_bytes());
    fs::write(&path, &bytes).unwrap();
    assert!(executable::verify(&mut fs::File::open(&path).unwrap()).is_err());
}

#[test]
fn record_lock_child_fixture() {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    let Some(path) = env::var_os("BUILDFIT_TEST_RECORD_LOCK") else {
        return;
    };
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut record: libc::flock = unsafe { std::mem::zeroed() };
    record.l_type = libc::F_WRLCK as _;
    record.l_whence = libc::SEEK_SET as _;
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &record) },
        0
    );
    println!("record-lock-ready");
    std::io::stdout().flush().unwrap();
    let mut byte = [0u8; 1];
    let _ = std::io::stdin().read(&mut byte);
}
#[test]
fn cargo_record_lock_conflicts_with_nonblocking_maintenance_on_each_platform() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let t = Temp::new();
    let path = t.0.join("record.lock");
    fs::write(&path, "").unwrap();
    let mut child = Command::new(env::current_exe().unwrap())
        .args(["--exact", "tests::record_lock_child_fixture", "--nocapture"])
        .env("BUILDFIT_TEST_RECORD_LOCK", &path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut ready = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
        if line.trim() == "record-lock-ready" {
            ready = true;
            break;
        }
    }
    let blocked = locks::Lock::acquire(&path, false).is_err();
    drop(child.stdin.take());
    let status = child.wait().unwrap();
    assert!(ready && status.success());
    assert!(blocked, "Cargo record lock must exclude maintenance");
    assert!(locks::Lock::acquire(&path, false).is_ok());
}

#[cfg(target_os = "macos")]
#[test]
fn installed_binary_launchd_plist_protects_its_configured_output() {
    let t = Temp::new();
    let target = t.0.join("target & resources");
    let plist = t.0.join("fixture.plist");
    let escaped = target.to_string_lossy().replace('&', "&amp;");
    fs::write(&plist,format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>ProgramArguments</key><array><string>{escaped}/test</string></array></dict></plist>")).unwrap();
    assert!(
        Command::new("/usr/bin/plutil")
            .args(["-convert", "binary1"])
            .arg(&plist)
            .status()
            .unwrap()
            .success()
    );
    let snapshot = consumers::inspect_installed_fixture(&plist, std::slice::from_ref(&target));
    assert!(snapshot.incomplete.is_empty());
    assert!(snapshot.protected(&target));
}
