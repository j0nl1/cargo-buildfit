use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = env::temp_dir().join(format!(
            "buildfit-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn candidate(path: &Path) -> artifacts::Candidate {
    fs::write(path, b"task-owned compiler output").unwrap();
    artifacts::Candidate {
        path: path.into(),
        target: path.parent().unwrap().into(),
        source: path.parent().unwrap().into(),
        profile: path.parent().unwrap().into(),
        fingerprint: path.with_extension("json"),
        fingerprint_sha256: String::new(),
        key: "test".into(),
        last_used: 0,
        identity: artifacts::Identity::read(path).unwrap(),
    }
}
#[test]
fn windows_metadata_and_native_deletion_agree() {
    let t = Temp::new();
    let c = candidate(&t.0.join("old.exe"));
    assert!(c.identity.allocated > 0);
    assert_eq!(c.identity.links, 1);
    pipeline::unlink_verified(&c).unwrap();
    assert!(!c.path.exists());
}
#[test]
fn open_descriptor_prevents_deletion() {
    let t = Temp::new();
    let c = candidate(&t.0.join("old.exe"));
    let held = fs::File::open(&c.path).unwrap();
    let err = pipeline::unlink_verified(&c).unwrap_err();
    assert!(platform::busy_error(&err));
    assert!(c.path.exists());
    drop(held);
    pipeline::unlink_verified(&c).unwrap();
}
#[test]
fn mapped_file_survives_after_descriptor_and_mapping_handles_close() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{Foundation::CloseHandle, System::Memory::*};
    let t = Temp::new();
    let c = candidate(&t.0.join("old.exe"));
    let file = fs::File::open(&c.path).unwrap();
    let mapping = unsafe {
        CreateFileMappingW(
            file.as_raw_handle(),
            std::ptr::null(),
            PAGE_READONLY,
            0,
            0,
            std::ptr::null(),
        )
    };
    assert!(!mapping.is_null());
    let view = unsafe { MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0) };
    assert!(!view.Value.is_null());
    drop(file);
    unsafe {
        CloseHandle(mapping);
    }
    let result = pipeline::unlink_verified(&c);
    let exists = c.path.exists();
    unsafe {
        UnmapViewOfFile(view);
    }
    assert!(result.is_err(), "mapped file must block classic deletion");
    assert!(exists);
    pipeline::unlink_verified(&c).unwrap();
}
#[test]
fn hardlinks_are_never_pruned() {
    let t = Temp::new();
    let mut c = candidate(&t.0.join("old.exe"));
    fs::hard_link(&c.path, t.0.join("retained")).unwrap();
    c.identity = artifacts::Identity::read(&c.path).unwrap();
    assert!(pipeline::unlink_verified(&c).is_err());
    assert!(c.path.exists());
}
#[test]
fn changed_output_is_retained() {
    let t = Temp::new();
    let c = candidate(&t.0.join("old.exe"));
    fs::write(&c.path, b"different content, original evidence").unwrap();
    assert!(pipeline::unlink_verified(&c).is_err());
}
#[test]
fn windows_lock_is_nonblocking_and_released() {
    let t = Temp::new();
    let path = t.0.join("cargo.lock");
    let lock = locks::Lock::acquire(&path, true).unwrap();
    assert!(locks::Lock::acquire(&path, false).is_err());
    drop(lock);
    assert!(locks::Lock::acquire(&path, false).is_ok());
}
#[test]
fn windows_file_replacement_supports_live_lease_updates() {
    let t = Temp::new();
    fs::write(t.0.join("old"), b"old").unwrap();
    fs::write(t.0.join("new"), b"new").unwrap();
    platform::replace_file(&t.0.join("new"), &t.0.join("old")).unwrap();
    assert_eq!(fs::read(t.0.join("old")).unwrap(), b"new");
}
#[test]
fn native_process_identity_and_boot_identity_are_stable() {
    let first = platform::start_time(std::process::id()).unwrap();
    assert_eq!(Some(first), platform::start_time(std::process::id()));
    assert!(platform::parent_pid(std::process::id()).is_some());
    assert_eq!(
        platform::boot_identity().unwrap(),
        platform::boot_identity().unwrap()
    );
}
#[test]
fn active_headroom_is_released_at_pipeline_completion() {
    let t = Temp::new();
    let lease = lease::OwnedLease::new(&t.0, vec![t.0.clone()]).unwrap();
    lease.admit(1024).unwrap();
    assert_eq!(lease::reserved_bytes(&t.0).unwrap(), 0);
    drop(lease);
    assert_eq!(fs::read_dir(t.0.join("leases")).unwrap().count(), 0);
}
#[test]
fn bounded_manual_reservation_survives_owner() {
    let t = Temp::new();
    lease::reserve(&t.0, t.0.clone(), 60, "next test".into()).unwrap();
    assert_eq!(lease::other_roots(&t.0).unwrap(), vec![t.0.clone()]);
}
#[test]
fn git_paths_decode_utf8_without_loss() {
    assert_eq!(
        platform::os_from_git("folder-ñ/source.rs".as_bytes()).unwrap(),
        std::ffi::OsString::from("folder-ñ/source.rs")
    );
    assert!(platform::os_from_git(&[0xff]).is_err());
}
#[test]
fn windows_capacity_query_and_floor_are_live() {
    let t = Temp::new();
    let free = pipeline::available(&t.0).unwrap();
    assert!(free > 0);
    let cfg = Config {
        reserve_gib: 1000000,
        stop_below_gib: 1000000,
        ..Default::default()
    };
    assert!(pipeline::admit(&cfg, free).is_err());
}
#[test]
fn project_configuration_uses_only_buildfit() {
    let mut cfg = Config::default();
    cfg.apply_project(&serde_json::json!({"metadata":{"buildfit":{"quota-gib":123}}}))
        .unwrap();
    assert_eq!(cfg.quota_gib, 123);
    assert!(
        cfg.apply_project(&serde_json::json!({"metadata":{"buildfit":{"unknown":true}}}))
            .is_err()
    );
}
#[test]
fn pe_parser_rejects_dlls_and_truncated_headers() {
    let t = Temp::new();
    let path = t.0.join("test.exe");
    let mut bytes = vec![0u8; 160];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
    bytes[64..68].copy_from_slice(b"PE\0\0");
    bytes[84..86].copy_from_slice(&64u16.to_le_bytes());
    bytes[86..88].copy_from_slice(&2u16.to_le_bytes());
    bytes[88..90].copy_from_slice(&0x20bu16.to_le_bytes());
    fs::write(&path, &bytes).unwrap();
    assert!(executable::verify(&mut fs::File::open(&path).unwrap()).is_ok());
    bytes[86..88].copy_from_slice(&0x2002u16.to_le_bytes());
    fs::write(&path, &bytes).unwrap();
    assert!(executable::verify(&mut fs::File::open(&path).unwrap()).is_err());
    fs::write(&path, b"MZ").unwrap();
    assert!(executable::verify(&mut fs::File::open(&path).unwrap()).is_err());
}
#[test]
fn junction_ancestor_is_never_followed() {
    let t = Temp::new();
    let source = t.0.join("source");
    fs::create_dir(&source).unwrap();
    let c = candidate(&source.join("old.exe"));
    let junction = t.0.join("junction");
    assert!(
        Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&source)
            .output()
            .unwrap()
            .status
            .success()
    );
    let mut redirected = c;
    redirected.path = junction.join("old.exe");
    assert!(pipeline::unlink_verified(&redirected).is_err());
    assert!(source.join("old.exe").exists());
    fs::remove_dir(&junction).unwrap();
}
#[test]
fn visibility_failure_and_unrelated_resources_are_distinguished() {
    let root = Path::new("C:\\source\\target");
    let s = consumers::Snapshot {
        incomplete: vec!["inspection unavailable".into()],
        ..Default::default()
    };
    assert!(s.protected(root));
    let s = consumers::Snapshot {
        precise_process_paths: true,
        referenced_paths: [root.join("runtime")].into(),
        ..Default::default()
    };
    assert!(!s.protects_candidate(root, &root.join("old.exe")));
}
