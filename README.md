# Buildfit

A Linux, macOS and Windows Cargo launcher that checks storage, protects current consumers, removes positively identified superseded test executables when necessary, and runs Cargo. Normal use remains a single command:

```sh
cargo build
cargo test
cargo xtask test
```

The launcher must be installed earlier on `PATH` than the real Cargo executable. Cargo itself does not interpret arbitrary metadata tables or provide a general pre-build hook. This tool interprets the policy and delegates to a separately configured real Cargo. Explicit calls to another Cargo executable bypass the launcher.

## Project configuration

Put the shared policy in the workspace root's `Cargo.toml`:

```toml
[workspace.metadata.buildfit]
quota-gib = 250
low-water-percent = 80
reserve-gib = 150
stop-below-gib = 30
build-headroom-gib = 20
min-age-seconds = 3600
check-interval-seconds = 300
max-cleanup-seconds = 30
max-remove-gib = 40
worktrees = true
line-tables-only = true
```

Use `[package.metadata.buildfit]` for an independent package. Root-package settings override workspace settings; these override global defaults. Member-package metadata does not independently override the workspace-wide policy. Unknown keys and invalid thresholds fail before starting a build.

`quota-gib` is one soft budget across the repository's qualified worktrees, not a budget multiplied by each checkout. Exceeding the quota triggers maintenance toward `low-water-percent`. Falling below `reserve-gib` also requests cleanup and prints a warning if protected output prevents recovery. A build cannot start below `stop-below-gib`, even when maintenance is busy or inspection is unavailable. These are pre-build thresholds, not an operating-system disk reservation or a guarantee about how much a running build will write.

`build-headroom-gib` reserves an estimated amount for each active pipeline. Admission subtracts other live pipelines' reservations and the requested build's headroom before checking the hard floor, under a short shared admission lock. This avoids several simultaneous builds all assuming the same free space. The default is 20 GiB; small projects can lower it and larger cold builds should raise it. Nested Cargo invocations recognize ancestor reservations for their own admission, so a command such as `cargo xtask` can launch its required Cargo child without reserving the same headroom twice for that admission. Other independent invocations count live nested reservations conservatively. This is cooperative admission accounting, not a filesystem allocation guarantee.

`line-tables-only` supplies `CARGO_PROFILE_DEV_DEBUG=line-tables-only` and `CARGO_PROFILE_TEST_DEBUG=line-tables-only` to subsequent Cargo invocations. Explicit environment overrides are preserved. This retains file/line backtraces and sacrifices detailed variable/type debugging. Set the project option to `false`, or explicitly set the profile debug environment value when full debug information is needed. Release settings and ongoing processes are unaffected.

## Installation

Build with an existing Cargo, then place the executable in a user-owned executable directory as `cargo-buildfit`. On Linux/macOS, create a `cargo` symlink to it in a directory earlier on `PATH` than Rustup. On Windows, copy the executable as `cargo.exe` into that user-owned launcher directory; keep `cargo-buildfit.exe` there for optional diagnostics. Set `real_cargo` to the original Cargo path; it must not point back at the launcher. Do not replace Rustup's executable.

Global configuration on Linux/macOS is read from `$XDG_CONFIG_HOME/cargo-buildfit/config.toml`, defaulting to `~/.config/cargo-buildfit/config.toml`. Windows defaults to `%APPDATA%/cargo-buildfit/config.toml`, with state under `%LOCALAPPDATA%/cargo-buildfit`; `XDG_CONFIG_HOME` can override the configuration base. `CARGO_BUILDFIT_CONFIG` selects another file. Global keys use snake_case:

```toml
real_cargo = "/path/to/original/cargo"
state_dir = "/path/to/guard-state"
maintenance_lock = "/path/to/shared-maintenance.lock"
receipt_dir = "/path/to/guard-receipts"
allowed_roots = ["/path/to/approved/checkouts"]
pins = ["/path/to/retained/target"]
privileged_probe = true
```

All roots and host paths must be absolute. Empty `allowed_roots` allows outputs inside the invoking repository's registered Git worktrees; a nonempty list restricts those roots further. Project metadata cannot change host paths, pins, probe privilege or the shared maintenance lock.

On Linux/macOS, all-user process visibility uses `sudo -n` for the executable's read-only `internal-probe` operation. No process or service is stopped. If privilege or visibility is unavailable, deletion is skipped and the free-space admission floor still applies. There is no automatic privilege setup or password prompt. State and receipts must be outside source checkouts.


## Automatic pipeline

1. Resolve global and project settings, Cargo metadata and registered worktrees. Inspect metadata with `--locked --offline`; leave ambiguous layouts alone.
2. Register the running pipeline's output lease. Other pipelines retain leased roots; stale process leases are validated with PID start time and boot identity.
3. Acquire the shared maintenance lock without waiting. Measure only qualified compiler output, deduplicating hard links. Throttle repeated inventories using actual measured state, with a fresh admission/free-space check on every invocation.
4. Retain the newest test executable per checkout and build configuration. Consider only older single-link ELF, Mach-O or PE test executables with unambiguous Cargo fingerprints, outside the recent-use window.
5. Check executable/cwd/open-descriptor/mapped-file references, compiler activity, configured pins, explicit reservations, installed services, desktop entries and installed symlinks. Incomplete inspection protects output.
6. Hash tracked and untracked sources and reconstruction inputs; verify Git worktree registration, HEAD, branch, index and status. Acquire all discovered applicable Cargo locks without waiting. Repeat source and usage checks under those locks and immediately before deletion.
7. Unlink only the verified executable through directories opened without following symlinks. Recheck inode, device, link count, size, timestamps and fingerprint identity. Verify source/Git state afterward and retain exact operational receipts. Source hashing uses fixed 64 KiB buffers with a 1 GiB aggregate inspection budget per capture; oversized inputs retain their output root. Cargo fingerprints are limited to 1 MiB.
8. Check available space and run Cargo, preserving its output and exit code. Run postflight maintenance with the same retention policy. Current processes are never interrupted to make room.

The recent-use window uses the newest executable/fingerprint access or modification time, plus live consumer and lease checks. Linux scanner reads use `O_NOATIME` so observation does not artificially refresh candidates. macOS uses non-symlink reads and captures freshness before reading; the filesystem may update access times during inspection, which conservatively postpones later cleanup. `relatime` and `noatime` can make access times approximate; age alone never authorizes deletion.

## Preservation scope

Version 0.1 removes **only superseded Cargo test executables**. It retains the newest configurations, dependency libraries, incremental caches, normal application binaries, native runtime support, `doc`, `tmp`, `nextest`, benchmark reports, fixtures, databases, models, source and unknown files. It never removes whole worktrees or invokes `cargo clean`. Hard-linked candidates, symlinked targets, unsupported build-directory layouts, unregistered worktrees and sources without a lockfile/committed Git identity are retained.

On macOS, consumer inspection uses the native process list, PID start time and boot-session UUID, plus bounded `lsof` inventories for executable mappings, mapped files, working directories and open descriptors. Installed entry checks cover system and user LaunchAgents/LaunchDaemons, application `Info.plist` and `Contents/MacOS` entry points, and standard installed command symlinks. Binary and XML property lists are decoded with the native Core Foundation property-list parser. A visible process missing from the inventory, inaccessible process, failed helper or incomplete scan blocks deletion. Verified zombies have already released file references. Darwin uses its shared flock/record-lock conflict domain; Linux acquires both lock namespaces. Mach-O objects, libraries, bundles and dSYM output are retained. Universal test executables qualify only when every bounded, nonoverlapping slice is executable.

On Windows, native `LockFileEx` locks coordinate Cargo/maintenance and file IDs, allocation sizes and timestamps come from native handles. Read-only CIM/registry/shortcut inspection checks active compiler activity, installed services, scheduled tasks, loaded-user startup/application entries, profile startup/desktop entries and installed symlinks. Unknown compiler output scope protects the whole qualified pool. Insufficient visibility retains output. Reparse ancestors, including junctions, are rejected. The final deletion holds directory handles against rename, opens the exact executable without sharing, revalidates its identity and uses classic delete disposition. Live handles, images or mapped sections can veto deletion in the kernel. POSIX/forced deletion flags are never used. PE libraries, PDB files, objects and unknown output are retained. Native qualification covers Windows 11 x64 with the GNU Rust target; MSVC execution is not independently qualified.

This conservative scope may leave a pool over quota. Receipts explain skips. Installed-wrapper scripts and symlinks in the standard scanned locations are checked; arbitrary application-specific deployment paths should also be pinned explicitly. Consumer visibility is a point-in-time check under cooperative Cargo/maintenance locks, not a kernel-level exclusion against unrelated future file opens.

Builds that invoke an absolute real Cargo path bypass the launcher. Cargo `--config` invocations are delegated but their output layout is not qualified for deletion in this version. Different output volumes, detached/subdirectory workspace layouts and externally configured build directories require qualification before extending cleanup scope.

## Diagnostics

These are optional; normal builds require no separate maintenance command:

```sh
cargo buildfit status
cargo buildfit clean
cargo buildfit reserve /path/to/target 3600 "pending regression verification"
```

`status` measures and records a nondeleting receipt; it does not update the maintenance throttle with hypothetical removal. `clean` uses the same quota and reserve policy. A reservation lasts at most one day and includes a reason. Pins provide indefinite explicit retention. Reservations are useful for external consumers between build invocations; ordinary active pipelines create their own leases automatically.

## Verification

```sh
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

The Unix ignored consumer-lifecycle integration test requires passwordless sudo and can be included with `cargo test --all-targets -- --include-ignored`. It builds two real Cargo test versions, verifies an open descriptor blocks cleanup, then checks that only the superseded executable is removed after release while source and original failure evidence survive. Other tests cover policy precedence, transparent invocation, line-table settings, compiler failure propagation, admission, locks, symlinks, hard links, unknown output, source mutations and reservations.

Windows unit tests run with `cargo test --all-targets`. They qualify native file identity/deletion, open and mapped consumers, junctions, hard links, byte-range locks, lease replacement, process/boot identity, PE validation and admission. A Windows installation needs the same project policy and a working original Cargo/toolchain; installing metadata alone never installs the launcher. Each worktree keeps its own output directory; this release does not configure a shared target or compiler cache.
