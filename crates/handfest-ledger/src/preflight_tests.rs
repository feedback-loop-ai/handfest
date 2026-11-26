use tempfile::TempDir;

use super::*;

fn write_valid_header_file(path: &Path) -> PathBuf {
    let mut fake_sqlite = [0u8; SQLITE_HEADER_LEN];
    fake_sqlite[..SQLITE_HEADER_MAGIC.len()].copy_from_slice(SQLITE_HEADER_MAGIC);
    fake_sqlite[18] = 1;
    fake_sqlite[19] = 1;
    fs::write(path, fake_sqlite).unwrap();
    fs::canonicalize(path).unwrap()
}

#[test]
fn read_only_header_and_sidecar_helpers_fail_closed_on_invalid_inputs() {
    let dir = TempDir::new().unwrap();
    let mut empty_reg = ActiveHandleRegistry::default();
    let missing = dir.path().join("missing.sqlite");
    assert!(matches!(
        open_read_only_guarded(&missing, |_| Ok(())),
        Err(LedgerError::Integrity(_))
    ));
    assert!(matches!(
        open_read_only_guarded(dir.path(), |_| Ok(())),
        Err(LedgerError::Integrity(_))
    ));
    assert!(matches!(
        inspect_sqlite_header_locked(&mut empty_reg, &missing),
        Err(LedgerError::Integrity(_))
    ));

    let short = dir.path().join("short.sqlite");
    fs::write(&short, b"short").unwrap();
    assert!(matches!(
        inspect_sqlite_header_locked(&mut empty_reg, &short),
        Err(LedgerError::Integrity(_))
    ));

    let bad_magic = dir.path().join("bad_magic.sqlite");
    fs::write(&bad_magic, [0u8; 128]).unwrap();
    assert!(matches!(
        inspect_sqlite_header_locked(&mut empty_reg, &bad_magic),
        Err(LedgerError::Integrity(_))
    ));

    let dir_sidecar = dir.path().join("dir-journal");
    fs::create_dir(&dir_sidecar).unwrap();
    assert!(matches!(
        check_wal_sidecar(&dir_sidecar),
        Err(LedgerError::Integrity(_))
    ));
    assert!(matches!(
        check_rollback_journal_sidecar_in(active_handles(), &dir_sidecar),
        Err(LedgerError::Integrity(_))
    ));

    let empty_journal = dir.path().join("empty-journal");
    fs::write(&empty_journal, b"").unwrap();
    check_rollback_journal_sidecar_in(active_handles(), &empty_journal).unwrap();

    let short_journal = dir.path().join("short-journal");
    fs::write(&short_journal, [0u8; 10]).unwrap();
    assert!(matches!(
        check_rollback_journal_sidecar_with_budget_in(
            active_handles(),
            &short_journal,
            Duration::ZERO
        ),
        Err(LedgerError::Integrity(_))
    ));

    let impossible = short_journal.join("child");
    assert!(matches!(
        check_wal_sidecar(&impossible),
        Err(LedgerError::Integrity(_))
    ));
    assert!(matches!(
        check_rollback_journal_sidecar_in(active_handles(), &impossible),
        Err(LedgerError::Integrity(_))
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let target = dir.path().join("sidecar_target");
        fs::write(&target, b"").unwrap();
        let sym_wal = dir.path().join("sym.sqlite-wal");
        let sym_jrnl = dir.path().join("sym.sqlite-journal");
        symlink(&target, &sym_wal).unwrap();
        symlink(&target, &sym_jrnl).unwrap();
        assert!(matches!(
            check_wal_sidecar(&sym_wal),
            Err(LedgerError::Integrity(ref m)) if m.contains("symlink")
        ));
        assert!(matches!(
            check_rollback_journal_sidecar_in(active_handles(), &sym_jrnl),
            Err(LedgerError::Integrity(ref m)) if m.contains("symlink")
        ));

        let unreadable = dir.path().join("unreadable-journal");
        fs::write(&unreadable, [0u8; 32]).unwrap();
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
        if File::open(&unreadable).is_ok() {
            let _ = fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o644));
            return;
        }
        let res = check_rollback_journal_sidecar_in(active_handles(), &unreadable);
        let _ = fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o644));
        assert!(matches!(res, Err(LedgerError::Integrity(_))));
    }
}

#[test]
fn active_handle_guard_refcounts_by_inode_across_hard_links_and_clears_on_drop() {
    let dir = TempDir::new().unwrap();
    let canonical = write_valid_header_file(&dir.path().join("guard.sqlite"));
    assert_eq!(active_handle_count(&canonical), 0);
    let ((), g1) = open_writable_guarded(&canonical, || Ok(())).unwrap();
    assert_eq!(active_handle_count(&canonical), 1);

    #[cfg(unix)]
    {
        let alias = dir.path().join("guard_hardlink.sqlite");
        fs::hard_link(&canonical, &alias).unwrap();
        let canonical_alias = fs::canonicalize(&alias).unwrap();
        assert_ne!(canonical, canonical_alias);
        assert_eq!(active_handle_count(&canonical_alias), 1);

        let ((), g2) = open_read_only_guarded(&canonical_alias, |_| Ok(())).unwrap();
        assert_eq!(active_handle_count(&canonical), 2);
        drop(g1);
        assert_eq!(active_handle_count(&canonical), 1);
        drop(g2);
        assert_eq!(active_handle_count(&canonical), 0);
    }

    #[cfg(not(unix))]
    {
        let ((), g2) = open_read_only_guarded(&canonical, |_| Ok(())).unwrap();
        assert_eq!(active_handle_count(&canonical), 2);
        drop(g1);
        assert_eq!(active_handle_count(&canonical), 1);
        drop(g2);
        assert_eq!(active_handle_count(&canonical), 0);
    }
}

#[test]
fn transient_rollback_journal_retry_succeeds_when_journal_clears_and_fails_when_stuck() {
    let dir = TempDir::new().unwrap();
    let journal = dir.path().join("transient.sqlite-journal");
    fs::write(
        &journal,
        b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7hot-commit-payload",
    )
    .unwrap();

    let journal_bg = journal.clone();
    let clearer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        fs::remove_file(&journal_bg).unwrap();
    });
    check_rollback_journal_sidecar_with_budget_in(
        active_handles(),
        &journal,
        Duration::from_millis(500),
    )
    .unwrap();
    clearer.join().unwrap();

    let stuck = dir.path().join("stuck.sqlite-journal");
    fs::write(
        &stuck,
        b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7crashed-hot-journal",
    )
    .unwrap();
    assert!(matches!(
        check_rollback_journal_sidecar_with_budget_in(
            active_handles(),
            &stuck,
            Duration::from_millis(15)
        ),
        Err(LedgerError::Integrity(_))
    ));
}

#[cfg(unix)]
#[test]
fn deferred_fds_deduplicate_by_inode_read_live_contents_and_clear_only_when_all_drop() {
    static REG: OnceLock<Mutex<ActiveHandleRegistry>> = OnceLock::new();
    let reg = REG.get_or_init(|| Mutex::new(ActiveHandleRegistry::default()));

    let dir = TempDir::new().unwrap();
    let orig = dir.path().join("orig.sqlite");
    let moved = dir.path().join("moved.sqlite");
    write_valid_header_file(&orig);

    let ((), writer_guard) = open_writable_guarded_in(reg, &orig, || {
        fs::rename(&orig, &moved).unwrap();
        write_valid_header_file(&orig);
        Ok(())
    })
    .unwrap();
    assert!(reg.lock().unwrap().deferred_fds.is_empty());

    // Repeated raw inspections of the same inode deduplicate to 1 deferred fd.
    let canonical_moved = fs::canonicalize(&moved).unwrap();
    let ((), ro1) = open_read_only_guarded_in(reg, &canonical_moved, |_| Ok(())).unwrap();
    assert_eq!(reg.lock().unwrap().deferred_fds.len(), 1);
    drop(ro1);

    let ((), ro2) = open_read_only_guarded_in(reg, &canonical_moved, |_| Ok(())).unwrap();
    assert_eq!(reg.lock().unwrap().deferred_fds.len(), 1);

    // Distinct regular-file inode with bad magic adds a second deferred fd, and rewinding it reads
    // live in-place updates on the same inode.
    let mutating = dir.path().join("mutating_deferred.sqlite");
    fs::write(&mutating, [0u8; SQLITE_HEADER_LEN]).unwrap();
    let canonical_mut = fs::canonicalize(&mutating).unwrap();
    assert!(matches!(
        open_read_only_guarded_in(reg, &canonical_mut, |_| Ok(())),
        Err(LedgerError::Integrity(_))
    ));
    assert_eq!(reg.lock().unwrap().deferred_fds.len(), 2);

    write_valid_header_file(&canonical_mut);
    let ((), ro_mut) = open_read_only_guarded_in(reg, &canonical_mut, |_| Ok(())).unwrap();
    assert_eq!(reg.lock().unwrap().deferred_fds.len(), 2);
    drop(ro_mut);

    let mut wal_hdr = [0u8; SQLITE_HEADER_LEN];
    wal_hdr[..SQLITE_HEADER_MAGIC.len()].copy_from_slice(SQLITE_HEADER_MAGIC);
    wal_hdr[18] = 2;
    wal_hdr[19] = 2;
    fs::write(&canonical_mut, wal_hdr).unwrap();
    assert!(matches!(
        open_read_only_guarded_in(reg, &canonical_mut, |_| Ok(())),
        Err(LedgerError::Integrity(ref m)) if m.contains("WAL")
    ));
    assert_eq!(reg.lock().unwrap().deferred_fds.len(), 2);

    // Dropping the last writer while ro2 is STILL active must NOT sweep uncounted deferred fds
    // (canonical_mut) retained while the writer was active, and must retain ro2's active inode
    // (canonical_moved) so neither POSIX lock is dropped before all handles close.
    drop(writer_guard);
    {
        use std::os::unix::fs::MetadataExt;
        let moved_meta = fs::metadata(&canonical_moved).unwrap();
        let mut_meta = fs::metadata(&canonical_mut).unwrap();
        let state = reg.lock().unwrap();
        assert_eq!(state.active_writers, 0);
        assert_eq!(state.counts.len(), 1);
        assert_eq!(state.deferred_fds.len(), 2);
        assert!(state
            .deferred_fds
            .contains_key(&(moved_meta.dev(), moved_meta.ino())));
        assert!(state
            .deferred_fds
            .contains_key(&(mut_meta.dev(), mut_meta.ino())));
    }

    // Only dropping the very last handle (ro2) clears deferred_fds.
    drop(ro2);
    {
        let state = reg.lock().unwrap();
        assert_eq!(state.active_writers, 0);
        assert!(state.counts.is_empty());
        assert!(state.deferred_fds.is_empty());
    }
}

#[test]
fn open_writable_guarded_error_and_deferred_fd_cap_fail_closed() {
    static REG: OnceLock<Mutex<ActiveHandleRegistry>> = OnceLock::new();
    let reg = REG.get_or_init(|| Mutex::new(ActiveHandleRegistry::default()));

    let dir = TempDir::new().unwrap();
    let writer_path = write_valid_header_file(&dir.path().join("writer.sqlite"));
    let missing_path = dir.path().join("does_not_exist.sqlite");

    let err: Result<((), ActiveHandleGuard), LedgerError> =
        open_writable_guarded_in(reg, &writer_path, || {
            Err(LedgerError::Storage("simulated open failure".into()))
        });
    assert!(matches!(err, Err(LedgerError::Storage(_))));
    assert_eq!(reg.lock().unwrap().active_writers, 0);

    let err = open_writable_guarded_in(reg, &missing_path, || Ok(()));
    assert!(matches!(err, Err(LedgerError::Storage(_))));
    assert_eq!(reg.lock().unwrap().active_writers, 0);

    #[cfg(unix)]
    {
        let ((), writer_guard) = open_writable_guarded_in(reg, &writer_path, || Ok(())).unwrap();
        let mut first_target = None;
        for i in 0..MAX_DEFERRED_FDS {
            let target = write_valid_header_file(&dir.path().join(format!("ro_target_{i}.sqlite")));
            if first_target.is_none() {
                first_target = Some(target.clone());
            }
            let ((), ro) = open_read_only_guarded_in(reg, &target, |_| Ok(())).unwrap();
            drop(ro);
        }
        assert_eq!(reg.lock().unwrap().total_deferred_fds(), MAX_DEFERRED_FDS);

        // Already-cached inode reuses its deferred fd even at the total-fd cap.
        let ((), ro_cached) =
            open_read_only_guarded_in(reg, first_target.as_ref().unwrap(), |_| Ok(())).unwrap();
        drop(ro_cached);
        assert_eq!(reg.lock().unwrap().total_deferred_fds(), MAX_DEFERRED_FDS);

        // Next distinct inode and uncached non-empty -journal both fail closed BEFORE opening.
        let overflow = write_valid_header_file(&dir.path().join("ro_target_overflow.sqlite"));
        let uncached_journal = dir.path().join("uncached_cap.sqlite-journal");
        fs::write(&uncached_journal, [0u8; ROLLBACK_JOURNAL_HDR_LEN]).unwrap();
        let calls_before = raw_open_calls();
        assert!(matches!(
            open_read_only_guarded_in(reg, &overflow, |_| Ok(())),
            Err(LedgerError::Storage(_))
        ));
        assert_eq!(
            raw_open_calls(),
            calls_before,
            "header inspection cap check must reject before calling open_no_follow_read_only"
        );
        assert!(matches!(
            probe_rollback_journal_once(reg, &uncached_journal),
            Err(LedgerError::Storage(_))
        ));
        assert_eq!(
            raw_open_calls(),
            calls_before,
            "journal cap check must reject before calling open_no_follow_read_only"
        );
        assert_eq!(reg.lock().unwrap().total_deferred_fds(), MAX_DEFERRED_FDS);

        drop(writer_guard);
        assert!(reg.lock().unwrap().deferred_fds.is_empty());
        let calls_before_clean = raw_open_calls();
        assert_eq!(
            probe_rollback_journal_once(reg, &uncached_journal).unwrap(),
            JournalProbe::Clean
        );
        assert_eq!(
            raw_open_calls(),
            calls_before_clean + 1,
            "positive control: uncached clean journal probe must record one raw open"
        );
        let ((), ro_after) = open_read_only_guarded_in(reg, &overflow, |_| Ok(())).unwrap();
        drop(ro_after);
        assert!(reg.lock().unwrap().deferred_fds.is_empty());

        assert_duplicate_inode_cap_and_journal_guard(
            reg,
            &writer_path,
            first_target.as_ref().unwrap(),
            &overflow,
            &uncached_journal,
        );
    }
}

#[cfg(unix)]
fn assert_duplicate_inode_cap_and_journal_guard(
    reg: &'static Mutex<ActiveHandleRegistry>,
    writer_path: &Path,
    dup_source: &Path,
    overflow: &Path,
    uncached_journal: &Path,
) {
    use std::os::unix::fs::MetadataExt;

    let ((), writer_guard) = open_writable_guarded_in(reg, writer_path, || Ok(())).unwrap();
    let meta = fs::metadata(dup_source).unwrap();
    let key = (meta.dev(), meta.ino());
    {
        let mut state = reg.lock().unwrap();
        for _ in 0..MAX_DEFERRED_FDS {
            state.maybe_defer_fd(key, File::open(dup_source).unwrap());
        }
        assert_eq!(state.deferred_fds.len(), 1);
        assert_eq!(state.deferred_fds[&key].len(), MAX_DEFERRED_FDS);
        assert_eq!(state.total_deferred_fds(), MAX_DEFERRED_FDS);
    }
    let calls_before = raw_open_calls();
    assert!(matches!(
        open_read_only_guarded_in(reg, overflow, |_| Ok(())),
        Err(LedgerError::Storage(_))
    ));
    assert_eq!(
        raw_open_calls(),
        calls_before,
        "header inspection cap check on duplicate-inode pool must reject before opening"
    );
    assert!(matches!(
        probe_rollback_journal_once(reg, uncached_journal),
        Err(LedgerError::Storage(_))
    ));
    assert_eq!(
        raw_open_calls(),
        calls_before,
        "journal cap check on duplicate-inode pool must reject before opening"
    );
    assert_eq!(reg.lock().unwrap().total_deferred_fds(), MAX_DEFERRED_FDS);

    // Pushing an extra duplicate on the occupied key retains it rather than dropping while active.
    {
        let mut state = reg.lock().unwrap();
        state.maybe_defer_fd(key, File::open(dup_source).unwrap());
        assert_eq!(state.deferred_fds[&key].len(), MAX_DEFERRED_FDS + 1);
        assert_eq!(state.total_deferred_fds(), MAX_DEFERRED_FDS + 1);
    }
    drop(writer_guard);
    assert!(reg.lock().unwrap().deferred_fds.is_empty());
}
#[cfg(unix)]
fn assert_supported_unix_open_flag(flag: Option<i32>, name: &str) -> bool {
    if cfg!(any(
        all(
            any(target_os = "linux", target_os = "android"),
            any(
                target_arch = "x86_64",
                target_arch = "x86",
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "riscv32",
                target_arch = "riscv64",
                target_arch = "powerpc",
                target_arch = "powerpc64",
                target_arch = "s390x",
                target_arch = "loongarch64",
                target_arch = "m68k",
                target_arch = "mips",
                target_arch = "mips32r6",
                target_arch = "mips64",
                target_arch = "mips64r6",
                target_arch = "sparc",
                target_arch = "sparc64"
            )
        ),
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )) {
        assert!(
            flag.is_some(),
            "{name} must be defined on all supported Unix targets"
        );
        true
    } else {
        false
    }
}

#[cfg(unix)]
#[test]
fn open_no_follow_read_only_rejects_symlinks_atomically() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    let target = dir.path().join("target.journal");
    fs::write(&target, b"rollback-payload").unwrap();

    // Positive control: regular file opens cleanly.
    let mut ok_file = open_no_follow_read_only(&target).unwrap();
    let mut buf = Vec::new();
    ok_file.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"rollback-payload");

    if !assert_supported_unix_open_flag(UNIX_O_NOFOLLOW, "UNIX_O_NOFOLLOW") {
        return;
    }

    // Derive the platform-native ELOOP io::Error (`ErrorKind::FilesystemLoop` is unstable behind
    // `io_error_more`) only on targets where O_NOFOLLOW returns ELOOP. FreeBSD/DragonFlyBSD return
    // EMLINK and NetBSD returns EFTYPE, so those targets assert only `err.kind() != NotFound`.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "openbsd"
    ))]
    let expected_eloop = {
        let loop_a = dir.path().join("eloop_a.journal");
        let loop_b = dir.path().join("eloop_b.journal");
        symlink(&loop_b, &loop_a).unwrap();
        symlink(&loop_a, &loop_b).unwrap();
        let eloop = fs::metadata(&loop_a).unwrap_err();
        assert!(eloop.raw_os_error().is_some());
        eloop
    };

    // Direct call on symlink to existing target (without symlink_metadata) fails atomically via
    // O_NOFOLLOW (never follows to Ok(File) or NotFound).
    let live_sym = dir.path().join("live_sym.journal");
    symlink(&target, &live_sym).unwrap();
    let err = open_no_follow_read_only(&live_sym).unwrap_err();
    assert_ne!(
        err.kind(),
        io::ErrorKind::NotFound,
        "symlink open must not be misclassified as NotFound: {err:?}"
    );
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "openbsd"
    ))]
    {
        assert_eq!(
            err.kind(),
            expected_eloop.kind(),
            "expected ELOOP ErrorKind from O_NOFOLLOW, got: {err:?}"
        );
        assert_eq!(
            err.raw_os_error(),
            expected_eloop.raw_os_error(),
            "expected OS ELOOP errno from O_NOFOLLOW, got: {err:?}"
        );
    }

    // Direct call on dangling symlink also fails atomically via O_NOFOLLOW (never NotFound / Clean).
    let dangling_sym = dir.path().join("dangling_sym.journal");
    symlink(dir.path().join("missing_target.journal"), &dangling_sym).unwrap();
    let dangling_err = open_no_follow_read_only(&dangling_sym).unwrap_err();
    assert_ne!(
        dangling_err.kind(),
        io::ErrorKind::NotFound,
        "dangling symlink must fail via O_NOFOLLOW, not NotFound: {dangling_err:?}"
    );
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "openbsd"
    ))]
    {
        assert_eq!(
            dangling_err.kind(),
            expected_eloop.kind(),
            "expected ELOOP ErrorKind on dangling symlink, got: {dangling_err:?}"
        );
        assert_eq!(
            dangling_err.raw_os_error(),
            expected_eloop.raw_os_error(),
            "expected OS ELOOP errno on dangling symlink, got: {dangling_err:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn reader_only_deferred_fds_prune_on_last_inode_drop_and_clear_on_final_reader_drop() {
    static REG: OnceLock<Mutex<ActiveHandleRegistry>> = OnceLock::new();
    let reg = REG.get_or_init(|| Mutex::new(ActiveHandleRegistry::default()));

    let dir = TempDir::new().unwrap();
    let db_a = write_valid_header_file(&dir.path().join("ro_only_a.sqlite"));
    let db_b = write_valid_header_file(&dir.path().join("ro_only_b.sqlite"));
    let bad_c = dir.path().join("ro_only_bad_c.sqlite");
    fs::write(&bad_c, [0u8; SQLITE_HEADER_LEN]).unwrap();
    let bad_c = fs::canonicalize(&bad_c).unwrap();

    let ((), ro_a) = open_read_only_guarded_in(reg, &db_a, |_| Ok(())).unwrap();
    {
        let state = reg.lock().unwrap();
        assert_eq!(state.active_writers, 0);
        assert_eq!(state.counts.len(), 1);
        assert!(state.deferred_fds.is_empty());
    }

    // With active_writers == 0, opening an unrelated db_b, probing bad_c, or probing 70 distinct
    // failed headers and rollback journals must NOT accumulate uncounted entries in deferred_fds.
    let ((), ro_b1) = open_read_only_guarded_in(reg, &db_b, |_| Ok(())).unwrap();
    let ((), ro_b2) = open_read_only_guarded_in(reg, &db_b, |_| Ok(())).unwrap();
    assert!(reg.lock().unwrap().deferred_fds.is_empty());

    // Hard-linked journal probe on tracked inode db_b MUST defer db_b's fd while db_b is active,
    // keep it when ro_b1 drops (counts[db_b] == 1), and prune it when ro_b2 drops while ro_a lives.
    let db_b_hl_journal = dir.path().join("hl_db_b.sqlite-journal");
    fs::hard_link(&db_b, &db_b_hl_journal).unwrap();
    assert!(matches!(
        probe_rollback_journal_once(reg, &db_b_hl_journal),
        Err(LedgerError::Integrity(_))
    ));
    fs::remove_file(&db_b_hl_journal).unwrap();
    assert_eq!(reg.lock().unwrap().deferred_fds.len(), 1);
    drop(ro_b1);
    assert_eq!(reg.lock().unwrap().deferred_fds.len(), 1);
    drop(ro_b2);
    {
        let state = reg.lock().unwrap();
        assert_eq!(state.active_writers, 0);
        assert_eq!(state.counts.len(), 1);
        assert!(state.deferred_fds.is_empty());
    }

    // 70 distinct failed header probes + 70 distinct journal probes while ro_a is active must NOT
    // retain uncounted fds or exhaust MAX_DEFERRED_FDS (64), leaving subsequent valid audits green.
    assert!(matches!(
        open_read_only_guarded_in(reg, &bad_c, |_| Ok(())),
        Err(LedgerError::Integrity(_))
    ));
    for i in 0..70 {
        let bad_i = dir.path().join(format!("bad_hdr_{i}.sqlite"));
        fs::write(&bad_i, [0u8; SQLITE_HEADER_LEN]).unwrap();
        let bad_i = fs::canonicalize(&bad_i).unwrap();
        assert!(matches!(
            open_read_only_guarded_in(reg, &bad_i, |_| Ok(())),
            Err(LedgerError::Integrity(_))
        ));

        let jrnl_i = dir.path().join(format!("probe_{i}.sqlite-journal"));
        fs::write(&jrnl_i, [0u8; ROLLBACK_JOURNAL_HDR_LEN]).unwrap();
        assert_eq!(
            probe_rollback_journal_once(reg, &jrnl_i).unwrap(),
            JournalProbe::Clean
        );
    }
    assert!(reg.lock().unwrap().deferred_fds.is_empty());
    let ((), ro_after) = open_read_only_guarded_in(reg, &db_b, |_| Ok(())).unwrap();
    drop(ro_after);

    drop(ro_a);
    {
        let state = reg.lock().unwrap();
        assert_eq!(state.active_writers, 0);
        assert!(state.counts.is_empty());
        assert!(state.deferred_fds.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn unix_open_flags_combination_and_symlink_fallback_guard() {
    assert_eq!(combine_unix_open_flags(Some(0x20000), Some(0x800)), 0x20800);
    assert_eq!(combine_unix_open_flags(Some(0x8000), None), 0x8000);
    assert_eq!(combine_unix_open_flags(None, Some(0x0004)), 0x0004);
    assert_eq!(combine_unix_open_flags(None, None), 0);

    let p = Path::new("/tmp/fake.sqlite-journal");
    assert!(matches!(
        reject_symlink_without_o_nofollow(false, true, p),
        Err(LedgerError::Integrity(ref m)) if m.contains("symlink")
    ));
    reject_symlink_without_o_nofollow(true, true, p).unwrap();
    reject_symlink_without_o_nofollow(false, false, p).unwrap();
}

#[cfg(unix)]
#[test]
fn post_open_non_file_guards_and_nonblock_fifo_reject_without_blocking() {
    use std::process::Command;

    let dir = TempDir::new().unwrap();
    let mut reg = ActiveHandleRegistry {
        active_writers: 1,
        ..Default::default()
    };

    // 1. Direct post-open !meta.is_file() guard in read_rollback_journal_from_file on /dev/null.
    let dev_null = Path::new("/dev/null");
    let mut null_file = File::open(dev_null).unwrap();
    let jrnl_err = read_rollback_journal_from_file(&mut null_file, dev_null).unwrap_err();
    assert!(
        matches!(&jrnl_err, LedgerError::Integrity(m) if m.contains("invalid non-file")),
        "expected invalid non-file error from read_rollback_journal_from_file, got: {jrnl_err:?}"
    );

    // 2. Direct post-open !meta.is_file() guard in inspect_sqlite_header_locked on /dev/null.
    let hdr_null_err = inspect_sqlite_header_locked(&mut reg, dev_null).unwrap_err();
    assert!(
        matches!(&hdr_null_err, LedgerError::Integrity(m) if m.contains("not a regular file")),
        "expected not a regular file error from inspect_sqlite_header_locked(/dev/null), got: {hdr_null_err:?}"
    );
    assert!(
        reg.deferred_fds.is_empty(),
        "non-regular file must never be inserted into deferred_fds"
    );

    if !assert_supported_unix_open_flag(UNIX_O_NONBLOCK, "UNIX_O_NONBLOCK") {
        return;
    }

    // 3. Writerless FIFO: O_NONBLOCK ensures open returns immediately (no deadlock under mutex)
    //    and post-open !meta.is_file() rejects it cleanly in both header and journal helpers.
    //    Run inside a child thread with a bounded deadline so mutating UNIX_O_NONBLOCK to Some(0)
    //    or omitting it fails cleanly with a timeout panic instead of hanging forever.
    let fifo = dir.path().join("writerless.fifo");
    let mkfifo_status = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(mkfifo_status.success(), "mkfifo must succeed");

    let fifo_for_thread = fifo.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let mut thread_reg = ActiveHandleRegistry {
            active_writers: 1,
            ..Default::default()
        };
        let hdr_fifo_res = inspect_sqlite_header_locked(&mut thread_reg, &fifo_for_thread);
        let deferred_empty = thread_reg.deferred_fds.is_empty();
        let mut fifo_file = open_no_follow_read_only(&fifo_for_thread).unwrap();
        let jrnl_fifo_res = read_rollback_journal_from_file(&mut fifo_file, &fifo_for_thread);
        let _ = tx.send((hdr_fifo_res, deferred_empty, jrnl_fifo_res));
    });

    let (hdr_fifo_res, deferred_empty, jrnl_fifo_res) = rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("writerless FIFO probe timed out after 2s (missing O_NONBLOCK?)");
    handle.join().unwrap();

    let hdr_fifo_err = hdr_fifo_res.unwrap_err();
    assert!(
        matches!(&hdr_fifo_err, LedgerError::Integrity(m) if m.contains("not a regular file")),
        "expected not a regular file error on writerless FIFO, got: {hdr_fifo_err:?}"
    );
    assert!(deferred_empty);

    let jrnl_fifo_err = jrnl_fifo_res.unwrap_err();
    assert!(
        matches!(&jrnl_fifo_err, LedgerError::Integrity(m) if m.contains("invalid non-file")),
        "expected invalid non-file error on writerless FIFO journal, got: {jrnl_fifo_err:?}"
    );
}

#[cfg(unix)]
#[test]
fn probe_rollback_journal_once_and_header_inspect_reject_symlinks_via_o_nofollow() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    let reg = Mutex::new(ActiveHandleRegistry::default());

    // Target is a 32-byte all-zero regular file (which read_rollback_journal_from_file would treat
    // as JournalProbe::Clean if followed!). Calling probe_rollback_journal_once directly on a
    // symlink to it proves production probing uses open_no_follow_read_only (O_NOFOLLOW).
    let zero_target = dir.path().join("zero_target.journal");
    fs::write(&zero_target, [0u8; 32]).unwrap();
    let sym_journal = dir.path().join("sym.sqlite-journal");
    symlink(&zero_target, &sym_journal).unwrap();

    let sym_err = probe_rollback_journal_once(&reg, &sym_journal).unwrap_err();
    assert!(
        matches!(&sym_err, LedgerError::Integrity(m) if m.contains("symlink")),
        "expected symlink Integrity error from probe_rollback_journal_once, got: {sym_err:?}"
    );

    // Dangling symlink must also fail with Integrity (never Clean/NotFound).
    let dangling = dir.path().join("dangling.sqlite-journal");
    symlink(dir.path().join("missing_target.journal"), &dangling).unwrap();
    let dangling_err = probe_rollback_journal_once(&reg, &dangling).unwrap_err();
    assert!(
        matches!(&dangling_err, LedgerError::Integrity(m) if m.contains("symlink")),
        "expected symlink Integrity error on dangling journal symlink, got: {dangling_err:?}"
    );

    // Replacing canonical with a symlink is rejected both by stat_read_only_regular_file
    // (fs::symlink_metadata) and atomically by inspect_sqlite_header_locked (O_NOFOLLOW).
    let valid_db = write_valid_header_file(&dir.path().join("valid_target.sqlite"));
    let sym_db = dir.path().join("sym_canonical.sqlite");
    symlink(&valid_db, &sym_db).unwrap();

    let stat_err = stat_read_only_regular_file(&sym_db).unwrap_err();
    assert!(
        matches!(&stat_err, LedgerError::Integrity(m) if m.contains("not a regular file")),
        "expected not a regular file error from stat_read_only_regular_file on symlink, got: {stat_err:?}"
    );

    if assert_supported_unix_open_flag(UNIX_O_NOFOLLOW, "UNIX_O_NOFOLLOW") {
        let mut reg_state = ActiveHandleRegistry::default();
        let hdr_err = inspect_sqlite_header_locked(&mut reg_state, &sym_db).unwrap_err();
        assert!(
            matches!(hdr_err, LedgerError::Integrity(_)),
            "expected Integrity error from inspect_sqlite_header_locked on symlink, got: {hdr_err:?}"
        );
    }
}

fn assert_concurrent_open_rejected<F>(canonical: &Path, mutate: F)
where
    F: FnOnce(&Path),
{
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    struct ConnDropProbe(Arc<AtomicBool>);
    impl Drop for ConnDropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let orig_id = FileIdentity::from_path(canonical).unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let err = open_read_only_guarded(canonical, |path| {
        mutate(path);
        Ok(ConnDropProbe(Arc::clone(&dropped)))
    })
    .err()
    .expect("concurrent path mutation during open_conn must fail closed");
    assert!(
        matches!(&err, LedgerError::Integrity(m) if m == "read-only ledger path changed concurrently during open"),
        "unexpected error on concurrent open mutation: {err:?}"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "conn must be dropped immediately"
    );
    let registry = lock_registry(active_handles());
    assert_eq!(registry.active_count_by_id(&orig_id), 0);
}

#[test]
fn open_read_only_guarded_rejects_concurrent_path_replacement_and_drops_conn() {
    let dir = TempDir::new().unwrap();

    // Unix verifies immutable `(st_dev, st_ino)` identity as well as symlink substitution.
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let other_db = write_valid_header_file(&dir.path().join("other.sqlite"));
        let swap_inode = write_valid_header_file(&dir.path().join("swap_inode.sqlite"));
        assert_concurrent_open_rejected(&swap_inode, |path| {
            let replacement = dir.path().join("replacement_inode.sqlite");
            write_valid_header_file(&replacement);
            fs::rename(&replacement, path).unwrap();
        });

        let swap_sym = write_valid_header_file(&dir.path().join("swap_symlink.sqlite"));
        assert_concurrent_open_rejected(&swap_sym, |path| {
            fs::remove_file(path).unwrap();
            symlink(&other_db, path).unwrap();
        });
    }

    // Windows post-open check rejects symlink substitution when symlink privileges are enabled
    // (without claiming Unix inode-level identity on non-Unix platforms).
    #[cfg(windows)]
    {
        use std::os::windows::fs::symlink_file;

        let other_db = write_valid_header_file(&dir.path().join("other_win.sqlite"));
        let probe_sym = dir.path().join("probe_win_symlink.sqlite");
        if symlink_file(&other_db, &probe_sym).is_ok() {
            let _ = fs::remove_file(&probe_sym);
            let swap_sym = write_valid_header_file(&dir.path().join("swap_win_symlink.sqlite"));
            assert_concurrent_open_rejected(&swap_sym, |path| {
                fs::remove_file(path).unwrap();
                symlink_file(&other_db, path).unwrap();
            });
        }
    }

    // Portable post-open checks (Unix and non-Unix): concurrent unlink and directory substitution.
    let unlink_db = write_valid_header_file(&dir.path().join("unlink_during_open.sqlite"));
    assert_concurrent_open_rejected(&unlink_db, |path| {
        fs::remove_file(path).unwrap();
    });

    let dir_db = write_valid_header_file(&dir.path().join("dir_during_open.sqlite"));
    assert_concurrent_open_rejected(&dir_db, |path| {
        fs::remove_file(path).unwrap();
        fs::create_dir(path).unwrap();
    });
}

#[test]
fn file_identity_and_post_open_check_tolerate_in_place_file_growth() {
    use std::io::Write;

    let dir = TempDir::new().unwrap();
    let growing_db = write_valid_header_file(&dir.path().join("growing.sqlite"));
    let id_before = FileIdentity::from_path(&growing_db).unwrap();

    // Growing the same file during open (e.g. concurrent page write / schema init) must never
    // mutate `FileIdentity` or trigger a spurious post-open Integrity error or refcount leak.
    let ((), guard) = open_read_only_guarded(&growing_db, |path| {
        let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(&[0u8; 4096]).unwrap();
        Ok(())
    })
    .unwrap();
    let id_after = FileIdentity::from_path(&growing_db).unwrap();
    assert_eq!(id_before, id_after);
    assert_eq!(active_handle_count(&growing_db), 1);
    drop(guard);
    assert_eq!(active_handle_count(&growing_db), 0);
}

#[cfg(unix)]
#[test]
fn cached_rollback_journal_fd_rewinds_to_start_on_repeated_clean_probes() {
    static REG: OnceLock<Mutex<ActiveHandleRegistry>> = OnceLock::new();
    let reg = REG.get_or_init(|| Mutex::new(ActiveHandleRegistry::default()));

    let dir = TempDir::new().unwrap();
    let db = write_valid_header_file(&dir.path().join("rewind_db.sqlite"));
    let journal = dir.path().join("rewind_db.sqlite-journal");
    fs::write(&journal, [0u8; ROLLBACK_JOURNAL_HDR_LEN]).unwrap();

    let ((), writer_guard) = open_writable_guarded_in(reg, &db, || Ok(())).unwrap();

    let first = probe_rollback_journal_once(reg, &journal).unwrap();
    assert_eq!(first, JournalProbe::Clean);
    assert_eq!(reg.lock().unwrap().total_deferred_fds(), 1);

    // Second probe hits deferred_fds cache and MUST rewind via seek(SeekFrom::Start(0));
    // without rewind, read_exact hits EOF and misclassifies the clean journal as Hot.
    let second = probe_rollback_journal_once(reg, &journal).unwrap();
    assert_eq!(second, JournalProbe::Clean);
    assert_eq!(reg.lock().unwrap().total_deferred_fds(), 1);

    // In-place update to non-zero hot bytes is observed via the rewound cached fd.
    fs::write(&journal, [0xd9u8; ROLLBACK_JOURNAL_HDR_LEN]).unwrap();
    let third = probe_rollback_journal_once(reg, &journal).unwrap();
    assert_eq!(third, JournalProbe::Hot);
    assert_eq!(reg.lock().unwrap().total_deferred_fds(), 1);

    drop(writer_guard);
    assert!(reg.lock().unwrap().deferred_fds.is_empty());
}
