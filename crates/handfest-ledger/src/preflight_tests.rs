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

#[test]
fn deferred_fds_never_reuse_handles_retain_for_readers_and_clear_only_when_all_drop() {
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

    // Each unindexed raw open pushes a fresh File (never reused).
    let canonical_moved = fs::canonicalize(&moved).unwrap();
    let ((), ro1) = open_read_only_guarded_in(reg, &canonical_moved, |_| Ok(())).unwrap();
    assert_eq!(reg.lock().unwrap().deferred_fds.len(), 1);
    drop(ro1);

    let ((), ro2) = open_read_only_guarded_in(reg, &canonical_moved, |_| Ok(())).unwrap();
    assert_eq!(reg.lock().unwrap().deferred_fds.len(), 2);

    // Journal probe while handles are active also defers its fd; failed header inspect too.
    let bad_magic = dir.path().join("bad_magic_deferred.sqlite");
    fs::write(&bad_magic, [0u8; SQLITE_HEADER_LEN]).unwrap();
    let canonical_bad = fs::canonicalize(&bad_magic).unwrap();
    assert!(matches!(
        open_read_only_guarded_in(reg, &canonical_bad, |_| Ok(())),
        Err(LedgerError::Integrity(_))
    ));
    assert_eq!(reg.lock().unwrap().deferred_fds.len(), 3);

    // Dropping writer while ro2 is STILL active MUST NOT clear deferred_fds.
    drop(writer_guard);
    {
        let state = reg.lock().unwrap();
        assert_eq!(state.active_writers, 0);
        assert!(!state.counts.is_empty());
        assert_eq!(state.deferred_fds.len(), 3);
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

    let ((), writer_guard) = open_writable_guarded_in(reg, &writer_path, || Ok(())).unwrap();
    let target = write_valid_header_file(&dir.path().join("ro_target.sqlite"));
    for _ in 0..MAX_DEFERRED_FDS {
        let ((), ro) = open_read_only_guarded_in(reg, &target, |_| Ok(())).unwrap();
        drop(ro);
    }
    assert_eq!(reg.lock().unwrap().deferred_fds.len(), MAX_DEFERRED_FDS);

    // Next raw open fails closed with Storage BEFORE opening another fd.
    assert!(matches!(
        open_read_only_guarded_in(reg, &target, |_| Ok(())),
        Err(LedgerError::Storage(_))
    ));
    // Direct maybe_defer_fd cap guard also fails closed with Storage.
    let extra_file = File::open(&target).unwrap();
    assert!(matches!(
        reg.lock().unwrap().maybe_defer_fd(extra_file),
        Err(LedgerError::Storage(_))
    ));

    drop(writer_guard);
    assert!(reg.lock().unwrap().deferred_fds.is_empty());
    let ((), ro_after) = open_read_only_guarded_in(reg, &target, |_| Ok(())).unwrap();
    drop(ro_after);
    assert!(reg.lock().unwrap().deferred_fds.is_empty());
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

    // Direct call on symlink to existing target (without symlink_metadata) fails atomically with ELOOP.
    let live_sym = dir.path().join("live_sym.journal");
    symlink(&target, &live_sym).unwrap();
    let err = open_no_follow_read_only(&live_sym).unwrap_err();
    assert_ne!(
        err.kind(),
        io::ErrorKind::NotFound,
        "symlink open must not be misclassified as NotFound: {err:?}"
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        err.raw_os_error(),
        Some(40),
        "expected Linux ELOOP (40) from O_NOFOLLOW, got: {err:?}"
    );

    // Direct call on dangling symlink also fails atomically with ELOOP (never NotFound / Clean).
    let dangling_sym = dir.path().join("dangling_sym.journal");
    symlink(dir.path().join("missing_target.journal"), &dangling_sym).unwrap();
    let dangling_err = open_no_follow_read_only(&dangling_sym).unwrap_err();
    assert_ne!(
        dangling_err.kind(),
        io::ErrorKind::NotFound,
        "dangling symlink must fail with ELOOP, not NotFound: {dangling_err:?}"
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        dangling_err.raw_os_error(),
        Some(40),
        "expected Linux ELOOP (40) on dangling symlink, got: {dangling_err:?}"
    );
}

#[test]
fn reader_only_deferred_fds_retain_with_zero_writers_and_clear_on_reader_drop() {
    static REG: OnceLock<Mutex<ActiveHandleRegistry>> = OnceLock::new();
    let reg = REG.get_or_init(|| Mutex::new(ActiveHandleRegistry::default()));

    let dir = TempDir::new().unwrap();
    let db_a = write_valid_header_file(&dir.path().join("ro_only_a.sqlite"));
    let db_b = write_valid_header_file(&dir.path().join("ro_only_b.sqlite"));

    let ((), ro_a) = open_read_only_guarded_in(reg, &db_a, |_| Ok(())).unwrap();
    {
        let state = reg.lock().unwrap();
        assert_eq!(state.active_writers, 0);
        assert_eq!(state.counts.len(), 1);
        assert!(state.deferred_fds.is_empty());
    }

    // Fresh raw header open on a second DB while active_writers == 0 must defer its fd.
    let ((), ro_b) = open_read_only_guarded_in(reg, &db_b, |_| Ok(())).unwrap();
    assert_eq!(reg.lock().unwrap().deferred_fds.len(), 1);
    drop(ro_b);
    {
        let state = reg.lock().unwrap();
        assert_eq!(state.active_writers, 0);
        assert_eq!(state.counts.len(), 1);
        assert_eq!(state.deferred_fds.len(), 1);
    }

    drop(ro_a);
    {
        let state = reg.lock().unwrap();
        assert_eq!(state.active_writers, 0);
        assert!(state.counts.is_empty());
        assert!(state.deferred_fds.is_empty());
    }
}
