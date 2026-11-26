//! Shared Unix cross-process `SQLITE_BUSY` lock-probe helper for `sqlite_tests` and
//! `preflight_tests`.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

const DB_PATH_ENV: &str = "HANDFEST_LOCK_PROBE_DB";
const EXPECT_LOCKED_ENV: &str = "HANDFEST_LOCK_PROBE_EXPECT_LOCKED";
const PROBE_TEST_NAME: &str = "lock_probe_test_util::cross_process_exclusive_lock_probe_helper";
const PROBE_VERIFIED_PREFIX: &str = "HANDFEST_LOCK_PROBE_VERIFIED=";

fn parse_probe_env(
    db_path: Option<OsString>,
    expect_locked_raw: Option<OsString>,
) -> Option<(PathBuf, bool)> {
    match (db_path, expect_locked_raw) {
        (None, None) => None,
        (None, Some(expect)) => panic!(
            "{EXPECT_LOCKED_ENV} ({expect:?}) set without {DB_PATH_ENV}; refusing silent pass"
        ),
        (Some(path), None) => {
            panic!("{DB_PATH_ENV} ({path:?}) set without {EXPECT_LOCKED_ENV}; refusing silent pass")
        }
        (Some(path), Some(expect)) => {
            assert!(
                !path.is_empty(),
                "{DB_PATH_ENV} must be a non-empty database path"
            );
            let expect_locked = match expect.to_str() {
                Some("1") => true,
                Some("0") => false,
                other => panic!(
                    "invalid {EXPECT_LOCKED_ENV}={expect:?} (utf8={other:?}); expected '0' or '1'"
                ),
            };
            Some((PathBuf::from(path), expect_locked))
        }
    }
}

#[test]
fn cross_process_exclusive_lock_probe_helper() {
    let Some((db_path, expect_locked)) = parse_probe_env(
        std::env::var_os(DB_PATH_ENV),
        std::env::var_os(EXPECT_LOCKED_ENV),
    ) else {
        return;
    };
    let conn = rusqlite::Connection::open(&db_path).expect("probe open");
    conn.busy_timeout(Duration::ZERO).unwrap();
    let res = conn.execute_batch("BEGIN EXCLUSIVE; ROLLBACK;");
    if expect_locked {
        match res {
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::DatabaseBusy => {}
            other => panic!(
                "expected parent POSIX lock to fail with DatabaseBusy (SQLITE_BUSY), got: {other:?}"
            ),
        }
        println!("{PROBE_VERIFIED_PREFIX}locked");
    } else {
        res.expect("expected child EXCLUSIVE lock to succeed after parent lock ended");
        println!("{PROBE_VERIFIED_PREFIX}unlocked");
    }
}

fn spawn_lock_probe(db_path: Option<&OsStr>, expect_locked: Option<&OsStr>) -> Output {
    let exe = std::env::current_exe().expect("current test exe");
    let mut cmd = Command::new(&exe);
    cmd.args(["--exact", PROBE_TEST_NAME, "--nocapture"]);
    match db_path {
        Some(path) => {
            cmd.env(DB_PATH_ENV, path);
        }
        None => {
            cmd.env_remove(DB_PATH_ENV);
        }
    }
    match expect_locked {
        Some(val) => {
            cmd.env(EXPECT_LOCKED_ENV, val);
        }
        None => {
            cmd.env_remove(EXPECT_LOCKED_ENV);
        }
    }
    cmd.output().expect("spawn exclusive lock probe")
}

fn verify_lock_probe_output(output: &Output, expect_locked: bool) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "cross-process BEGIN EXCLUSIVE probe failed (expect_locked={expect_locked})\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("1 passed"),
        "cross-process BEGIN EXCLUSIVE probe did not execute helper test (expect_locked={expect_locked}); stdout:\n{stdout}"
    );
    let expected_marker = if expect_locked {
        format!("{PROBE_VERIFIED_PREFIX}locked")
    } else {
        format!("{PROBE_VERIFIED_PREFIX}unlocked")
    };
    assert!(
        stdout.lines().any(|line| line.trim() == expected_marker),
        "cross-process BEGIN EXCLUSIVE probe returned without executing SQLite check (missing '{expected_marker}'); stdout:\n{stdout}"
    );
}

pub(crate) fn assert_cross_process_exclusive_lock(db_path: &Path, expect_locked: bool) {
    let output = spawn_lock_probe(
        Some(db_path.as_os_str()),
        Some(OsStr::new(if expect_locked { "1" } else { "0" })),
    );
    verify_lock_probe_output(&output, expect_locked);
}

#[test]
fn cross_process_lock_probe_supports_non_utf8_paths() {
    use std::os::unix::ffi::OsStrExt;
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let db_path = dir
        .path()
        .join(OsStr::from_bytes(b"non_utf8_\xff_probe.sqlite"));
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch("CREATE TABLE t(x INTEGER); BEGIN EXCLUSIVE;")
        .unwrap();

    assert_cross_process_exclusive_lock(&db_path, true);

    conn.execute_batch("ROLLBACK;").unwrap();
    assert_cross_process_exclusive_lock(&db_path, false);
}

#[test]
fn cross_process_lock_probe_rejects_missing_or_invalid_env_and_silent_early_return() {
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("probe_guard.sqlite");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch("CREATE TABLE t(x INTEGER);").unwrap();
    drop(conn);

    // Missing DB path while EXPECT_LOCKED is set must fail the child (never silent pass).
    let missing_db = spawn_lock_probe(None, Some(OsStr::new("1")));
    assert!(
        !missing_db.status.success(),
        "expected child probe to fail when {DB_PATH_ENV} is missing"
    );

    // Empty DB path must fail the child (never open a fresh SQLite temporary DB).
    let empty_db = spawn_lock_probe(Some(OsStr::new("")), Some(OsStr::new("0")));
    assert!(
        !empty_db.status.success(),
        "expected child probe to fail on empty {DB_PATH_ENV}"
    );

    // Non-'0'/'1' EXPECT_LOCKED must fail the child rather than being treated as unlocked.
    let bad_expect = spawn_lock_probe(Some(db_path.as_os_str()), Some(OsStr::new("2")));
    assert!(
        !bad_expect.status.success(),
        "expected child probe to fail on invalid {EXPECT_LOCKED_ENV}='2'"
    );

    // Even when the child exits 0 with "1 passed" via early return (no env vars set),
    // parent verification MUST reject it because the SQLite verification sentinel is absent.
    let silent_early_return = spawn_lock_probe(None, None);
    assert!(silent_early_return.status.success());
    let verified = std::panic::catch_unwind(|| {
        verify_lock_probe_output(&silent_early_return, true);
    });
    assert!(
        verified.is_err(),
        "verify_lock_probe_output must reject silent early-return child output lacking sentinel"
    );
}
