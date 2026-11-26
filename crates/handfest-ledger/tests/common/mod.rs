//! Shared Unix cross-process SQLite lock-probe helpers for integration tests.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const DB_PATH_ENV: &str = "HANDFEST_INTEG_LOCK_PROBE_DB";
const PROBE_MODE_ENV: &str = "HANDFEST_INTEG_LOCK_PROBE_MODE";
const EXPECT_LOCKED_ENV: &str = "HANDFEST_INTEG_LOCK_PROBE_EXPECT_LOCKED";
const PROBE_VERIFIED_PREFIX: &str = "HANDFEST_INTEG_LOCK_PROBE_VERIFIED=";

fn parse_probe_env(
    db_path: Option<OsString>,
    mode_raw: Option<OsString>,
    expect_locked_raw: Option<OsString>,
) -> Option<(PathBuf, &'static str, &'static str, bool)> {
    match (db_path, mode_raw, expect_locked_raw) {
        (None, None, None) => None,
        (Some(path), Some(mode), Some(expect)) => {
            assert!(
                !path.is_empty(),
                "{DB_PATH_ENV} must be a non-empty database path"
            );
            let (mode_name, sql) = match mode.to_str() {
                Some("exclusive") => ("exclusive", "BEGIN EXCLUSIVE; ROLLBACK;"),
                Some("immediate") => ("immediate", "BEGIN IMMEDIATE; ROLLBACK;"),
                other => panic!(
                    "invalid {PROBE_MODE_ENV}={mode:?} (utf8={other:?}); expected 'exclusive' or 'immediate'"
                ),
            };
            let expect_locked = match expect.to_str() {
                Some("1") => true,
                Some("0") => false,
                other => panic!(
                    "invalid {EXPECT_LOCKED_ENV}={expect:?} (utf8={other:?}); expected '0' or '1'"
                ),
            };
            Some((PathBuf::from(path), mode_name, sql, expect_locked))
        }
        (db, mode, expect) => panic!(
            "partial lock-probe env ({DB_PATH_ENV}={db:?}, {PROBE_MODE_ENV}={mode:?}, {EXPECT_LOCKED_ENV}={expect:?}); refusing silent pass"
        ),
    }
}

pub(crate) fn run_lock_probe_helper() {
    let Some((db_path, mode_name, sql, expect_locked)) = parse_probe_env(
        std::env::var_os(DB_PATH_ENV),
        std::env::var_os(PROBE_MODE_ENV),
        std::env::var_os(EXPECT_LOCKED_ENV),
    ) else {
        return;
    };
    let conn = rusqlite::Connection::open(&db_path).expect("probe open");
    conn.busy_timeout(Duration::ZERO).unwrap();
    let res = conn.execute_batch(sql);
    if expect_locked {
        match res {
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::DatabaseBusy => {}
            other => panic!(
                "expected parent POSIX lock ({mode_name}) to fail with DatabaseBusy, got: {other:?}"
            ),
        }
        println!("{PROBE_VERIFIED_PREFIX}{mode_name}:locked");
    } else {
        res.expect("expected child lock probe to succeed after parent released transaction");
        println!("{PROBE_VERIFIED_PREFIX}{mode_name}:unlocked");
    }
}

pub(crate) fn assert_cross_process_lock(
    helper_test_name: &str,
    db_path: &Path,
    mode: &str,
    expect_locked: bool,
) {
    let exe = std::env::current_exe().expect("current test exe");
    let output = Command::new(&exe)
        .args(["--exact", helper_test_name, "--nocapture"])
        .env(DB_PATH_ENV, db_path)
        .env(PROBE_MODE_ENV, mode)
        .env(EXPECT_LOCKED_ENV, if expect_locked { "1" } else { "0" })
        .output()
        .expect("spawn cross-process lock probe");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "cross-process lock probe failed (mode={mode}, expect_locked={expect_locked})\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("1 passed"),
        "cross-process lock probe did not execute helper test (mode={mode}, expect_locked={expect_locked}); stdout:\n{stdout}"
    );
    let expected_marker = format!(
        "{PROBE_VERIFIED_PREFIX}{mode}:{}",
        if expect_locked { "locked" } else { "unlocked" }
    );
    assert!(
        stdout.lines().any(|line| line.trim() == expected_marker),
        "cross-process lock probe returned without executing SQLite check (missing '{expected_marker}'); stdout:\n{stdout}"
    );
}
