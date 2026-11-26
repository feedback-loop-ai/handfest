//! Shared Unix cross-process `SQLITE_BUSY` lock-probe helper for `sqlite_tests` and
//! `preflight_tests`.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

const DB_PATH_ENV: &str = "HANDFEST_LOCK_PROBE_DB";
const EXPECT_LOCKED_ENV: &str = "HANDFEST_LOCK_PROBE_EXPECT_LOCKED";
const PROBE_TEST_NAME: &str = "lock_probe_test_util::cross_process_exclusive_lock_probe_helper";

#[test]
fn cross_process_exclusive_lock_probe_helper() {
    let Ok(db_path) = std::env::var(DB_PATH_ENV) else {
        return;
    };
    let conn = rusqlite::Connection::open(&db_path).expect("probe open");
    conn.busy_timeout(Duration::ZERO).unwrap();
    let res = conn.execute_batch("BEGIN EXCLUSIVE; ROLLBACK;");
    let expect_locked = std::env::var(EXPECT_LOCKED_ENV).as_deref() == Ok("1");
    if expect_locked {
        match res {
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::DatabaseBusy => {}
            other => panic!(
                "expected parent POSIX lock to fail with DatabaseBusy (SQLITE_BUSY), got: {other:?}"
            ),
        }
    } else {
        res.expect("expected child EXCLUSIVE lock to succeed after parent lock ended");
    }
}

pub(crate) fn assert_cross_process_exclusive_lock(db_path: &Path, expect_locked: bool) {
    let exe = std::env::current_exe().expect("current test exe");
    let output = Command::new(&exe)
        .args(["--exact", PROBE_TEST_NAME, "--quiet"])
        .env(DB_PATH_ENV, db_path)
        .env(EXPECT_LOCKED_ENV, if expect_locked { "1" } else { "0" })
        .output()
        .expect("spawn exclusive lock probe");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "cross-process BEGIN EXCLUSIVE probe failed (expect_locked={expect_locked})
stdout:
{stdout}
stderr:
{stderr}"
    );
    assert!(
        stdout.contains("1 passed"),
        "cross-process BEGIN EXCLUSIVE probe did not execute helper test (expect_locked={expect_locked}); stdout:
{stdout}"
    );
}
