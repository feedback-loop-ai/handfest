//! Single shared Unix cross-process `SQLITE_BUSY` lock-probe helper for both unit tests
//! (`sqlite_tests`, `preflight_tests`) and integration tests (`ledger_tests`,
//! `hardening_and_denial_tests`).

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

const DB_PATH_ENV: &str = "HANDFEST_LOCK_PROBE_DB";
const PROBE_MODE_ENV: &str = "HANDFEST_LOCK_PROBE_MODE";
const EXPECT_LOCKED_ENV: &str = "HANDFEST_LOCK_PROBE_EXPECT_LOCKED";
const PROBE_VERIFIED_PREFIX: &str = "HANDFEST_LOCK_PROBE_VERIFIED=";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockProbeMode {
    Exclusive,
    Immediate,
}

impl LockProbeMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Exclusive => "exclusive",
            Self::Immediate => "immediate",
        }
    }

    fn sql(self) -> &'static str {
        match self {
            Self::Exclusive => "BEGIN EXCLUSIVE; ROLLBACK;",
            Self::Immediate => "BEGIN IMMEDIATE; ROLLBACK;",
        }
    }

    fn from_env(raw: &OsStr) -> Self {
        match raw.to_str() {
            Some("exclusive") => Self::Exclusive,
            Some("immediate") => Self::Immediate,
            other => panic!(
                "invalid {PROBE_MODE_ENV}={raw:?} (utf8={other:?}); expected 'exclusive' or 'immediate'"
            ),
        }
    }
}

fn probe_helper_test_name() -> String {
    let mod_path = module_path!();
    let rel = mod_path.split_once("::").map_or(mod_path, |(_, rest)| rest);
    format!("{rel}::cross_process_lock_probe_helper")
}

fn parse_probe_env(
    db_path: Option<OsString>,
    mode_raw: Option<OsString>,
    expect_locked_raw: Option<OsString>,
) -> Option<(PathBuf, LockProbeMode, bool)> {
    match (db_path, mode_raw, expect_locked_raw) {
        (None, None, None) => None,
        (Some(path), Some(mode_os), Some(expect)) => {
            assert!(
                !path.is_empty(),
                "{DB_PATH_ENV} must be a non-empty database path"
            );
            let mode = LockProbeMode::from_env(&mode_os);
            let expect_locked = match expect.to_str() {
                Some("1") => true,
                Some("0") => false,
                other => panic!(
                    "invalid {EXPECT_LOCKED_ENV}={expect:?} (utf8={other:?}); expected '0' or '1'"
                ),
            };
            Some((PathBuf::from(path), mode, expect_locked))
        }
        (db, mode, expect) => panic!(
            "partial lock-probe env ({DB_PATH_ENV}={db:?}, {PROBE_MODE_ENV}={mode:?}, {EXPECT_LOCKED_ENV}={expect:?}); refusing silent pass"
        ),
    }
}

#[test]
fn cross_process_lock_probe_helper() {
    let Some((db_path, mode, expect_locked)) = parse_probe_env(
        std::env::var_os(DB_PATH_ENV),
        std::env::var_os(PROBE_MODE_ENV),
        std::env::var_os(EXPECT_LOCKED_ENV),
    ) else {
        return;
    };
    let conn = rusqlite::Connection::open(&db_path).expect("probe open");
    conn.busy_timeout(Duration::ZERO).unwrap();
    let res = conn.execute_batch(mode.sql());
    let mode_name = mode.as_str();
    if expect_locked {
        match res {
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::DatabaseBusy => {}
            other => panic!(
                "expected parent POSIX lock ({mode_name}) to fail with DatabaseBusy (SQLITE_BUSY), got: {other:?}"
            ),
        }
        println!("{PROBE_VERIFIED_PREFIX}{mode_name}:locked");
    } else {
        res.expect("expected child lock probe to succeed after parent released transaction");
        println!("{PROBE_VERIFIED_PREFIX}{mode_name}:unlocked");
    }
}

fn set_opt_env(cmd: &mut Command, key: &str, val: Option<&OsStr>) {
    match val {
        Some(v) => {
            cmd.env(key, v);
        }
        None => {
            cmd.env_remove(key);
        }
    }
}

fn spawn_lock_probe(
    db_path: Option<&OsStr>,
    mode: Option<&OsStr>,
    expect_locked: Option<&OsStr>,
) -> Output {
    let exe = std::env::current_exe().expect("current test exe");
    let test_name = probe_helper_test_name();
    let mut cmd = Command::new(&exe);
    cmd.args(["--exact", &test_name, "--nocapture"]);
    set_opt_env(&mut cmd, DB_PATH_ENV, db_path);
    set_opt_env(&mut cmd, PROBE_MODE_ENV, mode);
    set_opt_env(&mut cmd, EXPECT_LOCKED_ENV, expect_locked);
    cmd.output().expect("spawn cross-process lock probe")
}

fn verify_lock_probe_output(output: &Output, mode: LockProbeMode, expect_locked: bool) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mode_name = mode.as_str();
    assert!(
        output.status.success(),
        "cross-process lock probe failed (mode={mode_name}, expect_locked={expect_locked})\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("1 passed"),
        "cross-process lock probe did not execute helper test (mode={mode_name}, expect_locked={expect_locked}); stdout:\n{stdout}"
    );
    let expected_marker = format!(
        "{PROBE_VERIFIED_PREFIX}{mode_name}:{}",
        if expect_locked { "locked" } else { "unlocked" }
    );
    assert!(
        stdout.lines().any(|line| line.trim() == expected_marker),
        "cross-process lock probe returned without executing SQLite check (missing '{expected_marker}'); stdout:\n{stdout}"
    );
}

pub(crate) fn assert_cross_process_lock(db_path: &Path, mode: LockProbeMode, expect_locked: bool) {
    let output = spawn_lock_probe(
        Some(db_path.as_os_str()),
        Some(OsStr::new(mode.as_str())),
        Some(OsStr::new(if expect_locked { "1" } else { "0" })),
    );
    verify_lock_probe_output(&output, mode, expect_locked);
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

    assert_cross_process_lock(&db_path, LockProbeMode::Exclusive, true);
    assert_cross_process_lock(&db_path, LockProbeMode::Immediate, true);

    conn.execute_batch("ROLLBACK;").unwrap();
    assert_cross_process_lock(&db_path, LockProbeMode::Exclusive, false);
    assert_cross_process_lock(&db_path, LockProbeMode::Immediate, false);
}

#[test]
fn cross_process_lock_probe_rejects_missing_or_invalid_env_and_silent_early_return() {
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("probe_guard.sqlite");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch("CREATE TABLE t(x INTEGER);").unwrap();
    drop(conn);

    // Partial env combinations must fail the child (never silent pass).
    let missing_db = spawn_lock_probe(None, Some(OsStr::new("exclusive")), Some(OsStr::new("1")));
    assert!(
        !missing_db.status.success(),
        "expected child probe to fail when {DB_PATH_ENV} is missing"
    );
    let missing_mode = spawn_lock_probe(Some(db_path.as_os_str()), None, Some(OsStr::new("1")));
    assert!(
        !missing_mode.status.success(),
        "expected child probe to fail when {PROBE_MODE_ENV} is missing"
    );
    let missing_expect = spawn_lock_probe(
        Some(db_path.as_os_str()),
        Some(OsStr::new("exclusive")),
        None,
    );
    assert!(
        !missing_expect.status.success(),
        "expected child probe to fail when {EXPECT_LOCKED_ENV} is missing"
    );

    // Empty DB path must fail the child (never open a fresh SQLite temporary DB).
    let empty_db = spawn_lock_probe(
        Some(OsStr::new("")),
        Some(OsStr::new("exclusive")),
        Some(OsStr::new("0")),
    );
    assert!(
        !empty_db.status.success(),
        "expected child probe to fail on empty {DB_PATH_ENV}"
    );

    // Invalid mode or expect flag must fail the child rather than falling back silently.
    let bad_mode = spawn_lock_probe(
        Some(db_path.as_os_str()),
        Some(OsStr::new("shared")),
        Some(OsStr::new("0")),
    );
    assert!(
        !bad_mode.status.success(),
        "expected child probe to fail on invalid {PROBE_MODE_ENV}='shared'"
    );
    let bad_expect = spawn_lock_probe(
        Some(db_path.as_os_str()),
        Some(OsStr::new("immediate")),
        Some(OsStr::new("2")),
    );
    assert!(
        !bad_expect.status.success(),
        "expected child probe to fail on invalid {EXPECT_LOCKED_ENV}='2'"
    );

    // Even when the child exits 0 with "1 passed" via early return (no env vars set),
    // parent verification MUST reject it because the SQLite verification sentinel is absent.
    let silent_early_return = spawn_lock_probe(None, None, None);
    assert!(silent_early_return.status.success());
    let verified = std::panic::catch_unwind(|| {
        verify_lock_probe_output(&silent_early_return, LockProbeMode::Exclusive, true);
    });
    assert!(
        verified.is_err(),
        "verify_lock_probe_output must reject silent early-return child output lacking sentinel"
    );

    // Mismatched sentinel mode or lock-state must also be rejected.
    let unlocked_immediate = spawn_lock_probe(
        Some(db_path.as_os_str()),
        Some(OsStr::new("immediate")),
        Some(OsStr::new("0")),
    );
    assert!(unlocked_immediate.status.success());
    let wrong_mode = std::panic::catch_unwind(|| {
        verify_lock_probe_output(&unlocked_immediate, LockProbeMode::Exclusive, false);
    });
    assert!(
        wrong_mode.is_err(),
        "verify_lock_probe_output must reject mismatched probe mode sentinel"
    );
}
