//! Wall-clock abstraction supplying UTC Unix seconds for PEP authorization evaluation.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use handfest_core::ast::{parse_rfc3339_utc, AstError};

/// Wall-clock abstraction supplying UTC Unix seconds for authorization evaluation.
pub trait Clock {
    /// Returns the current UTC timestamp in Unix seconds.
    fn now_unix(&self) -> i64;
}

/// Converts a [`SystemTime`] into floored UTC Unix seconds, preserving pre-1970 negative
/// timestamps (with sub-second floor toward `-infinity`) and saturating to `i64::MIN`/`i64::MAX`.
#[must_use]
pub(crate) fn unix_seconds_from_system_time(t: SystemTime) -> i64 {
    unix_seconds_from_epoch_offset(t.duration_since(UNIX_EPOCH).map_err(|err| err.duration()))
}

fn unix_seconds_from_epoch_offset(offset: Result<Duration, Duration>) -> i64 {
    match offset {
        Ok(dur) => i64::try_from(dur.as_secs()).unwrap_or(i64::MAX),
        Err(dur) => {
            let abs_secs = dur
                .as_secs()
                .saturating_add(u64::from(dur.subsec_nanos() > 0));
            i64::try_from(abs_secs).map_or(i64::MIN, |secs| -secs)
        }
    }
}

/// Production wall-clock backed by [`SystemTime::now`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        unix_seconds_from_system_time(SystemTime::now())
    }
}

/// Deterministic fixed-timestamp clock for tests and replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock {
    now_unix: i64,
}

impl FixedClock {
    /// Creates a clock that always returns `now_unix` (UTC Unix seconds).
    #[must_use]
    pub const fn new(now_unix: i64) -> Self {
        Self { now_unix }
    }
}

impl Clock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.now_unix
    }
}

/// Wall-clock selector for PEP binaries: live [`SystemClock`] or fixed RFC 3339 [`FixedClock`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeClock {
    System(SystemClock),
    Fixed(FixedClock),
}

impl RuntimeClock {
    /// Builds a [`RuntimeClock::Fixed`] from an optional RFC 3339 UTC timestamp string, or
    /// [`RuntimeClock::System`] when `raw` is `None`.
    pub fn from_optional_rfc3339(raw: Option<&str>) -> Result<Self, AstError> {
        match raw {
            Some(ts_str) => Ok(Self::Fixed(FixedClock::new(parse_rfc3339_utc(ts_str)?))),
            None => Ok(Self::System(SystemClock)),
        }
    }
}

impl Clock for RuntimeClock {
    fn now_unix(&self) -> i64 {
        match self {
            Self::System(c) => c.now_unix(),
            Self::Fixed(c) => c.now_unix(),
        }
    }
}

#[cfg(test)]
mod tests {
    use handfest_core::ast::{is_valid_timestamp, MIN_RFC3339_TIMESTAMP};

    use super::*;

    #[test]
    fn unix_seconds_preserves_post_and_pre_1970_subsecond_and_saturation_bounds() {
        assert_eq!(unix_seconds_from_system_time(UNIX_EPOCH), 0);
        assert_eq!(
            unix_seconds_from_system_time(UNIX_EPOCH + Duration::new(1_700_000_000, 999_999_999)),
            1_700_000_000
        );
        assert_eq!(
            unix_seconds_from_system_time(UNIX_EPOCH - Duration::from_secs(3600)),
            -3600
        );
        assert_eq!(
            unix_seconds_from_system_time(UNIX_EPOCH - Duration::from_nanos(1)),
            -1
        );
        assert_eq!(
            unix_seconds_from_system_time(UNIX_EPOCH - Duration::new(3600, 1)),
            -3601
        );
        assert_eq!(
            unix_seconds_from_system_time(UNIX_EPOCH - Duration::new(3600, 999_999_999)),
            -3601
        );

        let before_year_zero_secs = MIN_RFC3339_TIMESTAMP.unsigned_abs() + 1;
        if let Some(pre_0000) = UNIX_EPOCH.checked_sub(Duration::from_secs(before_year_zero_secs)) {
            let ts = unix_seconds_from_system_time(pre_0000);
            assert_eq!(ts, MIN_RFC3339_TIMESTAMP - 1);
            assert!(!is_valid_timestamp(ts));
        }

        assert_eq!(
            unix_seconds_from_epoch_offset(Ok(Duration::from_secs(u64::MAX))),
            i64::MAX
        );
        assert_eq!(
            unix_seconds_from_epoch_offset(Ok(Duration::from_secs(i64::MAX as u64))),
            i64::MAX
        );
        assert_eq!(
            unix_seconds_from_epoch_offset(Err(Duration::from_secs(u64::MAX))),
            i64::MIN
        );
        assert_eq!(
            unix_seconds_from_epoch_offset(Err(Duration::new(i64::MAX as u64, 1))),
            i64::MIN
        );
        assert_eq!(
            unix_seconds_from_epoch_offset(Err(Duration::new(i64::MAX as u64, 0))),
            i64::MIN + 1
        );
        assert_eq!(unix_seconds_from_epoch_offset(Err(Duration::ZERO)), 0);
    }

    #[test]
    fn fixed_and_system_clocks_return_timestamps() {
        let fixed = FixedClock::new(1_760_000_000);
        assert_eq!(fixed.now_unix(), 1_760_000_000);
        assert!(SystemClock.now_unix() > 1_700_000_000);

        let sys_rt = RuntimeClock::from_optional_rfc3339(None).expect("system runtime clock");
        assert_eq!(sys_rt, RuntimeClock::System(SystemClock));
        assert!(sys_rt.now_unix() > 1_700_000_000);

        let fixed_rt = RuntimeClock::from_optional_rfc3339(Some("2026-06-01T00:00:00Z"))
            .expect("fixed runtime clock");
        assert_eq!(
            fixed_rt,
            RuntimeClock::Fixed(FixedClock::new(1_780_272_000))
        );
        assert_eq!(fixed_rt.now_unix(), 1_780_272_000);

        let bad_rt = RuntimeClock::from_optional_rfc3339(Some("not-a-timestamp"))
            .expect_err("invalid RFC 3339 timestamp must fail");
        assert_eq!(
            bad_rt,
            AstError::InvalidTimestamp("not-a-timestamp".to_string())
        );
    }
}
