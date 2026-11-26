//! Strict RFC 3339 UTC timestamp parsing, validation, and formatting (`0000..=9999`).

use alloc::format;
use alloc::string::{String, ToString};

use super::AstError;

/// Minimum RFC 3339 4-digit-year UTC timestamp (`0000-01-01T00:00:00Z`).
pub const MIN_RFC3339_TIMESTAMP: i64 = -62_167_219_200;

/// Maximum RFC 3339 4-digit-year UTC timestamp (`9999-12-31T23:59:59Z`).
pub const MAX_RFC3339_TIMESTAMP: i64 = 253_402_300_799;

/// Returns true if `ts` is representable as a 4-digit-year RFC 3339 UTC timestamp
/// (`0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z`).
#[must_use]
pub const fn is_valid_timestamp(ts: i64) -> bool {
    ts >= MIN_RFC3339_TIMESTAMP && ts <= MAX_RFC3339_TIMESTAMP
}

/// Parses a strict RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) into Unix epoch seconds.
pub fn parse_rfc3339_utc(input: &str) -> Result<i64, AstError> {
    let b = input.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return Err(AstError::InvalidTimestamp(input.to_string()));
    }
    let year = parse_u32_digits(&input[0..4])?;
    let month = parse_u32_digits(&input[5..7])?;
    let day = parse_u32_digits(&input[8..10])?;
    let hour = parse_u32_digits(&input[11..13])?;
    let minute = parse_u32_digits(&input[14..16])?;
    let second = parse_u32_digits(&input[17..19])?;

    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(AstError::InvalidTimestamp(input.to_string()));
    }

    let days = days_from_civil(i64::from(year), month, day);
    Ok(days * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second))
}

/// Formats Unix epoch seconds into strict 4-digit-year RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`),
/// rejecting timestamps outside `0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z`.
pub fn try_format_rfc3339_utc(ts: i64) -> Result<String, AstError> {
    if !is_valid_timestamp(ts) {
        return Err(AstError::InvalidTimestamp(format!(
            "timestamp {ts} outside 0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z"
        )));
    }
    Ok(format_rfc3339_utc(ts))
}

/// Formats Unix epoch seconds into strict RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
#[must_use]
pub fn format_rfc3339_utc(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let hour = secs / 3_600;
    let minute = (secs % 3_600) / 60;
    let second = secs % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn parse_u32_digits(s: &str) -> Result<u32, AstError> {
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AstError::InvalidTimestamp(s.to_string()));
    }
    s.parse::<u32>()
        .map_err(|_| AstError::InvalidTimestamp(s.to_string()))
}

const fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = month as u64;
    let d = day as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

const fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}
