//! ESE `LogTime` → `forensic_rs::utils::time::ForensicTimestamp` conversion.
//!
//! `LogTime` is an 8-byte packed struct (seconds, minutes, hours, day, month,
//! year-since-1900, ...) used throughout the ESE header for shutdown/attach/
//! repair timestamps. Both `day` and `month` are **1-based** (verified against
//! a real header: `artifacts/sru/SRUDB.dat`'s `shutdown_datetime` decodes to
//! 2020-11-09, byte 3 (day) = 9, byte 4 (month) = 11).

use forensic_rs::{err::ForensicError, utils::time::ForensicTimestamp};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct LogTime(pub u64);

impl TryFrom<LogTime> for ForensicTimestamp {
    type Error = ForensicError;

    fn try_from(value: LogTime) -> Result<Self, Self::Error> {
        let bf = value.0.to_le_bytes();
        let seconds = bf[0];
        if seconds > 59 {
            return Err(ForensicError::invalid_format("ESE", "Seconds must be between 0 and 59"));
        }
        let minutes = bf[1];
        if minutes > 59 {
            return Err(ForensicError::invalid_format("ESE", "Minutes must be between 0 and 59"));
        }
        let hours = bf[2];
        if hours > 23 {
            return Err(ForensicError::invalid_format("ESE", "Hours must be between 0 and 23"));
        }
        let day = bf[3];
        if !(1..=31).contains(&day) {
            return Err(ForensicError::invalid_format("ESE", "Day must be between 1 and 31"));
        }
        let month = bf[4];
        if !(1..=12).contains(&month) {
            return Err(ForensicError::invalid_format("ESE", "Month must be between 1 and 12"));
        }
        let year = bf[5] as u64 + 1900;

        // month/day are both 1-based: index the accumulator with `month - 1`
        // and count `day - 1` whole days already elapsed in the month.
        let acumulated_day_month = if is_leap_year(year) {
            [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335][(month - 1) as usize]
        } else {
            [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334][(month - 1) as usize]
        };
        let days_years = to_days_since_begining(year);
        let days_elapsed = days_years + acumulated_day_month + (day as u64 - 1);
        let total = ((days_elapsed * 24 + hours as u64) * 3600 + minutes as u64 * 60 + seconds as u64)
            * 1000 * 1000 * 10;
        Ok(ForensicTimestamp::from_win_filetime(total))
    }
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Number of days between 1601-01-01 and `year`-01-01 (closed form; avoids a
/// 400+ iteration loop run up to 10 times per header parse).
fn to_days_since_begining(year: u64) -> u64 {
    if year <= 1601 {
        return 0;
    }
    let leaps = |y: u64| y / 4 - y / 100 + y / 400;
    let days_in_full_years = (year - 1601) * 365;
    days_in_full_years + leaps(year - 1) - leaps(1600)
}

#[test]
fn should_convert_to_filetime() {
    // 2020-11-09 15:45:00 — verified directly against
    // `artifacts/sru/SRUDB.dat`'s header `shutdown_datetime` field
    // (bytes: sec=0, min=45, hour=15, day=9, month=11, year=120→2020).
    let time = LogTime(u64::from_le_bytes([0x00, 0x2d, 0x0f, 0x09, 0x0b, 0x78, 0x00, 0x00]));
    let ts: ForensicTimestamp = time.try_into().unwrap();
    assert_eq!(2020, ts.year());
    assert_eq!(11, ts.month());
    assert_eq!(9, ts.day());
    assert_eq!(15, ts.hour());
    assert_eq!(45, ts.minute());
    assert_eq!(0, ts.second());
}

#[test]
fn all_zero_bytes_is_an_invalid_timestamp() {
    // month=0, day=0 are both out of the (now correctly) 1-based valid range.
    let time = LogTime(u64::from_le_bytes([0, 0, 0, 0, 0, 0, 0, 0]));
    let result: Result<ForensicTimestamp, _> = time.try_into();
    assert!(result.is_err(), "day=0/month=0 must be rejected, not silently accepted");
}

#[test]
fn december_is_accepted() {
    // month=12 must not be rejected — `month >= 12` used to reject it outright.
    let time = LogTime(u64::from_le_bytes([0, 0, 0, 1, 12, 120, 0, 0]));
    let ts: ForensicTimestamp = time.try_into().expect("December should be a valid month");
    assert_eq!(12, ts.month());
    assert_eq!(1, ts.day());
    assert_eq!(2020, ts.year());
}

#[test]
fn days_since_beginning_matches_naive_loop() {
    fn naive(year: u64) -> u64 {
        let mut total = 0;
        for y in 1601..year {
            total += if is_leap_year(y) { 366 } else { 365 };
        }
        total
    }
    for year in [1601, 1602, 1700, 1900, 2000, 2020, 2024, 2100] {
        assert_eq!(naive(year), to_days_since_begining(year), "mismatch for year {year}");
    }
}
