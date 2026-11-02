// hivepack::rar: a port of UnRAR 7.3.2 to Rust. UnRAR's license says:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

//! Times as UnRAR keeps them: nanoseconds since 1601 (`RarTime`,
//! timefn.cpp).
//!
//! UnRAR takes MS-DOS times, which RAR 1.5 to 4.x store, in the system's
//! time zone; the port takes them in UTC, as UnRAR does with `TZ=UTC`,
//! which is how the oracle runs. Fields out of range (a month 0, a 60th
//! second) carry over as `mktime` carries them.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Nanoseconds between 1601-01-01 and 1970-01-01.
const USHIFT: u64 = 11_644_473_600_000_000_000;

/// A time: nanoseconds since 1601-01-01, UTC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RarTime {
    itime: u64,
}

/// A time taken apart, as `RarLocalTime`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LocalTime {
    pub year: i64,
    pub month: i64,
    pub day: i64,
    pub hour: i64,
    pub minute: i64,
    pub second: i64,
    /// Nanoseconds.
    pub reminder: u32,
}

impl RarTime {
    /// Nanoseconds since 1601-01-01, as UnRAR stores the time.
    pub fn ticks(&self) -> u64 {
        self.itime
    }

    /// Whether the time is set.
    pub fn is_set(&self) -> bool {
        self.itime != 0
    }

    /// The time, if it is set and fits.
    pub fn system_time(&self) -> Option<SystemTime> {
        if !self.is_set() {
            return None;
        }
        if self.itime >= USHIFT {
            UNIX_EPOCH.checked_add(Duration::from_nanos(self.itime - USHIFT))
        } else {
            UNIX_EPOCH.checked_sub(Duration::from_nanos(USHIFT - self.itime))
        }
    }

    pub(crate) fn reset(&mut self) {
        self.itime = 0;
    }

    /// Windows' FILETIME: 100 ns since 1601.
    pub(crate) fn set_win(&mut self, win: u64) {
        self.itime = win.wrapping_mul(100);
    }

    /// Seconds since 1970, a 64-bit `time_t`.
    pub(crate) fn set_unix(&mut self, unix: i64) {
        self.set_unix_ns((unix as u64).wrapping_mul(1_000_000_000));
    }

    pub(crate) fn set_unix_ns(&mut self, ns: u64) {
        self.itime = ns.wrapping_add(USHIFT);
    }

    fn get_unix(&self) -> i64 {
        (self.itime.wrapping_sub(USHIFT) / 1_000_000_000) as i64
    }

    /// Adds `ns` nanoseconds.
    pub(crate) fn adjust(&mut self, ns: i64) {
        self.itime = self.itime.wrapping_add(ns as u64);
    }

    pub(crate) fn set_dos(&mut self, dos: u32) {
        let local = LocalTime {
            second: i64::from(dos & 0x1f) * 2,
            minute: i64::from((dos >> 5) & 0x3f),
            hour: i64::from((dos >> 11) & 0x1f),
            day: i64::from((dos >> 16) & 0x1f),
            month: i64::from((dos >> 21) & 0x0f),
            year: i64::from(dos >> 25) + 1980,
            reminder: 0,
        };
        self.set_local(&local);
    }

    /// The time taken apart, in UTC: `localtime` with `TZ=UTC`.
    pub(crate) fn get_local(&self) -> LocalTime {
        let unix = self.get_unix();
        let days = unix.div_euclid(86_400);
        let seconds = unix.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        LocalTime {
            year,
            month,
            day,
            hour: seconds / 3600,
            minute: seconds % 3600 / 60,
            second: seconds % 60,
            reminder: (self.itime % 1_000_000_000) as u32,
        }
    }

    /// Sets the time from its parts, in UTC: `mktime` with `TZ=UTC`, which
    /// carries fields out of range over, then the nanoseconds.
    pub(crate) fn set_local(&mut self, local: &LocalTime) {
        let month0 = local.month - 1;
        let year = local.year + month0.div_euclid(12);
        let month = month0.rem_euclid(12) + 1;
        let days = days_from_civil(year, month, 1) + local.day - 1;
        let unix = days * 86_400 + local.hour * 3600 + local.minute * 60 + local.second;
        self.set_unix(unix);
        self.itime = self.itime.wrapping_add(u64::from(local.reminder));
    }
}

/// Days since 1970-01-01 of a date in the proleptic Gregorian calendar
/// (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_times_are_utc_and_carry_over() {
        let mut t = RarTime::default();
        // 2020-09-13 12:26:40, an even second.
        let dos =
            (40 / 2) | (26 << 5) | (12 << 11) | (13 << 16) | (9 << 21) | ((2020 - 1980) << 25);
        t.set_dos(dos);
        assert_eq!(t.get_unix(), 1_600_000_000);
        let local = t.get_local();
        assert_eq!((local.year, local.month, local.day), (2020, 9, 13));
        assert_eq!((local.hour, local.minute, local.second), (12, 26, 40));
        // Month 0 of 1980, day 0: 1979-11-30.
        t.set_dos(0);
        let local = t.get_local();
        assert_eq!((local.year, local.month, local.day), (1979, 11, 30));
    }
}
