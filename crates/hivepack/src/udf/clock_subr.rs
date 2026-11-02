//! Port of `clock_ymdhms_to_secs` from NetBSD's `sys/dev/clock_subr.c`,
//! which UDF's timestamps are converted with.
//!
//! NetBSD gives -1 for the years before 1970; here they count back from
//! 1970, as Linux reads them.

const POSIX_BASE_YEAR: i64 = 1970;
const FEBRUARY: u8 = 2;

/// Time from the epoch to 2001 (there were 8 leap years).
const DAYSTO2001: i64 = 365 * 31 + 8;
/// 4 year intervals include 1 leap year.
const DAYS4YEARS: i64 = 365 * 4 + 1;
/// 100 year intervals include 24 leap years.
const DAYS100YEARS: i64 = 365 * 100 + 24;
/// 400 year intervals include 97 leap years.
const DAYS400YEARS: i64 = 365 * 400 + 97;

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_per_year(year: i64) -> i64 {
    if is_leap_year(year) { 366 } else { 365 }
}

/// `days_in_month`, for the months of a year; the C reads past its table
/// for a month after December, counted as no days here.
fn days_in_month(month: i64) -> i64 {
    const MONTH_DAYS: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    usize::try_from(month - 1)
        .ok()
        .and_then(|m| MONTH_DAYS.get(m))
        .copied()
        .unwrap_or(0)
}

/// `struct clock_ymdhms`.
pub(crate) struct ClockYmdhms {
    pub(crate) dt_year: u16,
    pub(crate) dt_mon: u8,
    pub(crate) dt_day: u8,
    pub(crate) dt_hour: u8,
    pub(crate) dt_min: u8,
    pub(crate) dt_sec: u8,
}

/// `clock_ymdhms_to_secs`.
pub(crate) fn clock_ymdhms_to_secs(dt: &ClockYmdhms) -> i64 {
    let mut year = i64::from(dt.dt_year);

    // Compute days since start of time. First from years, then from
    // months.
    let mut days: i64 = 0;
    if is_leap_year(year) && dt.dt_mon > FEBRUARY {
        days += 1;
    }

    if year < POSIX_BASE_YEAR {
        // Not in NetBSD: the years back to 1970.
        for i in year..POSIX_BASE_YEAR {
            days -= days_per_year(i);
        }
    } else if year < 2001 {
        // Simple way for early years.
        for i in POSIX_BASE_YEAR..year {
            days += days_per_year(i);
        }
    } else {
        // Years are properly aligned.
        days += DAYSTO2001;
        year -= 2001;

        let i = year / 400;
        days += i * DAYS400YEARS;
        year -= i * 400;

        let i = year / 100;
        days += i * DAYS100YEARS;
        year -= i * 100;

        let i = year / 4;
        days += i * DAYS4YEARS;
        year -= i * 4;

        for i in (i64::from(dt.dt_year) - year)..i64::from(dt.dt_year) {
            days += days_per_year(i);
        }
    }

    // Months.
    for i in 1..i64::from(dt.dt_mon) {
        days += days_in_month(i);
    }
    days += i64::from(dt.dt_day) - 1;

    // Add hours, minutes, seconds.
    ((days * 24 + i64::from(dt.dt_hour)) * 60 + i64::from(dt.dt_min)) * 60 + i64::from(dt.dt_sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(dt_year: u16, dt_mon: u8, dt_day: u8, dt_hour: u8, dt_min: u8, dt_sec: u8) -> i64 {
        clock_ymdhms_to_secs(&ClockYmdhms {
            dt_year,
            dt_mon,
            dt_day,
            dt_hour,
            dt_min,
            dt_sec,
        })
    }

    #[test]
    fn dates() {
        assert_eq!(secs(1970, 1, 1, 0, 0, 0), 0);
        assert_eq!(secs(1969, 7, 20, 20, 17, 40), -14182940);
        assert_eq!(secs(1900, 3, 1, 0, 0, 0), -2203891200);
        assert_eq!(secs(2000, 2, 29, 12, 0, 0), 951825600);
        assert_eq!(secs(2001, 2, 3, 4, 5, 6), 981173106);
        assert_eq!(secs(2038, 1, 19, 3, 14, 8), 2147483648);
        assert_eq!(secs(2099, 12, 31, 23, 59, 59), 4102444799);
        assert_eq!(secs(2400, 12, 31, 0, 0, 0), 13601001600);
    }
}
