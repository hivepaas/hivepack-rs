//! The times a directory entry carries, as MS-DOS kept them.

/// A time a FAT file system holds: the parts, as they are in the entry.
///
/// **A FAT time has no time zone.** MS-DOS wrote the clock as the computer
/// read it, and nothing in the file system says where that was, so the
/// same card reads as different times on either side of a border. What a
/// reader does with that is its own to decide: [`Time::unix`] answers as
/// though the parts were UTC, which is what Linux does when a FAT file
/// system is mounted with `tz=UTC`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Time {
    pub year: u16,
    /// 1 to 12.
    pub month: u8,
    /// 1 to 31.
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    /// 0 to 59, and always even where the entry holds only the two-second
    /// steps a write time has; a creation time carries the odd second in
    /// its tenths.
    pub second: u8,
    /// Hundredths of a second, 0 to 99, which only a creation time has.
    pub hundredths: u8,
}

impl Time {
    /// The time in a date and a time field, or none where the date is zero,
    /// which is what an entry that never had one holds.
    ///
    /// `fine` is the creation time's extra field, which counts hundredths
    /// of a second from 0 to 199: its odd second goes to `second`, as a
    /// creation time is kept to the hundredth where a write time is kept to
    /// two seconds.
    pub(crate) fn of(date: u16, time: u16, fine: u8) -> Option<Time> {
        if date == 0 {
            return None;
        }
        let (month, day) = ((date >> 5) & 0x0F, date & 0x1F);
        // A date nothing could have written: refused rather than answered
        // as a day that is not one.
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return None;
        }
        let mut second = ((time & 0x1F) * 2) as u8;
        let mut hundredths = 0;
        if fine > 0 {
            second += fine / 100;
            hundredths = fine % 100;
        }
        let (hour, minute) = ((time >> 11) as u8, ((time >> 5) & 0x3F) as u8);
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        Some(Time {
            // The year is counted from 1980, which is where MS-DOS began.
            year: 1980 + (date >> 9),
            month: month as u8,
            day: day as u8,
            hour,
            minute,
            second,
            hundredths,
        })
    }

    /// The time as seconds from 1970, reading the parts as UTC. A FAT time
    /// is a local time with no zone, so this is a choice and not a fact:
    /// see the type's own note.
    pub fn unix(&self) -> i64 {
        let days = civil(
            i64::from(self.year),
            i64::from(self.month),
            i64::from(self.day),
        );
        days * 86400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }
}

/// How many days from 1970-01-01 to a date, by the arithmetic that needs no
/// table: months are shifted so that a leap day is the last day of a year.
fn civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let of_era = year - era * 400;
    let of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let of_era_days = of_era * 365 + of_era / 4 - of_era / 100 + of_year;
    era * 146_097 + of_era_days - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_day_it_all_began_counts_as_it_should() {
        // 1980-01-01 00:00:00, which is 3652 days after 1970-01-01.
        let at = Time::of(0x0021, 0, 0).unwrap();
        assert_eq!((at.year, at.month, at.day), (1980, 1, 1));
        assert_eq!(at.unix(), 3652 * 86400);
        assert_eq!(civil(1970, 1, 1), 0);
        assert_eq!(civil(2000, 3, 1), 11017);
    }

    #[test]
    fn a_write_time_keeps_two_seconds_and_a_creation_time_keeps_hundredths() {
        // 2024-02-29 13:45:30, a leap day.
        let date = ((2024 - 1980) << 9) | (2 << 5) | 29;
        let time = (13 << 11) | (45 << 5) | 15;
        let write = Time::of(date, time, 0).unwrap();
        assert_eq!((write.second, write.hundredths), (30, 0));
        // The same, one and a bit seconds later: the odd second is in the
        // tenths field, not in the time.
        let made = Time::of(date, time, 123).unwrap();
        assert_eq!((made.second, made.hundredths), (31, 23));
        assert_eq!(made.unix(), write.unix() + 1);
    }

    #[test]
    fn what_is_not_a_time_is_no_time() {
        assert!(Time::of(0, 0, 0).is_none());
        assert!(Time::of((2000 - 1980) << 9, 0, 0).is_none(), "no month");
        assert!(Time::of(((2000 - 1980) << 9) | (13 << 5) | 1, 0, 0).is_none());
        assert!(Time::of(0x0021, 25 << 11, 0).is_none(), "no such hour");
    }
}
