//! The times a directory entry carries: the parts MS-DOS wrote, and the
//! time zone exFAT added behind them.

/// A time an exFAT file system holds.
///
/// **An exFAT time says where it was written**, which a FAT time does not:
/// each of the three times carries an offset from UTC beside it, in steps
/// of 15 minutes, and [`Time::offset`] is that offset in minutes where the
/// entry has one. A volume written by a tool that left it out reads with
/// none, and then the parts are a local time of nowhere in particular, as
/// a FAT time is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Time {
    pub year: u16,
    /// 1 to 12.
    pub month: u8,
    /// 1 to 31.
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    /// 0 to 59. The two-second step of the field, and the odd second from
    /// the entry's tenths where it has them.
    pub second: u8,
    /// Hundredths of a second, 0 to 99, which the creation and modified
    /// times carry and the accessed time does not.
    pub hundredths: u8,
    /// Minutes from UTC, where the entry says: 330 for India's half hour,
    /// -480 for California in winter. None where the entry's offset field
    /// is not marked as holding one.
    pub offset: Option<i16>,
}

impl Time {
    /// The time in a timestamp field, or none where it is zero, which is
    /// what an entry that never had one holds.
    ///
    /// `fine` counts tenths of a second from 0 to 199, as the 10 ms
    /// increment field does, and `zone` is the offset field beside it: its
    /// top bit says whether the rest is an offset at all, and the rest is
    /// a count of 15 minutes in seven bits, negative numbers as two's
    /// complement.
    pub(crate) fn of(stamp: u32, fine: u8, zone: u8) -> Option<Time> {
        if stamp == 0 {
            return None;
        }
        let date = (stamp >> 16) as u16;
        let time = (stamp & 0xFFFF) as u16;
        let (month, day) = ((date >> 5) & 0x0F, date & 0x1F);
        // A date nothing could have written: refused rather than answered
        // as a day that is not one.
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return None;
        }
        let mut second = ((time & 0x1F) * 2) as u8;
        let mut hundredths = 0;
        if fine > 0 {
            if fine > 199 {
                return None;
            }
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
            offset: offset(zone),
        })
    }

    /// The time as seconds from 1970.
    ///
    /// Where the entry says what the offset from UTC was, that is taken
    /// off and the answer is the moment itself. Where it does not, the
    /// parts are read as though they were UTC, which is what Linux does
    /// with a FAT file system mounted `tz=UTC`.
    pub fn unix(&self) -> i64 {
        let days = civil(
            i64::from(self.year),
            i64::from(self.month),
            i64::from(self.day),
        );
        let local = days * 86400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second);
        local - i64::from(self.offset.unwrap_or(0)) * 60
    }
}

/// What an offset field says, in minutes, or none where its top bit says
/// it holds no offset at all.
///
/// The seven bits under that top bit count 15 minutes each, as two's
/// complement, so the field reaches from -16 hours to +15 hours 45
/// minutes. Nothing writes one past the zones that exist, but a number is
/// read as what it says rather than being bent into a zone that does.
fn offset(zone: u8) -> Option<i16> {
    if zone & 0x80 == 0 {
        return None;
    }
    let seven = zone & 0x7F;
    // A seven-bit number, negative above 0x40: sign-extended by hand.
    let quarters = if seven & 0x40 == 0 {
        i16::from(seven)
    } else {
        i16::from(seven) - 128
    };
    Some(quarters * 15)
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

    /// A timestamp as the format holds one: the date in the high half, the
    /// time in the low half.
    fn stamp(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> u32 {
        let date = (u32::from(year - 1980) << 9) | (u32::from(month) << 5) | u32::from(day);
        let time = (u32::from(hour) << 11) | (u32::from(minute) << 5) | u32::from(second / 2);
        (date << 16) | time
    }

    #[test]
    fn the_parts_come_out_as_they_went_in() {
        let at = Time::of(stamp(2026, 11, 19, 13, 45, 30), 0, 0).unwrap();
        assert_eq!(
            (at.year, at.month, at.day, at.hour, at.minute, at.second),
            (2026, 11, 19, 13, 45, 30)
        );
        assert_eq!(at.offset, None);
        // Read as UTC where no offset is given.
        assert_eq!(at.unix(), 1_795_095_930);
    }

    #[test]
    fn the_tenths_carry_the_odd_second() {
        let whole = Time::of(stamp(2024, 2, 29, 1, 2, 4), 0, 0).unwrap();
        let later = Time::of(stamp(2024, 2, 29, 1, 2, 4), 123, 0).unwrap();
        assert_eq!((later.second, later.hundredths), (5, 23));
        assert_eq!(later.unix(), whole.unix() + 1);
        // 200 tenths would be two whole seconds, which the field cannot
        // hold: nothing writes it, and it is not read as a time.
        assert!(Time::of(stamp(2024, 2, 29, 1, 2, 4), 200, 0).is_none());
    }

    /// The offset is a seven-bit count of quarter hours, so the zones that
    /// are not whole hours come out, and the ones behind UTC are negative.
    #[test]
    fn the_offset_says_where_the_time_was_written() {
        let at = |zone| Time::of(stamp(2026, 1, 1, 12, 0, 0), 0, zone).unwrap();
        // UTC itself, marked as an offset of zero.
        assert_eq!(at(0x80).offset, Some(0));
        // +07:00, which is Vietnam: 28 quarters.
        assert_eq!(at(0x80 | 28).offset, Some(420));
        // +05:30, India's half hour: 22 quarters.
        assert_eq!(at(0x80 | 22).offset, Some(330));
        // +05:45, Nepal's three quarters: 23 of them.
        assert_eq!(at(0x80 | 23).offset, Some(345));
        // -08:00, California in winter: -32 quarters as two's complement
        // in seven bits, which is 0x60, with the top bit set over it.
        assert_eq!(at(0xE0).offset, Some(-480));
        // The furthest the field reaches either way.
        assert_eq!(at(0x80 | 0x3F).offset, Some(945));
        assert_eq!(at(0x80 | 0x40).offset, Some(-960));
        // The field with its top bit clear says nothing, whatever is under
        // it: a volume written by a tool that left the zone out.
        assert_eq!(
            Time::of(stamp(2026, 1, 1, 12, 0, 0), 0, 28).unwrap().offset,
            None
        );
    }

    /// The moment is the same whichever side of the world wrote it: the
    /// offset is taken off the parts.
    #[test]
    fn the_same_moment_in_two_zones_counts_the_same() {
        // 19:00 in Vietnam and 12:00 in UTC are one moment.
        let there = Time::of(stamp(2026, 11, 19, 19, 0, 0), 0, 0x80 | 28).unwrap();
        let here = Time::of(stamp(2026, 11, 19, 12, 0, 0), 0, 0x80).unwrap();
        assert_eq!(there.unix(), here.unix());
    }

    #[test]
    fn what_is_not_a_time_is_no_time() {
        assert!(Time::of(0, 0, 0).is_none());
        assert!(
            Time::of(stamp(2000, 0, 1, 0, 0, 0), 0, 0).is_none(),
            "no month"
        );
        assert!(Time::of(stamp(2000, 13, 1, 0, 0, 0), 0, 0).is_none());
        assert!(
            Time::of(stamp(2000, 1, 0, 0, 0, 0), 0, 0).is_none(),
            "no day"
        );
        assert!(
            Time::of(stamp(2000, 1, 1, 25, 0, 0), 0, 0).is_none(),
            "no such hour"
        );
        assert!(Time::of(stamp(2000, 1, 1, 0, 61, 0), 0, 0).is_none());
    }

    #[test]
    fn the_day_it_all_began_counts_as_it_should() {
        let at = Time::of(stamp(1980, 1, 1, 0, 0, 0), 0, 0).unwrap();
        assert_eq!((at.year, at.month, at.day), (1980, 1, 1));
        assert_eq!(at.unix(), 3652 * 86400);
        assert_eq!(civil(1970, 1, 1), 0);
        assert_eq!(civil(2000, 3, 1), 11017);
    }
}
