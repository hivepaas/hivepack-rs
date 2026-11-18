//! The times an NTFS file carries.

/// A time an NTFS file system holds: how many hundreds of nanoseconds have
/// passed since the start of 1601, counted in UTC.
///
/// Unlike a FAT time, this is an instant and not a reading of a local
/// clock, so [`Time::unix`] is a conversion and not a choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Time {
    ticks: u64,
}

/// How many seconds from the start of 1601 to the start of 1970: 369 years
/// of which 89 were leap years.
const TO_1970: i64 = 11_644_473_600;

/// How many of the time's units make a second.
const A_SECOND: u64 = 10_000_000;

impl Time {
    /// The time a field holds, or none where it holds zero, which is what
    /// a file that never had one carries.
    pub(crate) fn of(ticks: u64) -> Option<Time> {
        (ticks != 0).then_some(Time { ticks })
    }

    /// The hundreds of nanoseconds since the start of 1601, as the file
    /// system keeps it.
    pub fn ticks(&self) -> u64 {
        self.ticks
    }

    /// The time as seconds from 1970, and how many nanoseconds past that
    /// second. A time before 1970 counts back, as a Unix time does.
    pub fn unix(&self) -> (i64, u32) {
        let seconds = (self.ticks / A_SECOND) as i64 - TO_1970;
        let nanoseconds = (self.ticks % A_SECOND) as u32 * 100;
        (seconds, nanoseconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_each_side_of_the_other() {
        // 1601-01-01, where the count begins, is 0 and so no time at all.
        assert!(Time::of(0).is_none());
        // 1970-01-01 00:00:00 UTC.
        let unix = Time::of(TO_1970 as u64 * A_SECOND).unwrap();
        assert_eq!(unix.unix(), (0, 0));
        // One tick later is a hundred nanoseconds later.
        let tick = Time::of(TO_1970 as u64 * A_SECOND + 1).unwrap();
        assert_eq!(tick.unix(), (0, 100));
        // A second before 1970, which counts back.
        let before = Time::of((TO_1970 as u64 - 1) * A_SECOND).unwrap();
        assert_eq!(before.unix(), (-1, 0));
    }

    #[test]
    fn what_windows_wrote_reads_back_as_the_day_it_was() {
        // The creation time measured on an image built for the tests:
        // 134393882019708000, which is 2026-11-17 11:23:21.9708 UTC.
        let (seconds, nanoseconds) = Time::of(134_393_882_019_708_000).unwrap().unix();
        assert_eq!(seconds, 1_794_914_601);
        assert_eq!(nanoseconds, 970_800_000);
        // 2026-11-17 is 20774 days after 1970-01-01.
        assert_eq!(seconds / 86400, 20774);
    }
}
