//! Port of `zip_get_archive_flag.c`.

use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::zip::{ArchiveFlags, Flags};

impl<R: ReadAt> Archive<R> {
    /// Whether `flag` is set: port of `zip_get_archive_flag`.
    pub fn get_archive_flag(&self, flag: ArchiveFlags, flags: Flags) -> bool {
        let fl = if flags.intersects(Flags::UNCHANGED) {
            self.flags
        } else {
            self.ch_flags
        };
        fl.intersects(flag)
    }
}
