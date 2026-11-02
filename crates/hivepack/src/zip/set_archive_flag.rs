//! Port of `zip_set_archive_flag.c`.

use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::zip::ArchiveFlags;

impl<R: ReadAt> Archive<R> {
    /// Sets or clears `flag`: port of `zip_set_archive_flag`. Whether the
    /// archive is torrentzipped cannot be set, an archive opened read-only
    /// stays so, and one with changes cannot be made read-only.
    pub fn set_archive_flag(&mut self, flag: ArchiveFlags, value: bool) -> Result<()> {
        if flag == ArchiveFlags::IS_TORRENTZIP {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        // TODO in libzip: when setting ZIP_AFL_WANT_TORRENTZIP, we should
        // error out if any changes have been made that are not allowed for
        // torrentzip.

        let new_flags = if value {
            ArchiveFlags(self.ch_flags.0 | flag.0)
        } else {
            ArchiveFlags(self.ch_flags.0 & !flag.0)
        };

        if new_flags == self.ch_flags {
            return Ok(());
        }

        // Allow removing ZIP_AFL_RDONLY if manually set, not if archive was
        // opened read-only.
        if self.flags.intersects(ArchiveFlags::RDONLY) {
            return Err(Error::new(ErrorCode::RdOnly, 0));
        }

        if flag.intersects(ArchiveFlags::RDONLY)
            && value
            && !self.ch_flags.intersects(ArchiveFlags::RDONLY)
            && self.changed().0
        {
            return Err(Error::new(ErrorCode::Changed, 0));
        }

        self.ch_flags = new_flags;
        Ok(())
    }
}
