//! Port of `zip_file_set_mtime.c`.

use crate::zip::dirent::{Dirent, DosTime, u2d_time};
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::zip::{Flags, em};
use crate::zip::zipint::changed;

impl<R: ReadAt> Archive<R> {
    /// Sets the modification time of entry `idx`, `dtime` and `ddate` in
    /// MS-DOS format: port of `zip_file_set_dostime`.
    pub fn file_set_dostime(
        &mut self,
        idx: u64,
        dtime: u16,
        ddate: u16,
        flags: Flags,
    ) -> Result<()> {
        self.file_set_time(idx, dtime, ddate, flags, None)
    }

    /// Sets the modification time of entry `idx`, in seconds since 1970,
    /// taken as UTC, as [`Archive::stat_index`] gives it: port of
    /// `zip_file_set_mtime`. It is stored to two seconds, and from 1980,
    /// and `stat_index` gives it as set.
    pub fn file_set_mtime(&mut self, idx: u64, mtime: i64, flags: Flags) -> Result<()> {
        let dostime = u2d_time(mtime)?;
        self.file_set_time(idx, dostime.time, dostime.date, flags, Some(mtime))
    }

    /// Port of `zip_file_set_time`.
    fn file_set_time(
        &mut self,
        idx: u64,
        dtime: u16,
        ddate: u16,
        _flags: Flags,
        mtime: Option<i64>,
    ) -> Result<()> {
        self.get_dirent(idx, Flags::NONE)?;

        if self.is_rdonly() {
            return Err(Error::new(ErrorCode::RdOnly, 0));
        }
        if self.want_torrentzip() {
            return Err(Error::new(ErrorCode::NotAllowed, 0));
        }

        let e = &mut self.entry[idx as usize];

        if e.orig
            .as_ref()
            .is_some_and(|o| o.encryption_method == em::TRAD_PKWARE)
            && !e.changed(changed::ENCRYPTION_METHOD)
            && !e.data_changed()
        {
            return Err(Error::new(ErrorCode::OpNotSupp, 0));
        }

        let changes = e
            .changes
            .get_or_insert_with(|| Box::new(Dirent::clone_changes(e.orig.as_deref())));

        changes.last_mod = DosTime {
            time: dtime,
            date: ddate,
        };
        changes.last_mod_mtime = mtime;
        changes.changed |= changed::LAST_MOD;

        Ok(())
    }
}
