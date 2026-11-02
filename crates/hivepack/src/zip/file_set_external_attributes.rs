//! Port of `zip_file_set_external_attributes.c`.

use crate::zip::dirent::Dirent;
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::zip::{Flags, opsys};
use crate::zip::zipint::{EXT_ATTRIB_DEFAULT, changed};

impl<R: ReadAt> Archive<R> {
    /// Sets the system entry `idx` was made on (an [`opsys`] value) and its
    /// external attributes: port of `zip_file_set_external_attributes`.
    pub fn file_set_external_attributes(
        &mut self,
        idx: u64,
        _flags: Flags,
        opsys: u8,
        attributes: u32,
    ) -> Result<()> {
        self.get_dirent(idx, Flags::NONE)?;

        if self.is_rdonly() {
            return Err(Error::new(ErrorCode::RdOnly, 0));
        }
        if self.want_torrentzip() {
            return Err(Error::new(ErrorCode::NotAllowed, 0));
        }

        let e = &mut self.entry[idx as usize];

        let unchanged_opsys = e
            .orig
            .as_ref()
            .map_or(opsys::DEFAULT, |o| (o.version_madeby >> 8) as u8);
        let unchanged_attributes = e.orig.as_ref().map_or(EXT_ATTRIB_DEFAULT, |o| o.ext_attrib);

        let is_changed = opsys != unchanged_opsys || attributes != unchanged_attributes;

        if is_changed {
            let changes = e
                .changes
                .get_or_insert_with(|| Box::new(Dirent::clone_changes(e.orig.as_deref())));
            changes.version_madeby = (u16::from(opsys) << 8) | (changes.version_madeby & 0xff);
            changes.ext_attrib = attributes;
            changes.changed |= changed::ATTRIBUTES;
        } else if let Some(changes) = e.changes.as_mut() {
            changes.changed &= !changed::ATTRIBUTES;
            if changes.changed == 0 {
                e.changes = None;
            } else {
                changes.version_madeby =
                    (u16::from(unchanged_opsys) << 8) | (changes.version_madeby & 0xff);
                changes.ext_attrib = unchanged_attributes;
            }
        }

        Ok(())
    }
}
