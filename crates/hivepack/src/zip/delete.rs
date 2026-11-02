//! Port of `zip_delete.c`.

use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::zip::Flags;

impl<R: ReadAt> Archive<R> {
    /// Deletes entry `idx`, dropping its changes: port of `zip_delete`. It
    /// keeps its index, and [`Archive::unchange`] brings it back.
    pub fn delete(&mut self, idx: u64) -> Result<()> {
        if idx >= self.entry.len() as u64 {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        if self.is_rdonly() {
            return Err(Error::new(ErrorCode::RdOnly, 0));
        }

        let name = self.get_name(idx, Flags::NONE)?.to_vec();
        self.names.delete(&name)?;

        // allow duplicate file names, because the file will be removed
        // directly afterwards
        self.unchange_impl(idx, true)?;

        self.entry[idx as usize].deleted = true;
        Ok(())
    }
}
