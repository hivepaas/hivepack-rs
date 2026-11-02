//! Port of `zip_unchange.c`.

use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::zip::Flags;
use crate::zip::zipint::changed;

impl<R: ReadAt> Archive<R> {
    /// Drops the changes of entry `idx`, and brings it back if it was
    /// deleted; fails with `ZIP_ER_EXISTS` if another entry has its name
    /// now. Port of `zip_unchange`.
    pub fn unchange(&mut self, idx: u64) -> Result<()> {
        self.unchange_impl(idx, false)
    }

    /// Port of `_zip_unchange`: with `allow_duplicates`, the names are left
    /// as they are.
    pub(crate) fn unchange_impl(&mut self, idx: u64, allow_duplicates: bool) -> Result<()> {
        if idx >= self.entry.len() as u64 {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        let entry = &self.entry[idx as usize];
        let renamed = entry.changed(changed::FILENAME);
        if !allow_duplicates && (renamed || entry.deleted) {
            let mut orig_name = None;
            if entry.orig.is_some() {
                let name = self.get_name(idx, Flags::UNCHANGED)?.to_vec();
                if let Ok(i) = self.name_locate(&name, Flags::NONE)
                    && i != idx
                {
                    return Err(Error::new(ErrorCode::Exists, 0));
                }
                orig_name = Some(name);
            }

            let changed_name = match renamed {
                true => Some(self.get_name(idx, Flags::NONE)?.to_vec()),
                false => None,
            };

            if let Some(orig_name) = &orig_name {
                self.names.add(orig_name, idx, Flags::NONE)?;
            }
            if let Some(changed_name) = &changed_name
                && let Err(e) = self.names.delete(changed_name)
            {
                if let Some(orig_name) = &orig_name {
                    let _ = self.names.delete(orig_name);
                }
                return Err(e);
            }
        }

        let entry = &mut self.entry[idx as usize];
        entry.changes = None;
        entry.unchange_data();
        Ok(())
    }
}
