//! Port of `zip_file_replace.c`.

use std::sync::Arc;

use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::source_data::DataSource;
use crate::zip::zip::Flags;
use crate::zip::zipint::{EF_BOTH, EXTRA_FIELD_ALL};

impl<R: ReadAt> Archive<R> {
    /// Replaces the data of entry `idx` with that of `source`: port of
    /// `zip_file_replace`. Its extra fields are deleted, as they are
    /// usually tied to the data.
    pub fn file_replace<S: DataSource + 'static>(
        &mut self,
        idx: u64,
        source: S,
        flags: Flags,
    ) -> Result<()> {
        if idx >= self.entry.len() as u64 {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        self.file_replace_impl(Some(idx), None, Arc::new(source), flags)?;
        Ok(())
    }

    /// Port of `_zip_file_replace`: entry `idx`, or a new one (or the one
    /// named `name`, with [`Flags::OVERWRITE`]) if `None`.
    pub(crate) fn file_replace_impl(
        &mut self,
        idx: Option<u64>,
        name: Option<&[u8]>,
        source: Arc<dyn DataSource>,
        flags: Flags,
    ) -> Result<u64> {
        if self.is_rdonly() {
            return Err(Error::new(ErrorCode::RdOnly, 0));
        }

        let nentry_prev = self.entry.len();

        let idx = match idx {
            Some(idx) => idx,
            None => {
                let mut i = None;
                if flags.intersects(Flags::OVERWRITE)
                    && let Some(name) = name
                {
                    i = self.name_locate(name, flags).ok();
                }
                // create and use new entry, used by zip_add
                i.unwrap_or_else(|| self.add_entry())
            }
        };

        if let Some(name) = name
            && let Err(e) = self.set_name(idx, name, flags)
        {
            if self.entry.len() != nentry_prev {
                self.entry.truncate(nentry_prev);
            }
            return Err(e);
        }

        // delete all extra fields - these are usually data that are
        // strongly coupled with the original data
        self.file_extra_field_delete(idx, EXTRA_FIELD_ALL, EF_BOTH)?;

        // does not change any name related data, so we can do it here;
        // needed for a double add of the same file name
        let entry = &mut self.entry[idx as usize];
        entry.unchange_data();
        entry.source = Some(source);

        Ok(idx)
    }
}
