//! Port of `zip_set_name.c`.

use crate::zip::dirent::Dirent;
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::hash::c_string;
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::string::{ZipString, string_equal, string_get};
use crate::zip::zip::Flags;
use crate::zip::zipint::{Encoding, FL_ENCODING_ALL, changed};

impl<R: ReadAt> Archive<R> {
    /// Gives entry `idx` the name `name` (none if it is empty), up to its
    /// first NUL byte: port of `_zip_set_name`. A name guessed to be UTF-8
    /// is taken to be.
    pub(crate) fn set_name(&mut self, idx: u64, name: &[u8], flags: Flags) -> Result<()> {
        if idx >= self.entry.len() as u64 {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        if self.is_rdonly() {
            return Err(Error::new(ErrorCode::RdOnly, 0));
        }

        let name = c_string(name);
        let str = if !name.is_empty() {
            if name.len() > usize::from(u16::MAX) {
                return Err(Error::new(ErrorCode::Inval, 0));
            }
            let mut str = ZipString::new(name, flags)?;
            if let Some(s) = str.as_mut()
                && Flags(flags.0 & FL_ENCODING_ALL.0) == Flags::ENC_GUESS
                && s.guess_encoding(Encoding::Unknown) == Encoding::Utf8Guessed
            {
                s.set_utf8_known();
            }
            str
        } else {
            None
        };

        // TODO in libzip: encoding flags needed for CP437?
        let i = self.name_locate(name, Flags::NONE);
        if let Ok(i) = i
            && i != idx
        {
            return Err(Error::new(ErrorCode::Exists, 0));
        }

        // no effective name change
        if i.is_ok() {
            return Ok(());
        }

        let e = &mut self.entry[idx as usize];
        let same_as_orig = match &e.orig {
            Some(orig) => string_equal(orig.filename.as_ref(), str.as_ref()),
            None => false,
        };

        if !same_as_orig && e.changes.is_none() {
            e.changes = Some(Box::new(Dirent::clone_changes(e.orig.as_deref())));
        }

        let new_name = match (same_as_orig, &e.orig) {
            (true, Some(orig)) => string_get(orig.filename.as_ref(), Flags::NONE),
            _ => string_get(str.as_ref(), Flags::NONE),
        }
        .to_vec();
        let old_str = match (&e.changes, &e.orig) {
            (Some(changes), _) => changes.filename.as_ref(),
            (None, Some(orig)) => orig.filename.as_ref(),
            (None, None) => None,
        };
        let old_name = old_str.map(|s| string_get(Some(s), Flags::NONE).to_vec());

        self.names.add(&new_name, idx, Flags::NONE)?;
        if let Some(old_name) = &old_name {
            let _ = self.names.delete(old_name);
        }

        let e = &mut self.entry[idx as usize];
        if same_as_orig {
            if let Some(changes) = e.changes.as_mut()
                && changes.changed & changed::FILENAME != 0
            {
                changes.changed &= !changed::FILENAME;
                if changes.changed == 0 {
                    e.changes = None;
                } else {
                    // TODO in libzip: what if not cloned? can that happen?
                    changes.filename = e.orig.as_ref().and_then(|o| o.filename.clone());
                }
            }
        } else if let Some(changes) = e.changes.as_mut() {
            changes.changed |= changed::FILENAME;
            changes.filename = str;
        }

        Ok(())
    }
}
