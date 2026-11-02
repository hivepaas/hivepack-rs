//! Port of `zip_file_set_comment.c`.

use crate::zip::dirent::Dirent;
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::string::{ZipString, string_equal};
use crate::zip::zip::Flags;
use crate::zip::zipint::{Encoding, FL_ENCODING_ALL, changed};

impl<R: ReadAt> Archive<R> {
    /// Sets the comment of entry `idx` (none if it is empty), in the
    /// encoding `flags` give: port of `zip_file_set_comment`. A comment
    /// guessed to be UTF-8 is taken to be. The comment can be up to 65,535
    /// bytes, any bytes.
    pub fn file_set_comment(&mut self, idx: u64, comment: &[u8], flags: Flags) -> Result<()> {
        self.get_dirent(idx, Flags::NONE)?;

        if self.is_rdonly() {
            return Err(Error::new(ErrorCode::RdOnly, 0));
        }
        if self.want_torrentzip() {
            return Err(Error::new(ErrorCode::NotAllowed, 0));
        }

        let Ok(len) = u16::try_from(comment.len()) else {
            // Differs from libzip, which takes the length as a zip_uint16_t.
            return Err(Error::new(ErrorCode::Inval, 0));
        };
        let cstr = if len > 0 {
            let mut cstr = ZipString::new(comment, flags)?;
            if let Some(s) = cstr.as_mut()
                && Flags(flags.0 & FL_ENCODING_ALL.0) == Flags::ENC_GUESS
                && s.guess_encoding(Encoding::Unknown) == Encoding::Utf8Guessed
            {
                s.set_utf8_known();
            }
            cstr
        } else {
            None
        };

        let e = &mut self.entry[idx as usize];

        if let Some(changes) = e.changes.as_mut()
            && changes.changed & changed::COMMENT != 0
        {
            // A dirent of changes is always a clone.
            changes.comment = e.orig.as_ref().and_then(|o| o.comment.clone());
            changes.changed &= !changed::COMMENT;
        }

        let is_changed = match e.orig.as_ref().and_then(|o| o.comment.as_ref()) {
            Some(orig_comment) => !string_equal(Some(orig_comment), cstr.as_ref()),
            None => cstr.is_some(),
        };

        if is_changed {
            let changes = e
                .changes
                .get_or_insert_with(|| Box::new(Dirent::clone_changes(e.orig.as_deref())));
            changes.comment = cstr;
            changes.changed |= changed::COMMENT;
        } else if e.changes.as_ref().is_some_and(|c| c.changed == 0) {
            e.changes = None;
        }

        Ok(())
    }
}
