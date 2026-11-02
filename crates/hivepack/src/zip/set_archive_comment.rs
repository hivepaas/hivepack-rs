//! Port of `zip_set_archive_comment.c`.

use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::string::{ZipString, string_equal};
use crate::zip::zip::Flags;
use crate::zip::zipint::Encoding;

impl<R: ReadAt> Archive<R> {
    /// Sets the archive comment (none if it is empty): port of
    /// `zip_set_archive_comment`. The comment must be ASCII or UTF-8, as
    /// the archive has no flag for its encoding.
    pub fn set_archive_comment(&mut self, comment: &[u8]) -> Result<()> {
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
            let mut cstr = ZipString::new(comment, Flags::ENC_GUESS)?;
            if cstr
                .as_mut()
                .is_some_and(|s| s.guess_encoding(Encoding::Unknown) == Encoding::Cp437)
            {
                return Err(Error::new(ErrorCode::Inval, 0));
            }
            cstr
        } else {
            None
        };

        self.comment_changes = None;

        if string_equal(self.comment_orig.as_ref(), cstr.as_ref()) {
            self.comment_changed = false;
        } else {
            self.comment_changes = cstr;
            self.comment_changed = true;
        }

        Ok(())
    }
}
