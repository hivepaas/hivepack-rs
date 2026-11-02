//! Port of `zip_file_get_comment.c`.

use crate::zip::error::Result;
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::string::string_get;
use crate::zip::zip::Flags;

impl<R: ReadAt> Archive<R> {
    /// The comment of entry `idx`, converted as names are: port of
    /// `zip_file_get_comment`.
    pub fn file_get_comment(&self, idx: u64, flags: Flags) -> Result<&[u8]> {
        let de = self.get_dirent(idx, flags)?;
        Ok(string_get(de.comment.as_ref(), flags))
    }
}
