//! Port of `zip_file_get_external_attributes.c`.

use crate::zip::error::Result;
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::zip::Flags;

impl<R: ReadAt> Archive<R> {
    /// The system entry `idx` was made on (an [`opsys`](crate::zip::opsys)
    /// value) and its external attributes: port of
    /// `zip_file_get_external_attributes`.
    pub fn file_get_external_attributes(&self, idx: u64, flags: Flags) -> Result<(u8, u32)> {
        let de = self.get_dirent(idx, flags)?;
        Ok(((de.version_madeby >> 8) as u8, de.ext_attrib))
    }
}
