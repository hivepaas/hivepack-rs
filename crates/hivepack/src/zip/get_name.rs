//! Port of `zip_get_name.c`.

use crate::zip::error::Result;
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::string::string_get;
use crate::zip::zip::Flags;

impl<R: ReadAt> Archive<R> {
    /// The name of entry `idx`: raw with [`Flags::ENC_RAW`], else in UTF-8
    /// if it is guessed to be CP437 (see [`Flags::ENC_STRICT`]). Port of
    /// `zip_get_name`.
    ///
    /// Differs from libzip: the name is all its bytes. libzip returns a C
    /// string, which ends at a NUL byte in the name (one that
    /// [`OpenFlags::CHECKCONS`](crate::zip::OpenFlags::CHECKCONS) refuses).
    pub fn get_name(&self, idx: u64, flags: Flags) -> Result<&[u8]> {
        let de = self.get_dirent(idx, flags)?;
        Ok(string_get(de.filename.as_ref(), flags))
    }
}
