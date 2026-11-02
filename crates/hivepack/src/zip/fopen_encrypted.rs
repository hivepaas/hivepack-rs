//! Port of `zip_fopen_encrypted.c`.

use crate::zip::error::Result;
use crate::zip::fopen_index_encrypted::ZipFile;
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::zip::Flags;

impl<R: ReadAt> Archive<R> {
    /// Opens the entry named `fname` for reading, looked up as
    /// [`Archive::name_locate`] looks it up with `flags`, and decrypted
    /// with `password`: port of `zip_fopen_encrypted`.
    pub fn fopen_encrypted(
        &self,
        fname: &[u8],
        flags: Flags,
        password: Option<&[u8]>,
    ) -> Result<ZipFile<'_, R>> {
        let idx = self.name_locate(fname, flags)?;
        self.fopen_index_encrypted(idx, flags, password)
    }
}
