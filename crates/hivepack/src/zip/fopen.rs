//! Port of `zip_fopen.c`.

use crate::zip::error::Result;
use crate::zip::fopen_index_encrypted::ZipFile;
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::zip::Flags;

impl<R: ReadAt> Archive<R> {
    /// Opens the entry named `fname` for reading, looked up as
    /// [`Archive::name_locate`] looks it up with `flags`, and decrypted with
    /// the default password: port of `zip_fopen`.
    pub fn fopen(&self, fname: &[u8], flags: Flags) -> Result<ZipFile<'_, R>> {
        let idx = self.name_locate(fname, flags)?;
        self.fopen_index_encrypted(idx, flags, self.default_password.as_deref())
    }
}
