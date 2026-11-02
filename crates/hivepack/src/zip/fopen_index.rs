//! Port of `zip_fopen_index.c`.

use crate::zip::error::Result;
use crate::zip::fopen_index_encrypted::ZipFile;
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::zip::Flags;

impl<R: ReadAt> Archive<R> {
    /// Opens entry `index` for reading: port of `zip_fopen_index`.
    ///
    /// The data is decompressed, unless `flags` has [`Flags::COMPRESSED`],
    /// and the CRC-32 and length of an entry read to its end are checked.
    /// Stored, deflated and Deflate64 entries are read for now (libzip
    /// reads no Deflate64); others fail with
    /// [`ErrorCode::CompNotSupp`](crate::zip::ErrorCode::CompNotSupp). An
    /// encrypted entry is decrypted with the default password
    /// ([`Archive::set_default_password`]), and fails with
    /// [`ErrorCode::NoPasswd`](crate::zip::ErrorCode::NoPasswd) without one.
    /// Several entries may be open at once, each reading at its own
    /// position.
    pub fn fopen_index(&self, index: u64, flags: Flags) -> Result<ZipFile<'_, R>> {
        self.fopen_index_encrypted(index, flags, self.default_password.as_deref())
    }
}
