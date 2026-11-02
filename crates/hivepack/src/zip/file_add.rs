//! Port of `zip_file_add.c`.

use std::sync::Arc;

use crate::zip::error::Result;
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::source_data::DataSource;
use crate::zip::zip::Flags;

impl<R: ReadAt> Archive<R> {
    /// Adds an entry named `name` with the data of `source`, and gives its
    /// index: port of `zip_file_add`. With [`Flags::OVERWRITE`], an entry
    /// with that name is replaced instead. The data is read when the
    /// archive is written, compressed with deflate unless that makes it
    /// larger (see [`Archive::set_file_compression`]).
    pub fn file_add<S: DataSource + 'static>(
        &mut self,
        name: &[u8],
        source: S,
        flags: Flags,
    ) -> Result<u64> {
        self.file_replace_impl(None, Some(name), Arc::new(source), flags)
    }
}
