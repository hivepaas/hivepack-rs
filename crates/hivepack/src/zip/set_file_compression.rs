//! Port of `zip_set_file_compression.c`.

use crate::zip::dirent::Dirent;
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::source_compress::compression_method_supported;
use crate::zip::zipint::changed;

impl<R: ReadAt> Archive<R> {
    /// Sets the method entry `idx` is compressed with when written, a
    /// [`cm`](crate::zip::cm) value or [`cm::DEFAULT`](crate::zip::cm::DEFAULT)
    /// (deflate, unless that makes it larger), and the level, 1 to 9 for
    /// deflate (9 otherwise), 1 to 12 with libdeflate's compressor
    /// ([`Archive::set_deflate_library`]): port of
    /// `zip_set_file_compression`. Its data is decompressed and compressed
    /// again if the method changes.
    pub fn set_file_compression(&mut self, idx: u64, method: i32, flags: u32) -> Result<()> {
        if idx >= self.entry.len() as u64 {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        if self.is_rdonly() {
            return Err(Error::new(ErrorCode::RdOnly, 0));
        }
        if self.want_torrentzip() {
            return Err(Error::new(ErrorCode::NotAllowed, 0));
        }

        if !compression_method_supported(method, true) {
            return Err(Error::new(ErrorCode::CompNotSupp, 0));
        }

        let e = &mut self.entry[idx as usize];

        // TODO in libzip: do we want to recompress if level is set? Only
        // if it's different than what bit flags tell us, but those are
        // not defined for all compression methods, or not directly
        // mappable to levels
        let changes = e
            .changes
            .get_or_insert_with(|| Box::new(Dirent::clone_changes(e.orig.as_deref())));
        changes.comp_method = method;
        changes.compression_level = u32::from(flags as u16);
        changes.changed |= changed::COMP_METHOD;
        Ok(())
    }
}
