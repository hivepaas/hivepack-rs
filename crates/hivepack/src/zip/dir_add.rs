//! Port of `zip_dir_add.c`.

use crate::zip::error::{Error, Result};
use crate::zip::hash::c_string;
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::source_data::BufferSource;
use crate::zip::zip::{Flags, opsys};
use crate::zip::zipint::EXT_ATTRIB_DEFAULT_DIR;

impl<R: ReadAt> Archive<R> {
    /// Adds a directory named `name`, up to its first NUL byte, with a `/`
    /// at its end if it has none, and gives its index: port of
    /// `zip_dir_add`.
    pub fn dir_add(&mut self, name: &[u8], flags: Flags) -> Result<u64> {
        if self.is_rdonly() {
            return Err(Error::new(crate::zip::ErrorCode::RdOnly, 0));
        }

        let name = c_string(name);
        let mut s = name.to_vec();
        if name.last() != Some(&b'/') {
            s.push(b'/');
        }

        let source = BufferSource::new(Vec::new());
        let idx = self.file_replace_impl(None, Some(&s), std::sync::Arc::new(source), flags)?;

        if let Err(e) = self.file_set_external_attributes(
            idx,
            Flags::NONE,
            opsys::DEFAULT,
            EXT_ATTRIB_DEFAULT_DIR,
        ) {
            let _ = self.delete(idx);
            return Err(e);
        }
        Ok(idx)
    }
}
