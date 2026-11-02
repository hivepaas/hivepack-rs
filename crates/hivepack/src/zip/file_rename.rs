//! Port of `zip_file_rename.c`.

use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::hash::c_string;
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::zip::Flags;

impl<R: ReadAt> Archive<R> {
    /// Renames entry `idx` to `name`, up to its first NUL byte as libzip
    /// takes a C string, in the encoding `flags` give
    /// ([`Flags::ENC_GUESS`], [`Flags::ENC_UTF_8`] or
    /// [`Flags::ENC_CP437`]): port of `zip_file_rename`. A directory, whose
    /// name ends in `/`, stays one, and a file stays a file; no other entry
    /// may have the name.
    pub fn file_rename(&mut self, idx: u64, name: &[u8], flags: Flags) -> Result<()> {
        let name = c_string(name);
        if idx >= self.entry.len() as u64 || name.len() > usize::from(u16::MAX) {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        if self.is_rdonly() {
            return Err(Error::new(ErrorCode::RdOnly, 0));
        }

        let old_name = c_string(self.get_name(idx, Flags::NONE)?);

        let new_is_dir = name.last() == Some(&b'/');
        let old_is_dir = old_name.last() == Some(&b'/');

        if new_is_dir != old_is_dir {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        self.set_name(idx, name, flags)
    }
}
