//! Port of `zip_unchange_all.c`.

use crate::zip::open::Archive;
use crate::zip::source::ReadAt;

impl<R: ReadAt> Archive<R> {
    /// Drops every change, to the entries, their names and the archive:
    /// port of `zip_unchange_all`, which cannot fail here.
    pub fn unchange_all(&mut self) {
        self.names.revert();

        for i in 0..self.entry.len() as u64 {
            // Only an index out of range fails.
            let _ = self.unchange_impl(i, true);
        }

        self.unchange_archive();
    }
}
