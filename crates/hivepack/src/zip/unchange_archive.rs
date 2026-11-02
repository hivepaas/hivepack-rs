//! Port of `zip_unchange_archive.c`.

use crate::zip::open::Archive;
use crate::zip::source::ReadAt;

impl<R: ReadAt> Archive<R> {
    /// Drops the changes to the archive comment and flags: port of
    /// `zip_unchange_archive`.
    pub fn unchange_archive(&mut self) {
        if self.comment_changed {
            self.comment_changes = None;
            self.comment_changed = false;
        }

        self.ch_flags = self.flags;
    }
}
