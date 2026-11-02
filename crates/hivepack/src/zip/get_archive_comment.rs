//! Port of `zip_get_archive_comment.c`.

use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::string::string_get;
use crate::zip::zip::Flags;

impl<R: ReadAt> Archive<R> {
    /// The archive comment, converted as names are, or nothing; as read with
    /// [`Flags::UNCHANGED`]: port of `zip_get_archive_comment`. A
    /// torrentzipped archive has none. As in libzip, a comment removed by
    /// [`Archive::set_archive_comment`] is still given until the archive is
    /// written.
    pub fn get_archive_comment(&self, flags: Flags) -> &[u8] {
        let comment = match &self.comment_changes {
            Some(changes) if !flags.intersects(Flags::UNCHANGED) => changes,
            _ => match &self.comment_orig {
                Some(orig) => orig,
                None => return &[],
            },
        };
        string_get(Some(comment), flags)
    }
}
