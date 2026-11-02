//! Port of `zip_add_entry.c`.

use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::zipint::Entry;

impl<R: ReadAt> Archive<R> {
    /// A new entry at the end, with nothing yet: port of `_zip_add_entry`.
    pub(crate) fn add_entry(&mut self) -> u64 {
        self.entry.push(Entry::default());
        self.entry.len() as u64 - 1
    }
}
