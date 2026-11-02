//! Port of `zip_get_num_entries.c`.

use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::zip::Flags;

impl<R: ReadAt> Archive<R> {
    /// The number of entries: port of `zip_get_num_entries`.
    pub fn get_num_entries(&self, flags: Flags) -> u64 {
        let mut n = self.entry.len();
        if flags.intersects(Flags::UNCHANGED) {
            while n > 0 && self.entry[n - 1].orig.is_none() {
                n -= 1;
            }
        }
        n as u64
    }
}
