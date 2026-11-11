//! squashfuse's cache: `cache.c`, single-threaded.
//!
//! "Really simplistic": a few entries, searched in order for an index, and
//! the next to evict taken in turn. Which blocks it keeps matters: the data
//! and fragment caches are keyed by where a block is, not by the header it
//! is read with, so in a damaged image two files that name the same place
//! with different headers read what the cache keeps, as in squashfuse.

/// `struct sqfs_cache_internal`, with its entries' headers
/// (`sqfs_cache_entry_hdr`) and data.
#[derive(Debug)]
pub struct Cache<T> {
    entries: Vec<Entry<T>>,
    /// The next entry to evict.
    next: usize,
}

#[derive(Debug)]
struct Entry<T> {
    valid: bool,
    idx: u64,
    data: Option<T>,
}

impl<T> Cache<T> {
    /// `sqfs_cache_init`: `count` entries, all of index 0 and not valid,
    /// as `calloc` leaves them.
    pub fn new(count: usize) -> Cache<T> {
        Cache {
            entries: (0..count)
                .map(|_| Entry {
                    valid: false,
                    idx: 0,
                    data: None,
                })
                .collect(),
            next: 0,
        }
    }

    /// `sqfs_cache_get`: the entry of `idx`, valid or not: the first whose
    /// index it is, or the next to evict, emptied and given that index.
    ///
    /// Differs from squashfuse: it asserts that an entry it finds is valid,
    /// which one whose read failed is not; built without assertions, as a
    /// release is, it gives it, and the caller reads it again, as here.
    pub fn get(&mut self, idx: u64) -> usize {
        if let Some(i) = self.entries.iter().position(|e| e.idx == idx) {
            return i;
        }
        let i = self.next;
        self.next = (self.next + 1) % self.entries.len();
        let entry = &mut self.entries[i];
        // Evict.
        entry.valid = false;
        entry.data = None;
        entry.idx = idx;
        i
    }

    /// `sqfs_cache_entry_valid`: the entry's data, if it is valid.
    pub fn valid(&self, i: usize) -> Option<&T> {
        let entry = &self.entries[i];
        if entry.valid {
            entry.data.as_ref()
        } else {
            None
        }
    }

    /// `sqfs_cache_entry_mark_valid`, with the data the caller made.
    pub fn mark_valid(&mut self, i: usize, data: T) {
        let entry = &mut self.entries[i];
        entry.valid = true;
        entry.data = Some(data);
    }
}
