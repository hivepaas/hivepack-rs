//! Looking up entries by name: the rules of `zip_hash.c`, on the standard
//! library's `HashMap`, which hashes with SipHash-1-3 and random keys as
//! libzip 1.12 does.

use std::collections::HashMap;
use std::hash::{BuildHasher, DefaultHasher, Hasher, RandomState};

use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::zip::Flags;

/// The name as libzip's table keys it: a C string, which ends at its first
/// NUL byte.
pub(crate) fn c_string(name: &[u8]) -> &[u8] {
    match name.iter().position(|&b| b == 0) {
        Some(end) => &name[..end],
        None => name,
    }
}

/// `zip_hash_entry_t`, without the name it is keyed by: the index of the
/// entry with the name in the archive as read, and now; -1 for none.
#[derive(Clone, Copy)]
struct Indices {
    orig_index: i64,
    current_index: i64,
}

/// The standard library's hasher, without the length it hashes before a slice:
/// keys here are one slice each, and SipHash counts the bytes itself. Hashing
/// is about a quarter of opening an archive of many entries.
struct NameHasher(DefaultHasher);

impl Hasher for NameHasher {
    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes);
    }

    fn write_usize(&mut self, _length: usize) {}

    fn finish(&self) -> u64 {
        self.0.finish()
    }
}

#[derive(Clone, Default)]
struct NameState(RandomState);

impl BuildHasher for NameState {
    type Hasher = NameHasher;

    fn build_hasher(&self) -> NameHasher {
        NameHasher(self.0.build_hasher())
    }
}

/// `zip_hash_t`: each name, and the entries that have it.
#[derive(Clone, Default)]
pub(crate) struct Names {
    table: HashMap<Vec<u8>, Indices, NameState>,
}

impl Names {
    /// `_zip_hash_reserve_capacity`.
    pub(crate) fn reserve_capacity(&mut self, capacity: usize) {
        let _ = self.table.try_reserve(capacity);
    }

    /// Gives `name` to entry `index`, or fails with `ZIP_ER_EXISTS` if an
    /// entry has it already (or had it in the archive as read, with
    /// [`Flags::UNCHANGED`], which also makes it the original name): port
    /// of `_zip_hash_add`.
    pub(crate) fn add(&mut self, name: &[u8], index: u64, flags: Flags) -> Result<()> {
        let name = c_string(name);
        let unchanged = flags.intersects(Flags::UNCHANGED);
        let entry = self.table.entry(name.to_vec()).or_insert(Indices {
            orig_index: -1,
            current_index: -1,
        });
        if (unchanged && entry.orig_index != -1) || entry.current_index != -1 {
            return Err(Error::new(ErrorCode::Exists, 0));
        }
        if unchanged {
            entry.orig_index = index as i64;
        }
        entry.current_index = index as i64;
        Ok(())
    }

    /// Takes `name` from the entry that has it now, or fails with
    /// `ZIP_ER_NOENT`: port of `_zip_hash_delete`.
    pub(crate) fn delete(&mut self, name: &[u8]) -> Result<()> {
        let name = c_string(name);
        let Some(entry) = self.table.get_mut(name) else {
            return Err(Error::new(ErrorCode::NoEntry, 0));
        };
        if entry.orig_index == -1 {
            self.table.remove(name);
        } else {
            entry.current_index = -1;
        }
        Ok(())
    }

    /// The index of the entry named `name` now, or with
    /// [`Flags::UNCHANGED`] in the archive as read: port of
    /// `_zip_hash_lookup`.
    pub(crate) fn lookup(&self, name: &[u8], flags: Flags) -> Result<u64> {
        let found = self.table.get(c_string(name)).map(|entry| {
            if flags.intersects(Flags::UNCHANGED) {
                entry.orig_index
            } else {
                entry.current_index
            }
        });
        match found {
            Some(index) if index != -1 => Ok(index as u64),
            _ => Err(Error::new(ErrorCode::NoEntry, 0)),
        }
    }

    /// Every name back to the entry that had it as read: port of
    /// `_zip_hash_revert`.
    pub(crate) fn revert(&mut self) {
        self.table.retain(|_, entry| {
            entry.current_index = entry.orig_index;
            entry.orig_index != -1
        });
    }
}
