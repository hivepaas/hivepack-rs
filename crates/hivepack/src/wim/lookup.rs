//! The table of resources: where each one is, how long it is, and the
//! SHA-1 of what it holds, which is what a tree's entries name it by.

use std::collections::HashMap;
use std::io::{Read, Seek};

use super::error::Error;
use super::{Compression, Resource, le16, le32, read_resource};

/// How long one entry is: a resource header, which part it is in, how many
/// names point at it, and the hash.
const ENTRY: usize = 50;

/// How many entries are read at most. A Windows disc's `install.wim` has a
/// hundred thousand or so; the table is held in memory.
const MOST_ENTRIES: usize = 1 << 22;

/// The flag that says a resource is one image's tree rather than a file's
/// bytes.
const METADATA: u8 = 0x02;

/// What the table holds: every resource by the hash of what it holds, and
/// the trees in the order the table gives them.
pub(crate) struct Resources {
    by_hash: HashMap<[u8; 20], Resource>,
    metadata: Vec<Resource>,
    count: usize,
}

impl Resources {
    /// The resource whose bytes hash to `hash`, where the table holds one.
    pub(crate) fn by_hash(&self, hash: &[u8; 20]) -> Option<Resource> {
        self.by_hash.get(hash).copied()
    }

    /// The trees, in the order the table holds them, which is the order
    /// the images are numbered in.
    pub(crate) fn metadata(&self) -> impl Iterator<Item = Resource> + '_ {
        self.metadata.iter().copied()
    }

    pub(crate) fn len(&self) -> usize {
        self.count
    }
}

/// The table at `table`, read whole.
///
/// Every entry is checked to be on the file as it is read, so a table
/// naming a resource somewhere else fails here rather than when something
/// reaches for that resource.
pub(crate) fn read<R: Read + Seek>(
    reader: &mut R,
    table: &Resource,
    whole: u64,
    compression: Compression,
    chunk: u32,
) -> Result<Resources, Error> {
    let raw = read_resource(
        reader,
        table,
        whole,
        compression,
        chunk,
        (MOST_ENTRIES * ENTRY) as u64,
    )?;
    if !raw.len().is_multiple_of(ENTRY) {
        return Err(Error::Lookup);
    }
    let count = raw.len() / ENTRY;
    if count > MOST_ENTRIES {
        return Err(Error::Lookup);
    }
    let mut by_hash = HashMap::with_capacity(count);
    let mut metadata = Vec::new();
    for entry in raw.as_chunks::<ENTRY>().0 {
        let resource = Resource::of(entry, 0);
        // A solid resource's numbers are not places on the file: its
        // offset is inside the block it was packed into, and that block
        // has a descriptor of its own. Measured on what `wimlib-imagex
        // capture --solid` writes, which is what a `.esd` is. Nothing here
        // unpacks one, so it is kept as it stands and refused by name when
        // something reaches for it, rather than counted a broken table.
        if !resource.solid() && !resource.on_the_file(whole) {
            return Err(Error::Lookup);
        }
        // Which part of a split set holds it. A whole archive says 1, and
        // the header has already refused a part of a set.
        let part = le16(entry, 24);
        if part > 1 {
            return Err(Error::Lookup);
        }
        let _refcount = le32(entry, 26);
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&entry[30..50]);
        if resource.flags & METADATA != 0 {
            metadata.push(resource);
            continue;
        }
        // A hash of nothing is what a file of no bytes carries, and the
        // table does not hold a resource for one.
        if hash != [0u8; 20] {
            by_hash.insert(hash, resource);
        }
    }
    Ok(Resources {
        by_hash,
        metadata,
        count,
    })
}
