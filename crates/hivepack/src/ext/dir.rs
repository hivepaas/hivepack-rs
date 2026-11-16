//! Directory records: a name, the inode it names, and what that is.

use super::error::Error;
use super::inode::What;
use super::sb::{le16, le32};

/// How short a record may be: the fields in front of the name.
const LEAST: usize = 8;

/// How many entries a directory may hold, and how many bytes of it are
/// read. The entries are kept in memory, and no directory any tool writes
/// comes near either.
const MOST_ENTRIES: usize = 1 << 20;
pub(crate) const MOST_ROOM: u64 = 64 << 20;

/// One name in a directory, and the inode it names.
///
/// A name is bytes. Linux puts no meaning on them beyond `/` and the byte
/// that ends a string, so a name may be anything else at all, and a reader
/// that made text of it would answer a name that is not the file's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: Vec<u8>,
    pub ino: u32,
    /// What the record says the inode is, where the file system's records
    /// say: an ext2 made without the feature says nothing, and then the
    /// inode itself is what tells.
    pub what: Option<What>,
}

impl Entry {
    /// The name as text, for showing: bytes that are not UTF-8 come out as
    /// the character that stands for them.
    pub fn name_text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.name)
    }
}

/// What a record says the inode is.
fn what(kind: u8) -> Option<What> {
    Some(match kind {
        1 => What::File,
        2 => What::Dir,
        3 => What::Char,
        4 => What::Block,
        5 => What::Fifo,
        6 => What::Socket,
        7 => What::Symlink,
        _ => return None,
    })
}

/// The entries in `raw`, a directory's blocks of `block` bytes each.
///
/// `.` and `..` are left out: they are what the file system finds its way
/// about with, not names of their own, and following them would walk a
/// directory into its own parent.
///
/// A record of inode 0 is read over. That is how a file system marks room
/// nothing uses any more, and it is also what the blocks of a directory's
/// own hash index look like, and what the record holding a block's
/// checksum is — so reading a directory this way reads what is in it and
/// nothing else, whichever of those a block turns out to be.
pub(crate) fn entries(raw: &[u8], block: usize, filetype: bool) -> Result<Vec<Entry>, Error> {
    let mut found = Vec::new();
    for piece in raw.chunks(block) {
        let mut at = 0usize;
        while at + LEAST <= piece.len() {
            let ino = le32(piece, at);
            let room = usize::from(le16(piece, at + 4));
            // A record has to move on, stay inside its block, and leave
            // room for what it says it holds.
            if room < LEAST || !room.is_multiple_of(4) || at + room > piece.len() {
                return Err(Error::Records);
            }
            let (name_len, kind) = if filetype {
                (usize::from(piece[at + 6]), what(piece[at + 7]))
            } else {
                (usize::from(le16(piece, at + 6)), None)
            };
            if LEAST + name_len > room {
                return Err(Error::Records);
            }
            if ino != 0 && name_len != 0 {
                let name = &piece[at + LEAST..at + LEAST + name_len];
                if name != b"." && name != b".." {
                    if found.len() >= MOST_ENTRIES {
                        return Err(Error::TooMany);
                    }
                    found.push(Entry {
                        name: name.to_vec(),
                        ino,
                        what: kind,
                    });
                }
            }
            at += room;
        }
    }
    Ok(found)
}
