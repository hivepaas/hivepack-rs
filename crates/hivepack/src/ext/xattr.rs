//! Extended attributes: the names and values kept beside an inode, in the
//! room left over in it and in a block of its own.

use super::error::Error;
use super::sb::{le16, le32};

/// What a region of extended attributes begins with, in the inode and in a
/// block alike.
pub(crate) const MAGIC: u32 = 0xEA02_0000;

/// How long a block's header is, before its first entry. The one in an
/// inode has four bytes of signature and nothing else.
pub(crate) const BLOCK_HEADER: usize = 32;
pub(crate) const INODE_HEADER: usize = 4;

/// How long an entry is before its name, and what the length of a whole one
/// is rounded up to.
const ENTRY: usize = 16;
const ALIGN: usize = 4;

/// How long a name may be, which the one byte it is counted in bounds
/// anyway, and how long a value is read: a value in a block is as long as a
/// block at most, and one in an inode of its own may be longer.
const MOST_NAME: usize = 255;
pub(crate) const MOST_VALUE: u64 = 1 << 20;

/// How many attributes an inode may have, which is a bound on arithmetic:
/// the room they are in holds far fewer.
const MOST: usize = 1 << 12;

/// One extended attribute: the whole name, the prefix the file system left
/// out put back, and the value, which is bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xattr {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl Xattr {
    /// The name as text, for showing: a name is bytes, as a file's is,
    /// though every name anything writes is ASCII.
    pub fn name_text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.name)
    }
}

/// What an entry says, before its value has been read.
pub(crate) struct Found {
    pub(crate) name: Vec<u8>,
    /// Where the value is in the region it belongs to, and how long it is.
    pub(crate) at: usize,
    pub(crate) len: usize,
    /// The inode the value is in instead, where the file system keeps the
    /// long ones in inodes of their own, and 0 where the value is here.
    pub(crate) inode: u32,
}

/// The entries of a region of extended attributes.
///
/// `from` is where the entries begin in `raw`, and `values` is what an
/// entry's own offset for its value is counted from: the start of the block
/// for a block, and the first entry for the room inside an inode.
pub(crate) fn entries(raw: &[u8], from: usize, values: usize) -> Result<Vec<Found>, Error> {
    let mut found = Vec::new();
    let mut at = from;
    loop {
        if at + ENTRY > raw.len() {
            // The region ended without a last entry saying so, which every
            // file system that wrote one does.
            return Err(Error::Xattrs);
        }
        // What says there is nothing after it: an entry of nothing at all.
        if le32(raw, at) == 0 {
            return Ok(found);
        }
        let name_len = usize::from(raw[at]);
        let index = raw[at + 1];
        let offset = usize::from(le16(raw, at + 2));
        let inode = le32(raw, at + 4);
        let len = le32(raw, at + 8) as usize;
        if name_len == 0 || name_len > MOST_NAME || at + ENTRY + name_len > raw.len() {
            return Err(Error::Xattrs);
        }
        let mut name = prefix(index).to_vec();
        name.extend_from_slice(&raw[at + ENTRY..at + ENTRY + name_len]);
        // A value kept here has to be in the room the entries are in; one
        // kept in an inode of its own says nothing about where.
        let value_at = values + offset;
        if inode == 0
            && (len > raw.len() || value_at > raw.len() - len || value_at < from.min(values))
        {
            return Err(Error::Xattrs);
        }
        if found.len() >= MOST {
            return Err(Error::TooMany);
        }
        found.push(Found {
            name,
            at: value_at,
            len,
            inode,
        });
        at += (ENTRY + name_len).next_multiple_of(ALIGN);
    }
}

/// What the file system left off the front of a name, which it keeps as a
/// number so that the common beginnings cost one byte.
///
/// Three of them are whole names rather than beginnings: the two kinds of
/// POSIX access control list, and the rich one. A number nothing is known
/// for leaves the name as it lies, which is what the kernel does with one.
fn prefix(index: u8) -> &'static [u8] {
    match index {
        1 => b"user.",
        2 => b"system.posix_acl_access",
        3 => b"system.posix_acl_default",
        4 => b"trusted.",
        6 => b"security.",
        7 => b"system.",
        8 => b"system.richacl",
        _ => b"",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One entry, laid out as a file system lays one out in a block.
    fn one(raw: &mut [u8], at: usize, index: u8, name: &[u8], value: &[u8], value_at: usize) {
        raw[at] = name.len() as u8;
        raw[at + 1] = index;
        raw[at + 2..at + 4].copy_from_slice(&(value_at as u16).to_le_bytes());
        raw[at + 8..at + 12].copy_from_slice(&(value.len() as u32).to_le_bytes());
        raw[at + ENTRY..at + ENTRY + name.len()].copy_from_slice(name);
        raw[value_at..value_at + value.len()].copy_from_slice(value);
    }

    #[test]
    fn the_prefix_the_file_system_left_off_is_put_back() {
        let mut raw = vec![0u8; 1024];
        raw[..4].copy_from_slice(&MAGIC.to_le_bytes());
        one(&mut raw, BLOCK_HEADER, 1, b"comment", b"a value", 900);
        one(&mut raw, BLOCK_HEADER + 24, 6, b"selinux", b"a label", 800);
        let found = entries(&raw, BLOCK_HEADER, 0).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].name, b"user.comment");
        assert_eq!(&raw[found[0].at..found[0].at + found[0].len], b"a value");
        assert_eq!(found[1].name, b"security.selinux");
        // An index that stands for a whole name, not a beginning.
        let mut raw = vec![0u8; 1024];
        one(&mut raw, BLOCK_HEADER, 2, b"", b"x", 900);
        // A name of no bytes at all is no entry.
        assert!(matches!(entries(&raw, BLOCK_HEADER, 0), Err(Error::Xattrs)));
    }

    #[test]
    fn a_value_that_is_not_in_the_room_it_says_is_refused() {
        let mut raw = vec![0u8; 256];
        // A value past the end of the room the entries are in.
        one(&mut raw, BLOCK_HEADER, 1, b"name", b"v", 200);
        raw[BLOCK_HEADER + 2..BLOCK_HEADER + 4].copy_from_slice(&1000u16.to_le_bytes());
        assert!(matches!(entries(&raw, BLOCK_HEADER, 0), Err(Error::Xattrs)));
        // And a region that ends without an entry saying it does.
        let raw = vec![1u8; 40];
        assert!(matches!(entries(&raw, BLOCK_HEADER, 0), Err(Error::Xattrs)));
    }
}
