//! Inodes: what a file is, apart from its name.

use super::error::Error;
use super::sb::{Super, le16, le32};

/// What a thing in the file system is, which its mode says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum What {
    File,
    Dir,
    Symlink,
    /// A device of bytes, whose major and minor numbers are
    /// [`Node::device`].
    Char,
    /// A device of blocks.
    Block,
    Fifo,
    Socket,
}

impl What {
    /// What a mode says, or none where it says nothing known.
    fn of(mode: u16) -> Option<What> {
        Some(match mode & 0xF000 {
            0x8000 => What::File,
            0x4000 => What::Dir,
            0xA000 => What::Symlink,
            0x2000 => What::Char,
            0x6000 => What::Block,
            0x1000 => What::Fifo,
            0xC000 => What::Socket,
            _ => return None,
        })
    }
}

/// A time an inode holds: seconds from 1970, and the nanoseconds a file
/// system with room for them keeps beside them.
///
/// Unlike a FAT time, this is UTC: ext has always held seconds from the
/// epoch, so there is nothing to decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Time {
    pub seconds: i64,
    pub nanoseconds: u32,
}

/// The flags of an inode that change how it is read.
const FLAG_EXTENTS: u32 = 0x8_0000;
const FLAG_INLINE_DATA: u32 = 0x1000_0000;
/// How long a symbolic link's target may be and still be kept in the inode
/// itself, in the room the block numbers are in.
pub(crate) const IN_INODE: u64 = 60;

/// One inode: what a file is, apart from the name a directory gives it.
#[derive(Clone, Debug)]
pub struct Node {
    /// Which inode it is.
    pub ino: u32,
    pub what: What,
    /// The permission bits, without what says the kind.
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    /// How many bytes the file holds. A directory's is how much room its
    /// records take.
    pub size: u64,
    /// How many names there are for it. A file of more than one is a hard
    /// link, and what reads a file system sees the same inode twice.
    pub links: u16,
    /// How many 512-byte blocks it takes, which is not how long it is: a
    /// file with holes takes fewer, and one with a tail takes more.
    pub blocks: u64,
    pub accessed: Option<Time>,
    pub modified: Option<Time>,
    /// When the inode itself last changed, which is not when the data did.
    pub changed: Option<Time>,
    /// When it was made, which only a file system with room for it keeps.
    pub created: Option<Time>,
    pub flags: u32,
    /// The 60 bytes that say where the data is: block numbers, or the root
    /// of a tree of extents.
    pub(crate) map: [u8; 60],
}

impl Node {
    /// The inode in `raw`, as the file system `sb` describes one.
    pub(crate) fn of(raw: &[u8], ino: u32, sb: &Super) -> Result<Node, Error> {
        let mode = le16(raw, 0);
        let Some(what) = What::of(mode) else {
            return Err(Error::NoSuchInode { ino });
        };
        let flags = le32(raw, 32);
        // A file whose data is in the inode is refused by the superblock's
        // own feature bit; this is the same thing said per file, which a
        // file system that had the feature turned off again may still hold.
        if flags & FLAG_INLINE_DATA != 0 {
            return Err(Error::Needs(super::Unsupported::InlineData));
        }
        // How much of the inode there is past the 128 bytes every one has,
        // which says which of the newer fields were written.
        let extra = if sb.inode_size > 128 {
            u32::from(le16(raw, 128))
        } else {
            0
        };
        let has = |at: u32, len: u32| sb.inode_size >= at + len && extra >= at + len - 128;
        let time = |at: usize, fine: u32| {
            let seconds = i64::from(le32(raw, at) as i32);
            if !has(fine, 4) {
                // No room for the extra field: seconds, and nothing finer.
                if seconds == 0 {
                    return None;
                }
                return Some(Time {
                    seconds,
                    nanoseconds: 0,
                });
            }
            let extra = le32(raw, fine as usize);
            // Two bits of the extra field carry what the seconds have run
            // out of room for, and the rest is nanoseconds.
            let seconds = seconds + (i64::from(extra & 3) << 32);
            Some(Time {
                seconds,
                nanoseconds: extra >> 2,
            })
        };
        // A size of more than four bytes' worth is a regular file's: the
        // field the high half is in is something else for a directory.
        let size = if what == What::File {
            u64::from(le32(raw, 4)) | (u64::from(le32(raw, 108)) << 32)
        } else {
            u64::from(le32(raw, 4))
        };
        let blocks = u64::from(le32(raw, 28)) | (u64::from(le16(raw, 118)) << 32);
        let mut map = [0u8; 60];
        map.copy_from_slice(&raw[40..100]);
        Ok(Node {
            ino,
            what,
            mode: mode & 0x0FFF,
            uid: u32::from(le16(raw, 2)) | (u32::from(le16(raw, 120)) << 16),
            gid: u32::from(le16(raw, 24)) | (u32::from(le16(raw, 122)) << 16),
            size,
            links: le16(raw, 26),
            blocks,
            accessed: time(8, 140),
            modified: time(16, 136),
            changed: time(12, 132),
            created: if has(144, 4) { time(144, 148) } else { None },
            flags,
            map,
        })
    }

    pub fn is_file(&self) -> bool {
        self.what == What::File
    }

    pub fn is_dir(&self) -> bool {
        self.what == What::Dir
    }

    pub fn is_symlink(&self) -> bool {
        self.what == What::Symlink
    }

    /// Whether the data is found through a tree of extents, which ext4
    /// brought, rather than through the block numbers ext2 had.
    pub(crate) fn extents(&self) -> bool {
        self.flags & FLAG_EXTENTS != 0
    }

    /// The major and minor numbers of a device, which are kept where a
    /// file's blocks would be. The first form is Linux's own, which holds
    /// numbers no older one could.
    pub fn device(&self) -> Option<(u32, u32)> {
        if !matches!(self.what, What::Char | What::Block) {
            return None;
        }
        let old = le32(&self.map, 0);
        let new = le32(&self.map, 4);
        if old != 0 {
            return Some(((old >> 8) & 0xFF, old & 0xFF));
        }
        Some(((new >> 8) & 0xFFF, (new & 0xFF) | ((new >> 20) << 8)))
    }

    /// Whether a symbolic link's target is in the inode itself rather than
    /// in blocks of its own: a short one, which is what every tool writes.
    pub(crate) fn link_in_inode(&self) -> bool {
        self.size < IN_INODE && self.blocks == 0
    }
}
