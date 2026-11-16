//! The superblock, and the group descriptors after it.

use crate::image::Disk;

use super::error::{Error, Unsupported};

/// Where the superblock is, and how long it is: 1024 bytes in, whatever a
/// block is, so that a boot sector can lie in front of it.
pub(crate) const AT: u64 = 1024;
pub(crate) const ROOM: usize = 1024;

/// What says a superblock is one.
const MAGIC: u16 = 0xEF53;

/// The block sizes the format has: 1 KiB to 64 KiB, as `s_log_block_size`
/// gives them.
const MOST_LOG_BLOCK: u32 = 6;

/// Which of the three it is: the file system says what it needs, not what
/// it is called, so what it is called is read off the features it has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// No journal and nothing newer: what `mkfs.ext2` writes.
    Ext2,
    /// A journal, and nothing ext4 brought.
    Ext3,
    /// Extents, 64-bit block numbers, checksums of its own metadata — any
    /// of the features that came with ext4.
    Ext4,
}

impl Kind {
    /// What it is called, as a tool names it.
    pub fn says(self) -> &'static str {
        match self {
            Kind::Ext2 => "ext2",
            Kind::Ext3 => "ext3",
            Kind::Ext4 => "ext4",
        }
    }
}

/// The features kept where a reader that does not know one must not read
/// the file system at all.
const INCOMPAT_COMPRESSION: u32 = 0x0001;
const INCOMPAT_FILETYPE: u32 = 0x0002;
const INCOMPAT_RECOVER: u32 = 0x0004;
const INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
const INCOMPAT_META_BG: u32 = 0x0010;
const INCOMPAT_EXTENTS: u32 = 0x0040;
const INCOMPAT_64BIT: u32 = 0x0080;
const INCOMPAT_MMP: u32 = 0x0100;
const INCOMPAT_FLEX_BG: u32 = 0x0200;
const INCOMPAT_EA_INODE: u32 = 0x0400;
const INCOMPAT_DIRDATA: u32 = 0x1000;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const INCOMPAT_LARGEDIR: u32 = 0x4000;
const INCOMPAT_INLINE_DATA: u32 = 0x8000;
const INCOMPAT_ENCRYPT: u32 = 0x1_0000;
const INCOMPAT_CASEFOLD: u32 = 0x2_0000;

/// Every one of those this knows about, whether it reads it or refuses it:
/// a bit outside this is a feature that was not thought of here, and the
/// file system is not read at all.
const INCOMPAT_KNOWN: u32 = INCOMPAT_COMPRESSION
    | INCOMPAT_FILETYPE
    | INCOMPAT_RECOVER
    | INCOMPAT_JOURNAL_DEV
    | INCOMPAT_META_BG
    | INCOMPAT_EXTENTS
    | INCOMPAT_64BIT
    | INCOMPAT_MMP
    | INCOMPAT_FLEX_BG
    | INCOMPAT_EA_INODE
    | INCOMPAT_DIRDATA
    | INCOMPAT_CSUM_SEED
    | INCOMPAT_LARGEDIR
    | INCOMPAT_INLINE_DATA
    | INCOMPAT_ENCRYPT
    | INCOMPAT_CASEFOLD;

/// The features that are ext4's and nothing older: what it is called is
/// read off these, as `blkid` reads it.
const INCOMPAT_EXT4: u32 = INCOMPAT_EXTENTS
    | INCOMPAT_64BIT
    | INCOMPAT_META_BG
    | INCOMPAT_MMP
    | INCOMPAT_FLEX_BG
    | INCOMPAT_EA_INODE
    | INCOMPAT_DIRDATA
    | INCOMPAT_CSUM_SEED
    | INCOMPAT_LARGEDIR
    | INCOMPAT_INLINE_DATA
    | INCOMPAT_ENCRYPT
    | INCOMPAT_CASEFOLD;

/// The features kept where a reader that only reads may read the file
/// system whether it knows them or not — which is what that field is for,
/// so none of them is a reason to refuse. Two change where the bytes are
/// all the same, and are read rather than passed over.
const RO_COMPAT_HUGE_FILE: u32 = 0x0008;
const RO_COMPAT_GDT_CSUM: u32 = 0x0010;
const RO_COMPAT_DIR_NLINK: u32 = 0x0020;
const RO_COMPAT_EXTRA_ISIZE: u32 = 0x0040;
const RO_COMPAT_QUOTA: u32 = 0x0100;
const RO_COMPAT_BIGALLOC: u32 = 0x0200;
const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
const RO_COMPAT_PROJECT: u32 = 0x2000;
const RO_COMPAT_VERITY: u32 = 0x8000;

const RO_COMPAT_EXT4: u32 = RO_COMPAT_HUGE_FILE
    | RO_COMPAT_GDT_CSUM
    | RO_COMPAT_DIR_NLINK
    | RO_COMPAT_EXTRA_ISIZE
    | RO_COMPAT_QUOTA
    | RO_COMPAT_BIGALLOC
    | RO_COMPAT_METADATA_CSUM
    | RO_COMPAT_PROJECT
    | RO_COMPAT_VERITY;

const COMPAT_HAS_JOURNAL: u32 = 0x0004;

/// How many groups there may be, as the descriptors are read when they are
/// wanted and nothing is kept: this is only a bound on arithmetic.
const MOST_GROUPS: u64 = 1 << 32;

/// What the superblock says, of what reading the file system needs.
pub(crate) struct Super {
    /// How many bytes a block is.
    pub(crate) block: u32,
    /// How many blocks there are, and which is the first that holds data:
    /// 1 where a block is 1 KiB, as the superblock is then block 1.
    pub(crate) blocks: u64,
    pub(crate) first_data: u32,
    pub(crate) inodes_per_group: u32,
    pub(crate) inodes: u32,
    /// How many bytes an inode takes in the table.
    pub(crate) inode_size: u32,
    /// How many bytes a group descriptor takes: 32, or what the superblock
    /// says where block numbers are 64 bits.
    pub(crate) desc_size: u32,
    pub(crate) groups: u32,
    /// Whether a directory record says what kind of thing it names, which
    /// every file system but an old ext2 does.
    pub(crate) filetype: bool,
    pub(crate) kind: Kind,
    pub(crate) label: Option<String>,
    pub(crate) uuid: [u8; 16],
}

impl Super {
    /// What the superblock of `disk` says, if it holds one.
    pub(crate) fn read<D: Disk>(disk: &D) -> Result<Super, Error> {
        let whole = disk.size()?;
        if whole < AT + ROOM as u64 {
            return Err(Error::Unrecognized);
        }
        let mut raw = vec![0u8; ROOM];
        disk.read_exact_at(AT, &mut raw)?;
        if le16(&raw, 56) != MAGIC {
            return Err(Error::Unrecognized);
        }
        let log_block = le32(&raw, 24);
        if log_block > MOST_LOG_BLOCK {
            return Err(Error::Says);
        }
        let block = 1024u32 << log_block;
        let incompat = le32(&raw, 96);
        let ro_compat = le32(&raw, 100);
        let compat = le32(&raw, 92);
        // A feature that was not thought of here may be anything at all,
        // and what it changes may be where the data is.
        if incompat & !INCOMPAT_KNOWN != 0 {
            return Err(Error::Needs(Unsupported::Feature));
        }
        if incompat & INCOMPAT_COMPRESSION != 0 {
            return Err(Error::Needs(Unsupported::Compression));
        }
        if incompat & INCOMPAT_ENCRYPT != 0 {
            return Err(Error::Needs(Unsupported::Encrypted));
        }
        // The journal holds what the file system was about to become, and
        // this bit says it has not become it yet.
        if incompat & INCOMPAT_RECOVER != 0 {
            return Err(Error::Needs(Unsupported::Journal));
        }
        if incompat & INCOMPAT_META_BG != 0 {
            return Err(Error::Needs(Unsupported::MetaGroups));
        }
        // A journal of its own is not a file system at all: it is the
        // journal of another one, kept on a disk by itself.
        if incompat & INCOMPAT_JOURNAL_DEV != 0 {
            return Err(Error::Needs(Unsupported::Feature));
        }
        // Clusters are not a reader's business to ignore, however the
        // field it is kept in says they are: every number of blocks in the
        // file system is counted in them.
        if ro_compat & RO_COMPAT_BIGALLOC != 0 {
            return Err(Error::Needs(Unsupported::BigAlloc));
        }
        // Everything after this is read, whether known or not: that is
        // what the read-only field means.
        let revision = le32(&raw, 76);
        let (inode_size, desc_size) = if revision == 0 {
            // The first revision had no such fields, and every file system
            // of it has the one size and the one first inode.
            (128, 32)
        } else {
            let size = u32::from(le16(&raw, 88));
            let desc = u32::from(le16(&raw, 254));
            let desc = if incompat & INCOMPAT_64BIT != 0 {
                if desc < 32 || desc > block || !desc.is_power_of_two() {
                    return Err(Error::Says);
                }
                desc
            } else {
                32
            };
            (size, desc)
        };
        if inode_size < 128 || inode_size > block || !inode_size.is_power_of_two() {
            return Err(Error::Says);
        }
        let blocks = u64::from(le32(&raw, 4))
            | if incompat & INCOMPAT_64BIT != 0 {
                u64::from(le32(&raw, 336)) << 32
            } else {
                0
            };
        let inodes = le32(&raw, 0);
        let blocks_per_group = le32(&raw, 32);
        let inodes_per_group = le32(&raw, 40);
        let first_data = le32(&raw, 20);
        if blocks == 0
            || inodes == 0
            || blocks_per_group == 0
            || inodes_per_group == 0
            || inodes_per_group > inodes
            || first_data >= 2
        {
            return Err(Error::Says);
        }
        // The file system has to be on the disk it is read from. A
        // partition is often longer than the file system in it, which is
        // not a reason to refuse one.
        if blocks.saturating_mul(u64::from(block)) > whole {
            return Err(Error::Says);
        }
        let groups = (blocks - u64::from(first_data)).div_ceil(u64::from(blocks_per_group));
        if groups == 0 || groups > MOST_GROUPS {
            return Err(Error::Says);
        }
        let kind = if incompat & INCOMPAT_EXT4 != 0 || ro_compat & RO_COMPAT_EXT4 != 0 {
            Kind::Ext4
        } else if compat & COMPAT_HAS_JOURNAL != 0 {
            Kind::Ext3
        } else {
            Kind::Ext2
        };
        let label = text(&raw[120..136]);
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&raw[104..120]);
        Ok(Super {
            block,
            blocks,
            first_data,
            inodes_per_group,
            inodes,
            inode_size,
            desc_size,
            groups: groups as u32,
            filetype: incompat & INCOMPAT_FILETYPE != 0,
            kind,
            label,
            uuid,
        })
    }

    /// Where the `block` block is in the file system, or none where there
    /// is no such block.
    pub(crate) fn at(&self, block: u64) -> Option<u64> {
        if block == 0 || block >= self.blocks {
            return None;
        }
        Some(block * u64::from(self.block))
    }

    /// Where the group descriptors are: the block after the one the
    /// superblock is in.
    pub(crate) fn descriptors(&self) -> u64 {
        u64::from(self.first_data + 1) * u64::from(self.block)
    }
}

/// Text of a fixed field, to the first byte that is nothing, or none where
/// there is none at all.
fn text(raw: &[u8]) -> Option<String> {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&raw[..end]).into_owned())
}

pub(crate) fn le16(of: &[u8], at: usize) -> u16 {
    of.get(at..at + 2)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

pub(crate) fn le32(of: &[u8], at: usize) -> u32 {
    of.get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}
