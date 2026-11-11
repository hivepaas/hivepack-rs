//! Reading the little-endian structures: `swap.c` and the `sqfs_swapin_*`
//! functions `gen_swap.sh` writes into `swap.c.inc`.
//!
//! Differs from squashfuse: squashfuse reads a structure's bytes into the
//! C structure, then swaps each field to the machine's order; here each
//! field is read from its offset in the bytes, little-endian, on every
//! machine.

use super::squashfs_fs::{
    BaseInode, DirEntryRaw, DirHeader, DirIndex, FragmentEntry, SuperBlock, XattrEntry, XattrId,
    XattrIdTable,
};

pub fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

pub fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

pub fn le64(b: &[u8], at: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(bytes)
}

/// `sqfs_swap16`: a 16-bit number's bytes the other way round.
pub fn sqfs_swap16(n: u16) -> u16 {
    n.swap_bytes()
}

/// `sqfs_swapin_super_block`.
pub fn sqfs_swapin_super_block(b: &[u8; 96]) -> SuperBlock {
    SuperBlock {
        s_magic: le32(b, 0),
        inodes: le32(b, 4),
        mkfs_time: le32(b, 8),
        block_size: le32(b, 12),
        fragments: le32(b, 16),
        compression: le16(b, 20),
        block_log: le16(b, 22),
        flags: le16(b, 24),
        no_ids: le16(b, 26),
        s_major: le16(b, 28),
        s_minor: le16(b, 30),
        root_inode: le64(b, 32),
        bytes_used: le64(b, 40),
        id_table_start: le64(b, 48),
        xattr_id_table_start: le64(b, 56),
        inode_table_start: le64(b, 64),
        directory_table_start: le64(b, 72),
        fragment_table_start: le64(b, 80),
        lookup_table_start: le64(b, 88),
    }
}

/// `sqfs_swapin_dir_index`.
pub fn sqfs_swapin_dir_index(b: &[u8; 12]) -> DirIndex {
    DirIndex {
        index: le32(b, 0),
        start_block: le32(b, 4),
        size: le32(b, 8),
    }
}

/// `sqfs_swapin_base_inode`.
pub fn sqfs_swapin_base_inode(b: &[u8]) -> BaseInode {
    BaseInode {
        inode_type: le16(b, 0),
        mode: le16(b, 2),
        uid: le16(b, 4),
        guid: le16(b, 6),
        mtime: le32(b, 8),
        inode_number: le32(b, 12),
    }
}

/// `sqfs_swapin_dir_entry`.
pub fn sqfs_swapin_dir_entry(b: &[u8; 8]) -> DirEntryRaw {
    DirEntryRaw {
        offset: le16(b, 0),
        inode_number: le16(b, 2),
        type_: le16(b, 4),
        size: le16(b, 6),
    }
}

/// `sqfs_swapin_dir_header`.
pub fn sqfs_swapin_dir_header(b: &[u8; 12]) -> DirHeader {
    DirHeader {
        count: le32(b, 0),
        start_block: le32(b, 4),
        inode_number: le32(b, 8),
    }
}

/// `sqfs_swapin_fragment_entry`.
pub fn sqfs_swapin_fragment_entry(b: &[u8]) -> FragmentEntry {
    FragmentEntry {
        start_block: le64(b, 0),
        size: le32(b, 8),
    }
}

/// `sqfs_swapin_xattr_entry`.
pub fn sqfs_swapin_xattr_entry(b: &[u8; 4]) -> XattrEntry {
    XattrEntry {
        type_: le16(b, 0),
        size: le16(b, 2),
    }
}

/// `sqfs_swapin_xattr_id`.
pub fn sqfs_swapin_xattr_id(b: &[u8]) -> XattrId {
    XattrId {
        xattr: le64(b, 0),
        count: le32(b, 8),
    }
}

/// `sqfs_swapin_xattr_id_table`.
pub fn sqfs_swapin_xattr_id_table(b: &[u8; 16]) -> XattrIdTable {
    XattrIdTable {
        xattr_table_start: le64(b, 0),
        xattr_ids: le32(b, 8),
    }
}
