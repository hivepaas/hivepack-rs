//! The on-disk format: `squashfs_fs.h`, Phillip Lougher's header as
//! squashfuse keeps it. The structures are little-endian on disk; `swap.rs`
//! reads them.

/// `SQUASHFS_MAGIC`: `hsqs` read as a little-endian number.
pub const SQUASHFS_MAGIC: u32 = 0x7371_7368;

pub const SQUASHFS_MAJOR: u16 = 4;
pub const SQUASHFS_MINOR: u16 = 0;

/// The data a metadata block holds, at most.
pub const SQUASHFS_METADATA_SIZE: usize = 8192;

/// The largest block size.
pub const SQUASHFS_FILE_MAX_SIZE: u32 = 1_048_576;
pub const SQUASHFS_FILE_MAX_LOG: u16 = 20;

/// The longest name, in bytes.
pub const SQUASHFS_NAME_LEN: usize = 256;

pub const SQUASHFS_INVALID_FRAG: u32 = 0xffff_ffff;
pub const SQUASHFS_INVALID_XATTR: u32 = 0xffff_ffff;
/// `SQUASHFS_INVALID_BLK`, `(int64_t)-1`: a table that is not there.
pub const SQUASHFS_INVALID_BLK: i64 = -1;

pub const SQUASHFS_DIR_TYPE: u16 = 1;
pub const SQUASHFS_REG_TYPE: u16 = 2;
pub const SQUASHFS_SYMLINK_TYPE: u16 = 3;
pub const SQUASHFS_BLKDEV_TYPE: u16 = 4;
pub const SQUASHFS_CHRDEV_TYPE: u16 = 5;
pub const SQUASHFS_FIFO_TYPE: u16 = 6;
pub const SQUASHFS_SOCKET_TYPE: u16 = 7;
pub const SQUASHFS_LDIR_TYPE: u16 = 8;
pub const SQUASHFS_LREG_TYPE: u16 = 9;
pub const SQUASHFS_LSYMLINK_TYPE: u16 = 10;
pub const SQUASHFS_LBLKDEV_TYPE: u16 = 11;
pub const SQUASHFS_LCHRDEV_TYPE: u16 = 12;
pub const SQUASHFS_LFIFO_TYPE: u16 = 13;
pub const SQUASHFS_LSOCKET_TYPE: u16 = 14;

pub const SQUASHFS_XATTR_VALUE_OOL: u16 = 256;
pub const SQUASHFS_XATTR_PREFIX_MASK: u16 = 0xff;

/// A metadata block's header: set when the block is stored as it is.
pub const SQUASHFS_COMPRESSED_BIT: u16 = 1 << 15;
/// A data block's size: set when the block is stored as it is.
pub const SQUASHFS_COMPRESSED_BIT_BLOCK: u32 = 1 << 24;

pub const ZLIB_COMPRESSION: u16 = 1;
pub const LZMA_COMPRESSION: u16 = 2;
pub const LZO_COMPRESSION: u16 = 3;
pub const XZ_COMPRESSION: u16 = 4;
pub const LZ4_COMPRESSION: u16 = 5;
pub const ZSTD_COMPRESSION: u16 = 6;

/// `struct squashfs_super_block`: the first 96 bytes of the image.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SuperBlock {
    pub s_magic: u32,
    /// How many inodes there are.
    pub inodes: u32,
    /// When the image was made, in seconds since 1970.
    pub mkfs_time: u32,
    pub block_size: u32,
    /// How many fragment blocks there are.
    pub fragments: u32,
    /// The compressor's id: 1 zlib, 2 LZMA, 3 LZO, 4 xz, 5 LZ4, 6 zstd.
    pub compression: u16,
    pub block_log: u16,
    /// The flags mksquashfs sets (`SQUASHFS_NOI` and the others), which
    /// squashfuse does not read.
    pub flags: u16,
    /// How many uids and gids the id table holds.
    pub no_ids: u16,
    pub s_major: u16,
    pub s_minor: u16,
    /// The root directory's inode.
    pub root_inode: u64,
    /// How long the image is.
    pub bytes_used: u64,
    pub id_table_start: u64,
    pub xattr_id_table_start: u64,
    pub inode_table_start: u64,
    pub directory_table_start: u64,
    pub fragment_table_start: u64,
    /// The export table, which gives an inode by its number.
    pub lookup_table_start: u64,
}

pub const SUPER_BLOCK_SIZE: usize = 96;

/// `struct squashfs_dir_index`, followed by `size + 1` bytes of name.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirIndex {
    pub index: u32,
    pub start_block: u32,
    pub size: u32,
}

/// `struct squashfs_base_inode`: what every inode starts with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BaseInode {
    /// `SQUASHFS_DIR_TYPE` to `SQUASHFS_LSOCKET_TYPE`.
    pub inode_type: u16,
    /// The permissions, and once read the type's `S_IF*` bits too.
    pub mode: u16,
    /// The index of the owner in the id table.
    pub uid: u16,
    /// The index of the group in the id table.
    pub guid: u16,
    pub mtime: u32,
    pub inode_number: u32,
}

/// `struct squashfs_dir_entry`, followed by `size + 1` bytes of name.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirEntryRaw {
    pub offset: u16,
    /// Signed: the inode's number less the header's.
    pub inode_number: u16,
    pub type_: u16,
    pub size: u16,
}

/// `struct squashfs_dir_header`.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirHeader {
    /// The entries after it, less one.
    pub count: u32,
    pub start_block: u32,
    pub inode_number: u32,
}

/// `struct squashfs_fragment_entry`.
#[derive(Clone, Copy, Debug, Default)]
pub struct FragmentEntry {
    pub start_block: u64,
    pub size: u32,
}

/// `struct squashfs_xattr_entry`, followed by `size` bytes of name.
#[derive(Clone, Copy, Debug, Default)]
pub struct XattrEntry {
    pub type_: u16,
    pub size: u16,
}

/// `struct squashfs_xattr_id`, without its `size`, which squashfuse does
/// not read.
#[derive(Clone, Copy, Debug, Default)]
pub struct XattrId {
    pub xattr: u64,
    pub count: u32,
}

/// `struct squashfs_xattr_id_table`.
#[derive(Clone, Copy, Debug, Default)]
pub struct XattrIdTable {
    pub xattr_table_start: u64,
    pub xattr_ids: u32,
}

// The sizes of the structures squashfuse reads with `sizeof`.
pub const DIR_INDEX_SIZE: usize = 12;
pub const BASE_INODE_SIZE: usize = 16;
pub const IPC_INODE_SIZE: usize = 20;
pub const LIPC_INODE_SIZE: usize = 24;
pub const DEV_INODE_SIZE: usize = 24;
pub const LDEV_INODE_SIZE: usize = 28;
pub const SYMLINK_INODE_SIZE: usize = 24;
pub const REG_INODE_SIZE: usize = 32;
pub const LREG_INODE_SIZE: usize = 56;
pub const DIR_INODE_SIZE: usize = 32;
pub const LDIR_INODE_SIZE: usize = 40;
pub const DIR_ENTRY_SIZE: usize = 8;
pub const DIR_HEADER_SIZE: usize = 12;
pub const FRAGMENT_ENTRY_SIZE: usize = 16;
pub const XATTR_ENTRY_SIZE: usize = 4;
pub const XATTR_VAL_SIZE: usize = 4;
pub const XATTR_ID_SIZE: usize = 16;
pub const XATTR_ID_TABLE_SIZE: usize = 16;
