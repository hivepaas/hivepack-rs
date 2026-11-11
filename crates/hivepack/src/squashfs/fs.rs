//! The file system: `fs.c` and `fs.h`. Opening the image (`sqfs_init`),
//! metadata and data blocks through their caches, metadata cursors, ids,
//! symbolic links, the export table and inodes.

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

use super::cache::Cache;
use super::decompress::{Compression, Contexts, Decompressor, sqfs_decompressor_get};
use super::error::{Error, Result, SqfsErr, err};
use super::nonstd::{s_islnk, sqfs_mode};
use super::squashfs_fs::{
    BASE_INODE_SIZE, BaseInode, DEV_INODE_SIZE, DIR_INODE_SIZE, FRAGMENT_ENTRY_SIZE,
    IPC_INODE_SIZE, LDEV_INODE_SIZE, LDIR_INODE_SIZE, LIPC_INODE_SIZE, LREG_INODE_SIZE,
    REG_INODE_SIZE, SQUASHFS_BLKDEV_TYPE, SQUASHFS_CHRDEV_TYPE, SQUASHFS_COMPRESSED_BIT,
    SQUASHFS_COMPRESSED_BIT_BLOCK, SQUASHFS_DIR_TYPE, SQUASHFS_FIFO_TYPE, SQUASHFS_FILE_MAX_LOG,
    SQUASHFS_FILE_MAX_SIZE, SQUASHFS_INVALID_BLK, SQUASHFS_INVALID_XATTR, SQUASHFS_LBLKDEV_TYPE,
    SQUASHFS_LCHRDEV_TYPE, SQUASHFS_LDIR_TYPE, SQUASHFS_LFIFO_TYPE, SQUASHFS_LREG_TYPE,
    SQUASHFS_LSOCKET_TYPE, SQUASHFS_LSYMLINK_TYPE, SQUASHFS_MAGIC, SQUASHFS_MAJOR,
    SQUASHFS_METADATA_SIZE, SQUASHFS_MINOR, SQUASHFS_REG_TYPE, SQUASHFS_SOCKET_TYPE,
    SQUASHFS_SYMLINK_TYPE, SUPER_BLOCK_SIZE, SYMLINK_INODE_SIZE, SuperBlock, XattrIdTable,
};
use super::swap::{le16, le32, le64, sqfs_swap16, sqfs_swapin_base_inode, sqfs_swapin_super_block};
use super::table::{Table, Which};

/// `SQFS_MAGIC_SWAP`: the magic of an image in the other byte order.
const SQFS_MAGIC_SWAP: u32 = 0x6873_7173;

/// `SQUASHFS_CACHED_BLKS`: the metadata blocks kept, single-threaded.
const SQUASHFS_CACHED_BLKS: usize = 8;
/// `DATA_CACHED_BLKS`: the data blocks kept, single-threaded.
const DATA_CACHED_BLKS: usize = 1;
/// `FRAG_CACHED_BLKS`: the fragment blocks kept, single-threaded.
const FRAG_CACHED_BLKS: usize = 3;
/// `SQUASHFS_META_SLOTS`: the files whose block index is kept.
const SQUASHFS_META_SLOTS: usize = 8;

/// `sqfs_block`: a block's data, decompressed, shared with the cache that
/// keeps it (squashfuse counts its references).
pub type Block = Arc<Vec<u8>>;

/// `sqfs_inode_id`: where an inode is, the start of its metadata block
/// from the inode table's start, shifted 16 bits, and its offset in the
/// block's data.
pub type InodeId = u64;

/// `sqfs_md_cursor`: a place in the metadata, a block (from the image's
/// start) and an offset in its data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MdCursor {
    /// Where the metadata block is: its header's place.
    pub block: i64,
    /// Where in its data.
    pub offset: usize,
}

/// `sqfs_blockidx_entry`: where a file goes on, at the start of one of the
/// metadata blocks that hold its block sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockidxEntry {
    /// A data block where the file continues.
    pub data_block: u64,
    /// The metadata block with the block sizes from there, from the inode
    /// table's start.
    pub md_block: u32,
}

/// `struct sqfs`: an open image.
#[derive(Debug)]
pub(crate) struct Sqfs<R> {
    reader: R,
    /// The image's length, past `offset` too.
    size: u64,
    /// Where the reader is, if known.
    at: Option<u64>,
    /// Where the image starts in the reader.
    pub offset: u64,
    pub sb: SuperBlock,
    pub id_table: Table,
    pub frag_table: Table,
    pub export_table: Table,
    md_cache: Cache<(Block, u64)>,
    pub data_cache: Cache<Block>,
    pub frag_cache: Cache<Block>,
    pub blockidx: Cache<Vec<BlockidxEntry>>,
    decompressor: Decompressor,
    contexts: Contexts,
    pub xattr_info: XattrIdTable,
    pub xattr_table: Table,
}

/// Which data cache: `fs->data_cache` or `fs->frag_cache`.
#[derive(Clone, Copy, Debug)]
pub enum DataCache {
    Data,
    Frag,
}

/// `sqfs_divceil`: how many groups of `group` hold `total`.
pub fn sqfs_divceil(total: u64, group: u64) -> u64 {
    let mut q = total / group;
    if !total.is_multiple_of(group) {
        q += 1;
    }
    q
}

/// `sqfs_md_header`: whether a metadata block is compressed, and its size
/// (0 meaning 32 KiB).
pub fn sqfs_md_header(hdr: u16) -> (bool, u16) {
    let compressed = hdr & SQUASHFS_COMPRESSED_BIT == 0;
    let mut size = hdr & !SQUASHFS_COMPRESSED_BIT;
    if size == 0 {
        size = SQUASHFS_COMPRESSED_BIT;
    }
    (compressed, size)
}

/// `sqfs_data_header`: whether a data block is compressed, and its size.
pub fn sqfs_data_header(hdr: u32) -> (bool, u32) {
    (
        hdr & SQUASHFS_COMPRESSED_BIT_BLOCK == 0,
        hdr & !SQUASHFS_COMPRESSED_BIT_BLOCK,
    )
}

/// `sqfs_md_cursor_inode`: the cursor of an inode id, from `base`.
pub fn sqfs_md_cursor_inode(id: InodeId, base: u64) -> MdCursor {
    MdCursor {
        block: (id >> 16).wrapping_add(base) as i64,
        offset: (id & 0xffff) as usize,
    }
}

impl<R: Read + Seek> Sqfs<R> {
    /// `sqfs_init`: opens the image that starts at `offset` in `reader`.
    ///
    /// Differs from squashfuse: the tables are read one after the other,
    /// and the first that fails stops it, where squashfuse reads them all
    /// and fails at the end; the error is `SQFS_ERR` either way.
    pub fn sqfs_init(mut reader: R, offset: u64) -> Result<Sqfs<R>> {
        let size = reader.seek(SeekFrom::End(0))?;
        let mut fs = Sqfs {
            reader,
            size,
            at: None,
            offset,
            sb: SuperBlock::default(),
            id_table: Table::default(),
            frag_table: Table::default(),
            export_table: Table::default(),
            md_cache: Cache::new(SQUASHFS_CACHED_BLKS),
            data_cache: Cache::new(DATA_CACHED_BLKS),
            frag_cache: Cache::new(FRAG_CACHED_BLKS),
            blockidx: Cache::new(SQUASHFS_META_SLOTS),
            decompressor: |_, _, _| None,
            contexts: Contexts::default(),
            xattr_info: XattrIdTable::default(),
            xattr_table: Table::default(),
        };
        let sb = match fs.sqfs_pread(SUPER_BLOCK_SIZE as u64, 0, "no superblock") {
            Ok(bytes) => {
                let mut b = [0u8; SUPER_BLOCK_SIZE];
                b.copy_from_slice(&bytes);
                b
            }
            Err(Error::Squashfs { .. }) => {
                return Err(Error::new(SqfsErr::BadFormat, "shorter than a superblock"));
            }
            Err(e) => return Err(e),
        };
        fs.sb = sqfs_swapin_super_block(&sb);
        if fs.sb.s_magic != SQUASHFS_MAGIC {
            if fs.sb.s_magic != SQFS_MAGIC_SWAP {
                return Err(Error::new(SqfsErr::BadFormat, "no SquashFS magic"));
            }
            fs.sb.s_major = sqfs_swap16(fs.sb.s_major);
            fs.sb.s_minor = sqfs_swap16(fs.sb.s_minor);
        }
        if fs.sb.s_major != SQUASHFS_MAJOR || fs.sb.s_minor > SQUASHFS_MINOR {
            return Err(Error::new(SqfsErr::BadVersion, "not SquashFS 4.0"));
        }
        let block_size = fs.sb.block_size;
        if block_size == 0
            || block_size > SQUASHFS_FILE_MAX_SIZE
            || block_size & (block_size - 1) != 0
            || fs.sb.block_log > SQUASHFS_FILE_MAX_LOG
            || block_size != 1u32 << fs.sb.block_log
        {
            return Err(Error::new(
                SqfsErr::BadFormat,
                "a block size it cannot have",
            ));
        }

        fs.decompressor = match sqfs_decompressor_get(Compression::from_id(fs.sb.compression)) {
            Some(decompressor) => decompressor,
            None => {
                return Err(Error::new(SqfsErr::BadComp, "an unknown compressor"));
            }
        };

        fs.id_table =
            fs.sqfs_table_init(fs.sb.id_table_start as i64, 4, u64::from(fs.sb.no_ids))?;
        fs.frag_table = fs.sqfs_table_init(
            fs.sb.fragment_table_start as i64,
            FRAGMENT_ENTRY_SIZE,
            u64::from(fs.sb.fragments),
        )?;
        if fs.sqfs_export_ok() {
            fs.export_table =
                fs.sqfs_table_init(fs.sb.lookup_table_start as i64, 8, u64::from(fs.sb.inodes))?;
        }
        fs.sqfs_xattr_init()?;
        Ok(fs)
    }

    /// `sqfs_pread`, which squashfuse's callers check gave all of `size`:
    /// `size` bytes at `pos` from the image's start. A read that would
    /// pass the end fails as a short read does, before anything is read.
    pub fn sqfs_pread(&mut self, size: u64, pos: i64, what: &'static str) -> Result<Vec<u8>> {
        let at = (pos as u64).wrapping_add(self.offset) as i64;
        if at < 0 {
            return Err(err(what));
        }
        let at = at as u64;
        if size > self.size.saturating_sub(at) || at > self.size {
            return Err(err(what));
        }
        // Where the reader is: a block after the one read last is read
        // without seeking.
        if self.at != Some(at) {
            self.at = None;
            self.reader.seek(SeekFrom::Start(at))?;
        }
        let mut buf = vec![0u8; size as usize];
        let mut got = 0;
        while got < buf.len() {
            match self.reader.read(&mut buf[got..]) {
                Ok(0) => return Err(err(what)),
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(Error::Io(e)),
            }
        }
        self.at = Some(at + size);
        Ok(buf)
    }

    /// The length of the image from where it starts.
    pub fn image_size(&self) -> u64 {
        self.size.saturating_sub(self.offset)
    }

    /// The reader.
    pub fn into_reader(self) -> R {
        self.reader
    }

    /// `sqfs_block_read`: `size` bytes at `pos`, decompressed into at most
    /// `outsize` if `compressed`.
    ///
    /// Differs from squashfuse: LZMA data that ends before the size its
    /// header gives is followed by zeros, where squashfuse leaves what was
    /// in memory.
    pub fn sqfs_block_read(
        &mut self,
        pos: i64,
        compressed: bool,
        size: u32,
        outsize: usize,
    ) -> Result<Block> {
        let data = self.sqfs_pread(u64::from(size), pos, "a block is past the end of the image")?;
        if compressed {
            match (self.decompressor)(&mut self.contexts, &data, outsize) {
                Some(out) => Ok(Arc::new(out)),
                None => Err(err("a block does not decompress")),
            }
        } else {
            Ok(Arc::new(data))
        }
    }

    /// `sqfs_md_block_read`: the metadata block at `pos`, and how many bytes
    /// it takes in the image, with its header.
    pub fn sqfs_md_block_read(&mut self, pos: i64) -> Result<(Block, u64)> {
        let hdr = self.sqfs_pread(2, pos, "a metadata block is past the end of the image")?;
        let (compressed, size) = sqfs_md_header(le16(&hdr, 0));
        let block = self.sqfs_block_read(
            pos.wrapping_add(2),
            compressed,
            u32::from(size),
            SQUASHFS_METADATA_SIZE,
        )?;
        Ok((block, 2 + u64::from(size)))
    }

    /// `sqfs_data_block_read`: the data block at `pos`, of header `hdr`.
    pub fn sqfs_data_block_read(&mut self, pos: i64, hdr: u32) -> Result<Block> {
        let (compressed, size) = sqfs_data_header(hdr);
        let block_size = self.sb.block_size as usize;
        self.sqfs_block_read(pos, compressed, size, block_size)
    }

    /// `sqfs_md_cache`: the metadata block at `*pos`, through the cache,
    /// and `*pos` moved past it.
    pub fn sqfs_md_cache(&mut self, pos: &mut i64) -> Result<Block> {
        let slot = self.md_cache.get(*pos as u64);
        let (block, data_size) = match self.md_cache.valid(slot) {
            Some((block, data_size)) => (block.clone(), *data_size),
            None => {
                let (block, data_size) = self.sqfs_md_block_read(*pos)?;
                self.md_cache.mark_valid(slot, (block.clone(), data_size));
                (block, data_size)
            }
        };
        *pos = pos.wrapping_add(data_size as i64);
        Ok(block)
    }

    /// `sqfs_data_cache`: the data block at `pos`, of header `hdr`,
    /// through a cache keyed by `pos` alone.
    pub fn sqfs_data_cache(&mut self, which: DataCache, pos: i64, hdr: u32) -> Result<Block> {
        let cache = match which {
            DataCache::Data => &mut self.data_cache,
            DataCache::Frag => &mut self.frag_cache,
        };
        let slot = cache.get(pos as u64);
        if let Some(block) = cache.valid(slot) {
            return Ok(block.clone());
        }
        let block = self.sqfs_data_block_read(pos, hdr)?;
        let cache = match which {
            DataCache::Data => &mut self.data_cache,
            DataCache::Frag => &mut self.frag_cache,
        };
        cache.mark_valid(slot, block.clone());
        Ok(block)
    }

    /// `sqfs_md_read`: `size` bytes of metadata at `cur`, which moves past
    /// them, appended to `buf`, or passed over without it.
    ///
    /// Differs from squashfuse: what is read grows as it is read, so that a
    /// size the image does not hold takes no more memory than it does.
    pub fn sqfs_md_read_into(
        &mut self,
        cur: &mut MdCursor,
        mut size: u64,
        mut buf: Option<&mut Vec<u8>>,
    ) -> Result<()> {
        let mut pos = cur.block;
        while size > 0 {
            let block = self.sqfs_md_cache(&mut pos)?;
            if cur.offset >= block.len() {
                return Err(err("a metadata read past the end of its block"));
            }
            let take = ((block.len() - cur.offset) as u64).min(size) as usize;
            if let Some(buf) = buf.as_deref_mut() {
                buf.extend_from_slice(&block[cur.offset..cur.offset + take]);
            }
            size -= take as u64;
            cur.offset += take;
            if cur.offset == block.len() {
                cur.block = pos;
                cur.offset = 0;
            }
        }
        Ok(())
    }

    /// `sqfs_md_read` of a structure of `N` bytes.
    pub fn sqfs_md_read<const N: usize>(&mut self, cur: &mut MdCursor) -> Result<[u8; N]> {
        let mut buf = Vec::with_capacity(N);
        self.sqfs_md_read_into(cur, N as u64, Some(&mut buf))?;
        let mut out = [0u8; N];
        out.copy_from_slice(&buf);
        Ok(out)
    }

    /// `sqfs_md_read` of `size` bytes.
    pub fn sqfs_md_read_vec(&mut self, cur: &mut MdCursor, size: u64) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.sqfs_md_read_into(cur, size, Some(&mut buf))?;
        Ok(buf)
    }

    /// `sqfs_id_get`: the uid or gid at `idx` in the id table.
    pub fn sqfs_id_get(&mut self, idx: u16) -> Result<u32> {
        let rid = self.sqfs_table_get(Which::Id, u64::from(idx))?;
        Ok(le32(&rid, 0))
    }

    /// `sqfs_readlink`: a symbolic link's target.
    pub fn sqfs_readlink(&mut self, inode: &Inode) -> Result<Vec<u8>> {
        if !s_islnk(inode.base.mode) {
            return Err(err("not a symbolic link"));
        }
        let want = inode.xtra.symlink_size();
        let mut cur = inode.next;
        self.sqfs_md_read_vec(&mut cur, want)
    }

    /// `sqfs_export_ok`: whether the image has an export table.
    pub fn sqfs_export_ok(&self) -> bool {
        self.sb.lookup_table_start as i64 != SQUASHFS_INVALID_BLK
    }

    /// `sqfs_export_inode`: the inode of number `n`, from the export table.
    pub fn sqfs_export_inode(&mut self, n: u32) -> Result<InodeId> {
        if !self.sqfs_export_ok() {
            return Err(Error::new(SqfsErr::Unsup, "no export table"));
        }
        let r = self.sqfs_table_get(Which::Export, u64::from(n.wrapping_sub(1)))?;
        Ok(le64(&r, 0))
    }

    /// `sqfs_inode_root`: the root directory's inode.
    pub fn sqfs_inode_root(&self) -> InodeId {
        self.sb.root_inode
    }

    /// `sqfs_inode_get`: the inode at `id`.
    pub fn sqfs_inode_get(&mut self, id: InodeId) -> Result<Inode> {
        let mut inode = Inode {
            base: BaseInode::default(),
            nlink: 0,
            xattr: SQUASHFS_INVALID_XATTR,
            next: sqfs_md_cursor_inode(id, self.sb.inode_table_start),
            xtra: Xtra::default(),
        };
        let mut cur = inode.next;
        let base = self.sqfs_md_read::<BASE_INODE_SIZE>(&mut cur)?;
        inode.base = sqfs_swapin_base_inode(&base);
        inode.base.mode |= sqfs_mode(inode.base.inode_type);
        // INODE_TYPE: the whole structure, from the inode's start.
        let ty = inode.base.inode_type;
        let size = match ty {
            SQUASHFS_REG_TYPE => REG_INODE_SIZE,
            SQUASHFS_LREG_TYPE => LREG_INODE_SIZE,
            SQUASHFS_DIR_TYPE => DIR_INODE_SIZE,
            SQUASHFS_LDIR_TYPE => LDIR_INODE_SIZE,
            SQUASHFS_SYMLINK_TYPE | SQUASHFS_LSYMLINK_TYPE => SYMLINK_INODE_SIZE,
            SQUASHFS_BLKDEV_TYPE | SQUASHFS_CHRDEV_TYPE => DEV_INODE_SIZE,
            SQUASHFS_LBLKDEV_TYPE | SQUASHFS_LCHRDEV_TYPE => LDEV_INODE_SIZE,
            SQUASHFS_SOCKET_TYPE | SQUASHFS_FIFO_TYPE => IPC_INODE_SIZE,
            SQUASHFS_LSOCKET_TYPE | SQUASHFS_LFIFO_TYPE => LIPC_INODE_SIZE,
            _ => return Err(err("an unknown inode type")),
        };
        let x = self.sqfs_md_read_vec(&mut inode.next, size as u64)?;
        match ty {
            SQUASHFS_REG_TYPE => {
                inode.nlink = 1;
                inode.xtra.set_reg(
                    u64::from(le32(&x, 16)),
                    u64::from(le32(&x, 28)),
                    le32(&x, 20),
                    le32(&x, 24),
                );
            }
            SQUASHFS_LREG_TYPE => {
                inode.nlink = le32(&x, 40);
                inode
                    .xtra
                    .set_reg(le64(&x, 16), le64(&x, 24), le32(&x, 44), le32(&x, 48));
                inode.xattr = le32(&x, 52);
            }
            SQUASHFS_DIR_TYPE => {
                inode.nlink = le32(&x, 20);
                inode.xtra.set_dir(
                    le32(&x, 16),
                    le16(&x, 26),
                    u32::from(le16(&x, 24)),
                    0,
                    le32(&x, 28),
                );
            }
            SQUASHFS_LDIR_TYPE => {
                inode.nlink = le32(&x, 16);
                inode.xtra.set_dir(
                    le32(&x, 24),
                    le16(&x, 34),
                    le32(&x, 20),
                    le16(&x, 32),
                    le32(&x, 28),
                );
                inode.xattr = le32(&x, 36);
            }
            SQUASHFS_SYMLINK_TYPE | SQUASHFS_LSYMLINK_TYPE => {
                inode.nlink = le32(&x, 16);
                inode.xtra.set_symlink_size(u64::from(le32(&x, 20)));
                if ty == SQUASHFS_LSYMLINK_TYPE {
                    // Past the target, its xattr index.
                    let mut cur = inode.next;
                    self.sqfs_md_read_into(&mut cur, inode.xtra.symlink_size(), None)?;
                    inode.xattr = u32::from_le_bytes(self.sqfs_md_read::<4>(&mut cur)?);
                }
            }
            SQUASHFS_BLKDEV_TYPE | SQUASHFS_CHRDEV_TYPE => {
                inode.nlink = le32(&x, 16);
                inode.xtra.sqfs_decode_dev(le32(&x, 20));
            }
            SQUASHFS_LBLKDEV_TYPE | SQUASHFS_LCHRDEV_TYPE => {
                inode.nlink = le32(&x, 16);
                inode.xtra.sqfs_decode_dev(le32(&x, 20));
                inode.xattr = le32(&x, 24);
            }
            SQUASHFS_SOCKET_TYPE | SQUASHFS_FIFO_TYPE => {
                inode.nlink = le32(&x, 16);
            }
            _ => {
                // SQUASHFS_LSOCKET_TYPE, SQUASHFS_LFIFO_TYPE.
                inode.nlink = le32(&x, 16);
                inode.xattr = le32(&x, 20);
            }
        }
        Ok(inode)
    }
}

/// `struct sqfs_inode`: an inode, as squashfuse keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Inode {
    /// What every inode starts with: its type, mode (with the type's
    /// `S_IF*` bits), owner and group indexes, time and number.
    pub base: BaseInode,
    /// Its link count, as recorded (1 for a basic file).
    pub nlink: u32,
    /// Its index in the xattr id table, `0xffffffff` for none.
    pub xattr: u32,
    /// Where its metadata goes on, past its fixed part: a file's block
    /// sizes, a link's target, a directory's index.
    pub next: MdCursor,
    pub(crate) xtra: Xtra,
}

/// The `xtra` union of `struct sqfs_inode`, laid out as C lays it out on a
/// 64-bit machine: what one type writes is what another reads, as in
/// squashfuse, whose functions choose by the mode, which a damaged image
/// can make another type's than the inode's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct Xtra([u8; 24]);

impl Xtra {
    fn u16_at(&self, at: usize) -> u16 {
        u16::from_le_bytes([self.0[at], self.0[at + 1]])
    }
    fn u32_at(&self, at: usize) -> u32 {
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.0[at..at + 4]);
        u32::from_le_bytes(b)
    }
    fn u64_at(&self, at: usize) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.0[at..at + 8]);
        u64::from_le_bytes(b)
    }
    fn put(&mut self, at: usize, bytes: &[u8]) {
        self.0[at..at + bytes.len()].copy_from_slice(bytes);
    }

    // reg: start_block at 0, file_size at 8, frag_idx at 16, frag_off at 20.
    fn set_reg(&mut self, start_block: u64, file_size: u64, frag_idx: u32, frag_off: u32) {
        self.put(0, &start_block.to_le_bytes());
        self.put(8, &file_size.to_le_bytes());
        self.put(16, &frag_idx.to_le_bytes());
        self.put(20, &frag_off.to_le_bytes());
    }
    pub fn reg_start_block(&self) -> u64 {
        self.u64_at(0)
    }
    pub fn reg_file_size(&self) -> u64 {
        self.u64_at(8)
    }
    pub fn reg_frag_idx(&self) -> u32 {
        self.u32_at(16)
    }
    pub fn reg_frag_off(&self) -> u32 {
        self.u32_at(20)
    }

    // dir: start_block at 0, offset at 4, dir_size at 8, idx_count at 12,
    // parent_inode at 16.
    fn set_dir(
        &mut self,
        start_block: u32,
        offset: u16,
        dir_size: u32,
        idx_count: u16,
        parent: u32,
    ) {
        self.put(0, &start_block.to_le_bytes());
        self.put(4, &offset.to_le_bytes());
        self.put(8, &dir_size.to_le_bytes());
        self.put(12, &idx_count.to_le_bytes());
        self.put(16, &parent.to_le_bytes());
    }
    pub fn dir_start_block(&self) -> u32 {
        self.u32_at(0)
    }
    pub fn dir_offset(&self) -> u16 {
        self.u16_at(4)
    }
    pub fn dir_size(&self) -> u32 {
        self.u32_at(8)
    }
    pub fn dir_idx_count(&self) -> u16 {
        self.u16_at(12)
    }
    pub fn dir_parent_inode(&self) -> u32 {
        self.u32_at(16)
    }

    // symlink_size (size_t) at 0.
    fn set_symlink_size(&mut self, size: u64) {
        self.put(0, &size.to_le_bytes());
    }
    pub fn symlink_size(&self) -> u64 {
        self.u64_at(0)
    }

    // dev: major (int) at 0, minor (int) at 4.
    /// `sqfs_decode_dev`: Linux's device number, a 20-bit minor split
    /// around a 12-bit major.
    fn sqfs_decode_dev(&mut self, rdev: u32) {
        let major = (rdev >> 8) & 0xfff;
        let minor = (rdev & 0xff) | ((rdev >> 12) & 0xfff00);
        self.put(0, &major.to_le_bytes());
        self.put(4, &minor.to_le_bytes());
    }
    pub fn dev_major(&self) -> u32 {
        self.u32_at(0)
    }
    pub fn dev_minor(&self) -> u32 {
        self.u32_at(4)
    }
}
