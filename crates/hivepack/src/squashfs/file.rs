//! A regular file's data: `file.c`. Its fragment, its list of block sizes,
//! reading a range, and the block index that skips to the middle of a large
//! file.

use std::io::{Read, Seek};

use super::error::{Result, err};
use super::fs::{BlockidxEntry, DataCache, Inode, MdCursor, Sqfs, sqfs_data_header, sqfs_divceil};
use super::nonstd::s_isreg;
use super::squashfs_fs::{FragmentEntry, SQUASHFS_INVALID_FRAG, SQUASHFS_METADATA_SIZE};
use super::swap::sqfs_swapin_fragment_entry;
use super::table::Which;

/// `sizeof(sqfs_blocklist_entry)`: a block size in the list.
const BLOCKLIST_ENTRY: u64 = 4;

/// `sqfs_blocklist`: going through a file's block sizes.
#[derive(Clone, Copy, Debug)]
pub struct Blocklist {
    /// How many blocks are left.
    pub remain: u64,
    /// The next block size in the metadata.
    pub cur: MdCursor,
    pub started: bool,
    /// Where in the file the block is.
    pub pos: u64,
    /// Where in the image the block is.
    pub block: u64,
    /// Its size, as recorded.
    pub header: u32,
    /// Its size in the image.
    pub input_size: u32,
}

/// Not in squashfuse: a place a file's data is read from, where it is in the
/// image and the header it is read with ([`Sqfs::check_data_with`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataPlace {
    /// A data block, through the data cache.
    Block { pos: u64, hdr: u32 },
    /// A fragment block, through the fragment cache.
    Fragment { pos: u64, hdr: u32 },
}

/// Not in squashfuse: what [`Sqfs::sqfs_blockidx_check`] finds of a file's
/// block index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockIndex {
    /// It is never made: the file has too few blocks.
    None,
    /// Its key, and its entries, each leading where the block sizes do.
    Regular(u64, Vec<BlockidxEntry>),
    /// An entry a read goes on from leads elsewhere, or is missing, or the
    /// index does not read.
    Irregular,
}

impl<R: Read + Seek> Sqfs<R> {
    /// `sqfs_frag_entry`: entry `idx` of the fragment table.
    pub fn sqfs_frag_entry(&mut self, idx: u32) -> Result<FragmentEntry> {
        if idx == SQUASHFS_INVALID_FRAG {
            return Err(err("no fragment"));
        }
        let frag = self.sqfs_table_get(Which::Frag, u64::from(idx))?;
        Ok(sqfs_swapin_fragment_entry(&frag))
    }

    /// `sqfs_frag_block`: a file's fragment block, and where its tail is in
    /// it (offset and size).
    pub fn sqfs_frag_block(&mut self, inode: &Inode) -> Result<(usize, usize, super::fs::Block)> {
        if !s_isreg(inode.base.mode) {
            return Err(err("not a regular file"));
        }
        let frag = self.sqfs_frag_entry(inode.xtra.reg_frag_idx())?;
        let block = self.sqfs_data_cache(DataCache::Frag, frag.start_block as i64, frag.size)?;
        let offset = inode.xtra.reg_frag_off() as usize;
        let size = (inode.xtra.reg_file_size() % u64::from(self.sb.block_size)) as usize;
        if offset > block.len() || size > block.len() - offset {
            return Err(err("a fragment past the end of its block"));
        }
        Ok((offset, size, block))
    }

    /// `sqfs_blocklist_count`: how many blocks a file has (its tail not
    /// among them when it is in a fragment).
    pub fn sqfs_blocklist_count(&self, inode: &Inode) -> u64 {
        let size = inode.xtra.reg_file_size();
        let block = u64::from(self.sb.block_size);
        if inode.xtra.reg_frag_idx() == SQUASHFS_INVALID_FRAG {
            sqfs_divceil(size, block)
        } else {
            size / block
        }
    }

    /// `sqfs_blocklist_init`.
    pub fn sqfs_blocklist_init(&self, inode: &Inode) -> Blocklist {
        Blocklist {
            remain: self.sqfs_blocklist_count(inode),
            cur: inode.next,
            started: false,
            pos: 0,
            block: inode.xtra.reg_start_block(),
            header: 0,
            input_size: 0,
        }
    }

    /// `sqfs_blocklist_next`: the next block.
    pub fn sqfs_blocklist_next(&mut self, bl: &mut Blocklist) -> Result<()> {
        if bl.remain == 0 {
            return Err(err("no more blocks"));
        }
        bl.remain -= 1;
        bl.header = u32::from_le_bytes(self.sqfs_md_read::<4>(&mut bl.cur)?);
        bl.block = bl.block.wrapping_add(u64::from(bl.input_size));
        bl.input_size = sqfs_data_header(bl.header).1;
        if bl.started {
            bl.pos = bl.pos.wrapping_add(u64::from(self.sb.block_size));
        }
        bl.started = true;
        Ok(())
    }

    /// `sqfs_read_range`: a file's data from `start`, as much as `buf`
    /// holds, to the end of the file: how much was read. A block of no size
    /// is a hole, of zeros. Reading nothing, but at the end, is an error.
    pub fn sqfs_read_range(&mut self, inode: &Inode, start: u64, buf: &mut [u8]) -> Result<usize> {
        if !s_isreg(inode.base.mode) {
            return Err(err("not a regular file"));
        }
        // sqfs_off_t, as in squashfuse.
        let file_size = inode.xtra.reg_file_size() as i64;
        let start = start as i64;
        let block_size = u64::from(self.sb.block_size);
        if start < 0 || start > file_size {
            return Err(err("a read past the end of the file"));
        }
        if start == file_size {
            return Ok(0);
        }
        let mut bl = self.sqfs_blockidx_blocklist(inode, start as u64)?;

        let mut read_off = start as u64 % block_size;
        let mut at = 0usize;
        while at < buf.len() {
            let fragment = bl.remain == 0;
            let (data_off, data_size, block) = if fragment {
                if inode.xtra.reg_frag_idx() == SQUASHFS_INVALID_FRAG {
                    break;
                }
                let (off, size, block) = self.sqfs_frag_block(inode)?;
                (off, size as u64, Some(block))
            } else {
                self.sqfs_blocklist_next(&mut bl)?;
                if bl.pos.wrapping_add(block_size) <= start as u64 {
                    continue;
                }
                if bl.input_size == 0 {
                    // A hole.
                    let size = (file_size as u64).wrapping_sub(bl.pos).min(block_size);
                    (0, size, None)
                } else {
                    let block =
                        self.sqfs_data_cache(DataCache::Data, bl.block as i64, bl.header)?;
                    let size = block.len() as u64;
                    (0, size, Some(block))
                }
            };
            if read_off >= data_size {
                return Err(err("a read past the end of a block"));
            }
            let take = (data_size - read_off).min((buf.len() - at) as u64) as usize;
            let out = &mut buf[at..at + take];
            match &block {
                Some(block) => {
                    let from = data_off + read_off as usize;
                    out.copy_from_slice(&block[from..from + take]);
                }
                None => out.fill(0),
            }
            read_off = 0;
            at += take;
            if fragment {
                break;
            }
        }
        if at == 0 {
            return Err(err("nothing to read"));
        }
        Ok(at)
    }

    /// Not in squashfuse: checks that a file's data is on the image without
    /// reading it: its block sizes read, each block within the image, and
    /// its fragment's entry read and within the image too. What does not
    /// decompress is only found when it is read.
    pub fn check_data(&mut self, inode: &Inode) -> Result<()> {
        self.check_data_with(inode, &mut |_| {})
    }

    /// Not in squashfuse: [`Sqfs::check_data`], telling `each` every place
    /// the file's data is read from as `sqfs_read_range` goes through it
    /// from its start, in order: each block but its holes, then its
    /// fragment's block.
    pub fn check_data_with(
        &mut self,
        inode: &Inode,
        each: &mut dyn FnMut(DataPlace),
    ) -> Result<()> {
        if !s_isreg(inode.base.mode) {
            return Err(err("not a regular file"));
        }
        let size = self.image_size();
        let within = |pos: u64, len: u64| pos.checked_add(len).is_some_and(|end| end <= size);
        let mut bl = self.sqfs_blocklist_init(inode);
        while bl.remain > 0 {
            self.sqfs_blocklist_next(&mut bl)?;
            if bl.input_size != 0 && !within(bl.block, u64::from(bl.input_size)) {
                return Err(err("a block is past the end of the image"));
            }
            if bl.input_size != 0 {
                each(DataPlace::Block {
                    pos: bl.block,
                    hdr: bl.header,
                });
            }
        }
        if inode.xtra.reg_frag_idx() != SQUASHFS_INVALID_FRAG {
            let frag = self.sqfs_frag_entry(inode.xtra.reg_frag_idx())?;
            if !within(frag.start_block, u64::from(sqfs_data_header(frag.size).1)) {
                return Err(err("a fragment is past the end of the image"));
            }
            each(DataPlace::Fragment {
                pos: frag.start_block,
                hdr: frag.size,
            });
        }
        Ok(())
    }

    /// Not in squashfuse: the block index `sqfs_read_range` makes of a file
    /// and keeps, if it ever does, with the key it keeps it by, and whether
    /// each of its entries that a read goes on from leads where going
    /// through the file's block sizes from its start does: in an image
    /// mksquashfs makes, each does; in a damaged one whose metadata blocks
    /// are not the usual size, an entry may lead elsewhere, or be missing
    /// and zeros.
    pub fn sqfs_blockidx_check(&mut self, inode: &Inode) -> BlockIndex {
        let count = self.sqfs_blocklist_count(inode);
        let md_size = count.wrapping_mul(BLOCKLIST_ENTRY);
        // sqfs_blockidx_indexable.
        if md_size < SQUASHFS_METADATA_SIZE as u64 {
            return BlockIndex::None;
        }
        let Ok(index) = self.sqfs_blockidx_add(inode) else {
            return BlockIndex::Irregular;
        };
        let offset = inode.next.offset as u64;
        // The last metadata block a read goes to: that of the block after
        // the last, where the fragment is.
        let last = offset.wrapping_add(md_size) / SQUASHFS_METADATA_SIZE as u64;
        let mut bl = self.sqfs_blocklist_init(inode);
        let mut gone = 0u64;
        for metablock in 1..=last {
            // As sqfs_blockidx_blocklist skips.
            let skipped = (metablock.wrapping_mul(SQUASHFS_METADATA_SIZE as u64) / BLOCKLIST_ENTRY)
                .wrapping_sub(offset / BLOCKLIST_ENTRY);
            if skipped >= count {
                // Nothing left but the fragment: the entry is not read.
                if skipped == count {
                    continue;
                }
                return BlockIndex::Irregular;
            }
            while gone < skipped {
                if self.sqfs_blocklist_next(&mut bl).is_err() {
                    return BlockIndex::Irregular;
                }
                gone += 1;
            }
            let Some(entry) = index.get((metablock - 1) as usize) else {
                return BlockIndex::Irregular;
            };
            let md_block = u64::from(entry.md_block).wrapping_add(self.sb.inode_table_start) as i64;
            if entry.data_block != bl.block.wrapping_add(u64::from(bl.input_size))
                || md_block != bl.cur.block
                || bl.cur.offset != inode.next.offset % BLOCKLIST_ENTRY as usize
            {
                return BlockIndex::Irregular;
            }
        }
        BlockIndex::Regular(u64::from(inode.base.inode_number.wrapping_add(1)), index)
    }

    /// `sqfs_blockidx_add`: the block index of a file, where it goes on at
    /// the start of each of its metadata blocks of block sizes but the
    /// first.
    ///
    /// Differs from squashfuse: the index grows as it is made, where
    /// squashfuse allocates it from the file's size first; and the entries
    /// squashfuse would leave as they were in memory, when the metadata
    /// blocks are not the usual size, are zeros.
    fn sqfs_blockidx_add(&mut self, inode: &Inode) -> Result<Vec<BlockidxEntry>> {
        let blocks = self.sqfs_blocklist_count(inode);
        let md_size = blocks.wrapping_mul(BLOCKLIST_ENTRY);
        let count = (inode.next.offset as u64)
            .wrapping_add(md_size)
            .wrapping_sub(1)
            / SQUASHFS_METADATA_SIZE as u64;
        let mut blockidx = Vec::new();
        let mut bl = self.sqfs_blocklist_init(inode);
        let mut first = true;
        while bl.remain != 0 && (blockidx.len() as u64) < count {
            // A small offset: a new metadata block. The first is known.
            if (bl.cur.offset as u64) < BLOCKLIST_ENTRY && !first {
                blockidx.push(BlockidxEntry {
                    data_block: bl.block.wrapping_add(u64::from(bl.input_size)),
                    md_block: (bl.cur.block as u64).wrapping_sub(self.sb.inode_table_start) as u32,
                });
            }
            first = false;
            self.sqfs_blocklist_next(&mut bl)?;
        }
        Ok(blockidx)
    }

    /// `sqfs_blockidx_blocklist`: a file's block list, moved on to the block
    /// at `start` through the block index, made and kept for large files.
    pub fn sqfs_blockidx_blocklist(&mut self, inode: &Inode, start: u64) -> Result<Blocklist> {
        let mut bl = self.sqfs_blocklist_init(inode);
        let block = start / u64::from(self.sb.block_size);
        if block > bl.remain {
            // The fragment.
            bl.remain = 0;
            return Ok(bl);
        }
        // How many metadata blocks to skip.
        let metablock = (bl.cur.offset as u64).wrapping_add(block.wrapping_mul(BLOCKLIST_ENTRY))
            / SQUASHFS_METADATA_SIZE as u64;
        if metablock == 0 {
            return Ok(bl);
        }
        // sqfs_blockidx_indexable: too small to index.
        let md_size = self
            .sqfs_blocklist_count(inode)
            .wrapping_mul(BLOCKLIST_ENTRY);
        if md_size < SQUASHFS_METADATA_SIZE as u64 {
            return Ok(bl);
        }

        // 0 is no index: the number plus one, in 32 bits.
        let idx = u64::from(inode.base.inode_number.wrapping_add(1));
        let slot = self.blockidx.get(idx);
        if self.blockidx.valid(slot).is_none() {
            let blockidx = self.sqfs_blockidx_add(inode)?;
            self.blockidx.mark_valid(slot, blockidx);
        }
        let entry = self
            .blockidx
            .valid(slot)
            .and_then(|index| index.get((metablock - 1) as usize))
            .copied()
            .unwrap_or_default();

        let skipped = (metablock * SQUASHFS_METADATA_SIZE as u64 / BLOCKLIST_ENTRY)
            .wrapping_sub(bl.cur.offset as u64 / BLOCKLIST_ENTRY);
        bl.cur.block = u64::from(entry.md_block).wrapping_add(self.sb.inode_table_start) as i64;
        bl.cur.offset %= BLOCKLIST_ENTRY as usize;
        bl.remain = bl.remain.wrapping_sub(skipped);
        bl.pos = skipped.wrapping_mul(u64::from(self.sb.block_size));
        bl.block = entry.data_block;
        Ok(bl)
    }
}
