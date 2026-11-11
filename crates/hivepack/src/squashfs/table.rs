//! Tables of fixed-size entries in metadata blocks, with the blocks' places
//! listed where the superblock points: `table.c`. The id, fragment, export
//! and xattr id tables are such.

use std::io::{Read, Seek};

use super::error::{Result, err};
use super::fs::{Sqfs, sqfs_divceil};
use super::squashfs_fs::SQUASHFS_METADATA_SIZE;
use super::swap::le64;

/// `sqfs_table`.
#[derive(Debug, Default)]
pub struct Table {
    each: usize,
    count: u64,
    blocks: Vec<u64>,
}

impl<R: Read + Seek> Sqfs<R> {
    /// `sqfs_table_init`: the places of the metadata blocks of `count`
    /// entries of `each` bytes, read at `start`.
    ///
    /// Differs from squashfuse: squashfuse allocates the list before it
    /// reads it; here it is read first, and is only as long as the image.
    pub(crate) fn sqfs_table_init(&mut self, start: i64, each: usize, count: u64) -> Result<Table> {
        if count == 0 {
            return Ok(Table::default());
        }
        let nblocks = sqfs_divceil(
            (each as u64).wrapping_mul(count),
            SQUASHFS_METADATA_SIZE as u64,
        );
        let bread = nblocks.wrapping_mul(8);
        let bytes = self.sqfs_pread(bread, start, "a table is past the end of the image")?;
        let blocks = (0..nblocks as usize).map(|i| le64(&bytes, 8 * i)).collect();
        Ok(Table {
            each,
            count,
            blocks,
        })
    }

    /// `sqfs_table_get`: entry `idx` of a table.
    ///
    /// Differs from squashfuse: an entry past the end of its metadata block
    /// is an error, where squashfuse copies what is in memory after it.
    pub(crate) fn sqfs_table_get(&mut self, table: Which, idx: u64) -> Result<Vec<u8>> {
        let t = self.table(table);
        if idx >= t.count {
            return Err(err("an entry past the end of its table"));
        }
        let each = t.each;
        let pos = idx * each as u64;
        let bnum = pos / SQUASHFS_METADATA_SIZE as u64;
        let off = (pos % SQUASHFS_METADATA_SIZE as u64) as usize;
        let mut bpos = t.blocks[bnum as usize] as i64;
        let block = self.sqfs_md_cache(&mut bpos)?;
        match block.get(off..off + each) {
            Some(entry) => Ok(entry.to_vec()),
            None => Err(err("an entry past the end of its metadata block")),
        }
    }

    fn table(&self, which: Which) -> &Table {
        match which {
            Which::Id => &self.id_table,
            Which::Frag => &self.frag_table,
            Which::Export => &self.export_table,
            Which::Xattr => &self.xattr_table,
        }
    }
}

/// Which of the image's tables.
#[derive(Clone, Copy, Debug)]
pub enum Which {
    Id,
    Frag,
    Export,
    Xattr,
}
