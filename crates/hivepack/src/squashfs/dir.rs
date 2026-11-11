//! Directories: `dir.c`. Listing one, skipping ahead through its index,
//! looking up a name and a path.

use std::cmp::Ordering;
use std::io::{Read, Seek};

use super::error::{Result, err};
use super::fs::{Inode, InodeId, MdCursor, Sqfs};
use super::nonstd::{s_isdir, sqfs_mode};
use super::squashfs_fs::{
    DIR_ENTRY_SIZE, DIR_HEADER_SIZE, DIR_INDEX_SIZE, DirHeader, DirIndex, SQUASHFS_METADATA_SIZE,
    SQUASHFS_NAME_LEN,
};
use super::swap::{sqfs_swapin_dir_entry, sqfs_swapin_dir_header, sqfs_swapin_dir_index};

/// `sqfs_dir`: a directory being listed.
#[derive(Clone, Copy, Debug)]
pub struct Dir {
    cur: MdCursor,
    /// Where in the listing, in bytes.
    offset: i64,
    /// The listing's length, in bytes.
    total: i64,
    header: DirHeader,
}

/// `sqfs_dir_entry`: an entry of a directory.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DirEntry {
    /// Its inode (`sqfs_dentry_inode`).
    pub inode: InodeId,
    /// Its inode's number (`sqfs_dentry_inode_num`).
    pub inode_number: u32,
    /// Its inode's type, as the directory records it (`sqfs_dentry_type`).
    pub inode_type: u16,
    /// Its name, 1 to 256 bytes (`sqfs_dentry_name`).
    pub name: Vec<u8>,
    /// Where it is in the listing (`sqfs_dentry_offset`).
    pub offset: i64,
    /// Where the next is (`sqfs_dentry_next_offset`): where to list from
    /// again.
    pub next_offset: i64,
}

impl DirEntry {
    /// `sqfs_dentry_mode`: the `S_IF*` bits of its type.
    pub fn mode(&self) -> u16 {
        sqfs_mode(self.inode_type)
    }

    /// `sqfs_dentry_is_dir`: whether it is a directory, by its type.
    pub fn is_dir(&self) -> bool {
        s_isdir(self.mode())
    }
}

/// `strncmp`: `a` and `b` as C strings, which end at a NUL (or at the
/// slice's end), compared in at most `n` bytes.
pub fn strncmp(a: &[u8], b: &[u8], n: usize) -> Ordering {
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x.cmp(&y);
        }
        if x == 0 {
            break;
        }
    }
    Ordering::Equal
}

impl<R: Read + Seek> Sqfs<R> {
    /// `sqfs_dir_md_read`: metadata of the listing, `buf` or passed over.
    fn sqfs_dir_md_read(
        &mut self,
        dir: &mut Dir,
        size: u64,
        buf: Option<&mut Vec<u8>>,
    ) -> Result<()> {
        dir.offset = dir.offset.wrapping_add(size as i64);
        self.sqfs_md_read_into(&mut dir.cur, size, buf)
    }

    fn sqfs_dir_md_read_array<const N: usize>(&mut self, dir: &mut Dir) -> Result<[u8; N]> {
        let mut buf = Vec::with_capacity(N);
        self.sqfs_dir_md_read(dir, N as u64, Some(&mut buf))?;
        let mut out = [0u8; N];
        out.copy_from_slice(&buf);
        Ok(out)
    }

    /// `sqfs_dir_open`: the listing of a directory, from `offset` (an
    /// entry's `next_offset`) if it is not 0.
    pub fn sqfs_dir_open(&mut self, inode: &Inode, offset: i64) -> Result<Dir> {
        if !s_isdir(inode.base.mode) {
            return Err(err("not a directory"));
        }
        let dir_size = inode.xtra.dir_size();
        let mut dir = Dir {
            cur: MdCursor {
                block: u64::from(inode.xtra.dir_start_block())
                    .wrapping_add(self.sb.directory_table_start) as i64,
                offset: usize::from(inode.xtra.dir_offset()),
            },
            offset: 0,
            total: if dir_size <= 3 {
                0
            } else {
                i64::from(dir_size - 3)
            },
            header: DirHeader::default(),
        };
        if offset != 0 {
            self.sqfs_dir_ff_offset(inode, &mut dir, offset)?;
        }
        Ok(dir)
    }

    /// `sqfs_dir_next`: the next entry, or `None` at the end. The name is
    /// read unless `with_name` is false (squashfuse's entry without a name
    /// buffer).
    pub fn sqfs_dir_next(&mut self, dir: &mut Dir, with_name: bool) -> Result<Option<DirEntry>> {
        let offset = dir.offset;
        while dir.header.count == 0 {
            if dir.offset >= dir.total {
                return Ok(None);
            }
            let header = self.sqfs_dir_md_read_array::<DIR_HEADER_SIZE>(dir)?;
            dir.header = sqfs_swapin_dir_header(&header);
            // Biased by one.
            dir.header.count = dir.header.count.wrapping_add(1);
        }
        let e = self.sqfs_dir_md_read_array::<DIR_ENTRY_SIZE>(dir)?;
        let e = sqfs_swapin_dir_entry(&e);
        dir.header.count -= 1;

        let name_size = usize::from(e.size) + 1;
        let mut entry = DirEntry {
            inode: (u64::from(dir.header.start_block) << 16).wrapping_add(u64::from(e.offset)),
            // e.inode_number is signed.
            inode_number: dir
                .header
                .inode_number
                .wrapping_add(e.inode_number as i16 as i32 as u32),
            inode_type: e.type_,
            name: Vec::new(),
            offset,
            next_offset: 0,
        };
        if name_size > SQUASHFS_NAME_LEN {
            return Err(err("a name longer than 256 bytes"));
        }
        let mut name = Vec::with_capacity(name_size);
        self.sqfs_dir_md_read(dir, name_size as u64, with_name.then_some(&mut name))?;
        entry.name = name;
        entry.next_offset = dir.offset;
        Ok(Some(entry))
    }

    /// `sqfs_dir_ff_header`: goes through the directory's index, from its
    /// inode's metadata, until `func` says to stop, moving `dir` to the
    /// header of the last index entry passed.
    fn sqfs_dir_ff_header(
        &mut self,
        inode: &Inode,
        dir: &mut Dir,
        mut func: impl FnMut(&mut Self, &mut MdCursor, &DirIndex) -> Result<bool>,
    ) -> Result<()> {
        let mut cur = inode.next;
        let count = inode.xtra.dir_idx_count();
        if count == 0 {
            return Ok(());
        }
        for _ in 0..count {
            let idx = self.sqfs_md_read::<DIR_INDEX_SIZE>(&mut cur)?;
            let idx = sqfs_swapin_dir_index(&idx);
            if func(self, &mut cur, &idx)? {
                break;
            }
            dir.cur.block =
                u64::from(idx.start_block).wrapping_add(self.sb.directory_table_start) as i64;
            dir.offset = i64::from(idx.index);
        }
        dir.cur.offset = ((dir.cur.offset as u64).wrapping_add(dir.offset as u64)
            % SQUASHFS_METADATA_SIZE as u64) as usize;
        Ok(())
    }

    /// `sqfs_dir_ff_offset`: moves `dir` to `offset` in the listing, which
    /// must be where an entry starts.
    fn sqfs_dir_ff_offset(&mut self, inode: &Inode, dir: &mut Dir, offset: i64) -> Result<()> {
        // sqfs_dir_ff_offset_f: stop at an index entry at or past `offset`,
        // else pass over its name.
        self.sqfs_dir_ff_header(inode, dir, |fs, cur, index| {
            if i64::from(index.index) >= offset {
                return Ok(true);
            }
            fs.sqfs_md_read_into(cur, u64::from(index.size.wrapping_add(1)), None)?;
            Ok(false)
        })?;
        while dir.offset < offset {
            if self.sqfs_dir_next(dir, false)?.is_none() {
                break;
            }
        }
        if dir.offset == offset {
            Ok(())
        } else {
            Err(err("no entry at that offset"))
        }
    }

    /// `sqfs_dir_lookup`: the entry of a directory named `name`, found
    /// through the directory's index then in order, as the names are
    /// sorted.
    pub fn sqfs_dir_lookup(&mut self, inode: &Inode, name: &[u8]) -> Result<Option<DirEntry>> {
        let mut dir = self.sqfs_dir_open(inode, 0)?;
        let namelen = name.len();
        // sqfs_dir_ff_name_f: stop at the first index entry past `name`.
        self.sqfs_dir_ff_header(inode, &mut dir, |fs, cur, index| {
            // In 32 bits, as in squashfuse.
            let name_size = index.size.wrapping_add(1) as usize;
            if name_size > SQUASHFS_NAME_LEN {
                return Err(err("a name longer than 256 bytes"));
            }
            let found = fs.sqfs_md_read_vec(cur, name_size as u64)?;
            let order = strncmp(&found, name, namelen);
            Ok(order == Ordering::Greater || (order == Ordering::Equal && name_size > namelen))
        })?;
        while let Some(entry) = self.sqfs_dir_next(&mut dir, true)? {
            let order = strncmp(&entry.name, name, namelen);
            if order == Ordering::Equal && entry.name.len() == namelen {
                return Ok(Some(entry));
            }
            if order != Ordering::Less {
                break;
            }
        }
        Ok(None)
    }

    /// `sqfs_lookup_path_with_id`: the inode at `path` from `inode`, which
    /// it replaces when found, with the id of the last one found. The path's
    /// parts are separated by `/`.
    pub fn sqfs_lookup_path_with_id(
        &mut self,
        inode: &mut Inode,
        path: &[u8],
        id: &mut Option<InodeId>,
    ) -> Result<bool> {
        let mut rest = path;
        loop {
            // Skip leading slashes.
            while let [b'/', more @ ..] = rest {
                rest = more;
            }
            let size = rest.iter().position(|&c| c == b'/').unwrap_or(rest.len());
            if size == 0 {
                break;
            }
            let name = &rest[..size];
            rest = &rest[size..];
            let Some(entry) = self.sqfs_dir_lookup(inode, name)? else {
                return Ok(false);
            };
            *id = Some(entry.inode);
            *inode = self.sqfs_inode_get(entry.inode)?;
        }
        Ok(true)
    }
}
