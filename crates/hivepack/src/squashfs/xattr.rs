//! Extended attributes: `xattr.c`. The xattr id table, and going through an
//! inode's attributes, whose values can be stored out of line (once for
//! several).

use std::io::{Read, Seek};

use super::error::{Result, err};
use super::fs::{Inode, MdCursor, Sqfs, sqfs_md_cursor_inode};
use super::squashfs_fs::{
    SQUASHFS_INVALID_BLK, SQUASHFS_INVALID_XATTR, SQUASHFS_XATTR_PREFIX_MASK,
    SQUASHFS_XATTR_VALUE_OOL, XATTR_ENTRY_SIZE, XATTR_ID_SIZE, XATTR_ID_TABLE_SIZE, XATTR_VAL_SIZE,
    XattrEntry, XattrId,
};
use super::swap::{sqfs_swapin_xattr_entry, sqfs_swapin_xattr_id, sqfs_swapin_xattr_id_table};
use super::table::Which;

/// `sqfs_xattr_prefixes`: the names' prefixes, by type.
const SQFS_XATTR_PREFIXES: [&[u8]; 3] = [b"user.", b"trusted.", b"security."];
/// `SQFS_XATTR_PREFIX_MAX`: `SQUASHFS_XATTR_SECURITY`.
const SQFS_XATTR_PREFIX_MAX: u16 = 2;

/// `sqfs_xattr_curs`: which cursors are set.
const CURS_VSIZE: u8 = 1;
const CURS_VAL: u8 = 2;
const CURS_NEXT: u8 = 4;

/// `sqfs_xattr`: going through an inode's attributes.
#[derive(Clone, Copy, Debug, Default)]
pub struct XattrIter {
    cursors: u8,
    c_name: MdCursor,
    c_vsize: MdCursor,
    c_val: MdCursor,
    c_next: MdCursor,
    /// How many are left.
    pub remain: u64,
    info: XattrId,
    type_: u16,
    ool: bool,
    entry: XattrEntry,
    vsize: u32,
}

impl<R: Read + Seek> Sqfs<R> {
    /// `sqfs_xattr_init`: the xattr id table, if the image has one.
    pub fn sqfs_xattr_init(&mut self) -> Result<()> {
        let start = self.sb.xattr_id_table_start as i64;
        if start == SQUASHFS_INVALID_BLK {
            return Ok(());
        }
        let bytes = self.sqfs_pread(
            XATTR_ID_TABLE_SIZE as u64,
            start,
            "the xattr id table is past the end of the image",
        )?;
        let mut info = [0u8; XATTR_ID_TABLE_SIZE];
        info.copy_from_slice(&bytes);
        self.xattr_info = sqfs_swapin_xattr_id_table(&info);
        self.xattr_table = self.sqfs_table_init(
            start.wrapping_add(XATTR_ID_TABLE_SIZE as i64),
            XATTR_ID_SIZE,
            u64::from(self.xattr_info.xattr_ids),
        )?;
        Ok(())
    }

    /// `sqfs_xattr_open`: the attributes of an inode, none if it has none.
    pub fn sqfs_xattr_open(&mut self, inode: &Inode) -> Result<XattrIter> {
        let mut x = XattrIter::default();
        if self.xattr_info.xattr_ids == 0 || inode.xattr == SQUASHFS_INVALID_XATTR {
            return Ok(x);
        }
        let info = self.sqfs_table_get(Which::Xattr, u64::from(inode.xattr))?;
        x.info = sqfs_swapin_xattr_id(&info);
        x.c_next = sqfs_md_cursor_inode(x.info.xattr, self.xattr_info.xattr_table_start);
        x.remain = u64::from(x.info.count);
        x.cursors = CURS_NEXT;
        Ok(x)
    }

    /// `sqfs_xattr_read`: the next attribute, past the value of the one
    /// before if it was not read.
    pub fn sqfs_xattr_read(&mut self, x: &mut XattrIter) -> Result<()> {
        if x.remain == 0 {
            return Err(err("no more xattrs"));
        }
        if x.cursors & CURS_NEXT == 0 {
            // Force inline: past the value, or the place of one out of line.
            x.ool = false;
            self.sqfs_xattr_value(x, None)?;
        }
        x.c_name = x.c_next;
        let entry = self.sqfs_md_read::<XATTR_ENTRY_SIZE>(&mut x.c_name)?;
        x.entry = sqfs_swapin_xattr_entry(&entry);
        x.type_ = x.entry.type_ & SQUASHFS_XATTR_PREFIX_MASK;
        x.ool = x.entry.type_ & SQUASHFS_XATTR_VALUE_OOL != 0;
        if x.type_ > SQFS_XATTR_PREFIX_MAX {
            return Err(err("an xattr of an unknown type"));
        }
        x.remain -= 1;
        x.cursors = 0;
        Ok(())
    }

    /// `sqfs_xattr_name`: the attribute's name, with its prefix if
    /// `prefix`, appended to `name`, or passed over.
    pub fn sqfs_xattr_name(
        &mut self,
        x: &mut XattrIter,
        name: Option<&mut Vec<u8>>,
        prefix: bool,
    ) -> Result<()> {
        let mut name = name;
        if prefix && let Some(name) = name.as_deref_mut() {
            name.extend_from_slice(SQFS_XATTR_PREFIXES[x.type_ as usize]);
        }
        x.c_vsize = x.c_name;
        self.sqfs_md_read_into(&mut x.c_vsize, u64::from(x.entry.size), name)?;
        x.cursors |= CURS_VSIZE;
        Ok(())
    }

    /// `sqfs_xattr_value_size`: the size of the attribute's value, where it
    /// is, and, for one out of line, where the next attribute is.
    pub fn sqfs_xattr_value_size(&mut self, x: &mut XattrIter) -> Result<u32> {
        if x.cursors & CURS_VSIZE == 0 {
            self.sqfs_xattr_name(x, None, false)?;
        }
        x.c_val = x.c_vsize;
        x.vsize = u32::from_le_bytes(self.sqfs_md_read::<XATTR_VAL_SIZE>(&mut x.c_val)?);
        if x.ool {
            x.c_next = x.c_val;
            let pos = u64::from_le_bytes(self.sqfs_md_read::<8>(&mut x.c_next)?);
            x.cursors |= CURS_NEXT;
            x.c_val = sqfs_md_cursor_inode(pos, self.xattr_info.xattr_table_start);
            x.vsize = u32::from_le_bytes(self.sqfs_md_read::<XATTR_VAL_SIZE>(&mut x.c_val)?);
        }
        x.cursors |= CURS_VAL;
        Ok(x.vsize)
    }

    /// `sqfs_xattr_value`: the attribute's value, appended to `buf`, or
    /// passed over.
    pub fn sqfs_xattr_value(&mut self, x: &mut XattrIter, buf: Option<&mut Vec<u8>>) -> Result<()> {
        if x.cursors & CURS_VAL == 0 {
            self.sqfs_xattr_value_size(x)?;
        }
        let mut c = x.c_val;
        self.sqfs_md_read_into(&mut c, u64::from(x.vsize), buf)?;
        if !x.ool {
            x.c_next = c;
            x.cursors |= CURS_NEXT;
        }
        Ok(())
    }

    /// `sqfs_xattr_name_size`: the name's length with its prefix.
    pub fn sqfs_xattr_name_size(&self, x: &XattrIter) -> usize {
        usize::from(x.entry.size) + SQFS_XATTR_PREFIXES[x.type_ as usize].len()
    }

    /// `sqfs_xattr_lookup`: the value of the attribute `name` of an inode,
    /// with its prefix, if it has it (`sqfs_xattr_find` then the value).
    /// A name without a known prefix is not found.
    pub fn sqfs_xattr_lookup(&mut self, inode: &Inode, name: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut x = self.sqfs_xattr_open(inode)?;
        // sqfs_xattr_find_prefix.
        let Some(type_) = SQFS_XATTR_PREFIXES.iter().position(|p| name.starts_with(p)) else {
            return Ok(None);
        };
        let name = &name[SQFS_XATTR_PREFIXES[type_].len()..];
        // As a C string.
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        let name = &name[..len];
        while x.remain > 0 {
            self.sqfs_xattr_read(&mut x)?;
            if usize::from(x.type_) != type_ || usize::from(x.entry.size) != len {
                continue;
            }
            let mut cmp = Vec::with_capacity(len);
            self.sqfs_xattr_name(&mut x, Some(&mut cmp), false)?;
            if super::dir::strncmp(name, &cmp, len).is_eq() {
                self.sqfs_xattr_value_size(&mut x)?;
                let mut value = Vec::new();
                self.sqfs_xattr_value(&mut x, Some(&mut value))?;
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
}
