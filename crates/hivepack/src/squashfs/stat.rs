//! An inode's attributes: `stat.c` (`sqfs_stat`), which squashfuse's FUSE
//! programs call.

use std::io::{Read, Seek};

use super::error::Result;
use super::fs::{Inode, Sqfs};
use super::nonstd::{s_isblk, s_ischr, s_islnk, s_isreg};

/// What `sqfs_stat` puts in a `struct stat`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Stat {
    /// `st_mode`: the type's bits and the permissions.
    pub mode: u32,
    /// `st_nlink`: the inode's link count.
    pub nlink: u32,
    /// `st_uid`, from the id table.
    pub uid: u32,
    /// `st_gid`, from the id table.
    pub gid: u32,
    /// `st_mtime`, and `st_ctime` and `st_atime`, which are the same: seconds
    /// since 1970.
    pub mtime: i64,
    /// `st_size`: a file's length, a symbolic link's target's, 0 for the
    /// others (an `off_t`, as in squashfuse).
    pub size: i64,
    /// `st_rdev`: a device's major and minor numbers, 0 for the others.
    pub rdev: (u32, u32),
    /// `st_blksize`: the image's block size.
    pub blksize: u32,
    /// `st_blocks`: a file's length in 512 bytes, rounded down.
    pub blocks: i64,
}

impl<R: Read + Seek> Sqfs<R> {
    /// `sqfs_stat`: an inode's attributes. squashfuse's mount options that
    /// give every inode one owner and group (`uid=`, `gid=`) are not here:
    /// the id table's are given.
    pub fn sqfs_stat(&mut self, inode: &Inode) -> Result<Stat> {
        let mode = inode.base.mode;
        let mut st = Stat {
            mode: u32::from(mode),
            nlink: inode.nlink,
            mtime: i64::from(inode.base.mtime),
            ..Stat::default()
        };
        if s_isreg(mode) {
            st.size = inode.xtra.reg_file_size() as i64;
            st.blocks = st.size / 512;
        } else if s_isblk(mode) || s_ischr(mode) {
            st.rdev = (inode.xtra.dev_major(), inode.xtra.dev_minor());
        } else if s_islnk(mode) {
            st.size = inode.xtra.symlink_size() as i64;
        }
        st.blksize = self.sb.block_size;
        st.uid = self.sqfs_id_get(inode.base.uid)?;
        st.gid = self.sqfs_id_get(inode.base.guid)?;
        Ok(st)
    }
}
