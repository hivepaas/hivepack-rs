//! What squashfuse takes from the system: `nonstd-stat.c` (`sqfs_mode`)
//! and the `S_IF*` bits, which POSIX does not number but every Unix numbers
//! alike, and SquashFS records.

use super::squashfs_fs::{
    SQUASHFS_BLKDEV_TYPE, SQUASHFS_CHRDEV_TYPE, SQUASHFS_DIR_TYPE, SQUASHFS_FIFO_TYPE,
    SQUASHFS_LBLKDEV_TYPE, SQUASHFS_LCHRDEV_TYPE, SQUASHFS_LDIR_TYPE, SQUASHFS_LFIFO_TYPE,
    SQUASHFS_LREG_TYPE, SQUASHFS_LSOCKET_TYPE, SQUASHFS_LSYMLINK_TYPE, SQUASHFS_REG_TYPE,
    SQUASHFS_SOCKET_TYPE, SQUASHFS_SYMLINK_TYPE,
};

pub const S_IFMT: u16 = 0o170000;
pub const S_IFSOCK: u16 = 0o140000;
pub const S_IFLNK: u16 = 0o120000;
pub const S_IFREG: u16 = 0o100000;
pub const S_IFBLK: u16 = 0o060000;
pub const S_IFDIR: u16 = 0o040000;
pub const S_IFCHR: u16 = 0o020000;
pub const S_IFIFO: u16 = 0o010000;

pub fn s_isreg(mode: u16) -> bool {
    mode & S_IFMT == S_IFREG
}

pub fn s_isdir(mode: u16) -> bool {
    mode & S_IFMT == S_IFDIR
}

pub fn s_islnk(mode: u16) -> bool {
    mode & S_IFMT == S_IFLNK
}

pub fn s_isblk(mode: u16) -> bool {
    mode & S_IFMT == S_IFBLK
}

pub fn s_ischr(mode: u16) -> bool {
    mode & S_IFMT == S_IFCHR
}

/// `sqfs_mode`: the `S_IF*` bits of an inode type, 0 for none.
pub fn sqfs_mode(inode_type: u16) -> u16 {
    match inode_type {
        SQUASHFS_DIR_TYPE | SQUASHFS_LDIR_TYPE => S_IFDIR,
        SQUASHFS_REG_TYPE | SQUASHFS_LREG_TYPE => S_IFREG,
        SQUASHFS_SYMLINK_TYPE | SQUASHFS_LSYMLINK_TYPE => S_IFLNK,
        SQUASHFS_BLKDEV_TYPE | SQUASHFS_LBLKDEV_TYPE => S_IFBLK,
        SQUASHFS_CHRDEV_TYPE | SQUASHFS_LCHRDEV_TYPE => S_IFCHR,
        SQUASHFS_FIFO_TYPE | SQUASHFS_LFIFO_TYPE => S_IFIFO,
        SQUASHFS_SOCKET_TYPE | SQUASHFS_LSOCKET_TYPE => S_IFSOCK,
        _ => 0,
    }
}
