//! An entry's header, as libarchive's `archive_entry` holds what the cpio
//! reader sets in it (`archive_entry.c`).

use crate::cpio::error::Warning;

/// `AE_IFMT`: the file type bits of a mode.
pub const AE_IFMT: u32 = 0o170000;
/// `AE_IFREG`: a regular file.
pub const AE_IFREG: u32 = 0o100000;
/// `AE_IFLNK`: a symbolic link.
pub const AE_IFLNK: u32 = 0o120000;
/// `AE_IFSOCK`: a socket.
pub const AE_IFSOCK: u32 = 0o140000;
/// `AE_IFCHR`: a character device.
pub const AE_IFCHR: u32 = 0o020000;
/// `AE_IFBLK`: a block device.
pub const AE_IFBLK: u32 = 0o060000;
/// `AE_IFDIR`: a directory.
pub const AE_IFDIR: u32 = 0o040000;
/// `AE_IFIFO`: a FIFO.
pub const AE_IFIFO: u32 = 0o010000;

/// A device number, as the archive records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Device {
    /// One number, as odc, afio and the binary formats have it
    /// (`archive_entry_set_dev`, `archive_entry_set_rdev`): `st_dev` or
    /// `st_rdev` on the system that made the archive, whose `major` and
    /// `minor` split it.
    Number(u32),
    /// A major and a minor number, as newc has them
    /// (`archive_entry_set_devmajor` and `archive_entry_set_devminor`).
    /// libarchive gives `makedev` of the two as the number.
    Split {
        /// The major number.
        major: u32,
        /// The minor number.
        minor: u32,
    },
}

impl Default for Device {
    fn default() -> Device {
        Device::Number(0)
    }
}

/// An entry: what libarchive's `archive_entry` gives back after the cpio
/// reader filled it.
///
/// libarchive stores the mode in a `mode_t` and the device numbers in a
/// `dev_t`, which are narrower on some systems (16 and 32 bits on macOS);
/// here they are as wide as the archive has them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// The path, as the archive has it, up to its first NUL.
    pub path: Vec<u8>,
    /// The mode: the file type ([`AE_IFMT`]) and permissions.
    pub mode: u32,
    /// The owner.
    pub uid: u32,
    /// The group.
    pub gid: u32,
    /// The number of links.
    pub nlink: u32,
    /// The inode number, which with [`Header::dev`] tells hard links.
    pub ino: u64,
    /// The size of the data, as the header gives it. A symbolic link's
    /// target is its data, which the reader takes: the size is then that
    /// of the target, and the link has no data left to read.
    pub size: u64,
    /// When the data last changed, in seconds since 1970.
    pub mod_time: i64,
    /// The device the file was on.
    pub dev: Device,
    /// A device file's number.
    pub rdev: Device,
    /// Where a symbolic link points: its data up to the first NUL.
    pub symlink: Option<Vec<u8>>,
    /// The path of an earlier entry with the same device and inode, when
    /// this one is a hard link to it. The data of hard links is wherever
    /// the archive put it: on the first (odc, binary), or on the last with
    /// the others empty (newc, as GNU cpio writes it).
    pub hardlink: Option<Vec<u8>>,
    /// What was wrong before the entry: libarchive's `ARCHIVE_WARN`.
    pub warning: Option<Warning>,
}

impl Header {
    /// The file type: [`AE_IFMT`] of the mode.
    pub fn file_type(&self) -> u32 {
        self.mode & AE_IFMT
    }

    /// Whether this is a directory.
    pub fn is_dir(&self) -> bool {
        self.file_type() == AE_IFDIR
    }
}

/// `archive_entry` as the reader sets it: the link name is one string
/// that the symbolic and hard link flags share, as in libarchive.
#[derive(Debug, Default)]
pub(crate) struct Entry {
    pub(crate) header: Header,
    /// `ae_linkname`: `None` when unset.
    linkname: Option<Vec<u8>>,
    /// `AE_SET_HARDLINK` and `AE_SET_SYMLINK`.
    hardlink: bool,
    symlink: bool,
}

impl Entry {
    /// `archive_entry_copy_symlink_l` of a name, without conversion: up to
    /// its first NUL.
    pub(crate) fn copy_symlink_l(&mut self, target: &[u8]) {
        self.hardlink = false;
        self.linkname = Some(c_string(target).to_vec());
        self.symlink = true;
    }

    /// `archive_entry_copy_hardlink` of a name: the symbolic link flag
    /// stays as it was, so that a symbolic link that is also a hard link
    /// has the hard link's target as both.
    pub(crate) fn copy_hardlink(&mut self, target: &[u8]) {
        self.linkname = Some(target.to_vec());
        self.hardlink = true;
    }

    /// The header, with the links as `archive_entry_symlink` and
    /// `archive_entry_hardlink` give them.
    pub(crate) fn into_header(mut self) -> Header {
        if self.symlink {
            self.header.symlink = self.linkname.clone();
        }
        if self.hardlink {
            self.header.hardlink = self.linkname;
        }
        self.header
    }
}

/// What `archive_strncat` copies of `bytes`: up to the first NUL.
pub(crate) fn c_string(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(n) => &bytes[..n],
        None => bytes,
    }
}
