//! An entry's header, as libarchive's `archive_entry` holds what the XAR
//! reader sets in it (`archive_entry.c`, `archive_entry_xattr.c`).

use crate::xar::error::Warning;

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

/// The device an entry is on, as `archive_entry` keeps it: a number
/// (`<deviceno>`), or its two parts (`<device><major>`, `<minor>`), which
/// libarchive puts together with the system's `makedev`.
///
/// libarchive's reader sets this, the device the file was on, where its
/// writer wrote the device a device file is ([`Header::rdev`] stays 0):
/// a device file read back has its numbers here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dev {
    /// `archive_entry_set_dev`.
    Number(u64),
    /// `archive_entry_set_devmajor` and `archive_entry_set_devminor`; a
    /// part not given is 0.
    Parts {
        /// The major number.
        major: u64,
        /// The minor number.
        minor: u64,
    },
}

/// An extended attribute: its name (up to a NUL, as libarchive's C
/// string) and value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Xattr {
    /// The name.
    pub name: Vec<u8>,
    /// The value.
    pub value: Vec<u8>,
}

/// An entry: what libarchive's `archive_entry` gives back after the XAR
/// reader filled it.
///
/// libarchive stores the mode in a `mode_t` and the device in a `dev_t`,
/// which are narrower on some systems (16 and 32 bits on macOS), where it
/// refuses larger values; here they are as wide as on Linux.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// The path, with "/" between directories, made of the `<name>` of
    /// each `<file>` it is in; `None` when there is no name, or it is not
    /// UTF-8 (see [`Warning::PathnameConversion`]).
    pub path: Option<Vec<u8>>,
    /// The mode: the file type ([`AE_IFMT`]) from `<type>` (a regular file
    /// if none), and the permissions from `<mode>` (0o777 if none).
    pub mode: u32,
    /// The owner (`<uid>`).
    pub uid: i64,
    /// The group (`<gid>`).
    pub gid: i64,
    /// The owner's name (`<user>`).
    pub uname: Option<Vec<u8>>,
    /// The group's name (`<group>`).
    pub gname: Option<Vec<u8>>,
    /// The number of links: for a directory, 2 and its subdirectories; for
    /// hard links, how many files share the data.
    pub nlink: u32,
    /// The size of the data, once decompressed (`<data><size>`); 0 for one
    /// above `i64::MAX`, as libarchive's `archive_entry_set_size` makes it.
    pub size: u64,
    /// When the file was last read (`<atime>`), in seconds since 1970.
    pub atime: Option<i64>,
    /// When the data last changed (`<mtime>`).
    pub mtime: Option<i64>,
    /// When the file's attributes last changed (`<ctime>`).
    pub ctime: Option<i64>,
    /// The inode (`<inode>`); 0 if none.
    pub ino: i64,
    /// The device (`<deviceno>`, or `<device>`'s parts).
    pub dev: Option<Dev>,
    /// The device a device file is: 0, as libarchive's reader never sets
    /// it (see [`Dev`]).
    pub rdev: u64,
    /// Where a symbolic link points (`<link>`).
    pub symlink: Option<Vec<u8>>,
    /// The path of the file this one is a hard link to.
    pub hardlink: Option<Vec<u8>>,
    /// The file flags, as libarchive's text (`nodump,uappend`), from
    /// `<flags>` (BSD's) and `<ext2>` (Linux's).
    pub fflags_text: Option<Vec<u8>>,
    /// The extended attributes, in the order libarchive gives them: the
    /// reverse of the archive's, which is by `id`.
    pub xattrs: Vec<Xattr>,
    /// What was wrong with the entry: libarchive's `ARCHIVE_WARN`.
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
    /// `aest_devmajor` and `aest_devminor`, which `archive_entry_set_dev`
    /// leaves as they are.
    devmajor: u64,
    devminor: u64,
}

impl Entry {
    /// `archive_entry_copy_symlink_l` of a name that was converted, or
    /// could not be (`None`).
    pub(crate) fn copy_symlink_l(&mut self, target: Option<Vec<u8>>) {
        self.symlink = true;
        self.hardlink = false;
        self.linkname = target;
    }

    /// `archive_entry_set_hardlink` of a name.
    pub(crate) fn set_hardlink(&mut self, target: &[u8]) {
        self.hardlink = true;
        self.symlink = false;
        self.linkname = Some(target.to_vec());
    }

    /// `archive_entry_set_devmajor`: the device in parts, the minor as it
    /// was.
    pub(crate) fn set_devmajor(&mut self, major: u64) {
        self.devmajor = major;
        self.header.dev = Some(Dev::Parts {
            major,
            minor: self.devminor,
        });
    }

    /// `archive_entry_set_devminor`.
    pub(crate) fn set_devminor(&mut self, minor: u64) {
        self.devminor = minor;
        self.header.dev = Some(Dev::Parts {
            major: self.devmajor,
            minor,
        });
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
