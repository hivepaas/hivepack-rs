//! An entry's header, as libarchive's `archive_entry` holds what the ISO
//! 9660 reader sets in it (`archive_entry.c`).

use crate::iso::error::Warning;

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

/// An entry: what libarchive's `archive_entry` gives back after the ISO
/// 9660 reader filled it. What the reader did not set is `None` (or 0, as
/// libarchive gives it).
///
/// libarchive stores the mode in a `mode_t` and the device number in a
/// `dev_t`, which are narrower on some systems (16 and 32 bits on macOS);
/// here they are as wide as the image has them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// The path, with "/" between directories: Rock Ridge's name, else
    /// Joliet's in UTF-8, else ISO 9660's without its ";1" version. "."
    /// is the root directory. `None` when it could not be made (see
    /// [`crate::iso::Warning::PathnameConversion`]).
    pub path: Option<Vec<u8>>,
    /// The mode: the file type ([`AE_IFMT`]) and permissions. Rock Ridge's,
    /// else `AE_IFDIR | 0o700` or `AE_IFREG | 0o400`.
    pub mode: u32,
    /// The owner, from Rock Ridge.
    pub uid: u32,
    /// The group, from Rock Ridge.
    pub gid: u32,
    /// The number of links: for a directory, 2 and its subdirectories.
    pub nlink: u32,
    /// The size of the data; `None` for a hard link to the entry before,
    /// whose data that entry has. A zisofs file's data can end before it:
    /// libarchive leaves out the blocks of zeros at its end (zisofs stores
    /// them as nothing), which an extractor writes as zeros, as
    /// libarchive's does.
    pub size: Option<u64>,
    /// When the file was made, in seconds since 1970: Rock Ridge's.
    pub birth_time: Option<i64>,
    /// When the data last changed.
    pub mod_time: Option<i64>,
    /// When the file was last read.
    pub access_time: Option<i64>,
    /// When the file's attributes last changed.
    pub change_time: Option<i64>,
    /// A device's number, from Rock Ridge (the high 32 bits, then the low).
    pub rdev: u64,
    /// Where a symbolic link points.
    pub symlink: Option<Vec<u8>>,
    /// The path of the entry before, when this one is a hard link to it.
    pub hardlink: Option<Vec<u8>>,
    /// What was wrong with the entry: libarchive's `ARCHIVE_WARN`. The
    /// entry then has less than the rest of this says; with
    /// [`Warning::DirectoryOutOfOrder`] or [`Warning::DirectoryBeyondEnd`]
    /// it has nothing but the warning.
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
    /// `archive_entry_copy_symlink` of a name.
    pub(crate) fn copy_symlink(&mut self, target: &[u8]) {
        self.linkname = Some(target.to_vec());
        self.hardlink = false;
        self.symlink = true;
    }

    /// `archive_entry_set_hardlink`.
    pub(crate) fn set_hardlink(&mut self, target: Option<&[u8]>) {
        match target {
            None => {
                self.hardlink = false;
                if self.symlink {
                    return;
                }
            }
            Some(_) => self.hardlink = true,
        }
        self.symlink = false;
        self.linkname = target.map(<[u8]>::to_vec);
    }

    /// `archive_entry_copy_hardlink_l` of a name that was converted, or
    /// could not be (`None`); the symbolic link flag stays as it was.
    pub(crate) fn copy_hardlink_l(&mut self, target: Option<Vec<u8>>) {
        self.hardlink = target.is_some();
        self.linkname = target;
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
