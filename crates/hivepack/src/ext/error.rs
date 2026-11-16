//! Why an ext file system, or something in it, could not be read.

use core::fmt;
use std::io;

/// Why reading failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The disk could not be read.
    Io(io::Error),
    /// Not an ext2, ext3 or ext4 file system: no superblock that could be
    /// one.
    Unrecognized,
    /// The superblock says a layout that cannot be read: a block size the
    /// format has not got, no blocks or no inodes, groups that do not fit
    /// the disk, or an inode larger than a block.
    Says,
    /// A number that is no inode of this file system: 0, past the last one
    /// there is, or one nothing is in — an inode whose mode says it is
    /// nothing, which is what an inode nothing uses holds.
    NoSuchInode {
        /// What was asked for.
        ino: u32,
    },
    /// A block past the end of the file system, which something names.
    PastTheEnd {
        /// The block that is not there.
        block: u64,
    },
    /// An extent tree that cannot be walked: a node with no signature of
    /// its own, more entries than it has room for, or deeper than the
    /// format allows.
    ExtentTree,
    /// A directory whose records run past the end of a block, or whose
    /// record says a length that would not move on.
    Records,
    /// The extended attributes of an inode cannot be read: a block with no
    /// signature of its own, an entry that runs past the room it is in, an
    /// entry of no name, or a value that is not where it says.
    Xattrs,
    /// A directory of more entries, or more bytes, than are read.
    TooMany,
    /// Directories inside directories past what is walked, or a directory
    /// that leads back into itself.
    TooDeep,
    /// What was to be read as a directory is not one.
    NotADirectory,
    /// What was to be read as a file is not one.
    NotAFile,
    /// What was to be read as a symbolic link is not one.
    NotALink,
    /// The file system needs something this does not do. Each of these
    /// would otherwise be read as a tree that is not on the disk.
    Needs(Unsupported),
}

/// What a file system needs that is not read, which is why it is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unsupported {
    /// A journal that was written and never replayed: what its entries say
    /// belongs in the file system, and putting it there is writing. What
    /// is on the disk is what the file system held before.
    Journal,
    /// Encryption of the file system's own, rather than of a layer around
    /// it: the names and the data are both encrypted.
    Encrypted,
    /// Group descriptors spread over the file system rather than kept
    /// together after the superblock.
    MetaGroups,
    /// Blocks allocated in clusters of several, which every number in the
    /// file system is then counted in.
    BigAlloc,
    /// A file whose data is in the inode itself, in the room extended
    /// attributes are kept in.
    InlineData,
    /// Compression, which no released Linux ever wrote.
    Compression,
    /// A feature the file system says it needs that is not known here at
    /// all.
    Feature,
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Unsupported::Journal => "its journal replayed, which is a write",
            Unsupported::Encrypted => "to be decrypted",
            Unsupported::MetaGroups => "group descriptors spread over it",
            Unsupported::BigAlloc => "blocks counted in clusters",
            Unsupported::InlineData => "data kept in the inode itself",
            Unsupported::Compression => "compression, which Linux never wrote",
            Unsupported::Feature => "a feature this does not know",
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "the disk could not be read: {e}"),
            Error::Unrecognized => write!(f, "not an ext2, ext3 or ext4 file system"),
            Error::Says => write!(f, "the superblock says a layout it cannot have"),
            Error::NoSuchInode { ino } => write!(f, "there is no inode {ino}"),
            Error::PastTheEnd { block } => {
                write!(f, "block {block} is past the end of the file system")
            }
            Error::ExtentTree => write!(f, "the extent tree cannot be walked"),
            Error::Records => write!(f, "a directory's records run past its blocks"),
            Error::Xattrs => write!(f, "the extended attributes of an inode cannot be read"),
            Error::TooMany => write!(f, "a directory holds more than is read"),
            Error::TooDeep => write!(f, "directories inside directories past what is walked"),
            Error::NotADirectory => write!(f, "that is not a directory"),
            Error::NotAFile => write!(f, "that is not a file"),
            Error::NotALink => write!(f, "that is not a symbolic link"),
            Error::Needs(what) => write!(f, "the file system needs {what}, which is not read"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        match e {
            Error::Io(e) => e,
            e => io::Error::new(io::ErrorKind::InvalidData, e),
        }
    }
}
