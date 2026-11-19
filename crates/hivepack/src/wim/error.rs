//! Why a WIM archive, or something in it, could not be read.

use core::fmt;
use std::io;

/// Why reading failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The file could not be read.
    Io(io::Error),
    /// Not a WIM: the eight bytes it begins with are not the ones.
    Unrecognized,
    /// A version this does not read. The one every tool writes is 1.13,
    /// which is what Windows has written since Vista.
    Version {
        /// What the header says, as it says it.
        version: u32,
    },
    /// The header says a layout that cannot be read: a size that is not
    /// the format's, a resource that is not on the file, or a part of a
    /// spanned set rather than a whole archive.
    Says,
    /// A resource's own numbers cannot be read: longer than the file, or
    /// an uncompressed length that does not match what it holds.
    Resource,
    /// The table of resources holds something that is not an entry, or
    /// more entries than are read.
    Lookup,
    /// The directory tree holds something that is not an entry: a length
    /// that leaves no room for the entry itself, a name that is not UTF-16,
    /// or a child list that leads out of the metadata.
    Tree,
    /// The directory tree leads back into itself: a directory whose
    /// children are a directory already walked into.
    TreeLoops,
    /// Directories inside directories past what is walked.
    TooDeep,
    /// More entries than are read, in one image or in all of them.
    TooMany,
    /// The image asked for is not in the archive.
    NoSuchImage {
        /// What was asked for, counted from 1 as every tool counts.
        index: u32,
    },
    /// What was to be read as a file is a directory.
    NotAFile,
    /// The archive holds what this does not read, named rather than
    /// guessed at.
    Needs(Unsupported),
}

/// What a WIM may hold that is not read, which is why it is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unsupported {
    /// Resources compressed with XPRESS.
    Xpress,
    /// Resources compressed with LZX, which is what `install.wim` on a
    /// Windows disc holds.
    Lzx,
    /// Resources compressed with LZMS, which is what a `.esd` holds.
    Lzms,
    /// A compression the header names and nothing here knows.
    Compression {
        /// The bits the header's flags hold for it.
        flags: u32,
    },
    /// A solid resource: many files compressed together in one block, as
    /// an `.esd` and a `wimlib --solid` archive hold them.
    Solid,
    /// An archive cut into parts (`.swm`), each holding some of the
    /// resources: reading one part cannot reach the others.
    Spanned,
    /// A file whose data is a reparse point — a symbolic link, a junction,
    /// a placeholder a filter driver fills in — which is not a file's
    /// bytes.
    Reparse {
        /// What kind, as the entry says.
        tag: u32,
    },
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unsupported::Xpress => f.write_str("XPRESS, which is not decoded yet"),
            Unsupported::Lzx => f.write_str("LZX, which is not decoded yet"),
            Unsupported::Lzms => f.write_str("LZMS, which is not decoded yet"),
            Unsupported::Compression { flags } => {
                write!(f, "a compression this does not know ({flags:#x})")
            }
            Unsupported::Solid => f.write_str("a solid block, which is not read yet"),
            Unsupported::Spanned => f.write_str("the other parts of a split archive"),
            Unsupported::Reparse { tag } => {
                write!(
                    f,
                    "a reparse point ({tag:#010x}), which is not a file's bytes"
                )
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "the file could not be read: {e}"),
            Error::Unrecognized => write!(f, "not a WIM archive"),
            Error::Version { version } => {
                write!(f, "a WIM of version {version:#010x}, which is not read")
            }
            Error::Says => write!(f, "the header says a layout it cannot have"),
            Error::Resource => write!(f, "a resource's own numbers cannot be read"),
            Error::Lookup => write!(f, "the table of resources is not one"),
            Error::Tree => write!(f, "the directory tree holds what is not an entry"),
            Error::TreeLoops => write!(f, "the directory tree leads back into itself"),
            Error::TooDeep => write!(f, "directories inside directories past what is walked"),
            Error::TooMany => write!(f, "more entries than are read"),
            Error::NoSuchImage { index } => write!(f, "the archive holds no image {index}"),
            Error::NotAFile => write!(f, "that is a directory, not a file"),
            Error::Needs(what) => write!(f, "the archive needs {what}"),
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
