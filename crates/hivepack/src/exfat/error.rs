//! Why an exFAT file system, or something in it, could not be read.

use core::fmt;
use std::io;

/// Why reading failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The disk could not be read.
    Io(io::Error),
    /// Not an exFAT file system: no boot sector that could be one.
    Unrecognized,
    /// FAT12, FAT16 or FAT32, which carries the same signature and is
    /// another file system throughout: `hivepack::fat` reads those.
    Fat,
    /// Both boot regions — the one at the volume's start and the backup
    /// after it — fail the checksum the format keeps for them.
    Checksum,
    /// The boot sector says a layout that cannot be read: a sector or
    /// cluster size the format does not have, a table or a cluster heap
    /// that is not on the volume, no clusters at all, or a root directory
    /// outside them.
    Says,
    /// A chain of clusters leads out of the file system, or back into
    /// itself. Reading on would read the same clusters for ever.
    Chain {
        /// The cluster the chain went wrong at.
        at: u32,
    },
    /// A set of directory entries fails the checksum held in its first
    /// entry: what a name and a length would be read from cannot be
    /// trusted.
    SetChecksum,
    /// A set of directory entries is not one: a name of no entries, fewer
    /// entries than the first says, or a secondary entry where a primary
    /// one belongs.
    Set,
    /// A directory of more entries than are read: a file system whose
    /// directory is longer than any a tool writes.
    TooMany,
    /// Directories inside directories past what is walked, which a chain
    /// of them leading into itself would otherwise be.
    TooDeep,
    /// What was to be read as a directory is a file.
    NotADirectory,
    /// What was to be read as a file is a directory.
    NotAFile,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "the disk could not be read: {e}"),
            Error::Unrecognized => write!(f, "not an exFAT file system"),
            Error::Fat => write!(f, "FAT, which is another file system"),
            Error::Checksum => {
                write!(f, "both boot regions fail the checksum the format keeps")
            }
            Error::Says => write!(f, "the boot sector says a layout it cannot have"),
            Error::Chain { at } => {
                write!(f, "the chain of clusters goes wrong at cluster {at}")
            }
            Error::SetChecksum => {
                write!(f, "a set of directory entries fails its own checksum")
            }
            Error::Set => write!(f, "a set of directory entries is not one"),
            Error::TooMany => write!(f, "a directory holds more entries than are read"),
            Error::TooDeep => write!(f, "directories inside directories past what is walked"),
            Error::NotADirectory => write!(f, "that is a file, not a directory"),
            Error::NotAFile => write!(f, "that is a directory, not a file"),
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
