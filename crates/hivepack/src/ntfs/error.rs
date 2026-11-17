//! Why an NTFS file system, or something in it, could not be read.

use core::fmt;
use std::io;

/// Why reading failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The disk could not be read.
    Io(io::Error),
    /// Not an NTFS file system: no boot sector that names one.
    Unrecognized,
    /// The library that reads the file system refused what it was given:
    /// a field that does not hold, a structure whose signature is not its
    /// own, or a position outside the volume.
    ///
    /// The message is the library's own, kept as text rather than as its
    /// error type, so that which library reads NTFS stays an answer this
    /// crate can change.
    Says(String),
    /// The file's data is compressed, which is not read. NTFS compresses
    /// with LZNT1, and the library hands back the compressed bytes
    /// unchanged rather than refusing them, so a reader that did not stop
    /// here would write files that are not the ones in the image:
    /// `docs/ntfs.md` has the measurement.
    Compressed,
    /// The file's data is encrypted, which is not read: the key is a
    /// Windows user's, and is not in the file system.
    Encrypted,
    /// The file is a reparse point — a symbolic link, a junction, or a
    /// system file Windows stores through its overlay filter. What it
    /// stands for is in the reparse data and not in the file's own data,
    /// which may be empty or compressed by another algorithm again.
    Reparse,
    /// The file's data is described by an attribute list, which is not
    /// read: a file so fragmented that what says where its bytes are does
    /// not fit in one record. The library reads these elsewhere but offers
    /// no way to ask where the bytes went, so they are refused rather than
    /// read wrongly.
    AttributeList,
    /// The runs of a file's data do not cover the length it says it has.
    Short {
        /// How many bytes the file says it holds.
        says: u64,
        /// How many the runs cover.
        covers: u64,
    },
    /// A directory of more entries, or a file of more runs, than are read:
    /// an image whose structures are longer than any a tool writes.
    TooMany,
    /// Directories inside directories past what is walked, which a chain
    /// of them leading into itself would otherwise be.
    TooDeep,
    /// A directory that leads back to one already walked into. Reading on
    /// would walk the same directories for ever.
    Again {
        /// The record the walk came back to.
        at: u64,
    },
    /// What was to be read as a directory is a file.
    NotADirectory,
    /// What was to be read as a file is a directory.
    NotAFile,
}

impl Error {
    /// The library's own refusal, as the message it gives.
    pub(crate) fn says(e: ntfs::NtfsError) -> Error {
        Error::Says(e.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "the disk could not be read: {e}"),
            Error::Unrecognized => write!(f, "not an NTFS file system"),
            Error::Says(what) => write!(f, "the file system could not be read: {what}"),
            Error::Compressed => write!(f, "the file's data is compressed, which is not read"),
            Error::Encrypted => write!(f, "the file's data is encrypted, which is not read"),
            Error::Reparse => write!(
                f,
                "the file is a reparse point, whose content is not its own data"
            ),
            Error::AttributeList => write!(
                f,
                "the file's data is described by an attribute list, which is not read"
            ),
            Error::Short { says, covers } => {
                write!(f, "the file says {says} bytes and its runs cover {covers}")
            }
            Error::TooMany => write!(f, "a structure holds more than is read"),
            Error::TooDeep => write!(f, "directories inside directories past what is walked"),
            Error::Again { at } => write!(f, "the walk comes back to record {at}"),
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
