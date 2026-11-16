//! Why a disk image's partitions could not be read.

use core::fmt;
use std::io;

/// Why the table could not be read. A disk with no table at all is not an
/// error: [`partitions`](super::partitions) says there is none.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The disk could not be read.
    Io(io::Error),
    /// A GUID partition table's header does not pass its own CRC-32, in
    /// the one at the disk's start and in the copy at its end alike.
    HeaderCheck,
    /// A GUID partition table's entries do not pass the CRC-32 its header
    /// gives for them, in both copies alike.
    EntriesCheck,
    /// A GUID partition table's header says a size, an entry size or a
    /// number of entries that cannot be read: smaller than the
    /// specification's least, or larger than the disk.
    HeaderSays,
    /// A partition reaches past the end of the disk, or is so long that
    /// where it ends cannot be counted.
    PastTheEnd {
        /// Which partition, as the table numbers it.
        number: u32,
    },
    /// A master boot record's chain of extended partitions leads back into
    /// itself.
    ExtendedLoops,
    /// [`partitions_in`](super::partitions_in) was given a sector size no
    /// disk has: smaller than 512 bytes, or not a power of two.
    SectorSize {
        /// What it was given.
        sector: u64,
    },
    /// Not an image of the format it was opened as.
    Unrecognized,
    /// A VHD's dynamic header does not pass its own checksum. The footer
    /// failing its own is `Unrecognized`, as that is what tells a VHD.
    VhdCheck,
    /// A VHD says a layout that cannot be read: a disk of no whole
    /// sectors, a block size that is not a power of two, a table that is
    /// not on the file or that does not reach the whole disk.
    VhdSays,
    /// A VHD that holds only what changed from another disk. Reading one
    /// means reading its parent, which is a file this cannot reach.
    Differencing,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "the disk could not be read: {e}"),
            Error::HeaderCheck => write!(f, "the partition table's header fails its own CRC-32"),
            Error::EntriesCheck => write!(f, "the partition table's entries fail their CRC-32"),
            Error::HeaderSays => {
                write!(f, "the partition table's header says sizes it cannot have")
            }
            Error::PastTheEnd { number } => {
                write!(f, "partition {number} reaches past the end of the disk")
            }
            Error::ExtendedLoops => {
                write!(f, "the extended partitions lead back into themselves")
            }
            Error::SectorSize { sector } => {
                write!(f, "no disk has sectors of {sector} bytes")
            }
            Error::Unrecognized => write!(f, "not an image of that format"),
            Error::VhdCheck => write!(f, "the VHD's dynamic header fails its own checksum"),
            Error::VhdSays => write!(f, "the VHD says a layout it cannot have"),
            Error::Differencing => {
                write!(
                    f,
                    "a differencing VHD holds only what changed from its parent"
                )
            }
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
