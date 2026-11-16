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
    /// A QCOW2 image says a layout that cannot be read: a cluster size the
    /// format does not have, a table that is not on the file, or one that
    /// does not reach the whole disk.
    Qcow2Says,
    /// A VHDX's headers, or both of its region tables, fail their own
    /// CRC-32C: neither copy of what says where the image's parts are can
    /// be trusted.
    VhdxCheck,
    /// A VHDX says a layout that cannot be read: a block size the format
    /// does not have, a region or an item that is not on the file, a sector
    /// that is neither 512 bytes nor 4096, or metadata that does not say
    /// what the disk is.
    VhdxSays,
    /// A VMDK says a layout that cannot be read: a grain size the format
    /// does not have, a table that is not on the file, a descriptor naming
    /// no extent at all or more than are read, or a stream of compressed
    /// grains whose footer is not where it has to be.
    VmdkSays,
    /// A VMDK's descriptor names an extent as a path rather than as a name
    /// beside it. Reading it would be reading a file the descriptor chose,
    /// which is refused however the path reads.
    VmdkElsewhere,
    /// An image that needs something this does not do. Each of these would
    /// otherwise be read as a disk of holes, so none is passed over.
    Needs(Unsupported),
}

/// What an image needs that is not read, which is why it is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unsupported {
    /// Another image behind this one: what is not in it is in that one,
    /// named by a path written when this one was made. A differencing VHD
    /// and a QCOW2 image with a backing file are both this.
    Backing,
    /// The data in a file of its own, this one holding only the tables.
    ExternalData,
    /// The files beside it, which hold the disk a descriptor only
    /// describes: a reader of one file cannot reach them, and
    /// [`Vmdk::beside`](super::Vmdk::beside), which is given a path, can.
    Beside,
    /// Encryption of the image's own, rather than of a layer around it.
    Encrypted,
    /// The image is marked as damaged by whatever last wrote it.
    Corrupt,
    /// Clusters divided into subclusters, whose tables are twice as wide.
    ExtendedL2,
    /// Clusters compressed with Zstandard, in a build without hivepack's
    /// `zstd` feature.
    Zstd,
    /// Entries written to a VHDX's log and never applied: what they say
    /// belongs in its tables, and putting it there is writing.
    Log,
    /// Something the image says it needs that is not known here at all.
    Feature,
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Unsupported::Backing => "another image behind it",
            Unsupported::ExternalData => "its data in a file of its own",
            Unsupported::Beside => "the files beside it, which hold the disk",
            Unsupported::Encrypted => "to be decrypted",
            Unsupported::Corrupt => "repairing, as it is marked damaged",
            Unsupported::ExtendedL2 => "subclusters",
            Unsupported::Zstd => "Zstandard, which this build leaves out",
            Unsupported::Log => "its log applied, which is a write",
            Unsupported::Feature => "a feature this does not know",
        })
    }
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
            Error::Qcow2Says => write!(f, "the QCOW2 image says a layout it cannot have"),
            Error::VhdxCheck => {
                write!(f, "the VHDX's headers and tables fail their own CRC-32C")
            }
            Error::VhdxSays => write!(f, "the VHDX says a layout it cannot have"),
            Error::VmdkSays => write!(f, "the VMDK says a layout it cannot have"),
            Error::VmdkElsewhere => {
                write!(f, "the VMDK names an extent somewhere other than beside it")
            }
            Error::Needs(what) => write!(f, "the image needs {what}, which is not read"),
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
