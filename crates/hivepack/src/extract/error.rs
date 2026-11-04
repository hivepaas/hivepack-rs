//! Why an extraction stopped, and at which entry.

use std::fmt;

use crate::extract::name::NameError;

/// Why an extraction stopped: the entry, by its index in the archive and
/// its name as the archive has it, and the reason.
#[derive(Debug)]
pub struct Error {
    /// The entry's index, if an entry is to blame.
    pub index: Option<u64>,
    /// The entry's name, as the archive has it.
    pub name: Option<Vec<u8>>,
    pub kind: ErrorKind,
}

/// What is wrong with a RAR archive or entry, as [`crate::rar::Extract`]
/// says it.
#[cfg(feature = "rar")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RarProblem {
    /// A header is broken, or the archive is cut short.
    BrokenArchive,
    /// An entry's data does not match its hash.
    BrokenData,
    /// A link's target is too long to be one, or cut short.
    BrokenLink,
    /// An entry is encrypted, and there is no password.
    MissingPassword,
    /// The password is not the entry's.
    BadPassword,
    /// A next volume is not there.
    MissingVolume,
    /// The first entry goes on from a volume before this one.
    NeedsPreviousVolume,
    /// An entry asks for a dictionary over what UnRAR allows.
    DictionaryTooLarge,
    /// An entry is of a version or an encryption not known.
    UnknownFormat,
}

#[cfg(feature = "rar")]
impl std::fmt::Display for RarProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RarProblem::BrokenArchive => "a header is broken, or the archive is cut short",
            RarProblem::BrokenData => "data does not match its hash",
            RarProblem::BrokenLink => "a link's target is too long or cut short",
            RarProblem::MissingPassword => "encrypted, and there is no password",
            RarProblem::BadPassword => "the password is wrong",
            RarProblem::MissingVolume => "a next volume is not there",
            RarProblem::NeedsPreviousVolume => "goes on from a volume before this one",
            RarProblem::DictionaryTooLarge => "the dictionary is too large",
            RarProblem::UnknownFormat => "a version or an encryption not known",
        })
    }
}

/// The reasons an extraction stops.
#[derive(Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The name is refused (see [`check_name`](crate::extract::check_name)).
    Name(NameError),
    /// Another entry, `first`, names the same path, ignoring case, or
    /// names a file where this one has a directory, or the other way.
    Duplicate { first: u64 },
    /// A symbolic link, which is not created (see
    /// [`Links`](crate::extract::Links)).
    Link,
    /// A hard link (tar, ISO 9660) whose target is not a file extracted
    /// before it.
    HardLinkTarget,
    /// A device or FIFO (tar, ISO 9660): nothing is created as one.
    Special,
    /// A link whose target is refused, as a name is
    /// ([`NameError::Dot`] for one that climbs out of the destination).
    LinkTarget(NameError),
    /// A link whose target passes through link `other`, which the system
    /// would follow where the target's text does not.
    LinkChain { other: u64 },
    /// The entry's data overlaps that of entry `other`: an archive bomb
    /// that reuses the same compressed data, or a broken archive.
    Overlap { other: u64 },
    /// More entries than [`Limits::max_entries`](crate::extract::Limits::max_entries).
    TooManyEntries,
    /// More data than [`Limits::max_entry_size`](crate::extract::Limits::max_entry_size).
    EntryTooLarge,
    /// More data in all than [`Limits::max_total_size`](crate::extract::Limits::max_total_size).
    TotalTooLarge,
    /// More data for the compressed data than [`Limits::max_ratio`](crate::extract::Limits::max_ratio).
    Ratio,
    /// More or less data than the archive says the entry has.
    SizeMismatch,
    /// Something is already at the entry's path: nothing is overwritten.
    Exists,
    /// A directory on the entry's path is a symbolic link, or not a
    /// directory: nothing is written through it.
    NotADirectory,
    /// Past [`Options::time_limit`](crate::extract::Options::time_limit).
    TimeLimit,
    /// Stopped by [`Options::cancel`](crate::extract::Options::cancel).
    Cancelled,
    /// The mark of origin ([`Options::origin`](crate::extract::Options::origin))
    /// could not be written, or this system cannot carry it.
    Origin(std::io::Error),
    /// The archive could not be read.
    Archive(crate::zip::Error),
    /// The tar archive could not be read.
    Tar(crate::tar::Error),
    /// The ISO 9660 image could not be read.
    Iso(crate::iso::Error),
    /// An entry of the ISO 9660 image that libarchive gives with something
    /// missing ([`crate::iso::Warning`]): a directory left out with what
    /// it holds, a file past the image's end or whose data is before its
    /// directory, a name not in UTF-16, a part of a file's data out of
    /// place.
    IsoEntry(crate::iso::Warning),
    /// The cpio archive could not be read: cut short, without
    /// `TRAILER!!!`, or with a header that cannot be.
    Cpio(crate::cpio::Error),
    /// An entry of the cpio archive found after bytes that are not a
    /// header were passed over ([`crate::cpio::Warning`]): what they
    /// held is lost.
    CpioEntry(crate::cpio::Warning),
    /// The XAR archive could not be read: its table of contents, or an
    /// entry's data (a checksum that does not match, data that does not
    /// decompress), or an entry whose data is before the place read to.
    Xar(crate::xar::Error),
    /// An entry of the XAR archive that libarchive gives with something
    /// missing ([`crate::xar::Warning`]): a name that is not UTF-8.
    XarEntry(crate::xar::Warning),
    /// A package's payload could not be opened through its layers.
    Payload(std::io::Error),
    /// The UDF volume could not be read: an entry's node, data or link
    /// target, or a directory with a broken entry.
    Udf(crate::udf::Error),
    /// The 7z archive's data could not be read: damaged, a CRC that does
    /// not match, a method `hivepack::sevenz` does not decode, or a password
    /// missing or wrong.
    SevenZip(crate::sevenz::Error),
    /// The RAR archive could not be read: not one, a next volume that is not
    /// of it, headers encrypted with no password, or no memory for a dictionary.
    #[cfg(feature = "rar")]
    Rar(crate::rar::Error),
    /// An entry of the RAR archive, or the archive, is what UnRAR would report.
    #[cfg(feature = "rar")]
    RarEntry(RarProblem),
    /// A directory of the UDF volume met again: under two names, or its
    /// own ancestor, which UDF does not allow.
    DirectoryAgain,
    /// The tar or cpio archive or ISO 9660 image read again, to write it,
    /// is not the one checked.
    Changed,
    /// The destination could not be written.
    Io(std::io::Error),
}

impl ErrorKind {
    /// Whether this says an entry's data is damaged: it fails its check (a
    /// CRC, a hash, an authentication code), cannot be decompressed, or ends
    /// before the size the archive says, which [`OnDamaged`](crate::extract::OnDamaged)
    /// can go on from. A wrong or missing password is not damage, nor a method
    /// not known, nor anything about names, links, limits, the destination or
    /// the archive as a whole.
    pub fn is_damage(&self) -> bool {
        use crate::zip::ErrorCode;
        match self {
            ErrorKind::SizeMismatch => true,
            ErrorKind::Archive(e) => !matches!(
                e.code(),
                ErrorCode::NoPasswd
                    | ErrorCode::WrongPasswd
                    | ErrorCode::EncrNotSupp
                    | ErrorCode::CompNotSupp
                    | ErrorCode::Memory
                    | ErrorCode::Cancelled
            ),
            ErrorKind::Tar(_)
            | ErrorKind::Iso(_)
            | ErrorKind::Cpio(_)
            | ErrorKind::Xar(_)
            | ErrorKind::Udf(_) => true,
            ErrorKind::SevenZip(e) => !matches!(
                e,
                crate::sevenz::Error::PasswordRequired
                    | crate::sevenz::Error::WrongPassword
                    | crate::sevenz::Error::Unsupported
                    | crate::sevenz::Error::Mem
            ),
            #[cfg(feature = "rar")]
            ErrorKind::Rar(e) => matches!(e, crate::rar::Error::Io(_)),
            #[cfg(feature = "rar")]
            ErrorKind::RarEntry(problem) => *problem == RarProblem::BrokenData,
            _ => false,
        }
    }
}

impl Error {
    pub(crate) fn new(index: u64, name: &[u8], kind: ErrorKind) -> Error {
        Error {
            index: Some(index),
            name: Some(name.to_vec()),
            kind,
        }
    }

    pub(crate) fn global(kind: ErrorKind) -> Error {
        Error {
            index: None,
            name: None,
            kind,
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Name(e) => write!(f, "name refused: {e}"),
            ErrorKind::Duplicate { first } => write!(f, "same path as entry {first}"),
            ErrorKind::Link => f.write_str("link"),
            ErrorKind::HardLinkTarget => f.write_str("hard link to no file extracted before it"),
            ErrorKind::Special => f.write_str("device or FIFO"),
            ErrorKind::LinkTarget(e) => write!(f, "link target refused: {e}"),
            ErrorKind::LinkChain { other } => write!(f, "link through link {other}"),
            ErrorKind::Overlap { other } => write!(f, "data overlaps entry {other}"),
            ErrorKind::TooManyEntries => f.write_str("too many entries"),
            ErrorKind::EntryTooLarge => f.write_str("entry too large"),
            ErrorKind::TotalTooLarge => f.write_str("too much data in all"),
            ErrorKind::Ratio => f.write_str("compression ratio too high"),
            ErrorKind::SizeMismatch => f.write_str("data not of the size the archive says"),
            ErrorKind::Exists => f.write_str("already exists"),
            ErrorKind::NotADirectory => f.write_str("a directory on the path is a link or a file"),
            ErrorKind::TimeLimit => f.write_str("past the time limit"),
            ErrorKind::Cancelled => f.write_str("cancelled"),
            ErrorKind::Origin(e) => write!(f, "mark of origin not written: {e}"),
            ErrorKind::Archive(e) => write!(f, "archive: {e}"),
            ErrorKind::Tar(e) => write!(f, "archive: {e}"),
            ErrorKind::Iso(e) => write!(f, "image: {e}"),
            ErrorKind::IsoEntry(w) => write!(f, "entry with something missing: {w}"),
            ErrorKind::Cpio(e) => write!(f, "archive: {e}"),
            ErrorKind::CpioEntry(w) => write!(f, "entry after a damaged part: {w}"),
            ErrorKind::Xar(e) => write!(f, "archive: {e}"),
            ErrorKind::XarEntry(w) => write!(f, "entry with something missing: {w}"),
            ErrorKind::Payload(e) => write!(f, "payload: {e}"),
            ErrorKind::Udf(e) => write!(f, "volume: {e}"),
            ErrorKind::SevenZip(e) => write!(f, "archive: {e}"),
            #[cfg(feature = "rar")]
            ErrorKind::Rar(e) => write!(f, "archive: {e}"),
            #[cfg(feature = "rar")]
            ErrorKind::RarEntry(e) => write!(f, "archive: {e}"),
            ErrorKind::DirectoryAgain => f.write_str("a directory met again"),
            ErrorKind::Changed => f.write_str("the archive changed between its two readings"),
            ErrorKind::Io(e) => write!(f, "{e}"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.index, &self.name) {
            (Some(index), Some(name)) => write!(
                f,
                "entry {index} ({}): {}",
                String::from_utf8_lossy(name),
                self.kind
            ),
            _ => write!(f, "{}", self.kind),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::Archive(e) => Some(e),
            ErrorKind::Tar(e) => Some(e),
            ErrorKind::Iso(e) => Some(e),
            ErrorKind::Cpio(e) => Some(e),
            ErrorKind::Xar(e) => Some(e),
            ErrorKind::Payload(e) => Some(e),
            ErrorKind::Udf(e) => Some(e),
            ErrorKind::SevenZip(e) => Some(e),
            #[cfg(feature = "rar")]
            ErrorKind::Rar(e) => Some(e),
            ErrorKind::Io(e) | ErrorKind::Origin(e) => Some(e),
            _ => None,
        }
    }
}
