//! Why an image could not be read, or what was wrong with an entry:
//! libarchive's `archive_set_error` messages, as variants.
//!
//! libarchive returns `ARCHIVE_FATAL` with a message for an image it cannot
//! go on reading, an [`Error`] here, and `ARCHIVE_WARN` with one for an
//! entry it gives with something missing, a [`Warning`]. The messages
//! ([`Error::message`], [`Warning::message`]) are libarchive's, byte for
//! byte, names and numbers included.

use core::fmt;
use std::io;

/// Why the image cannot be read on: libarchive's `ARCHIVE_FATAL`, with its
/// message. Once a call fails so, every later one fails the same way.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// "Unrecognized archive format": not an ISO 9660 image (no Primary
    /// Volume Descriptor, or no Volume Descriptor Set Terminator).
    Unrecognized,
    /// "Truncated input file (needed N bytes, only M available)": the image
    /// ends before a place it says something is.
    Truncated {
        /// How many bytes were to be skipped.
        needed: i64,
        /// How many there were.
        available: i64,
    },
    /// "Truncated input file": the image ends in the middle of a file.
    TruncatedFile,
    /// libarchive's `ARCHIVE_FATAL` without a message of its own: a skip
    /// by a negative amount, to something the image places before its
    /// start or 8 EiB on. libarchive's message is then the last one it set
    /// since the entry began, if any, which this holds.
    Unspecified(Option<Vec<u8>>),
    /// "Failed to read full block when scanning ISO9660 directory list".
    DirectoryRead,
    /// "Pathname is too long": over 1,000 directories deep, or a Joliet
    /// path over 1,024 bytes.
    PathnameTooLong,
    /// "Invalid length of directory record".
    RecordLength,
    /// "Invalid length of file identifier".
    IdentifierLength,
    /// "Invalid location of extent of file".
    ExtentLocation,
    /// "Directory structure contains loop".
    Loop,
    /// "Invalid Rockridge RE".
    RockRidgeRe,
    /// "Invalid Rockridge RE and CL".
    RockRidgeReCl,
    /// "Invalid Rockridge CL".
    RockRidgeCl,
    /// "Tried to parse Rockridge extensions, but none found".
    NoRockRidge,
    /// "Invalid parameter in SUSP \"CE\" extension".
    SuspCe,
    /// "Malformed CE information".
    MalformedCe,
    /// "Failed to connect 'CL' pointer to 'RE' rr_moved pointer of
    /// Rockridge extensions: current position = N, CL offset = M".
    ClRe {
        /// Where the reading was in the image.
        position: i64,
        /// Where the CL entry pointed.
        cl_offset: i64,
    },
    /// "Truncated zisofs file body".
    ZisofsTruncated,
    /// "Illegal zisofs file body": a zisofs header that does not match the
    /// file's ZF entry.
    ZisofsBody,
    /// "Illegal zisofs block pointers".
    ZisofsPointers,
    /// "Illegal zisofs block pointers(cannot seek)".
    ZisofsSeek,
    /// "zisofs decompression failed (N)", with zlib's return code.
    ZisofsInflate(i32),
    /// A zisofs block with bytes after the end of its zlib stream. Not
    /// libarchive's: libarchive never gets past such a block, returning
    /// nothing forever; the port stops there.
    ZisofsStuck,
    /// Reading the image failed.
    Io(io::Error),

    /// A warning while reading a file's data ([`Warning::ExtentOutOfOrder`]):
    /// reading can go on after it.
    Warning(Warning),
}

/// What was wrong with an entry that comes anyway: libarchive's
/// `ARCHIVE_WARN`, with its message.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Warning {
    /// "Ignoring out-of-order directory (NAME) N > M": a
    /// directory before the place already read to, which is left out with
    /// all it holds. The entry that comes with it is empty.
    DirectoryOutOfOrder {
        /// The directory's name, `None` on a Joliet image (where libarchive
        /// prints "(null)").
        name: Option<Vec<u8>>,
        /// Where the reading was.
        position: i64,
        /// Where the directory is.
        offset: i64,
    },
    /// "Directory is beyond end-of-media: NAME". The entry that
    /// comes with it is empty.
    DirectoryBeyondEnd {
        /// The directory's name, as for `DirectoryOutOfOrder`.
        name: Option<Vec<u8>>,
    },
    /// "File is beyond end-of-media: PATH": the entry has its
    /// path, and nothing else.
    FileBeyondEnd {
        /// The entry's path.
        path: Option<Vec<u8>>,
    },
    /// "Ignoring out-of-order file @NUMBER (PATH) N < M": a
    /// file whose data is before the place already read to, on an image
    /// that cannot seek. The entry has no data.
    FileOutOfOrder {
        /// The file's serial number, in hexadecimal in the message.
        number: u64,
        /// The path of the last entry read by name, `None` on a Joliet
        /// image.
        path: Option<Vec<u8>>,
        /// Where the file's data is.
        offset: i64,
        /// Where the reading was.
        position: i64,
    },
    /// From reading the data, "Ignoring out-of-order file (PATH)
    /// N < M": a part of a file in several extents before the place
    /// already read to. Reading goes on with the next part.
    ExtentOutOfOrder {
        /// As for `FileOutOfOrder`.
        path: Option<Vec<u8>>,
        /// Where the part is.
        offset: i64,
        /// Where the reading was.
        position: i64,
    },
    /// "Pathname cannot be converted from UTF-16BE to current
    /// locale": a Joliet name that is not UTF-16. The entry has no path.
    PathnameConversion,
    /// "Linkname cannot be converted from UTF-16BE to current
    /// locale": the same, for the name a hard link points to.
    LinknameConversion,
}

/// What `printf("%s")` of a C string gives in libarchive's messages:
/// "(null)" for none.
fn c_string(text: &mut Vec<u8>, s: &Option<Vec<u8>>) {
    match s {
        Some(s) => text.extend_from_slice(s),
        None => text.extend_from_slice(b"(null)"),
    }
}

impl Warning {
    /// The message libarchive gives, byte for byte (names are bytes).
    pub fn message(&self) -> Vec<u8> {
        match self {
            Warning::DirectoryOutOfOrder {
                name,
                position,
                offset,
            } => {
                let mut text = b"Ignoring out-of-order directory (".to_vec();
                c_string(&mut text, name);
                text.extend_from_slice(format!(") {position} > {offset}").as_bytes());
                text
            }
            Warning::DirectoryBeyondEnd { name } => {
                let mut text = b"Directory is beyond end-of-media: ".to_vec();
                c_string(&mut text, name);
                text
            }
            Warning::FileBeyondEnd { path } => {
                let mut text = b"File is beyond end-of-media: ".to_vec();
                c_string(&mut text, path);
                text
            }
            Warning::FileOutOfOrder {
                number,
                path,
                offset,
                position,
            } => {
                let mut text = format!("Ignoring out-of-order file @{number:x} (").into_bytes();
                c_string(&mut text, path);
                text.extend_from_slice(format!(") {offset} < {position}").as_bytes());
                text
            }
            Warning::ExtentOutOfOrder {
                path,
                offset,
                position,
            } => {
                let mut text = b"Ignoring out-of-order file (".to_vec();
                c_string(&mut text, path);
                text.extend_from_slice(format!(") {offset} < {position}").as_bytes());
                text
            }
            Warning::PathnameConversion => {
                b"Pathname cannot be converted from UTF-16BE to current locale".to_vec()
            }
            Warning::LinknameConversion => {
                b"Linkname cannot be converted from UTF-16BE to current locale".to_vec()
            }
        }
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.message()))
    }
}

impl Error {
    /// Whether this is a [`Warning`] from reading data, after which reading
    /// can go on.
    pub fn is_warning(&self) -> bool {
        matches!(self, Error::Warning(_))
    }

    /// The message libarchive gives, byte for byte (names are bytes);
    /// `None` for an [`Error::Unspecified`] without one.
    pub fn message(&self) -> Option<Vec<u8>> {
        let text = match self {
            Error::Unrecognized => "Unrecognized archive format".into(),
            Error::Truncated { needed, available } => {
                format!("Truncated input file (needed {needed} bytes, only {available} available)")
            }
            Error::TruncatedFile => "Truncated input file".into(),
            Error::Unspecified(message) => return message.clone(),
            Error::DirectoryRead => {
                "Failed to read full block when scanning ISO9660 directory list".into()
            }
            Error::PathnameTooLong => "Pathname is too long".into(),
            Error::RecordLength => "Invalid length of directory record".into(),
            Error::IdentifierLength => "Invalid length of file identifier".into(),
            Error::ExtentLocation => "Invalid location of extent of file".into(),
            Error::Loop => "Directory structure contains loop".into(),
            Error::RockRidgeRe => "Invalid Rockridge RE".into(),
            Error::RockRidgeReCl => "Invalid Rockridge RE and CL".into(),
            Error::RockRidgeCl => "Invalid Rockridge CL".into(),
            Error::NoRockRidge => "Tried to parse Rockridge extensions, but none found".into(),
            Error::SuspCe => "Invalid parameter in SUSP \"CE\" extension".into(),
            Error::MalformedCe => "Malformed CE information".into(),
            Error::ClRe {
                position,
                cl_offset,
            } => format!(
                "Failed to connect 'CL' pointer to 'RE' rr_moved pointer of Rockridge \
                 extensions: current position = {position}, CL offset = {cl_offset}"
            ),
            Error::ZisofsTruncated => "Truncated zisofs file body".into(),
            Error::ZisofsBody => "Illegal zisofs file body".into(),
            Error::ZisofsPointers => "Illegal zisofs block pointers".into(),
            Error::ZisofsSeek => "Illegal zisofs block pointers(cannot seek)".into(),
            Error::ZisofsInflate(code) => format!("zisofs decompression failed ({code})"),
            Error::ZisofsStuck => "zisofs block with data after its end".into(),
            Error::Io(e) => e.to_string(),
            Error::Warning(w) => return Some(w.message()),
        };
        Some(String::into_bytes(text))
    }

    /// The same error again: `io::Error` cannot be cloned, so its kind and
    /// message are kept.
    pub(crate) fn again(&self) -> Error {
        match self {
            Error::Unrecognized => Error::Unrecognized,
            Error::Truncated { needed, available } => Error::Truncated {
                needed: *needed,
                available: *available,
            },
            Error::TruncatedFile => Error::TruncatedFile,
            Error::Unspecified(message) => Error::Unspecified(message.clone()),
            Error::DirectoryRead => Error::DirectoryRead,
            Error::PathnameTooLong => Error::PathnameTooLong,
            Error::RecordLength => Error::RecordLength,
            Error::IdentifierLength => Error::IdentifierLength,
            Error::ExtentLocation => Error::ExtentLocation,
            Error::Loop => Error::Loop,
            Error::RockRidgeRe => Error::RockRidgeRe,
            Error::RockRidgeReCl => Error::RockRidgeReCl,
            Error::RockRidgeCl => Error::RockRidgeCl,
            Error::NoRockRidge => Error::NoRockRidge,
            Error::SuspCe => Error::SuspCe,
            Error::MalformedCe => Error::MalformedCe,
            Error::ClRe {
                position,
                cl_offset,
            } => Error::ClRe {
                position: *position,
                cl_offset: *cl_offset,
            },
            Error::ZisofsTruncated => Error::ZisofsTruncated,
            Error::ZisofsBody => Error::ZisofsBody,
            Error::ZisofsPointers => Error::ZisofsPointers,
            Error::ZisofsSeek => Error::ZisofsSeek,
            Error::ZisofsInflate(code) => Error::ZisofsInflate(*code),
            Error::ZisofsStuck => Error::ZisofsStuck,
            Error::Io(e) => Error::Io(io::Error::new(e.kind(), e.to_string())),
            Error::Warning(w) => Error::Warning(w.clone()),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(text) => f.write_str(&String::from_utf8_lossy(&text)),
            None => f.write_str("unspecified error"),
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

/// An error that came through `io::Read` comes out as itself.
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        if error.get_ref().is_some_and(|inner| inner.is::<Error>()) {
            if let Some(inner) = error.into_inner()
                && let Ok(error) = inner.downcast::<Error>()
            {
                return *error;
            }
            return Error::Io(io::Error::other("lost error"));
        }
        Error::Io(error)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> io::Error {
        match error {
            Error::Io(e) => e,
            error => io::Error::other(error),
        }
    }
}
