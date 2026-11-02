//! Why an archive could not be read, or what was wrong with an entry:
//! libarchive's `archive_set_error` messages, as variants.
//!
//! libarchive returns `ARCHIVE_FATAL` with a message for an archive it
//! cannot go on reading, an [`Error`] here; `ARCHIVE_FAILED` for an entry
//! whose header it could not read, after which it goes on with the next
//! ([`Error::CannotSeek`]); and `ARCHIVE_WARN` with a message for an entry
//! it gives with something missing, a [`Warning`]. The messages
//! ([`Error::message`], [`Warning::message`]) are libarchive's, byte for
//! byte, but for the XML parser's (see [`Error::Xml`]).

use core::fmt;
use std::io;

/// Why the archive cannot be read on: libarchive's `ARCHIVE_FATAL` (or,
/// for [`Error::CannotSeek`], `ARCHIVE_FAILED`), with its message.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// "Unrecognized archive format": not a XAR archive (its header's
    /// magic number, size, version or checksum type is not XAR's).
    Unrecognized,
    /// "Truncated archive header".
    TruncatedHeader,
    /// "Invalid header magic".
    InvalidMagic,
    /// "Unsupported header version(N)".
    UnsupportedVersion(u16),
    /// "TOC uncompressed size error": the table of contents is not as
    /// long as the header says.
    TocSize,
    /// "Truncated archive file": the archive ends in the middle of the
    /// table of contents, its checksum, or a file's data.
    TruncatedFile,
    /// "Truncated input file (needed N bytes, only M available)": the
    /// archive ends before a place it says something is.
    Truncated {
        /// How many bytes were to be skipped.
        needed: i64,
        /// How many there were.
        available: i64,
    },
    /// "Checksum error": the table of contents or a file's data does not
    /// have the checksum the archive gives.
    Checksum,
    /// "File with multiple link attributes": a file that is both a hard
    /// link's original and a link, or a link twice.
    MultipleLinks,
    /// "XML Parsing error: MESSAGE": libxml2 could not read the table of
    /// contents. libarchive's message is libxml2's after the prefix; the
    /// port's is its own (`docs/xar.md`).
    Xml(String),
    /// "Decompressed size error": a file's or extended attribute's data
    /// is not as long as the archive says.
    DecompressedSize,
    /// "XAR decompressor made no progress".
    NoProgress,
    /// "File decompression failed (N)", with zlib's return code.
    Inflate(i32),
    /// "bzip decompression failed".
    Bzip2,
    /// "xz decompression failed (N)" or "lzma decompression failed (N)",
    /// with liblzma's return code.
    Lzma {
        /// Whether the file's data is xz (libarchive names the file's
        /// encoding, even for an extended attribute's).
        xz: bool,
        /// liblzma's return code.
        code: i32,
    },
    /// "Cannot seek": an entry's data or extended attribute is before the
    /// place already read to, on an input that cannot seek.
    /// libarchive's `ARCHIVE_FAILED`: the entry is lost, but
    /// [`crate::xar::Reader::next`] goes on with the next one, skipping as many
    /// bytes as the lost entry's data has.
    CannotSeek,
    /// libarchive's `ARCHIVE_FATAL` without a message of its own: a number
    /// in the table of contents too large for its field, a skip by a
    /// negative amount, or a read after a seek out of the archive.
    /// libarchive's message is then the last one it set since the entry
    /// began, if any, which this holds.
    Unspecified(Option<Vec<u8>>),
    /// Reading the archive failed.
    Io(io::Error),
}

/// What was wrong with an entry that comes anyway: libarchive's
/// `ARCHIVE_WARN`, with its message.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Warning {
    /// "Pathname cannot be converted from UTF-8 to current locale": a path
    /// that is not UTF-8 (a name in base64 makes any bytes). The entry has
    /// no path. libarchive then leaves the entry's data where it is, and
    /// gives what follows instead, if the entry has no extended attributes;
    /// with them, the warning is lost, and the entry comes as if there were
    /// none.
    PathnameConversion,
    /// "Linkname cannot be converted from UTF-8 to current locale".
    LinknameConversion,
    /// "Uname cannot be converted from UTF-8 to current locale".
    UnameConversion,
    /// "Gname cannot be converted from UTF-8 to current locale".
    GnameConversion,
    /// "Xattr checksum error": an extended attribute's data does not have
    /// its checksum. The entry has the attributes before it, and its data
    /// is what follows the attribute's, as libarchive leaves the place.
    XattrChecksum,
    /// "Xattr name error": an extended attribute without a name, likewise.
    XattrName,
}

impl Warning {
    /// The message libarchive gives, byte for byte.
    pub fn message(&self) -> Vec<u8> {
        let text = match self {
            Warning::PathnameConversion => {
                "Pathname cannot be converted from UTF-8 to current locale"
            }
            Warning::LinknameConversion => {
                "Linkname cannot be converted from UTF-8 to current locale"
            }
            Warning::UnameConversion => "Uname cannot be converted from UTF-8 to current locale",
            Warning::GnameConversion => "Gname cannot be converted from UTF-8 to current locale",
            Warning::XattrChecksum => "Xattr checksum error",
            Warning::XattrName => "Xattr name error",
        };
        text.as_bytes().to_vec()
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.message()))
    }
}

impl Error {
    /// Whether reading can go on after this: [`Error::CannotSeek`] only.
    pub fn is_fatal(&self) -> bool {
        !matches!(self, Error::CannotSeek)
    }

    /// The message libarchive gives, byte for byte (but an XML error's
    /// text after its prefix); `None` for an [`Error::Unspecified`] without
    /// one.
    pub fn message(&self) -> Option<Vec<u8>> {
        let text = match self {
            Error::Unrecognized => "Unrecognized archive format".into(),
            Error::TruncatedHeader => "Truncated archive header".into(),
            Error::InvalidMagic => "Invalid header magic".into(),
            Error::UnsupportedVersion(v) => format!("Unsupported header version({v})"),
            Error::TocSize => "TOC uncompressed size error".into(),
            Error::TruncatedFile => "Truncated archive file".into(),
            Error::Truncated { needed, available } => {
                format!("Truncated input file (needed {needed} bytes, only {available} available)")
            }
            Error::Checksum => "Checksum error".into(),
            Error::MultipleLinks => "File with multiple link attributes".into(),
            Error::Xml(msg) => format!("XML Parsing error: {msg}"),
            Error::DecompressedSize => "Decompressed size error".into(),
            Error::NoProgress => "XAR decompressor made no progress".into(),
            Error::Inflate(code) => format!("File decompression failed ({code})"),
            Error::Bzip2 => "bzip decompression failed".into(),
            Error::Lzma { xz, code } => format!(
                "{} decompression failed ({code})",
                if *xz { "xz" } else { "lzma" }
            ),
            Error::CannotSeek => "Cannot seek".into(),
            Error::Unspecified(message) => return message.clone(),
            Error::Io(e) => e.to_string(),
        };
        Some(String::into_bytes(text))
    }

    /// The same error again: `io::Error` cannot be cloned, so its kind and
    /// message are kept.
    pub(crate) fn again(&self) -> Error {
        match self {
            Error::Unrecognized => Error::Unrecognized,
            Error::TruncatedHeader => Error::TruncatedHeader,
            Error::InvalidMagic => Error::InvalidMagic,
            Error::UnsupportedVersion(v) => Error::UnsupportedVersion(*v),
            Error::TocSize => Error::TocSize,
            Error::TruncatedFile => Error::TruncatedFile,
            Error::Truncated { needed, available } => Error::Truncated {
                needed: *needed,
                available: *available,
            },
            Error::Checksum => Error::Checksum,
            Error::MultipleLinks => Error::MultipleLinks,
            Error::Xml(msg) => Error::Xml(msg.clone()),
            Error::DecompressedSize => Error::DecompressedSize,
            Error::NoProgress => Error::NoProgress,
            Error::Inflate(code) => Error::Inflate(*code),
            Error::Bzip2 => Error::Bzip2,
            Error::Lzma { xz, code } => Error::Lzma {
                xz: *xz,
                code: *code,
            },
            Error::CannotSeek => Error::CannotSeek,
            Error::Unspecified(message) => Error::Unspecified(message.clone()),
            Error::Io(e) => Error::Io(io::Error::new(e.kind(), e.to_string())),
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
