//! Why an archive could not be read: libarchive's `archive_set_error`
//! messages, as variants.
//!
//! libarchive's ar reader returns `ARCHIVE_FATAL` with a message for an
//! archive it cannot go on reading, an [`Error`] here. It gives no warnings.
//! The messages ([`Error::message`]) are libarchive's, byte for byte,
//! numbers included.

use core::fmt;
use std::io;

/// Why the archive cannot be read on: libarchive's `ARCHIVE_FATAL`, with
/// its message. Once a call fails so, every later one fails the same way.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// "Unrecognized archive format": not an ar archive (it does not start
    /// with `!<arch>\n`).
    Unrecognized,
    /// "Truncated input file (needed N bytes, only M available)": the
    /// archive ends before what is to be skipped: an entry's data and its
    /// padding byte, or a filename table's.
    Truncated {
        /// How many bytes were to be skipped.
        needed: i64,
        /// How many there were.
        available: i64,
    },
    /// libarchive's `ARCHIVE_FATAL` without a message: the archive ends in
    /// a GNU filename table (`//`).
    Unspecified,
    /// "Incorrect file header signature": a header does not end in
    /// `` `\n ``.
    HeaderSignature,
    /// "Found entry with empty filename": a name of spaces only.
    EmptyFilename,
    /// "Invalid filename table size": a GNU filename table that is empty or
    /// larger than 1 GiB.
    FilenameTableSize,
    /// "More than one filename table exists".
    TwoFilenameTables,
    /// "Invalid string table": a GNU filename table that does not end in
    /// `\n`, `` ` `` or NUL.
    StringTable,
    /// "Can't find long filename for GNU/SVR4 archive entry": a name
    /// `/<number>` with no filename table, or past its end.
    LongFilename,
    /// "Bad input file size": a BSD name (`#1/<length>`) longer than 1 MiB
    /// or than its entry.
    BadSize,
    /// "Truncated input file": the archive ends in a BSD name.
    TruncatedName,
    /// "Truncated ar archive": the archive ends in an entry's data.
    TruncatedData,
    /// Reading the archive failed.
    Io(io::Error),
}

impl Error {
    /// The message libarchive gives, byte for byte; `None` for
    /// [`Error::Unspecified`].
    pub fn message(&self) -> Option<Vec<u8>> {
        let text = match self {
            Error::Unrecognized => "Unrecognized archive format".into(),
            Error::Truncated { needed, available } => {
                format!("Truncated input file (needed {needed} bytes, only {available} available)")
            }
            Error::Unspecified => return None,
            Error::HeaderSignature => "Incorrect file header signature".into(),
            Error::EmptyFilename => "Found entry with empty filename".into(),
            Error::FilenameTableSize => "Invalid filename table size".into(),
            Error::TwoFilenameTables => "More than one filename table exists".into(),
            Error::StringTable => "Invalid string table".into(),
            Error::LongFilename => "Can't find long filename for GNU/SVR4 archive entry".into(),
            Error::BadSize => "Bad input file size".into(),
            Error::TruncatedName => "Truncated input file".into(),
            Error::TruncatedData => "Truncated ar archive".into(),
            Error::Io(e) => e.to_string(),
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
            Error::Unspecified => Error::Unspecified,
            Error::HeaderSignature => Error::HeaderSignature,
            Error::EmptyFilename => Error::EmptyFilename,
            Error::FilenameTableSize => Error::FilenameTableSize,
            Error::TwoFilenameTables => Error::TwoFilenameTables,
            Error::StringTable => Error::StringTable,
            Error::LongFilename => Error::LongFilename,
            Error::BadSize => Error::BadSize,
            Error::TruncatedName => Error::TruncatedName,
            Error::TruncatedData => Error::TruncatedData,
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
