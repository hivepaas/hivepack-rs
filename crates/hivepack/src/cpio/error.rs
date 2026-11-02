//! Why an archive could not be read, or what was wrong before an entry:
//! libarchive's `archive_set_error` messages, as variants.
//!
//! libarchive returns `ARCHIVE_FATAL` with a message for an archive it
//! cannot go on reading, an [`Error`] here, and `ARCHIVE_WARN` with one for
//! an entry it gives after something it did not expect, a [`Warning`]. The
//! messages ([`Error::message`], [`Warning::message`]) are libarchive's,
//! byte for byte, numbers included.

use core::fmt;
use std::io;

/// Why the archive cannot be read on: libarchive's `ARCHIVE_FATAL`, with
/// its message. Once a call fails so, every later one fails the same way.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// "Unrecognized archive format": not a cpio archive.
    Unrecognized,
    /// "Truncated input file (needed N bytes, only M available)": the
    /// archive ends before a place it says something is.
    Truncated {
        /// How many bytes were to be skipped.
        needed: i64,
        /// How many there were.
        available: i64,
    },
    /// libarchive's `ARCHIVE_FATAL` without a message of its own: the
    /// archive ends in a header, a name, a symbolic link's target or a
    /// file's data, or no header is found before it ends. libarchive's
    /// message is then the last one it set since the entry began, if any,
    /// which this holds.
    Unspecified(Option<Vec<u8>>),
    /// "End of file trying to read next cpio header": a binary archive
    /// ends in a header.
    EndOfFile,
    /// "Rejecting malformed cpio archive: pathname exceeds 1 megabyte".
    PathnameTooLong,
    /// "Rejecting malformed cpio archive: symlink contents exceed 1
    /// megabyte".
    SymlinkTooLong,
    /// "Nonsensical file size": an afio header's size is negative.
    NonsensicalSize,
    /// "Unrecognized rpm header": an RPM package's lead is not followed by
    /// a header.
    RpmHeader,
    /// Reading the archive failed.
    Io(io::Error),
}

/// What was wrong before an entry that comes anyway: libarchive's
/// `ARCHIVE_WARN`, with its message.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Warning {
    /// "Skipped N bytes before finding valid header": bytes that are not a
    /// header were passed over to find this one.
    Skipped {
        /// How many.
        bytes: u64,
    },
    /// "Truncated input file (needed N bytes, only M available)": an entry
    /// found after skipped bytes, when the archive then ends in the padding
    /// after its name. libarchive gives the entry with `ARCHIVE_WARN` for
    /// the skipped bytes, and the message it set last, which is this one.
    Truncated {
        /// How many bytes of padding there were to be.
        needed: i64,
        /// How many there were.
        available: i64,
    },
}

impl Warning {
    /// The message libarchive gives, byte for byte.
    pub fn message(&self) -> Vec<u8> {
        match self {
            Warning::Skipped { bytes } => {
                format!("Skipped {bytes} bytes before finding valid header").into_bytes()
            }
            Warning::Truncated { needed, available } => {
                format!("Truncated input file (needed {needed} bytes, only {available} available)")
                    .into_bytes()
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
    /// The message libarchive gives, byte for byte; `None` for an
    /// [`Error::Unspecified`] without one.
    pub fn message(&self) -> Option<Vec<u8>> {
        let text = match self {
            Error::Unrecognized => "Unrecognized archive format".into(),
            Error::Truncated { needed, available } => {
                format!("Truncated input file (needed {needed} bytes, only {available} available)")
            }
            Error::Unspecified(message) => return message.clone(),
            Error::EndOfFile => "End of file trying to read next cpio header".into(),
            Error::PathnameTooLong => {
                "Rejecting malformed cpio archive: pathname exceeds 1 megabyte".into()
            }
            Error::SymlinkTooLong => {
                "Rejecting malformed cpio archive: symlink contents exceed 1 megabyte".into()
            }
            Error::NonsensicalSize => "Nonsensical file size".into(),
            Error::RpmHeader => "Unrecognized rpm header".into(),
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
            Error::Unspecified(message) => Error::Unspecified(message.clone()),
            Error::EndOfFile => Error::EndOfFile,
            Error::PathnameTooLong => Error::PathnameTooLong,
            Error::SymlinkTooLong => Error::SymlinkTooLong,
            Error::NonsensicalSize => Error::NonsensicalSize,
            Error::RpmHeader => Error::RpmHeader,
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

/// An error that came through `io::Read` comes out as itself: one from the
/// RPM filter under the cpio reader, for one.
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
