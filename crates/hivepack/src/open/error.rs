//! Why a file did not open.

use std::fmt;
use std::io;

/// Why a file did not open.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Reading failed, or a layer's data did not decode: then a
    /// [`DecodeError`](crate::open::DecodeError) is inside, of kind
    /// `InvalidData`.
    Io(io::Error),
    /// An age layer did not decrypt: no identity matched it (its
    /// [`NoIdentityMatch`](crate::age::NoIdentityMatch) tells what key
    /// it needs), the passphrase was wrong, or its header is damaged.
    Age(crate::age::Error),
    /// More layers than [`Limits::max_layers`](crate::open::Limits::max_layers).
    TooManyLayers(usize),
    /// The file changed since it was first opened: its layers are others,
    /// or an age layer's file key is another.
    Changed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(error) => error.fmt(f),
            Error::Age(error) => write!(f, "age: {error}"),
            Error::TooManyLayers(max) => write!(f, "more than {max} layers"),
            Error::Changed => f.write_str("the file changed while it was read"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(error) => Some(error),
            Error::Age(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::Io(error)
    }
}

impl From<crate::age::Error> for Error {
    fn from(error: crate::age::Error) -> Error {
        match error {
            // A layer under it failed, or reading did.
            crate::age::Error::Io(error) => Error::Io(error),
            error => Error::Age(error),
        }
    }
}

/// For an opener given where an `io::Result` is wanted, such as
/// `hivepack::extract::extract_tar`'s `open`: an [`Error::Io`] as it is,
/// the others inside.
impl From<Error> for io::Error {
    fn from(error: Error) -> io::Error {
        match error {
            Error::Io(error) => error,
            error => io::Error::new(io::ErrorKind::InvalidData, error),
        }
    }
}
