//! What fails, as NetBSD's errno values with what failed.

use std::fmt;
use std::io;

/// The errno NetBSD returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Errno {
    /// Not permitted: the volume is not closed and NetBSD would not mount
    /// it (only with [`Options::strict`](crate::udf::Options::strict)).
    EPERM,
    /// Not there: a missing descriptor or entry.
    ENOENT,
    /// A read error, or a broken structure.
    EIO,
    /// A bad structure.
    EINVAL,
    /// The metadata files of the metadata partition are not readable.
    EFAULT,
    /// Not a directory.
    ENOTDIR,
    /// A directory, read as a file.
    EISDIR,
    /// Too many indirect entries.
    EMLINK,
    /// Read-only: what NetBSD only mounts read-only, here what it does not
    /// support (space tables).
    EROFS,
}

impl Errno {
    fn name(self) -> &'static str {
        match self {
            Errno::EPERM => "EPERM",
            Errno::ENOENT => "ENOENT",
            Errno::EIO => "EIO",
            Errno::EINVAL => "EINVAL",
            Errno::EFAULT => "EFAULT",
            Errno::ENOTDIR => "ENOTDIR",
            Errno::EISDIR => "EISDIR",
            Errno::EMLINK => "EMLINK",
            Errno::EROFS => "EROFS",
        }
    }
}

/// A failure to read the image, or what NetBSD fails on.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Reading the image failed.
    Io(io::Error),
    /// What NetBSD returns, and what failed.
    Udf {
        /// The errno.
        errno: Errno,
        /// What failed: NetBSD's message where it prints one.
        what: &'static str,
    },
}

impl Error {
    pub(crate) fn new(errno: Errno, what: &'static str) -> Error {
        Error::Udf { errno, what }
    }

    /// The errno NetBSD returns: `EIO` for a read error.
    pub fn errno(&self) -> Errno {
        match self {
            Error::Io(_) => Errno::EIO,
            Error::Udf { errno, .. } => *errno,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "UDF: read error: {e}"),
            Error::Udf { errno, what } => write!(f, "UDF: {what} ({})", errno.name()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Udf { .. } => None,
        }
    }
}

/// The image's read error, or the [`Error`] an `io::Error` holds (from
/// [`File`](crate::udf::File)'s reads).
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        match e.get_ref().map(|inner| inner.is::<Error>()) {
            Some(true) => match e.into_inner().map(|inner| inner.downcast::<Error>()) {
                Some(Ok(inner)) => *inner,
                Some(Err(other)) => Error::Io(io::Error::new(io::ErrorKind::InvalidData, other)),
                None => Error::new(Errno::EIO, "read error"),
            },
            _ => Error::Io(e),
        }
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        match e {
            Error::Io(e) => e,
            e @ Error::Udf { .. } => io::Error::new(io::ErrorKind::InvalidData, e),
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
