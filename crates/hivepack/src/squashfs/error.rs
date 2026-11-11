//! What fails: squashfuse's `sqfs_err` (`common.h`), with what failed.

use std::fmt;
use std::io;

/// `sqfs_err`: what squashfuse returns when something fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SqfsErr {
    /// `SQFS_ERR`: a read past the image's end, a broken structure, or
    /// what was asked of the wrong kind of inode.
    Err = 1,
    /// `SQFS_BADFORMAT`: not a SquashFS image (no magic, a block size it
    /// cannot have).
    BadFormat = 2,
    /// `SQFS_BADVERSION`: a SquashFS version other than 4.0.
    BadVersion = 3,
    /// `SQFS_BADCOMP`: a compressor that is not read.
    BadComp = 4,
    /// `SQFS_UNSUP`: what the image does not have (an export table).
    Unsup = 5,
}

impl SqfsErr {
    fn name(self) -> &'static str {
        match self {
            SqfsErr::Err => "SQFS_ERR",
            SqfsErr::BadFormat => "SQFS_BADFORMAT",
            SqfsErr::BadVersion => "SQFS_BADVERSION",
            SqfsErr::BadComp => "SQFS_BADCOMP",
            SqfsErr::Unsup => "SQFS_UNSUP",
        }
    }
}

/// A failure to read the image, or what squashfuse fails on.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Reading the image failed (not its end: a read past the end is
    /// [`SqfsErr::Err`], as squashfuse's short `pread`).
    Io(io::Error),
    /// What squashfuse returns, and what failed.
    Squashfs {
        /// The `sqfs_err`.
        err: SqfsErr,
        /// What failed.
        what: &'static str,
    },
}

impl Error {
    pub(crate) fn new(err: SqfsErr, what: &'static str) -> Error {
        Error::Squashfs { err, what }
    }

    /// The `sqfs_err` squashfuse returns: `SQFS_ERR` for a read error.
    pub fn code(&self) -> SqfsErr {
        match self {
            Error::Io(_) => SqfsErr::Err,
            Error::Squashfs { err, .. } => *err,
        }
    }

    /// What failed, or `"read error"`.
    pub fn what(&self) -> &'static str {
        match self {
            Error::Io(_) => "read error",
            Error::Squashfs { what, .. } => what,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "SquashFS: read error: {e}"),
            Error::Squashfs { err, what } => write!(f, "SquashFS: {what} ({})", err.name()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Squashfs { .. } => None,
        }
    }
}

/// The image's read error, or the [`Error`] an `io::Error` holds (from
/// [`File`](crate::squashfs::File)'s reads).
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        match e.get_ref().map(|inner| inner.is::<Error>()) {
            Some(true) => match e.into_inner().map(|inner| inner.downcast::<Error>()) {
                Some(Ok(inner)) => *inner,
                Some(Err(other)) => Error::Io(io::Error::new(io::ErrorKind::InvalidData, other)),
                None => Error::new(SqfsErr::Err, "read error"),
            },
            _ => Error::Io(e),
        }
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        match e {
            Error::Io(e) => e,
            e @ Error::Squashfs { .. } => io::Error::new(io::ErrorKind::InvalidData, e),
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// `SQFS_ERR`, and what failed.
pub(crate) fn err(what: &'static str) -> Error {
    Error::new(SqfsErr::Err, what)
}
