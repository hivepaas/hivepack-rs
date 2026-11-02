// hivepack::rar: a port of UnRAR 7.3.2 to Rust. UnRAR's license says:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

//! What went wrong: UnRAR's exit codes, which its `ErrHandler` keeps
//! (errhnd.cpp), and the errors that stop reading.

use std::fmt;
use std::io;

/// UnRAR's exit code: the worst of what happened, by UnRAR's rules.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExitCode {
    #[default]
    Success,
    Warning,
    Fatal,
    Crc,
    Lock,
    Write,
    Open,
    User,
    Memory,
    Create,
    NoFiles,
    BadPassword,
    Read,
    BadArchive,
    Delete,
    UserLimit,
    UserBreak,
}

impl ExitCode {
    /// The number UnRAR exits with.
    pub fn number(self) -> u32 {
        match self {
            ExitCode::Success => 0,
            ExitCode::Warning => 1,
            ExitCode::Fatal => 2,
            ExitCode::Crc => 3,
            ExitCode::Lock => 4,
            ExitCode::Write => 5,
            ExitCode::Open => 6,
            ExitCode::User => 7,
            ExitCode::Memory => 8,
            ExitCode::Create => 9,
            ExitCode::NoFiles => 10,
            ExitCode::BadPassword => 11,
            ExitCode::Read => 12,
            ExitCode::BadArchive => 13,
            ExitCode::Delete => 14,
            ExitCode::UserLimit => 15,
            ExitCode::UserBreak => 255,
        }
    }

    /// `ErrorHandler::SetErrorCode`: the code after `code` happens.
    pub(crate) fn set(self, code: ExitCode) -> ExitCode {
        match code {
            ExitCode::Warning | ExitCode::UserBreak => {
                if self == ExitCode::Success {
                    code
                } else {
                    self
                }
            }
            ExitCode::Crc => {
                if self != ExitCode::BadPassword && self != ExitCode::Open {
                    code
                } else {
                    self
                }
            }
            ExitCode::Fatal => {
                if self == ExitCode::Success || self == ExitCode::Warning {
                    ExitCode::Fatal
                } else {
                    self
                }
            }
            _ => code,
        }
    }
}

/// Why an archive could not be read on.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Not a RAR archive, or one whose main header is broken: what UnRAR's
    /// `IsArchive` refuses, with the exit code so far.
    NotRar { exit_code: ExitCode },
    /// The headers are encrypted, and no password was given: UnRAR's
    /// library stops there, with the exit code so far.
    MissingPassword { exit_code: ExitCode },
    /// A next volume is not an archive, or says otherwise about encrypting
    /// its headers: UnRAR stops all reading there, with this exit code.
    BadVolume { exit_code: ExitCode },
    /// A QuickOpen record is said to be further than a file can be: UnRAR
    /// stops all reading there, with this exit code.
    BadSeek { exit_code: ExitCode },
    /// There is no memory for a dictionary, or UnRAR refuses it for one: too
    /// large, or larger than the one of the solid stream it goes on.
    NoMemory,
    /// The archive could not be read.
    Io(io::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotRar { .. } => f.write_str("not a RAR archive, or its main header is broken"),
            Error::MissingPassword { .. } => {
                f.write_str("the headers are encrypted, and no password was given")
            }
            Error::BadVolume { .. } => f.write_str("a next volume is not of this archive"),
            Error::BadSeek { .. } => f.write_str("a QuickOpen record is past where a file can be"),
            Error::NoMemory => f.write_str("no memory for this dictionary"),
            Error::Io(e) => write!(f, "{e}"),
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
