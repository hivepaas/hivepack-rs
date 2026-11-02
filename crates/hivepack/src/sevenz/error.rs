//! `SRes`, the results of the LZMA SDK's functions (`7zTypes.h`).

/// An error: `SZ_ERROR_*`, with the LZMA SDK's numbers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Error {
    /// `SZ_ERROR_DATA`: damaged data.
    Data = 1,
    /// `SZ_ERROR_MEM`: more memory than can be had, or than the limit
    /// allows.
    Mem = 2,
    /// `SZ_ERROR_CRC`: a checksum that does not match.
    Crc = 3,
    /// `SZ_ERROR_UNSUPPORTED`: a method or a structure the decoder does not
    /// handle.
    Unsupported = 4,
    /// `SZ_ERROR_PARAM`.
    Param = 5,
    /// `SZ_ERROR_INPUT_EOF`: the archive ends early.
    InputEof = 6,
    /// `SZ_ERROR_OUTPUT_EOF`.
    OutputEof = 7,
    /// `SZ_ERROR_READ`: the archive could not be read.
    Read = 8,
    /// `SZ_ERROR_WRITE`.
    Write = 9,
    /// `SZ_ERROR_PROGRESS`.
    Progress = 10,
    /// `SZ_ERROR_FAIL`.
    Fail = 11,
    /// `SZ_ERROR_THREAD`.
    Thread = 12,
    /// `SZ_ERROR_ARCHIVE`: damaged headers.
    Archive = 16,
    /// `SZ_ERROR_NO_ARCHIVE`: not a 7z archive.
    NoArchive = 17,
    /// Not one of the SDK's, which has no AES: the data is encrypted, and no
    /// password was given.
    PasswordRequired = 100,
    /// Not one of the SDK's: encrypted data did not decode. 7z has nothing to
    /// check a password with but the data, so it may be damaged instead.
    WrongPassword = 101,
}

impl Error {
    /// The error's number, `SZ_ERROR_*`.
    pub fn number(self) -> i32 {
        self as i32
    }

    /// The name of its constant: `"SZ_ERROR_DATA"` and so on.
    pub fn name(self) -> &'static str {
        match self {
            Error::Data => "SZ_ERROR_DATA",
            Error::Mem => "SZ_ERROR_MEM",
            Error::Crc => "SZ_ERROR_CRC",
            Error::Unsupported => "SZ_ERROR_UNSUPPORTED",
            Error::Param => "SZ_ERROR_PARAM",
            Error::InputEof => "SZ_ERROR_INPUT_EOF",
            Error::OutputEof => "SZ_ERROR_OUTPUT_EOF",
            Error::Read => "SZ_ERROR_READ",
            Error::Write => "SZ_ERROR_WRITE",
            Error::Progress => "SZ_ERROR_PROGRESS",
            Error::Fail => "SZ_ERROR_FAIL",
            Error::Thread => "SZ_ERROR_THREAD",
            Error::Archive => "SZ_ERROR_ARCHIVE",
            Error::NoArchive => "SZ_ERROR_NO_ARCHIVE",
            Error::PasswordRequired => "PASSWORD_REQUIRED",
            Error::WrongPassword => "WRONG_PASSWORD",
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let what = match self {
            Error::Data => "damaged data",
            Error::Mem => "not enough memory",
            Error::Crc => "checksum mismatch",
            Error::Unsupported => "unsupported method or structure",
            Error::Param => "invalid parameter",
            Error::InputEof => "unexpected end of the archive",
            Error::OutputEof => "output full",
            Error::Read => "read error",
            Error::Write => "write error",
            Error::Progress => "interrupted",
            Error::Fail => "failure",
            Error::Thread => "thread error",
            Error::Archive => "damaged headers",
            Error::NoArchive => "not a 7z archive",
            Error::PasswordRequired => "the data is encrypted, and needs a password",
            Error::WrongPassword => "wrong password, or damaged data",
        };
        write!(f, "{what} ({})", self.name())
    }
}

impl std::error::Error for Error {}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        let kind = match e {
            Error::InputEof => std::io::ErrorKind::UnexpectedEof,
            Error::Unsupported => std::io::ErrorKind::Unsupported,
            Error::Mem => std::io::ErrorKind::OutOfMemory,
            _ => std::io::ErrorKind::InvalidData,
        };
        std::io::Error::new(kind, e)
    }
}

/// `SRes` as a result.
pub type Result<T> = core::result::Result<T, Error>;
