//! Constants, return codes and messages: port of the parts of `zlib.h`,
//! `zconf.h` and `zutil.{h,c}` that inflate uses.
//!
//! zlib returns an `int`: `Z_OK`, `Z_STREAM_END` and `Z_NEED_DICT` on
//! success, a negative code on failure, and sets `strm->msg` for data
//! errors. The port returns `Result<Status, Error>` instead, with the same
//! codes and messages.

use core::fmt;

/// `MAX_WBITS`: the base-two logarithm of the largest window, 32 KiB.
pub const MAX_WBITS: i32 = 15;

/// `DEF_WBITS`: the window `inflateInit` asks for.
pub(crate) const DEF_WBITS: i32 = MAX_WBITS;

/// `Z_DEFLATED`: the only compression method zlib and gzip headers name.
pub(crate) const Z_DEFLATED: u32 = 8;

/// zlib's return codes, as numbers, for the code that follows the C.
pub(crate) const Z_OK: i32 = 0;
pub(crate) const Z_STREAM_END: i32 = 1;
pub(crate) const Z_NEED_DICT: i32 = 2;
pub(crate) const Z_DATA_ERROR: i32 = -3;
pub(crate) const Z_BUF_ERROR: i32 = -5;

/// The `flush` argument of `inflate()` (and, later, `deflate()`):
/// `Z_NO_FLUSH` to `Z_TREES`, with the same numbers.
///
/// inflate always writes as much as it can, so for it only three matter:
/// with `Finish` it never returns `Status::Ok`, and `Block` and `Trees`
/// make it stop at block boundaries.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Flush {
    NoFlush = 0,
    PartialFlush = 1,
    SyncFlush = 2,
    FullFlush = 3,
    Finish = 4,
    Block = 5,
    Trees = 6,
}

/// Success: `Z_OK`, `Z_STREAM_END` or `Z_NEED_DICT`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Status {
    /// `Z_OK`: progress was made, and the stream goes on.
    Ok,
    /// `Z_STREAM_END`: the end of the stream, its check value verified.
    StreamEnd,
    /// `Z_NEED_DICT`: the stream needs the dictionary whose Adler-32
    /// [`crate::deflate::Inflate::adler`] gives.
    NeedDict,
}

/// zlib's negative return codes, with the same numbers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum ErrorCode {
    /// `Z_ERRNO`: a file system error, which inflate never returns.
    Errno = -1,
    /// `Z_STREAM_ERROR`: a parameter out of range, or a call in the wrong
    /// state.
    Stream = -2,
    /// `Z_DATA_ERROR`: the input is not a valid stream, or a check value
    /// does not match; [`Error::msg`] says which.
    Data = -3,
    /// `Z_MEM_ERROR`: not enough memory.
    Mem = -4,
    /// `Z_BUF_ERROR`: no progress was possible, or, with `Flush::Finish`,
    /// the stream did not end. Not fatal: calling again with more input or
    /// output space continues.
    Buf = -5,
    /// `Z_VERSION_ERROR`, which the port never returns.
    Version = -6,
}

impl ErrorCode {
    /// The number zlib gives this error.
    pub fn number(self) -> i32 {
        self as i32
    }

    /// The message `zError()` gives for this code.
    ///
    /// Port of `z_errmsg` in `zutil.c`.
    pub fn message(self) -> &'static str {
        match self {
            ErrorCode::Errno => "file error",
            ErrorCode::Stream => "stream error",
            ErrorCode::Data => "data error",
            ErrorCode::Mem => "insufficient memory",
            ErrorCode::Buf => "buffer error",
            ErrorCode::Version => "incompatible version",
        }
    }

    pub(crate) fn from_number(code: i32) -> ErrorCode {
        match code {
            -1 => ErrorCode::Errno,
            -2 => ErrorCode::Stream,
            -3 => ErrorCode::Data,
            -4 => ErrorCode::Mem,
            -5 => ErrorCode::Buf,
            _ => ErrorCode::Version,
        }
    }
}

/// A failure: zlib's return code, and the message it left in `strm->msg`,
/// if any.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Error {
    code: ErrorCode,
    msg: Option<&'static str>,
}

impl Error {
    pub(crate) fn new(code: ErrorCode, msg: Option<&'static str>) -> Error {
        Error { code, msg }
    }

    pub(crate) fn stream() -> Error {
        Error::new(ErrorCode::Stream, None)
    }

    /// The return code.
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// What `strm->msg` said when the call returned, such as `"invalid
    /// distance too far back"`. Data errors always have one.
    pub fn msg(&self) -> Option<&'static str> {
        self.msg
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.msg.unwrap_or(self.code.message()))
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

/// `ZSWAP32`: the four low bytes of `q` in the other order.
pub(crate) fn zswap32(q: u64) -> u32 {
    (q as u32).swap_bytes()
}

/// zlib's return code as the port returns it, with `msg` for a failure.
pub(crate) fn result(ret: i32, msg: Option<&'static str>) -> Result<Status> {
    match ret {
        Z_OK => Ok(Status::Ok),
        Z_STREAM_END => Ok(Status::StreamEnd),
        Z_NEED_DICT => Ok(Status::NeedDict),
        _ => Err(Error::new(ErrorCode::from_number(ret), msg)),
    }
}
