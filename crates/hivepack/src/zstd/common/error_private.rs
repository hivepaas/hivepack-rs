//! Error codes: port of `zstd_errors.h` and `common/error_private.{h,c}`.
//!
//! libzstd returns errors as `size_t` values near `SIZE_MAX`. The port
//! returns `Result<_, Error>` instead, with the same codes and messages.

use core::fmt;

/// libzstd's `ZSTD_ErrorCode`, with the same numbers. `ZSTD_error_no_error`
/// and `ZSTD_error_maxCode` have no variant: success is `Ok`, and the
/// maximum is not an error.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum ErrorCode {
    Generic = 1,
    PrefixUnknown = 10,
    VersionUnsupported = 12,
    FrameParameterUnsupported = 14,
    FrameParameterWindowTooLarge = 16,
    CorruptionDetected = 20,
    ChecksumWrong = 22,
    LiteralsHeaderWrong = 24,
    DictionaryCorrupted = 30,
    DictionaryWrong = 32,
    DictionaryCreationFailed = 34,
    ParameterUnsupported = 40,
    ParameterCombinationUnsupported = 41,
    ParameterOutOfBound = 42,
    TableLogTooLarge = 44,
    MaxSymbolValueTooLarge = 46,
    MaxSymbolValueTooSmall = 48,
    CannotProduceUncompressedBlock = 49,
    StabilityConditionNotRespected = 50,
    StageWrong = 60,
    InitMissing = 62,
    MemoryAllocation = 64,
    WorkSpaceTooSmall = 66,
    DstSizeTooSmall = 70,
    SrcSizeWrong = 72,
    DstBufferNull = 74,
    NoForwardProgressDestFull = 80,
    NoForwardProgressInputEmpty = 82,
    FrameIndexTooLarge = 100,
    SeekableIo = 102,
    DstBufferWrong = 104,
    SrcBufferWrong = 105,
    SequenceProducerFailed = 106,
    ExternalSequencesInvalid = 107,
}

impl ErrorCode {
    /// The number libzstd gives this error.
    pub fn number(self) -> u32 {
        self as u32
    }

    /// The message `ZSTD_getErrorName` gives for this error.
    ///
    /// Port of `ERR_getErrorString`.
    pub fn message(self) -> &'static str {
        match self {
            ErrorCode::Generic => "Error (generic)",
            ErrorCode::PrefixUnknown => "Unknown frame descriptor",
            ErrorCode::VersionUnsupported => "Version not supported",
            ErrorCode::FrameParameterUnsupported => "Unsupported frame parameter",
            ErrorCode::FrameParameterWindowTooLarge => {
                "Frame requires too much memory for decoding"
            }
            ErrorCode::CorruptionDetected => "Data corruption detected",
            ErrorCode::ChecksumWrong => "Restored data doesn't match checksum",
            ErrorCode::LiteralsHeaderWrong => {
                "Header of Literals' block doesn't respect format specification"
            }
            ErrorCode::ParameterUnsupported => "Unsupported parameter",
            ErrorCode::ParameterCombinationUnsupported => "Unsupported combination of parameters",
            ErrorCode::ParameterOutOfBound => "Parameter is out of bound",
            ErrorCode::InitMissing => "Context should be init first",
            ErrorCode::MemoryAllocation => "Allocation error : not enough memory",
            ErrorCode::WorkSpaceTooSmall => "workSpace buffer is not large enough",
            ErrorCode::StageWrong => "Operation not authorized at current processing stage",
            ErrorCode::TableLogTooLarge => "tableLog requires too much memory : unsupported",
            ErrorCode::MaxSymbolValueTooLarge => "Unsupported max Symbol Value : too large",
            ErrorCode::MaxSymbolValueTooSmall => "Specified maxSymbolValue is too small",
            ErrorCode::CannotProduceUncompressedBlock => {
                "This mode cannot generate an uncompressed block"
            }
            ErrorCode::StabilityConditionNotRespected => {
                "pledged buffer stability condition is not respected"
            }
            ErrorCode::DictionaryCorrupted => "Dictionary is corrupted",
            ErrorCode::DictionaryWrong => "Dictionary mismatch",
            ErrorCode::DictionaryCreationFailed => "Cannot create Dictionary from provided samples",
            ErrorCode::DstSizeTooSmall => "Destination buffer is too small",
            ErrorCode::SrcSizeWrong => "Src size is incorrect",
            ErrorCode::DstBufferNull => "Operation on NULL destination buffer",
            ErrorCode::NoForwardProgressDestFull => {
                "Operation made no progress over multiple calls, due to output buffer being full"
            }
            ErrorCode::NoForwardProgressInputEmpty => {
                "Operation made no progress over multiple calls, due to input being empty"
            }
            ErrorCode::FrameIndexTooLarge => "Frame index is too large",
            ErrorCode::SeekableIo => "An I/O error occurred when reading/seeking",
            ErrorCode::DstBufferWrong => "Destination buffer is wrong",
            ErrorCode::SrcBufferWrong => "Source buffer is wrong",
            ErrorCode::SequenceProducerFailed => {
                "Block-level external sequence producer returned an error code"
            }
            ErrorCode::ExternalSequencesInvalid => "External sequences are not valid",
        }
    }
}

/// An error from compressing or decompressing, as libzstd reports it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Error {
    code: ErrorCode,
}

impl Error {
    pub fn code(&self) -> ErrorCode {
        self.code
    }
}

impl From<ErrorCode> for Error {
    fn from(code: ErrorCode) -> Self {
        Error { code }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error({:?}: {})", self.code, self.code.message())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code.message())
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

/// `ERROR(name)`: an `Err` with that code.
macro_rules! error {
    ($code:ident) => {
        Err($crate::zstd::common::error_private::Error::from(
            $crate::zstd::common::error_private::ErrorCode::$code,
        ))
    };
}
pub(crate) use error;
