//! bzip2 through hivepack::bzip2, whose compressor and decompressor give
//! libbzip2's output and results: port of `zip_algorithm_bzip2.c`.

use crate::bzip2::{Action, Compress, Decompress, Error as BzError, InBuffer, OutBuffer, Status};

use crate::zip::algorithm_deflate::CompressionStatus;
use crate::zip::error::{Error, ErrorCode};

/// The version needed to extract bzip2 data, the algorithms'
/// `version_needed`.
pub(crate) const VERSION_NEEDED: u8 = 46;

/// The most a bzip2 stream of `uncompressed_size` bytes can take:
/// `maximum_compressed_size`.
pub(crate) fn maximum_compressed_size(uncompressed_size: u64) -> u64 {
    // According to the bzip2 man page, random data is coded at about 8.05
    // bits per byte, giving an expansion of around 0.5%. However, in
    // practice the per-block overhead doubles the factor for compression
    // level 1. Add an additional safety factor.
    uncompressed_size.saturating_add(uncompressed_size / 64 + 1024)
}

/// `map_error`: the libzip error for a libbzip2 error.
fn map_error(error: BzError) -> Error {
    let code = match error {
        BzError::Data | BzError::DataMagic | BzError::UnexpectedEof => ErrorCode::CompressedData,
        BzError::Mem => ErrorCode::Memory,
        BzError::Param => ErrorCode::Inval,
        // BZ_CONFIG_ERROR (actually, bzip2 miscompiled), BZ_IO_ERROR,
        // BZ_OUTBUFF_FULL, BZ_SEQUENCE_ERROR.
        _ => ErrorCode::Internal,
    };
    Error::new(code, 0)
}

/// The stream: a compressor or a decompressor, once started.
enum Stream {
    Compress(Box<Compress>),
    Decompress(Box<Decompress>),
}

/// `struct ctx`: the stream, and the input it holds, a range of the
/// compression source's buffer.
pub(crate) struct Bzip2 {
    compress: bool,
    compression_flags: i32,
    end_of_input: bool,
    zstr: Option<Stream>,
    /// `next_in` and `avail_in`, as positions in the buffer given to
    /// `process`.
    next_in: usize,
    avail_in: usize,
}

impl Bzip2 {
    /// `allocate`: to compress, at block size 1 to 9 from
    /// `compression_flags`, else 9, or to decompress.
    fn new(compress: bool, compression_flags: u32) -> Bzip2 {
        Bzip2 {
            compress,
            compression_flags: if (1..=9).contains(&compression_flags) {
                compression_flags as i32
            } else {
                9
            },
            end_of_input: false,
            zstr: None,
            next_in: 0,
            avail_in: 0,
        }
    }

    /// `compress_allocate`.
    pub(crate) fn compressor(compression_flags: u32) -> Bzip2 {
        Bzip2::new(true, compression_flags)
    }

    /// `decompress_allocate`.
    pub(crate) fn decompressor() -> Bzip2 {
        Bzip2::new(false, 0)
    }

    /// `general_purpose_bit_flags`: none.
    pub(crate) fn general_purpose_bit_flags(&self) -> u16 {
        0
    }

    /// `start`: `BZ2_bzCompressInit` with the work factor 30, or
    /// `BZ2_bzDecompressInit`, not small.
    pub(crate) fn start(&mut self) -> Result<(), Error> {
        self.next_in = 0;
        self.avail_in = 0;
        self.zstr = Some(if self.compress {
            Stream::Compress(Box::new(
                Compress::new(self.compression_flags, 30).map_err(map_error)?,
            ))
        } else {
            Stream::Decompress(Box::new(Decompress::new(false)))
        });
        Ok(())
    }

    /// `end`: `BZ2_bzCompressEnd` or `BZ2_bzDecompressEnd`, which do not
    /// fail on a stream that was started.
    pub(crate) fn end(&mut self) -> Result<(), Error> {
        self.zstr = None;
        Ok(())
    }

    /// `input`: `length` bytes at the start of the buffer.
    pub(crate) fn input(&mut self, length: usize) -> Result<(), Error> {
        if length as u64 > u64::from(u32::MAX) || self.avail_in > 0 {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        self.next_in = 0;
        self.avail_in = length;
        Ok(())
    }

    /// `end_of_input`: whether input is left over.
    pub(crate) fn end_of_input(&mut self) -> bool {
        self.end_of_input = true;
        self.avail_in != 0
    }

    /// `process`: compresses from `buffer` into `data`, with `BZ_FINISH`
    /// once the input ended, or decompresses, returning the status and the
    /// bytes written.
    pub(crate) fn process(&mut self, buffer: &[u8], data: &mut [u8]) -> (CompressionStatus, usize) {
        if self.avail_in == 0 && !self.end_of_input {
            return (CompressionStatus::NeedData, 0);
        }
        let Some(zstr) = self.zstr.as_mut() else {
            return (
                CompressionStatus::Error(Error::new(ErrorCode::Internal, 0)),
                0,
            );
        };

        let avail_out = data.len().min(u32::MAX as usize);
        let mut output = OutBuffer::new(&mut data[..avail_out]);
        let mut input = InBuffer::new(&buffer[self.next_in..self.next_in + self.avail_in]);
        let ret = match zstr {
            Stream::Compress(zstr) => {
                let action = if self.end_of_input {
                    Action::Finish
                } else {
                    Action::Run
                };
                zstr.compress(&mut output, &mut input, action)
            }
            Stream::Decompress(zstr) => zstr.decompress(&mut output, &mut input),
        };
        self.next_in += input.pos;
        self.avail_in -= input.pos;
        let length = output.pos;

        let status = match ret {
            // compression
            Ok(Status::FinishOk) => CompressionStatus::Ok,
            // decompression, compression
            Ok(Status::Ok | Status::RunOk) => {
                if self.avail_in == 0 {
                    CompressionStatus::NeedData
                } else {
                    CompressionStatus::Ok
                }
            }
            Ok(Status::StreamEnd) => CompressionStatus::End,
            // BZ_FLUSH_OK, which BZ_RUN and BZ_FINISH never return, falls
            // to map_error's default in libzip.
            Ok(Status::FlushOk) => CompressionStatus::Error(Error::new(ErrorCode::Ok, 0)),
            Err(e) => CompressionStatus::Error(map_error(e)),
        };
        (status, length)
    }
}
