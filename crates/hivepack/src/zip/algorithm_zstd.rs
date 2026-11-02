//! Zstandard through hivepack::zstd, whose streams give libzstd's frames and
//! results: port of `zip_algorithm_zstd.c`.

use crate::zstd::{CCtx, DCtx, InBuffer, OutBuffer, compress_bound, max_c_level, min_c_level};

use crate::zip::algorithm_deflate::CompressionStatus;
use crate::zip::error::{Error, ErrorCode};

/// The version needed to extract Zstandard data, the algorithms'
/// `version_needed`. Version Required should be set to 63 (6.3) because
/// this compression method was only defined in appnote.txt version 6.3.7,
/// but Winzip does not unpack it if the value is not 20.
pub(crate) const VERSION_NEEDED: u8 = 20;

/// `ZSTD_error_srcSize_wrong`, which `ZSTD_compressBound` returns, negated
/// as a `size_t`, for a size too large for a frame.
const SRC_SIZE_WRONG: u64 = 72;

/// The most a Zstandard frame of `uncompressed_size` bytes can take:
/// `maximum_compressed_size`, which gives libzip libzstd's error code, a
/// large number, for sizes too large for a frame.
///
/// Differs from libzip on 32-bit machines, where C cuts a size past a
/// `size_t` down to one first.
pub(crate) fn maximum_compressed_size(uncompressed_size: u64) -> u64 {
    usize::try_from(uncompressed_size)
        .ok()
        .and_then(compress_bound)
        .map_or(SRC_SIZE_WRONG.wrapping_neg(), |bound| bound as u64)
}

/// `map_error`, as libzip uses it: it is given what libzstd's functions
/// return, an error negated as a `size_t` (`ZSTD_getErrorCode` would tell
/// which), so that no `ZSTD_error_` value it looks for matches and every
/// error falls to its default.
fn map_error() -> ErrorCode {
    ErrorCode::Internal
}

/// `struct ctx`, the input being where the compressing layer's buffer has
/// it. libzstd's streams live from `start` to `end`.
pub(crate) struct Zstd {
    compress: bool,
    compression_flags: i32,
    end_of_input: bool,
    zdstream: Option<Box<DCtx>>,
    zcstream: Option<Box<CCtx>>,
    in_pos: usize,
    in_size: usize,
}

impl Zstd {
    /// `allocate`. `zip_set_file_compression` cuts the flags to a `u16`, in
    /// libzip as here, so no negative level gets this far: those it is given
    /// are past `ZSTD_maxCLevel()` by now.
    fn new(compress: bool, compression_flags: u32) -> Zstd {
        let mut compression_flags = compression_flags as i32;
        if compression_flags < min_c_level() || compression_flags > max_c_level() {
            compression_flags = 0; // let zstd choose
        }
        Zstd {
            compress,
            compression_flags,
            end_of_input: false,
            zdstream: None,
            zcstream: None,
            in_pos: 0,
            in_size: 0,
        }
    }

    /// `compress_allocate`.
    pub(crate) fn compressor(compression_flags: u32) -> Zstd {
        Zstd::new(true, compression_flags)
    }

    /// `decompress_allocate`.
    pub(crate) fn decompressor() -> Zstd {
        Zstd::new(false, 0)
    }

    /// `general_purpose_bit_flags`.
    pub(crate) fn general_purpose_bit_flags(&self) -> u16 {
        0
    }

    /// `start`.
    pub(crate) fn start(&mut self) -> Result<(), Error> {
        self.in_pos = 0;
        self.in_size = 0;
        if self.compress {
            let mut zcstream = Box::new(CCtx::new());
            if zcstream.init_cstream(self.compression_flags).is_err() {
                return Err(Error::new(ErrorCode::Zlib, map_error().number()));
            }
            self.zcstream = Some(zcstream);
        } else {
            self.zdstream = Some(Box::default());
        }
        Ok(())
    }

    /// `end`.
    pub(crate) fn end(&mut self) -> Result<(), Error> {
        self.zcstream = None;
        self.zdstream = None;
        Ok(())
    }

    /// `input`: the first `length` bytes of the layer's buffer.
    pub(crate) fn input(&mut self, length: usize) -> Result<(), Error> {
        if self.in_pos != self.in_size {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        self.in_size = length;
        self.in_pos = 0;
        Ok(())
    }

    /// `end_of_input`: whether input is left over.
    pub(crate) fn end_of_input(&mut self) -> bool {
        self.end_of_input = true;
        self.in_pos != self.in_size
    }

    /// `process`: from `buffer` into `data`, returning the status and the
    /// bytes written.
    pub(crate) fn process(&mut self, buffer: &[u8], data: &mut [u8]) -> (CompressionStatus, usize) {
        if self.in_pos == self.in_size && !self.end_of_input {
            return (CompressionStatus::NeedData, 0);
        }

        let mut output = OutBuffer::new(data);
        let mut input = InBuffer::new(&buffer[self.in_pos..self.in_size]);

        let ret = if let Some(zcstream) = self.zcstream.as_mut() {
            if self.in_pos == self.in_size && self.end_of_input {
                let ret = zcstream.end_stream(&mut output);
                if ret == Ok(0) {
                    return (CompressionStatus::End, output.pos);
                }
                ret
            } else {
                zcstream.compress_stream(&mut output, &mut input)
            }
        } else if let Some(zdstream) = self.zdstream.as_mut() {
            zdstream.decompress_stream(&mut output, &mut input)
        } else {
            return (
                CompressionStatus::Error(Error::new(ErrorCode::Internal, 0)),
                0,
            );
        };
        if ret.is_err() {
            return (
                CompressionStatus::Error(Error::new(map_error(), 0)),
                output.pos,
            );
        }
        self.in_pos += input.pos;

        let length = output.pos;
        if self.in_pos == self.in_size {
            return (CompressionStatus::NeedData, length);
        }
        (CompressionStatus::Ok, length)
    }
}
