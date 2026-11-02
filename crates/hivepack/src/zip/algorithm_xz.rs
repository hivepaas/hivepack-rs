//! LZMA and XZ through hivepack::xz, whose encoders and decoders give
//! liblzma's output and results: port of `zip_algorithm_xz.c`.

use crate::xz::{
    Action, CONCATENATED, Check, Error as XzError, Filter, InBuffer, LzmaOptions, OutBuffer,
    PRESET_EXTREME, Status, Stream,
};

use crate::zip::algorithm_deflate::CompressionStatus;
use crate::zip::error::{Error, ErrorCode};
use crate::zip::source_data::{FileAttributes, file_attributes};
use crate::zip::zip::{Stat, cm, stat};

/// `enum header_state`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HeaderState {
    Incomplete,
    Output,
    Done,
}

const HEADER_BYTES_ZIP: usize = 9;
const HEADER_MAGIC_LENGTH: usize = 4;
const HEADER_MAGIC2_OFFSET: usize = 2;
const HEADER_SIZE_OFFSET: usize = 9;
const HEADER_SIZE_LENGTH: usize = 8;
const HEADER_PARAMETERS_LENGTH: usize = 5;
const HEADER_LZMA_ALONE_LENGTH: usize = HEADER_PARAMETERS_LENGTH + HEADER_SIZE_LENGTH;

/// The version needed to extract LZMA and XZ data, the algorithms'
/// `version_needed`. Version Required should be set to 63 (6.3) because
/// this compression method was only defined in appnote.txt version 6.3.8,
/// but Winzip does not unpack it if the value is not 20.
pub(crate) const VERSION_NEEDED: u8 = 20;

/// `LZMA_WINDOW_LIMIT`, as libzip's CMake build sets it unless it is told
/// otherwise with `LIMIT_LZMA_WINDOW`: none. The memory of a big window is
/// reserved and written only as far as data is decoded.
#[cfg(not(fuzzing))]
const LZMA_WINDOW_LIMIT: u64 = u64::MAX;

/// The fuzzers tell it otherwise, for libFuzzer takes the 4 GiB reserved for
/// a window that a header can ask for as being out of memory.
#[cfg(fuzzing)]
const LZMA_WINDOW_LIMIT: u64 = 300 << 20;

/// The most an LZMA or XZ stream of `uncompressed_size` bytes can take:
/// `maximum_compressed_size`.
pub(crate) fn maximum_compressed_size(uncompressed_size: u64) -> u64 {
    // According to https://sourceforge.net/p/sevenzip/discussion/45797/thread/b6bd62f8/
    //
    // 1) you can use outSize = 1.10 * originalSize + 64 KB. in most cases
    // outSize is less then 1.02 from originalSize.
    // 2) You can try LZMA2, where outSize can be = 1.001 * originalSize + 1 KB.
    //
    // 13 bytes added for lzma alone header.
    //
    // Differs from libzip: a product past what a u64 holds, which is
    // undefined behaviour to convert in C, is the most a u64 holds.
    let compressed_size = ((uncompressed_size as f64 * 1.1) as u64).wrapping_add(64 * 1024 + 13);

    if compressed_size < uncompressed_size {
        return u64::MAX;
    }
    compressed_size
}

/// `map_error`: the libzip error for a liblzma error.
fn map_error(error: XzError) -> Error {
    let code = match error {
        XzError::Data | XzError::UnsupportedCheck => ErrorCode::CompressedData,
        XzError::Mem | XzError::Memlimit => ErrorCode::Memory,
        XzError::Options => ErrorCode::Inval,
        _ => ErrorCode::Internal,
    };
    Error::new(code, 0)
}

/// `struct ctx`: the stream, and the input it holds, a range of the
/// compression source's buffer.
pub(crate) struct Xz {
    compress: bool,
    compression_flags: u32,
    end_of_input: bool,
    zstr: Option<Stream>,
    method: u16,
    /// Used for converting from zip to "lzma alone" format.
    ///
    /// "lzma alone" file format starts with:
    /// 5 bytes lzma parameters
    /// 8 bytes uncompressed size
    /// compressed data
    ///
    /// zip archive on-disk format starts with
    /// 4 bytes magic (first two bytes vary, e.g. 0x0914 or 0x1002, next
    /// bytes are 0x0500)
    /// 5 bytes lzma parameters
    /// compressed data
    ///
    /// we read the data into a header of the form
    /// 4 bytes magic
    /// 5 bytes lzma parameters
    /// 8 bytes uncompressed size
    header: [u8; HEADER_MAGIC_LENGTH + HEADER_LZMA_ALONE_LENGTH],
    header_bytes_offset: usize,
    header_state: HeaderState,
    uncompressed_size: u64,
    /// `next_in` and `avail_in`, as positions in the buffer given to
    /// `process`.
    next_in: usize,
    avail_in: usize,
}

impl Xz {
    /// `allocate`.
    fn new(compress: bool, compression_flags: u32, method: u16) -> Xz {
        Xz {
            compress,
            compression_flags: if compression_flags <= 9 {
                compression_flags
            } else {
                // default value
                6
            } | PRESET_EXTREME,
            end_of_input: false,
            zstr: None,
            method,
            header: [0; HEADER_MAGIC_LENGTH + HEADER_LZMA_ALONE_LENGTH],
            header_bytes_offset: 0,
            header_state: if method == cm::LZMA {
                HeaderState::Incomplete
            } else {
                HeaderState::Done
            },
            uncompressed_size: 0,
            next_in: 0,
            avail_in: 0,
        }
    }

    /// `compress_allocate`.
    pub(crate) fn compressor(method: u16, compression_flags: u32) -> Xz {
        Xz::new(true, compression_flags, method)
    }

    /// `decompress_allocate`.
    pub(crate) fn decompressor(method: u16) -> Xz {
        Xz::new(false, 0, method)
    }

    /// `general_purpose_bit_flags`: liblzma always returns an EOS/EOPM
    /// marker, see
    /// <https://sourceforge.net/p/lzmautils/discussion/708858/thread/84c5dbb9/#a5e4/3764>.
    pub(crate) fn general_purpose_bit_flags(&self) -> u16 {
        if self.compress && self.method == cm::LZMA {
            1 << 1
        } else {
            0
        }
    }

    /// `start`.
    pub(crate) fn start(
        &mut self,
        st: &Stat<'_>,
        attributes: &FileAttributes,
    ) -> Result<(), Error> {
        // The flags are a level of 9 at most and the extreme flag, which
        // lzma_lzma_preset() takes.
        let opt_lzma = LzmaOptions::preset(self.compression_flags)
            .ok_or_else(|| Error::new(ErrorCode::Internal, 0))?;

        self.next_in = 0;
        self.avail_in = 0;

        let made = if self.compress {
            if self.method == cm::LZMA {
                Stream::alone_encoder(&opt_lzma)
            } else {
                Stream::stream_encoder(&[Filter::lzma2(opt_lzma)], Check::CRC64)
            }
        } else if self.method == cm::LZMA {
            Stream::alone_decoder(LZMA_WINDOW_LIMIT)
        } else {
            Stream::stream_decoder(LZMA_WINDOW_LIMIT, CONCATENATED)
        };
        self.zstr = Some(made.map_err(map_error)?);

        // If general purpose bits 1 & 2 are both zero, write real
        // uncompressed size in header.
        self.uncompressed_size = if attributes.valid & file_attributes::GENERAL_PURPOSE_BIT_FLAGS
            != 0
            && attributes.general_purpose_bit_mask & 0x6 == 0x6
            && attributes.general_purpose_bit_flags & 0x06 == 0
            && st.valid & stat::SIZE != 0
        {
            st.size
        } else {
            u64::MAX
        };

        Ok(())
    }

    /// `end`.
    pub(crate) fn end(&mut self) -> Result<(), Error> {
        self.zstr = None;
        Ok(())
    }

    /// `input`: `length` bytes at the start of `data`, the compression
    /// source's buffer.
    pub(crate) fn input(&mut self, data: &[u8], length: usize) -> Result<(), Error> {
        if length as u64 > u64::from(u32::MAX) || self.avail_in > 0 {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        let mut next_in = 0;
        let mut length = length;

        // For decompression of LZMA1: Have we read the full "lzma alone"
        // header yet?
        if self.method == cm::LZMA && !self.compress && self.header_state == HeaderState::Incomplete
        {
            // if not, get more of the data
            let got = (HEADER_BYTES_ZIP - self.header_bytes_offset).min(length);
            self.header[self.header_bytes_offset..self.header_bytes_offset + got]
                .copy_from_slice(&data[..got]);
            self.header_bytes_offset += got;
            length -= got;
            next_in = got;
            // Do we have a complete header now?
            if self.header_bytes_offset == HEADER_BYTES_ZIP {
                // check magic
                if self.header[HEADER_MAGIC2_OFFSET] != 0x05
                    || self.header[HEADER_MAGIC2_OFFSET + 1] != 0x00
                {
                    // magic does not match
                    return Err(Error::new(ErrorCode::CompressedData, 0));
                }
                // set size of uncompressed data in "lzma alone" header to
                // "unknown"
                self.header[HEADER_SIZE_OFFSET..HEADER_SIZE_OFFSET + HEADER_SIZE_LENGTH]
                    .copy_from_slice(&self.uncompressed_size.to_le_bytes());
                // Feed header into "lzma alone" decoder, for
                // initialization; this should not produce output.
                let Some(zstr) = self.zstr.as_mut() else {
                    return Err(Error::new(ErrorCode::Internal, 0));
                };
                let mut empty_buffer = [0];
                let mut output = OutBuffer::new(&mut empty_buffer);
                let mut input = InBuffer::new(&self.header[HEADER_MAGIC_LENGTH..]);
                // this just initializes the decoder and does not produce
                // output, so it consumes the complete header
                let ret = zstr.code(&mut output, &mut input, Action::Run);
                if ret != Ok(Status::Ok) || output.pos > 0 {
                    return Err(Error::new(ErrorCode::CompressedData, 0));
                }
                self.header_state = HeaderState::Done;
            }
        }
        self.next_in = next_in;
        self.avail_in = length;

        Ok(())
    }

    /// `end_of_input`: whether input is left over.
    pub(crate) fn end_of_input(&mut self) -> bool {
        self.end_of_input = true;
        self.avail_in != 0
    }

    /// `process`: from `buffer` into `data`, with `LZMA_FINISH` once the
    /// input ended, returning the status and the bytes written.
    pub(crate) fn process(&mut self, buffer: &[u8], data: &mut [u8]) -> (CompressionStatus, usize) {
        let Some(zstr) = self.zstr.as_mut() else {
            return (
                CompressionStatus::Error(Error::new(ErrorCode::Internal, 0)),
                0,
            );
        };
        let in_range = self.next_in..self.next_in + self.avail_in;

        // for compression of LZMA1
        if self.method == cm::LZMA && self.compress {
            if self.header_state == HeaderState::Incomplete {
                // write magic to output buffer
                self.header[..HEADER_MAGIC_LENGTH].copy_from_slice(&[0x09, 0x14, 0x05, 0x00]);
                // generate lzma parameters into output buffer
                let mut output = OutBuffer::new(&mut self.header[HEADER_MAGIC_LENGTH..]);
                let mut input = InBuffer::new(&buffer[in_range.clone()]);
                let ret = zstr.code(&mut output, &mut input, Action::Run);
                let filled = output.pos == HEADER_LZMA_ALONE_LENGTH;
                let read = input.pos;
                self.next_in += read;
                self.avail_in -= read;
                if ret != Ok(Status::Ok) || !filled {
                    // assume that the whole header will be provided with
                    // the first call to lzma_code
                    return (CompressionStatus::Error(Error::new(ErrorCode::Ok, 0)), 0);
                }
                self.header_state = HeaderState::Output;
            }
            if self.header_state == HeaderState::Output {
                // write header
                let write_len = (HEADER_BYTES_ZIP - self.header_bytes_offset).min(data.len());
                data[..write_len].copy_from_slice(
                    &self.header[self.header_bytes_offset..self.header_bytes_offset + write_len],
                );
                self.header_bytes_offset += write_len;
                if self.header_bytes_offset == HEADER_BYTES_ZIP {
                    self.header_state = HeaderState::Done;
                }
                return (CompressionStatus::Ok, write_len);
            }
        }

        let in_range = self.next_in..self.next_in + self.avail_in;
        let avail_out = data.len().min(u32::MAX as usize);
        let mut output = OutBuffer::new(&mut data[..avail_out]);
        let mut input = InBuffer::new(&buffer[in_range]);
        let action = if self.end_of_input {
            Action::Finish
        } else {
            Action::Run
        };
        let ret = zstr.code(&mut output, &mut input, action);
        self.next_in += input.pos;
        self.avail_in -= input.pos;
        let length = output.pos;

        let status = match ret {
            Ok(Status::Ok) => CompressionStatus::Ok,
            Ok(Status::StreamEnd) => CompressionStatus::End,
            Err(XzError::Buf) if self.avail_in == 0 => CompressionStatus::NeedData,
            Err(e) => CompressionStatus::Error(map_error(e)),
            // LZMA_NO_CHECK, LZMA_UNSUPPORTED_CHECK and LZMA_GET_CHECK, for
            // flags that are not given, fall to map_error's default.
            Ok(_) => CompressionStatus::Error(Error::new(ErrorCode::Internal, 0)),
        };
        (status, length)
    }
}
