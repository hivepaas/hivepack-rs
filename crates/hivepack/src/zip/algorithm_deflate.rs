//! Deflate through hivepack::deflate, whose inflate and deflate give zlib's
//! results and output: port of `zip_algorithm_deflate.c`.
//!
//! Differs from libzip, which has no Deflate64: the same algorithm decodes
//! Deflate64 (method 9) with `Inflate9`, which follows zlib's
//! `contrib/infback9`, and reports its errors as zlib's (`ZIP_ER_ZLIB`).

use crate::deflate::{
    Deflate, ErrorCode as ZErrorCode, Flush, InBuffer, Inflate, Inflate9, OutBuffer, Status,
};

use crate::zip::error::{Error, ErrorCode};
use crate::zip::zipint::TORRENTZIP_COMPRESSION_FLAGS;

/// `TORRENTZIP_MEM_LEVEL`.
const TORRENTZIP_MEM_LEVEL: i32 = 8;
/// zlib's `MAX_MEM_LEVEL`.
const MAX_MEM_LEVEL: i32 = 9;
/// zlib's `Z_BEST_COMPRESSION`.
const Z_BEST_COMPRESSION: i32 = 9;

/// The version needed to extract deflated data, the algorithms'
/// `version_needed`.
pub(crate) const VERSION_NEEDED: u8 = 20;

/// The most a deflate stream of `uncompressed_size` bytes can take:
/// `maximum_compressed_size`.
pub(crate) fn maximum_compressed_size(uncompressed_size: u64) -> u64 {
    // max deflate size increase: size + ceil(size/16k)*5+6
    uncompressed_size.saturating_add(uncompressed_size.div_ceil(16384) * 5 + 6)
}

/// `struct ctx`, for compressing: the level, the stream, and the input it
/// holds, a range of the compression source's buffer.
pub(crate) struct DeflateCompress {
    level: i32,
    mem_level: i32,
    end_of_input: bool,
    zstr: Option<Deflate>,
    next_in: usize,
    avail_in: usize,
}

impl DeflateCompress {
    /// `compress_allocate`: level 1 to 9 from `compression_flags`, else 9,
    /// and torrentzip's `memLevel` for its flags.
    pub(crate) fn new(compression_flags: u32) -> DeflateCompress {
        DeflateCompress {
            level: if (1..=9).contains(&compression_flags) {
                compression_flags as i32
            } else {
                Z_BEST_COMPRESSION
            },
            mem_level: if compression_flags == TORRENTZIP_COMPRESSION_FLAGS {
                TORRENTZIP_MEM_LEVEL
            } else {
                MAX_MEM_LEVEL
            },
            end_of_input: false,
            zstr: None,
            next_in: 0,
            avail_in: 0,
        }
    }

    /// `general_purpose_bit_flags`: the deflate option bits for the level.
    pub(crate) fn general_purpose_bit_flags(&self) -> u16 {
        if self.level < 3 {
            2 << 1
        } else if self.level > 7 {
            1 << 1
        } else {
            0
        }
    }

    /// `start`: a raw deflate stream (`windowBits` -15).
    pub(crate) fn start(&mut self) -> Result<(), Error> {
        self.next_in = 0;
        self.avail_in = 0;
        // negative value to tell zlib not to write a header
        match Deflate::new(self.level, -15, self.mem_level, 0) {
            Ok(zstr) => {
                self.zstr = Some(zstr);
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorCode::Zlib, e.code().number())),
        }
    }

    /// `end`: `deflateEnd`, which fails if the stream was not finished.
    pub(crate) fn end(&mut self) -> Result<(), Error> {
        match self.zstr.take().map(Deflate::end) {
            Some(Err(e)) => Err(Error::new(ErrorCode::Zlib, e.code().number())),
            _ => Ok(()),
        }
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

    /// `process`: deflates from `buffer` into `data`, with `Z_FINISH` once
    /// the input ended, returning the status and the bytes written.
    pub(crate) fn process(&mut self, buffer: &[u8], data: &mut [u8]) -> (CompressionStatus, usize) {
        let Some(zstr) = self.zstr.as_mut() else {
            return (
                CompressionStatus::Error(Error::new(ErrorCode::Internal, 0)),
                0,
            );
        };
        let avail_out = data.len().min(u32::MAX as usize);
        let mut output = OutBuffer::new(&mut data[..avail_out]);
        let mut input = InBuffer::new(&buffer[self.next_in..self.next_in + self.avail_in]);
        let flush = if self.end_of_input {
            Flush::Finish
        } else {
            Flush::NoFlush
        };
        let ret = zstr.deflate(&mut output, &mut input, flush);
        self.next_in += input.pos;
        self.avail_in -= input.pos;
        let length = output.pos;

        let status = match ret {
            Ok(Status::Ok) => CompressionStatus::Ok,
            Ok(Status::StreamEnd) => CompressionStatus::End,
            Err(e) if e.code() == ZErrorCode::Buf && self.avail_in == 0 => {
                CompressionStatus::NeedData
            }
            Err(e) => CompressionStatus::Error(Error::new(ErrorCode::Zlib, e.code().number())),
            Ok(Status::NeedDict) => CompressionStatus::Error(Error::new(ErrorCode::Zlib, 2)),
        };
        (status, length)
    }
}

/// `zip_compression_status_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompressionStatus {
    Ok,
    End,
    /// with the error the algorithm sets
    Error(Error),
    NeedData,
}

/// The stream being decoded: deflate, or Deflate64.
enum Stream {
    Deflate(Inflate),
    Deflate64(Box<Inflate9>),
}

/// `struct ctx`, for decompressing: the stream, and the input it holds,
/// a range of the compression source's buffer.
pub(crate) struct DeflateDecompress {
    deflate64: bool,
    zstr: Option<Stream>,
    end_of_input: bool,
    /// `next_in` and `avail_in`, as positions in the buffer given to
    /// `process`.
    next_in: usize,
    avail_in: usize,
}

impl DeflateDecompress {
    /// `decompress_allocate`, for Deflate64 if `deflate64`.
    pub(crate) fn new(deflate64: bool) -> DeflateDecompress {
        DeflateDecompress {
            deflate64,
            zstr: None,
            end_of_input: false,
            next_in: 0,
            avail_in: 0,
        }
    }

    /// `general_purpose_bit_flags`: none, when decompressing.
    pub(crate) fn general_purpose_bit_flags(&self) -> u16 {
        0
    }

    /// `start`: a raw inflate stream (`windowBits` -15).
    pub(crate) fn start(&mut self) -> Result<(), Error> {
        self.next_in = 0;
        self.avail_in = 0;
        if self.deflate64 {
            self.zstr = Some(Stream::Deflate64(Box::default()));
            return Ok(());
        }
        match Inflate::new(-15) {
            Ok(zstr) => {
                self.zstr = Some(Stream::Deflate(zstr));
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorCode::Zlib, e.code().number())),
        }
    }

    /// `end`.
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

    /// `process`: inflates from `buffer` into `data` with `Z_SYNC_FLUSH`,
    /// returning the status and the bytes written.
    pub(crate) fn process(&mut self, buffer: &[u8], data: &mut [u8]) -> (CompressionStatus, usize) {
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
            Stream::Deflate(zstr) => zstr.inflate(&mut output, &mut input, Flush::SyncFlush),
            Stream::Deflate64(zstr) => zstr.inflate(&mut output, &mut input),
        };
        self.next_in += input.pos;
        self.avail_in -= input.pos;
        let length = output.pos;

        let status = match ret {
            Ok(Status::Ok) => CompressionStatus::Ok,
            Ok(Status::StreamEnd) => CompressionStatus::End,
            Err(e) if e.code() == ZErrorCode::Buf && self.avail_in == 0 => {
                CompressionStatus::NeedData
            }
            Err(e) => CompressionStatus::Error(Error::new(ErrorCode::Zlib, e.code().number())),
            // A raw stream never asks for a dictionary.
            Ok(Status::NeedDict) => CompressionStatus::Error(Error::new(ErrorCode::Zlib, 2)),
        };
        (status, length)
    }
}
