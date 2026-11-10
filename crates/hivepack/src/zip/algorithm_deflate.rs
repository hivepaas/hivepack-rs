//! Deflate through hivepack::deflate, whose inflate and deflate give zlib's
//! results and output: port of `zip_algorithm_deflate.c`.
//!
//! Differs from libzip, when asked (`Archive::set_deflate_in_blocks`): new
//! data is deflated in blocks, as pigz cuts them, each compressed in a
//! thread ([`DeflateMt`], raw), one deflate stream that any reader reads.
//!
//! Differs from libzip, when asked (`Archive::set_deflate_library`): new
//! data is deflated by libdeflate's compressor, at levels 1 to 12, always
//! in blocks compressed alone ([`DeflateMt`] with [`Library::Libdeflate`]),
//! of 1, 2 or 4 MiB as the data's size says ([`libdeflate_block_size`]),
//! in the threads of the blocks if they are on, else in the thread that
//! compresses the entry: the stream is the same either way.
//!
//! Differs from libzip, which has no Deflate64: the same algorithm decodes
//! Deflate64 (method 9) with `Inflate9`, which follows zlib's
//! `contrib/infback9`, and reports its errors as zlib's (`ZIP_ER_ZLIB`).

use crate::Threads;
use crate::deflate::{
    Compressor, Deflate, DeflateMt, ErrorCode as ZErrorCode, Flush, InBuffer, Inflate, Inflate9,
    Library, MtOptions, OutBuffer, Status, libdeflate_block_size,
};

use crate::zip::error::{Error, ErrorCode};
use crate::zip::zipint::TORRENTZIP_COMPRESSION_FLAGS;

/// `TORRENTZIP_MEM_LEVEL`.
const TORRENTZIP_MEM_LEVEL: i32 = 8;
/// zlib's `MAX_MEM_LEVEL`.
const MAX_MEM_LEVEL: i32 = 9;
/// zlib's `Z_BEST_COMPRESSION`.
const Z_BEST_COMPRESSION: i32 = 9;
/// libdeflate's best level.
const LIBDEFLATE_BEST_COMPRESSION: u32 = 12;

/// The version needed to extract deflated data, the algorithms'
/// `version_needed`.
pub(crate) const VERSION_NEEDED: u8 = 20;

/// The most a deflate stream of `uncompressed_size` bytes can take:
/// `maximum_compressed_size`. Differs from libzip: with libdeflate, its
/// bound for its blocks.
pub(crate) fn maximum_compressed_size(uncompressed_size: u64, library: Library) -> u64 {
    match library {
        // max deflate size increase: size + ceil(size/16k)*5+6
        Library::Zlib => {
            uncompressed_size.saturating_add(uncompressed_size.div_ceil(16384) * 5 + 6)
        }
        Library::Libdeflate => libdeflate_maximum_compressed_size(uncompressed_size),
    }
}

/// The most libdeflate's blocks can take for `size` bytes, cut as the size
/// says: each block's bound, as a part
/// (`Compressor::deflate_compress_part_bound`), 5 bytes for each 5,000
/// bytes and for its end, then the marker's 5.
fn libdeflate_maximum_compressed_size(size: u64) -> u64 {
    let block_size = libdeflate_block_size(Some(size));
    let block = block_size as u64;
    let full = size / block;
    let rest = (size % block) as usize;
    let mut most = full.saturating_mul(Compressor::part_bound(block_size) as u64);
    if rest > 0 || full == 0 {
        most = most.saturating_add(Compressor::part_bound(rest) as u64);
    }
    most
}

/// How new data is deflated, as the archive says: in blocks, in which
/// threads, and whose compressor. Not in libzip.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Deflating {
    /// In blocks, in these threads (`Archive::set_deflate_in_blocks`).
    pub(crate) blocks: Option<Threads>,
    /// Whose compressor (`Archive::set_deflate_library`).
    pub(crate) library: Library,
    /// libdeflate's blocks, as the data's size says
    /// ([`libdeflate_block_size`]); 0 for 1 MiB.
    pub(crate) block_size: usize,
}

impl Deflating {
    /// How data of `size` bytes, or of a size not known, is deflated: in
    /// libdeflate's blocks for that size.
    pub(crate) fn with_size(self, size: Option<u64>) -> Deflating {
        Deflating {
            block_size: libdeflate_block_size(size),
            ..self
        }
    }

    /// libdeflate's blocks, if libdeflate deflates; else 0.
    pub(crate) fn libdeflate_block_size(&self) -> usize {
        match self.library {
            Library::Zlib => 0,
            Library::Libdeflate => self.block_size,
        }
    }

    /// How data at `compression_flags` is deflated: as libzip deflates
    /// torrentzip's, one zlib stream, whatever the archive says.
    pub(crate) fn for_flags(self, compression_flags: u32) -> Deflating {
        if compression_flags == TORRENTZIP_COMPRESSION_FLAGS {
            return Deflating::default();
        }
        self
    }
}

/// What deflates: zlib's one stream, or blocks in threads.
enum Deflater {
    One(Deflate),
    Blocks(Box<DeflateMt>),
}

/// `struct ctx`, for compressing: the level, the stream, and the input it
/// holds, a range of the compression source's buffer. Not in libzip:
/// `deflating`, the threads it deflates in blocks in, if it does, and
/// whose compressor.
pub(crate) struct DeflateCompress {
    level: i32,
    mem_level: i32,
    deflating: Deflating,
    end_of_input: bool,
    zstr: Option<Deflater>,
    next_in: usize,
    avail_in: usize,
}

impl DeflateCompress {
    /// `compress_allocate`: level 1 to 9 from `compression_flags`, else 9,
    /// and torrentzip's `memLevel` for its flags. With
    /// `deflating.blocks`, in blocks in those threads, but for torrentzip,
    /// whose stream is zlib's. With libdeflate (`deflating.library`), but
    /// for torrentzip, level 1 to 12 from `compression_flags`, else 9 as
    /// for zlib, always in blocks.
    pub(crate) fn new(compression_flags: u32, deflating: Deflating) -> DeflateCompress {
        let deflating = deflating.for_flags(compression_flags);
        let most = match deflating.library {
            Library::Zlib => Z_BEST_COMPRESSION as u32,
            Library::Libdeflate => LIBDEFLATE_BEST_COMPRESSION,
        };
        DeflateCompress {
            deflating,
            level: if (1..=most).contains(&compression_flags) {
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
    /// libdeflate's levels 10 to 12 are maximum compression, as 8 and 9;
    /// APPNOTE has nothing above.
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
        let Deflating {
            blocks, library, ..
        } = self.deflating;
        let made = if blocks.is_some() || library == Library::Libdeflate {
            // libdeflate's blocks are in this thread if not in the blocks'.
            DeflateMt::new(&MtOptions {
                level: self.level,
                raw: true,
                threads: blocks.unwrap_or(Threads::One),
                library,
                block_size: self.deflating.libdeflate_block_size(),
                ..MtOptions::default()
            })
            .map(|blocks| Deflater::Blocks(Box::new(blocks)))
        } else {
            // negative value to tell zlib not to write a header
            Deflate::new(self.level, -15, self.mem_level, 0).map(Deflater::One)
        };
        match made {
            Ok(zstr) => {
                self.zstr = Some(zstr);
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorCode::Zlib, e.code().number())),
        }
    }

    /// `end`: `deflateEnd`, which fails if the stream was not finished.
    /// Blocks end with nothing to fail.
    pub(crate) fn end(&mut self) -> Result<(), Error> {
        match self.zstr.take() {
            Some(Deflater::One(zstr)) => zstr
                .end()
                .map_err(|e| Error::new(ErrorCode::Zlib, e.code().number())),
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
        let ret = match zstr {
            Deflater::One(zstr) => zstr.deflate(&mut output, &mut input, flush),
            Deflater::Blocks(blocks) => {
                // It returns once the input is read or the output full,
                // where zlib says so with `Z_BUF_ERROR` on the next call.
                let ret = blocks.deflate(&mut output, &mut input, flush);
                let read = input.pos == input.src.len();
                match ret {
                    Ok(Status::Ok) if read && !self.end_of_input && output.pos < avail_out => {
                        Err(crate::deflate::Error::new(ZErrorCode::Buf, None))
                    }
                    ret => ret,
                }
            }
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// `data` through the compressing algorithm, as the compressing layer
    /// gives it, in pieces.
    fn through(compress: &mut DeflateCompress, data: &[u8]) -> Vec<u8> {
        compress.start().unwrap();
        let mut out = Vec::new();
        let mut buf = vec![0; 1 << 16];
        for piece in data.chunks(1 << 16) {
            compress.input(piece.len()).unwrap();
            loop {
                let (status, n) = compress.process(piece, &mut buf);
                out.extend_from_slice(&buf[..n]);
                match status {
                    CompressionStatus::Ok => {}
                    CompressionStatus::NeedData => break,
                    _ => panic!("{status:?}"),
                }
            }
        }
        assert!(!compress.end_of_input());
        loop {
            // Nothing left of the last piece.
            let (status, n) = compress.process(data, &mut buf);
            out.extend_from_slice(&buf[..n]);
            match status {
                CompressionStatus::Ok => {}
                CompressionStatus::End => break,
                _ => panic!("{status:?}"),
            }
        }
        compress.end().unwrap();
        out
    }

    /// libdeflate's blocks are cut as the size the data was said to have
    /// says, whatever it turns out to be, and whatever the threads.
    #[test]
    fn libdeflate_blocks_by_the_size_said() {
        let data: Vec<u8> = (0..9u32 << 20)
            .map(|i| b"abcdefgh  \n"[(i.wrapping_mul(2_654_435_761) >> 29) as usize])
            .collect();
        let want = |block_size: usize| {
            let mut mt = DeflateMt::new(&MtOptions {
                level: 6,
                raw: true,
                library: Library::Libdeflate,
                block_size,
                ..MtOptions::default()
            })
            .unwrap();
            let mut out = vec![0; data.len() + (1 << 20)];
            let mut output = OutBuffer::new(&mut out);
            let status = mt.deflate(&mut output, &mut InBuffer::new(&data), Flush::Finish);
            assert_eq!(status, Ok(Status::StreamEnd));
            let n = output.pos;
            out.truncate(n);
            out
        };
        let (one, two, four) = (want(1 << 20), want(2 << 20), want(4 << 20));
        assert!(one != two && two != four);
        for blocks in [None, Some(Threads::One), Some(Threads::of(4))] {
            for (size, stream) in [
                (None, &one),
                (Some(9 << 20), &one),
                (Some((64 << 20) - 1), &one),
                (Some(64 << 20), &two),
                (Some((128 << 20) - 1), &two),
                (Some(128 << 20), &four),
            ] {
                let deflating = Deflating {
                    blocks,
                    library: Library::Libdeflate,
                    block_size: 0,
                }
                .with_size(size);
                let mut compress = DeflateCompress::new(6, deflating);
                assert!(
                    through(&mut compress, &data) == *stream,
                    "{size:?}, {blocks:?}"
                );
            }
        }
    }

    /// libdeflate's blocks of random bytes, stored, at every level, fit the
    /// most libdeflate's bound says.
    #[test]
    fn libdeflate_fits_its_maximum() {
        const MIB: usize = 1 << 20;
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let noise: Vec<u8> = (0..3 * MIB + 7)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        for size in [0, 1, 4999, 5001, MIB - 1, MIB, MIB + 1, 3 * MIB + 7] {
            let most = maximum_compressed_size(size as u64, Library::Libdeflate);
            for level in [0, 1, 6, 12] {
                let mut mt = DeflateMt::new(&MtOptions {
                    level,
                    raw: true,
                    library: Library::Libdeflate,
                    ..MtOptions::default()
                })
                .unwrap();
                let mut out = vec![0; most as usize + 64];
                let mut output = OutBuffer::new(&mut out);
                let mut input = InBuffer::new(&noise[..size]);
                let status = mt.deflate(&mut output, &mut input, Flush::Finish);
                assert_eq!(status, Ok(Status::StreamEnd));
                assert!(output.pos as u64 <= most, "{size} bytes, level {level}");
            }
        }
    }
}
