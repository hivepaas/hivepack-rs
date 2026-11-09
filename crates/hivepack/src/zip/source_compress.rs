//! The decompressing and compressing layers: port of
//! `zip_source_compress.c`, with deflate, bzip2, LZMA, XZ and Zstandard for algorithms,
//! and PPMd and Deflate64 to decompress, which libzip does not read.

use crate::Threads;
use crate::zip::algorithm_bzip2::{self, Bzip2};
use crate::zip::algorithm_deflate::{self, CompressionStatus, DeflateCompress, DeflateDecompress};
use crate::zip::algorithm_ppmd::Ppmd;
use crate::zip::algorithm_xz::{self, Xz};
use crate::zip::algorithm_zstd::{self, Zstd};
use crate::zip::dirent::{CM_DEFAULT, cm_actual};
use crate::zip::error::{Detail, Error, ErrorCode, Result};
use crate::zip::source_data::{
    FileAttributes, GENERAL_PURPOSE_BIT_FLAGS_ALLOWED_MASK, file_attributes,
};
use crate::zip::zip::{Stat, cm, stat};

/// `BUFSIZE`.
const BUFSIZE: usize = 8192;

/// The most compressed data a [`Decompress`] reads at once, where libzip
/// reads [`BUFSIZE`]: each piece costs a call of the decompressor, which
/// decodes the end of its input the slow way and, for deflate, copies what
/// it decoded into its window. A ZIP entry of 207 MB, deflated, extracts in
/// 0.35 s read in pieces of 128 KiB where it took 0.40 s in pieces of 8 KiB.
const MOST_READ: usize = 128 << 10;

/// What a [`Decompress`] reads at once from data of `compressed` bytes, if
/// known: all of it, from [`BUFSIZE`] up to [`MOST_READ`].
fn piece(compressed: Option<u64>) -> usize {
    compressed.map_or(BUFSIZE, |n| {
        usize::try_from(n)
            .unwrap_or(usize::MAX)
            .clamp(BUFSIZE, MOST_READ)
    })
}

/// `struct context`, for decompressing.
pub(crate) struct Decompress {
    pub(crate) error: Error,
    end_of_input: bool,
    end_of_stream: bool,
    check_consistency: bool,
    size: u64,
    first_read: i64,
    buffer: Box<[u8]>,
    algorithm: DecompressAlgorithm,
}

/// A decompressing algorithm: the `zip_compression_algorithm_t` of
/// `implementations[]` for decompressing.
pub(crate) enum DecompressAlgorithm {
    Deflate(DeflateDecompress),
    Bzip2(Bzip2),
    Xz(Xz),
    Zstd(Zstd),
    /// Not in libzip.
    Ppmd(Ppmd),
}

/// A compressing algorithm, the same for compressing.
pub(crate) enum CompressAlgorithm {
    Deflate(DeflateCompress),
    Bzip2(Bzip2),
    Xz(Xz),
    Zstd(Zstd),
}

/// The algorithms' functions, the same for both directions, with the
/// variants of one direction only after the name.
macro_rules! algorithm_functions {
    ($name:ident $(, $only:ident)*) => {
        impl $name {
            fn version_needed(&self) -> u8 {
                match self {
                    Self::Deflate(_) => algorithm_deflate::VERSION_NEEDED,
                    Self::Bzip2(_) => algorithm_bzip2::VERSION_NEEDED,
                    Self::Xz(_) => algorithm_xz::VERSION_NEEDED,
                    Self::Zstd(_) => algorithm_zstd::VERSION_NEEDED,
                    $(Self::$only(a) => a.version_needed(),)*
                }
            }

            fn general_purpose_bit_flags(&self) -> u16 {
                match self {
                    Self::Deflate(a) => a.general_purpose_bit_flags(),
                    Self::Bzip2(a) => a.general_purpose_bit_flags(),
                    Self::Xz(a) => a.general_purpose_bit_flags(),
                    Self::Zstd(a) => a.general_purpose_bit_flags(),
                    $(Self::$only(a) => a.general_purpose_bit_flags(),)*
                }
            }

            fn start(&mut self, st: &Stat<'_>, attributes: &FileAttributes) -> Result<()> {
                match self {
                    Self::Deflate(a) => a.start(),
                    Self::Bzip2(a) => a.start(),
                    Self::Xz(a) => a.start(st, attributes),
                    Self::Zstd(a) => a.start(),
                    $(Self::$only(a) => a.start(),)*
                }
            }

            fn end(&mut self) -> Result<()> {
                match self {
                    Self::Deflate(a) => a.end(),
                    Self::Bzip2(a) => a.end(),
                    Self::Xz(a) => a.end(),
                    Self::Zstd(a) => a.end(),
                    $(Self::$only(a) => a.end(),)*
                }
            }

            fn input(&mut self, buffer: &[u8], length: usize) -> Result<()> {
                match self {
                    Self::Deflate(a) => a.input(length),
                    Self::Bzip2(a) => a.input(length),
                    Self::Xz(a) => a.input(buffer, length),
                    Self::Zstd(a) => a.input(length),
                    $(Self::$only(a) => a.input(buffer, length),)*
                }
            }

            fn end_of_input(&mut self) -> bool {
                match self {
                    Self::Deflate(a) => a.end_of_input(),
                    Self::Bzip2(a) => a.end_of_input(),
                    Self::Xz(a) => a.end_of_input(),
                    Self::Zstd(a) => a.end_of_input(),
                    $(Self::$only(a) => a.end_of_input(),)*
                }
            }

            fn process(&mut self, buffer: &[u8], data: &mut [u8]) -> (CompressionStatus, usize) {
                match self {
                    Self::Deflate(a) => a.process(buffer, data),
                    Self::Bzip2(a) => a.process(buffer, data),
                    Self::Xz(a) => a.process(buffer, data),
                    Self::Zstd(a) => a.process(buffer, data),
                    $(Self::$only(a) => a.process(buffer, data),)*
                }
            }
        }
    };
}
algorithm_functions!(DecompressAlgorithm, Ppmd);
algorithm_functions!(CompressAlgorithm);

impl DecompressAlgorithm {
    /// Not in libzip: whether input the stream did not read is left, once
    /// both have ended. libzip's algorithms end without waiting for the end
    /// of their input, and are asked what they hold back of it then
    /// (`end_of_input`); PPMd decodes only with 1 KiB of input ahead or the
    /// input's end, so that its input has ended first.
    fn input_left(&self) -> bool {
        match self {
            Self::Ppmd(a) => a.input_left(),
            _ => false,
        }
    }
}

/// The decompressing algorithm for `method`, if libzip has one: port of
/// `_zip_get_compression_algorithm`, for decompressing. Differs from
/// libzip, which has no Deflate64 and no PPMd, read here.
pub(crate) fn get_compression_algorithm(method: u16) -> Option<DecompressAlgorithm> {
    match method {
        cm::DEFLATE => Some(DecompressAlgorithm::Deflate(DeflateDecompress::new(false))),
        cm::DEFLATE64 => Some(DecompressAlgorithm::Deflate(DeflateDecompress::new(true))),
        cm::BZIP2 => Some(DecompressAlgorithm::Bzip2(Bzip2::decompressor())),
        cm::LZMA | cm::XZ => Some(DecompressAlgorithm::Xz(Xz::decompressor(method))),
        cm::ZSTD => Some(DecompressAlgorithm::Zstd(Zstd::decompressor())),
        cm::PPMD => Some(DecompressAlgorithm::Ppmd(Ppmd::decompressor())),
        _ => None,
    }
}

/// The compressing algorithm for `method` at `compression_flags`, if
/// libzip has one: `_zip_get_compression_algorithm` for compressing, then
/// its `compress_allocate`.
fn get_compressing_algorithm(
    method: u16,
    compression_flags: u32,
    blocks: Option<Threads>,
) -> Option<CompressAlgorithm> {
    match method {
        cm::DEFLATE => Some(CompressAlgorithm::Deflate(DeflateCompress::new(
            compression_flags,
            blocks,
        ))),
        cm::BZIP2 => Some(CompressAlgorithm::Bzip2(Bzip2::compressor(
            compression_flags,
        ))),
        cm::LZMA | cm::XZ => Some(CompressAlgorithm::Xz(Xz::compressor(
            method,
            compression_flags,
        ))),
        cm::ZSTD => Some(CompressAlgorithm::Zstd(Zstd::compressor(compression_flags))),
        _ => None,
    }
}

/// The most the compressed data of `size` bytes can take with `method`:
/// its algorithm's `maximum_compressed_size`, or `None` without one.
pub(crate) fn maximum_compressed_size(method: u16, size: u64) -> Option<u64> {
    match method {
        cm::DEFLATE => Some(algorithm_deflate::maximum_compressed_size(size)),
        cm::BZIP2 => Some(algorithm_bzip2::maximum_compressed_size(size)),
        cm::LZMA | cm::XZ => Some(algorithm_xz::maximum_compressed_size(size)),
        cm::ZSTD => Some(algorithm_zstd::maximum_compressed_size(size)),
        _ => None,
    }
}

/// Whether `method` can be used, to compress or to decompress: port of
/// `zip_compression_method_supported`.
pub(crate) fn compression_method_supported(method: i32, compress: bool) -> bool {
    if method == i32::from(cm::STORE) {
        return true;
    }
    let real_method = cm_actual(method);
    if compress {
        get_compressing_algorithm(real_method, 0, None).is_some()
    } else {
        get_compression_algorithm(real_method).is_some()
    }
}

/// `ZIP_SOURCE_GET_FILE_ATTRIBUTES` of a compression layer: the version
/// needed for the algorithm, and the general purpose bits it sets, all of
/// the allowed ones decided here.
fn compression_attributes(version_needed: u8, general_purpose_bit_flags: u16) -> FileAttributes {
    FileAttributes {
        valid: file_attributes::VERSION_NEEDED | file_attributes::GENERAL_PURPOSE_BIT_FLAGS,
        version_needed,
        general_purpose_bit_mask: GENERAL_PURPOSE_BIT_FLAGS_ALLOWED_MASK,
        general_purpose_bit_flags,
        ..FileAttributes::default()
    }
}

impl Decompress {
    /// `ZIP_SOURCE_GET_FILE_ATTRIBUTES`: the algorithm's general purpose
    /// bits, which no decompressing algorithm sets.
    pub(crate) fn file_attributes(&self) -> FileAttributes {
        compression_attributes(
            self.algorithm.version_needed(),
            self.algorithm.general_purpose_bit_flags(),
        )
    }

    /// Port of `context_new` for decompressing; `None` if `method` has no
    /// algorithm (`compression_source_new` fails with
    /// `ZIP_ER_COMPNOTSUPP`). `compressed` is the size of the data, if known:
    /// it is read in pieces of up to [`MOST_READ`] rather than [`BUFSIZE`].
    pub(crate) fn new(
        method: u16,
        check_consistency: bool,
        compressed: Option<u64>,
    ) -> Result<Decompress> {
        let Some(algorithm) = get_compression_algorithm(method) else {
            return Err(Error::new(ErrorCode::CompNotSupp, 0));
        };
        Ok(Decompress {
            error: Error::OK,
            end_of_input: false,
            end_of_stream: false,
            check_consistency,
            size: 0,
            first_read: -1,
            buffer: vec![0; piece(compressed)].into_boxed_slice(),
            algorithm,
        })
    }

    /// `ZIP_SOURCE_OPEN`, with the lower source's stat and attributes.
    pub(crate) fn open(&mut self, st: &Stat<'_>, attributes: &FileAttributes) -> Result<()> {
        self.size = 0;
        self.end_of_input = false;
        self.end_of_stream = false;
        self.first_read = -1;
        if let Err(e) = self.algorithm.start(st, attributes) {
            self.error = e;
            return Err(e);
        }
        Ok(())
    }

    /// `ZIP_SOURCE_CLOSE`.
    pub(crate) fn close(&mut self) -> Result<()> {
        if let Err(e) = self.algorithm.end() {
            self.error = e;
            return Err(e);
        }
        Ok(())
    }

    /// `ZIP_SOURCE_STAT`, on the lower source's stat: the data is stored
    /// now, of the size decompressed once the stream ended.
    pub(crate) fn stat(&self, st: &mut Stat<'_>) {
        st.comp_method = cm::STORE;
        st.valid |= stat::COMP_METHOD;
        st.valid &= !stat::COMP_SIZE;
        if self.end_of_stream {
            st.size = self.size;
            st.valid |= stat::SIZE;
        }
    }

    /// `ZIP_SOURCE_READ`: port of `compress_read`, reading the compressed
    /// data with `lower`.
    pub(crate) fn read(
        &mut self,
        data: &mut [u8],
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    ) -> Result<usize> {
        if self.error.is_set() {
            return Err(self.error);
        }
        if data.is_empty() || self.end_of_stream {
            return Ok(0);
        }

        let len = data.len();
        let mut out_offset = 0;
        let mut end = false;
        while !end && out_offset < len {
            let (ret, out_len) = self
                .algorithm
                .process(&self.buffer[..], &mut data[out_offset..]);
            if !matches!(ret, CompressionStatus::Error(_)) {
                out_offset += out_len;
            }

            match ret {
                CompressionStatus::End => {
                    self.end_of_stream = true;
                    if !self.end_of_input {
                        let n = match lower(&mut self.buffer[..1]) {
                            Ok(0) => {
                                self.end_of_input = true;
                                usize::from(self.algorithm.end_of_input())
                            }
                            Ok(n) => n,
                            Err(e) => {
                                self.error = e;
                                break;
                            }
                        };
                        if n > 0 && self.check_consistency {
                            // garbage after stream, or compression ended
                            // before all data read
                            self.error = Error::incons(Detail::CompressedDataTrailingGarbage);
                            break;
                        }
                    } else if self.check_consistency && self.algorithm.input_left() {
                        // Not in libzip, whose algorithms do not wait for
                        // the end of their input (see input_left).
                        self.error = Error::incons(Detail::CompressedDataTrailingGarbage);
                        break;
                    }

                    if self.first_read < 0 {
                        // we got end of processed stream before reading any
                        // input data
                        self.error = Error::new(ErrorCode::Internal, 0);
                        break;
                    }
                    end = true;
                }
                CompressionStatus::Ok => {}
                CompressionStatus::NeedData => {
                    if self.end_of_input {
                        // TODO in libzip: error: stream not ended, but no
                        // more input
                        end = true;
                        continue;
                    }

                    match lower(&mut self.buffer[..]) {
                        Err(e) => {
                            self.error = e;
                            end = true;
                        }
                        Ok(0) => {
                            self.end_of_input = true;
                            self.algorithm.end_of_input();
                            if self.first_read < 0 {
                                self.first_read = 0;
                            }
                        }
                        Ok(n) => {
                            if self.first_read < 0 {
                                self.first_read = n as i64;
                            }
                            if let Err(e) = self.algorithm.input(&self.buffer[..], n) {
                                self.error = e;
                            }
                        }
                    }
                }
                CompressionStatus::Error(e) => {
                    // error set by algorithm
                    self.error = if e.is_set() {
                        e
                    } else {
                        Error::new(ErrorCode::Internal, 0)
                    };
                    end = true;
                }
            }
        }

        if out_offset > 0 {
            self.size += out_offset as u64;
            return Ok(out_offset);
        }

        if self.error.is_set() {
            Err(self.error)
        } else {
            Ok(0)
        }
    }
}

/// `struct context`, for compressing.
pub(crate) struct Compress {
    pub(crate) error: Error,
    end_of_input: bool,
    end_of_stream: bool,
    /// whether the data may be stored instead, for `ZIP_CM_DEFAULT`
    can_store: bool,
    /// only valid if end_of_stream is true
    is_stored: bool,
    method: i32,
    size: u64,
    first_read: i64,
    buffer: Box<[u8; BUFSIZE]>,
    algorithm: CompressAlgorithm,
}

impl Compress {
    /// Port of `compression_source_new` and `context_new` for compressing
    /// with `method` at `compression_flags`: fails with
    /// `ZIP_ER_COMPNOTSUPP` if `method` has no algorithm. Not in libzip:
    /// with `blocks`, deflate is in blocks, in those threads.
    pub(crate) fn new(
        method: i32,
        compression_flags: u32,
        blocks: Option<Threads>,
    ) -> Result<Compress> {
        let Some(algorithm) =
            get_compressing_algorithm(cm_actual(method), compression_flags, blocks)
        else {
            return Err(Error::new(ErrorCode::CompNotSupp, 0));
        };
        Ok(Compress {
            error: Error::OK,
            end_of_input: false,
            end_of_stream: false,
            can_store: method == CM_DEFAULT,
            is_stored: false,
            method,
            size: 0,
            first_read: -1,
            buffer: Box::new([0; BUFSIZE]),
            algorithm,
        })
    }

    /// Whether the stream ended, and whether it was stored: what changes the
    /// stat and the attributes. Not in libzip.
    pub(crate) fn ended(&self) -> (bool, bool) {
        (self.end_of_stream, self.is_stored)
    }

    /// Whatever the data comes to, it is not stored instead.
    pub(crate) fn keep_compressing(&mut self) {
        self.can_store = false;
    }

    /// `ZIP_SOURCE_OPEN`, with the lower source's stat and attributes.
    pub(crate) fn open(&mut self, st: &Stat<'_>, attributes: &FileAttributes) -> Result<()> {
        self.size = 0;
        self.end_of_input = false;
        self.end_of_stream = false;
        self.is_stored = false;
        self.first_read = -1;
        if let Err(e) = self.algorithm.start(st, attributes) {
            self.error = e;
            return Err(e);
        }
        Ok(())
    }

    /// `ZIP_SOURCE_CLOSE`.
    pub(crate) fn close(&mut self) -> Result<()> {
        if let Err(e) = self.algorithm.end() {
            self.error = e;
            return Err(e);
        }
        Ok(())
    }

    /// `ZIP_SOURCE_STAT`, on the lower source's stat: the method and the
    /// compressed size once the stream ended, stored if it was.
    pub(crate) fn stat(&self, st: &mut Stat<'_>) {
        if self.end_of_stream {
            st.comp_method = if self.is_stored {
                cm::STORE
            } else {
                cm_actual(self.method)
            };
            st.comp_size = self.size;
            st.valid |= stat::COMP_SIZE | stat::COMP_METHOD;
        } else {
            st.valid &= !(stat::COMP_SIZE | stat::COMP_METHOD);
        }
    }

    /// `ZIP_SOURCE_GET_FILE_ATTRIBUTES`: the general purpose bits of the
    /// level, none if the data was stored.
    pub(crate) fn file_attributes(&self) -> FileAttributes {
        compression_attributes(
            self.algorithm.version_needed(),
            if self.is_stored {
                0
            } else {
                self.algorithm.general_purpose_bit_flags()
            },
        )
    }

    /// `ZIP_SOURCE_READ`: port of `compress_read`, reading the data to
    /// compress with `lower`. With `ZIP_CM_DEFAULT`, data read in one piece
    /// is stored if it does not compress in the same call.
    pub(crate) fn read(
        &mut self,
        data: &mut [u8],
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    ) -> Result<usize> {
        if self.error.is_set() {
            return Err(self.error);
        }
        if data.is_empty() || self.end_of_stream {
            return Ok(0);
        }

        let len = data.len();
        let mut out_offset = 0;
        let mut end = false;
        while !end && out_offset < len {
            let (ret, out_len) = self
                .algorithm
                .process(&self.buffer[..], &mut data[out_offset..]);
            if !matches!(ret, CompressionStatus::Error(_)) {
                out_offset += out_len;
            }

            match ret {
                CompressionStatus::End => {
                    self.end_of_stream = true;
                    if !self.end_of_input {
                        match lower(&mut self.buffer[..1]) {
                            Ok(0) => {
                                self.end_of_input = true;
                                self.algorithm.end_of_input();
                            }
                            Ok(_) => {}
                            Err(e) => {
                                self.error = e;
                                break;
                            }
                        }
                    }

                    if self.first_read < 0 {
                        // we got end of processed stream before reading any
                        // input data
                        self.error = Error::new(ErrorCode::Internal, 0);
                        break;
                    }
                    if self.can_store && self.first_read as u64 <= out_offset as u64 {
                        self.is_stored = true;
                        self.size = self.first_read as u64;
                        let n = self.size as usize;
                        data[..n].copy_from_slice(&self.buffer[..n]);
                        return Ok(n);
                    }
                    end = true;
                }
                CompressionStatus::Ok => {}
                CompressionStatus::NeedData => {
                    if self.end_of_input {
                        // TODO in libzip: error: stream not ended, but no
                        // more input
                        end = true;
                        continue;
                    }

                    match lower(&mut self.buffer[..]) {
                        Err(e) => {
                            self.error = e;
                            end = true;
                        }
                        Ok(0) => {
                            self.end_of_input = true;
                            self.algorithm.end_of_input();
                            if self.first_read < 0 {
                                self.first_read = 0;
                            }
                        }
                        Ok(n) => {
                            if self.first_read >= 0 {
                                // we overwrote a previously filled
                                // ctx->buffer
                                self.can_store = false;
                            } else {
                                self.first_read = n as i64;
                            }
                            if let Err(e) = self.algorithm.input(&self.buffer[..], n) {
                                self.error = e;
                            }
                        }
                    }
                }
                CompressionStatus::Error(e) => {
                    // error set by algorithm
                    self.error = if e.is_set() {
                        e
                    } else {
                        Error::new(ErrorCode::Internal, 0)
                    };
                    end = true;
                }
            }
        }

        if out_offset > 0 {
            self.can_store = false;
            self.size += out_offset as u64;
            return Ok(out_offset);
        }

        if self.error.is_set() {
            Err(self.error)
        } else {
            Ok(0)
        }
    }
}
