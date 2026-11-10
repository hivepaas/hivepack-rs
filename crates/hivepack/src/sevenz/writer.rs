//! Writing 7z archives. Nothing here is a port: the LZMA SDK's C files only
//! decode, and 7-Zip's own writer, `CPP/7zip/Archive/7z/7zOut.cpp`, is under the
//! LGPL, so none of it is read. This follows the format as `DOC/7zFormat.txt` and
//! `DOC/Methods.txt` describe it, and is checked from the outside, against `7zz`
//! and the SDK's decoder.
//!
//! An archive is a signature header of 32 bytes, the packed streams of its folders
//! one after another, and at the end the header that describes them. So files can
//! be written as they come, of sizes not known beforehand; the signature header,
//! which says where the end is, is written last, which takes `Seek`. Until then it
//! is zeros, and what is cut short is no archive.
//!
//! LZMA2 can be cut in blocks ([`WriteOptions::lzma2_blocks`]), as 7-Zip's
//! encoder does in threads: each block is compressed as a stream of its own,
//! whose first chunk resets the dictionary, and the streams, each without its
//! end but the last, make one, which any decoder of LZMA2 reads. Threads
//! compress the blocks apart, and decoders can decompress them apart: see
//! `docs/7z.md`.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use crate::bzip2::{
    Action as BzAction, Compress, InBuffer as BzIn, OutBuffer as BzOut, Status as BzStatus,
};
use crate::deflate::{
    Deflate, ErrorCode as ZErrorCode, Flush, InBuffer as ZIn, OutBuffer as ZOut, Status as ZStatus,
};
use crate::xz::{
    Action as XzAction, DELTA_DIST_MAX, DELTA_DIST_MIN, DICT_SIZE_MIN, FILTER_ARM, FILTER_ARM64,
    FILTER_ARMTHUMB, FILTER_IA64, FILTER_POWERPC, FILTER_RISCV, FILTER_SPARC, FILTER_X86,
    Filter as XzFilter, InBuffer as XzIn, LzmaOptions, OutBuffer as XzOut, Status as XzStatus,
    Stream,
};

use crate::sevenz::aes7z::{AesEncoder, K_AES_ID, MAX_KEY_CYCLES};
use crate::sevenz::arc_in::SIGNATURE;
use crate::sevenz::error::{Error, Result};
use crate::sevenz::{Archive, Entry, Walk, crc};
use crate::threads::Threads;
use crate::workers::Workers;

/// How much a compressor gives at a time.
const OUT_BUF: usize = 1 << 16;

/// The header's property numbers, `NID` in `DOC/7zFormat.txt`.
mod nid {
    pub(super) const END: u8 = 0x00;
    pub(super) const HEADER: u8 = 0x01;
    pub(super) const MAIN_STREAMS_INFO: u8 = 0x04;
    pub(super) const FILES_INFO: u8 = 0x05;
    pub(super) const PACK_INFO: u8 = 0x06;
    pub(super) const UNPACK_INFO: u8 = 0x07;
    pub(super) const SUBSTREAMS_INFO: u8 = 0x08;
    pub(super) const SIZE: u8 = 0x09;
    pub(super) const CRC: u8 = 0x0A;
    pub(super) const FOLDER: u8 = 0x0B;
    pub(super) const CODERS_UNPACK_SIZE: u8 = 0x0C;
    pub(super) const NUM_UNPACK_STREAM: u8 = 0x0D;
    pub(super) const EMPTY_STREAM: u8 = 0x0E;
    pub(super) const EMPTY_FILE: u8 = 0x0F;
    pub(super) const NAME: u8 = 0x11;
    pub(super) const CTIME: u8 = 0x12;
    pub(super) const MTIME: u8 = 0x14;
    pub(super) const WIN_ATTRIBUTES: u8 = 0x15;
    pub(super) const ENCODED_HEADER: u8 = 0x17;
}

/// How a folder's data is compressed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Method {
    /// Stored as it is.
    Copy,
    /// LZMA, by `hivepack::xz`, of an `xz` preset: 0 to 9, with
    /// `hivepack::xz::PRESET_EXTREME` if wanted. Its stream ends in a marker, as
    /// its size is not known when it starts, which every decoder of 7z takes.
    Lzma { preset: u32 },
    /// LZMA2, by `hivepack::xz`, of an `xz` preset. Data that does not compress
    /// grows by little, where it does with LZMA.
    Lzma2 { preset: u32 },
    /// Deflate, by `hivepack::deflate`, of a level from 1 to 9.
    Deflate { level: i32 },
    /// BZip2, by `hivepack::bzip2`, with blocks of a level from 1 to 9 hundred
    /// KiB.
    BZip2 { level: i32 },
}

/// What is run over the data before it is compressed, for LZMA and LZMA2: the
/// branch converters for machine code, or the delta filter for samples of a
/// fixed size.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Filter {
    None,
    /// `BCJ`.
    X86,
    Arm,
    ArmThumb,
    Arm64,
    PowerPc,
    Sparc,
    Ia64,
    RiscV,
    /// The distance, from 1 to 256 bytes.
    Delta(u32),
}

/// Whether LZMA2's data is cut in blocks, each of which resets the dictionary,
/// so that threads can compress and decompress them apart. A block is a
/// number of bytes of a folder's data, whatever files they are of: where
/// blocks end depends on this alone, never on the threads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Lzma2Blocks {
    /// A folder is one stream, as before: the default.
    #[default]
    None,
    /// Blocks of 4 times the dictionary, from 1 MiB to 256 MiB, as 7-Zip
    /// makes them: 32 MiB for the presets 6 to 9, of 8 MiB.
    Auto,
    /// Blocks of this many bytes, from 4 KiB to 1 GiB. The dictionary is no
    /// larger than a block, which needs no more.
    Size(u64),
}

/// The fewest bytes [`Lzma2Blocks::Size`] takes.
const BLOCK_MIN: u64 = 1 << 12;
/// The most.
const BLOCK_MAX: u64 = 1 << 30;

impl Lzma2Blocks {
    /// The size of a block, for a dictionary of `dict` bytes; none for one
    /// stream.
    fn size(self, dict: u32) -> Result<Option<u64>> {
        const MIB: u64 = 1 << 20;
        Ok(Some(match self {
            Lzma2Blocks::None => return Ok(None),
            // 7-Zip's, as its `Lzma2Enc.c` makes it, rounded up to MiB.
            Lzma2Blocks::Auto => (u64::from(dict) * 4)
                .clamp(MIB, 256 * MIB)
                .max(u64::from(dict))
                .div_ceil(MIB)
                .saturating_mul(MIB),
            Lzma2Blocks::Size(size) if (BLOCK_MIN..=BLOCK_MAX).contains(&size) => size,
            Lzma2Blocks::Size(_) => return Err(Error::Param),
        }))
    }
}

/// A filter as liblzma has it, and its ID and properties as 7z has them.
type FilterCoder = (XzFilter, &'static [u8], Vec<u8>);

impl Filter {
    /// The filter as liblzma has it, and as 7z does: its ID, and properties.
    fn coder(self) -> Result<Option<FilterCoder>> {
        let bcj =
            |id, seven_zip: &'static [u8]| Ok(Some((XzFilter::bcj(id, 0), seven_zip, Vec::new())));
        match self {
            Filter::None => Ok(None),
            Filter::X86 => bcj(FILTER_X86, &[0x03, 0x03, 0x01, 0x03]),
            Filter::Arm => bcj(FILTER_ARM, &[0x03, 0x03, 0x05, 0x01]),
            Filter::ArmThumb => bcj(FILTER_ARMTHUMB, &[0x03, 0x03, 0x07, 0x01]),
            Filter::Arm64 => bcj(FILTER_ARM64, &[0x0A]),
            Filter::PowerPc => bcj(FILTER_POWERPC, &[0x03, 0x03, 0x02, 0x05]),
            Filter::Sparc => bcj(FILTER_SPARC, &[0x03, 0x03, 0x08, 0x05]),
            Filter::Ia64 => bcj(FILTER_IA64, &[0x03, 0x03, 0x04, 0x01]),
            Filter::RiscV => bcj(FILTER_RISCV, &[0x0B]),
            Filter::Delta(distance) => {
                if !(DELTA_DIST_MIN..=DELTA_DIST_MAX).contains(&distance) {
                    return Err(Error::Param);
                }
                Ok(Some((
                    XzFilter::delta(distance),
                    &[0x03],
                    vec![(distance - 1) as u8],
                )))
            }
        }
    }
}

/// Where random bytes come from: it fills the buffer it is given, or fails. Salts
/// and IVs take them, when encrypting.
pub use crate::crypto::RandomSource;

/// How an archive is written.
#[derive(Clone)]
pub struct WriteOptions {
    /// How the data is compressed: LZMA2 of preset 6 by default.
    pub method: Method,
    /// What runs over the data before that. None by default.
    pub filter: Filter,
    /// LZMA's and LZMA2's dictionary, in place of the preset's: from 4 KiB to
    /// 1.5 GiB, as liblzma takes it. The preset's by default. The other
    /// methods have none, and leave it be. An encoder takes about 10 times
    /// it, which [`WriteOptions::memory_usage`] counts.
    pub dictionary: Option<u32>,
    /// Files go together in a folder, a solid block, which compresses better
    /// and reads worse, until it has this many bytes; `None` gives each file a
    /// folder of its own. 4 GiB by default.
    pub solid_block_size: Option<u64>,
    /// Whether the header is compressed, if that makes it smaller. It is by
    /// default.
    pub compress_headers: bool,
    /// The password to encrypt the data with, in AES-256.
    pub password: Option<String>,
    /// Whether the header is encrypted too, names included, with the password.
    /// Not by default.
    pub encrypt_headers: bool,
    /// How many times the key is hashed, as a power of 2: 19 by default, as
    /// 7-Zip does, up to 24, the most it takes.
    pub key_cycles: u32,
    /// Where the salts and IVs come from when encrypting: by default
    /// `/dev/urandom`, and so it must be given where there is none, or the
    /// archive fails with [`Error::Fail`].
    pub random_source: Option<RandomSource>,
    /// Whether [`Method::Lzma2`] cuts a folder's data in blocks, which threads
    /// compress and decompress apart. Not by default: a folder is one stream.
    /// Blocks cost a little in size, as each starts with an empty dictionary.
    pub lzma2_blocks: Lzma2Blocks,
    /// How many threads compress LZMA2's blocks, each taking an encoder's
    /// memory (94 MiB for preset 6) and a block in and out; one, the caller's,
    /// by default. Other methods, and LZMA2 in one stream, use the caller's
    /// thread alone. What is written is the same whatever this is. Fewer
    /// are used where they would take more than
    /// [`memory_limit`](WriteOptions::memory_limit).
    pub threads: Threads,
    /// The most bytes compressing may take: the threads LZMA2's blocks are
    /// compressed in are lowered until [`WriteOptions::memory_usage`] says
    /// they fit ([`WriteOptions::threads_used`]). One thread is always
    /// allowed, even where it takes more, as liblzma allows one: so the
    /// limit never makes an archive fail, and what is written is the same
    /// whatever it is. No limit (`u64::MAX`) by default. See
    /// `docs/memory.md`.
    pub memory_limit: u64,
    /// Set from another thread, stops the writer where it waits for
    /// LZMA2's blocks, which may be long: the call fails with
    /// [`Error::Progress`], 7-Zip's error for a progress that stops it, and
    /// the archive is not finished. Looked at every 50 ms while waiting.
    /// None by default.
    pub stop: Option<Arc<AtomicBool>>,
}

/// How far a [`Writer`] has come, readable from another thread while it
/// writes: what it was given, and of that, what is compressed. With LZMA2 in
/// blocks, up to a block for each thread, and the one being filled, is
/// given and not yet compressed, so a progress counted on what is given ends
/// long before the archive does; one counted on what is compressed does not.
/// Other methods compress what they are given as they are given it.
#[derive(Clone, Debug, Default)]
pub struct WriteProgress {
    taken: Arc<AtomicU64>,
    compressed: Arc<AtomicU64>,
}

impl WriteProgress {
    /// The bytes of files' data given to the writer so far.
    pub fn taken(&self) -> u64 {
        self.taken.load(Ordering::Relaxed)
    }

    /// Of those, the bytes compressed: all of them once the archive is
    /// finished.
    pub fn compressed(&self) -> u64 {
        self.compressed.load(Ordering::Relaxed).min(self.taken())
    }
}

/// The largest dictionary liblzma's encoder takes: 1.5 GiB.
const DICT_SIZE_MAX: u32 = (1 << 30) + (1 << 29);

/// How often a writer waiting for LZMA2's blocks looks at
/// [`WriteOptions::stop`].
const STOP_EVERY: Duration = Duration::from_millis(50);

impl Default for WriteOptions {
    fn default() -> Self {
        WriteOptions {
            method: Method::Lzma2 { preset: 6 },
            filter: Filter::None,
            dictionary: None,
            solid_block_size: Some(1 << 32),
            compress_headers: true,
            password: None,
            encrypt_headers: false,
            key_cycles: 19,
            random_source: None,
            lzma2_blocks: Lzma2Blocks::None,
            threads: Threads::One,
            memory_limit: u64::MAX,
            stop: None,
        }
    }
}

impl core::fmt::Debug for WriteOptions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WriteOptions")
            .field("method", &self.method)
            .field("filter", &self.filter)
            .field("dictionary", &self.dictionary)
            .field("solid_block_size", &self.solid_block_size)
            .field("compress_headers", &self.compress_headers)
            .field("password", &self.password.as_ref().map(|_| "(hidden)"))
            .field("encrypt_headers", &self.encrypt_headers)
            .field("key_cycles", &self.key_cycles)
            .field("lzma2_blocks", &self.lzma2_blocks)
            .field("threads", &self.threads)
            .field("memory_limit", &self.memory_limit)
            .field("stop", &self.stop.is_some())
            .finish_non_exhaustive()
    }
}

/// What a writer takes besides its coders, at most: its buffer, AES, a
/// filter before LZMA2's blocks, the threads' channels. Not the list of
/// files, nor the header at the end, which grow with the files.
const WRITER_MEMORY: u64 = 1 << 20;

/// The smallest dictionary of the header's encoder: as large as the header,
/// from this to 64 MiB.
const HEADER_DICT_MIN: u32 = 1 << 16;

/// What Deflate's compressor takes at most, with a window of 32 KiB and
/// zlib's `memLevel` 8, as `make_compressor` makes it: 256 KiB of tables
/// and buffers, and its state.
const DEFLATE_MEMORY: u64 = 512 << 10;

/// The most an LZMA2 stream of `size` bytes, without its end, can be: a
/// chunk at most every 64 KiB of compressed data, each with a header of 6
/// bytes at most, and a few bytes more.
fn lzma2_bound(size: u64) -> u64 {
    size + size.div_ceil(1 << 16) * 6 + 16
}

impl WriteOptions {
    /// The options [`Writer::with_options`] refuses, with
    /// [`Error::Param`].
    fn check(&self) -> Result<()> {
        let lzma = matches!(self.method, Method::Lzma { .. } | Method::Lzma2 { .. });
        if (self.filter != Filter::None && !lzma)
            || self
                .dictionary
                .is_some_and(|d| !(DICT_SIZE_MIN..=DICT_SIZE_MAX).contains(&d))
            || (self.encrypt_headers && self.password.is_none())
            || self.key_cycles > MAX_KEY_CYCLES
        {
            return Err(Error::Param);
        }
        Ok(())
    }

    /// The most bytes a [`Writer`] with these options takes to compress,
    /// with LZMA2's blocks in `threads` threads (0 is taken for 1): an
    /// upper bound, of what it allocates, whatever the data. Methods other
    /// than LZMA2 in blocks use one thread, whatever `threads` is. Options
    /// [`Writer::with_options`] refuses are [`Error::Param`].
    ///
    /// LZMA2 in blocks takes, for each thread, an encoder
    /// ([`raw_encoder_memusage`](crate::xz::raw_encoder_memusage), 94 MiB
    /// for preset 6, 674 MiB for preset 9), a block and room for what it
    /// compresses to; and room for one more block compressed, waiting to
    /// be written. Preset 6 with [`Lzma2Blocks::Auto`], blocks of 32 MiB:
    /// 157 MiB a thread, and 33 MiB more. The list of files is beside it,
    /// and so is a header of more than 64 KiB (of a few thousand files),
    /// whose encoder, made at the end once the coders are let go, takes
    /// about 12 times its size. See `docs/memory.md`.
    pub fn memory_usage(&self, threads: u32) -> Result<u64> {
        self.check()?;
        let encoder = |chain: &[XzFilter]| match crate::xz::raw_encoder_memusage(chain) {
            u64::MAX => Err(Error::Param),
            bytes => Ok(bytes),
        };
        let coder = match self.method {
            Method::Copy => 0,
            Method::Lzma { preset: p } => {
                encoder(&xz_chain(self, XzFilter::lzma1(lzma_preset(self, p)?))?)?
            }
            Method::Lzma2 { preset: p } => match lzma2_options(self, p)? {
                (lzma, Some(size)) => {
                    self.filter.coder()?;
                    let threads = u64::from(threads.max(1));
                    let block = size as u64;
                    let out = lzma2_bound(block);
                    let per_thread = encoder(&[XzFilter::lzma2(lzma)])? + block + out;
                    threads.saturating_mul(per_thread).saturating_add(out)
                }
                (lzma, None) => encoder(&xz_chain(self, XzFilter::lzma2(lzma))?)?,
            },
            Method::Deflate { level } if (1..=9).contains(&level) => DEFLATE_MEMORY,
            Method::BZip2 { level } if (1..=9).contains(&level) => {
                crate::bzip2::compress_memory(level)
            }
            Method::Deflate { .. } | Method::BZip2 { .. } => return Err(Error::Param),
        };
        // The header's encoder comes once the coders are let go.
        let header = if self.compress_headers || self.encrypt_headers {
            let mut lzma = LzmaOptions::preset(6).ok_or(Error::Param)?;
            lzma.dict_size = HEADER_DICT_MIN;
            encoder(&[XzFilter::lzma2(lzma)])?
        } else {
            0
        };
        Ok(coder
            .max(header)
            .saturating_add(OUT_BUF as u64 + WRITER_MEMORY))
    }

    /// The threads a [`Writer`] with these options compresses LZMA2's
    /// blocks in: as many as [`threads`](WriteOptions::threads) says, fewer
    /// while [`memory_usage`](WriteOptions::memory_usage) is over
    /// [`memory_limit`](WriteOptions::memory_limit), and one at least. One
    /// for the other methods, and for LZMA2 in one stream. Options
    /// [`Writer::with_options`] refuses are [`Error::Param`].
    pub fn threads_used(&self) -> Result<u32> {
        let blocks =
            matches!(self.method, Method::Lzma2 { .. }) && self.lzma2_blocks != Lzma2Blocks::None;
        let mut threads = if blocks { self.threads.count() } else { 1 };
        // Each thread takes the same: the most that fit, at least one.
        let one = self.memory_usage(1)?;
        if threads > 1 {
            let per_thread = self.memory_usage(2)? - one;
            let room = self.memory_limit.saturating_sub(one) / per_thread.max(1);
            threads = threads.min(u32::try_from(room.saturating_add(1)).unwrap_or(u32::MAX));
        }
        Ok(threads.max(1))
    }
}

/// A file or directory to write: what the header says of it, as
/// [`Entry`](crate::sevenz::Entry) reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewEntry {
    /// Its name, with `/` between folders. It cannot hold a NUL.
    pub name: String,
    /// Its Windows attributes; 7-Zip keeps a Unix mode in the high 16 bits, with
    /// bit 15 (`0x8000`) set.
    pub attributes: Option<u32>,
    /// When it was last written, in 100 ns since 1601 (an NTFS time).
    pub mtime: Option<u64>,
    /// When it was created, in the same units.
    pub ctime: Option<u64>,
}

impl NewEntry {
    /// An entry of this name, and nothing else.
    pub fn new(name: impl Into<String>) -> Self {
        NewEntry {
            name: name.into(),
            ..NewEntry::default()
        }
    }
}

/// What a folder copied is copied in, a piece at a time.
const COPY_PIECE: usize = 1 << 20;

/// What `entry` of an archive read is, to write again.
fn new_entry(entry: &Entry) -> NewEntry {
    NewEntry {
        name: entry.name.clone(),
        attributes: entry.attributes,
        mtime: entry.mtime,
        ctime: entry.ctime,
    }
}

/// `value` as 7z writes numbers: the first byte's leading ones count the bytes
/// after it, little-endian, and the rest of it holds the top.
fn number(out: &mut Vec<u8>, value: u64) {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut extra = 0;
    while extra < 8 {
        if value < 1u64 << (7 * (extra + 1)) {
            first |= (value >> (8 * extra)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        extra += 1;
    }
    out.push(first);
    out.extend_from_slice(&value.to_le_bytes()[..extra]);
}

/// Bits, the first the top of its byte.
fn bits(out: &mut Vec<u8>, values: impl Iterator<Item = bool>) {
    let mut byte = 0u8;
    let mut mask = 0x80u8;
    for value in values {
        if value {
            byte |= mask;
        }
        mask >>= 1;
        if mask == 0 {
            out.push(byte);
            byte = 0;
            mask = 0x80;
        }
    }
    if mask != 0x80 {
        out.push(byte);
    }
}

/// `dict_size` as LZMA2's property: the smallest it can say that holds it.
fn lzma2_dict_prop(dict_size: u32) -> u8 {
    for prop in 0..40u8 {
        let size = u64::from(2 | u32::from(prop & 1)) << (prop / 2 + 11);
        if size >= u64::from(dict_size) {
            return prop;
        }
    }
    40
}

/// The compressor of a folder.
enum Compressor {
    Copy,
    Xz(Box<Stream>),
    Deflate(Box<Deflate>),
    BZip2(Box<Compress>),
    /// LZMA2 in blocks.
    Blocks(Box<Blocks>),
}

impl Compressor {
    /// Gives `out` what `input` compresses to, and if `finish`, the stream's end.
    fn code(
        &mut self,
        input: &[u8],
        finish: bool,
        buf: &mut [u8],
        out: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut at = 0;
        match self {
            Compressor::Copy => out(input),
            Compressor::Blocks(blocks) => blocks.code(input, finish, buf, out),
            Compressor::Xz(stream) => {
                let action = if finish {
                    XzAction::Finish
                } else {
                    XzAction::Run
                };
                loop {
                    let mut output = XzOut::new(buf);
                    let mut from = XzIn::new(&input[at..]);
                    let status = stream
                        .code(&mut output, &mut from, action)
                        .map_err(|_| io::Error::other(Error::Fail))?;
                    at += from.pos;
                    let (made, full) = (output.pos, output.pos == output.dst.len());
                    out(&buf[..made])?;
                    if status == XzStatus::StreamEnd || (!finish && at == input.len() && !full) {
                        return Ok(());
                    }
                }
            }
            Compressor::Deflate(stream) => {
                let flush = if finish {
                    Flush::Finish
                } else {
                    Flush::NoFlush
                };
                loop {
                    let mut output = ZOut::new(buf);
                    let mut from = ZIn::new(&input[at..]);
                    let status = stream.deflate(&mut output, &mut from, flush);
                    at += from.pos;
                    let (made, full) = (output.pos, output.pos == output.dst.len());
                    out(&buf[..made])?;
                    match status {
                        Ok(ZStatus::StreamEnd) => return Ok(()),
                        Ok(_) if !finish && at == input.len() && !full => return Ok(()),
                        Ok(_) => {}
                        // Nothing to do: no more input, and nothing held back.
                        Err(e) if e.code() == ZErrorCode::Buf && !finish => return Ok(()),
                        Err(_) => return Err(io::Error::other(Error::Fail)),
                    }
                }
            }
            Compressor::BZip2(stream) => {
                let action = if finish {
                    BzAction::Finish
                } else {
                    BzAction::Run
                };
                if !finish && input.is_empty() {
                    return Ok(());
                }
                loop {
                    let mut output = BzOut::new(buf);
                    let mut from = BzIn::new(&input[at..]);
                    let status = stream
                        .compress(&mut output, &mut from, action)
                        .map_err(|_| io::Error::other(Error::Fail))?;
                    at += from.pos;
                    let (made, full) = (output.pos, output.pos == output.dst.len());
                    out(&buf[..made])?;
                    if status == BzStatus::StreamEnd || (!finish && at == input.len() && !full) {
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// A block of LZMA2 to compress, with the options to compress it with, and
/// where its size is counted once it is compressed.
type BlockJob = (LzmaOptions, Vec<u8>, Arc<AtomicU64>);

/// The threads that compress LZMA2's blocks, each keeping its encoder for
/// the next block.
type BlockWorkers = Workers<Option<Box<Stream>>, BlockJob, Result<Vec<u8>>>;

/// A block compressed as a stream of its own, without its end: `spare` is the
/// encoder of the block before, whose memory it takes over. Its first chunk
/// resets the dictionary, as the first of a stream does.
fn compress_block(
    spare: &mut Option<Box<Stream>>,
    (lzma, data, compressed): BlockJob,
) -> Result<Vec<u8>> {
    let filters = [XzFilter::lzma2(lzma)];
    let mut stream = match spare.take() {
        Some(stream) => stream.raw_encoder_again(&filters),
        None => Stream::raw_encoder(&filters),
    }
    .map_err(|_| Error::Fail)?;
    let mut input = XzIn::new(&data);
    // Room for the most it can be, reserved once: never more, and no copy
    // as it grows. What is not written to is not touched.
    let mut out = Vec::with_capacity(lzma2_bound(data.len() as u64) as usize);
    loop {
        if out.len() == out.capacity() {
            out.reserve(out.len() / 4 + OUT_BUF);
        }
        let start = out.len();
        out.resize(out.capacity(), 0);
        let mut output = XzOut::new(&mut out[start..]);
        let status = stream
            .code(&mut output, &mut input, XzAction::Finish)
            .map_err(|_| Error::Fail)?;
        let made = output.pos;
        out.truncate(start + made);
        if status == XzStatus::StreamEnd {
            break;
        }
    }
    *spare = Some(Box::new(stream));
    // The end of the stream, which only the folder's last block has.
    if out.pop() != Some(0) {
        return Err(Error::Fail);
    }
    compressed.fetch_add(data.len() as u64, Ordering::Relaxed);
    Ok(out)
}

/// The result of a block whose thread failed.
fn block_lost() -> Result<Vec<u8>> {
    Err(Error::Fail)
}

/// LZMA2 in blocks: what the folder's filter gives, on the caller's thread as
/// it keeps state, cut every `size` bytes, each block compressed by
/// [`compress_block`] in a thread and written in order, and the end of the
/// stream after the last. At most a block for each thread waits to be
/// written, besides the one being filled.
struct Blocks {
    filter: Option<Compressor>,
    lzma: LzmaOptions,
    size: usize,
    block: Vec<u8>,
    workers: Box<BlockWorkers>,
    /// Where each block is counted once compressed.
    compressed: Arc<AtomicU64>,
    /// [`WriteOptions::stop`].
    stop: Option<Arc<AtomicBool>>,
}

impl Blocks {
    fn code(
        &mut self,
        input: &[u8],
        finish: bool,
        buf: &mut [u8],
        out: &mut dyn FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let Blocks {
            filter,
            lzma,
            size,
            block,
            workers,
            compressed,
            stop,
        } = self;
        let job =
            |block: &mut Vec<u8>| (lzma.clone(), std::mem::take(block), Arc::clone(compressed));
        let mut add = |mut data: &[u8]| -> io::Result<()> {
            while !data.is_empty() {
                if block.capacity() < *size {
                    // The whole block, once, not to copy it as it grows.
                    block.reserve_exact(*size - block.len());
                }
                let n = (*size - block.len()).min(data.len());
                block.extend_from_slice(&data[..n]);
                data = &data[n..];
                if block.len() == *size {
                    give(workers, job(block), stop.as_deref(), out)?;
                }
            }
            Ok(())
        };
        match filter {
            Some(filter) => filter.code(input, finish, buf, &mut add)?,
            None => add(input)?,
        }
        if finish {
            if !block.is_empty() {
                give(workers, job(block), stop.as_deref(), out)?;
            }
            while let Some(made) = wait(workers, stop.as_deref())? {
                out(&made.map_err(io::Error::other)?)?;
            }
            out(&[0])?;
        }
        Ok(())
    }
}

/// The oldest block, waited for, `stop` looked at as it waits: none if all
/// are written.
fn wait(
    workers: &mut BlockWorkers,
    stop: Option<&AtomicBool>,
) -> io::Result<Option<Result<Vec<u8>>>> {
    loop {
        if stop.is_some_and(|stop| stop.load(Ordering::Relaxed)) {
            return Err(io::Error::other(Error::Progress));
        }
        if let Ok(made) = workers.take_within(STOP_EVERY) {
            return Ok(made);
        }
    }
}

/// Gives `block` to a thread, and writes the blocks before it until no more
/// wait than there are threads.
fn give(
    workers: &mut BlockWorkers,
    job: BlockJob,
    stop: Option<&AtomicBool>,
    out: &mut dyn FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    workers.give(job);
    while workers.pending() > workers.most() {
        match wait(workers, stop)? {
            Some(made) => out(&made.map_err(io::Error::other)?)?,
            None => break,
        }
    }
    Ok(())
}

/// The options of LZMA's or LZMA2's encoder of `preset`, with the
/// dictionary the options give.
fn lzma_preset(options: &WriteOptions, preset: u32) -> Result<LzmaOptions> {
    let mut lzma = LzmaOptions::preset(preset).ok_or(Error::Param)?;
    if let Some(dictionary) = options.dictionary {
        lzma.dict_size = dictionary;
    }
    Ok(lzma)
}

/// The options of LZMA2's encoder, and the size of its blocks if it is cut
/// in blocks: then the dictionary is no larger than a block.
fn lzma2_options(options: &WriteOptions, preset: u32) -> Result<(LzmaOptions, Option<usize>)> {
    let mut lzma = lzma_preset(options, preset)?;
    let Some(size) = options.lzma2_blocks.size(lzma.dict_size)? else {
        return Ok((lzma, None));
    };
    let size = usize::try_from(size).map_err(|_| Error::Param)?;
    lzma.dict_size = lzma.dict_size.min(u32::try_from(size).unwrap_or(u32::MAX));
    Ok((lzma, Some(size)))
}

/// A coder as a folder describes it: its ID and properties.
type CoderInfo = (Vec<u8>, Vec<u8>);

/// What the header says of a folder.
struct FolderInfo {
    /// Its coders, each reading the one before: the first the packed stream, the
    /// last giving the data.
    coders: Vec<CoderInfo>,
    /// The folder's description as another archive had it, its coders, their
    /// bonds and its packed streams, written as it is in place of `coders`: a
    /// folder copied ([`Writer::copy_from`]).
    copied: Option<Vec<u8>>,
    /// Each coder's output.
    unpack_sizes: Vec<u64>,
    /// Its packed streams' sizes, in order: one, but in a folder copied.
    pack_sizes: Vec<u64>,
    /// The CRC of the folder, for an encoded header.
    crc: Option<u32>,
}

impl FolderInfo {
    fn write(&self, out: &mut Vec<u8>) {
        if let Some(copied) = &self.copied {
            out.extend_from_slice(copied);
            return;
        }
        number(out, self.coders.len() as u64);
        for (id, props) in &self.coders {
            let flags = id.len() as u8 | if props.is_empty() { 0 } else { 0x20 };
            out.push(flags);
            out.extend_from_slice(id);
            if !props.is_empty() {
                number(out, props.len() as u64);
                out.extend_from_slice(props);
            }
        }
        // A coder's input is the output of the one before.
        for i in 1..self.coders.len() as u64 {
            number(out, i);
            number(out, i - 1);
        }
    }
}

/// `PackInfo` and `CodersInfo`, for folders whose packed streams start at
/// `pack_pos`.
fn streams_info(out: &mut Vec<u8>, pack_pos: u64, folders: &[&FolderInfo]) {
    out.push(nid::PACK_INFO);
    number(out, pack_pos);
    let streams: usize = folders.iter().map(|f| f.pack_sizes.len()).sum();
    number(out, streams as u64);
    out.push(nid::SIZE);
    for &size in folders.iter().flat_map(|f| &f.pack_sizes) {
        number(out, size);
    }
    out.push(nid::END);

    out.push(nid::UNPACK_INFO);
    out.push(nid::FOLDER);
    number(out, folders.len() as u64);
    out.push(0); // Not external.
    for folder in folders {
        folder.write(out);
    }
    out.push(nid::CODERS_UNPACK_SIZE);
    for folder in folders {
        for &size in &folder.unpack_sizes {
            number(out, size);
        }
    }
    if folders.iter().any(|f| f.crc.is_some()) {
        out.push(nid::CRC);
        out.push(1); // All are defined.
        for folder in folders {
            out.extend_from_slice(&folder.crc.unwrap_or(0).to_le_bytes());
        }
    }
    out.push(nid::END);
}

/// An open folder: the coders it writes through, and what they have made.
struct OpenFolder {
    compressor: Compressor,
    aes: Option<AesEncoder>,
    coders: Vec<CoderInfo>,
    has_filter: bool,
    /// The data given, the compressor's output, and what is written.
    unpacked: u64,
    compressed: u64,
    packed: u64,
    /// The sizes and CRCs of its files, the last still being written.
    files: Vec<(u64, u32)>,
}

/// A file's size and CRC, in a folder: a file of a folder copied may have no
/// CRC.
type FileSum = (u64, Option<u32>);

/// A file or directory written.
struct Written {
    info: NewEntry,
    /// Its name as UTF-16 units, as an archive copied had it, in place of
    /// `info.name`: a name that is not text stays as it was.
    name16: Option<Vec<u16>>,
    /// Neither a directory nor empty.
    has_stream: bool,
    is_dir: bool,
}

/// Writes a 7z archive: [`Writer::start_file`] begins a file, `io::Write` takes
/// its data, [`Writer::add_directory`] adds a directory, and [`Writer::finish`]
/// ends the archive. Until then it cannot be read.
///
/// An error stays: every later call returns it.
pub struct Writer<W> {
    w: W,
    start: u64,
    options: WriteOptions,
    /// The salt and key of the archive, when encrypting.
    salt_key: Option<([u8; 16], [u8; 32])>,
    buf: Vec<u8>,
    /// The encoder of the last folder, for the next.
    spare: Option<Box<Stream>>,
    /// The threads of the last folder in blocks, for the next.
    block_workers: Option<Box<BlockWorkers>>,
    entries: Vec<Written>,
    /// Whether the last entry is a file, which takes data.
    in_file: bool,
    folder: Option<OpenFolder>,
    /// The method changed since the open folder began: the next file starts
    /// another.
    method_changed: bool,
    /// The folders written, and the sizes and CRCs of their files: a file of
    /// a folder copied may have none.
    folders: Vec<(FolderInfo, Vec<FileSum>)>,
    pack_total: u64,
    failed: Option<Error>,
    progress: WriteProgress,
}

impl<W: Write + Seek> Writer<W> {
    /// An archive with the default [`WriteOptions`], from where `w` is.
    pub fn new(w: W) -> Result<Writer<W>> {
        Writer::with_options(w, WriteOptions::default())
    }

    /// An archive with `options`, from where `w` is. Options that cannot be are
    /// [`Error::Param`]: a filter with a method other than LZMA and LZMA2, headers
    /// encrypted without a password, more key cycles than 7-Zip takes.
    pub fn with_options(mut w: W, options: WriteOptions) -> Result<Writer<W>> {
        options.check()?;
        // Finds a bad preset, level, filter or block size before anything is
        // written. LZMA2 in blocks makes its encoders in its threads.
        let spare = match check_method(&options)? {
            Some(Compressor::Xz(stream)) => Some(stream),
            _ => None,
        };

        let salt_key = match &options.password {
            None => None,
            Some(password) => {
                let mut salt = [0; 16];
                random(&options, &mut salt)?;
                Some((salt, AesEncoder::key(options.key_cycles, &salt, password)))
            }
        };
        let start = w.stream_position().map_err(|_| Error::Write)?;
        w.write_all(&[0; 32]).map_err(|_| Error::Write)?;
        Ok(Writer {
            w,
            start,
            options,
            salt_key,
            buf: vec![0; OUT_BUF],
            entries: Vec::new(),
            in_file: false,
            folder: None,
            method_changed: false,
            spare,
            block_workers: None,
            folders: Vec::new(),
            pack_total: 0,
            failed: None,
            progress: WriteProgress::default(),
        })
    }

    fn check(&self, entry: &NewEntry) -> Result<()> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if entry.name.contains('\0') {
            return Err(Error::Param);
        }
        Ok(())
    }

    /// Begins a file, ending the one before; `io::Write` takes its data, none
    /// making it an empty file. A name with a NUL is [`Error::Param`], and the
    /// archive goes on without it.
    pub fn start_file(&mut self, entry: NewEntry) -> Result<()> {
        self.check(&entry)?;
        self.entries.push(Written {
            info: entry,
            name16: None,
            has_stream: false,
            is_dir: false,
        });
        self.in_file = true;
        Ok(())
    }

    /// Compresses the files from the next with data on with `method`, in a
    /// folder of their own: what is compressed already can be stored with
    /// [`Method::Copy`] beside what is not. A file begun keeps the method it
    /// began with. A method that cannot be, as in [`Writer::with_options`], is
    /// [`Error::Param`], and the method stays as it was.
    pub fn set_method(&mut self, method: Method) -> Result<()> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if method == self.options.method {
            return Ok(());
        }
        let options = WriteOptions {
            method,
            ..self.options.clone()
        };
        let lzma = matches!(method, Method::Lzma { .. } | Method::Lzma2 { .. });
        if options.filter != Filter::None && !lzma {
            return Err(Error::Param);
        }
        check_method(&options)?;
        self.options.method = method;
        self.method_changed = true;
        Ok(())
    }

    /// A file with what `reader` gives, and the bytes it was.
    pub fn add_file<R: Read>(&mut self, entry: NewEntry, reader: &mut R) -> io::Result<u64> {
        self.start_file(entry).map_err(io::Error::other)?;
        io::copy(reader, self)
    }

    /// A directory, ending the file before. Parents are not added by themselves.
    /// A name with a NUL is [`Error::Param`], and the archive goes on without it.
    pub fn add_directory(&mut self, entry: NewEntry) -> Result<()> {
        self.check(&entry)?;
        self.entries.push(Written {
            info: entry,
            name16: None,
            has_stream: false,
            is_dir: true,
        });
        self.in_file = false;
        Ok(())
    }

    /// What `keep` keeps of `archive`, put in this archive: an archive changed,
    /// as 7-Zip changes one, by writing it again. A folder whose files are all
    /// kept is copied as it is, its packed streams and its description, with
    /// whatever coders it has, encrypted or not, and nothing decoded; one some
    /// of whose files go is decoded, and the files kept written again through
    /// this writer's method and password; one none of whose files are kept is
    /// left out. Directories and empty files kept go across as they are. Each
    /// keeps its name, as UTF-16, its attributes, its times and its CRC.
    ///
    /// What is copied comes first, in the archive's order, then the files
    /// written again; what is added after comes after them. A folder decoded
    /// needs `archive`'s password if it is encrypted; the folders copied keep
    /// their encryption, so a caller changing an encrypted archive gives this
    /// writer the same password, and [`WriteOptions::encrypt_headers`] where
    /// [`Archive::headers_encrypted`] says. [`WriteOptions::stop`] is looked at
    /// as a folder is copied. An error stays, as any of the writer's does.
    pub fn copy_from<R: Read + Seek>(
        &mut self,
        archive: &mut Archive<R>,
        keep: impl FnMut(&Entry) -> bool,
    ) -> Result<()> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let copied = self.copy_inner(archive, keep);
        if let Err(e) = copied {
            self.failed = Some(e);
        }
        copied
    }

    fn copy_inner<R: Read + Seek>(
        &mut self,
        archive: &mut Archive<R>,
        mut keep: impl FnMut(&Entry) -> bool,
    ) -> Result<()> {
        // The file before ends, and its folder: the folders copied come after.
        self.in_file = false;
        self.close_folder().map_err(|e| as_error(&e))?;
        let len = archive.len();
        let entries: Vec<Entry> = archive.entries().collect();
        let kept: Vec<bool> = entries.iter().map(&mut keep).collect();
        let folders = archive.folders();
        // Whether each folder's files are all kept, and whether any is.
        let mut whole = vec![true; folders];
        let mut any = vec![false; folders];
        // Of the files with data: an empty one between a folder's files, or
        // a directory there, is in its folder by its index alone.
        let folder_of = |entry: &Entry| entry.folder.filter(|_| entry.has_stream);
        for (entry, &kept) in entries.iter().zip(&kept) {
            if let Some(fo) = folder_of(entry) {
                whole[fo] &= kept;
                any[fo] |= kept;
            }
        }
        let mut copied = vec![false; folders];
        for (entry, _) in entries.iter().zip(&kept).filter(|(_, kept)| **kept) {
            match folder_of(entry) {
                None => self.entries.push(Written {
                    info: new_entry(entry),
                    name16: Some(entry.name_utf16.clone()),
                    has_stream: false,
                    is_dir: entry.is_dir,
                }),
                Some(fo) if whole[fo] => {
                    if !copied[fo] {
                        self.copy_folder(archive, fo)?;
                        copied[fo] = true;
                    }
                    self.entries.push(Written {
                        info: new_entry(entry),
                        name16: Some(entry.name_utf16.clone()),
                        has_stream: true,
                        is_dir: false,
                    });
                }
                // Written again below.
                Some(_) => {}
            }
        }
        // The files kept of folders some of whose files go, decoded.
        let db = &archive.db;
        let runs: Vec<std::ops::Range<usize>> = (0..folders)
            .filter(|&fo| any[fo] && !whole[fo])
            .map(|fo| db.folder_to_file[fo] as usize..db.folder_to_file[fo + 1] as usize)
            .collect();
        let mut buf = vec![0u8; 64 << 10];
        for run in runs {
            let mut walk = Walk::new(run.start..run.end.min(len));
            while let Some(entry) = walk.next(&mut *archive)? {
                if folder_of(&entry).is_none() || !kept[entry.index] {
                    continue;
                }
                self.start_file(new_entry(&entry))?;
                if let Some(written) = self.entries.last_mut() {
                    written.name16 = Some(entry.name_utf16.clone());
                }
                loop {
                    let n = walk.read_current(&mut *archive, &mut buf)?;
                    if n == 0 {
                        break;
                    }
                    self.write_all(&buf[..n]).map_err(|e| as_error(&e))?;
                }
            }
        }
        self.in_file = false;
        Ok(())
    }

    /// Folder `fo` of `archive` copied as it is: its packed streams, then what
    /// the header will say of it and of its files.
    fn copy_folder<R: Read + Seek>(&mut self, archive: &mut Archive<R>, fo: usize) -> Result<()> {
        let db = &archive.db;
        let ar = &db.db;
        let description =
            ar.coders_data[ar.fo_coders_offsets[fo]..ar.fo_coders_offsets[fo + 1]].to_vec();
        let unpack_sizes = ar.coder_unpack_sizes[ar.fo_to_coder_unpack_sizes[fo] as usize
            ..ar.fo_to_coder_unpack_sizes[fo + 1] as usize]
            .to_vec();
        let (first, end) = (
            ar.fo_start_pack_stream_index[fo] as usize,
            ar.fo_start_pack_stream_index[fo + 1] as usize,
        );
        let pack_sizes: Vec<u64> = (first..end)
            .map(|i| ar.pack_positions[i + 1] - ar.pack_positions[i])
            .collect();
        let start = db
            .data_pos
            .checked_add(ar.pack_positions[first])
            .ok_or(Error::Archive)?;
        let packed = ar.pack_positions[end] - ar.pack_positions[first];
        let files: Vec<FileSum> = (db.folder_to_file[fo] as usize
            ..db.folder_to_file[fo + 1] as usize)
            .filter(|&i| db.file_to_folder[i] as usize == fo && db.has_stream(i))
            .map(|i| (db.file_size(i), db.crcs.check(i).then(|| db.crcs.vals[i])))
            .collect();
        let size = archive.folder_size(fo);

        // The packed streams, a piece at a time.
        let reader = &mut archive.reader;
        reader
            .seek(SeekFrom::Start(start))
            .map_err(|_| Error::Read)?;
        let mut left = packed;
        let mut buf = vec![0u8; COPY_PIECE.min(packed as usize).max(1)];
        while left > 0 {
            if self
                .options
                .stop
                .as_ref()
                .is_some_and(|stop| stop.load(Ordering::Relaxed))
            {
                return Err(Error::Progress);
            }
            let n = buf.len().min(left as usize);
            reader
                .read_exact(&mut buf[..n])
                .map_err(|e| match e.kind() {
                    io::ErrorKind::UnexpectedEof => Error::InputEof,
                    _ => Error::Read,
                })?;
            self.w.write_all(&buf[..n]).map_err(|_| Error::Write)?;
            left -= n as u64;
        }
        self.pack_total += packed;
        self.progress.taken.fetch_add(size, Ordering::Relaxed);
        self.progress.compressed.fetch_add(size, Ordering::Relaxed);
        self.folders.push((
            FolderInfo {
                coders: Vec::new(),
                copied: Some(description),
                unpack_sizes,
                pack_sizes,
                crc: None,
            },
            files,
        ));
        Ok(())
    }

    /// Opens a folder for the file's first data, closing the one before if the
    /// file should not join it.
    fn prepare_folder(&mut self) -> io::Result<()> {
        if let Some(folder) = &self.folder {
            let room = self.options.solid_block_size.unwrap_or(0);
            if folder.unpacked >= room || self.method_changed {
                self.close_folder()?;
            }
        }
        self.method_changed = false;
        if self.folder.is_none() {
            let compressor = self.folder_compressor().map_err(io::Error::other)?;
            let (mut coders, aes) = (Vec::new(), self.make_aes().map_err(io::Error::other)?);
            let aes = match aes {
                Some((encoder, props)) => {
                    coders.push((K_AES_ID.to_vec(), props));
                    Some(encoder)
                }
                None => None,
            };
            coders.push(method_coder(&self.options).map_err(io::Error::other)?);
            let filter = self.options.filter.coder().map_err(io::Error::other)?;
            let has_filter = filter.is_some();
            if let Some((_, id, props)) = filter {
                coders.push((id.to_vec(), props));
            }
            self.folder = Some(OpenFolder {
                compressor,
                aes,
                coders,
                has_filter,
                unpacked: 0,
                compressed: 0,
                packed: 0,
                files: Vec::new(),
            });
        }
        if let Some(folder) = &mut self.folder {
            folder.files.push((0, 0));
        }
        Ok(())
    }

    /// The compressor of a new folder: LZMA2 in blocks, with the threads of
    /// the folder before, or as [`make_compressor`] makes it.
    fn folder_compressor(&mut self) -> Result<Compressor> {
        let blocks = match self.options.method {
            Method::Lzma2 { preset } => lzma2_options(&self.options, preset)?,
            _ => (LzmaOptions::default(), None),
        };
        let (lzma, Some(size)) = blocks else {
            if matches!(
                self.options.method,
                Method::Lzma { .. } | Method::Lzma2 { .. }
            ) {
                // The threads' encoders, no longer wanted, are let go
                // before this one is made.
                self.block_workers = None;
            }
            return make_compressor(&self.options, &mut self.spare);
        };
        // An encoder of one stream is let go, and the threads of the folder
        // before kept only if they are as many as this one may have.
        self.spare = None;
        let threads = self.options.threads_used()?;
        if self
            .block_workers
            .as_ref()
            .is_some_and(|workers| workers.most() != threads as usize)
        {
            self.block_workers = None;
        }
        let filter = match self.options.filter.coder()? {
            Some((filter, ..)) => Some(Compressor::Xz(Box::new(
                Stream::filter_encoder(&filter).map_err(|_| Error::Param)?,
            ))),
            None => None,
        };
        let workers = match self.block_workers.take() {
            Some(workers) => workers,
            None => Box::new(Workers::new(
                threads,
                "sevenz-lzma2",
                compress_block,
                block_lost,
            )),
        };
        Ok(Compressor::Blocks(Box::new(Blocks {
            filter,
            lzma,
            size,
            block: Vec::new(),
            workers,
            compressed: Arc::clone(&self.progress.compressed),
            stop: self.options.stop.clone(),
        })))
    }

    /// An AES encoder with a new IV and the coder's properties, when encrypting.
    fn make_aes(&self) -> Result<Option<(AesEncoder, Vec<u8>)>> {
        let Some((salt, key)) = &self.salt_key else {
            return Ok(None);
        };
        let mut iv = [0; 16];
        random(&self.options, &mut iv)?;
        Ok(Some((
            AesEncoder::new(key, iv)?,
            AesEncoder::props(self.options.key_cycles, salt, &iv),
        )))
    }

    /// Runs `input` through the open folder's coders, to the output.
    fn feed(&mut self, input: &[u8], finish: bool) -> io::Result<()> {
        let Writer { w, buf, folder, .. } = self;
        let Some(folder) = folder else {
            return Ok(());
        };
        let OpenFolder {
            compressor,
            aes,
            compressed,
            packed,
            ..
        } = folder;
        compressor.code(input, finish, buf, &mut |made| {
            *compressed += made.len() as u64;
            match aes {
                Some(aes) => aes.encrypt(made, &mut |cipher| {
                    *packed += cipher.len() as u64;
                    w.write_all(cipher)
                }),
                None => {
                    *packed += made.len() as u64;
                    w.write_all(made)
                }
            }
        })?;
        if finish && let Some(aes) = aes {
            aes.finish(&mut |cipher| {
                *packed += cipher.len() as u64;
                w.write_all(cipher)
            })?;
        }
        Ok(())
    }

    /// Ends the open folder's streams, and notes what the header will say.
    fn close_folder(&mut self) -> io::Result<()> {
        self.feed(&[], true)?;
        let Some(folder) = self.folder.take() else {
            return Ok(());
        };
        match folder.compressor {
            Compressor::Xz(stream) => self.spare = Some(stream),
            Compressor::Blocks(blocks) => self.block_workers = Some(blocks.workers),
            _ => {}
        }
        let mut unpack_sizes = Vec::new();
        if folder.aes.is_some() {
            unpack_sizes.push(folder.compressed);
        }
        unpack_sizes.push(folder.unpacked);
        if folder.has_filter {
            unpack_sizes.push(folder.unpacked);
        }
        self.pack_total += folder.packed;
        self.folders.push((
            FolderInfo {
                coders: folder.coders,
                copied: None,
                unpack_sizes,
                pack_sizes: vec![folder.packed],
                crc: None,
            },
            folder
                .files
                .into_iter()
                .map(|(size, sum)| (size, Some(sum)))
                .collect(),
        ));
        Ok(())
    }

    /// `FilesInfo` and all before it: the header as it is before being encoded.
    fn header(&self) -> Vec<u8> {
        let mut out = vec![nid::HEADER];
        if !self.folders.is_empty() {
            out.push(nid::MAIN_STREAMS_INFO);
            let infos: Vec<&FolderInfo> = self.folders.iter().map(|(f, _)| f).collect();
            streams_info(&mut out, 0, &infos);
            out.push(nid::SUBSTREAMS_INFO);
            out.push(nid::NUM_UNPACK_STREAM);
            for (_, files) in &self.folders {
                number(&mut out, files.len() as u64);
            }
            out.push(nid::SIZE);
            for (_, files) in &self.folders {
                for (size, _) in &files[..files.len() - 1] {
                    number(&mut out, *size);
                }
            }
            let crcs: Vec<Option<u32>> = self
                .folders
                .iter()
                .flat_map(|(_, files)| files.iter().map(|&(_, crc)| crc))
                .collect();
            if crcs.iter().any(Option::is_some) {
                out.push(nid::CRC);
                if crcs.iter().all(Option::is_some) {
                    out.push(1); // All are defined.
                } else {
                    out.push(0);
                    bits(&mut out, crcs.iter().map(Option::is_some));
                }
                for crc in crcs.iter().flatten() {
                    out.extend_from_slice(&crc.to_le_bytes());
                }
            }
            out.push(nid::END);
            out.push(nid::END);
        }
        if !self.entries.is_empty() {
            self.files_info(&mut out);
        }
        out.push(nid::END);
        out
    }

    fn files_info(&self, out: &mut Vec<u8>) {
        out.push(nid::FILES_INFO);
        number(out, self.entries.len() as u64);
        let property = |out: &mut Vec<u8>, id: u8, body: &[u8]| {
            out.push(id);
            number(out, body.len() as u64);
            out.extend_from_slice(body);
        };
        if self.entries.iter().any(|e| !e.has_stream) {
            let mut body = Vec::new();
            bits(&mut body, self.entries.iter().map(|e| !e.has_stream));
            property(out, nid::EMPTY_STREAM, &body);
            if self.entries.iter().any(|e| !e.has_stream && !e.is_dir) {
                let mut body = Vec::new();
                let empties = self.entries.iter().filter(|e| !e.has_stream);
                bits(&mut body, empties.map(|e| !e.is_dir));
                property(out, nid::EMPTY_FILE, &body);
            }
        }
        let mut names = vec![0]; // Not external.
        for entry in &self.entries {
            match &entry.name16 {
                Some(units) => {
                    for unit in units {
                        names.extend_from_slice(&unit.to_le_bytes());
                    }
                }
                None => {
                    for unit in entry.info.name.encode_utf16() {
                        names.extend_from_slice(&unit.to_le_bytes());
                    }
                }
            }
            names.extend_from_slice(&[0, 0]);
        }
        property(out, nid::NAME, &names);
        let mut defined = |id: u8, value: &dyn Fn(&NewEntry) -> Option<Vec<u8>>| {
            let values: Vec<Option<Vec<u8>>> =
                self.entries.iter().map(|e| value(&e.info)).collect();
            if values.iter().all(Option::is_none) {
                return;
            }
            let mut body = Vec::new();
            if values.iter().all(Option::is_some) {
                body.push(1); // All are defined.
            } else {
                body.push(0);
                bits(&mut body, values.iter().map(Option::is_some));
            }
            body.push(0); // Not external.
            for bytes in values.iter().flatten() {
                body.extend_from_slice(bytes);
            }
            property(out, id, &body);
        };
        defined(nid::CTIME, &|e| e.ctime.map(|t| t.to_le_bytes().to_vec()));
        defined(nid::MTIME, &|e| e.mtime.map(|t| t.to_le_bytes().to_vec()));
        defined(nid::WIN_ATTRIBUTES, &|e| {
            e.attributes.map(|a| a.to_le_bytes().to_vec())
        });
        out.push(nid::END);
    }

    /// The header as it goes in the archive, with its packed stream if it is
    /// encoded, which is written here.
    fn encode_header(&mut self, raw: Vec<u8>) -> io::Result<Vec<u8>> {
        let encrypt = self.options.encrypt_headers;
        if !encrypt && !self.options.compress_headers {
            return Ok(raw);
        }
        let mut lzma = LzmaOptions::preset(6).ok_or_else(|| io::Error::other(Error::Fail))?;
        lzma.dict_size = (raw.len() as u32).clamp(HEADER_DICT_MIN, 1 << 26);
        let lzma2 = (vec![0x21], vec![lzma2_dict_prop(lzma.dict_size)]);
        let mut stream = Compressor::Xz(Box::new(
            Stream::raw_encoder(&[XzFilter::lzma2(lzma)])
                .map_err(|_| io::Error::other(Error::Fail))?,
        ));
        let mut compressed = Vec::new();
        let mut buf = std::mem::take(&mut self.buf);
        stream.code(&raw, true, &mut buf, &mut |made| {
            compressed.extend_from_slice(made);
            Ok(())
        })?;
        self.buf = buf;
        let raw_size = raw.len() as u64;
        if !encrypt && compressed.len() + 32 >= raw.len() {
            return Ok(raw);
        }
        let compressed_size = compressed.len() as u64;
        let mut coders = Vec::new();
        let mut unpack_sizes = Vec::new();
        let packed = if encrypt {
            let (mut aes, props) = self
                .make_aes()
                .map_err(io::Error::other)?
                .ok_or_else(|| io::Error::other(Error::Param))?;
            coders.push((K_AES_ID.to_vec(), props));
            unpack_sizes.push(compressed_size);
            let mut cipher = Vec::with_capacity(compressed.len() + 16);
            aes.encrypt(&compressed, &mut |c| {
                cipher.extend_from_slice(c);
                Ok(())
            })?;
            aes.finish(&mut |c| {
                cipher.extend_from_slice(c);
                Ok(())
            })?;
            cipher
        } else {
            compressed
        };
        coders.push(lzma2);
        unpack_sizes.push(raw_size);
        self.w.write_all(&packed)?;
        let info = FolderInfo {
            coders,
            copied: None,
            unpack_sizes,
            pack_sizes: vec![packed.len() as u64],
            crc: Some(crc(&raw)),
        };
        let mut out = vec![nid::ENCODED_HEADER];
        streams_info(&mut out, self.pack_total, &[&info]);
        out.push(nid::END);
        self.pack_total += packed.len() as u64;
        Ok(out)
    }

    fn finish_inner(&mut self) -> io::Result<()> {
        self.close_folder()?;
        // The encoders kept for a next folder, let go before the header's.
        self.spare = None;
        self.block_workers = None;
        let next_header = if self.entries.is_empty() {
            Vec::new()
        } else {
            let raw = self.header();
            self.encode_header(raw)?
        };
        self.w.write_all(&next_header)?;

        let mut start_header = Vec::with_capacity(20);
        start_header.extend_from_slice(&self.pack_total.to_le_bytes());
        start_header.extend_from_slice(&(next_header.len() as u64).to_le_bytes());
        start_header.extend_from_slice(&crc(&next_header).to_le_bytes());
        let end = self.w.stream_position()?;
        self.w.seek(SeekFrom::Start(self.start))?;
        self.w.write_all(&SIGNATURE)?;
        self.w.write_all(&[0, 4])?; // The version of the format.
        self.w.write_all(&crc(&start_header).to_le_bytes())?;
        self.w.write_all(&start_header)?;
        self.w.seek(SeekFrom::Start(end))?;
        self.w.flush()
    }

    /// Ends the archive: the last folder's end, the header, and the signature
    /// header that says where it is. The output is left at the archive's end and
    /// flushed, and given back.
    pub fn finish(mut self) -> Result<W> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        self.finish_inner().map_err(|e| as_error(&e))?;
        Ok(self.w)
    }

    /// The output.
    pub fn get_ref(&self) -> &W {
        &self.w
    }

    /// How far it has come, to read from another thread while it writes.
    pub fn progress(&self) -> WriteProgress {
        self.progress.clone()
    }
}

/// The error an `io::Error` of this writer's stands for.
fn as_error(e: &io::Error) -> Error {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<Error>())
        .copied()
        .unwrap_or(Error::Write)
}

/// Fills `bytes`, from the options' source or the system's.
fn random(options: &WriteOptions, bytes: &mut [u8]) -> Result<()> {
    match &options.random_source {
        Some(source) => source(bytes).map_err(|_| Error::Fail),
        None => crate::crypto::system_random(bytes).map_err(|_| Error::Fail),
    }
}

/// The filters for `hivepack::xz`, ending with `last`.
fn xz_chain(options: &WriteOptions, last: XzFilter) -> Result<Vec<XzFilter>> {
    let mut chain = Vec::new();
    if let Some((filter, ..)) = options.filter.coder()? {
        chain.push(filter);
    }
    chain.push(last);
    Ok(chain)
}

/// Checks the method's options as [`make_compressor`] does, and gives the
/// compressor it made: none for LZMA2 in blocks, whose encoders are made in
/// its threads, as an encoder of one stream would take as much memory as
/// one of them for nothing.
fn check_method(options: &WriteOptions) -> Result<Option<Compressor>> {
    if let Method::Lzma2 { preset } = options.method
        && lzma2_options(options, preset)?.1.is_some()
    {
        options.memory_usage(1)?;
        return Ok(None);
    }
    make_compressor(options, &mut None).map(Some)
}

/// The compressor of a new folder. `spare`: the encoder of the last one, whose
/// memory it takes over, which saves much when each file is a folder.
fn make_compressor(options: &WriteOptions, spare: &mut Option<Box<Stream>>) -> Result<Compressor> {
    let preset = |p| lzma_preset(options, p);
    let spare = spare.take();
    let raw = move |filters: Vec<XzFilter>| {
        match spare {
            Some(stream) => stream.raw_encoder_again(&filters),
            None => Stream::raw_encoder(&filters),
        }
        .map(|s| Compressor::Xz(Box::new(s)))
        .map_err(|_| Error::Param)
    };
    match options.method {
        Method::Copy => Ok(Compressor::Copy),
        Method::Lzma { preset: p } => raw(xz_chain(options, XzFilter::lzma1(preset(p)?))?),
        Method::Lzma2 { preset: p } => raw(xz_chain(options, XzFilter::lzma2(preset(p)?))?),
        Method::Deflate { level } => {
            if !(1..=9).contains(&level) {
                return Err(Error::Param);
            }
            Deflate::new(level, -15, 8, 0)
                .map(|s| Compressor::Deflate(Box::new(s)))
                .map_err(|_| Error::Param)
        }
        Method::BZip2 { level } => Compress::new(level, 30)
            .map(|s| Compressor::BZip2(Box::new(s)))
            .map_err(|_| Error::Param),
    }
}

/// The method's coder as a folder says it.
fn method_coder(options: &WriteOptions) -> Result<CoderInfo> {
    let preset = |p| lzma_preset(options, p);
    Ok(match options.method {
        Method::Copy => (vec![0x00], Vec::new()),
        Method::Lzma { preset: p } => {
            let o = preset(p)?;
            let mut props = vec![((o.pb * 5 + o.lp) * 9 + o.lc) as u8];
            props.extend_from_slice(&o.dict_size.to_le_bytes());
            (vec![0x03, 0x01, 0x01], props)
        }
        Method::Lzma2 { preset: p } => {
            let (lzma, _) = lzma2_options(options, p)?;
            (vec![0x21], vec![lzma2_dict_prop(lzma.dict_size)])
        }
        Method::Deflate { .. } => (vec![0x04, 0x01, 0x08], Vec::new()),
        Method::BZip2 { .. } => (vec![0x04, 0x02, 0x02], Vec::new()),
    })
}

/// A file's data: the part of the archive's folder that is its own.
impl<W: Write + Seek> Write for Writer<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if let Some(e) = self.failed {
            return Err(io::Error::other(e));
        }
        if !self.in_file {
            return Err(io::Error::other(Error::Param));
        }
        if data.is_empty() {
            return Ok(0);
        }
        let mut go = || -> io::Result<()> {
            let opened = self.entries.last().is_some_and(|e| !e.has_stream);
            if opened {
                self.prepare_folder()?;
                if let Some(entry) = self.entries.last_mut() {
                    entry.has_stream = true;
                }
            }
            self.progress
                .taken
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            self.feed(data, false)?;
            if let Some(folder) = &mut self.folder {
                // What is not in blocks is compressed as it is given.
                if !matches!(folder.compressor, Compressor::Blocks(_)) {
                    self.progress
                        .compressed
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                folder.unpacked += data.len() as u64;
                if let Some((size, sum)) = folder.files.last_mut() {
                    *size += data.len() as u64;
                    *sum = crate::deflate::crc32(*sum, data);
                }
            }
            Ok(())
        };
        match go() {
            Ok(()) => Ok(data.len()),
            Err(e) => {
                self.failed = Some(as_error(&e));
                Err(e)
            }
        }
    }

    /// The output's `flush`. Compressors hold on to what they have, so this does
    /// not make the archive any more readable.
    fn flush(&mut self) -> io::Result<()> {
        if let Some(e) = self.failed {
            return Err(io::Error::other(e));
        }
        self.w.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_as_the_format_says() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0]),
            (0x7F, &[0x7F]),
            (0x80, &[0x80, 0x80]),
            (0x3FFF, &[0xBF, 0xFF]),
            (0x4000, &[0xC0, 0x00, 0x40]),
            (0x12_3456, &[0xD2, 0x56, 0x34]),
            (u64::MAX, &[0xFF, 255, 255, 255, 255, 255, 255, 255, 255]),
            (1 << 56, &[0xFF, 0, 0, 0, 0, 0, 0, 0, 1]),
            ((1 << 56) - 1, &[0xFE, 255, 255, 255, 255, 255, 255, 255]),
        ];
        for &(value, want) in cases {
            let mut got = Vec::new();
            number(&mut got, value);
            assert_eq!(got, want, "{value:#x}");
        }
    }

    #[test]
    fn lzma2_properties_as_xz_says() {
        for (dict, want) in [
            (1, 0),
            (4096, 0),
            (4097, 1),
            (6144, 1),
            (8 << 20, 22),
            ((8 << 20) + 1, 23),
            (64 << 20, 28),
            (u32::MAX, 40),
        ] {
            assert_eq!(lzma2_dict_prop(dict), want, "{dict}");
        }
    }
}
