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

use crate::bzip2::{
    Action as BzAction, Compress, InBuffer as BzIn, OutBuffer as BzOut, Status as BzStatus,
};
use crate::deflate::{
    Deflate, ErrorCode as ZErrorCode, Flush, InBuffer as ZIn, OutBuffer as ZOut, Status as ZStatus,
};
use crate::xz::{
    Action as XzAction, DELTA_DIST_MAX, DELTA_DIST_MIN, FILTER_ARM, FILTER_ARM64, FILTER_ARMTHUMB,
    FILTER_IA64, FILTER_POWERPC, FILTER_RISCV, FILTER_SPARC, FILTER_X86, Filter as XzFilter,
    InBuffer as XzIn, LzmaOptions, OutBuffer as XzOut, Status as XzStatus, Stream,
};

use crate::sevenz::aes7z::{AesEncoder, K_AES_ID, MAX_KEY_CYCLES};
use crate::sevenz::arc_in::SIGNATURE;
use crate::sevenz::crc;
use crate::sevenz::error::{Error, Result};
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
    /// thread alone. What is written is the same whatever this is.
    pub threads: Threads,
}

impl Default for WriteOptions {
    fn default() -> Self {
        WriteOptions {
            method: Method::Lzma2 { preset: 6 },
            filter: Filter::None,
            solid_block_size: Some(1 << 32),
            compress_headers: true,
            password: None,
            encrypt_headers: false,
            key_cycles: 19,
            random_source: None,
            lzma2_blocks: Lzma2Blocks::None,
            threads: Threads::One,
        }
    }
}

impl core::fmt::Debug for WriteOptions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WriteOptions")
            .field("method", &self.method)
            .field("filter", &self.filter)
            .field("solid_block_size", &self.solid_block_size)
            .field("compress_headers", &self.compress_headers)
            .field("password", &self.password.as_ref().map(|_| "(hidden)"))
            .field("encrypt_headers", &self.encrypt_headers)
            .field("key_cycles", &self.key_cycles)
            .field("lzma2_blocks", &self.lzma2_blocks)
            .field("threads", &self.threads)
            .finish_non_exhaustive()
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

/// A block of LZMA2 to compress, with the options to compress it with.
type BlockJob = (LzmaOptions, Vec<u8>);

/// The threads that compress LZMA2's blocks, each keeping its encoder for
/// the next block.
type BlockWorkers = Workers<Option<Box<Stream>>, BlockJob, Result<Vec<u8>>>;

/// A block compressed as a stream of its own, without its end: `spare` is the
/// encoder of the block before, whose memory it takes over. Its first chunk
/// resets the dictionary, as the first of a stream does.
fn compress_block(spare: &mut Option<Box<Stream>>, (lzma, data): BlockJob) -> Result<Vec<u8>> {
    let filters = [XzFilter::lzma2(lzma)];
    let mut stream = match spare.take() {
        Some(stream) => stream.raw_encoder_again(&filters),
        None => Stream::raw_encoder(&filters),
    }
    .map_err(|_| Error::Fail)?;
    let mut input = XzIn::new(&data);
    let mut out = Vec::with_capacity(data.len() / 4 + OUT_BUF);
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
        } = self;
        let mut add = |mut data: &[u8]| -> io::Result<()> {
            while !data.is_empty() {
                let n = (*size - block.len()).min(data.len());
                block.extend_from_slice(&data[..n]);
                data = &data[n..];
                if block.len() == *size {
                    give(workers, lzma, block, out)?;
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
                give(workers, lzma, block, out)?;
            }
            while let Some(made) = workers.take() {
                out(&made.map_err(io::Error::other)?)?;
            }
            out(&[0])?;
        }
        Ok(())
    }
}

/// Gives `block` to a thread, and writes the blocks before it until no more
/// wait than there are threads.
fn give(
    workers: &mut BlockWorkers,
    lzma: &LzmaOptions,
    block: &mut Vec<u8>,
    out: &mut dyn FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    workers.give((lzma.clone(), std::mem::take(block)));
    while workers.pending() > workers.most() {
        match workers.take() {
            Some(made) => out(&made.map_err(io::Error::other)?)?,
            None => break,
        }
    }
    Ok(())
}

/// The options of LZMA2's encoder, and the size of its blocks if it is cut
/// in blocks: then the dictionary is no larger than a block.
fn lzma2_options(options: &WriteOptions, preset: u32) -> Result<(LzmaOptions, Option<usize>)> {
    let mut lzma = LzmaOptions::preset(preset).ok_or(Error::Param)?;
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
    /// Each coder's output.
    unpack_sizes: Vec<u64>,
    pack_size: u64,
    /// The CRC of the folder, for an encoded header.
    crc: Option<u32>,
}

impl FolderInfo {
    fn write(&self, out: &mut Vec<u8>) {
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
    number(out, folders.len() as u64);
    out.push(nid::SIZE);
    for folder in folders {
        number(out, folder.pack_size);
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

/// A file or directory written.
struct Written {
    info: NewEntry,
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
    folders: Vec<(FolderInfo, Vec<(u64, u32)>)>,
    pack_total: u64,
    failed: Option<Error>,
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
        let lzma = matches!(options.method, Method::Lzma { .. } | Method::Lzma2 { .. });
        if (options.filter != Filter::None && !lzma)
            || (options.encrypt_headers && options.password.is_none())
            || options.key_cycles > MAX_KEY_CYCLES
        {
            return Err(Error::Param);
        }
        // Finds a bad preset, level, filter or block size before anything is
        // written.
        let compressor = make_compressor(&options, &mut None)?;
        if let Method::Lzma2 { preset } = options.method {
            lzma2_options(&options, preset)?;
        }
        let spare = match compressor {
            Compressor::Xz(stream) => Some(stream),
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
        make_compressor(&options, &mut None)?;
        if let Method::Lzma2 { preset } = method {
            lzma2_options(&options, preset)?;
        }
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
            has_stream: false,
            is_dir: true,
        });
        self.in_file = false;
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
        let Method::Lzma2 { preset } = self.options.method else {
            return make_compressor(&self.options, &mut self.spare);
        };
        let (lzma, Some(size)) = lzma2_options(&self.options, preset)? else {
            return make_compressor(&self.options, &mut self.spare);
        };
        let filter = match self.options.filter.coder()? {
            Some((filter, ..)) => Some(Compressor::Xz(Box::new(
                Stream::filter_encoder(&filter).map_err(|_| Error::Param)?,
            ))),
            None => None,
        };
        let workers = match self.block_workers.take() {
            Some(workers) => workers,
            None => Box::new(Workers::new(
                self.options.threads.count(),
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
                unpack_sizes,
                pack_size: folder.packed,
                crc: None,
            },
            folder.files,
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
            out.push(nid::CRC);
            out.push(1); // All are defined.
            for (_, files) in &self.folders {
                for (_, crc) in files {
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
            for unit in entry.info.name.encode_utf16() {
                names.extend_from_slice(&unit.to_le_bytes());
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
        lzma.dict_size = (raw.len() as u32).clamp(1 << 16, 1 << 26);
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
            unpack_sizes,
            pack_size: packed.len() as u64,
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

/// The compressor of a new folder. `spare`: the encoder of the last one, whose
/// memory it takes over, which saves much when each file is a folder.
fn make_compressor(options: &WriteOptions, spare: &mut Option<Box<Stream>>) -> Result<Compressor> {
    let preset = |p| LzmaOptions::preset(p).ok_or(Error::Param);
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
    let preset = |p| LzmaOptions::preset(p).ok_or(Error::Param);
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
            self.feed(data, false)?;
            if let Some(folder) = &mut self.folder {
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
