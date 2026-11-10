//! Deflate in threads, as pigz does it: the input cut into blocks of a fixed
//! size, each compressed in a thread with the 32 KiB of input before it as
//! its dictionary, the blocks one after the other in one deflate stream, in
//! one gzip member: what every gzip reader reads, `gzip -d` among them.
//!
//! Not part of the port: zlib has no threads, and nothing here changes what
//! [`Deflate`] does. Each block is [`Deflate`]'s, and is ended on a byte as
//! pigz 2.8 ends it, so that the stream is pigz's, byte for byte, at its
//! default block size.
//!
//! The blocks are cut where their size says, never where the threads would:
//! the output is the same whatever the threads, one or many.
//!
//! With [`Library::Libdeflate`], each block is libdeflate's instead
//! ([`Compressor`]), at its levels 0 to 12: blocks of 1 MiB by default,
//! each compressed alone, without the input before it, every one but the
//! last with [`Compressor::deflate_compress_part`], which ends it with a
//! sync marker. libdeflate's compressor takes a whole buffer at once, and
//! has no dictionary to give it.

use super::deflate::OS_CODE;
use crate::Threads;
use crate::deflate::{
    Compressor, DEF_MEM_LEVEL, Deflate, Error, ErrorCode, Flush, InBuffer, OutBuffer, Result,
    Status, Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY, Z_FIXED, Z_HUFFMAN_ONLY, crc32,
    crc32_combine,
};
use crate::workers::Workers;

/// The input of each block by default: 128 KiB, pigz's.
pub const BLOCK_SIZE: usize = 128 << 10;

/// The input of each block by default with [`Library::Libdeflate`]: 1 MiB.
/// Each block is compressed alone, without the 32 KiB before it, which
/// costs 0.2% at level 12 on shared libraries, where blocks of 4 MiB cost
/// 0.04% and of 256 KiB 0.75%.
pub const LIBDEFLATE_BLOCK_SIZE: usize = 1 << 20;

/// The largest input of a block.
const BLOCK_SIZE_MAX: usize = 1 << 30;

/// The input before a block that it takes as its dictionary: deflate's
/// window, 32 KiB.
const DICT: usize = 32 << 10;

/// Whose compressor compresses the blocks of a [`DeflateMt`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Library {
    /// zlib's, [`Deflate`]: each block with the 32 KiB of input before it as
    /// its dictionary, as pigz compresses them. The default.
    #[default]
    Zlib,
    /// libdeflate's, [`Compressor`]: each block alone, at levels 0 to 12,
    /// whose 10 to 12 make smaller streams than zlib's 9.
    Libdeflate,
}

/// How a [`DeflateMt`] compresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MtOptions {
    /// 0 to 9, or [`Z_DEFAULT_COMPRESSION`] (6), as [`Deflate::new`] takes
    /// it: the default. With [`Library::Libdeflate`], 0 to 12, as
    /// [`Compressor::new`] takes it.
    pub level: i32,
    /// [`Z_DEFAULT_STRATEGY`] to [`Z_FIXED`], as [`Deflate::new`] takes it:
    /// [`Z_DEFAULT_STRATEGY`] by default. libdeflate has no strategies:
    /// with [`Library::Libdeflate`], only [`Z_DEFAULT_STRATEGY`].
    pub strategy: i32,
    /// Raw deflate, without gzip's header and trailer, as in a ZIP entry:
    /// off by default.
    pub raw: bool,
    /// The threads, besides the caller's, that compress the blocks.
    pub threads: Threads,
    /// The input of each block, or 0 for [`BLOCK_SIZE`], and
    /// [`LIBDEFLATE_BLOCK_SIZE`] with [`Library::Libdeflate`]; at most 1 GiB.
    pub block_size: usize,
    /// The most bytes compressing may take: the threads are lowered until
    /// [`MtOptions::memory_usage`] says they fit
    /// ([`MtOptions::threads_used`]). One thread is always allowed, even
    /// where it takes more: the output is the same whatever the threads. No
    /// limit (`u64::MAX`) by default. See `docs/memory.md`.
    pub memory_limit: u64,
    /// Whose compressor compresses the blocks: [`Library::Zlib`] by
    /// default.
    pub library: Library,
}

impl Default for MtOptions {
    fn default() -> MtOptions {
        MtOptions {
            level: Z_DEFAULT_COMPRESSION,
            strategy: Z_DEFAULT_STRATEGY,
            raw: false,
            threads: Threads::One,
            block_size: 0,
            memory_limit: u64::MAX,
            library: Library::Zlib,
        }
    }
}

impl MtOptions {
    /// The input of each block.
    fn block(&self) -> usize {
        match (self.block_size, self.library) {
            (0, Library::Zlib) => BLOCK_SIZE,
            (0, Library::Libdeflate) => LIBDEFLATE_BLOCK_SIZE,
            (size, _) => size,
        }
    }

    /// `ErrorCode::Stream` where [`Deflate::new`] would give it, or
    /// [`Compressor::new`] would give `None`, for another strategy than
    /// the default with libdeflate, or for a block size over 1 GiB.
    fn check(&self) -> Result<()> {
        let (level, strategy) = match self.library {
            Library::Zlib => (
                (0..=9).contains(&self.level) || self.level == Z_DEFAULT_COMPRESSION,
                (Z_DEFAULT_STRATEGY..=Z_FIXED).contains(&self.strategy),
            ),
            Library::Libdeflate => (
                Compressor::memory_usage(self.level).is_some(),
                self.strategy == Z_DEFAULT_STRATEGY,
            ),
        };
        if !level || !strategy || self.block() > BLOCK_SIZE_MAX {
            return Err(Error::stream());
        }
        Ok(())
    }

    /// The most bytes a [`DeflateMt`] with these options takes, in
    /// `threads` threads (0 is taken for 1): an upper bound, of what it
    /// allocates, whatever the input. `ErrorCode::Stream` where
    /// [`DeflateMt::new`] would give it.
    ///
    /// Each thread keeps a compressor, zlib's 256 KiB and its own state; and
    /// two blocks for each thread are in flight at most, each holding its
    /// input, the 32 KiB before it, and room for what it compresses to;
    /// besides the block being filled and the one being written out. Blocks
    /// of 128 KiB: 0.84 MiB a thread. With [`Library::Libdeflate`], the
    /// compressor is libdeflate's, 0.2 MB at level 1, 0.7 MB at 2 to 9 and
    /// 9 MB at 10 to 12, and a block holds no input before it: blocks of
    /// 1 MiB, 4.2 MiB a thread at level 1, 4.8 MiB at 2 to 9 and 12.6 MiB
    /// at 10 to 12. See `docs/memory.md`.
    pub fn memory_usage(&self, threads: u32) -> Result<u64> {
        self.check()?;
        let threads = u64::from(threads.max(1));
        let block = self.block() as u64;
        let (compressor, dict, room) = match self.library {
            Library::Zlib => (DEFLATE_MEMORY, DICT as u64, output_room(self.block())),
            Library::Libdeflate => (
                Compressor::memory_usage(self.level).unwrap_or(0) + LIBDEFLATE_STATE,
                0,
                Compressor::part_bound(self.block()) as u64,
            ),
        };
        let piece = block + dict + room;
        let per_thread = compressor + 2 * piece;
        Ok(threads
            .saturating_mul(per_thread)
            .saturating_add(piece + MT_MEMORY))
    }

    /// The threads a [`DeflateMt`] with these options compresses in: as many
    /// as [`threads`](MtOptions::threads) says, fewer while
    /// [`memory_usage`](MtOptions::memory_usage) is over
    /// [`memory_limit`](MtOptions::memory_limit), and one at least.
    pub fn threads_used(&self) -> Result<u32> {
        let one = self.memory_usage(1)?;
        let per_thread = self.memory_usage(2)? - one;
        let room = self.memory_limit.saturating_sub(one) / per_thread.max(1);
        let most = u32::try_from(room.saturating_add(1)).unwrap_or(u32::MAX);
        Ok(self.threads.count().min(most).max(1))
    }
}

/// What a compressor takes, at window bits 15 and memory level 8: zlib's
/// window, `prev`, `head` and pending buffer (256 KiB), and the port's
/// state around them, counted high.
const DEFLATE_MEMORY: u64 = 288 << 10;

/// What a libdeflate compressor takes besides what
/// `Compressor::memory_usage` counts: what the allocator rounds up, counted
/// high.
const LIBDEFLATE_STATE: u64 = 16 << 10;

/// What a [`DeflateMt`] takes besides its blocks and compressors: the
/// threads' channels, and itself.
const MT_MEMORY: u64 = 1 << 20;

/// The room a block of `size` bytes is compressed into: zlib's bound for
/// raw deflate at the default window and memory level, and the empty
/// blocks that end it on a byte. More is taken only if a block does not fit,
/// which the bound says it always does.
fn output_room(size: usize) -> u64 {
    let size = size as u64;
    size + (size >> 12) + (size >> 14) + (size >> 25) + 7 + 64
}

/// How a block ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// On a byte, the block after it taking this one's end as its
    /// dictionary: as pigz ends one, with empty fixed blocks where they
    /// make it, a sync marker where they cannot.
    Byte,
    /// With a sync marker, the block after it taking no dictionary
    /// (`Flush::FullFlush`).
    Full,
    /// The last block of the stream.
    Last,
}

/// A block to compress: the input before it, of `dict` bytes, then its own.
struct Job {
    data: Vec<u8>,
    dict: usize,
    library: Library,
    level: i32,
    strategy: i32,
    end: End,
}

/// A block compressed, the CRC-32 of its input, and its size.
struct Block {
    bytes: Vec<u8>,
    crc: u32,
    size: usize,
}

/// What a thread keeps: a compressor, zlib's at its level and strategy, or
/// libdeflate's at its level.
#[derive(Default)]
struct Kept {
    zlib: Option<(i32, i32, Deflate)>,
    libdeflate: Option<Compressor>,
}

/// `job`'s block, compressed with the compressor the thread keeps.
fn compress_block(kept: &mut Kept, job: Job) -> Result<Block> {
    if job.library == Library::Libdeflate {
        return compress_libdeflate(kept, job);
    }
    let deflate = match &mut kept.zlib {
        Some((level, strategy, deflate)) if *level == job.level && *strategy == job.strategy => {
            deflate.reset();
            deflate
        }
        slot => {
            let deflate = Deflate::new(job.level, -15, DEF_MEM_LEVEL, job.strategy)?;
            &mut slot.insert((job.level, job.strategy, deflate)).2
        }
    };
    let (dict, input) = job.data.split_at(job.dict);
    if !dict.is_empty() {
        deflate.set_dictionary(dict)?;
    }
    let mut bytes = Vec::with_capacity(output_room(input.len()) as usize);
    let mut input = InBuffer::new(input);
    match job.end {
        End::Last => engine(deflate, &mut bytes, &mut input, Flush::Finish)?,
        End::Full => engine(deflate, &mut bytes, &mut input, Flush::SyncFlush)?,
        End::Byte => {
            // pigz's: the block's codes, then empty fixed blocks of 10 bits
            // until the end is on a byte, which an odd number of bits left
            // cannot reach: a sync marker then.
            engine(deflate, &mut bytes, &mut input, Flush::Block)?;
            let (_, bits) = deflate.pending();
            if bits & 1 != 0 {
                engine(deflate, &mut bytes, &mut input, Flush::SyncFlush)?;
            } else if bits & 7 != 0 {
                loop {
                    deflate.prime(10, 2)?;
                    if deflate.pending().1 & 7 == 0 {
                        break;
                    }
                }
                engine(deflate, &mut bytes, &mut input, Flush::Block)?;
            }
        }
    }
    Ok(Block {
        bytes,
        crc: crc32(0, input.src),
        size: input.src.len(),
    })
}

/// `job`'s block, compressed alone by libdeflate's compressor: the last
/// with [`Compressor::deflate_compress`], every other with
/// [`Compressor::deflate_compress_part`], which ends it with a sync marker.
fn compress_libdeflate(kept: &mut Kept, job: Job) -> Result<Block> {
    let compressor = match &mut kept.libdeflate {
        Some(compressor) if compressor.compression_level() as i32 == job.level => compressor,
        slot => slot.insert(Compressor::new(job.level).ok_or_else(Error::stream)?),
    };
    let input = &job.data[job.dict..];
    let mut bytes = vec![0; Compressor::part_bound(input.len())];
    let size = match job.end {
        End::Last => compressor.deflate_compress(input, &mut bytes),
        End::Byte | End::Full => compressor.deflate_compress_part(input, &mut bytes),
    };
    if size == 0 {
        // The bound says it always fits.
        return Err(Error::new(ErrorCode::Stream, Some("a block did not fit")));
    }
    bytes.truncate(size);
    Ok(Block {
        bytes,
        crc: crc32(0, input),
        size: input.len(),
    })
}

/// [`Deflate::deflate`] with `flush`, until it leaves room in `out`, which
/// grows if it must: pigz's `deflate_engine`. `ErrorCode::Buf`, which says
/// only that there was nothing to do, is not an error here.
fn engine(
    deflate: &mut Deflate,
    out: &mut Vec<u8>,
    input: &mut InBuffer<'_>,
    flush: Flush,
) -> Result<()> {
    loop {
        if out.len() == out.capacity() {
            out.reserve(64 << 10);
        }
        let at = out.len();
        let room = out.capacity();
        out.resize(room, 0);
        let mut output = OutBuffer::new(&mut out[at..]);
        let result = deflate.deflate(&mut output, input, flush);
        let end = at + output.pos;
        out.truncate(end);
        match result {
            Ok(_) => {}
            Err(e) if e.code() == ErrorCode::Buf => {}
            Err(e) => return Err(e),
        }
        if end < room {
            return Ok(());
        }
    }
}

/// A block whose thread panicked.
fn lost() -> Result<Block> {
    Err(Error::new(
        ErrorCode::Stream,
        Some("a compressing thread failed"),
    ))
}

/// Where a [`DeflateMt`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Running,
    /// `Flush::Finish` asked for: whether the last block is given to a
    /// thread, and the trailer to write out.
    Finishing {
        last: bool,
        trailer: bool,
    },
    /// The stream ended.
    Done,
}

/// A compressor that writes one deflate stream, in a gzip member unless
/// raw, its blocks compressed in threads: as pigz writes it.
///
/// It is used as [`Deflate`] is, a call at a time with an output, an input
/// and a [`Flush`], so that one can take the other's place. The input is
/// cut into blocks of [`MtOptions::block_size`], each compressed by a
/// [`Deflate`] of its own with the 32 KiB of input before it as its
/// dictionary, and ended on a byte; a flush, or the end, cuts a block
/// short. The output is the same whatever [`MtOptions::threads`] says, one
/// thread too: it depends only on the input, the options and where the
/// flushes are. At the default block size and without flushes, it is
/// pigz 2.8's, byte for byte, but for gzip's header, which has neither a
/// name nor a time, as [`Deflate`]'s has not.
///
/// With [`Library::Libdeflate`], each block is compressed by libdeflate's
/// [`Compressor`] instead, alone, in blocks of [`LIBDEFLATE_BLOCK_SIZE`] by
/// default, every one but the last ended with a sync marker
/// ([`Compressor::deflate_compress_part`]). The output is the same whatever
/// the threads too.
///
/// With [`Threads::One`], each block is compressed in the call that fills
/// it. With more, at most two blocks for each thread are in flight, and a
/// call waits for the oldest of them when it can go no further without.
/// [`MtOptions::memory_limit`] lowers the threads to fit what
/// [`MtOptions::memory_usage`] counts.
pub struct DeflateMt {
    library: Library,
    level: i32,
    strategy: i32,
    raw: bool,
    block_size: usize,
    workers: Workers<Kept, Job, Result<Block>>,
    threads: u32,
    /// The blocks in flight at most.
    in_flight: usize,
    /// The next block: the input before it that it takes as its dictionary,
    /// of `dict` bytes, then its own.
    piece: Vec<u8>,
    dict: usize,
    /// The most input before a block that it takes: 32 KiB, none with
    /// libdeflate.
    dict_max: usize,
    /// What is being written out, and how much of it is.
    out: Vec<u8>,
    out_pos: usize,
    /// The CRC-32 and size of the input of the blocks written out.
    crc: u32,
    size: u64,
    mode: Mode,
    /// The error that every later call returns.
    failed: Option<Error>,
    total_in: u64,
    total_out: u64,
}

impl DeflateMt {
    /// A compressor with `options`: `ErrorCode::Stream` where
    /// [`Deflate::new`] would give it, or [`Compressor::new`] `None` with
    /// [`Library::Libdeflate`], for another strategy than the default with
    /// it, or for a block size over 1 GiB.
    pub fn new(options: &MtOptions) -> Result<DeflateMt> {
        let threads = options.threads_used()?;
        let level = match options.level {
            Z_DEFAULT_COMPRESSION => 6,
            level => level,
        };
        let out = if options.raw {
            Vec::new()
        } else {
            // zlib's header, without a name or a time: the extra flags say
            // the slowest or the fastest. libdeflate's gzip header says them
            // for its own levels.
            let xfl = match options.library {
                Library::Zlib if level == 9 => 2,
                Library::Zlib if options.strategy >= Z_HUFFMAN_ONLY || level < 2 => 4,
                Library::Libdeflate if level < 2 => 4,
                Library::Libdeflate if level >= 8 => 2,
                _ => 0,
            };
            vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, xfl, OS_CODE]
        };
        Ok(DeflateMt {
            library: options.library,
            level,
            strategy: options.strategy,
            raw: options.raw,
            block_size: options.block(),
            workers: Workers::new(threads, "hivepack-deflate", compress_block, lost),
            threads,
            in_flight: 2 * threads as usize,
            piece: Vec::new(),
            dict: 0,
            dict_max: match options.library {
                Library::Zlib => DICT,
                Library::Libdeflate => 0,
            },
            out,
            out_pos: 0,
            crc: 0,
            size: 0,
            mode: Mode::Running,
            failed: None,
            total_in: 0,
            total_out: 0,
        })
    }

    /// Reads what it can of `input`, and writes what it can to `output`, as
    /// [`Deflate::deflate`] does: it returns once all of `input` is read,
    /// or `output` is full.
    ///
    /// - `Flush::NoFlush` takes input, and writes out the blocks made.
    ///   When the blocks in flight are two for each thread, it waits for the
    ///   oldest, if there is room to write it.
    /// - `Flush::SyncFlush` ends the current block on a byte once the input
    ///   given is read, and writes out every block: what was given can then
    ///   be decompressed. `Flush::FullFlush` does the same with a sync
    ///   marker, and the block after it takes no dictionary. With
    ///   [`Library::Libdeflate`], whose blocks take none, both end the block
    ///   with a sync marker, as every block but the last ends. Either is done
    ///   when it returns with room left in `output`; till then, call again
    ///   with the same flush. A flush with nothing given since the last one
    ///   writes nothing, where zlib writes an empty block.
    /// - `Flush::Finish` does the same, then ends the stream:
    ///   `Status::StreamEnd` once all of it is written out, and on every
    ///   later call with `Flush::Finish`.
    ///
    /// `Flush::PartialFlush`, `Flush::Block` and `Flush::Trees` are refused
    /// with `ErrorCode::Stream`, and so is any flush but `Flush::Finish` once
    /// it is asked for. An error of a block's is returned by every later
    /// call.
    pub fn deflate(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        flush: Flush,
    ) -> Result<Status> {
        if output.pos > output.dst.len() || input.pos > input.src.len() {
            return Err(Error::stream());
        }
        if let Some(e) = self.failed {
            return Err(e);
        }
        match (self.mode, flush) {
            (_, Flush::PartialFlush | Flush::Block | Flush::Trees) => {
                return Err(Error::stream());
            }
            (Mode::Done, Flush::Finish) => return Ok(Status::StreamEnd),
            (Mode::Done, _)
            | (Mode::Finishing { .. }, Flush::NoFlush | Flush::SyncFlush | Flush::FullFlush) => {
                return Err(Error::stream());
            }
            (Mode::Running, Flush::Finish) => {
                self.mode = Mode::Finishing {
                    last: false,
                    trailer: false,
                };
            }
            _ => {}
        }
        let result = self.run(output, input, flush);
        if let Err(e) = result {
            self.failed = Some(e);
        }
        result
    }

    /// The bytes read so far.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// The bytes written so far.
    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// The threads it compresses in, as [`MtOptions::threads_used`] said.
    pub fn threads(&self) -> u32 {
        self.threads
    }

    fn run(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        flush: Flush,
    ) -> Result<Status> {
        loop {
            if !self.write_out(output)? {
                return Ok(Status::Ok);
            }
            let filled = self.piece.len() - self.dict;
            let more = input.pos < input.src.len();
            // A full block is given once more input says it is not the last.
            if more && filled == self.block_size {
                self.give(End::Byte)?;
                continue;
            }
            if more {
                self.take(input);
                continue;
            }
            // All of the input is read.
            match (flush, self.mode) {
                (Flush::NoFlush, _) => return Ok(Status::Ok),
                (Flush::SyncFlush | Flush::FullFlush, _) => {
                    let full = flush == Flush::FullFlush;
                    if filled > 0 {
                        self.give(if full { End::Full } else { End::Byte })?;
                        continue;
                    }
                    if full {
                        self.piece.clear();
                        self.dict = 0;
                    }
                    if !self.next_block(true)? {
                        return Ok(Status::Ok);
                    }
                }
                (_, Mode::Finishing { last: false, .. }) => {
                    self.give(End::Last)?;
                }
                (
                    _,
                    Mode::Finishing {
                        last: true,
                        trailer,
                    },
                ) => {
                    if self.next_block(true)? {
                        continue;
                    }
                    if !trailer {
                        self.mode = Mode::Finishing {
                            last: true,
                            trailer: true,
                        };
                        if !self.raw {
                            self.out = Vec::with_capacity(8);
                            self.out.extend_from_slice(&self.crc.to_le_bytes());
                            // ISIZE: the size modulo 2^32.
                            self.out
                                .extend_from_slice(&(self.size as u32).to_le_bytes());
                            self.out_pos = 0;
                        }
                        continue;
                    }
                    self.mode = Mode::Done;
                    return Ok(Status::StreamEnd);
                }
                _ => return Ok(Status::Ok),
            }
        }
    }

    /// What of `input` fits in the block.
    fn take(&mut self, input: &mut InBuffer<'_>) {
        if self.piece.capacity() == 0 {
            self.piece.reserve_exact(self.dict_max + self.block_size);
        }
        let filled = self.piece.len() - self.dict;
        let n = (self.block_size - filled).min(input.src.len() - input.pos);
        self.piece
            .extend_from_slice(&input.src[input.pos..input.pos + n]);
        input.pos += n;
        self.total_in += n as u64;
    }

    /// The block given to a thread, ended as `end` says, if fewer than the
    /// most are in flight; else the oldest waited for, to write out.
    fn give(&mut self, end: End) -> Result<()> {
        if self.workers.pending() >= self.in_flight {
            self.next_block(true)?;
            return Ok(());
        }
        let data = std::mem::take(&mut self.piece);
        let dict = self.dict;
        self.dict = 0;
        if end == End::Byte && self.dict_max > 0 {
            // The next block takes the end of this one's input, and of the
            // input before it, as its dictionary.
            let kept = data.len().min(self.dict_max);
            self.piece.reserve_exact(self.dict_max + self.block_size);
            self.piece.extend_from_slice(&data[data.len() - kept..]);
            self.dict = kept;
        }
        if end == End::Last {
            self.mode = Mode::Finishing {
                last: true,
                trailer: false,
            };
        }
        self.workers.give(Job {
            data,
            dict,
            library: self.library,
            level: self.level,
            strategy: self.strategy,
            end,
        });
        Ok(())
    }

    /// The oldest block in flight, to write out: waited for with `wait`.
    /// Whether there was one.
    fn next_block(&mut self, wait: bool) -> Result<bool> {
        let next = if wait {
            self.workers.take()
        } else {
            self.workers.try_take()
        };
        let Some(block) = next else {
            return Ok(false);
        };
        let block = block?;
        self.crc = crc32_combine(self.crc, block.crc, block.size as i64);
        self.size += block.size as u64;
        self.out = block.bytes;
        self.out_pos = 0;
        Ok(true)
    }

    /// Writes out what it can, and the blocks made, without waiting.
    /// Whether all is written out: false when `output` is full.
    fn write_out(&mut self, output: &mut OutBuffer<'_>) -> Result<bool> {
        loop {
            let n = (self.out.len() - self.out_pos).min(output.dst.len() - output.pos);
            output.dst[output.pos..output.pos + n]
                .copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
            output.pos += n;
            self.out_pos += n;
            self.total_out += n as u64;
            if self.out_pos < self.out.len() {
                return Ok(false);
            }
            if !self.next_block(false)? {
                return Ok(true);
            }
        }
    }
}

impl std::fmt::Debug for DeflateMt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeflateMt")
            .field("library", &self.library)
            .field("level", &self.level)
            .field("strategy", &self.strategy)
            .field("raw", &self.raw)
            .field("block_size", &self.block_size)
            .field("threads", &self.threads)
            .field("total_in", &self.total_in)
            .field("total_out", &self.total_out)
            .finish_non_exhaustive()
    }
}
