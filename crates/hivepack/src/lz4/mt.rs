//! An LZ4 frame of independent blocks, each compressed in a thread, as
//! `lz4 -T` writes it: the input cut into blocks of the frame's block size,
//! each compressed by a [`CompressionContext`] of its own thread, and the
//! blocks written in order between the frame's header and its end. Not part
//! of the port: liblz4's frame API has no threads.
//!
//! Each block is what the port's [`CompressionContext`] makes of it in a
//! frame of independent blocks, and the header and the end are its own, so
//! the frame is [`compress_frame`](crate::lz4::frame::compress_frame)'s,
//! byte for byte, with the same preferences: the same whatever the threads,
//! one or many.

use std::io::{self, Write};

use crate::Threads;
use crate::lz4::lz4frame::{BlockMode, BlockSizeId, Error, FrameInfo, Result, get_block_size};
use crate::lz4::lz4frame_compress::{CompressionContext, Preferences, compress_bound};
use crate::lz4::xxhash::Xxh32;
use crate::workers::Workers;

/// How an [`EncoderMt`] compresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MtOptions {
    /// The level, as [`Preferences::compression_level`] takes it: below 2,
    /// the fast compressor (a negative level is faster still); 2 to 12, high
    /// compression. 0 by default.
    pub level: i32,
    /// The size of each block, which is what a thread compresses at once:
    /// 4 MB by default, as `lz4` writes.
    pub block_size: BlockSizeId,
    /// A checksum of the content at the frame's end, as `lz4` writes: on by
    /// default. It is computed on the caller's thread as the input comes.
    pub content_checksum: bool,
    /// A checksum after each block, computed in its thread. Off by default.
    pub block_checksum: bool,
    /// The threads, besides the caller's, that compress the blocks.
    pub threads: Threads,
    /// The most bytes compressing may take: the threads are lowered until
    /// [`MtOptions::memory_usage`] says they fit
    /// ([`MtOptions::threads_used`]). One thread is always allowed: the
    /// frame is the same whatever the threads. No limit (`u64::MAX`) by
    /// default.
    pub memory_limit: u64,
}

impl Default for MtOptions {
    fn default() -> MtOptions {
        MtOptions {
            level: 0,
            block_size: BlockSizeId::Max4Mb,
            content_checksum: true,
            block_checksum: false,
            threads: Threads::One,
            memory_limit: u64::MAX,
        }
    }
}

/// What a context takes besides its blocks, counted high: high
/// compression's tables (256 KiB of hash, 128 KiB of chains) and its state.
const CONTEXT_MEMORY: u64 = 512 << 10;

/// What an [`EncoderMt`] takes besides its threads: itself, and its
/// threads' channels.
const MT_MEMORY: u64 = 1 << 20;

impl MtOptions {
    /// The preferences each block is compressed with: the frame's, in
    /// independent blocks.
    fn preferences(&self) -> Preferences {
        Preferences {
            frame_info: FrameInfo {
                block_size_id: self.block_size,
                block_mode: BlockMode::Independent,
                content_checksum: self.content_checksum,
                block_checksum: self.block_checksum,
                ..FrameInfo::default()
            },
            compression_level: self.level,
            ..Preferences::default()
        }
    }

    /// The input of each block.
    fn block(&self) -> usize {
        get_block_size(self.block_size)
    }

    /// The most bytes an [`EncoderMt`] with these options takes, in
    /// `threads` threads (0 is taken for 1): an upper bound. Each thread
    /// keeps a context; two blocks for each thread are in flight at most,
    /// each holding its input and room for what it compresses to; besides
    /// the block being filled. Blocks of 4 MB: 16.5 MiB a thread.
    pub fn memory_usage(&self, threads: u32) -> u64 {
        let threads = u64::from(threads.max(1));
        let block = self.block() as u64;
        let piece = block + compress_bound(self.block(), Some(&self.preferences())) as u64;
        threads
            .saturating_mul(CONTEXT_MEMORY + 2 * piece)
            .saturating_add(block + MT_MEMORY)
    }

    /// The threads an [`EncoderMt`] with these options compresses in: as
    /// many as [`threads`](MtOptions::threads) says, fewer while
    /// [`memory_usage`](MtOptions::memory_usage) is over
    /// [`memory_limit`](MtOptions::memory_limit), and one at least.
    pub fn threads_used(&self) -> u32 {
        let one = self.memory_usage(1);
        let per_thread = self.memory_usage(2) - one;
        let room = self.memory_limit.saturating_sub(one) / per_thread.max(1);
        let most = u32::try_from(room.saturating_add(1)).unwrap_or(u32::MAX);
        self.threads.count().min(most).max(1)
    }
}

/// A block to compress, with the preferences to compress it with.
type Job = (Preferences, Vec<u8>);

/// A block compressed, with its header and its checksum if it has one.
type Block = Result<Vec<u8>>;

/// `job`'s block, by the context the thread keeps: a frame begun once, in
/// independent blocks, each `compress_update` then one block of it.
fn compress_block(context: &mut Option<Box<CompressionContext>>, (prefs, data): Job) -> Block {
    let mut scratch = [0; 32];
    let context = match context {
        Some(context) => context,
        None => {
            let mut made = Box::new(CompressionContext::new());
            made.compress_begin(&mut scratch, Some(&prefs))?;
            context.insert(made)
        }
    };
    let mut out = vec![0; compress_bound(data.len(), Some(&prefs))];
    let mut size = context.compress_update(&mut out, &data)?;
    // A block smaller than the block size waits in the context for more:
    // flushed, as the frame's last.
    size += context.flush(&mut out[size..])?;
    out.truncate(size);
    Ok(out)
}

/// A block whose thread panicked.
fn lost() -> Block {
    Err(Error::Generic)
}

/// Writes one LZ4 frame of independent blocks, as an [`std::io::Write`], its
/// blocks compressed in threads: as [`Encoder`](crate::lz4::Encoder) is used,
/// [`EncoderMt::finish`] ending the frame. The frame is the same whatever
/// the threads.
///
/// With [`Threads::One`], each block is compressed in the call that fills
/// it. With more, at most two blocks for each thread are in flight, and a
/// call waits for the oldest when it can go no further without.
pub struct EncoderMt<W: Write> {
    out: W,
    /// The blocks' preferences: the frame's, without the content checksum,
    /// which the caller's thread computes, and which does not change them.
    prefs: Preferences,
    block_size: usize,
    workers: Workers<Option<Box<CompressionContext>>, Job, Block>,
    in_flight: usize,
    /// The input of the next block.
    block: Vec<u8>,
    xxh: Option<Xxh32>,
    total_in: u64,
}

impl<W: Write> EncoderMt<W> {
    /// An encoder into `out` with `options`, the frame's header written:
    /// [`Error::MaxBlockSizeInvalid`] for [`BlockSizeId::Default`].
    pub fn new(mut out: W, options: &MtOptions) -> io::Result<EncoderMt<W>> {
        if options.block_size == BlockSizeId::Default {
            return Err(io::Error::other(Error::MaxBlockSizeInvalid));
        }
        let prefs = options.preferences();
        let mut header = [0; 32];
        let size = CompressionContext::new()
            .compress_begin(&mut header, Some(&prefs))
            .map_err(io::Error::other)?;
        out.write_all(&header[..size])?;
        let threads = options.threads_used();
        let mut blocks = prefs;
        blocks.frame_info.content_checksum = false;
        Ok(EncoderMt {
            out,
            prefs: blocks,
            block_size: options.block(),
            workers: Workers::new(threads, "hivepack-lz4", compress_block, lost),
            in_flight: 2 * threads as usize,
            block: Vec::new(),
            xxh: options.content_checksum.then(|| Xxh32::new(0)),
            total_in: 0,
        })
    }

    /// The bytes given so far.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// The output, as far as the blocks written out have come.
    pub fn get_ref(&self) -> &W {
        &self.out
    }

    /// The output, to take what is written out so far: what is taken from
    /// it is not given back.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.out
    }

    /// The block filled given to a thread, and the blocks done written out
    /// while as many as the threads may hold are in flight.
    fn give(&mut self) -> io::Result<()> {
        let data = std::mem::replace(&mut self.block, Vec::with_capacity(self.block_size));
        self.workers.give((self.prefs, data));
        while self.workers.pending() >= self.in_flight {
            self.write_next()?;
        }
        Ok(())
    }

    /// The oldest block, waited for and written out; whether there was one.
    fn write_next(&mut self) -> io::Result<bool> {
        match self.workers.take() {
            Some(block) => {
                self.out.write_all(&block.map_err(io::Error::other)?)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Ends the frame: the last block, every block written out, the end
    /// mark and the content checksum. Gives the output back.
    pub fn finish(mut self) -> io::Result<W> {
        if !self.block.is_empty() {
            self.give()?;
        }
        while self.write_next()? {}
        let mut end = Vec::with_capacity(8);
        end.extend_from_slice(&0u32.to_le_bytes());
        if let Some(xxh) = &self.xxh {
            end.extend_from_slice(&xxh.digest().to_le_bytes());
        }
        self.out.write_all(&end)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

impl<W: Write> Write for EncoderMt<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let given = buf.len();
        if let Some(xxh) = &mut self.xxh {
            xxh.update(buf);
        }
        self.total_in += given as u64;
        while !buf.is_empty() {
            if self.block.capacity() == 0 {
                self.block.reserve_exact(self.block_size);
            }
            let n = (self.block_size - self.block.len()).min(buf.len());
            self.block.extend_from_slice(&buf[..n]);
            buf = &buf[n..];
            if self.block.len() == self.block_size {
                self.give()?;
            }
        }
        Ok(given)
    }

    /// The output's `flush`: the blocks are not ended early, which would
    /// change them.
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}
