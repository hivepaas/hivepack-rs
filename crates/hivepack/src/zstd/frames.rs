//! zstd in threads, in frames of a fixed size: the input cut into pieces of
//! [`FRAME_SIZE`], each compressed into a frame of its own in a thread, the
//! frames one after the other, and a seek table after them, as zstd's
//! seekable format has it (`contrib/seekable_format` in zstd's sources).
//!
//! Not part of the port: libzstd's workers ([`CParameter::NbWorkers`]) make
//! one frame, which one thread decodes. Frames of their own are decoded a
//! frame in each thread, and read by every zstd reader as one stream: `zstd`,
//! `pzstd`, GNU tar, 7-Zip and Python's `compression.zstd` among them, which
//! pass over the seek table, a skippable frame. Each frame is
//! [`CCtx::compress2`]'s, byte for byte.
//!
//! The pieces are cut where their size says, never where the threads would:
//! the output is the same whatever the threads, one or many.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::Threads;
use crate::workers::Workers;
use crate::zstd::{
    CCtx, CParameter, EndDirective, Error, ErrorCode, InBuffer, OutBuffer, ResetDirective, Result,
    compress_bound,
};

/// The input of each frame by default: 32 MiB. Each frame costs a little of
/// what one frame would compress to, more at the higher levels, whose window
/// is larger: on 546 MB of mixed files, 0.01% at level 1, 0.04% at 3, 0.17%
/// at 9 and 0.48% at 19 (with `zstd` 1.5.7).
pub const FRAME_SIZE: usize = 32 << 20;

/// The largest input of a frame: its sizes stay well within the seek
/// table's 32 bits, compressed too.
const FRAME_SIZE_MAX: usize = 1 << 30;

/// The most frames a seek table has, as libzstd's seekable format allows
/// (`ZSTD_SEEKABLE_MAXFRAMES`).
const MAX_FRAMES: usize = 0x800_0000;

/// The magic number of the skippable frame that holds the seek table.
const SEEK_TABLE_MAGIC: u32 = 0x184D_2A5E;

/// The magic number that ends the seek table (`ZSTD_SEEKABLE_MAGICNUMBER`).
const SEEKABLE_MAGIC: u32 = 0x8F92_EAB1;

/// How a [`CompressFrames`] compresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FramesOptions {
    /// The level of each frame, as [`CParameter::CompressionLevel`] takes it:
    /// 3 by default.
    pub level: i32,
    /// Each frame with a checksum of its content
    /// ([`CParameter::ChecksumFlag`]), as `zstd` writes one: on by default.
    pub checksum: bool,
    /// The threads, besides the caller's, that compress the frames.
    pub threads: Threads,
    /// The input of each frame, or 0 for [`FRAME_SIZE`]; at most 1 GiB.
    pub frame_size: usize,
    /// The seek table after the frames, which says where each frame starts
    /// in the input and in the output, for a reader that seeks: on by
    /// default. 8 bytes a frame, and 17.
    pub seek_table: bool,
    /// The most bytes compressing may take: the threads are lowered until
    /// [`FramesOptions::memory_usage`] says they fit
    /// ([`FramesOptions::threads_used`]). One thread is always allowed, even
    /// where it takes more: the output is the same whatever the threads. No
    /// limit (`u64::MAX`) by default. See `docs/memory.md`.
    pub memory_limit: u64,
}

impl Default for FramesOptions {
    fn default() -> FramesOptions {
        FramesOptions {
            level: crate::zstd::default_c_level(),
            checksum: true,
            threads: Threads::One,
            frame_size: 0,
            seek_table: true,
            memory_limit: u64::MAX,
        }
    }
}

impl FramesOptions {
    /// The input of each frame.
    fn frame(&self) -> usize {
        match self.frame_size {
            0 => FRAME_SIZE,
            size => size,
        }
    }

    /// The most bytes a [`CompressFrames`] with these options takes, in
    /// `threads` threads (0 is taken for 1): an upper bound, of what it
    /// allocates, whatever the input. [`ErrorCode::ParameterOutOfBound`] for
    /// a frame size over 1 GiB.
    ///
    /// Each thread keeps a context, as [`CCtx::estimate_memory`] counts one
    /// for a frame of [`FramesOptions::frame_size`]; and each frame in flight,
    /// one for each thread and the one being filled, holds its input and
    /// room for its frame ([`compress_bound`]). Level 3, of 32 MiB frames:
    /// 69 MiB a thread; level 19: 155 MiB.
    pub fn memory_usage(&self, threads: u32) -> Result<u64> {
        let frame = self.frame();
        if frame > FRAME_SIZE_MAX {
            return Err(Error::from(ErrorCode::ParameterOutOfBound));
        }
        let threads = u64::from(threads.max(1));
        let context = frame_context(self.level, self.checksum, frame)?.estimate_memory(0)?;
        let bound = compress_bound(frame).ok_or(Error::from(ErrorCode::ParameterOutOfBound))?;
        let in_flight = (frame + bound) as u64;
        Ok(threads
            .saturating_mul(context.saturating_add(in_flight))
            .saturating_add(in_flight + MT_MEMORY))
    }

    /// The threads a [`CompressFrames`] with these options compresses in: as
    /// many as [`threads`](FramesOptions::threads) says, fewer while
    /// [`memory_usage`](FramesOptions::memory_usage) is over
    /// [`memory_limit`](FramesOptions::memory_limit), and one at least.
    pub fn threads_used(&self) -> Result<u32> {
        let one = self.memory_usage(1)?;
        let per_thread = self.memory_usage(2)? - one;
        let room = self.memory_limit.saturating_sub(one) / per_thread.max(1);
        let most = u32::try_from(room.saturating_add(1)).unwrap_or(u32::MAX);
        Ok(self.threads.count().min(most).max(1))
    }
}

/// What a [`CompressFrames`] takes besides its frames and contexts: the
/// threads' channels, the seek table of a terabyte, and itself.
const MT_MEMORY: u64 = 1 << 20;

/// A context set for a frame of `size` bytes at `level`, with or without a
/// checksum.
fn frame_context(level: i32, checksum: bool, size: usize) -> Result<CCtx> {
    let mut cctx = CCtx::new();
    set_frame(&mut cctx, level, checksum)?;
    cctx.set_pledged_src_size(size as u64)?;
    Ok(cctx)
}

/// `cctx` set back to its defaults, then to `level` and `checksum`.
fn set_frame(cctx: &mut CCtx, level: i32, checksum: bool) -> Result<()> {
    cctx.reset(ResetDirective::SessionAndParameters)?;
    cctx.set_parameter(CParameter::CompressionLevel(level))?;
    cctx.set_parameter(CParameter::ChecksumFlag(checksum))
}

/// A piece, to make a frame of.
struct Job {
    piece: Vec<u8>,
    level: i32,
    checksum: bool,
    /// Where the piece is counted once it is compressed.
    compressed: Arc<AtomicU64>,
}

/// A frame, and the size of its content.
type Frame = Result<(Vec<u8>, usize)>;

/// `job`'s piece as one frame, with the context the thread keeps.
fn compress_frame(cctx: &mut Option<Box<CCtx>>, job: Job) -> Frame {
    let cctx = cctx.get_or_insert_with(|| Box::new(CCtx::new()));
    set_frame(cctx, job.level, job.checksum)?;
    let bound = compress_bound(job.piece.len()).ok_or(Error::from(ErrorCode::SrcSizeWrong))?;
    let mut frame = vec![0; bound];
    let size = cctx.compress2(&mut frame, &job.piece)?;
    job.compressed
        .fetch_add(job.piece.len() as u64, Ordering::Relaxed);
    frame.truncate(size);
    frame.shrink_to_fit();
    Ok((frame, job.piece.len()))
}

/// A frame whose thread panicked.
fn lost() -> Frame {
    Err(Error::from(ErrorCode::Generic))
}

/// Where a [`CompressFrames`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Running,
    /// A flush, or the end, asked for and not done.
    Ending {
        finish: bool,
    },
}

/// A compressor that writes zstd frames of a fixed input each, one after the
/// other, each compressed in a thread, and a seek table after them: zstd's
/// seekable format.
///
/// It is used as [`CCtx::compress_stream2`] is, a call at a time with an
/// input, an output and an [`EndDirective`], so that one can take the other's
/// place. The input is cut into pieces of [`FramesOptions::frame_size`], each
/// made a frame of its own by [`CCtx::compress2`], with its content size in
/// its header (a flush, or the end, cuts a piece short), and the frames come
/// out in order. The output is the same whatever [`FramesOptions::threads`]
/// says, one thread too: it depends only on the input, the options and where
/// the flushes are.
///
/// With one thread, each frame is compressed in the call that fills its
/// piece. With more, a frame for each thread is in flight at most, and a call
/// waits for the oldest when it can go no further without.
/// [`FramesOptions::memory_limit`] lowers the threads to fit what
/// [`FramesOptions::memory_usage`] counts.
pub struct CompressFrames {
    level: i32,
    checksum: bool,
    frame_size: usize,
    seek_table: bool,
    workers: Workers<Option<Box<CCtx>>, Job, Frame>,
    /// The frames in flight at most.
    in_flight: usize,
    /// The input of the next frame.
    piece: Vec<u8>,
    /// What is being written out, and how much of it is.
    out: Vec<u8>,
    out_pos: usize,
    /// The seek table's entries: each frame's size, and its content's.
    entries: Vec<(u32, u32)>,
    /// A frame was started since the stream was: without one, the end
    /// writes an empty frame, as `zstd` does for an empty input.
    started: bool,
    /// The seek table is being written out, the frames all are.
    table_out: bool,
    mode: Mode,
    /// The error that every later call returns.
    failed: Option<Error>,
    total_in: u64,
    total_out: u64,
    /// The input of the frames compressed, counted by the threads.
    compressed: Arc<AtomicU64>,
}

impl CompressFrames {
    /// A compressor with `options`: [`ErrorCode::ParameterOutOfBound`] for a
    /// frame size over 1 GiB.
    pub fn new(options: &FramesOptions) -> Result<CompressFrames> {
        let threads = options.threads_used()?;
        let in_flight = threads as usize;
        Ok(CompressFrames {
            level: options.level,
            checksum: options.checksum,
            frame_size: options.frame(),
            seek_table: options.seek_table,
            workers: Workers::new(threads, "hivepack-zstd", compress_frame, lost),
            in_flight,
            piece: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            entries: Vec::new(),
            started: false,
            table_out: false,
            mode: Mode::Running,
            failed: None,
            total_in: 0,
            total_out: 0,
            compressed: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Reads what it can of `input`, and writes what it can to `output`, as
    /// [`CCtx::compress_stream2`] does. Returns how much is left to write out,
    /// at least: 0 when all is.
    ///
    /// - [`EndDirective::Continue`] takes input, and writes out the frames
    ///   made. When the frames in flight are as many as the threads, it waits
    ///   for the oldest, if there is room to write it.
    /// - [`EndDirective::Flush`] ends the current frame once the input given
    ///   is read, and writes out every frame. What follows starts a new frame.
    /// - [`EndDirective::End`] does the same, then writes the seek table:
    ///   the stream is complete when it returns 0, and what follows starts
    ///   another.
    ///
    /// Once a flush or the end is asked for, every call until it returns 0
    /// must ask for it again: another is refused with
    /// [`ErrorCode::StageWrong`], and changes nothing. An error of a frame's
    /// is returned by every later call.
    pub fn compress_stream(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        directive: EndDirective,
    ) -> Result<usize> {
        if output.pos > output.dst.len() {
            return Err(Error::from(ErrorCode::DstSizeTooSmall));
        }
        if input.pos > input.src.len() {
            return Err(Error::from(ErrorCode::SrcSizeWrong));
        }
        if let Some(e) = self.failed {
            return Err(e);
        }
        let finish = match (self.mode, directive) {
            (Mode::Running, EndDirective::Continue) => None,
            (Mode::Running, EndDirective::Flush) => Some(false),
            (Mode::Running, EndDirective::End) => Some(true),
            (Mode::Ending { finish: false }, EndDirective::Flush) => Some(false),
            (Mode::Ending { finish: true }, EndDirective::End) => Some(true),
            _ => return Err(Error::from(ErrorCode::StageWrong)),
        };
        let result = match finish {
            None => self.run(output, input),
            Some(finish) => {
                self.mode = Mode::Ending { finish };
                self.end(output, input, finish)
            }
        };
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

    /// The bytes read so far whose frames are compressed, as
    /// `ZSTD_getFrameProgression` says of a stream's `consumed`:
    /// [`CompressFrames::total_in`] less the frames in flight and the piece
    /// not yet a frame. With more than one thread, read takes up to a frame
    /// for each thread before they are compressed, so this, not
    /// `total_in`, is how far the compression has gone. It counts a frame
    /// as its thread ends it, before it is written out.
    pub fn consumed(&self) -> u64 {
        self.compressed.load(Ordering::Relaxed)
    }

    /// The threads it compresses in, as [`FramesOptions::threads_used`] said.
    pub fn threads(&self) -> u32 {
        self.in_flight as u32
    }

    /// [`EndDirective::Continue`].
    fn run(&mut self, output: &mut OutBuffer<'_>, input: &mut InBuffer<'_>) -> Result<usize> {
        loop {
            if !self.write_out(output, false)? {
                break;
            }
            if self.piece.len() == self.frame_size {
                if self.workers.pending() < self.in_flight {
                    self.submit()?;
                } else {
                    self.next_frame(true)?;
                }
                continue;
            }
            if input.pos == input.src.len() {
                break;
            }
            self.take(input);
        }
        Ok(self.out.len() - self.out_pos)
    }

    /// [`EndDirective::Flush`] and [`EndDirective::End`].
    fn end(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        finish: bool,
    ) -> Result<usize> {
        loop {
            if !self.write_out(output, false)? {
                break;
            }
            let all_read = input.pos == input.src.len();
            if self.piece.len() == self.frame_size || (all_read && !self.piece.is_empty()) {
                if self.workers.pending() < self.in_flight {
                    self.submit()?;
                } else {
                    self.next_frame(true)?;
                }
                continue;
            }
            if !all_read {
                self.take(input);
                continue;
            }
            if finish && !self.started {
                self.submit()?;
                continue;
            }
            if self.workers.pending() > 0 {
                self.next_frame(true)?;
                continue;
            }
            if finish && self.seek_table && !self.table_out {
                self.out = seek_table(&self.entries);
                self.out_pos = 0;
                self.table_out = true;
                continue;
            }
            // All written out.
            if finish {
                self.entries.clear();
                self.started = false;
                self.table_out = false;
            }
            self.mode = Mode::Running;
            return Ok(0);
        }
        // Left: what is being written out, the frames in flight, the piece.
        let left = self.out.len() - self.out_pos;
        Ok(left.max(1))
    }

    /// What of `input` fits in the piece.
    fn take(&mut self, input: &mut InBuffer<'_>) {
        if self.piece.capacity() == 0 {
            self.piece.reserve_exact(self.frame_size);
        }
        let n = (self.frame_size - self.piece.len()).min(input.src.len() - input.pos);
        self.piece
            .extend_from_slice(&input.src[input.pos..input.pos + n]);
        input.pos += n;
        self.total_in += n as u64;
    }

    /// The piece given to a thread, to make a frame of.
    fn submit(&mut self) -> Result<()> {
        if self.seek_table && self.entries.len() + self.workers.pending() >= MAX_FRAMES {
            return Err(Error::from(ErrorCode::FrameIndexTooLarge));
        }
        self.started = true;
        self.workers.give(Job {
            piece: std::mem::take(&mut self.piece),
            level: self.level,
            checksum: self.checksum,
            compressed: Arc::clone(&self.compressed),
        });
        Ok(())
    }

    /// The oldest frame in flight, to write out: waited for with `wait`.
    /// Whether there was one.
    fn next_frame(&mut self, wait: bool) -> Result<bool> {
        let next = if wait {
            self.workers.take()
        } else {
            self.workers.try_take()
        };
        let Some(frame) = next else {
            return Ok(false);
        };
        let (frame, content) = frame?;
        // Within 32 bits: frames of 1 GiB at most.
        self.entries.push((frame.len() as u32, content as u32));
        self.out = frame;
        self.out_pos = 0;
        Ok(true)
    }

    /// Writes out what it can, and the frames made, without waiting. Whether
    /// all is written out: false when `output` is full.
    fn write_out(&mut self, output: &mut OutBuffer<'_>, wait: bool) -> Result<bool> {
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
            if !self.next_frame(wait)? {
                return Ok(true);
            }
        }
    }
}

impl std::fmt::Debug for CompressFrames {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompressFrames")
            .field("level", &self.level)
            .field("frame_size", &self.frame_size)
            .field("threads", &self.in_flight)
            .field("total_in", &self.total_in)
            .field("total_out", &self.total_out)
            .finish_non_exhaustive()
    }
}

/// The seek table of frames of `entries`, as a skippable frame: each frame's
/// size and its content's, then their number, a descriptor (no checksums:
/// the frames have theirs) and the seekable format's magic number.
fn seek_table(entries: &[(u32, u32)]) -> Vec<u8> {
    let size = entries.len() * 8 + 9;
    let mut table = Vec::with_capacity(8 + size);
    table.extend_from_slice(&SEEK_TABLE_MAGIC.to_le_bytes());
    // Within 32 bits: MAX_FRAMES at most.
    table.extend_from_slice(&(size as u32).to_le_bytes());
    for &(compressed, content) in entries {
        table.extend_from_slice(&compressed.to_le_bytes());
        table.extend_from_slice(&content.to_le_bytes());
    }
    table.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    table.push(0);
    table.extend_from_slice(&SEEKABLE_MAGIC.to_le_bytes());
    table
}
