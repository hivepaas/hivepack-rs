//! bzip2 in threads, as pbzip2 does it: the input cut into pieces of a
//! fixed size, each compressed into a bzip2 stream of its own, the streams
//! one after the other. `bzip2 -d`, and every reader that reads streams
//! one after the other as it does, reads them back as one.
//!
//! Not part of the port: libbzip2 has no threads, and nothing here changes
//! what [`Compress`] and [`Decompress`](crate::bzip2::Decompress) do. Each
//! stream is [`Compress`]'s, byte for byte.
//!
//! The pieces are cut where their size says, never where the threads
//! would: the output is the same whatever the threads, one or many.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread::JoinHandle;

use crate::Threads;
use crate::bzip2::{Action, Compress, Error, InBuffer, OutBuffer, Result, Status};

/// The input of each stream by default, for blocks of `block_size_100k` ×
/// 100,000 bytes (1 to 9): 95% of a block, 855,000 bytes at 9.
///
/// libbzip2 ends a block once its first run-length coding has made
/// `block_size_100k` × 100,000 − 19 bytes. That coding writes a run of 4
/// to 255 bytes as 5, so it can make more than it reads (up to 5/4, from
/// runs of exactly 4, such as indents of four spaces), or much less (from
/// longer runs, such as a tar archive's zeros). A piece of a whole block
/// spills over into a second, small block whenever it grows: in a quarter
/// of the streams of the Silesia corpus. At 95%, a piece spills over only
/// where more than about one byte in five is in a run of exactly 4, which
/// none of Silesia's do, and each stream is one block, as pbzip2's mostly
/// are. The streams are 0.1% larger than with pieces of a whole block, and
/// 0.2% larger than the one stream of `bzip2 -9`.
pub fn piece_size(block_size_100k: i32) -> usize {
    let level = usize::try_from(block_size_100k.clamp(1, 9)).unwrap_or(9);
    level * 95_000
}

/// How a [`CompressMt`] compresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MtOptions {
    /// Blocks of `block_size_100k` × 100,000 bytes, from 1 to 9, as
    /// [`Compress::new`] takes it: 9 by default.
    pub block_size_100k: i32,
    /// From 0 to 250, 0 meaning the default, as [`Compress::new`] takes it.
    /// The output is the same with every work factor.
    pub work_factor: i32,
    /// The threads, besides the caller's, that compress the pieces.
    pub threads: Threads,
    /// The input of each stream, or 0 for [`piece_size`]'s. Larger pieces
    /// make streams of several blocks.
    pub piece_size: usize,
    /// The most bytes compressing may take: the threads are lowered until
    /// [`MtOptions::memory_usage`] says they fit
    /// ([`MtOptions::threads_used`]). One thread is always allowed, even
    /// where it takes more, as liblzma allows one: the output is the same
    /// whatever the threads. No limit (`u64::MAX`) by default. See
    /// `docs/memory.md`.
    pub memory_limit: u64,
}

impl Default for MtOptions {
    fn default() -> MtOptions {
        MtOptions {
            block_size_100k: 9,
            work_factor: 0,
            threads: Threads::One,
            piece_size: 0,
            memory_limit: u64::MAX,
        }
    }
}

impl MtOptions {
    /// The input of each stream.
    fn piece(&self) -> usize {
        match self.piece_size {
            0 => piece_size(self.block_size_100k),
            size => size,
        }
    }

    /// The most bytes a [`CompressMt`] with these options takes, in
    /// `threads` threads (0 is taken for 1): an upper bound, of what it
    /// allocates, whatever the input. [`Error::Param`] where
    /// [`Compress::new`] would give it.
    ///
    /// Each thread has a compressor ([`Compress`]'s, about 15 bytes for
    /// each byte of a block: 14 MB at block size 9), a piece and room for
    /// its stream, 1% more than it and 601 bytes; and as many pieces again
    /// wait, read or compressed, besides the one being filled and the
    /// stream being written out: 15.8 MiB a thread at block size 9, and
    /// 2.6 MiB more. See `docs/memory.md`.
    pub fn memory_usage(&self, threads: u32) -> Result<u64> {
        if !(1..=9).contains(&self.block_size_100k) || !(0..=250).contains(&self.work_factor) {
            return Err(Error::Param);
        }
        let threads = u64::from(threads.max(1));
        let piece = self.piece() as u64;
        let stream = piece + piece / 100 + 601;
        let compress = crate::bzip2::compress_memory(self.block_size_100k);
        let per_thread = piece + compress + 2 * stream;
        Ok(threads
            .saturating_mul(per_thread)
            .saturating_add(piece + stream + MT_MEMORY))
    }

    /// The threads a [`CompressMt`] with these options compresses in: as
    /// many as [`threads`](MtOptions::threads) says, fewer while
    /// [`memory_usage`](MtOptions::memory_usage) is over
    /// [`memory_limit`](MtOptions::memory_limit), and one at least.
    /// [`Error::Param`] where [`Compress::new`] would give it.
    pub fn threads_used(&self) -> Result<u32> {
        let one = self.memory_usage(1)?;
        let per_thread = self.memory_usage(2)? - one;
        let room = self.memory_limit.saturating_sub(one) / per_thread.max(1);
        let most = u32::try_from(room.saturating_add(1)).unwrap_or(u32::MAX);
        Ok(self.threads.count().min(most).max(1))
    }
}

/// What a [`CompressMt`] takes besides its pieces and compressors: the
/// threads' channels, and itself.
const MT_MEMORY: u64 = 1 << 20;

/// Where a [`CompressMt`] is, as libbzip2's `mode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Running,
    /// A flush, with the input it still expects to be given.
    Flushing(usize),
    /// The end, with the input it still expects to be given.
    Finishing(usize),
    Done,
}

/// A compressor that writes several bzip2 streams, one after the other,
/// each compressed in a thread: as pbzip2 writes them, and as `bzip2 -d`
/// reads them.
///
/// It is used as [`Compress`] is, a call at a time with an input and an
/// output, so that one can take the other's place. The input is cut into
/// pieces of [`MtOptions::piece_size`], each made a stream of its own (a
/// flush, or the end, cuts a piece short), and the streams come out in
/// order. The output is the same whatever [`MtOptions::threads`] says, one
/// thread too: it depends only on the input, the options and where the
/// flushes are.
///
/// With [`Threads::One`], each piece is compressed in the call that fills
/// it. With more, at most two pieces for each thread are in flight, and a
/// call waits for the oldest of them when it can go no further without.
/// Each thread's compressor takes about 15 bytes for each byte of a block,
/// as [`Compress`] does: 14 MB at block size 9.
/// [`MtOptions::memory_limit`] lowers the threads to fit what
/// [`MtOptions::memory_usage`] counts.
pub struct CompressMt {
    block_size_100k: i32,
    work_factor: i32,
    piece_size: usize,
    /// The streams in flight at most.
    in_flight: usize,
    pool: Pool,
    /// The input of the next stream.
    piece: Vec<u8>,
    /// The streams being made, oldest first.
    queue: VecDeque<Pending<Result<Vec<u8>>>>,
    /// The stream being written out, and how much of it is.
    out: Vec<u8>,
    out_pos: usize,
    /// A stream was started: without one, the end writes an empty stream,
    /// as `bzip2` does for an empty input.
    started: bool,
    mode: Mode,
    /// The error that every later call returns.
    failed: Option<Error>,
    total_in: u64,
    total_out: u64,
}

impl CompressMt {
    /// A compressor of blocks of `block_size_100k` × 100,000 bytes, with a
    /// work factor, as [`Compress::new`] takes them, in `threads`, with
    /// pieces of [`piece_size`].
    pub fn new(block_size_100k: i32, work_factor: i32, threads: Threads) -> Result<CompressMt> {
        CompressMt::with_options(&MtOptions {
            block_size_100k,
            work_factor,
            threads,
            ..MtOptions::default()
        })
    }

    /// A compressor with `options`: [`Error::Param`] where
    /// [`Compress::new`] would give it.
    pub fn with_options(options: &MtOptions) -> Result<CompressMt> {
        // What Compress::new checks, and the threads that fit the limit.
        let threads = options.threads_used()?;
        let piece_size = options.piece();
        let threads = usize::try_from(threads).unwrap_or(usize::MAX);
        let pool = Pool::new(threads);
        let in_flight = if pool.inline() {
            1
        } else {
            threads.saturating_mul(2)
        };
        Ok(CompressMt {
            block_size_100k: options.block_size_100k,
            work_factor: options.work_factor,
            piece_size,
            in_flight,
            pool,
            piece: Vec::new(),
            queue: VecDeque::new(),
            out: Vec::new(),
            out_pos: 0,
            started: false,
            mode: Mode::Running,
            failed: None,
            total_in: 0,
            total_out: 0,
        })
    }

    /// Reads what it can of `input`, and writes what it can to `output`,
    /// for `action`, as [`Compress::compress`] does, with the same results:
    ///
    /// - [`Action::Run`] gives [`Status::RunOk`], or fails with
    ///   [`Error::Param`] when it can neither read nor write. When it has
    ///   nothing to read, it waits for the oldest stream in flight, if
    ///   there is one and room to write it.
    /// - [`Action::Flush`] ends the current piece once the input given is
    ///   read, and writes out every stream: [`Status::FlushOk`] until it is
    ///   done, then [`Status::RunOk`]. What follows starts a new stream.
    /// - [`Action::Finish`] does the same, then ends: [`Status::FinishOk`]
    ///   until it is done, then [`Status::StreamEnd`].
    ///
    /// Once a flush or the end is asked for, every call until it is done
    /// must ask for it again, with the input that was left
    /// ([`Error::Sequence`] otherwise), and every call after the end fails
    /// with [`Error::Sequence`]. An error of a stream's compressor (only
    /// [`Error::Mem`] can be) is returned by every later call.
    pub fn compress(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        action: Action,
    ) -> Result<Status> {
        if output.pos > output.dst.len() || input.pos > input.src.len() {
            return Err(Error::Param);
        }
        if let Some(e) = self.failed {
            return Err(e);
        }
        let left = input.src.len() - input.pos;
        let finish = match (self.mode, action) {
            (Mode::Running, Action::Run) => return self.run(output, input),
            (Mode::Running, Action::Flush) => {
                self.mode = Mode::Flushing(left);
                false
            }
            (Mode::Running, Action::Finish) => {
                self.mode = Mode::Finishing(left);
                true
            }
            (Mode::Flushing(expected), Action::Flush) if expected == left => false,
            (Mode::Finishing(expected), Action::Finish) if expected == left => true,
            _ => return Err(Error::Sequence),
        };
        let result = self.end(output, input, finish);
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

    /// [`Action::Run`].
    fn run(&mut self, output: &mut OutBuffer<'_>, input: &mut InBuffer<'_>) -> Result<Status> {
        match self.run_inner(output, input) {
            Ok(true) => Ok(Status::RunOk),
            Ok(false) => Err(Error::Param),
            Err(e) => {
                self.failed = Some(e);
                Err(e)
            }
        }
    }

    /// Whether it read or wrote anything.
    fn run_inner(&mut self, output: &mut OutBuffer<'_>, input: &mut InBuffer<'_>) -> Result<bool> {
        let mut progress = false;
        loop {
            progress |= self.write_out(output, 0)?;
            if self.piece.len() == self.piece_size {
                if self.queue.len() < self.in_flight {
                    self.submit();
                    continue;
                }
                if output.pos == output.dst.len() {
                    break;
                }
                progress |= self.write_out(output, 1)?;
                continue;
            }
            if input.pos == input.src.len() {
                break;
            }
            self.take(input);
            progress = true;
        }
        if !progress {
            progress = self.write_out(output, 1)?;
        }
        Ok(progress)
    }

    /// [`Action::Flush`] and [`Action::Finish`].
    fn end(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        finish: bool,
    ) -> Result<Status> {
        let before = input.pos;
        loop {
            self.write_out(output, 0)?;
            let all_read = input.pos == input.src.len();
            if self.piece.len() == self.piece_size || (all_read && !self.piece.is_empty()) {
                if self.queue.len() < self.in_flight {
                    self.submit();
                    continue;
                }
                if output.pos == output.dst.len() {
                    break;
                }
                self.write_out(output, 1)?;
                continue;
            }
            if !all_read {
                self.take(input);
                continue;
            }
            if finish && !self.started {
                self.started = true;
                self.queue.push_back(Pending::Ready(compress_piece(
                    &[],
                    self.block_size_100k,
                    self.work_factor,
                )));
            }
            self.write_out(output, usize::MAX)?;
            if self.out_pos == self.out.len() && self.queue.is_empty() {
                self.mode = if finish { Mode::Done } else { Mode::Running };
                return Ok(if finish {
                    Status::StreamEnd
                } else {
                    Status::RunOk
                });
            }
            break;
        }
        let read = input.pos - before;
        self.mode = match self.mode {
            Mode::Flushing(expected) => Mode::Flushing(expected - read),
            Mode::Finishing(expected) => Mode::Finishing(expected - read),
            mode => mode,
        };
        Ok(if finish {
            Status::FinishOk
        } else {
            Status::FlushOk
        })
    }

    /// What of `input` fits in the piece.
    fn take(&mut self, input: &mut InBuffer<'_>) {
        if self.piece.capacity() == 0 {
            self.piece.reserve_exact(self.piece_size);
        }
        let n = (self.piece_size - self.piece.len()).min(input.src.len() - input.pos);
        self.piece
            .extend_from_slice(&input.src[input.pos..input.pos + n]);
        input.pos += n;
        self.total_in += n as u64;
    }

    /// The piece given to a thread, to make a stream of.
    fn submit(&mut self) {
        let piece = std::mem::take(&mut self.piece);
        let (block_size_100k, work_factor) = (self.block_size_100k, self.work_factor);
        self.started = true;
        let pending = self
            .pool
            .run(move || compress_piece(&piece, block_size_100k, work_factor));
        self.queue.push_back(pending);
    }

    /// Writes out what it can of the streams made, oldest first, waiting
    /// for at most `waits` streams still being made. True iff it wrote
    /// anything.
    fn write_out(&mut self, output: &mut OutBuffer<'_>, mut waits: usize) -> Result<bool> {
        let mut wrote = false;
        loop {
            if self.out_pos < self.out.len() {
                let n = (self.out.len() - self.out_pos).min(output.dst.len() - output.pos);
                if n == 0 {
                    return Ok(wrote);
                }
                output.dst[output.pos..output.pos + n]
                    .copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
                output.pos += n;
                self.out_pos += n;
                self.total_out += n as u64;
                wrote = true;
                continue;
            }
            let Some(oldest) = self.queue.front_mut() else {
                return Ok(wrote);
            };
            if !oldest.ready() {
                if waits == 0 || output.pos == output.dst.len() {
                    return Ok(wrote);
                }
                waits -= 1;
            }
            let Some(oldest) = self.queue.pop_front() else {
                return Ok(wrote);
            };
            self.out = oldest.wait()?;
            self.out_pos = 0;
        }
    }
}

impl std::fmt::Debug for CompressMt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompressMt")
            .field("block_size_100k", &self.block_size_100k)
            .field("piece_size", &self.piece_size)
            .field("total_in", &self.total_in)
            .field("total_out", &self.total_out)
            .finish_non_exhaustive()
    }
}

/// `piece` as one bzip2 stream, [`Compress`]'s.
fn compress_piece(piece: &[u8], block_size_100k: i32, work_factor: i32) -> Result<Vec<u8>> {
    let mut stream = Compress::new(block_size_100k, work_factor)?;
    // bzip2's manual: 1% more than the input, and 600 bytes, always do.
    let mut out = vec![0; piece.len() + piece.len() / 100 + 601];
    let mut input = InBuffer::new(piece);
    let mut written = 0;
    loop {
        let mut output = OutBuffer {
            dst: &mut out,
            pos: written,
        };
        let status = stream.compress(&mut output, &mut input, Action::Finish)?;
        written = output.pos;
        if status == Status::StreamEnd {
            out.truncate(written);
            return Ok(out);
        }
        let more = out.len();
        out.resize(more * 2, 0);
    }
}

/// A job's result: there already, or to come from a thread.
pub(crate) enum Pending<T> {
    Ready(T),
    Waiting(mpsc::Receiver<std::thread::Result<T>>),
}

impl<T> Pending<T> {
    /// Whether the result is there, without waiting.
    pub(crate) fn ready(&mut self) -> bool {
        let Pending::Waiting(receiver) = self else {
            return true;
        };
        match receiver.try_recv() {
            Ok(Ok(value)) => {
                *self = Pending::Ready(value);
                true
            }
            Ok(Err(panic)) => std::panic::resume_unwind(panic),
            Err(mpsc::TryRecvError::Empty) => false,
            // The thread is gone without a result: wait() says so.
            Err(mpsc::TryRecvError::Disconnected) => true,
        }
    }

    /// The result, once it is there. A job that panicked panics here, in
    /// the caller's thread, as it would have without threads.
    pub(crate) fn wait(self) -> T {
        match self {
            Pending::Ready(value) => value,
            Pending::Waiting(receiver) => match receiver.recv() {
                Ok(Ok(value)) => value,
                Ok(Err(panic)) => std::panic::resume_unwind(panic),
                // A job is dropped unrun only once its pool is.
                Err(mpsc::RecvError) => {
                    std::panic::resume_unwind(Box::new("a bzip2 thread is gone"))
                }
            },
        }
    }
}

type Job = Box<dyn FnOnce() + Send>;

/// Threads that run jobs, each result coming back on its own channel: the
/// caller keeps them in the order it wants them. A thread is started when
/// a job is given and fewer than the most are running; with one at most,
/// or when no thread can be started, the caller's thread runs each job
/// when it is given.
pub(crate) struct Pool {
    max: usize,
    sender: Option<mpsc::Sender<Job>>,
    receiver: Arc<Mutex<mpsc::Receiver<Job>>>,
    /// Set when the pool is dropped: the jobs not started are not run.
    stop: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
    /// What its threads are named.
    name: &'static str,
}

impl Pool {
    /// A pool of `threads` at most, or none with one.
    pub(crate) fn new(threads: usize) -> Pool {
        Pool::named(threads, "hivepack-bzip2")
    }

    /// A pool of `threads` at most, or none with one, its threads named
    /// `name`.
    pub(crate) fn named(threads: usize, name: &'static str) -> Pool {
        let (sender, receiver) = mpsc::channel();
        Pool {
            max: if threads > 1 { threads } else { 0 },
            sender: Some(sender),
            receiver: Arc::new(Mutex::new(receiver)),
            stop: Arc::new(AtomicBool::new(false)),
            handles: Vec::new(),
            name,
        }
    }

    /// Whether the caller's thread runs every job.
    pub(crate) fn inline(&self) -> bool {
        self.max == 0
    }

    /// `job` run, in a thread if there can be one.
    pub(crate) fn run<T, F>(&mut self, job: F) -> Pending<T>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        if self.handles.len() < self.max {
            self.start();
        }
        let sender = match &self.sender {
            Some(sender) if !self.handles.is_empty() => sender,
            _ => return Pending::Ready(job()),
        };
        let (result_sender, result) = mpsc::sync_channel(1);
        let stop = Arc::clone(&self.stop);
        let boxed: Job = Box::new(move || {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let value = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
            // No one waits for it once the pool's owner is gone.
            let _ = result_sender.send(value);
        });
        match sender.send(boxed) {
            Ok(()) => Pending::Waiting(result),
            // The threads are gone, which only a panic outside a job does.
            Err(mpsc::SendError(_)) => {
                std::panic::resume_unwind(Box::new("the bzip2 threads are gone"))
            }
        }
    }

    /// Another thread, if the system gives one: if not, the ones there are
    /// do, or the caller's.
    fn start(&mut self) {
        let receiver = Arc::clone(&self.receiver);
        let spawned = std::thread::Builder::new()
            .name(self.name.into())
            .spawn(move || {
                loop {
                    let job = receiver
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .recv();
                    match job {
                        Ok(job) => job(),
                        Err(mpsc::RecvError) => return,
                    }
                }
            });
        match spawned {
            Ok(handle) => self.handles.push(handle),
            Err(_) => self.max = self.handles.len(),
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.sender = None;
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}
