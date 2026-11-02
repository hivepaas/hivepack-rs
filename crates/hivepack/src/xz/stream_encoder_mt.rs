//! The threaded .xz encoder: port of `common/stream_encoder_mt.c`.
//!
//! liblzma's threads and its mutexes and condition variables
//! (`mythread.h`) are `std::thread`, `Mutex` and `Condvar`. Each Mutex
//! holds what liblzma's mutex protects: [`Shared`] the coder's, with the
//! output queue, which liblzma reads under it; [`WorkerShared`] a
//! worker's. The rest is the main thread's ([`StreamEncoderMt`]) or the
//! worker's own ([`WorkerLocal`]).
//!
//! Differs from liblzma, without a difference to see: liblzma's main
//! thread writes the input of a Block into the worker's buffer while the
//! worker reads the part before it; here the main thread appends it to
//! [`WorkerShared::pending`], which the worker moves to its own buffer
//! ([`take_pending`]).
//! The worker writes its output to a buffer it has taken from the output
//! queue and gives back when it has finished, as liblzma's main thread
//! reads only finished Blocks.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::xz::block::{Block, BlockEncoder, block_buffer_bound64, block_uncomp_encode};
use crate::xz::check::{CHECK_ID_MAX, Check};
use crate::xz::common::{Action, MEMUSAGE_BASE, NextCoder, Ret, VLI_UNKNOWN, bufcpy};
use crate::xz::filter::{Filter, filters_copy, mt_block_size, raw_encoder_memusage};
use crate::xz::outqueue::{OutQueue, THREADS_MAX, outq_memusage};
use crate::xz::stream_encoder::{Index, IndexEncoder};
use crate::xz::stream_flags::{STREAM_HEADER_SIZE, StreamFlags, footer_encode, header_encode};

/// Maximum supported block size. This makes it simpler to prevent integer
/// overflows if we are given unusually large block size.
const BLOCK_SIZE_MAX: u64 = u64::MAX / THREADS_MAX as u64;

/// `sizeof(lzma_stream_coder)` of `stream_encoder_mt.c` in liblzma on
/// x86-64 Linux with glibc's POSIX threads, which its memory usage counts.
const STREAM_CODER_SIZE: u64 = 568;

/// `sizeof(worker_thread)` of `stream_encoder_mt.c` in liblzma on x86-64
/// Linux with glibc's POSIX threads.
const WORKER_THREAD_SIZE: u64 = 544;

/// Limit the amount of input given to the Block encoder at once. This way
/// a worker can react fairly quickly if the main thread wants it to stop
/// or exit.
const IN_CHUNK_MAX: usize = 16384;

/// `lzma_mt`: the options of the threaded encoder and decoder.
#[derive(Clone, Debug)]
pub struct MtOptions {
    /// Set this to zero if no flags are wanted. The encoder takes none; the
    /// decoder takes those of [`Stream::stream_decoder`](crate::xz::Stream::stream_decoder).
    pub flags: u32,
    /// Number of worker threads to use, from 1 to 16384.
    pub threads: u32,
    /// Encoder only: the maximum uncompressed size of a Block, or 0 for
    /// the size the filter chain asks for (three times LZMA2's dictionary,
    /// at least 1 MiB).
    pub block_size: u64,
    /// Timeout to allow [`Stream::code`](crate::xz::Stream::code) to return
    /// early, in milliseconds, or 0 to wait as long as needed.
    pub timeout: u32,
    /// Encoder only: the preset, used when `filters` is `None`.
    pub preset: u32,
    /// Encoder only: the filter chain, or `None` for the preset.
    pub filters: Option<Vec<Filter>>,
    /// Encoder only: the integrity check of the Blocks.
    pub check: Check,
    /// Decoder only: the memory usage above which the decoder does not start
    /// another Block in a thread, and decodes a Block that would need more
    /// than this alone without threads. It is at most `memlimit_stop`.
    pub memlimit_threading: u64,
    /// Decoder only: the memory usage that decoding never goes over; a
    /// Block that would need more gives [`Error::Memlimit`](crate::xz::Error::Memlimit).
    pub memlimit_stop: u64,
}

impl Default for MtOptions {
    fn default() -> MtOptions {
        MtOptions {
            flags: 0,
            threads: 1,
            block_size: 0,
            timeout: 0,
            preset: crate::xz::PRESET_DEFAULT,
            filters: None,
            check: Check::CRC64,
            memlimit_threading: u64::MAX,
            memlimit_stop: u64::MAX,
        }
    }
}

/// The state of a worker.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum WorkerState {
    /// Waiting for work.
    Idle,
    /// Encoding is in progress.
    Run,
    /// Encoding is in progress but no more input data will be read.
    Finish,
    /// The main thread wants the thread to stop whatever it was doing but
    /// not exit.
    Stop,
    /// The main thread wants the thread to exit.
    Exit,
}

/// The output buffer a worker writes: its number in the output queue, its
/// data, and its allocated size.
struct WorkerOutBuf {
    id: u64,
    buf: Vec<u8>,
    allocated: usize,
}

/// What a worker's mutex protects in `worker_thread`.
struct WorkerShared {
    state: WorkerState,
    /// Amount of data available in the input buffer. This is modified
    /// only by the main thread.
    in_size: usize,
    /// The input the main thread has given since the worker last took it.
    pending: Vec<u8>,
    /// The output buffer for the next Block, set by the main thread every
    /// time a new Block is started with this worker.
    outbuf: Option<WorkerOutBuf>,
    /// Filter chain for the next Block.
    filters: Vec<Filter>,
    /// Amount of uncompressed data that has already been compressed.
    progress_in: u64,
    /// Amount of compressed data that is ready.
    progress_out: u64,
}

/// `worker_thread`, as the main thread and the worker share it.
struct Worker {
    mutex: Mutex<WorkerShared>,
    cond: Condvar,
}

/// What the coder's mutex protects in `lzma_stream_coder`.
struct Shared {
    /// Error code from a worker thread
    thread_error: Ret,
    /// Stack of free threads. When a thread finishes, it puts itself back
    /// into this stack. This starts as empty because threads are created
    /// only when actually needed.
    threads_free: Vec<usize>,
    /// Amount of uncompressed data in Blocks that have already been
    /// finished.
    progress_in: u64,
    /// Amount of compressed data in Stream Header + Blocks that have
    /// already been finished.
    progress_out: u64,
    /// Output buffer queue for compressed data
    outq: OutQueue,
}

/// The coder's mutex and condition variable.
struct Coder {
    mutex: Mutex<Shared>,
    cond: Condvar,
}

/// A mutex's data. A thread that panicked while holding it cannot leave it
/// inconsistent in a way that matters here, as no code panics.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn wait<'a, T>(cond: &Condvar, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
    cond.wait(guard).unwrap_or_else(PoisonError::into_inner)
}

/// The sequence of the main thread.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sequence {
    StreamHeader,
    Block,
    Index,
    StreamFooter,
}

/// A worker as the main thread has it.
struct WorkerHandle {
    worker: Arc<Worker>,
    /// The ID of this thread is used to join the thread when it's not
    /// needed anymore.
    thread: Option<JoinHandle<()>>,
}

/// `lzma_stream_coder` of `stream_encoder_mt.c`: the main thread's part.
pub(crate) struct StreamEncoderMt {
    sequence: Sequence,
    /// Start a new Block every block_size bytes of input unless
    /// LZMA_FULL_FLUSH or LZMA_FULL_BARRIER is used earlier.
    block_size: usize,
    /// The filter chain to use for the next Block.
    filters: Vec<Filter>,
    /// Index to hold sizes of the Blocks
    index: Index,
    /// Index encoder
    index_encoder: IndexEncoder,
    /// Stream Flags for encoding the Stream Header and Stream Footer.
    stream_flags: StreamFlags,
    /// Buffer to hold Stream Header and Stream Footer.
    header: [u8; STREAM_HEADER_SIZE],
    /// Read position in header[]
    header_pos: usize,
    /// How much memory to allocate for each lzma_outbuf.buf
    outbuf_alloc_size: usize,
    /// Maximum wait time if cannot use all the input and cannot fill the
    /// output buffer. This is in milliseconds.
    timeout: u32,
    /// The workers created so far: `threads_initialized` of liblzma.
    threads: Vec<WorkerHandle>,
    /// The number of workers that will be created at maximum.
    threads_max: u32,
    /// The most recent worker thread to which the main thread writes the
    /// new input from the application.
    thr: Option<usize>,
    /// The amount of input given to `thr`, its `in_size`.
    thr_in_size: usize,
    coder: Arc<Coder>,
}

/// `worker_error`: tell the main thread that something has gone wrong.
fn worker_error(coder: &Coder, ret: Ret) {
    let mut shared = lock(&coder.mutex);
    if shared.thread_error == Ret::Ok {
        shared.thread_error = ret;
    }

    coder.cond.notify_one();
}

/// What a worker keeps to itself.
struct WorkerLocal {
    worker: Arc<Worker>,
    coder: Arc<Coder>,
    /// The worker's place among the coder's.
    index: usize,
    check: Check,
    block_size: usize,
    /// Input buffer of up to block_size bytes.
    input: Vec<u8>,
    /// What the main thread has given for the Block.
    outbuf: Option<WorkerOutBuf>,
    filters: Vec<Filter>,
    /// Block encoder, kept from one Block to the next.
    block_encoder: Option<BlockEncoder>,
    /// The Block's sizes, for the Index, once it has been encoded.
    unpadded_size: u64,
    uncompressed_size: u64,
}

/// The input the main thread has given, moved to the worker's buffer: by
/// exchanging the two if the worker's is empty, as it is when a Block comes
/// in one piece, else by copying.
pub(crate) fn take_pending(input: &mut Vec<u8>, pending: &mut Vec<u8>) {
    if input.is_empty() {
        core::mem::swap(input, pending);
    } else {
        input.append(pending);
    }
}

/// Room in `buf` to write at `out_pos`, up to `out_size` bytes in all.
///
/// Differs from liblzma, without a difference to see: liblzma's buffer is
/// allocated at its full size and written as it goes; here it grows as it
/// is written, and the Block encoder is called again when it has filled
/// what there was, as with an output buffer of the full size.
pub(crate) fn ensure_room(buf: &mut Vec<u8>, out_pos: usize, out_size: usize) {
    if buf.len() <= out_pos && buf.len() < out_size {
        let len = (out_pos + (1 << 16)).max(buf.len() * 2).min(out_size);
        buf.resize(len, 0);
    }
}

impl WorkerLocal {
    /// `worker_encode`.
    fn encode(&mut self, out_pos: &mut usize, mut state: WorkerState) -> WorkerState {
        let Some(mut outbuf) = self.outbuf.take() else {
            worker_error(&self.coder, Ret::ProgError);
            return WorkerState::Stop;
        };
        let state = self.encode_into(&mut outbuf, out_pos, &mut state);
        self.outbuf = Some(outbuf);
        state
    }

    fn encode_into(
        &mut self,
        outbuf: &mut WorkerOutBuf,
        out_pos: &mut usize,
        state: &mut WorkerState,
    ) -> WorkerState {
        self.input.clear();

        // Set the Block options.
        let mut block_options = Block::new();
        block_options.version = 0;
        block_options.check = self.check;
        block_options.compressed_size = outbuf.allocated as u64;
        block_options.uncompressed_size = self.block_size as u64;
        block_options.filters = core::mem::take(&mut self.filters);

        // Calculate maximum size of the Block Header. This amount is
        // reserved in the beginning of the buffer so that Block Header
        // along with Compressed Size and Uncompressed Size can be written
        // there.
        let ret = block_options.header_size_compute();
        if ret != Ret::Ok {
            worker_error(&self.coder, ret);
            return WorkerState::Stop;
        }

        // Initialize the Block encoder.
        let block_encoder =
            match BlockEncoder::new(block_options.clone(), self.block_encoder.take()) {
                Ok(encoder) => self.block_encoder.insert(encoder),
                Err(ret) => {
                    worker_error(&self.coder, ret);
                    return WorkerState::Stop;
                }
            };

        let mut in_pos = 0;
        let mut in_size = 0;

        *out_pos = block_options.header_size as usize;
        let out_size = outbuf.allocated;

        let mut ret;
        loop {
            {
                let mut shared = lock(&self.worker.mutex);

                // Store in_pos and *out_pos so that an application may
                // read them via lzma_get_progress() to get progress
                // information.
                shared.progress_in = in_pos as u64;
                shared.progress_out = *out_pos as u64;

                while in_size == shared.in_size && shared.state == WorkerState::Run {
                    shared = wait(&self.worker.cond, shared);
                }

                *state = shared.state;
                in_size = shared.in_size;
                take_pending(&mut self.input, &mut shared.pending);
            }

            // Return if we were asked to stop or exit.
            if *state >= WorkerState::Stop {
                return *state;
            }

            let mut action = if *state == WorkerState::Finish {
                Action::Finish
            } else {
                Action::Run
            };

            // Limit the amount of input given to the Block encoder at
            // once.
            let mut in_limit = in_size;
            if in_size - in_pos > IN_CHUNK_MAX {
                in_limit = in_pos + IN_CHUNK_MAX;
                action = Action::Run;
            }

            loop {
                ensure_room(&mut outbuf.buf, *out_pos, out_size);
                ret = block_encoder.code(
                    &self.input[..in_limit],
                    &mut in_pos,
                    &mut outbuf.buf,
                    out_pos,
                    action,
                );
                if !(ret == Ret::Ok && *out_pos == outbuf.buf.len() && *out_pos < out_size) {
                    break;
                }
            }

            if !(ret == Ret::Ok && *out_pos < out_size) {
                break;
            }
        }

        match ret {
            Ret::StreamEnd => {
                // Encode the Block Header. By doing it after the
                // compression, we can store the Compressed Size and
                // Uncompressed Size fields.
                block_options.clone_from(&block_encoder.block);
                let ret = block_options.header_encode(&mut outbuf.buf);
                if ret != Ret::Ok {
                    worker_error(&self.coder, ret);
                    return WorkerState::Stop;
                }
            }

            Ret::Ok => {
                // The data was incompressible. Encode it using
                // uncompressed LZMA2 chunks.
                //
                // First wait that we have gotten all the input.
                {
                    let mut shared = lock(&self.worker.mutex);
                    while shared.state == WorkerState::Run {
                        shared = wait(&self.worker.cond, shared);
                    }

                    *state = shared.state;
                    in_size = shared.in_size;
                    take_pending(&mut self.input, &mut shared.pending);
                }

                if *state >= WorkerState::Stop {
                    return *state;
                }

                // Do the encoding. This takes care of the Block Header too.
                *out_pos = 0;
                outbuf.buf.resize(out_size, 0);
                let ret = block_uncomp_encode(
                    &mut block_options,
                    &self.input[..in_size],
                    &mut outbuf.buf,
                    out_pos,
                );

                // It shouldn't fail.
                if ret != Ret::Ok {
                    worker_error(&self.coder, Ret::ProgError);
                    return WorkerState::Stop;
                }
            }

            _ => {
                worker_error(&self.coder, ret);
                return WorkerState::Stop;
            }
        }

        // Set the size information that will be read by the main thread
        // to write the Index field.
        self.unpadded_size = block_options.unpadded_size();
        self.uncompressed_size = block_options.uncompressed_size;

        WorkerState::Finish
    }

    /// `worker_start`.
    fn start(mut self) {
        loop {
            // Wait for work.
            let mut state;
            {
                let mut shared = lock(&self.worker.mutex);
                loop {
                    // The thread is already idle so if we are requested to
                    // stop, just set the state.
                    if shared.state == WorkerState::Stop {
                        shared.state = WorkerState::Idle;
                        self.worker.cond.notify_one();
                    }

                    state = shared.state;
                    if state != WorkerState::Idle {
                        break;
                    }

                    shared = wait(&self.worker.cond, shared);
                }

                // The Block's output buffer and filters, which the main
                // thread has set.
                if let Some(outbuf) = shared.outbuf.take() {
                    self.outbuf = Some(outbuf);
                }
                self.filters = core::mem::take(&mut shared.filters);
            }

            let mut out_pos = 0;
            self.unpadded_size = 0;
            self.uncompressed_size = 0;

            if state <= WorkerState::Finish {
                state = self.encode(&mut out_pos, state);
            }

            if state == WorkerState::Exit {
                break;
            }

            // Mark the thread as idle unless the main thread has told us
            // to exit. Signal is needed for the case where the main thread
            // is waiting for the threads to stop.
            {
                let mut shared = lock(&self.worker.mutex);
                if shared.state != WorkerState::Exit {
                    shared.state = WorkerState::Idle;
                    self.worker.cond.notify_one();
                }
            }

            {
                let mut shared = lock(&self.coder.mutex);

                // Give the output buffer back and, if no errors occurred,
                // make the encoded data available to be copied out.
                if let Some(outbuf) = self.outbuf.take() {
                    match shared.outq.buf_mut(outbuf.id) {
                        Some(buf) => {
                            buf.buf = outbuf.buf;
                            if state == WorkerState::Finish {
                                buf.pos = out_pos;
                                buf.finished = true;
                                buf.unpadded_size = self.unpadded_size;
                                buf.uncompressed_size = self.uncompressed_size;
                            }
                        }
                        None => shared.outq.give_back(outbuf.buf, outbuf.allocated),
                    }
                }

                // Update the main progress info.
                shared.progress_in += self.uncompressed_size;
                shared.progress_out += out_pos as u64;
                {
                    let mut worker = lock(&self.worker.mutex);
                    worker.progress_in = 0;
                    worker.progress_out = 0;
                }

                // Return this thread to the stack of free threads.
                shared.threads_free.push(self.index);

                self.coder.cond.notify_one();
            }
        }
    }
}

impl StreamEncoderMt {
    /// `threads_stop`: make the threads stop but not exit. Optionally wait
    /// for them to stop.
    fn threads_stop(&self, wait_for_threads: bool) {
        // Tell the threads to stop.
        for thread in &self.threads {
            let mut shared = lock(&thread.worker.mutex);
            shared.state = WorkerState::Stop;
            thread.worker.cond.notify_one();
        }

        if !wait_for_threads {
            return;
        }

        // Wait for the threads to settle in the idle state.
        for thread in &self.threads {
            let mut shared = lock(&thread.worker.mutex);
            while shared.state != WorkerState::Idle {
                shared = wait(&thread.worker.cond, shared);
            }
        }
    }

    /// `threads_end`: stop the threads and free the resources associated
    /// with them. Wait until the threads have exited.
    fn threads_end(&mut self) {
        for thread in &self.threads {
            let mut shared = lock(&thread.worker.mutex);
            shared.state = WorkerState::Exit;
            thread.worker.cond.notify_one();
        }

        for thread in &mut self.threads {
            if let Some(handle) = thread.thread.take() {
                // A worker does not panic.
                let _ = handle.join();
            }
        }

        self.threads.clear();
    }

    /// `initialize_new_thread`: a new worker and its thread.
    fn initialize_new_thread(&mut self) -> Ret {
        let mut pending = Vec::new();
        if pending.try_reserve_exact(self.block_size).is_err() {
            return Ret::MemError;
        }

        let worker = Arc::new(Worker {
            mutex: Mutex::new(WorkerShared {
                state: WorkerState::Idle,
                in_size: 0,
                pending,
                outbuf: None,
                filters: Vec::new(),
                progress_in: 0,
                progress_out: 0,
            }),
            cond: Condvar::new(),
        });

        let local = WorkerLocal {
            worker: Arc::clone(&worker),
            coder: Arc::clone(&self.coder),
            index: self.threads.len(),
            check: self.stream_flags.check,
            block_size: self.block_size,
            input: Vec::new(),
            outbuf: None,
            filters: Vec::new(),
            block_encoder: None,
            unpadded_size: 0,
            uncompressed_size: 0,
        };

        let thread = match std::thread::Builder::new()
            .name("xz-encoder".into())
            .spawn(move || local.start())
        {
            Ok(thread) => thread,
            Err(_) => return Ret::MemError,
        };

        self.thr = Some(self.threads.len());
        self.threads.push(WorkerHandle {
            worker,
            thread: Some(thread),
        });

        Ret::Ok
    }

    /// `get_thread`: a free worker for the next Block, if there is one.
    fn get_thread(&mut self) -> Ret {
        {
            let mut shared = lock(&self.coder.mutex);

            // If there are no free output subqueues, there is no point to
            // try getting a thread.
            if !shared.outq.has_buf() {
                return Ret::Ok;
            }

            // That's also true if we cannot allocate memory for the output
            // buffer in the output queue.
            let ret = shared.outq.prealloc_buf(self.outbuf_alloc_size);
            if ret != Ret::Ok {
                return ret;
            }

            // If there is a free structure on the stack, use it.
            if let Some(index) = shared.threads_free.pop() {
                self.thr = Some(index);
            }
        }

        if self.thr.is_none() {
            // If there are no uninitialized structures left, return.
            if self.threads.len() as u32 == self.threads_max {
                return Ret::Ok;
            }

            // Initialize a new thread.
            let ret = self.initialize_new_thread();
            if ret != Ret::Ok {
                return ret;
            }
        }

        let Some(thr) = self.thr else {
            return Ret::ProgError;
        };

        // The output buffer for the Block.
        let outbuf = {
            let mut shared = lock(&self.coder.mutex);
            let id = shared.outq.get_buf(None);
            match shared.outq.buf_mut(id) {
                Some(buf) => WorkerOutBuf {
                    id,
                    buf: core::mem::take(&mut buf.buf),
                    allocated: buf.allocated,
                },
                None => return Ret::ProgError,
            }
        };

        // Reset the parts of the thread state that have to be done in the
        // main thread.
        let worker = &self.threads[thr].worker;
        let mut shared = lock(&worker.mutex);
        shared.state = WorkerState::Run;
        shared.in_size = 0;
        shared.pending.clear();
        shared.outbuf = Some(outbuf);
        shared.filters = self.filters.clone();
        self.thr_in_size = 0;
        worker.cond.notify_one();

        Ret::Ok
    }

    /// `stream_encode_in`: gives the input to the workers.
    fn encode_in(&mut self, input: &[u8], in_pos: &mut usize, action: Action) -> Ret {
        while *in_pos < input.len() || (self.thr.is_some() && action != Action::Run) {
            if self.thr.is_none() {
                // Get a new thread.
                let ret = self.get_thread();
                if self.thr.is_none() {
                    return ret;
                }
            }

            let Some(thr) = self.thr else {
                return Ret::ProgError;
            };

            // Copy the input data to thread's buffer.
            let start = *in_pos;
            let copy_size = (input.len() - start).min(self.block_size - self.thr_in_size);
            *in_pos += copy_size;
            let thr_in_size = self.thr_in_size + copy_size;

            // Tell the Block encoder to finish if
            //  - it has got block_size bytes of input; or
            //  - all input was used and LZMA_FINISH, LZMA_FULL_FLUSH, or
            //    LZMA_FULL_BARRIER was used.
            let finish =
                thr_in_size == self.block_size || (*in_pos == input.len() && action != Action::Run);

            let mut block_error = false;

            {
                let worker = &self.threads[thr].worker;
                let mut shared = lock(&worker.mutex);
                if shared.state == WorkerState::Idle {
                    // Something has gone wrong with the Block encoder. It
                    // has set coder->thread_error which we will read a few
                    // lines later.
                    block_error = true;
                } else {
                    // Tell the Block encoder its new amount of input and
                    // update the state if needed.
                    shared.pending.extend_from_slice(&input[start..*in_pos]);
                    shared.in_size = thr_in_size;
                    self.thr_in_size = thr_in_size;

                    if finish {
                        shared.state = WorkerState::Finish;
                    }

                    worker.cond.notify_one();
                }
            }

            if block_error {
                return lock(&self.coder.mutex).thread_error;
            }

            if finish {
                self.thr = None;
            }
        }

        Ret::Ok
    }

    /// `wait_for_work`: wait until more input can be consumed, more output
    /// can be read, or an optional timeout is reached; whether it was.
    fn wait_for_work(
        &self,
        wait_abs: &mut Option<Instant>,
        has_blocked: &mut bool,
        has_input: bool,
    ) -> bool {
        if self.timeout != 0 && !*has_blocked {
            // Every time when stream_encode_mt() is called via lzma_code(),
            // *has_blocked starts as false. We set it to true here and
            // calculate the absolute time when we must return if there's
            // nothing to do.
            *has_blocked = true;
            *wait_abs = Some(Instant::now() + Duration::from_millis(u64::from(self.timeout)));
        }

        let mut timed_out = false;

        let mut shared = lock(&self.coder.mutex);

        // There are four things that we wait. If one of them becomes
        // possible, we return.
        //  - If there is input left, we need to get a free worker thread
        //    and an output buffer for it.
        //  - Data ready to be read from the output queue.
        //  - A worker thread indicates an error.
        //  - Time out occurs.
        while (!has_input || shared.threads_free.is_empty() || !shared.outq.has_buf())
            && !shared.outq.is_readable()
            && shared.thread_error == Ret::Ok
            && !timed_out
        {
            match *wait_abs {
                Some(deadline) if self.timeout != 0 => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    let (guard, result) = self
                        .coder
                        .cond
                        .wait_timeout(shared, left)
                        .unwrap_or_else(PoisonError::into_inner);
                    shared = guard;
                    timed_out = result.timed_out();
                }
                _ => shared = wait(&self.coder.cond, shared),
            }
        }

        timed_out
    }
}

impl Drop for StreamEncoderMt {
    /// `stream_encoder_mt_end`: threads must be killed before the output
    /// queue can be freed.
    fn drop(&mut self) {
        self.threads_end();
    }
}

impl NextCoder for StreamEncoderMt {
    /// `stream_encode_mt`.
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        // liblzma's switch falls through from one sequence to the next.
        if self.sequence == Sequence::StreamHeader {
            bufcpy(&self.header, &mut self.header_pos, output, out_pos);
            if self.header_pos < self.header.len() {
                return Ret::Ok;
            }

            self.header_pos = 0;
            self.sequence = Sequence::Block;
        }

        if self.sequence == Sequence::Block {
            // These are for wait_for_work().
            let mut has_blocked = false;
            let mut wait_abs = None;

            loop {
                let (mut ret, unpadded_size, uncompressed_size) = {
                    let mut shared = lock(&self.coder.mutex);

                    // Check for Block encoder errors.
                    if shared.thread_error != Ret::Ok {
                        (shared.thread_error, 0, 0)
                    } else {
                        // Try to read compressed data to out[].
                        shared.outq.read(output, out_pos)
                    }
                };

                if ret == Ret::StreamEnd {
                    // End of Block. Add it to the Index.
                    ret = self.index.append(unpadded_size, uncompressed_size);
                    if ret != Ret::Ok {
                        self.threads_stop(false);
                        return ret;
                    }

                    // If we didn't fill the output buffer yet, try to read
                    // more data. Maybe the next outbuf has been finished
                    // already too.
                    if *out_pos < output.len() {
                        continue;
                    }
                }

                if ret != Ret::Ok {
                    // coder->thread_error was set.
                    self.threads_stop(false);
                    return ret;
                }

                // Try to give uncompressed data to a worker thread.
                let ret = self.encode_in(input, in_pos, action);
                if ret != Ret::Ok {
                    self.threads_stop(false);
                    return ret;
                }

                // See if we should wait or return.
                if *in_pos == input.len() {
                    // LZMA_RUN: More data is probably coming so return to
                    // let the caller fill the input buffer.
                    if action == Action::Run {
                        return Ret::Ok;
                    }

                    // LZMA_FULL_BARRIER: The same as with LZMA_RUN but tell
                    // the caller that the barrier was completed.
                    if action == Action::FullBarrier {
                        return Ret::StreamEnd;
                    }

                    // Finishing or flushing isn't completed until all input
                    // data has been encoded and copied to the output
                    // buffer.
                    if lock(&self.coder.mutex).outq.is_empty() {
                        // LZMA_FINISH: Continue to encode the Index field.
                        if action == Action::Finish {
                            break;
                        }

                        // LZMA_FULL_FLUSH: Return to tell the caller that
                        // flushing was completed.
                        if action == Action::FullFlush {
                            return Ret::StreamEnd;
                        }
                    }
                }

                // Return if there is no output space left. This check must
                // be done after testing the input buffer, because we might
                // want to use a different return code.
                if *out_pos == output.len() {
                    return Ret::Ok;
                }

                // Neither in nor out has been used completely. Wait until
                // there's something we can do.
                if self.wait_for_work(&mut wait_abs, &mut has_blocked, *in_pos < input.len()) {
                    return Ret::TimedOut;
                }
            }

            // All Blocks have been encoded and the threads have stopped.
            // Prepare to encode the Index field.
            self.index_encoder = IndexEncoder::new();
            self.sequence = Sequence::Index;

            // Update the progress info to take the Index and Stream Footer
            // into account. Those are very fast to encode so in terms of
            // progress information they can be thought to be ready to be
            // copied out.
            lock(&self.coder.mutex).progress_out += self.index.size() + STREAM_HEADER_SIZE as u64;
        }

        if self.sequence == Sequence::Index {
            // Call the Index encoder. It doesn't take any input.
            let ret = self.index_encoder.encode(&self.index, output, out_pos);
            if ret != Ret::StreamEnd {
                return ret;
            }

            // Encode the Stream Footer into coder->buffer.
            self.stream_flags.backward_size = self.index.size();
            if footer_encode(&self.stream_flags, &mut self.header) != Ret::Ok {
                return Ret::ProgError;
            }

            self.sequence = Sequence::StreamFooter;
        }

        bufcpy(&self.header, &mut self.header_pos, output, out_pos);
        if self.header_pos < self.header.len() {
            Ret::Ok
        } else {
            Ret::StreamEnd
        }
    }

    /// `get_progress`.
    fn get_progress(&self) -> Option<(u64, u64)> {
        // Lock the coder's mutex to prevent finishing threads from moving
        // their progress info from the worker to the coder.
        let shared = lock(&self.coder.mutex);
        let mut progress_in = shared.progress_in;
        let mut progress_out = shared.progress_out;

        for thread in &self.threads {
            let worker = lock(&thread.worker.mutex);
            progress_in += worker.progress_in;
            progress_out += worker.progress_out;
        }

        Some((progress_in, progress_out))
    }
}

/// The options `get_options` reads: the filter chain, the Block size, and
/// the most output a Block may need.
struct Options {
    filters: Vec<Filter>,
    block_size: u64,
    outbuf_size_max: u64,
}

/// `get_options`: options handling for `lzma_stream_encoder_mt_init()` and
/// `lzma_stream_encoder_mt_memusage()`.
fn get_options(options: &MtOptions) -> Result<Options, Ret> {
    // Validate some of the options.
    if options.flags != 0 || options.threads == 0 || options.threads > THREADS_MAX {
        return Err(Ret::OptionsError);
    }

    let filters = match &options.filters {
        // Filter chain was given, use it as is.
        Some(filters) => filters.clone(),
        // Use a preset.
        None => crate::xz::easy_preset(options.preset).ok_or(Ret::OptionsError)?,
    };

    // If the Block size is not set, determine it from the filter chain.
    let block_size = if options.block_size > 0 {
        options.block_size
    } else {
        mt_block_size(&filters)
    };

    if block_size > BLOCK_SIZE_MAX || block_size == u64::MAX {
        return Err(Ret::OptionsError);
    }

    // Calculate the maximum amount output that a single output buffer may
    // need to hold. This is the same as the maximum total size of a Block.
    let outbuf_size_max = block_buffer_bound64(block_size);
    if outbuf_size_max == 0 {
        return Err(Ret::MemError);
    }

    Ok(Options {
        filters,
        block_size,
        outbuf_size_max,
    })
}

impl StreamEncoderMt {
    /// `stream_encoder_mt_init`.
    pub(crate) fn new(options: &MtOptions) -> Result<StreamEncoderMt, Ret> {
        // Get the filter chain.
        let Options {
            filters,
            block_size,
            outbuf_size_max,
        } = get_options(options)?;

        let (Ok(block_size), Ok(outbuf_alloc_size)) = (
            usize::try_from(block_size),
            usize::try_from(outbuf_size_max),
        ) else {
            return Err(Ret::MemError);
        };

        // Validate the filter chain so that we can give an error in this
        // function instead of delaying it to the first call to lzma_code().
        // The memory usage calculation verifies the filter chain as a side
        // effect so we take advantage of that. It's not a perfect check
        // though as raw encoder allows LZMA1 too but such problems will be
        // caught eventually with Block Header encoder.
        if raw_encoder_memusage(&filters) == u64::MAX {
            return Err(Ret::OptionsError);
        }

        // Validate the Check ID.
        if options.check.0 > CHECK_ID_MAX {
            return Err(Ret::ProgError);
        }

        if !options.check.is_supported() {
            return Err(Ret::UnsupportedCheck);
        }

        // Output queue
        let mut outq = OutQueue::default();
        let ret = outq.init(options.threads);
        if ret != Ret::Ok {
            return Err(ret);
        }

        // Copy the new filter chain.
        let filters = filters_copy(&filters)?;

        // Stream Header
        let stream_flags = StreamFlags {
            version: 0,
            backward_size: VLI_UNKNOWN,
            check: options.check,
        };
        let mut header = [0; STREAM_HEADER_SIZE];
        let ret = header_encode(&stream_flags, &mut header);
        if ret != Ret::Ok {
            return Err(ret);
        }

        Ok(StreamEncoderMt {
            sequence: Sequence::StreamHeader,
            block_size,
            filters,
            index: Index::default(),
            index_encoder: IndexEncoder::new(),
            stream_flags,
            header,
            header_pos: 0,
            outbuf_alloc_size,
            timeout: options.timeout,
            threads: Vec::new(),
            threads_max: options.threads,
            thr: None,
            thr_in_size: 0,
            coder: Arc::new(Coder {
                mutex: Mutex::new(Shared {
                    thread_error: Ret::Ok,
                    threads_free: Vec::new(),
                    progress_in: 0,
                    progress_out: STREAM_HEADER_SIZE as u64,
                    outq,
                }),
                cond: Condvar::new(),
            }),
        })
    }
}

/// `lzma_stream_encoder_mt_memusage`: the memory the threaded encoder
/// needs, or u64::MAX if the options are invalid.
pub(crate) fn stream_encoder_mt_memusage(options: &MtOptions) -> u64 {
    let Ok(Options {
        filters,
        block_size,
        outbuf_size_max,
    }) = get_options(options)
    else {
        return u64::MAX;
    };

    let threads = u64::from(options.threads);

    // Memory usage of the input buffers
    let inbuf_memusage = threads * block_size;

    // Memory usage of the filter encoders
    let mut filters_memusage = raw_encoder_memusage(&filters);
    if filters_memusage == u64::MAX {
        return u64::MAX;
    }

    filters_memusage *= threads;

    // Memory usage of the output queue
    let outq_memusage = outq_memusage(outbuf_size_max, options.threads);
    if outq_memusage == u64::MAX {
        return u64::MAX;
    }

    // Sum them with overflow checking.
    let mut total_memusage = MEMUSAGE_BASE + STREAM_CODER_SIZE + threads * WORKER_THREAD_SIZE;

    if u64::MAX - total_memusage < inbuf_memusage {
        return u64::MAX;
    }

    total_memusage += inbuf_memusage;

    if u64::MAX - total_memusage < filters_memusage {
        return u64::MAX;
    }

    total_memusage += filters_memusage;

    if u64::MAX - total_memusage < outq_memusage {
        return u64::MAX;
    }

    total_memusage + outq_memusage
}
