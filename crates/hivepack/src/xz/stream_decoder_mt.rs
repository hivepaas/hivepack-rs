//! The threaded .xz decoder: port of `common/stream_decoder_mt.c`.
//!
//! As in [`stream_encoder_mt`](crate::xz::stream_encoder_mt), liblzma's threads,
//! mutexes and condition variables are `std::thread`, `Mutex` and `Condvar`,
//! each mutex holding what liblzma's protects.
//!
//! Differs from liblzma, without a difference to see: liblzma's main thread
//! writes a Block's input into the worker's buffer while the worker reads
//! the part before it, and reads the output of the oldest Block from the
//! worker's buffer while the worker writes the part after it. Here the main
//! thread appends the input to [`WorkerShared::pending`], which the worker
//! moves to its own buffer, and the worker writes its output to a buffer of
//! its own, which it moves to the output queue under the coder's mutex where
//! liblzma updates `outbuf->pos`: the whole buffer the first time, as little
//! has to be copied, and what it has written since then the other times.

use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::xz::block::{BLOCK_HEADER_SIZE_MAX, Block, BlockDecoder, header_size_decode, vli_ceil4};
use crate::xz::check::Check;
use crate::xz::common::{
    Action, CONCATENATED, FAIL_FAST, IGNORE_CHECK, MEMUSAGE_BASE, NextCoder, Ret, SUPPORTED_FLAGS,
    TELL_ANY_CHECK, TELL_NO_CHECK, TELL_UNSUPPORTED_CHECK, VLI_UNKNOWN, bufcpy,
};
use crate::xz::filter::raw_decoder_memusage;
use crate::xz::index_hash::{INDEX_INDICATOR, IndexHash};
use crate::xz::outqueue::{OutQueue, THREADS_MAX, outbuf_memusage};
use crate::xz::stream_encoder_mt::{MtOptions, ensure_room, lock, take_pending, wait};
use crate::xz::stream_flags::{self, STREAM_HEADER_SIZE, StreamFlags};

/// Pass the input in small chunks to the Block decoder. This way a worker
/// reacts reasonably fast if it is told to stop or exit, and (when partial
/// update is enabled) tells about its progress to the main thread frequently
/// enough.
const CHUNK_SIZE: usize = 16384;

/// The state of a worker.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WorkerState {
    /// Waiting for work. Main thread may change this to Run or Exit.
    Idle,
    /// Decoding is in progress. Main thread may change this to Idle or Exit.
    /// The worker thread may change this to Idle.
    Run,
    /// The main thread wants the thread to exit.
    Exit,
}

/// What the main thread gives a worker for a Block.
struct Job {
    block_decoder: BlockDecoder,
    /// The number of the output buffer in the output queue, its data, and
    /// its allocated size.
    outbuf_id: u64,
    buf: Vec<u8>,
    allocated: usize,
    /// Amount of memory allocated for the input.
    in_size: usize,
    /// Filter chain memory usage
    mem_filters: u64,
}

/// What a worker's mutex protects in `worker_thread`.
struct WorkerShared {
    state: WorkerState,
    /// The next Block, when the state becomes Run.
    job: Option<Job>,
    /// Number of bytes written to "in" by the main thread
    in_filled: usize,
    /// The input the main thread has given since the worker last took it.
    pending: Vec<u8>,
    /// Amount of compressed data that has already been decompressed.
    progress_in: u64,
    /// Like progress_in but for uncompressed data.
    progress_out: u64,
    /// When this is true, this worker will update outbuf->pos and
    /// outbuf->decoder_in_pos after each call to the Block decoder. This is
    /// initially false. Main thread may set this to true.
    partial_update_enabled: bool,
    /// Block decoder of the last Block, while the worker is free: its memory
    /// counts as cached until the main thread frees it.
    block_decoder: Option<BlockDecoder>,
}

/// `worker_thread`, as the main thread and the worker share it.
struct Worker {
    mutex: Mutex<WorkerShared>,
    cond: Condvar,
}

/// What the coder's mutex protects in `lzma_stream_coder`.
struct Shared {
    /// Error code from a worker thread.
    thread_error: Ret,
    /// Stack of free threads. When a thread finishes, it puts itself back
    /// into this stack. This starts as empty because threads are created
    /// only when actually needed.
    threads_free: Vec<usize>,
    /// Output buffer queue for decompressed data from the worker threads
    outq: OutQueue,
    /// Amount of memory needed by the running worker threads. This doesn't
    /// include the memory needed by the output buffer.
    mem_in_use: u64,
    /// Amount of memory used by the idle (cached) threads.
    mem_cached: u64,
    /// Amount of compressed data in Stream Header + Blocks that have
    /// already been finished.
    progress_in: u64,
    /// Amount of uncompressed data in Blocks that have already been
    /// finished.
    progress_out: u64,
}

/// The coder's mutex and condition variable.
struct Coder {
    mutex: Mutex<Shared>,
    cond: Condvar,
}

/// What a worker keeps to itself.
struct WorkerLocal {
    worker: Arc<Worker>,
    coder: Arc<Coder>,
    /// The worker's place among the coder's.
    index: usize,
    /// Input buffer that will contain the whole Block except Block Header.
    input: Vec<u8>,
    /// Amount of memory allocated for "in"
    in_size: usize,
    /// Number of bytes consumed from "in" by the worker thread.
    in_pos: usize,
    /// Block decoder
    block_decoder: Option<BlockDecoder>,
    /// The output not yet moved to the output queue.
    window: Vec<u8>,
    /// The amount of it that has been written.
    window_pos: usize,
    /// The output moved to the output queue so far.
    published: usize,
    /// The number of the output buffer in the output queue.
    outbuf_id: u64,
    /// Its allocated size.
    allocated: usize,
    /// Once the main thread has set partial_update_enabled = true, we will
    /// do the first partial update as soon as we can and set
    /// partial_update_started = true. After the first update, we only update
    /// if we have made progress. This avoids useless locking of the coder's
    /// mutex.
    partial_update_started: bool,
    /// Filter chain memory usage
    mem_filters: u64,
}

impl WorkerLocal {
    /// `thr->out_pos`: amount of uncompressed data that has been decoded.
    fn out_pos(&self) -> usize {
        self.published + self.window_pos
    }

    /// The fields `get_thread()` and the main thread's next steps set.
    fn begin(&mut self, job: Job) {
        self.block_decoder = Some(job.block_decoder);
        self.outbuf_id = job.outbuf_id;
        self.window = job.buf;
        self.allocated = job.allocated;
        self.in_size = job.in_size;
        self.mem_filters = job.mem_filters;
        self.input.clear();
        self.in_pos = 0;
        self.window_pos = 0;
        self.published = 0;
        self.partial_update_started = false;
    }

    /// Moves the output so far to the output queue, and sets `pos` and
    /// `decoder_in_pos`, with the coder's mutex held.
    fn publish(&mut self, shared: &mut Shared) {
        let Some(outbuf) = shared.outq.buf_mut(self.outbuf_id) else {
            return;
        };

        if self.window_pos > 0 {
            if self.published == 0 {
                self.window.truncate(self.window_pos);
                outbuf.buf = core::mem::take(&mut self.window);
            } else {
                outbuf
                    .buf
                    .extend_from_slice(&self.window[..self.window_pos]);
            }
            self.published += self.window_pos;
            self.window_pos = 0;
        }

        outbuf.pos = self.published;
        outbuf.decoder_in_pos = self.in_pos;
    }

    /// `worker_decoder`.
    fn start(mut self) {
        let worker = Arc::clone(&self.worker);
        loop {
            let in_filled;
            let partial_update_enabled;
            {
                let mut shared = lock(&worker.mutex);
                loop {
                    match shared.state {
                        WorkerState::Idle => {
                            shared = wait(&worker.cond, shared);
                            continue;
                        }
                        WorkerState::Exit => return,
                        WorkerState::Run => {}
                    }

                    if let Some(job) = shared.job.take() {
                        self.begin(job);
                    }
                    take_pending(&mut self.input, &mut shared.pending);

                    // Update progress info for get_progress().
                    shared.progress_in = self.in_pos as u64;
                    shared.progress_out = self.out_pos() as u64;

                    // If we don't have any new input, wait for a signal from
                    // the main thread except if partial output has just been
                    // enabled (partial_update_enabled is true but _started is
                    // false). In that case we will do one normal run so that
                    // the partial output info gets passed to the main thread.
                    // The call to the Block decoder is useless but harmless
                    // as it can occur only once per Block.
                    if shared.in_filled == self.in_pos
                        && !(shared.partial_update_enabled && !self.partial_update_started)
                    {
                        shared = wait(&worker.cond, shared);
                        continue;
                    }

                    in_filled = shared.in_filled;
                    partial_update_enabled = shared.partial_update_enabled;
                    break;
                }
            }

            let Some(block_decoder) = self.block_decoder.as_mut() else {
                return;
            };

            let in_limit = if in_filled - self.in_pos > CHUNK_SIZE {
                self.in_pos + CHUNK_SIZE
            } else {
                in_filled
            };

            // As liblzma with a buffer of the whole Block: called again when
            // it has filled what there is.
            let room = self.allocated - self.published;
            let mut ret;
            loop {
                ensure_room(&mut self.window, self.window_pos, room);
                let end = room.min(self.window.len());
                ret = block_decoder.code(
                    &self.input[..in_limit],
                    &mut self.in_pos,
                    &mut self.window[..end],
                    &mut self.window_pos,
                    Action::Run,
                );
                if !(ret == Ret::Ok && self.window_pos == end && self.window_pos < room) {
                    break;
                }
            }

            if ret == Ret::Ok {
                if partial_update_enabled {
                    // Remember that we have done at least one partial
                    // update. After the first update we won't do updates
                    // unless we have made progress.
                    self.partial_update_started = true;

                    // The main thread is reading decompressed data from
                    // this Block. Tell the main thread about our progress.
                    let coder = Arc::clone(&self.coder);
                    let mut shared = lock(&coder.mutex);
                    self.publish(&mut shared);
                    coder.cond.notify_one();
                }

                continue;
            }

            // Either we finished successfully (LZMA_STREAM_END) or an error
            // occurred.
            {
                let mut shared = lock(&self.worker.mutex);

                // Block decoder ensures this, but do a sanity check anyway.
                if ret == Ret::StreamEnd && shared.in_filled != self.in_size {
                    ret = Ret::ProgError;
                }

                if shared.state != WorkerState::Exit {
                    shared.state = WorkerState::Idle;
                }
            }

            // Free the input buffer.
            if ret == Ret::StreamEnd {
                self.input = Vec::new();
            }

            let coder = Arc::clone(&self.coder);
            let mut shared = lock(&coder.mutex);

            // Move our progress info to the main thread.
            shared.progress_in += self.in_pos as u64;
            shared.progress_out += self.out_pos() as u64;

            // Mark the outbuf as finished.
            self.publish(&mut shared);
            if let Some(outbuf) = shared.outq.buf_mut(self.outbuf_id) {
                outbuf.finished = true;
                outbuf.finish_ret = ret;
            }

            // If an error occurred, tell it to the main thread.
            if ret != Ret::StreamEnd && shared.thread_error == Ret::Ok {
                shared.thread_error = ret;
            }

            {
                let mut worker = lock(&self.worker.mutex);
                worker.progress_in = 0;
                worker.progress_out = 0;

                // Return the worker thread to the stack of available threads
                // only if no errors occurred.
                if ret == Ret::StreamEnd {
                    worker.block_decoder = self.block_decoder.take();
                }
            }

            if ret == Ret::StreamEnd {
                // Update memory usage counters.
                shared.mem_in_use -= self.in_size as u64;
                shared.mem_in_use -= self.mem_filters;
                shared.mem_cached += self.mem_filters;

                // Put this thread to the stack of free threads.
                shared.threads_free.push(self.index);
            }

            coder.cond.notify_one();
        }
    }
}

/// A worker as the main thread has it.
struct WorkerHandle {
    worker: Arc<Worker>,
    /// The ID of this thread is used to join the thread when it's not needed
    /// anymore.
    thread: Option<JoinHandle<()>>,
    /// Filter chain memory usage
    mem_filters: u64,
    /// `partial_update_enabled`, which only the main thread modifies.
    partial_update_enabled: bool,
}

/// The sequence of the main thread.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sequence {
    StreamHeader,
    BlockHeader,
    BlockInit,
    BlockThrInit,
    BlockThrRun,
    BlockDirectInit,
    BlockDirectRun,
    IndexWaitOutput,
    IndexDecode,
    StreamFooter,
    StreamPadding,
    Error,
}

/// What `decode_block_header` returns.
enum BlockHeader {
    /// We didn't decode the whole Block Header yet.
    NotYet,
    /// The Index comes instead of a Block: `LZMA_INDEX_DETECTED`.
    IndexDetected,
    /// `coder->block_options` is ready.
    Decoded,
    Error(Ret),
}

/// `lzma_stream_coder` of `stream_decoder_mt.c`: the main thread's part.
pub(crate) struct StreamDecoderMt {
    sequence: Sequence,
    /// Block decoder of the direct mode
    block_decoder: Option<BlockDecoder>,
    /// Every Block Header will be decoded into this structure.
    block_options: Block,
    /// Stream Flags from Stream Header
    stream_flags: StreamFlags,
    /// Index is hashed so that it can be compared to the sizes of Blocks
    /// with O(1) memory usage.
    index_hash: IndexHash,
    /// Maximum wait time if cannot use all the input and cannot fill the
    /// output buffer. This is in milliseconds.
    timeout: u32,
    /// Error code to return after pending output has been copied out. If set
    /// in read_output_and_wait(), this is a mirror of thread_error. If set
    /// in stream_decode_mt() then it's, for example, error that occurred
    /// when decoding Block Header.
    pending_error: Ret,
    /// Number of threads that will be created at maximum.
    threads_max: u32,
    /// The workers created so far: `threads_initialized` of liblzma.
    threads: Vec<WorkerHandle>,
    /// The most recent worker thread to which the main thread writes the new
    /// input from the application.
    thr: Option<usize>,
    /// Its `in_size` and `in_filled`, which only the main thread modifies.
    thr_in_size: usize,
    thr_in_filled: usize,
    /// Memory usage that will not be exceeded in multi-threaded mode.
    /// Single-threaded mode can exceed this even by a large amount.
    memlimit_threading: u64,
    /// Memory usage limit that should never be exceeded. LZMA_MEMLIMIT_ERROR
    /// will be returned if decoding isn't possible even in single-threaded
    /// mode without exceeding this limit.
    memlimit_stop: u64,
    /// Amount of memory in use by the direct mode decoder. In threaded mode
    /// this is 0.
    mem_direct_mode: u64,
    /// Amount of memory needed for the filter chain of the next Block.
    mem_next_filters: u64,
    /// Amount of memory needed for the thread-specific input buffer for the
    /// next Block.
    mem_next_in: u64,
    /// Amount of memory actually needed to decode the next Block in threaded
    /// mode. This is mem_next_filters + mem_next_in + memory needed for
    /// lzma_outbuf.
    mem_next_block: u64,
    /// If true, LZMA_NO_CHECK is returned if the Stream has no integrity
    /// check.
    tell_no_check: bool,
    /// If true, LZMA_UNSUPPORTED_CHECK is returned if the Stream has an
    /// integrity check that isn't supported by this liblzma build.
    tell_unsupported_check: bool,
    /// If true, LZMA_GET_CHECK is returned after decoding Stream Header.
    tell_any_check: bool,
    /// If true, we will tell the Block decoder to skip calculating and
    /// verifying the integrity check.
    ignore_check: bool,
    /// If true, we will decode concatenated Streams that possibly have
    /// Stream Padding between or after them.
    concatenated: bool,
    /// If true, we will return any errors immediately instead of first
    /// producing all output before the location of the error.
    fail_fast: bool,
    /// When decoding concatenated Streams, this is true as long as we are
    /// decoding the first Stream.
    first_stream: bool,
    /// This is used to track if the previous call to stream_decode_mt() had
    /// output space (*out_pos < out_size) and managed to fill the output
    /// buffer (*out_pos == out_size). This may be set to true in
    /// read_output_and_wait(). This is read and then reset to false at the
    /// beginning of stream_decode_mt().
    out_was_filled: bool,
    /// Write position in buffer[] and position in Stream Padding
    pos: usize,
    /// Buffer to hold Stream Header, Block Header, and Stream Footer. Block
    /// Header has biggest maximum size.
    buffer: Box<[u8; BLOCK_HEADER_SIZE_MAX as usize]>,
    coder: Arc<Coder>,
}

/// `is_direct_mode_needed`: true if the size (compressed or uncompressed) is
/// such that threaded decompression cannot be used.
fn is_direct_mode_needed(size: u64) -> bool {
    size == VLI_UNKNOWN || size > usize::MAX as u64 / 3
}

impl StreamDecoderMt {
    /// `stream_decoder_mt_init`.
    pub(crate) fn new(options: &MtOptions) -> Result<StreamDecoderMt, Ret> {
        if options.threads == 0 || options.threads > THREADS_MAX {
            return Err(Ret::OptionsError);
        }

        if options.flags & !SUPPORTED_FLAGS != 0 {
            return Err(Ret::OptionsError);
        }

        let memlimit_stop = options.memlimit_stop.max(1);
        let memlimit_threading = options.memlimit_threading.max(1).min(memlimit_stop);

        let mut outq = OutQueue::default();
        let ret = outq.init(options.threads);
        if ret != Ret::Ok {
            return Err(ret);
        }

        Ok(StreamDecoderMt {
            sequence: Sequence::StreamHeader,
            block_decoder: None,
            block_options: Block::new(),
            stream_flags: StreamFlags::new(),
            index_hash: IndexHash::new(),
            timeout: options.timeout,
            pending_error: Ret::Ok,
            threads_max: options.threads,
            threads: Vec::new(),
            thr: None,
            thr_in_size: 0,
            thr_in_filled: 0,
            memlimit_threading,
            memlimit_stop,
            mem_direct_mode: 0,
            mem_next_filters: 0,
            mem_next_in: 0,
            mem_next_block: 0,
            tell_no_check: options.flags & TELL_NO_CHECK != 0,
            tell_unsupported_check: options.flags & TELL_UNSUPPORTED_CHECK != 0,
            tell_any_check: options.flags & TELL_ANY_CHECK != 0,
            ignore_check: options.flags & IGNORE_CHECK != 0,
            concatenated: options.flags & CONCATENATED != 0,
            fail_fast: options.flags & FAIL_FAST != 0,
            first_stream: true,
            out_was_filled: false,
            pos: 0,
            buffer: Box::new([0; BLOCK_HEADER_SIZE_MAX as usize]),
            coder: Arc::new(Coder {
                mutex: Mutex::new(Shared {
                    thread_error: Ret::Ok,
                    threads_free: Vec::new(),
                    outq,
                    mem_in_use: 0,
                    mem_cached: 0,
                    progress_in: 0,
                    progress_out: 0,
                }),
                cond: Condvar::new(),
            }),
        })
    }

    /// `threads_end`: tells the worker threads to exit and waits for them to
    /// terminate.
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

        // The threads don't update these when they exit. Do it here.
        let mut shared = lock(&self.coder.mutex);
        shared.threads_free.clear();
        shared.mem_in_use = 0;
        shared.mem_cached = 0;
    }

    /// `threads_stop`: tell worker threads to stop without doing any cleaning
    /// up. The clean up will be done when threads_end() is called; it's not
    /// possible to reuse the threads after threads_stop().
    ///
    /// This is called before returning an unrecoverable error code to the
    /// application.
    fn threads_stop(&self) {
        for thread in &self.threads {
            // The threads that are in the Run state will stop when they
            // check the state the next time. There's no need to signal the
            // condition variable.
            lock(&thread.worker.mutex).state = WorkerState::Idle;
        }
    }

    /// `initialize_new_thread`: a new worker and its thread.
    fn initialize_new_thread(&mut self) -> Ret {
        let worker = Arc::new(Worker {
            mutex: Mutex::new(WorkerShared {
                state: WorkerState::Idle,
                job: None,
                in_filled: 0,
                pending: Vec::new(),
                progress_in: 0,
                progress_out: 0,
                partial_update_enabled: false,
                block_decoder: None,
            }),
            cond: Condvar::new(),
        });

        let local = WorkerLocal {
            worker: Arc::clone(&worker),
            coder: Arc::clone(&self.coder),
            index: self.threads.len(),
            input: Vec::new(),
            in_size: 0,
            in_pos: 0,
            block_decoder: None,
            window: Vec::new(),
            window_pos: 0,
            published: 0,
            outbuf_id: 0,
            allocated: 0,
            partial_update_started: false,
            mem_filters: 0,
        };

        let thread = match std::thread::Builder::new()
            .name("xz-decoder".into())
            .spawn(move || local.start())
        {
            Ok(thread) => thread,
            Err(_) => return Ret::MemError,
        };

        self.thr = Some(self.threads.len());
        self.threads.push(WorkerHandle {
            worker,
            thread: Some(thread),
            mem_filters: 0,
            partial_update_enabled: false,
        });

        Ret::Ok
    }

    /// `get_thread`: a free worker for the next Block.
    fn get_thread(&mut self) -> Ret {
        // If there is a free structure on the stack, use it.
        {
            let mut shared = lock(&self.coder.mutex);
            if let Some(index) = shared.threads_free.pop() {
                self.thr = Some(index);

                // The thread is no longer in the cache so subtract it from
                // the cached memory usage. Don't add it to mem_in_use though;
                // the caller will handle it since it knows how much memory
                // it will actually use (the filter chain might change).
                shared.mem_cached -= self.threads[index].mem_filters;
            }
        }

        if self.thr.is_none() {
            // Initialize a new thread.
            let ret = self.initialize_new_thread();
            if ret != Ret::Ok {
                return ret;
            }
        }

        let Some(thr) = self.thr else {
            return Ret::ProgError;
        };

        self.thr_in_filled = 0;
        self.threads[thr].partial_update_enabled = false;

        let mut shared = lock(&self.threads[thr].worker.mutex);
        shared.in_filled = 0;
        shared.pending.clear();
        shared.progress_in = 0;
        shared.progress_out = 0;
        shared.partial_update_enabled = false;

        Ret::Ok
    }

    /// `worker_enable_partial_update`.
    fn enable_partial_update(&mut self, index: usize) {
        let thread = &mut self.threads[index];
        thread.partial_update_enabled = true;
        lock(&thread.worker.mutex).partial_update_enabled = true;
        thread.worker.cond.notify_one();
    }

    /// `read_output_and_wait`.
    fn read_output_and_wait(
        &mut self,
        output: &mut [u8],
        out_pos: &mut usize,
        mut input_is_possible: Option<&mut bool>,
        waiting_allowed: bool,
        wait_abs: &mut Option<Instant>,
    ) -> Ret {
        let mut ret;

        let coder = Arc::clone(&self.coder);
        let mut shared = lock(&coder.mutex);

        loop {
            // Get as much output from the queue as is possible without
            // blocking.
            let out_start = *out_pos;
            loop {
                ret = shared.outq.read(output, out_pos).0;

                // If a Block was finished, tell the worker thread of the next
                // Block (if it is still running) to start telling the main
                // thread when new output is available.
                if ret == Ret::StreamEnd
                    && let Some(index) = shared.outq.enable_partial_output()
                {
                    self.enable_partial_update(index);
                }

                // Loop until a Block wasn't finished. It's important to loop
                // around even if *out_pos == out_size because there could be
                // an empty Block that will return LZMA_STREAM_END without
                // needing any output space.
                if ret != Ret::StreamEnd {
                    break;
                }
            }

            // Check if lzma_outq_read reported an error from the Block
            // decoder.
            if ret != Ret::Ok {
                break;
            }

            // If the output buffer is now full but it wasn't full when this
            // function was called, set out_was_filled.
            if *out_pos == output.len() && *out_pos != out_start {
                self.out_was_filled = true;
            }

            // Check if any thread has indicated an error.
            if shared.thread_error != Ret::Ok {
                // If LZMA_FAIL_FAST was used, report errors from worker
                // threads immediately.
                if self.fail_fast {
                    ret = shared.thread_error;
                    break;
                }

                // Otherwise set pending_error. The value we set here will not
                // actually get used other than working as a flag that an
                // error has occurred.
                self.pending_error = Ret::ProgError;
            }

            // Check if decoding of the next Block can be started. The
            // memusage of the active threads must be low enough, there must
            // be a free buffer slot in the output queue, and there must be a
            // free thread (that can be either created or an existing one
            // reused).
            if let Some(possible) = input_is_possible.as_deref_mut()
                && self
                    .memlimit_threading
                    .wrapping_sub(shared.mem_in_use)
                    .wrapping_sub(shared.outq.mem_in_use)
                    >= self.mem_next_block
                && shared.outq.has_buf()
                && ((self.threads.len() as u32) < self.threads_max
                    || !shared.threads_free.is_empty())
            {
                *possible = true;
                break;
            }

            // If the caller doesn't want us to block, return now.
            if !waiting_allowed {
                break;
            }

            // This check is needed only when input_is_possible is NULL. We
            // must return if we aren't waiting for input to become possible
            // and there is no more output coming from the queue.
            if shared.outq.is_empty() {
                break;
            }

            // If there is more data available from the queue, our out buffer
            // must be full and we need to return so that the application can
            // provide more output space.
            if shared.outq.is_readable() {
                break;
            }

            // If the application stops providing more input in the middle of
            // a Block, there will eventually be one worker thread left that
            // is stuck waiting for more input (that might never arrive) and a
            // matching outbuf which the worker thread cannot finish due to
            // lack of input. We must detect this situation, otherwise we
            // would end up waiting indefinitely.
            if let Some(thr) = self.thr
                && self.threads[thr].partial_update_enabled
                && shared.outq.head_decoder_in_pos() == Some(self.thr_in_filled)
            {
                break;
            }

            // Wait for input or output to become possible.
            if self.timeout != 0 {
                let deadline = *wait_abs.get_or_insert_with(|| {
                    Instant::now() + Duration::from_millis(u64::from(self.timeout))
                });
                let left = deadline.saturating_duration_since(Instant::now());
                let (guard, result) = coder
                    .cond
                    .wait_timeout(shared, left)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                shared = guard;
                if result.timed_out() {
                    ret = Ret::TimedOut;
                    break;
                }
            } else {
                shared = wait(&coder.cond, shared);
            }
        }

        drop(shared);

        // If we are returning an error, then the application cannot get more
        // output from us and thus keeping the threads running is useless and
        // waste of CPU time.
        if ret != Ret::Ok && ret != Ret::TimedOut {
            self.threads_stop();
        }

        ret
    }

    /// `decode_block_header`.
    fn decode_block_header(&mut self, input: &[u8], in_pos: &mut usize) -> BlockHeader {
        if *in_pos >= input.len() {
            return BlockHeader::NotYet;
        }

        if self.pos == 0 {
            // Detect if it's Index.
            if input[*in_pos] == INDEX_INDICATOR {
                return BlockHeader::IndexDetected;
            }

            // Calculate the size of the Block Header. Note that Block Header
            // decoder wants to see this byte too so don't advance *in_pos.
            self.block_options.header_size = header_size_decode(input[*in_pos]);
        }

        // Copy the Block Header to the internal buffer.
        let header_size = self.block_options.header_size as usize;
        bufcpy(
            input,
            in_pos,
            &mut self.buffer[..header_size],
            &mut self.pos,
        );

        // Return if we didn't get the whole Block Header yet.
        if self.pos < header_size {
            return BlockHeader::NotYet;
        }

        self.pos = 0;

        // Version 1 is needed to support the .ignore_check option.
        self.block_options.version = 1;

        // Decode the Block Header.
        let ret = self
            .block_options
            .header_decode(&self.buffer[..header_size]);
        if ret != Ret::Ok {
            return BlockHeader::Error(ret);
        }

        // If LZMA_IGNORE_CHECK was used, this flag needs to be set. It has to
        // be set after lzma_block_header_decode() because it always resets
        // this to false.
        self.block_options.ignore_check = self.ignore_check;

        // coder->block_options is ready now.
        BlockHeader::Decoded
    }

    /// `comp_blk_size`: the size of the Compressed Data + Block Padding +
    /// Check.
    fn comp_blk_size(&self) -> u64 {
        vli_ceil4(self.block_options.compressed_size) + u64::from(self.stream_flags.check.size())
    }

    /// `stream_decoder_reset`.
    fn reset(&mut self) {
        // Initialize the Index hash used to verify the Index.
        self.index_hash = IndexHash::new();

        // Reset the rest of the variables.
        self.sequence = Sequence::StreamHeader;
        self.pos = 0;
    }

    /// `SEQ_BLOCK_THR_INIT` after `read_output_and_wait()` has told that the
    /// Block can start: the memory, the worker and the Block decoder.
    fn block_thr_start(&mut self) -> Result<(), Ret> {
        // We know that we can start decoding this Block without exceeding
        // memlimit_threading. However, to stay below memlimit_threading may
        // require freeing some of the cached memory.
        //
        // Get a local copy of variables that require locking the mutex. It is
        // fine if the worker threads modify the real values after we read
        // these as those changes can only be towards more favorable
        // conditions (less memory in use, more in cache).
        let (mem_in_use, mem_cached, mut free) = {
            let shared = lock(&self.coder.mutex);
            (
                shared.mem_in_use,
                shared.mem_cached,
                shared.threads_free.clone(),
            )
        };

        // The maximum amount of memory that can be held by other threads and
        // cached buffers while allowing us to start decoding the next Block.
        let mem_max = self.memlimit_threading.wrapping_sub(self.mem_next_block);

        let uncompressed_size = self.block_options.uncompressed_size as usize;
        let outq_mem_in_use;
        {
            let mut shared = lock(&self.coder.mutex);

            // If the existing allocations are so large that starting to
            // decode this Block might exceed memlimit_threads, try to free
            // memory from the output queue cache first.
            if mem_in_use + mem_cached + shared.outq.mem_allocated > mem_max {
                // Clear the outq cache except leave one buffer in the cache
                // if its size is correct. That way we don't free and almost
                // immediately reallocate an identical buffer.
                shared.outq.clear_cache2(uncompressed_size);
            }
            outq_mem_in_use = shared.outq.mem_in_use;
        }

        // If there is at least one worker_thread in the cache and the
        // existing allocations are so large that starting to decode this
        // Block might exceed memlimit_threads, free memory by freeing cached
        // Block decoders.
        let mut mem_freed = 0;
        if !free.is_empty() && mem_in_use + mem_cached + outq_mem_in_use > mem_max {
            // Don't free the first Block decoder if its memory usage isn't
            // greater than what this Block will need. Typically the same
            // filter chain is used for all Blocks so this way the allocations
            // can be reused when get_thread() picks the first worker_thread
            // from the cache.
            if let Some(&first) = free.last()
                && self.threads[first].mem_filters <= self.mem_next_filters
            {
                free.pop();
            }

            for index in free {
                let thread = &mut self.threads[index];
                lock(&thread.worker.mutex).block_decoder = None;
                mem_freed += thread.mem_filters;
                thread.mem_filters = 0;
            }
        }

        // Update the memory usage counters. Note that coder->mem_* may have
        // changed since we read them so we must subtract or add the changes.
        {
            let mut shared = lock(&self.coder.mutex);
            shared.mem_cached -= mem_freed;

            // Memory needed for the filters and the input buffer. The output
            // queue takes care of its own counter so we don't touch it here.
            shared.mem_in_use += self.mem_next_in + self.mem_next_filters;
        }

        // Allocate memory for the output buffer in the output queue.
        let ret = lock(&self.coder.mutex).outq.prealloc_buf(uncompressed_size);
        if ret != Ret::Ok {
            self.threads_stop();
            return Err(ret);
        }

        // Set up coder->thr.
        let ret = self.get_thread();
        if ret != Ret::Ok {
            self.threads_stop();
            return Err(ret);
        }

        let Some(thr) = self.thr else {
            return Err(Ret::ProgError);
        };

        // The new Block decoder memory usage is already counted in
        // coder->mem_in_use. Store it in the thread too.
        self.threads[thr].mem_filters = self.mem_next_filters;

        // Initialize the Block decoder, after freeing the last one.
        lock(&self.threads[thr].worker.mutex).block_decoder = None;
        let block_decoder = BlockDecoder::new(self.block_options.clone());

        // Free the allocated filter options since they are needed only to
        // initialize the Block decoder.
        self.block_options.filters.clear();

        // Check if memory usage calculation and Block encoder initialization
        // succeeded.
        let block_decoder = match block_decoder {
            Ok(block_decoder) => block_decoder,
            Err(ret) => {
                self.pending_error = ret;
                self.sequence = Sequence::Error;
                return Ok(());
            }
        };

        // Allocate the input buffer.
        self.thr_in_size = self.mem_next_in as usize;
        {
            let worker = &self.threads[thr].worker;
            let mut shared = lock(&worker.mutex);
            if shared.pending.try_reserve_exact(self.thr_in_size).is_err() {
                drop(shared);
                self.threads_stop();
                return Err(Ret::MemError);
            }
        }

        // Get the preallocated output buffer.
        let (outbuf_id, buf, allocated) = {
            let mut shared = lock(&self.coder.mutex);
            let id = shared.outq.get_buf(Some(thr));
            match shared.outq.buf_mut(id) {
                Some(outbuf) => (id, core::mem::take(&mut outbuf.buf), outbuf.allocated),
                None => return Err(Ret::ProgError),
            }
        };

        // Start the decoder.
        {
            let worker = &self.threads[thr].worker;
            let mut shared = lock(&worker.mutex);
            shared.job = Some(Job {
                block_decoder,
                outbuf_id,
                buf,
                allocated,
                in_size: self.thr_in_size,
                mem_filters: self.mem_next_filters,
            });
            shared.state = WorkerState::Run;
            worker.cond.notify_one();
        }

        // Enable output from the thread that holds the oldest output buffer
        // in the output queue (if such a thread exists).
        let index = lock(&self.coder.mutex).outq.enable_partial_output();
        if let Some(index) = index {
            self.enable_partial_update(index);
        }

        self.sequence = Sequence::BlockThrRun;
        Ok(())
    }
}

impl Drop for StreamDecoderMt {
    /// `stream_decoder_mt_end`.
    fn drop(&mut self) {
        self.threads_end();
    }
}

impl NextCoder for StreamDecoderMt {
    /// `stream_decode_mt`.
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        let mut wait_abs = None;

        // Determine if in SEQ_BLOCK_HEADER and SEQ_BLOCK_THR_RUN we should
        // tell read_output_and_wait() to wait until it can fill the output
        // buffer (or a timeout occurs). Two conditions must be met:
        //
        // (1) If the caller provided no new input.
        //
        // (2) Even if (1) is true, we will not wait if the previous call to
        //     this function managed to produce some output and the output
        //     buffer became full.
        //
        // However, if LZMA_FINISH is used, the above is ignored and we always
        // wait (timeout can still cause us to return) because we know that
        // we won't get any more input.
        let waiting_allowed =
            action == Action::Finish || (*in_pos == input.len() && !self.out_was_filled);
        self.out_was_filled = false;

        loop {
            match self.sequence {
                Sequence::StreamHeader => {
                    // Copy the Stream Header to the internal buffer.
                    let in_old = *in_pos;
                    bufcpy(
                        input,
                        in_pos,
                        &mut self.buffer[..STREAM_HEADER_SIZE],
                        &mut self.pos,
                    );
                    lock(&self.coder.mutex).progress_in += (*in_pos - in_old) as u64;

                    // Return if we didn't get the whole Stream Header yet.
                    if self.pos < STREAM_HEADER_SIZE {
                        return Ret::Ok;
                    }

                    self.pos = 0;

                    // Decode the Stream Header.
                    let ret = stream_flags::header_decode(&mut self.stream_flags, &self.buffer[..]);
                    if ret != Ret::Ok {
                        return if ret == Ret::FormatError && !self.first_stream {
                            Ret::DataError
                        } else {
                            ret
                        };
                    }

                    // If we are decoding concatenated Streams, and the later
                    // Streams have invalid Header Magic Bytes, we give
                    // LZMA_DATA_ERROR instead of LZMA_FORMAT_ERROR.
                    self.first_stream = false;

                    // Copy the type of the Check so that Block Header and
                    // Block decoders see it.
                    self.block_options.check = self.stream_flags.check;

                    // Even if we return LZMA_*_CHECK below, we want to
                    // continue from Block Header decoding.
                    self.sequence = Sequence::BlockHeader;

                    // Detect if there's no integrity check or if it is
                    // unsupported if those were requested by the application.
                    if self.tell_no_check && self.stream_flags.check == Check::NONE {
                        return Ret::NoCheck;
                    }

                    if self.tell_unsupported_check && !self.stream_flags.check.is_supported() {
                        return Ret::UnsupportedCheck;
                    }

                    if self.tell_any_check {
                        return Ret::GetCheck;
                    }
                }

                Sequence::BlockHeader => {
                    let in_old = *in_pos;
                    let header = self.decode_block_header(input, in_pos);

                    // Worker threads may finish earlier Blocks and need to
                    // update coder->progress_in at the same time with us.
                    lock(&self.coder.mutex).progress_in += (*in_pos - in_old) as u64;

                    match header {
                        BlockHeader::NotYet => {
                            // We didn't decode the whole Block Header yet.
                            //
                            // Read output from the queue before returning.
                            // This is important because it is possible that
                            // the application doesn't have any new input
                            // available immediately.
                            //
                            // If LZMA_FINISH was used we know that we won't
                            // get more input, so the file must be truncated
                            // if we get here. If fail-fast is enabled then we
                            // will return immediately using LZMA_DATA_ERROR
                            // instead of LZMA_OK or LZMA_BUF_ERROR.
                            if action == Action::Finish && self.fail_fast {
                                // We won't produce any more output. Stop the
                                // unfinished worker threads so they won't
                                // waste CPU time.
                                self.threads_stop();
                                return Ret::DataError;
                            }

                            // read_output_and_wait() will call threads_stop()
                            // if needed.
                            let ret = self.read_output_and_wait(
                                output,
                                out_pos,
                                None,
                                waiting_allowed,
                                &mut wait_abs,
                            );
                            if ret != Ret::Ok {
                                return ret;
                            }

                            if self.pending_error != Ret::Ok {
                                self.sequence = Sequence::Error;
                                continue;
                            }

                            return Ret::Ok;
                        }

                        BlockHeader::IndexDetected => {
                            self.sequence = Sequence::IndexWaitOutput;
                            continue;
                        }

                        // See if an error occurred.
                        BlockHeader::Error(ret) => {
                            self.pending_error = ret;
                            self.sequence = Sequence::Error;
                            continue;
                        }

                        BlockHeader::Decoded => {}
                    }

                    // Calculate the memory usage of the filters / Block
                    // decoder.
                    self.mem_next_filters = raw_decoder_memusage(&self.block_options.filters);

                    if self.mem_next_filters == u64::MAX {
                        // One or more unknown Filter IDs.
                        self.pending_error = Ret::OptionsError;
                        self.sequence = Sequence::Error;
                        continue;
                    }

                    self.sequence = Sequence::BlockInit;
                }

                Sequence::BlockInit => {
                    // Check if decoding is possible at all with the current
                    // memlimit_stop which we must never exceed.
                    //
                    // This needs to be the first thing in SEQ_BLOCK_INIT to
                    // make it possible to restart decoding after increasing
                    // memlimit_stop with lzma_memlimit_set().
                    if self.mem_next_filters > self.memlimit_stop {
                        // Flush pending output before returning
                        // LZMA_MEMLIMIT_ERROR. If the application doesn't
                        // want to increase the limit, at least it will get
                        // all the output possible so far.
                        let ret =
                            self.read_output_and_wait(output, out_pos, None, true, &mut wait_abs);
                        if ret != Ret::Ok {
                            return ret;
                        }

                        if !lock(&self.coder.mutex).outq.is_empty() {
                            return Ret::Ok;
                        }

                        return Ret::MemlimitError;
                    }

                    // Check if the size information is available in Block
                    // Header. If it is, check if the sizes are small enough
                    // that we don't need to worry *too* much about integer
                    // overflows later in the code. If these conditions are
                    // not met, we must use the single-threaded direct mode.
                    if is_direct_mode_needed(self.block_options.compressed_size)
                        || is_direct_mode_needed(self.block_options.uncompressed_size)
                    {
                        self.sequence = Sequence::BlockDirectInit;
                        continue;
                    }

                    // Calculate the amount of memory needed for the input and
                    // output buffers in threaded mode.
                    //
                    // These cannot overflow because we already checked that
                    // the sizes are small enough using
                    // is_direct_mode_needed().
                    self.mem_next_in = self.comp_blk_size();
                    let mem_buffers = self.mem_next_in
                        + outbuf_memusage(self.block_options.uncompressed_size as usize);

                    // Add the amount needed by the filters. Avoid integer
                    // overflows.
                    if u64::MAX - mem_buffers < self.mem_next_filters {
                        // Use direct mode if the memusage would overflow.
                        self.sequence = Sequence::BlockDirectInit;
                        continue;
                    }

                    // Amount of memory needed to decode this Block in
                    // threaded mode:
                    self.mem_next_block = self.mem_next_filters + mem_buffers;

                    // If this alone would exceed memlimit_threading, then we
                    // must use the single-threaded direct mode.
                    if self.mem_next_block > self.memlimit_threading {
                        self.sequence = Sequence::BlockDirectInit;
                        continue;
                    }

                    // Use the threaded mode. Free the direct mode decoder in
                    // case it has been initialized.
                    self.block_decoder = None;
                    self.mem_direct_mode = 0;

                    // Since we already know what the sizes are supposed to
                    // be, we can already add them to the Index hash. The
                    // Block decoder will verify the values while decoding.
                    let ret = self.index_hash.append(
                        self.block_options.unpadded_size(),
                        self.block_options.uncompressed_size,
                    );
                    if ret != Ret::Ok {
                        self.pending_error = ret;
                        self.sequence = Sequence::Error;
                        continue;
                    }

                    self.sequence = Sequence::BlockThrInit;
                }

                Sequence::BlockThrInit => {
                    // We need to wait for a multiple conditions to become
                    // true until we can initialize the Block decoder and let
                    // a worker thread decode it. While we wait, we must copy
                    // decompressed data to the out buffer and catch possible
                    // decoder errors.
                    let mut block_can_start = false;

                    let ret = self.read_output_and_wait(
                        output,
                        out_pos,
                        Some(&mut block_can_start),
                        true,
                        &mut wait_abs,
                    );
                    if ret != Ret::Ok {
                        return ret;
                    }

                    if self.pending_error != Ret::Ok {
                        self.sequence = Sequence::Error;
                        continue;
                    }

                    if !block_can_start {
                        // It's not a timeout because that was returned
                        // already. Output queue cannot be empty either
                        // because in that case block_can_start would have
                        // been true. Thus the output buffer must be full and
                        // the queue isn't empty.
                        return Ret::Ok;
                    }

                    if let Err(ret) = self.block_thr_start() {
                        return ret;
                    }
                }

                Sequence::BlockThrRun => {
                    if action == Action::Finish && self.fail_fast {
                        // We know that we won't get more input and that the
                        // caller wants fail-fast behavior. If we see that we
                        // don't have enough input to finish this Block,
                        // return LZMA_DATA_ERROR immediately.
                        let in_avail = input.len() - *in_pos;
                        let in_needed = self.thr_in_size - self.thr_in_filled;
                        if in_avail < in_needed {
                            self.threads_stop();
                            return Ret::DataError;
                        }
                    }

                    let Some(thr) = self.thr else {
                        return Ret::ProgError;
                    };

                    // Copy input to the worker thread.
                    let copy_size =
                        (input.len() - *in_pos).min(self.thr_in_size - self.thr_in_filled);
                    let start = *in_pos;
                    *in_pos += copy_size;
                    self.thr_in_filled += copy_size;

                    // Tell the thread how much we copied.
                    {
                        let worker = &self.threads[thr].worker;
                        let mut shared = lock(&worker.mutex);
                        shared.pending.extend_from_slice(&input[start..*in_pos]);
                        shared.in_filled = self.thr_in_filled;
                        worker.cond.notify_one();
                    }

                    // Read output from the output queue. Just like in
                    // SEQ_BLOCK_HEADER, we wait to fill the output buffer
                    // only if waiting_allowed was set to true in the
                    // beginning of this function and there is no input
                    // available.
                    let ret = self.read_output_and_wait(
                        output,
                        out_pos,
                        None,
                        waiting_allowed && *in_pos == input.len(),
                        &mut wait_abs,
                    );
                    if ret != Ret::Ok {
                        return ret;
                    }

                    if self.pending_error != Ret::Ok {
                        self.sequence = Sequence::Error;
                        continue;
                    }

                    // Return if the input didn't contain the whole Block.
                    if self.thr_in_filled < self.thr_in_size {
                        return Ret::Ok;
                    }

                    // The whole Block has been copied to the thread-specific
                    // buffer. Continue from the next Block Header or Index.
                    self.thr = None;
                    self.sequence = Sequence::BlockHeader;
                }

                Sequence::BlockDirectInit => {
                    // Wait for the threads to finish and that all decoded
                    // data has been copied to the output. That is, wait until
                    // the output queue becomes empty.
                    let ret = self.read_output_and_wait(output, out_pos, None, true, &mut wait_abs);
                    if ret != Ret::Ok {
                        return ret;
                    }

                    {
                        let mut shared = lock(&self.coder.mutex);
                        if !shared.outq.is_empty() {
                            return Ret::Ok;
                        }

                        // Free the cached output buffers.
                        shared.outq.clear_cache();
                    }

                    // Get rid of the worker threads.
                    self.threads_end();

                    // Initialize the Block decoder.
                    let block_decoder = BlockDecoder::new(self.block_options.clone());

                    // Free the allocated filter options since they are needed
                    // only to initialize the Block decoder.
                    self.block_options.filters.clear();

                    // Check if Block decoder initialization succeeded.
                    match block_decoder {
                        Ok(block_decoder) => self.block_decoder = Some(block_decoder),
                        Err(ret) => return ret,
                    }

                    // Make the memory usage visible to _memconfig().
                    self.mem_direct_mode = self.mem_next_filters;

                    self.sequence = Sequence::BlockDirectRun;
                }

                Sequence::BlockDirectRun => {
                    let Some(block_decoder) = self.block_decoder.as_mut() else {
                        return Ret::ProgError;
                    };
                    let (in_old, out_old) = (*in_pos, *out_pos);
                    let ret = block_decoder.code(input, in_pos, output, out_pos, action);
                    {
                        let mut shared = lock(&self.coder.mutex);
                        shared.progress_in += (*in_pos - in_old) as u64;
                        shared.progress_out += (*out_pos - out_old) as u64;
                    }

                    if ret != Ret::StreamEnd {
                        return ret;
                    }

                    // Block decoded successfully. Add the new size pair to
                    // the Index hash.
                    let ret = self.index_hash.append(
                        block_decoder.block.unpadded_size(),
                        block_decoder.block.uncompressed_size,
                    );
                    if ret != Ret::Ok {
                        return ret;
                    }

                    self.sequence = Sequence::BlockHeader;
                }

                Sequence::IndexWaitOutput => {
                    // Flush the output from all worker threads so that we can
                    // decode the Index without thinking about threading.
                    let ret = self.read_output_and_wait(output, out_pos, None, true, &mut wait_abs);
                    if ret != Ret::Ok {
                        return ret;
                    }

                    if !lock(&self.coder.mutex).outq.is_empty() {
                        return Ret::Ok;
                    }

                    self.sequence = Sequence::IndexDecode;
                }

                Sequence::IndexDecode => {
                    // If we don't have any input, don't call
                    // lzma_index_hash_decode() since it would return
                    // LZMA_BUF_ERROR, which we must not do here.
                    if *in_pos >= input.len() {
                        return Ret::Ok;
                    }

                    // Decode the Index and compare it to the hash calculated
                    // from the sizes of the Blocks (if any).
                    let in_old = *in_pos;
                    let ret = self.index_hash.decode(input, in_pos);
                    lock(&self.coder.mutex).progress_in += (*in_pos - in_old) as u64;
                    if ret != Ret::StreamEnd {
                        return ret;
                    }

                    self.sequence = Sequence::StreamFooter;
                }

                Sequence::StreamFooter => {
                    // Copy the Stream Footer to the internal buffer.
                    let in_old = *in_pos;
                    bufcpy(
                        input,
                        in_pos,
                        &mut self.buffer[..STREAM_HEADER_SIZE],
                        &mut self.pos,
                    );
                    lock(&self.coder.mutex).progress_in += (*in_pos - in_old) as u64;

                    // Return if we didn't get the whole Stream Footer yet.
                    if self.pos < STREAM_HEADER_SIZE {
                        return Ret::Ok;
                    }

                    self.pos = 0;

                    // Decode the Stream Footer. The decoder gives
                    // LZMA_FORMAT_ERROR if the magic bytes don't match, so
                    // convert that return code to LZMA_DATA_ERROR.
                    let mut footer_flags = StreamFlags::new();
                    let ret = stream_flags::footer_decode(&mut footer_flags, &self.buffer[..]);
                    if ret != Ret::Ok {
                        return if ret == Ret::FormatError {
                            Ret::DataError
                        } else {
                            ret
                        };
                    }

                    // Check that Index Size stored in the Stream Footer
                    // matches the real size of the Index field.
                    if self.index_hash.size() != footer_flags.backward_size {
                        return Ret::DataError;
                    }

                    // Compare that the Stream Flags fields are identical in
                    // both Stream Header and Stream Footer.
                    let ret = stream_flags::compare(&self.stream_flags, &footer_flags);
                    if ret != Ret::Ok {
                        return ret;
                    }

                    if !self.concatenated {
                        return Ret::StreamEnd;
                    }

                    self.sequence = Sequence::StreamPadding;
                }

                Sequence::StreamPadding => {
                    // Skip over possible Stream Padding.
                    loop {
                        if *in_pos >= input.len() {
                            // Unless LZMA_FINISH was used, we cannot know if
                            // there's more input coming later.
                            if action != Action::Finish {
                                return Ret::Ok;
                            }

                            // Stream Padding must be a multiple of four
                            // bytes.
                            return if self.pos == 0 {
                                Ret::StreamEnd
                            } else {
                                Ret::DataError
                            };
                        }

                        // If the byte is not zero, it probably indicates
                        // beginning of a new Stream (or the file is corrupt).
                        if input[*in_pos] != 0x00 {
                            break;
                        }

                        *in_pos += 1;
                        lock(&self.coder.mutex).progress_in += 1;
                        self.pos = (self.pos + 1) & 3;
                    }

                    // Stream Padding must be a multiple of four bytes (empty
                    // Stream Padding is OK).
                    if self.pos != 0 {
                        *in_pos += 1;
                        lock(&self.coder.mutex).progress_in += 1;
                        return Ret::DataError;
                    }

                    // Prepare to decode the next Stream.
                    self.reset();
                }

                Sequence::Error => {
                    if !self.fail_fast {
                        // Let the application get all data before the point
                        // where the error was detected. This matches the
                        // behavior of single-threaded use.
                        let ret =
                            self.read_output_and_wait(output, out_pos, None, true, &mut wait_abs);
                        if ret != Ret::Ok {
                            return ret;
                        }

                        // We get here only if the error happened in the main
                        // thread, for example, unsupported Block Header.
                        if !lock(&self.coder.mutex).outq.is_empty() {
                            return Ret::Ok;
                        }
                    }

                    // We only get here if no errors were detected by the
                    // worker threads. Errors from worker threads would have
                    // already been returned by the call to
                    // read_output_and_wait() above.
                    return self.pending_error;
                }
            }
        }
    }

    /// `stream_decoder_mt_get_check`.
    fn get_check(&self) -> Option<Check> {
        Some(self.stream_flags.check)
    }

    /// `stream_decoder_mt_memconfig`: this gets and sets memlimit_stop.
    /// memlimit_threading cannot be modified after initialization.
    fn memconfig(
        &mut self,
        memusage: &mut u64,
        old_memlimit: &mut u64,
        new_memlimit: u64,
    ) -> Option<Ret> {
        {
            let shared = lock(&self.coder.mutex);
            *memusage = self.mem_direct_mode
                + shared.mem_in_use
                + shared.mem_cached
                + shared.outq.mem_allocated;
        }

        // If no filter chains are allocated, *memusage may be zero. Always
        // return at least LZMA_MEMUSAGE_BASE.
        if *memusage < MEMUSAGE_BASE {
            *memusage = MEMUSAGE_BASE;
        }

        *old_memlimit = self.memlimit_stop;

        if new_memlimit != 0 {
            if new_memlimit < *memusage {
                return Some(Ret::MemlimitError);
            }

            self.memlimit_stop = new_memlimit;
        }

        Some(Ret::Ok)
    }

    /// `stream_decoder_mt_get_progress`.
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
