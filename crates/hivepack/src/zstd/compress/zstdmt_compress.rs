//! Port of `compress/zstdmt_compress.c`: compression on several threads.
//!
//! A frame streamed with workers (`ZSTD_c_nbWorkers`) is cut into jobs of
//! its input, which a pool of threads ([`Pool`]) compresses side by side,
//! while the caller's thread takes the input, cuts it into jobs, and
//! writes out their output in order. A job compresses its input as blocks
//! of the one frame, with a context of its own: the first job writes the
//! frame header (and has the frame's dictionary), the last one the last
//! block. Each job after the first loads the end of the input before it
//! as raw content, its prefix (the overlap), starts with no repeat offsets
//! (the decoder's are those the job before left, which it does not know),
//! and writes no frame header. What must go through the input in order,
//! the frame's checksum and long distance matching, each job does in
//! turn before it compresses (the serial state).
//!
//! The frames do not depend on the number of threads, nor on their
//! timing: where a job ends depends only on the input and on the calls
//! (it is full, a flush or the end of the frame comes, or, with
//! `ZSTD_c_rsyncable`, the content says), and what a job writes only on
//! its input, its prefix, the parameters and the frame's dictionary. How
//! much input a call takes, and how much it writes out, depends on how far
//! the threads have got.
//!
//! Differs from libzstd, in how memory is managed, with the same jobs:
//! - **Input.** libzstd copies the input into a round buffer, where each
//!   job reads its input and prefix in place, and a call takes no input
//!   while the part of the buffer to fill is still used by a job not
//!   done, or by the window of long distance matching
//!   (`ZSTDMT_tryGetInputRange`, `ZSTDMT_waitForLdmComplete`). The port
//!   copies each job's prefix and input into a buffer of the job's own,
//!   which the job gives back once it is done; a call never waits for
//!   room.
//!   The input held is still bounded: one buffer being filled, one job
//!   waiting for a thread, and one job per thread. A job's input ends
//!   after the same bytes as libzstd's, and its prefix is the same bytes.
//! - **Output.** Each job compresses into a buffer of the size libzstd
//!   gives it, `ZSTD_compressBound` of the job size, and copies what each
//!   chunk adds to where the caller's thread reads it from (libzstd's
//!   thread reads the job's buffer).
//! - **Long distance matching.** It runs on the input in order, with a
//!   window of its own over the whole input, as libzstd's serial state
//!   does; libzstd's window lies in the round buffer, and has its older
//!   segment where the buffer wraps around. The port keeps the input that
//!   window can reach in a buffer of its own, one segment. Its indices
//!   are libzstd's, and its matches the same: the round buffer always
//!   holds more than the window's size before each job, so that libzstd's
//!   segments only ever end below what the window's maximum distance
//!   keeps, and a match across them reads the bytes that follow.
//! - **Pools.** No pools of buffers of sequences (`ZSTDMT_seqPool`): each
//!   job gets the sequences of long distance matching from the serial
//!   state. Contexts and output buffers are kept for later jobs, as in
//!   libzstd, and so are the jobs' input buffers and the copies of their
//!   output, whose memory is then mapped already, as libzstd's round buffer
//!   is.

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use crate::zstd::common::bits::highbit32;
#[cfg(doc)]
use crate::zstd::common::error_private::ErrorCode;
use crate::zstd::common::error_private::{Result, error};
use crate::zstd::common::pool::{BusyTicket, Pool};
use crate::zstd::common::xxhash::Xxh64State;
use crate::zstd::common::zstd_internal::{BlockType, ZSTD_BLOCKSIZE_MAX, ZSTD_BLOCKSIZELOG_MAX};
use crate::zstd::compress::zstd_cdict::CDict;
use crate::zstd::compress::zstd_compress::{
    CCtx, CCtxParams, EndDirective, FrameProgression, zstd_compress_bound, zstd_cycle_log,
};
use crate::zstd::compress::zstd_compress_internal::{
    Buffers, CompressionParameters, LdmEntry, LdmParams, LdmState, ParamSwitch, RawSeqStore,
    Strategy, Window, WindowBuffer, zstd_rolling_hash_append, zstd_rolling_hash_compute,
    zstd_rolling_hash_prime_power, zstd_rolling_hash_rotate,
};
use crate::zstd::compress::zstd_ldm::{
    zstd_ldm_adjust_parameters, zstd_ldm_fill_hash_table, zstd_ldm_generate_sequences,
    zstd_ldm_get_max_nb_seq,
};
use crate::zstd::decompress::zstd_ddict::DictContentType;
use crate::zstd::decompress::zstd_decompress::{InBuffer, OutBuffer};

#[cfg(test)]
use crate::zstd::compress::zstd_compress_internal::OVERFLOW_CORRECT_FREQUENTLY;

/// `ZSTDMT_NBWORKERS_MAX` on 64-bit machines: the most worker threads.
///
/// The port takes libzstd's numbers for 64-bit machines everywhere, as it
/// does for the window: libzstd allows 64 on 32-bit machines, and jobs up
/// to 512 MB (a job log up to 29). Only frames with windows of 256 MB or
/// more, or jobs set larger than 512 MB, could differ there.
pub(crate) const ZSTDMT_NBWORKERS_MAX: u32 = 256;
/// `ZSTDMT_JOBSIZE_MIN`: the smallest job; a frame of a known size up to
/// this is compressed without workers.
pub(crate) const ZSTDMT_JOBSIZE_MIN: usize = 512 << 10;
/// `ZSTDMT_JOBLOG_MAX` on 64-bit machines.
const ZSTDMT_JOBLOG_MAX: u32 = 30;
/// `ZSTDMT_JOBSIZE_MAX` on 64-bit machines.
pub(crate) const ZSTDMT_JOBSIZE_MAX: usize = 1024 << 20;
/// `ZSTD_OVERLAPLOG_MIN`, `ZSTD_OVERLAPLOG_MAX`: the bounds of
/// `ZSTD_c_overlapLog`.
pub(crate) const ZSTD_OVERLAPLOG_MIN: i32 = 0;
pub(crate) const ZSTD_OVERLAPLOG_MAX: i32 = 9;

/// `RSYNC_LENGTH`: the bytes the rolling hash of `ZSTD_c_rsyncable` covers.
const RSYNC_LENGTH: usize = 32;
/// `RSYNC_MIN_BLOCK_LOG`, `RSYNC_MIN_BLOCK_SIZE`: no job ends at a
/// synchronization point before this much input, a block's worth, so as
/// not to lose too much compression, and for the output to stay within
/// `ZSTD_compressBound`.
const RSYNC_MIN_BLOCK_LOG: u32 = ZSTD_BLOCKSIZELOG_MAX;
const RSYNC_MIN_BLOCK_SIZE: usize = 1 << RSYNC_MIN_BLOCK_LOG;

/// The chunks a job compresses its input in, for the caller's thread to
/// write out what is done sooner.
const CHUNK_SIZE: usize = 4 * ZSTD_BLOCKSIZE_MAX;

/// `ZSTD_pthread_mutex_lock`: a thread that panicked while holding a lock
/// leaves the state it guards as consistent as the code around it, which
/// fails the job.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `ZSTD_pthread_cond_wait`
fn wait<'a, T>(cond: &Condvar, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
    cond.wait(guard).unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Buffer pool

/// `BUF_POOL_MAX_NB_BUFFERS`: two output buffers per thread, and three
/// more.
fn buf_pool_max_nb_buffers(nb_workers: usize) -> usize {
    2 * nb_workers + 3
}

/// `ZSTDMT_bufferPool`, for the jobs' output buffers: those of the jobs
/// done, kept for the next ones.
///
/// Differs from libzstd: the port has two more, for the jobs' input
/// buffers and the copies of their output (see the module's notes); a
/// buffer kept is one whose memory is mapped already, as libzstd's round
/// buffer is.
struct BufferPool {
    state: Mutex<BufferPoolState>,
}

struct BufferPoolState {
    /// `buffers`: the buffers kept, `nbBuffers` of them.
    buffers: Vec<Vec<u8>>,
    /// `totalBuffers`: the most kept.
    total_buffers: usize,
}

impl BufferPool {
    /// `ZSTDMT_createBufferPool`: a pool that keeps up to `total_buffers`.
    fn new(total_buffers: usize) -> BufferPool {
        BufferPool {
            state: Mutex::new(BufferPoolState {
                buffers: Vec::new(),
                total_buffers,
            }),
        }
    }

    /// An empty buffer with room for at least `capacity` bytes: one kept,
    /// if large enough but not more than 8 times so, or a new one. Fails
    /// with `MemoryAllocation` where the room cannot be had.
    fn get_empty(&self, capacity: usize) -> Result<Vec<u8>> {
        let kept = lock(&self.state).buffers.pop();
        if let Some(mut buffer) = kept
            && buffer.capacity() >= capacity
            && buffer.capacity() >> 3 <= capacity
        {
            buffer.clear();
            return Ok(buffer);
        }
        let mut buffer = Vec::new();
        if buffer.try_reserve_exact(capacity).is_err() {
            return error!(MemoryAllocation);
        }
        Ok(buffer)
    }

    /// `ZSTDMT_getBuffer`: a buffer of at least `size` bytes: one kept, if
    /// large enough but not more than 8 times so, or a new one. What it
    /// holds is not to be read before it is written. Fails with
    /// `MemoryAllocation` where a 32-bit machine has not the room.
    fn get_buffer(&self, size: usize) -> Result<Vec<u8>> {
        let kept = lock(&self.state).buffers.pop();
        if let Some(buffer) = kept
            && buffer.len() >= size
            && buffer.len() >> 3 <= size
        {
            return Ok(buffer);
        }
        // On 64-bit machines, taken zeroed: its pages are mapped only as
        // they are written, as libzstd's are, and a job sized for more
        // input than it gets costs only what it writes. On 32-bit machines,
        // where jobs of up to 1 GB may not find the room, reserved first,
        // so that the job fails as libzstd's does rather than abort; then
        // zeroed.
        if cfg!(target_pointer_width = "64") {
            return Ok(vec![0; size]);
        }
        let mut buffer = Vec::new();
        if buffer.try_reserve_exact(size).is_err() {
            return error!(MemoryAllocation);
        }
        buffer.resize(size, 0);
        Ok(buffer)
    }

    /// `ZSTDMT_releaseBuffer`: `buffer` kept for later, up to the pool's
    /// capacity.
    fn release_buffer(&self, buffer: Vec<u8>) {
        let mut state = lock(&self.state);
        if state.buffers.len() < state.total_buffers {
            state.buffers.push(buffer);
        }
    }

    /// `ZSTDMT_expandBufferPool`: room for at least `max_nb_buffers`.
    fn expand(&self, max_nb_buffers: usize) {
        let mut state = lock(&self.state);
        state.total_buffers = state.total_buffers.max(max_nb_buffers);
    }
}

// ---------------------------------------------------------------------------
// Thread pools shared between contexts

/// `ZSTD_threadPool`: worker threads that contexts compressing with
/// workers ([`CParameter::NbWorkers`](crate::zstd::CParameter::NbWorkers)) can
/// share ([`CCtx::ref_thread_pool`]), rather than each starting threads of
/// its own. A clone is the same pool. Its threads end once the pool and
/// the contexts that use it are dropped (`ZSTD_freeThreadPool`), and their
/// jobs are done.
///
/// The frames do not depend on it. Each job waits for a thread free in the
/// pool, whichever context's jobs the others run. As in libzstd, a context
/// whose number of workers changes between its frames resizes the pool to
/// that number, for every context that shares it.
#[derive(Clone)]
pub struct ThreadPool(Arc<Pool<JobDescription>>);

impl ThreadPool {
    /// `ZSTD_createThreadPool`: a pool of `num_threads` threads, started
    /// at once. Fails with [`ErrorCode::MemoryAllocation`] for no threads,
    /// or when a thread cannot be started, where libzstd returns `NULL`.
    pub fn new(num_threads: usize) -> Result<ThreadPool> {
        if num_threads == 0 {
            return error!(MemoryAllocation);
        }
        Ok(ThreadPool(Arc::new(Pool::new(
            num_threads,
            zstdmt_compression_job,
        )?)))
    }
}

impl std::fmt::Debug for ThreadPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreadPool").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// CCtx pool

/// `ZSTDMT_CCtxPool`: the jobs' contexts, kept for the next jobs.
struct CCtxPool {
    state: Mutex<CCtxPoolState>,
}

struct CCtxPoolState {
    /// The contexts kept, `availCCtx` of them.
    cctxs: Vec<CCtx>,
    /// `totalCCtx`: the most kept, one per thread.
    total_cctx: usize,
}

impl CCtxPool {
    /// `ZSTDMT_getCCtx`: a context kept, or a new one.
    fn get_cctx(&self) -> CCtx {
        lock(&self.state).cctxs.pop().unwrap_or_default()
    }

    /// `ZSTDMT_releaseCCtx`: `cctx` kept for later, up to the pool's size.
    fn release_cctx(&self, cctx: CCtx) {
        let mut state = lock(&self.state);
        if state.cctxs.len() < state.total_cctx {
            state.cctxs.push(cctx);
        }
    }

    /// `ZSTDMT_expandCCtxPool`: room for at least `nb_workers`.
    fn expand(&self, nb_workers: usize) {
        let mut state = lock(&self.state);
        state.total_cctx = state.total_cctx.max(nb_workers);
    }
}

// ---------------------------------------------------------------------------
// Serial state

/// `SerialState`: what each job does in turn, in the order of the input:
/// the frame's checksum and long distance matching.
struct SerialState {
    state: Mutex<Serial>,
    /// `cond`: signaled when the next job may take its turn.
    cond: Condvar,
}

struct Serial {
    /// `params`: the frame's, those of long distance matching adjusted.
    params: CCtxParams,
    /// `ldmState`: the window and tables of long distance matching, over
    /// the frame's whole input.
    ldm_state: LdmState,
    /// The input the window of long distance matching can still reach,
    /// [`WindowBuffer::Input`] for it: each job's, one after another.
    ///
    /// Differs from libzstd: there the window is over the round buffer;
    /// see the module's notes.
    ldm_input: Vec<u8>,
    /// The frame's prefix of raw content, the window's
    /// [`WindowBuffer::Dict`]: loaded first, the older segment after.
    ldm_dict: Arc<[u8]>,
    /// The most sequences long distance matching can find in a job
    /// (`ZSTDMT_setNbSeq`).
    max_nb_seq: usize,
    /// `xxhState`: the checksum of the input so far.
    xxh_state: Xxh64State,
    /// `nextJobID`: the job whose turn it is.
    next_job_id: u32,
}

impl SerialState {
    fn new() -> SerialState {
        let (params, _) = CCtxParams::requested_default();
        SerialState {
            state: Mutex::new(Serial {
                params,
                ldm_state: LdmState::new(),
                ldm_input: Vec::new(),
                ldm_dict: Arc::from(&[][..]),
                max_nb_seq: 0,
                xxh_state: Xxh64State::new(0),
                next_job_id: 0,
            }),
            cond: Condvar::new(),
        }
    }

    /// `ZSTDMT_serialState_reset`: for a new frame with `params`, of jobs
    /// up to `job_size`, with `dict`, a prefix of raw content, loaded into
    /// long distance matching's tables. Fails with `MemoryAllocation`
    /// where its hash table cannot be had.
    fn reset(
        &self,
        mut params: CCtxParams,
        job_size: usize,
        dict: Option<&Arc<[u8]>>,
    ) -> Result<()> {
        let mut serial = lock(&self.state);
        let serial = &mut *serial;
        // The parameters of long distance matching, adjusted, or none.
        if params.ldm_enable == ParamSwitch::Enable {
            zstd_ldm_adjust_parameters(&mut params.ldm, &params.c_params);
            debug_assert!(params.ldm.hash_log >= params.ldm.bucket_size_log);
            debug_assert!(params.ldm.hash_rate_log < 32);
        } else {
            params.ldm = LdmParams::default();
        }
        serial.next_job_id = 0;
        if params.f_params.checksum_flag {
            serial.xxh_state = Xxh64State::new(0);
        }
        if params.ldm_enable == ParamSwitch::Enable {
            let hash_log = params.ldm.hash_log;
            let bucket_log = hash_log - params.ldm.bucket_size_log;
            // The sequences of a job.
            serial.max_nb_seq = zstd_ldm_get_max_nb_seq(ParamSwitch::Enable, &params.ldm, job_size);
            // The window, new.
            let ldm = &mut serial.ldm_state;
            ldm.window = Window::new();
            // The tables, cleared. libzstd's allocation may fail; so may
            // the port's, rather than abort.
            let hash_size = 1usize << hash_log;
            ldm.hash_table.clear();
            if ldm.hash_table.try_reserve_exact(hash_size).is_err() {
                return error!(MemoryAllocation);
            }
            ldm.hash_table.resize(hash_size, LdmEntry::default());
            ldm.bucket_offsets.clear();
            ldm.bucket_offsets.resize(1usize << bucket_log, 0);
            serial.ldm_input.clear();
            serial.ldm_dict = Arc::from(&[][..]);

            // The window and the hash table with the dictionary.
            ldm.loaded_dict_end = 0;
            if let Some(dict) = dict.filter(|dict| !dict.is_empty()) {
                ldm.window.update(WindowBuffer::Dict, 0, dict.len(), false);
                zstd_ldm_fill_hash_table(ldm, dict, 0, dict.len(), &params.ldm);
                ldm.loaded_dict_end = if params.force_window {
                    0
                } else {
                    ldm.window.index(dict.len())
                };
                serial.ldm_dict = dict.clone();
            }
        }
        serial.params = params;
        serial.params.job_size = job_size;
        Ok(())
    }

    /// `ZSTDMT_serialState_genSequences`: the turn of job `job_id`, once
    /// the jobs before have had theirs: its input `src` through long
    /// distance matching, whose sequences come back, and the checksum.
    /// Then the next job's turn. A job after it that failed may have taken
    /// its turn: then nothing.
    fn gen_sequences(&self, src: &[u8], job_id: u32) -> RawSeqStore {
        let mut serial = lock(&self.state);
        // Wait for our turn.
        while serial.next_job_id < job_id {
            serial = wait(&self.cond, serial);
        }
        let mut seq_store = RawSeqStore::default();
        if serial.next_job_id == job_id {
            let serial = &mut *serial;
            if serial.params.ldm_enable == ParamSwitch::Enable {
                debug_assert!(src.len() <= serial.params.job_size);
                seq_store.capacity = serial.max_nb_seq;
                seq_store
                    .seq
                    .reserve(serial.max_nb_seq.min(src.len() / 4 + 1));
                serial.drop_ldm_input_out_of_reach();
                // The input into the window, after the input before.
                let start = serial.ldm_input.len();
                serial.ldm_input.extend_from_slice(src);
                let ldm = &mut serial.ldm_state;
                ldm.window
                    .update(WindowBuffer::Input, start, src.len(), false);
                let window = ldm.window;
                let buffer = |which| match which {
                    WindowBuffer::Input => &serial.ldm_input[..],
                    WindowBuffer::Dict => &serial.ldm_dict[..],
                    WindowBuffer::None | WindowBuffer::InBuff => &[][..],
                };
                let result = zstd_ldm_generate_sequences(
                    ldm,
                    &mut seq_store,
                    &serial.params.ldm,
                    buffer(window.buffer),
                    buffer(window.dict_buffer),
                    start,
                    start + src.len(),
                );
                // The store has room for the most sequences a job can
                // have: it never fails.
                debug_assert!(result.is_ok());
            }
            if serial.params.f_params.checksum_flag && !src.is_empty() {
                serial.xxh_state.update(src);
            }
        }
        // Now it is the next job's turn.
        serial.next_job_id += 1;
        self.cond.notify_all();
        seq_store
    }

    /// `ZSTDMT_serialState_ensureFinished`: the turn of job `job_id` taken,
    /// if it failed before taking it, so that the jobs after do not wait
    /// for it.
    fn ensure_finished(&self, job_id: u32) {
        let mut serial = lock(&self.state);
        if serial.next_job_id <= job_id {
            serial.next_job_id = job_id + 1;
            self.cond.notify_all();
        }
    }

    /// `XXH64_digest(&serial.xxhState)`, once the last job has had its
    /// turn.
    fn digest(&self) -> u64 {
        lock(&self.state).xxh_state.digest()
    }

    /// How many times long distance matching has lowered its indices.
    #[cfg(test)]
    fn nb_overflow_corrections(&self) -> u32 {
        lock(&self.state).ldm_state.window.nb_overflow_corrections
    }
}

/// In tests, how many times the jobs, and long distance matching, have
/// lowered their indices, all frames together (the jobs' contexts are not
/// the caller's).
#[cfg(test)]
pub(crate) static MT_OVERFLOW_CORRECTIONS: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

impl Serial {
    /// Lets go of the input of long distance matching that its window can
    /// no longer reach: before its prefix, in the one buffer. Its limits
    /// only go up (a correction of the indices keeps them above the bytes
    /// they were at), so those bytes are never read again. Only once they
    /// are half of the buffer, not to move the rest too often.
    fn drop_ldm_input_out_of_reach(&mut self) {
        let window = &mut self.ldm_state.window;
        if window.buffer != WindowBuffer::Input {
            return;
        }
        // The older segment is the dictionary's, if any.
        debug_assert!(window.dict_buffer != WindowBuffer::Input);
        let below = (i64::from(window.dict_limit) - window.base)
            .clamp(0, self.ldm_input.len() as i64) as usize;
        if below > 0 && below >= self.ldm_input.len() / 2 {
            self.ldm_input.drain(..below);
            // The same indices, at positions that many bytes lower.
            window.base += below as i64;
        }
    }
}

// ---------------------------------------------------------------------------
// Jobs

/// What a job and the caller's thread share (`consumed`, `cSize` and the
/// output, behind `job_mutex`; `job_cond`, signaled at each chunk done).
struct JobProgress {
    state: Mutex<JobState>,
    cond: Condvar,
}

struct JobState {
    /// `consumed`: the input compressed so far; the whole input once the
    /// job is done, failed or not.
    consumed: usize,
    /// `cSize`: the output so far, or the job's error.
    c_size: Result<usize>,
    /// The output so far, `c_size` bytes.
    ///
    /// Differs from libzstd: libzstd's caller reads the job's own output
    /// buffer, `dstBuff`; here a copy of what each chunk wrote, which the
    /// job adds to once its chunk is done.
    dst: Vec<u8>,
}

impl JobProgress {
    /// A job not started, its output to go into `dst`, empty.
    fn new(dst: Vec<u8>) -> JobProgress {
        JobProgress {
            state: Mutex::new(JobState {
                consumed: 0,
                c_size: Ok(0),
                dst,
            }),
            cond: Condvar::new(),
        }
    }
}

/// What the contexts' and buffers' pools, and the serial state, are to
/// the jobs: shared by the frame's jobs and the caller's thread.
struct Shared {
    cctx_pool: CCtxPool,
    buf_pool: BufferPool,
    /// The jobs' input buffers, and the copies of their output.
    in_pool: BufferPool,
    out_pool: BufferPool,
    serial: SerialState,
}

/// `ZSTDMT_jobDescription`, as the thread that compresses the job gets it.
struct JobDescription {
    /// `jobID`: the job's number in the frame, from 0.
    job_id: u32,
    /// `firstJob`, `lastJob`
    first_job: bool,
    last_job: bool,
    /// `params`: the frame's parameters when the job was made.
    params: CCtxParams,
    /// `cdict`: the frame's `CDict`, for the first job.
    cdict: Option<Arc<CDict>>,
    /// For the first job, its prefix: the frame's prefix of raw content
    /// (`ZSTD_CCtx_refPrefix`), apart from its input. libzstd's first job
    /// has it as its `prefix`.
    dict_prefix: Option<Arc<[u8]>>,
    /// `fullFrameSize`: the frame's size, pledged, or unknown.
    full_frame_size: u64,
    /// `prefix`, the end of the job before (for the jobs after the first),
    /// and then `src`, the job's input.
    data: Vec<u8>,
    prefix_size: usize,
    /// The size of the output buffer: `ZSTD_compressBound` of the job size.
    dst_capacity: usize,
    progress: Arc<JobProgress>,
    shared: Arc<Shared>,
    /// In tests, `ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY` as the caller's
    /// thread has it: libzstd's is set for the whole program.
    #[cfg(test)]
    overflow_correct_frequently: bool,
}

/// `ZSTDMT_jobDescription`, as the caller's thread keeps it, from the
/// moment the job is handed over until its output is all written out.
struct JobSlot {
    /// The size of the job's input (`src.size`).
    src_size: usize,
    /// `frameChecksumNeeded`: the frame's checksum comes after this job's
    /// output.
    frame_checksum_needed: bool,
    /// `dstFlushed`: the output written out so far.
    dst_flushed: usize,
    progress: Arc<JobProgress>,
}

/// `ZSTDMT_compressionJob`, the pool's function: compresses a job, then
/// reports it done (with its error, if it failed) and lets go of its
/// input.
fn zstdmt_compression_job(mut job: JobDescription, mut ticket: BusyTicket<JobDescription>) {
    #[cfg(test)]
    OVERFLOW_CORRECT_FREQUENTLY.with(|flag| flag.set(job.overflow_correct_frequently));
    let progress = job.progress.clone();
    let shared = job.shared.clone();
    let src_size = job.data.len() - job.prefix_size;
    // Without room for its output, the job fails
    // (JOB_ERROR(memory_allocation)).
    let (mut dst, room) = match shared.buf_pool.get_buffer(job.dst_capacity) {
        Ok(dst) => (dst, Ok(())),
        Err(error) => (Vec::new(), Err(error)),
    };
    let had_room = room.is_ok();
    let mut cctx = shared.cctx_pool.get_cctx();
    // A panic is a bug; it fails the job rather than leave the caller
    // waiting for it.
    let result = catch_unwind(AssertUnwindSafe(|| {
        room?;
        zstdmt_compress_job(&job, &mut cctx, &mut dst[..job.dst_capacity], &progress)
    }));
    // _endJob: the job's turn of the serial state taken, if it failed
    // before; its context back to the pool (but after a panic).
    shared.serial.ensure_finished(job.job_id);
    let result = match result {
        Ok(result) => {
            #[cfg(test)]
            MT_OVERFLOW_CORRECTIONS.fetch_add(
                cctx.nb_overflow_corrections() + shared.serial.nb_overflow_corrections(),
                std::sync::atomic::Ordering::Relaxed,
            );
            shared.cctx_pool.release_cctx(cctx);
            result
        }
        Err(_) => error!(Generic),
    };
    // The input buffer, for a later job.
    shared.in_pool.release_buffer(std::mem::take(&mut job.data));
    drop(job);
    ticket.release();
    // Report: the last block's output, and the whole input consumed (the
    // job is then done).
    {
        let mut state = lock(&progress.state);
        match result {
            Ok((at, last_c_block_size)) => {
                state
                    .dst
                    .extend_from_slice(&dst[at..at + last_c_block_size]);
                if let Ok(c_size) = &mut state.c_size {
                    *c_size += last_c_block_size;
                }
            }
            Err(error) => state.c_size = Err(error),
        }
        state.consumed = src_size;
    }
    progress.cond.notify_all();
    if had_room {
        shared.buf_pool.release_buffer(dst);
    }
}

/// The work of `ZSTDMT_compressionJob`: the job's input into `dst`, by
/// chunks, each reported to `progress` as it is done but the last.
/// Returns where the last chunk's output is in `dst`, and its size.
fn zstdmt_compress_job(
    job: &JobDescription,
    cctx: &mut CCtx,
    dst: &mut [u8],
    progress: &JobProgress,
) -> Result<(usize, usize)> {
    // The job's parameters: the frame's, copied.
    let mut job_params = job.params;
    // The frame's checksum is computed apart, but written in the header:
    // the first job keeps the flag.
    if job.job_id != 0 {
        job_params.f_params.checksum_flag = false;
    }
    // Long distance matching is done apart, too.
    job_params.ldm_enable = ParamSwitch::Disable;
    job_params.nb_workers = 0;
    let src_size = job.data.len() - job.prefix_size;

    // The serial step, as early as possible.
    let raw_seq_store = job
        .shared
        .serial
        .gen_sequences(&job.data[job.prefix_size..], job.job_id);

    // The job's input is in the input buffer, after its prefix.
    let mut bufs = Buffers::new(&job.data, &[]);
    if let Some(cdict) = &job.cdict {
        // Only the first job.
        debug_assert!(job.first_job);
        cctx.compress_begin_internal(None, Some(cdict), &job_params, job.full_frame_size, false)?;
        bufs.dict = &cdict.content;
        bufs.cdict = Some(cdict);
    } else {
        let pledged_src_size = if job.first_job {
            job.full_frame_size
        } else {
            src_size as u64
        };
        // The prefix of a job after the first is part of its window, not a
        // dictionary reached whole (ZSTD_c_forceMaxWindow); in the input's
        // segment, ZSTD_checkDictValidity would drop it as one at the first
        // block anyway. Their prefix and input, one buffer, are one
        // segment too: they turn deterministicRefPrefix off.
        job_params.force_window = !job.first_job;
        if !job.first_job {
            job_params.deterministic_ref_prefix = false;
        }
        if job.first_job {
            // Its prefix is the frame's prefix of raw content, if any,
            // apart from the input: the window's older segment.
            debug_assert!(job.prefix_size == 0);
            let prefix = job.dict_prefix.as_deref();
            cctx.compress_begin_internal(
                prefix.map(|prefix| (prefix, DictContentType::RawContent)),
                None,
                &job_params,
                pledged_src_size,
                false,
            )?;
            if let Some(prefix) = prefix {
                bufs.dict = prefix;
            }
        } else {
            cctx.compress_begin_job(&job.data, job.prefix_size, &job_params, pledged_src_size)?;
        }
    }

    // The sequences of long distance matching, once the context is set up.
    if raw_seq_store.size() > 0 {
        cctx.reference_external_sequences(raw_seq_store);
    }

    if !job.first_job {
        // The frame header, written over: the first job writes the frame's.
        cctx.compress_continue(
            dst,
            bufs,
            WindowBuffer::Input,
            job.prefix_size,
            job.prefix_size,
        )?;
        cctx.invalidate_rep_codes();
    }

    // The job by chunks, for the caller's thread to write out sooner.
    let nb_chunks = src_size.div_ceil(CHUNK_SIZE);
    let mut ip = job.prefix_size;
    let mut op = 0;
    for chunk_nb in 1..nb_chunks {
        let c_size = cctx.compress_continue(
            &mut dst[op..],
            bufs,
            WindowBuffer::Input,
            ip,
            ip + CHUNK_SIZE,
        )?;
        {
            let mut state = lock(&progress.state);
            state.dst.extend_from_slice(&dst[op..op + c_size]);
            if let Ok(total) = &mut state.c_size {
                *total += c_size;
            }
            state.consumed = CHUNK_SIZE * chunk_nb;
        }
        // Some more output to write out.
        progress.cond.notify_all();
        ip += CHUNK_SIZE;
        op += c_size;
    }
    // The last chunk; the last job must write a last block, even empty.
    if nb_chunks > 0 || job.last_job {
        let last_block_size1 = src_size & (CHUNK_SIZE - 1);
        let last_block_size = if last_block_size1 == 0 && src_size >= CHUNK_SIZE {
            CHUNK_SIZE
        } else {
            last_block_size1
        };
        let end = ip + last_block_size;
        let c_size = if job.last_job {
            cctx.compress_end(&mut dst[op..], bufs, WindowBuffer::Input, ip, end)?
        } else {
            cctx.compress_continue(&mut dst[op..], bufs, WindowBuffer::Input, ip, end)?
        };
        return Ok((op, c_size));
    }
    Ok((op, 0))
}

// ---------------------------------------------------------------------------
// The context

/// `RSyncState_t`: the rolling hash of `ZSTD_c_rsyncable`, and the bits it
/// must have set at a synchronization point.
#[derive(Clone, Copy, Default)]
struct RsyncState {
    hash: u64,
    hit_mask: u64,
    prime_power: u64,
}

/// `SyncPoint`: how much input to take, and whether the job must then end.
struct SyncPoint {
    to_load: usize,
    flush: bool,
}

/// `ZSTDMT_CCtx`: the worker threads, the jobs of the frame, and the input
/// taken for the next.
pub(crate) struct MtCCtx {
    /// `factory`: the threads, the context's own or a pool shared with
    /// other contexts (`providedFactory`).
    factory: Arc<Pool<JobDescription>>,
    /// The jobs handed over and not all written out yet, from `doneJobID`
    /// to `nextJobID`, oldest first.
    jobs: VecDeque<JobSlot>,
    /// `jobIDMask + 1`: the most jobs handed over and not all written out.
    job_table_size: usize,
    shared: Arc<Shared>,
    /// `params`: the frame's.
    params: CCtxParams,
    /// `targetSectionSize`: the input of a job.
    target_section_size: usize,
    /// `targetPrefixSize`: the overlap.
    target_prefix_size: usize,
    /// `jobReady`: a job made, which no thread was free to take.
    job_ready: Option<(JobSlot, JobDescription)>,
    /// `inBuff`: the next job's prefix, then the input taken for it so far
    /// (`filled` bytes).
    in_buff: Vec<u8>,
    in_prefix_size: usize,
    rsync: RsyncState,
    /// `nextJobID`: the number of the next job.
    next_job_id: u32,
    /// `consumed`, `produced`: the input and the output of the frame's
    /// jobs done and all written out.
    consumed: u64,
    produced: u64,
    /// `frameEnded`: the last job is made.
    frame_ended: bool,
    /// `frameContentSize`: the frame's size, pledged, or unknown.
    frame_content_size: u64,
    /// `cdict`: the first job's `CDict`: the one set, or one made from the
    /// prefix (`cdictLocal`).
    cdict: Option<Arc<CDict>>,
    /// The first job's prefix, the frame's prefix of raw content
    /// (`inBuff.prefix` before the first job).
    dict_prefix: Option<Arc<[u8]>>,
    /// The size of a job's output buffer (the buffer pool's `bufferSize`).
    dst_capacity: usize,
}

/// `ZSTDMT_createJobsTable`: the size of the job table for `nb_workers`
/// threads: a power of 2 over `nb_workers + 2`.
pub(crate) fn zstdmt_jobs_table_size(nb_workers: usize) -> usize {
    1 << (highbit32((nb_workers + 2) as u32) + 1)
}

/// `ZSTDMT_computeTargetJobLog`: the log of the job size by default, from
/// the window; with long distance matching, whose window is usually far
/// larger, from the cycle of the chain table.
pub(crate) fn zstdmt_compute_target_job_log(params: &CCtxParams) -> u32 {
    let job_log = if params.ldm_enable == ParamSwitch::Enable {
        21.max(zstd_cycle_log(params.c_params.chain_log, params.c_params.strategy) + 3)
    } else {
        20.max(params.c_params.window_log + 2)
    };
    job_log.min(ZSTDMT_JOBLOG_MAX)
}

/// `ZSTDMT_overlapLog_default`: the overlap of each strategy.
fn zstdmt_overlap_log_default(strategy: Strategy) -> i32 {
    match strategy {
        Strategy::Btultra2 => 9,
        Strategy::Btultra | Strategy::Btopt => 8,
        Strategy::Btlazy2 | Strategy::Lazy2 => 7,
        Strategy::Lazy | Strategy::Greedy | Strategy::Dfast | Strategy::Fast => 6,
    }
}

/// `ZSTDMT_overlapLog`: the overlap log set, or the strategy's for 0.
fn zstdmt_overlap_log(ovlog: i32, strategy: Strategy) -> i32 {
    debug_assert!((0..=9).contains(&ovlog));
    if ovlog == 0 {
        return zstdmt_overlap_log_default(strategy);
    }
    ovlog
}

/// `ZSTDMT_computeOverlapSize`: the overlap, a fraction of the window
/// (with long distance matching, of the job size as long as it is
/// smaller).
pub(crate) fn zstdmt_compute_overlap_size(params: &CCtxParams) -> usize {
    let overlap_r_log = 9 - zstdmt_overlap_log(params.overlap_log, params.c_params.strategy);
    let window_log = params.c_params.window_log as i32;
    let mut ov_log = if overlap_r_log >= 8 {
        0
    } else {
        window_log - overlap_r_log
    };
    debug_assert!((0..=8).contains(&overlap_r_log));
    if params.ldm_enable == ParamSwitch::Enable {
        // A fraction of the job size, rather than of the window; there is
        // one even for an overlap log of 1.
        ov_log = window_log.min(zstdmt_compute_target_job_log(params) as i32 - 2) - overlap_r_log;
    }
    debug_assert!((0..=31).contains(&ov_log));
    if ov_log == 0 { 0 } else { 1 << ov_log }
}

impl MtCCtx {
    /// `ZSTDMT_createCCtx_advanced`: the threads, and the pools, for
    /// `nb_workers` (at least one); with `pool`, its threads rather than
    /// threads of its own, the pool's size left as it is.
    pub(crate) fn new(nb_workers: u32, pool: Option<&ThreadPool>) -> Result<MtCCtx> {
        let nb_workers = nb_workers.clamp(1, ZSTDMT_NBWORKERS_MAX);
        let workers = nb_workers as usize;
        let (mut params, _) = CCtxParams::requested_default();
        params.nb_workers = nb_workers;
        let factory = match pool {
            Some(pool) => pool.0.clone(),
            None => Arc::new(Pool::new(workers, zstdmt_compression_job)?),
        };
        Ok(MtCCtx {
            factory,
            jobs: VecDeque::new(),
            job_table_size: zstdmt_jobs_table_size(workers),
            shared: Arc::new(Shared {
                cctx_pool: CCtxPool {
                    state: Mutex::new(CCtxPoolState {
                        cctxs: Vec::new(),
                        total_cctx: workers,
                    }),
                },
                buf_pool: BufferPool::new(buf_pool_max_nb_buffers(workers)),
                in_pool: BufferPool::new(workers + 2),
                out_pool: BufferPool::new(buf_pool_max_nb_buffers(workers)),
                serial: SerialState::new(),
            }),
            params,
            target_section_size: 0,
            target_prefix_size: 0,
            job_ready: None,
            in_buff: Vec::new(),
            in_prefix_size: 0,
            rsync: RsyncState::default(),
            next_job_id: 0,
            consumed: 0,
            produced: 0,
            frame_ended: false,
            frame_content_size: 0,
            cdict: None,
            dict_prefix: None,
            dst_capacity: 0,
        })
    }

    /// `ZSTDMT_resize`: `nb_workers` threads, and the pools and the job
    /// table grown for them. A pool shared with other contexts is resized
    /// too, for all of them, as in libzstd.
    fn resize(&mut self, nb_workers: u32) -> Result<()> {
        let workers = nb_workers as usize;
        self.factory.resize(workers)?;
        // ZSTDMT_expandJobsTable: only ever larger.
        if workers + 2 > self.job_table_size {
            self.job_table_size = zstdmt_jobs_table_size(workers);
        }
        self.shared
            .buf_pool
            .expand(buf_pool_max_nb_buffers(workers));
        self.shared.in_pool.expand(workers + 2);
        self.shared
            .out_pool
            .expand(buf_pool_max_nb_buffers(workers));
        self.shared.cctx_pool.expand(workers);
        self.params.nb_workers = nb_workers;
        Ok(())
    }

    /// The input taken for the next job (`inBuff.filled`).
    fn filled(&self) -> usize {
        self.in_buff.len() - self.in_prefix_size
    }

    /// `ZSTDMT_waitForAllJobsCompleted`: waits for the jobs handed over to
    /// be done.
    fn wait_for_all_jobs_completed(&self) {
        for job in &self.jobs {
            let mut state = lock(&job.progress.state);
            while state.consumed < job.src_size {
                state = wait(&job.progress.cond, state);
            }
        }
    }

    /// `ZSTDMT_releaseAllJobResources`: forgets the jobs, all done, and the
    /// input taken.
    ///
    /// Differs from libzstd: libzstd keeps `jobReady` set, and would hand
    /// over the next frame's first job in the place of the one made; the
    /// port drops that job.
    fn release_all_job_resources(&mut self) {
        self.jobs.clear();
        self.job_ready = None;
        self.in_buff = Vec::new();
        self.in_prefix_size = 0;
    }

    /// `ZSTDMT_updateCParams_whileCompressing`: the compression level and
    /// parameters set while streaming, for the jobs made from now on; but
    /// the window, which the frame header gives.
    pub(crate) fn update_cparams_while_compressing(
        &mut self,
        compression_level: i32,
        mut c_params: CompressionParameters,
    ) {
        c_params.window_log = self.params.c_params.window_log;
        self.params.compression_level = compression_level;
        self.params.c_params = c_params;
    }

    /// `ZSTDMT_getFrameProgression`: the frame's input taken, compressed,
    /// and its output produced and written out, by the jobs done and
    /// written out, those not yet, and the input taken for the next; the
    /// jobs that are compressing, or waiting for a thread.
    pub(crate) fn frame_progression(&self) -> FrameProgression {
        let filled = self.filled() as u64;
        let mut fps = FrameProgression {
            ingested: self.consumed + filled,
            consumed: self.consumed,
            produced: self.produced,
            flushed: self.produced,
            current_job_id: self.next_job_id,
            nb_active_workers: 0,
        };
        let ready = self.job_ready.as_ref().map(|(slot, _)| slot);
        for job in self.jobs.iter().chain(ready) {
            let state = lock(&job.progress.state);
            let (produced, flushed) = match state.c_size {
                Ok(c_size) => (c_size, job.dst_flushed),
                Err(_) => (0, 0),
            };
            debug_assert!(flushed <= produced);
            fps.ingested += job.src_size as u64;
            fps.consumed += state.consumed as u64;
            fps.produced += produced as u64;
            fps.flushed += flushed as u64;
            fps.nb_active_workers += u32::from(state.consumed < job.src_size);
        }
        fps
    }

    /// `ZSTDMT_toFlushNow`: what the oldest job handed over has produced
    /// and not written out yet; 0 without one.
    pub(crate) fn to_flush_now(&self) -> usize {
        let Some(job) = self.jobs.front() else {
            return 0;
        };
        let state = lock(&job.progress.state);
        match state.c_size {
            Ok(c_size) => c_size - job.dst_flushed,
            Err(_) => 0,
        }
    }

    /// `ZSTDMT_nextInputSizeHint`: the input that completes the next job.
    pub(crate) fn next_input_size_hint(&self) -> usize {
        match self.target_section_size - self.filled() {
            0 => self.target_section_size,
            hint => hint,
        }
    }

    /// `ZSTDMT_initCStream_internal`: starts a frame of `pledged_src_size`
    /// bytes (or unknown) with `params`, once the jobs of the frame before
    /// are done; with `prefix`, for the first job: raw content as its
    /// prefix, other content made a `CDict`; or with `cdict`. Not both.
    pub(crate) fn init_cstream_internal(
        &mut self,
        prefix: Option<(Box<[u8]>, DictContentType)>,
        cdict: Option<Arc<CDict>>,
        params: &CCtxParams,
        pledged_src_size: u64,
    ) -> Result<()> {
        let mut params = *params;
        debug_assert!(prefix.is_none() || cdict.is_none());
        if params.nb_workers != self.params.nb_workers {
            self.resize(params.nb_workers)?;
        }
        if params.job_size != 0 && params.job_size < ZSTDMT_JOBSIZE_MIN {
            params.job_size = ZSTDMT_JOBSIZE_MIN;
        }
        params.job_size = params.job_size.min(ZSTDMT_JOBSIZE_MAX);

        // The frame before, not finished: its jobs done first.
        self.wait_for_all_jobs_completed();
        self.release_all_job_resources();

        self.params = params;
        self.frame_content_size = pledged_src_size;

        self.target_prefix_size = zstdmt_compute_overlap_size(&params);
        self.target_section_size = params.job_size;
        if self.target_section_size == 0 {
            self.target_section_size = 1 << zstdmt_compute_target_job_log(&params);
        }
        debug_assert!(self.target_section_size <= ZSTDMT_JOBSIZE_MAX);

        if params.rsyncable {
            // The job size, on average.
            let job_size_kb = (self.target_section_size >> 10) as u32;
            debug_assert!(job_size_kb >= 1);
            let rsync_bits = highbit32(job_size_kb) + 10;
            // No job ends at a synchronization point before
            // RSYNC_MIN_BLOCK_SIZE: the average must be at least 4 times
            // that.
            debug_assert!(rsync_bits >= RSYNC_MIN_BLOCK_LOG + 2);
            self.rsync = RsyncState {
                hash: 0,
                hit_mask: (1u64 << rsync_bits) - 1,
                prime_power: zstd_rolling_hash_prime_power(RSYNC_LENGTH as u32),
            };
        }
        // A job is no smaller than the overlap.
        self.target_section_size = self.target_section_size.max(self.target_prefix_size);
        // ZSTDMT_setBufferSize
        self.dst_capacity = zstd_compress_bound(self.target_section_size)?;

        self.in_buff = Vec::new();
        self.in_prefix_size = 0;
        self.next_job_id = 0;
        self.frame_ended = false;
        self.consumed = 0;
        self.produced = 0;

        // The dictionary: a prefix of raw content for the first job, other
        // content made a CDict (referencing it in libzstd, copied here).
        self.cdict = None;
        self.dict_prefix = None;
        match prefix {
            Some((prefix, DictContentType::RawContent)) => {
                self.dict_prefix = Some(Arc::from(prefix));
            }
            Some((prefix, content_type)) => {
                let Ok(cdict) = CDict::create_advanced(&prefix, content_type, &params.c_params)
                else {
                    return error!(MemoryAllocation);
                };
                self.cdict = Some(Arc::new(cdict));
            }
            None => self.cdict = cdict,
        }

        self.shared
            .serial
            .reset(params, self.target_section_size, self.dict_prefix.as_ref())
    }

    /// `ZSTDMT_createCompressionJob`: a job of the `src_size` bytes taken,
    /// the last one with [`EndDirective::End`], handed over to a thread if
    /// one is free (otherwise kept ready, and handed over at a later
    /// call). None while the job table is full.
    fn create_compression_job(&mut self, src_size: usize, end_op: EndDirective) -> Result<()> {
        let end_frame = end_op == EndDirective::End;
        if self.jobs.len() >= self.job_table_size {
            // The table is full: no new job yet.
            debug_assert!(self.jobs.len() == self.job_table_size);
            return Ok(());
        }

        let (slot, job) = match self.job_ready.take() {
            Some(ready) => ready,
            None => {
                let job_id = self.next_job_id;
                debug_assert!(self.filled() >= src_size);
                let params = self.params;
                let prefix_size = self.in_prefix_size;
                // The copy of its output (none for the empty last block),
                // before anything changes.
                let dst = if src_size == 0 && job_id > 0 {
                    Vec::new()
                } else {
                    self.shared.out_pool.get_empty(self.dst_capacity)?
                };
                let next_buff = if !end_frame {
                    // The next job's prefix: the end of this one's input.
                    let new_prefix_size = src_size.min(self.target_prefix_size);
                    let end = prefix_size + src_size;
                    self.in_buff[end - new_prefix_size..end].to_vec()
                } else {
                    // No input buffer after the last job.
                    self.frame_ended = true;
                    if job_id == 0 {
                        // A single job computes the checksum itself.
                        self.params.f_params.checksum_flag = false;
                    }
                    Vec::new()
                };
                self.in_prefix_size = next_buff.len();
                let data = std::mem::replace(&mut self.in_buff, next_buff);
                let progress = Arc::new(JobProgress::new(dst));
                let slot = JobSlot {
                    src_size,
                    frame_checksum_needed: params.f_params.checksum_flag && end_frame && job_id > 0,
                    dst_flushed: 0,
                    progress: progress.clone(),
                };

                if src_size == 0 && job_id > 0 {
                    // ZSTDMT_writeLastEmptyBlock: the last job, empty, is an
                    // empty last block, never handed over. A single job
                    // must write the frame header too.
                    debug_assert!(end_frame);
                    {
                        let mut state = lock(&progress.state);
                        let c_block_header24 = 1 /* last block */ + ((BlockType::Raw as u32) << 1);
                        state
                            .dst
                            .extend_from_slice(&c_block_header24.to_le_bytes()[..3]);
                        state.c_size = Ok(3);
                    }
                    self.jobs.push_back(slot);
                    self.next_job_id += 1;
                    return Ok(());
                }

                let job = JobDescription {
                    job_id,
                    first_job: job_id == 0,
                    last_job: end_frame,
                    params,
                    cdict: if job_id == 0 {
                        self.cdict.clone()
                    } else {
                        None
                    },
                    dict_prefix: if job_id == 0 {
                        self.dict_prefix.clone()
                    } else {
                        None
                    },
                    full_frame_size: self.frame_content_size,
                    data,
                    prefix_size,
                    dst_capacity: self.dst_capacity,
                    progress,
                    shared: self.shared.clone(),
                    #[cfg(test)]
                    overflow_correct_frequently: OVERFLOW_CORRECT_FREQUENTLY
                        .with(std::cell::Cell::get),
                };
                (slot, job)
            }
        };

        match self.factory.try_add(job) {
            Ok(()) => {
                self.jobs.push_back(slot);
                self.next_job_id += 1;
            }
            Err(job) => {
                // No thread free for it.
                self.job_ready = Some((slot, job));
            }
        }
        Ok(())
    }

    /// `ZSTDMT_flushProduced`: writes out what the oldest job has produced
    /// and not written out yet, and moves on to the next job once it is
    /// done and all written out; with `block_to_flush`, first waits for
    /// it to produce something, if it has not. Returns how much is left
    /// to write out, 1 when not known (a job is not done, or input is
    /// waiting); with [`EndDirective::End`], whether the frame is not
    /// complete. A job failed fails it, after the jobs handed over are done.
    fn flush_produced(
        &mut self,
        output: &mut OutBuffer<'_>,
        block_to_flush: bool,
        end: EndDirective,
    ) -> Result<usize> {
        if let Some(job) = self.jobs.front_mut() {
            let mut state = lock(&job.progress.state);
            if block_to_flush {
                // Nothing to write out, but more to come: wait for it.
                while state.c_size == Ok(job.dst_flushed) {
                    if state.consumed == job.src_size {
                        // Done: nothing more will come.
                        break;
                    }
                    state = wait(&job.progress.cond, state);
                }
            }

            // Write out what there is.
            let mut c_size = match state.c_size {
                Ok(c_size) => c_size,
                Err(error) => {
                    // The job failed: wait for the others, forget them all.
                    drop(state);
                    self.wait_for_all_jobs_completed();
                    self.release_all_job_resources();
                    return Err(error);
                }
            };
            let src_consumed = state.consumed;
            let src_size = job.src_size;
            debug_assert!(src_consumed <= src_size);
            // The frame's checksum, after the last job, once done (only
            // once).
            if src_consumed == src_size && job.frame_checksum_needed {
                let checksum = self.shared.serial.digest() as u32;
                state.dst.extend_from_slice(&checksum.to_le_bytes());
                c_size += 4;
                state.c_size = Ok(c_size);
                job.frame_checksum_needed = false;
            }

            let mut dst_flushed = job.dst_flushed;
            if c_size > 0 {
                // Compression is going on, or done.
                let to_flush = (c_size - dst_flushed).min(output.dst.len() - output.pos);
                output.dst[output.pos..output.pos + to_flush]
                    .copy_from_slice(&state.dst[dst_flushed..dst_flushed + to_flush]);
                output.pos += to_flush;
                dst_flushed += to_flush;
                job.dst_flushed = dst_flushed;
                if src_consumed == src_size && dst_flushed == c_size {
                    // Done and all written out: on to the next job, the
                    // copy of the output kept for a later one.
                    let dst = std::mem::take(&mut state.dst);
                    drop(state);
                    self.jobs.pop_front();
                    self.consumed += src_size as u64;
                    self.produced += c_size as u64;
                    self.shared.out_pool.release_buffer(dst);
                }
            }

            // What is left to write out; 1 when not known but more.
            if c_size > dst_flushed {
                return Ok(c_size - dst_flushed);
            }
            if src_size > src_consumed {
                // The job is not done.
                return Ok(1);
            }
        }
        if !self.jobs.is_empty() {
            // More jobs going on.
            return Ok(1);
        }
        if self.job_ready.is_some() {
            // A job made, waiting for a thread.
            return Ok(1);
        }
        if self.filled() > 0 {
            // Input waiting to make a job of.
            return Ok(1);
        }
        // All the jobs done and written out. For ZSTD_e_end: whether the
        // frame is complete, rather than all written out.
        if end == EndDirective::End {
            return Ok(usize::from(!self.frame_ended));
        }
        Ok(0)
    }

    /// `findSynchronizationPoint`: how much of `input` to take into the
    /// next job, and, with `ZSTD_c_rsyncable`, whether the job then ends
    /// at a synchronization point: where the rolling hash of the last
    /// `RSYNC_LENGTH` bytes has the bits of `hit_mask` set, once the job
    /// has `RSYNC_MIN_BLOCK_SIZE` bytes. Without one, as much as there is
    /// room for.
    fn find_synchronization_point(&self, input: &InBuffer<'_>) -> SyncPoint {
        let istart = &input.src[input.pos..];
        let prime_power = self.rsync.prime_power;
        let hit_mask = self.rsync.hit_mask;
        let filled = self.filled();
        let buffered = &self.in_buff[self.in_prefix_size..];

        let mut sync_point = SyncPoint {
            to_load: istart.len().min(self.target_section_size - filled),
            flush: false,
        };
        if !self.params.rsyncable {
            return sync_point;
        }
        if filled + istart.len() < RSYNC_MIN_BLOCK_SIZE {
            // Too small a job to end at a synchronization point: no need
            // to look.
            return sync_point;
        }
        if filled + sync_point.to_load < RSYNC_LENGTH {
            // Not enough to compute the hash: a point here is missed, but
            // only with a job size under the length, which none is.
            return sync_point;
        }
        // The byte RSYNC_LENGTH before position `pos` of the input: in the
        // input, or at the end of the input taken (libzstd's `prev`).
        let byte_before = |pos: usize| -> u8 {
            if pos < RSYNC_LENGTH {
                buffered[filled - RSYNC_LENGTH + pos]
            } else {
                istart[pos - RSYNC_LENGTH]
            }
        };
        let mut pos;
        let mut hash;
        if filled < RSYNC_MIN_BLOCK_SIZE {
            // No synchronization point in the first RSYNC_MIN_BLOCK_SIZE
            // bytes: start from there.
            pos = RSYNC_MIN_BLOCK_SIZE - filled;
            if pos >= RSYNC_LENGTH {
                hash = zstd_rolling_hash_compute(&istart[pos - RSYNC_LENGTH..pos]);
            } else {
                debug_assert!(filled >= RSYNC_LENGTH);
                hash = zstd_rolling_hash_compute(&buffered[filled - RSYNC_LENGTH + pos..filled]);
                hash = zstd_rolling_hash_append(hash, &istart[..pos]);
            }
        } else {
            // The hash of the end of the input taken, and the points from
            // the start of the input.
            debug_assert!(filled >= RSYNC_MIN_BLOCK_SIZE);
            pos = 0;
            hash = zstd_rolling_hash_compute(&buffered[filled - RSYNC_LENGTH..filled]);
            if hash & hit_mask == hit_mask {
                // At a synchronization point already: take no more input
                // until the job is made (the job table was full).
                sync_point.to_load = 0;
                sync_point.flush = true;
                return sync_point;
            }
        }
        // Roll the hash through the input; the job ends at the first
        // synchronization point, or when full (a synchronized stream stays
        // so).
        while pos < sync_point.to_load {
            hash = zstd_rolling_hash_rotate(hash, byte_before(pos), istart[pos], prime_power);
            debug_assert!(filled + pos >= RSYNC_MIN_BLOCK_SIZE);
            if hash & hit_mask == hit_mask {
                sync_point.to_load = pos + 1;
                sync_point.flush = true;
                break;
            }
            pos += 1;
        }
        sync_point
    }

    /// `ZSTDMT_compressStream_generic`: takes input into the next job,
    /// makes a job when it is full or when `end_op` asks, and writes out
    /// what the jobs have produced, waiting for the oldest when no input
    /// could be taken. Returns how much is left to write out, at least.
    pub(crate) fn compress_stream_generic(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        mut end_op: EndDirective,
    ) -> Result<usize> {
        let mut forward_input_progress = false;
        debug_assert!(output.pos <= output.dst.len());
        debug_assert!(input.pos <= input.src.len());

        if self.frame_ended && end_op == EndDirective::Continue {
            // The frame is being ended: only flushes and its end.
            return error!(StageWrong);
        }

        // Fill the input buffer.
        if self.job_ready.is_none() && input.src.len() > input.pos {
            // ZSTDMT_tryGetInputRange: libzstd waits for room in its round
            // buffer; the port's input buffer is the job's, always there.
            let sync_point = self.find_synchronization_point(input);
            if sync_point.flush && end_op == EndDirective::Continue {
                end_op = EndDirective::Flush;
            }
            let needed = self.in_prefix_size + self.target_section_size;
            if self.in_buff.capacity() < needed {
                // A buffer for the job, its prefix first.
                let mut buffer = self.shared.in_pool.get_empty(needed)?;
                buffer.extend_from_slice(&self.in_buff);
                self.in_buff = buffer;
            }
            self.in_buff
                .extend_from_slice(&input.src[input.pos..input.pos + sync_point.to_load]);
            input.pos += sync_point.to_load;
            forward_input_progress = sync_point.to_load > 0;
        }
        if input.pos < input.src.len() && end_op == EndDirective::End {
            // Not all the input taken: the job is full, or ends at a
            // synchronization point. Not the end of the frame yet.
            debug_assert!(
                self.filled() == 0
                    || self.filled() == self.target_section_size
                    || self.params.rsyncable
            );
            end_op = EndDirective::Flush;
        }

        if self.job_ready.is_some()
            || self.filled() >= self.target_section_size
            || (end_op != EndDirective::Continue && self.filled() > 0)
            || (end_op == EndDirective::End && !self.frame_ended)
        {
            // Full, or something to flush, or the frame to end with an
            // empty last block.
            let job_size = self.filled();
            debug_assert!(job_size <= self.target_section_size);
            self.create_compression_job(job_size, end_op)?;
        }

        // Write out what is ready; wait for it when no input was taken.
        let remaining_to_flush = self.flush_produced(output, !forward_input_progress, end_op)?;
        if input.pos < input.src.len() {
            // Input not all taken: not done yet.
            return Ok(remaining_to_flush.max(1));
        }
        Ok(remaining_to_flush)
    }
}
