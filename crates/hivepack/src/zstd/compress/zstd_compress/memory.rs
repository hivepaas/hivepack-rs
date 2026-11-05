//! Not part of the port: how much memory a context takes, and a limit on
//! what its workers take. libzstd estimates a context without workers
//! (`ZSTD_estimateCStreamSize`) and refuses to estimate one with them; this
//! counts what the port allocates, with workers or without, from its code,
//! as an upper bound, and lowers the workers of a frame until it fits a
//! limit. The frames are the same with one worker or many, so the limit
//! changes how fast a frame is made, never what it is. `docs/memory.md`
//! has the formula, and `tests/memory_limits.rs` checks it against what is
//! allocated.

use super::{
    CCtx, CCtxParams, ZSTD_HASHLOG3_MAX, sequence_bound, zstd_allocate_chain_table,
    zstd_compress_bound, zstd_max_nb_seq, zstd_row_match_finder_used,
};
use crate::zstd::common::error_private::Result;
use crate::zstd::compress::zstd_compress::{BufferMode, Sequence};
use crate::zstd::compress::zstd_compress_internal::{
    CompressionParameters, EntropyCTables, LdmEntry, OptMatch, OptState, Optimal, ParamSwitch,
    RawSeq, SeqDef, Strategy, WILDCOPY_OVERLENGTH, ZSTD_OPT_SIZE,
};
use crate::zstd::compress::zstd_ldm::{zstd_ldm_adjust_parameters, zstd_ldm_get_max_nb_seq};
use crate::zstd::compress::zstdmt_compress::{
    ZSTDMT_JOBSIZE_MAX, ZSTDMT_JOBSIZE_MIN, zstdmt_compute_overlap_size,
    zstdmt_compute_target_job_log, zstdmt_jobs_table_size,
};

/// What a context takes besides its tables and buffers: its block states,
/// the entropy tables and workspaces it makes as it compresses a block, and
/// the context itself.
const CONTEXT_MEMORY: u64 = 1 << 20;

/// What the workers' context takes besides its jobs: its job table, its
/// pools, the serial state.
const WORKERS_MEMORY: u64 = 1 << 20;

/// `n` items of `T`, in bytes.
fn bytes<T>(n: u64) -> u64 {
    n.saturating_mul(size_of::<T>() as u64)
}

/// The match state's tables for `c_params`, as `zstd_reset_match_state`
/// makes them for a context, and the optimal parser's state.
fn match_state(c_params: &CompressionParameters, row: ParamSwitch) -> u64 {
    let h_size = 1u64 << c_params.hash_log;
    let chain_size = if zstd_allocate_chain_table(c_params.strategy, row, false) {
        1u64 << c_params.chain_log
    } else {
        0
    };
    let h3_size = if c_params.min_match == 3 {
        1u64 << ZSTD_HASHLOG3_MAX.min(c_params.window_log)
    } else {
        0
    };
    let tags = if zstd_row_match_finder_used(c_params.strategy, row) {
        h_size
    } else {
        0
    };
    let opt = if c_params.strategy >= Strategy::Btopt {
        let tables =
            bytes::<OptMatch>(ZSTD_OPT_SIZE as u64) + bytes::<Optimal>(ZSTD_OPT_SIZE as u64);
        size_of::<OptState>() as u64 + tables
    } else {
        0
    };
    bytes::<u32>(h_size + chain_size + h3_size) + tags + opt
}

/// A context for blocks of up to `block_size` bytes, without its streaming
/// buffers and long distance matching: the match state, the sequences
/// and literals of a block, and the rest.
fn context(params: &CCtxParams, block_size: usize) -> u64 {
    let max_nb_seq = zstd_max_nb_seq(block_size, params.c_params.min_match, params.ext_seq_prod);
    let seq_store = (block_size + WILDCOPY_OVERLENGTH) as u64
        + bytes::<SeqDef>(max_nb_seq as u64)
        + 3 * max_nb_seq as u64;
    let producer = if params.ext_seq_prod {
        bytes::<Sequence>(sequence_bound(block_size) as u64)
    } else {
        0
    };
    match_state(&params.c_params, params.use_row_match_finder)
        + seq_store
        + producer
        + 2 * size_of::<EntropyCTables>() as u64
        + CONTEXT_MEMORY
}

/// Long distance matching's hash table and buckets, for `params`, adjusted.
fn ldm_tables(params: &CCtxParams) -> u64 {
    let mut ldm = params.ldm;
    zstd_ldm_adjust_parameters(&mut ldm, &params.c_params);
    let hash = 1u64 << ldm.hash_log;
    let buckets = 1u64 << (ldm.hash_log - ldm.bucket_size_log);
    bytes::<LdmEntry>(hash) + buckets
}

/// The most sequences long distance matching finds in `size` bytes.
fn ldm_sequences(params: &CCtxParams, size: usize) -> u64 {
    let mut ldm = params.ldm;
    zstd_ldm_adjust_parameters(&mut ldm, &params.c_params);
    bytes::<RawSeq>(zstd_ldm_get_max_nb_seq(ParamSwitch::Enable, &ldm, size) as u64)
}

/// A frame of `pledged_src_size` bytes with `params`, resolved, without
/// workers: the context, its streaming buffers, long distance matching.
fn without_workers(params: &CCtxParams, pledged_src_size: u64) -> Result<u64> {
    let window_size = (1u64 << params.c_params.window_log)
        .min(pledged_src_size)
        .max(1) as usize;
    let block_size = params.max_block_size.min(window_size);
    let mut total = context(params, block_size);
    if params.in_buffer_mode == BufferMode::Buffered {
        total += (window_size + block_size) as u64;
    }
    if params.out_buffer_mode == BufferMode::Buffered {
        total += zstd_compress_bound(block_size)? as u64 + 1;
    }
    if params.ldm_enable == ParamSwitch::Enable {
        total += ldm_tables(params) + ldm_sequences(params, block_size);
    }
    Ok(total)
}

/// A frame with `params`, resolved, with `nb_workers` workers (at least
/// one): as `zstdmt_compress.rs` holds it at most.
///
/// - Each worker has a context of its own, for blocks of the frame, and a
///   buffer for its job's output, `ZSTD_compressBound` of a job.
/// - A job's input, after its overlap with the job before, is in a buffer
///   of its own until the job is done: one for each worker, one made and
///   waiting for a worker, one being filled, and the next one's overlap.
/// - What a job writes is copied out for the caller, into a buffer of
///   `ZSTD_compressBound` of a job, until all is written out: one for each
///   place in the job table (`jobIDMask + 1`, a power of 2 over the
///   workers and 2), where the jobs not all written out are, and a job made
///   and waiting for a worker is only made when the table has room for it.
///   A caller that writes out little at a time can fill it.
/// - Long distance matching keeps its tables and the input its window
///   reaches, which the buffer it is in may hold twice, with room to grow
///   twice that; each job, the sequences it finds.
fn with_workers(params: &CCtxParams, nb_workers: u32) -> Result<u64> {
    let workers = u64::from(nb_workers.max(1));
    let mut job_size = params.job_size;
    if job_size != 0 && job_size < ZSTDMT_JOBSIZE_MIN {
        job_size = ZSTDMT_JOBSIZE_MIN;
    }
    job_size = job_size.min(ZSTDMT_JOBSIZE_MAX);
    let overlap = zstdmt_compute_overlap_size(params);
    let section = match job_size {
        0 => 1 << zstdmt_compute_target_job_log(params),
        size => size,
    }
    .max(overlap);
    let dst = zstd_compress_bound(section)? as u64;
    let window = 1u64 << params.c_params.window_log;
    let block_size = params.max_block_size.min(window as usize);
    let ldm = params.ldm_enable == ParamSwitch::Enable;
    let job_sequences = if ldm {
        ldm_sequences(params, section)
    } else {
        0
    };
    let per_worker = context(params, block_size) + dst + job_sequences;
    let (section, overlap) = (section as u64, overlap as u64);
    let inputs = (workers + 2) * (overlap + section) + overlap;
    let table = zstdmt_jobs_table_size(nb_workers.max(1) as usize) as u64;
    let copies = table * dst;
    let serial = if ldm {
        ldm_tables(params) + 4 * (window + section) + job_sequences
    } else {
        0
    };
    Ok(workers
        .saturating_mul(per_worker)
        .saturating_add(inputs + copies + serial + WORKERS_MEMORY + CONTEXT_MEMORY))
}

/// The memory of a frame with `params`, resolved, with `nb_workers`
/// workers, or none.
fn frame_memory(params: &CCtxParams, pledged_src_size: u64, nb_workers: u32) -> Result<u64> {
    if nb_workers == 0 || pledged_src_size <= ZSTDMT_JOBSIZE_MIN as u64 {
        return without_workers(params, pledged_src_size);
    }
    with_workers(params, nb_workers)
}

/// The most workers, from `params`'s down to one, whose frame fits
/// `limit`; one if none does.
fn workers_within(params: &CCtxParams, limit: u64) -> Result<u32> {
    let mut nb_workers = params.nb_workers.max(1);
    while nb_workers > 1 && with_workers(params, nb_workers)? > limit {
        nb_workers -= 1;
    }
    Ok(nb_workers)
}

impl CCtx {
    /// The parameters the next frame starts with, with the dictionary set,
    /// and its size, pledged or not known.
    fn next_frame_params(&self) -> (CCtxParams, u64) {
        let pledged_src_size = self.pledged_src_size_plus_one.wrapping_sub(1);
        let cdict = self
            .cdict
            .as_deref()
            .or_else(|| self.local_dict.as_ref().and_then(|d| d.cdict.as_deref()));
        let dict_size = match (&self.prefix_dict, cdict, &self.local_dict) {
            (Some((prefix, _)), ..) => prefix.len(),
            (None, Some(cdict), _) => cdict.dict_size(),
            (None, None, Some(local)) => local.dict.len(),
            (None, None, None) => 0,
        };
        let params =
            self.resolve_frame_params(self.requested_params, cdict, dict_size, pledged_src_size);
        (params, pledged_src_size)
    }

    /// Not libzstd's: the most bytes the next frame takes to compress with
    /// the parameters set, and its size if pledged
    /// ([`CCtx::set_pledged_src_size`]), with `nb_workers` workers, or
    /// none for 0: an upper bound, of what is allocated, whatever the
    /// data. A frame of a known size of 512 KB or less takes no workers,
    /// and so the memory of none. Dictionaries are beside it.
    ///
    /// Without workers it is the context's tables, the sequences of a
    /// block, and the buffers of streaming: as libzstd's
    /// `ZSTD_estimateCStreamSize` counts them. With them, for each worker
    /// a context and the output of a job, and for each job held the input
    /// of a job and a copy of its output; `docs/memory.md` has the formula.
    /// Level 3, of jobs of 8 MiB: 4.5 MiB without workers, 69 MiB with
    /// one, 157 MiB with 4, 572 MiB with 16; level 19, of jobs of 32 MiB:
    /// 90 MiB, 373 MiB, 964 MiB and 3.5 GiB. Each worker more costs more
    /// where the job table, which a copy of each job's output waits in,
    /// grows to the next power of 2.
    ///
    /// The context's own tables, from frames without workers before, are
    /// beside it too: they are kept, as libzstd keeps them.
    pub fn estimate_memory(&self, nb_workers: u32) -> Result<u64> {
        let (mut params, pledged_src_size) = self.next_frame_params();
        params.nb_workers = nb_workers;
        frame_memory(&params, pledged_src_size, nb_workers)
    }

    /// Not libzstd's: the most bytes the frames from the next on may take
    /// with workers ([`CParameter::NbWorkers`](crate::zstd::CParameter::NbWorkers)):
    /// each frame takes as many as are set, fewer while
    /// [`CCtx::estimate_memory`] is over `limit`, and one at least, even
    /// where one takes more, as liblzma allows one thread under its limit.
    /// The frames are the same with one worker or many, so the limit
    /// changes how fast they are made, never what they are; frames without
    /// workers are not changed by it. `u64::MAX`, the default, is no
    /// limit. It stays until set again, through [`CCtx::reset`].
    ///
    /// Under a limit, the workers' threads, contexts and buffers are made
    /// again for a frame that would take other than the frame before took,
    /// so that none are kept from a larger frame. With a pool shared with
    /// other contexts ([`CCtx::ref_thread_pool`]), the pool referred to
    /// then is taken.
    pub fn set_workers_memory_limit(&mut self, limit: u64) {
        self.workers_memory_limit = limit;
    }

    /// Not libzstd's: the workers the next frame takes: as many as are
    /// set, fewer while [`CCtx::estimate_memory`] is over the limit
    /// ([`CCtx::set_workers_memory_limit`]), one at least; 0 without
    /// workers, or for a frame of a known size of 512 KB or less.
    pub fn nb_workers_within_limit(&self) -> Result<u32> {
        let (params, pledged_src_size) = self.next_frame_params();
        if params.nb_workers == 0 || pledged_src_size <= ZSTDMT_JOBSIZE_MIN as u64 {
            return Ok(0);
        }
        workers_within(&params, self.workers_memory_limit)
    }

    /// At the start of a frame with `params`, resolved: its workers
    /// lowered to the limit, and the workers' context dropped if it was
    /// set up for other frames, to be made again.
    pub(super) fn fit_workers_to_limit(&mut self, params: &mut CCtxParams) -> Result<()> {
        if params.nb_workers == 0 {
            return Ok(());
        }
        if self.workers_memory_limit == u64::MAX {
            self.mt_set_up_for = None;
            return Ok(());
        }
        params.nb_workers = workers_within(params, self.workers_memory_limit)?;
        let set_up_for = (params.nb_workers, with_workers(params, params.nb_workers)?);
        if self.mt_set_up_for != Some(set_up_for) {
            self.mtctx = None;
            self.mt_set_up_for = Some(set_up_for);
        }
        Ok(())
    }
}
