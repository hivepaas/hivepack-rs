//! Port of `dictBuilder/fastcover.c`: the COVER trainer with the dmers'
//! hashes in place of the dmers. Their frequencies are counted in a table
//! of `2^f` cells, without a suffix array, and dmers whose hashes collide
//! count as one: quicker, with less memory, and nearly as good. Only `d` =
//! 6 and 8 are offered. With `accel` over 1, only every so many dmers are
//! counted, and fewer samples make the dictionaries' tables.
//!
//! The optimizer, its trials and the selection of their dictionaries are
//! the COVER trainer's (`cover.rs`). The default trainer
//! ([`train_from_buffer`](crate::zstd::train_from_buffer)) is this optimizer.

use crate::zstd::common::error_private::{Result, error};
use crate::zstd::common::mem::read_le64;
use crate::zstd::compress::zstd_compress_internal::zstd_hash_u64;
use crate::zstd::dict_builder::cover::{
    COVER_MAX_SAMPLES_SIZE, CoverBest, CoverParams, CoverSegment, DictSelection,
    cover_compute_epochs, cover_run_trials, cover_select_dict, k_values, sample_offsets,
    split_samples,
};
use crate::zstd::dict_builder::zdict::{
    Content, DictParams, ZDICT_DICTSIZE_MIN, zdict_finalize_dictionary,
};
use crate::zstd::dict_builder::{check_samples, zeroed};

/// `FASTCOVER_MAX_SAMPLES_SIZE`: as `COVER_MAX_SAMPLES_SIZE`.
const FASTCOVER_MAX_SAMPLES_SIZE: usize = COVER_MAX_SAMPLES_SIZE;
/// `FASTCOVER_MAX_F`
const FASTCOVER_MAX_F: u32 = 31;
/// `FASTCOVER_MAX_ACCEL`
const FASTCOVER_MAX_ACCEL: u32 = 10;
/// `FASTCOVER_DEFAULT_SPLITPOINT`: three quarters of the samples train,
/// the last quarter tests.
const FASTCOVER_DEFAULT_SPLITPOINT: f64 = 0.75;
/// `DEFAULT_F`
const DEFAULT_F: u32 = 20;
/// `DEFAULT_ACCEL`
const DEFAULT_ACCEL: u32 = 1;

/// `ZDICT_fastCover_params_t`: the parameters of the fast COVER trainers.
///
/// [`train_from_buffer_fast_cover`] needs `k` and `d`; the others are
/// optional, and those of the optimizer
/// ([`optimize_train_from_buffer_fast_cover`]) too, where 0 (0.0) means
/// the default for each. `Default` is all zeros.
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub struct FastCoverParams {
    /// The size of the segments, from `d` to the dictionary's size; 16 to
    /// 2048 and more is reasonable. The optimizer tries `steps` values from
    /// 50 to 2000 when it is 0.
    pub k: u32,
    /// The size of the dmers: 6 or 8. The optimizer tries both when it is
    /// 0.
    pub d: u32,
    /// The log of the size of the table of frequencies, 1 to 31; 20 for 0.
    /// The trainers need 6 times `2^f` bytes, for each thread.
    pub f: u32,
    /// The optimizer's number of values of `k` to try: 40 for 0.
    pub steps: u32,
    /// The optimizer's threads, for its trials: 0 and 1 for none.
    pub nb_threads: u32,
    /// The optimizer's share of samples to train on, in (0, 1]: the first
    /// ones train, the others test the dictionaries; all of them do both at
    /// 1.0. 0.0 for 0.75.
    pub split_point: f64,
    /// How fast, and less accurate, from 1 to 10: 1 for 0. Above 1, the
    /// trainers count only one dmer in `accel`, and make the dictionaries'
    /// tables from fewer training samples (`100 / accel` percent, about).
    pub accel: u32,
    /// Whether to shrink the dictionary to the smallest one within
    /// `shrink_dict_max_regression` percent of the largest's compressed
    /// size. Taken and ignored, as libzstd 1.5.7's optimizer ignores it
    /// (it sets it to 0 for every trial); the trainers never shrink.
    pub shrink_dict: bool,
    /// How much worse, in percent, a smaller dictionary may compress, when
    /// shrinking.
    pub shrink_dict_max_regression: u32,
    /// The parameters of the dictionary's header.
    pub z_params: DictParams,
}

/// `FASTCOVER_accel_t`
#[derive(Clone, Copy, Debug)]
struct AccelParams {
    /// The percentage of training samples the dictionaries' tables are
    /// made from (`ZDICT_finalizeDictionary`).
    finalize: u32,
    /// The dmers skipped between two counted (`FASTCOVER_computeFrequency`).
    skip: u32,
}

/// `FASTCOVER_defaultAccelParameters`, by `accel`.
const FASTCOVER_DEFAULT_ACCEL_PARAMETERS: [AccelParams; FASTCOVER_MAX_ACCEL as usize + 1] = [
    // accel = 0, which does not happen: 0 is taken as 1.
    AccelParams {
        finalize: 100,
        skip: 0,
    },
    AccelParams {
        finalize: 100,
        skip: 0,
    },
    AccelParams {
        finalize: 50,
        skip: 1,
    },
    AccelParams {
        finalize: 34,
        skip: 2,
    },
    AccelParams {
        finalize: 25,
        skip: 3,
    },
    AccelParams {
        finalize: 20,
        skip: 4,
    },
    AccelParams {
        finalize: 17,
        skip: 5,
    },
    AccelParams {
        finalize: 14,
        skip: 6,
    },
    AccelParams {
        finalize: 13,
        skip: 7,
    },
    AccelParams {
        finalize: 11,
        skip: 8,
    },
    AccelParams {
        finalize: 10,
        skip: 9,
    },
];

/// `FASTCOVER_ctx_t`: the samples, with the frequency of each dmer hash,
/// which only depends on `d`: one context serves every `k`.
struct FastCoverCtx<'a> {
    samples: &'a [u8],
    /// Where each sample starts, and the end of the last one.
    offsets: Vec<usize>,
    samples_sizes: &'a [usize],
    nb_samples: usize,
    nb_train_samples: usize,
    nb_test_samples: usize,
    /// The positions of the training samples that start a dmer, all but
    /// the last `max(d, 8) - 1`.
    nb_dmers: usize,
    /// How often each hash is in the training samples, by hash.
    freqs: Vec<u32>,
    d: u32,
    f: u32,
    accel_params: AccelParams,
}

/// `FASTCOVER_hashPtrToIndex`: the hash of the `d` bytes at `at` (8
/// read), `f` bits long, as an index into the table of frequencies.
#[inline(always)]
fn fastcover_hash_ptr_to_index(samples: &[u8], at: usize, f: u32, d: u32) -> usize {
    let u = read_le64(samples, at);
    if d == 6 {
        zstd_hash_u64(u, f, 6)
    } else {
        zstd_hash_u64(u, f, 8)
    }
}

/// `FASTCOVER_selectSegment`: the best segment of the epoch `begin..end`,
/// as `COVER_selectSegment`, with the frequencies of the dmers' hashes:
///
/// ```text
/// Score(S) = F(S_1) + F(S_2) + ... + F(S_{k-d+1})
/// ```
///
/// each hash once, then those frequencies zeroed. It is not trimmed.
/// `segment_freqs`, how often each hash is in the active segment, is all
/// zeros again on return.
fn fastcover_select_segment(
    ctx: &FastCoverCtx<'_>,
    freqs: &mut [u32],
    begin: u32,
    end: u32,
    parameters: &CoverParams,
    segment_freqs: &mut [u16],
) -> CoverSegment {
    let d = parameters.d;
    let f = ctx.f;
    let dmers_in_k = parameters.k - d + 1;

    // Try each segment (active) and keep the best.
    let mut best_segment = CoverSegment::default();
    // The active segment starts at the start of the epoch, with no dmers.
    let mut active_segment = CoverSegment {
        begin,
        end: begin,
        score: 0,
    };

    // Slide it through the whole epoch.
    while active_segment.end < end {
        let idx = fastcover_hash_ptr_to_index(ctx.samples, active_segment.end as usize, f, d);
        // A hash new to the segment adds its frequency.
        if segment_freqs[idx] == 0 {
            active_segment.score = active_segment.score.wrapping_add(freqs[idx]);
        }
        active_segment.end += 1;
        segment_freqs[idx] = segment_freqs[idx].wrapping_add(1);
        // Too large a window: drop its first position.
        if active_segment.end - active_segment.begin == dmers_in_k.wrapping_add(1) {
            let del_index =
                fastcover_hash_ptr_to_index(ctx.samples, active_segment.begin as usize, f, d);
            segment_freqs[del_index] = segment_freqs[del_index].wrapping_sub(1);
            // Its last occurrence: subtract its frequency.
            if segment_freqs[del_index] == 0 {
                active_segment.score = active_segment.score.wrapping_sub(freqs[del_index]);
            }
            active_segment.begin += 1;
        }

        if active_segment.score > best_segment.score {
            best_segment = active_segment;
        }
    }

    // segment_freqs back to zeros.
    while active_segment.begin < end {
        let del_index =
            fastcover_hash_ptr_to_index(ctx.samples, active_segment.begin as usize, f, d);
        segment_freqs[del_index] = segment_freqs[del_index].wrapping_sub(1);
        active_segment.begin += 1;
    }

    // The hashes of the segment's dmers are in the dictionary: no
    // frequency any more.
    for pos in best_segment.begin..best_segment.end {
        let i = fastcover_hash_ptr_to_index(ctx.samples, pos as usize, f, d);
        freqs[i] = 0;
    }

    best_segment
}

/// `FASTCOVER_checkParameters`: whether the parameters are valid for a
/// dictionary of `max_dict_size` bytes, with the table log `f` and `accel`
/// resolved: `d` 6 or 8, `d <= k <= max_dict_size`, `0 < f <= 31`,
/// `0 < split_point <= 1` and `0 < accel <= 10`.
fn fastcover_check_parameters(
    parameters: &CoverParams,
    max_dict_size: usize,
    f: u32,
    accel: u32,
) -> bool {
    // k and d are required.
    if parameters.d == 0 || parameters.k == 0 {
        return false;
    }
    if parameters.d != 6 && parameters.d != 8 {
        return false;
    }
    if parameters.k as usize > max_dict_size {
        return false;
    }
    if parameters.d > parameters.k {
        return false;
    }
    if f > FASTCOVER_MAX_F || f == 0 {
        return false;
    }
    // NaN passes, as in libzstd, and is then taken as 1.
    if parameters.split_point <= 0.0 || parameters.split_point > 1.0 {
        return false;
    }
    if accel > FASTCOVER_MAX_ACCEL || accel == 0 {
        return false;
    }
    true
}

/// `FASTCOVER_computeFrequency`: how often each hash is in the training
/// samples, every `skip + 1`-th dmer of each sample counted, none across
/// two samples.
fn fastcover_compute_frequency(freqs: &mut [u32], ctx: &FastCoverCtx<'_>) {
    let f = ctx.f;
    let d = ctx.d;
    let skip = ctx.accel_params.skip as usize;
    let read_length = (d as usize).max(8);
    debug_assert!(ctx.nb_train_samples >= 5);
    debug_assert!(ctx.nb_train_samples <= ctx.nb_samples);
    for i in 0..ctx.nb_train_samples {
        // The start of the current dmer.
        let mut start = ctx.offsets[i];
        let curr_sample_end = ctx.offsets[i + 1];
        while start + read_length <= curr_sample_end {
            let dmer_index = fastcover_hash_ptr_to_index(ctx.samples, start, f, d);
            freqs[dmer_index] = freqs[dmer_index].wrapping_add(1);
            start += skip + 1;
        }
    }
}

/// `FASTCOVER_ctx_init`: the context for dmers of `d` bytes and a table of
/// `2^f` frequencies: the samples split (see
/// [`split_samples`](crate::zstd::dict_builder::cover::split_samples), whose
/// note says how the port fails where libzstd reads past the samples), and
/// the hashes' frequencies counted.
fn fastcover_ctx_init<'a>(
    samples: &'a [u8],
    samples_sizes: &'a [usize],
    d: u32,
    split_point: f64,
    f: u32,
    accel_params: AccelParams,
) -> Result<FastCoverCtx<'a>> {
    let split = split_samples(samples_sizes, d, split_point, FASTCOVER_MAX_SAMPLES_SIZE)?;
    let dmer_size = (d as usize).max(8);
    if split.training_samples_size < dmer_size {
        // No dmer, or a number of them that wraps around: libzstd divides
        // by zero, or reads past the samples.
        return error!(SrcSizeWrong);
    }
    let offsets = sample_offsets(samples_sizes)?;
    // The table of frequencies, of 2^f cells.
    let freqs = zeroed::<u32>(1usize << f)?;
    let mut ctx = FastCoverCtx {
        samples,
        offsets,
        samples_sizes,
        nb_samples: samples_sizes.len(),
        nb_train_samples: split.nb_train_samples,
        nb_test_samples: split.nb_test_samples,
        nb_dmers: split.training_samples_size - dmer_size + 1,
        freqs: Vec::new(),
        d,
        f,
        accel_params,
    };
    let mut freqs = freqs;
    fastcover_compute_frequency(&mut freqs, &ctx);
    ctx.freqs = freqs;
    Ok(ctx)
}

/// `FASTCOVER_buildDictionary`: the dictionary's content, a segment from
/// each epoch in turn, into the end of `dict`, the first at the very end,
/// until it is full or no segment adds anything. Returns where the content
/// starts (`tail`).
fn fastcover_build_dictionary(
    ctx: &FastCoverCtx<'_>,
    freqs: &mut [u32],
    dict: &mut [u8],
    parameters: &CoverParams,
    segment_freqs: &mut [u16],
) -> usize {
    let capacity = dict.len();
    let mut tail = capacity;
    // Cut the dmers into epochs: a segment from each.
    let epochs = cover_compute_epochs(capacity as u32, ctx.nb_dmers as u32, parameters.k, 1);
    let max_zero_score_run = 10;
    let mut zero_score_run = 0;
    let mut epoch = 0usize;
    // Until the dictionary is full, or no segment is left.
    while tail > 0 {
        let epoch_begin = (epoch * epochs.size as usize) as u32;
        let epoch_end = epoch_begin.wrapping_add(epochs.size);
        let segment = fastcover_select_segment(
            ctx,
            freqs,
            epoch_begin,
            epoch_end,
            parameters,
            segment_freqs,
        );
        epoch = (epoch + 1) % epochs.num as usize;

        // A segment of no dmers: this epoch has nothing more, others may
        // still have some, for a while.
        if segment.score == 0 {
            zero_score_run += 1;
            if zero_score_run >= max_zero_score_run {
                break;
            }
            continue;
        }
        zero_score_run = 0;

        // Cut the segment to fit; too small, and the dictionary is done.
        let segment_size =
            ((segment.end - segment.begin).wrapping_add(parameters.d - 1) as usize).min(tail);
        if segment_size < parameters.d as usize {
            break;
        }

        // From the back: the best segments are then the cheapest to reach,
        // at the smallest offsets.
        tail -= segment_size;
        let begin = segment.begin as usize;
        dict[tail..tail + segment_size].copy_from_slice(&ctx.samples[begin..begin + segment_size]);
    }
    tail
}

/// The samples the dictionaries' tables are made from: the first
/// `accel_params.finalize` percent of the training ones.
fn nb_finalize_samples(ctx: &FastCoverCtx<'_>) -> usize {
    ctx.nb_train_samples * ctx.accel_params.finalize as usize / 100
}

/// `FASTCOVER_tryParameters`: a trial: the dictionary of `parameters` built
/// with the context's frequencies (a copy, which the segments chosen
/// change), finalized and judged (`COVER_selectDict`).
fn fastcover_try_parameters(
    ctx: &FastCoverCtx<'_>,
    dict_buffer_capacity: usize,
    parameters: &CoverParams,
) -> Result<DictSelection> {
    // How often each hash is in the active segment.
    let mut segment_freqs = zeroed::<u16>(1usize << ctx.f)?;
    let mut dict = zeroed::<u8>(dict_buffer_capacity)?;
    let mut freqs = zeroed::<u32>(ctx.freqs.len())?;
    freqs.copy_from_slice(&ctx.freqs);
    let tail =
        fastcover_build_dictionary(ctx, &mut freqs, &mut dict, parameters, &mut segment_freqs);
    cover_select_dict(
        &dict,
        tail,
        ctx.samples,
        ctx.samples_sizes,
        nb_finalize_samples(ctx),
        ctx.nb_train_samples,
        ctx.nb_samples,
        parameters,
        &ctx.offsets,
    )
}

/// `FASTCOVER_convertToCoverParams`: the parameters the COVER functions
/// take; `shrink_dict_max_regression` is left at 0, as in libzstd.
fn fastcover_convert_to_cover_params(params: &FastCoverParams) -> CoverParams {
    CoverParams {
        k: params.k,
        d: params.d,
        steps: params.steps,
        nb_threads: params.nb_threads,
        split_point: params.split_point,
        z_params: params.z_params,
        shrink_dict: params.shrink_dict,
        ..CoverParams::default()
    }
}

/// `FASTCOVER_convertToFastCoverParams`: the parameters a dictionary was
/// made with, back into `fast_cover_params`, with `f` and `accel`; its
/// `shrink_dict_max_regression` stays as it was, as in libzstd.
fn fastcover_convert_to_fast_cover_params(
    cover_params: &CoverParams,
    fast_cover_params: &mut FastCoverParams,
    f: u32,
    accel: u32,
) {
    fast_cover_params.k = cover_params.k;
    fast_cover_params.d = cover_params.d;
    fast_cover_params.steps = cover_params.steps;
    fast_cover_params.nb_threads = cover_params.nb_threads;
    fast_cover_params.split_point = cover_params.split_point;
    fast_cover_params.f = f;
    fast_cover_params.accel = accel;
    fast_cover_params.z_params = cover_params.z_params;
    fast_cover_params.shrink_dict = cover_params.shrink_dict;
}

/// `ZDICT_trainFromBuffer_fastCover`: a dictionary trained on the samples
/// with the fast COVER algorithm, for segments of `parameters.k` bytes and
/// dmers of `parameters.d` (6 or 8), into `dict`. Returns its size, at
/// most `dict.len()`.
///
/// All the samples train (`split_point`, `steps`, `nb_threads` and the
/// shrinking are the optimizer's); `f` and `accel` are 20 and 1 for 0. It
/// needs 6 times `2^f` bytes of memory. Fails with
/// [`ErrorCode::ParameterOutOfBound`](crate::zstd::ErrorCode::ParameterOutOfBound) for parameters out of their bounds
/// (see [`FastCoverParams`]), [`ErrorCode::SrcSizeWrong`](crate::zstd::ErrorCode::SrcSizeWrong) without samples,
/// with fewer than 5, or under 8 bytes of them,
/// [`ErrorCode::DstSizeTooSmall`](crate::zstd::ErrorCode::DstSizeTooSmall) for room under 256 bytes, and as
/// [`finalize_dictionary`](crate::zstd::finalize_dictionary) fails.
pub fn train_from_buffer_fast_cover(
    dict: &mut [u8],
    samples: &[u8],
    sample_sizes: &[usize],
    mut parameters: FastCoverParams,
) -> Result<usize> {
    check_samples(samples, sample_sizes)?;
    let capacity = dict.len();
    // The split point, f and accel, if not given.
    parameters.split_point = 1.0;
    parameters.f = if parameters.f == 0 {
        DEFAULT_F
    } else {
        parameters.f
    };
    parameters.accel = if parameters.accel == 0 {
        DEFAULT_ACCEL
    } else {
        parameters.accel
    };
    let cover_params = fastcover_convert_to_cover_params(&parameters);
    if !fastcover_check_parameters(&cover_params, capacity, parameters.f, parameters.accel) {
        return error!(ParameterOutOfBound);
    }
    if sample_sizes.is_empty() {
        // At least one sample.
        return error!(SrcSizeWrong);
    }
    if capacity < ZDICT_DICTSIZE_MIN {
        return error!(DstSizeTooSmall);
    }
    let accel_params = FASTCOVER_DEFAULT_ACCEL_PARAMETERS[parameters.accel as usize];
    let mut ctx = fastcover_ctx_init(
        samples,
        sample_sizes,
        cover_params.d,
        parameters.split_point,
        parameters.f,
        accel_params,
    )?;
    // How often each hash is in the active segment.
    //
    // Differs from libzstd: libzstd does not check this allocation, and
    // crashes where it fails; the port fails with MemoryAllocation.
    let mut segment_freqs = zeroed::<u16>(1usize << parameters.f)?;
    // The context's frequencies, used up: it serves no other trial.
    let mut freqs = std::mem::take(&mut ctx.freqs);
    let tail =
        fastcover_build_dictionary(&ctx, &mut freqs, dict, &cover_params, &mut segment_freqs);
    let nb_finalize = nb_finalize_samples(&ctx);
    zdict_finalize_dictionary(
        dict,
        Content::Within(tail),
        samples,
        &sample_sizes[..nb_finalize],
        cover_params.z_params,
    )
}

/// `ZDICT_optimizeTrainFromBuffer_fastCover`: the dictionary of the fast
/// COVER trainer for the best `k` and `d` among those it tries, into
/// `dict`; the parameters it was made with go into `parameters`. Returns
/// its size, at most `dict.len()`.
///
/// It tries `d` = 6 and 8 when `parameters.d` is 0 (only that value
/// otherwise), and for each, `steps` values of `k` from 50 to 2000 when
/// `parameters.k` is 0 (only that value otherwise), 40 when `steps` is 0;
/// `f` and `accel` are 20 and 1 for 0. Each trial's dictionary is made
/// from the training samples (the first `split_point` of them, three
/// quarters by default) and judged by the size of the test samples (the
/// others, or all at 1.0) compressed with it; the smallest wins, the first
/// one tried among equals. With `nb_threads` over 1, the trials of each
/// `d` run on that many threads; the dictionary does not depend on their
/// number. It needs about 6 times `2^f` bytes of memory for each thread.
///
/// On success, `parameters` holds those of the dictionary: its `k` and
/// `d`, the split point, steps, `f` and `accel` used, no shrinking, and the
/// notification level lowered by one. It fails as
/// [`train_from_buffer_fast_cover`] does, with
/// [`ErrorCode::ParameterOutOfBound`](crate::zstd::ErrorCode::ParameterOutOfBound) for a split point out of (0, 1], an
/// `accel` over 10, a `k` under `d` or an `f` over 31, and
/// [`ErrorCode::Generic`](crate::zstd::ErrorCode::Generic) when no trial succeeds (a `d` other than 6 and
/// 8, for one).
///
/// Differs from libzstd: libzstd does not check `f` before it makes the
/// table of `2^f` frequencies: over 31, it fails to allocate it
/// (`MemoryAllocation`), or, where that much memory is to be had, fails
/// once every trial has refused `f` (`Generic`). The port fails at once.
/// With threads, libzstd's choice among trials of the same compressed size
/// depends on their timing; the port's is the first in order, as
/// libzstd's on one thread.
pub fn optimize_train_from_buffer_fast_cover(
    dict: &mut [u8],
    samples: &[u8],
    sample_sizes: &[usize],
    parameters: &mut FastCoverParams,
) -> Result<usize> {
    check_samples(samples, sample_sizes)?;
    let capacity = dict.len();
    let nb_threads = parameters.nb_threads;
    let split_point = if parameters.split_point <= 0.0 {
        FASTCOVER_DEFAULT_SPLITPOINT
    } else {
        parameters.split_point
    };
    let k_min_d = if parameters.d == 0 { 6 } else { parameters.d };
    let k_max_d = if parameters.d == 0 { 8 } else { parameters.d };
    let k_min_k = if parameters.k == 0 { 50 } else { parameters.k };
    let k_max_k = if parameters.k == 0 {
        2000
    } else {
        parameters.k
    };
    let k_steps = if parameters.steps == 0 {
        40
    } else {
        parameters.steps
    };
    let k_step_size = ((k_max_k.wrapping_sub(k_min_k)) / k_steps).max(1);
    let f = if parameters.f == 0 {
        DEFAULT_F
    } else {
        parameters.f
    };
    let accel = if parameters.accel == 0 {
        DEFAULT_ACCEL
    } else {
        parameters.accel
    };
    let shrink_dict = false;
    let display_level = parameters.z_params.notification_level;

    if split_point <= 0.0 || split_point > 1.0 {
        return error!(ParameterOutOfBound);
    }
    if accel == 0 || accel > FASTCOVER_MAX_ACCEL {
        return error!(ParameterOutOfBound);
    }
    if k_min_k < k_max_d || k_max_k < k_min_k {
        return error!(ParameterOutOfBound);
    }
    if sample_sizes.is_empty() {
        // At least one sample.
        return error!(SrcSizeWrong);
    }
    if capacity < ZDICT_DICTSIZE_MIN {
        return error!(DstSizeTooSmall);
    }
    if f > FASTCOVER_MAX_F {
        // See the note above.
        return error!(ParameterOutOfBound);
    }
    let mut best = CoverBest::default();
    let cover_params = fastcover_convert_to_cover_params(parameters);
    let accel_params = FASTCOVER_DEFAULT_ACCEL_PARAMETERS[accel as usize];
    // The trials' notification level, lowered (libzstd's g_displayLevel).
    let trial_display_level = display_level.saturating_sub(1);
    // d first: each value needs a new context.
    let mut d = k_min_d;
    while d <= k_max_d {
        let ctx = fastcover_ctx_init(samples, sample_sizes, d, split_point, f, accel_params)?;
        // k next, on the same context.
        let mut trials = Vec::new();
        for k in k_values(k_min_k, k_max_k, k_step_size) {
            let mut trial = cover_params;
            trial.k = k;
            trial.d = d;
            trial.split_point = split_point;
            trial.steps = k_steps;
            trial.shrink_dict = shrink_dict;
            trial.z_params.notification_level = trial_display_level;
            // Parameters out of their bounds are skipped.
            if fastcover_check_parameters(&trial, capacity, ctx.f, accel) {
                trials.push(trial);
            }
        }
        cover_run_trials(&mut best, nb_threads, &trials, &|trial| {
            fastcover_try_parameters(&ctx, capacity, trial)
        })?;
        match d.checked_add(2) {
            Some(next) => d = next,
            None => break,
        }
    }
    // The best trial's dictionary and parameters.
    let (best_dict, best_parameters) = best.into_result()?;
    fastcover_convert_to_fast_cover_params(&best_parameters, parameters, f, accel);
    dict[..best_dict.len()].copy_from_slice(&best_dict);
    Ok(best_dict.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zstd::common::error_private::{Error, ErrorCode};

    #[test]
    fn the_hashes_are_libzstds() {
        // ZSTD_hash6Ptr and ZSTD_hash8Ptr, worked out from their
        // definitions.
        let bytes = *b"abcdefgh";
        let u = u64::from_le_bytes(bytes);
        let h6 = ((u << 16).wrapping_mul(227_718_039_650_203) >> (64 - 20)) as usize;
        let h8 = (u.wrapping_mul(0xCF1B_BCDC_B7A5_6463) >> (64 - 20)) as usize;
        assert_eq!(fastcover_hash_ptr_to_index(&bytes, 0, 20, 6), h6);
        assert_eq!(fastcover_hash_ptr_to_index(&bytes, 0, 20, 8), h8);
        assert_eq!(fastcover_hash_ptr_to_index(&bytes, 0, 20, 7), h8);
    }

    #[test]
    fn errors_come_in_libzstds_order() {
        let samples = vec![7u8; 1000];
        let sizes = [100; 10];
        let mut dict = vec![0u8; 1000];
        let code = |r: Result<usize>| r.map_err(|e: Error| e.code());
        let params = FastCoverParams {
            k: 200,
            d: 8,
            ..FastCoverParams::default()
        };
        // d not 6 or 8.
        let bad = FastCoverParams { d: 7, ..params };
        assert_eq!(
            code(train_from_buffer_fast_cover(
                &mut dict, &samples, &sizes, bad
            )),
            Err(ErrorCode::ParameterOutOfBound)
        );
        // No samples, after the parameters.
        assert_eq!(
            code(train_from_buffer_fast_cover(
                &mut dict,
                &samples,
                &[],
                params
            )),
            Err(ErrorCode::SrcSizeWrong)
        );
        // Too little room: the parameters first (a k over 255).
        let mut small = vec![0u8; 255];
        let large_k = FastCoverParams { k: 300, ..params };
        assert_eq!(
            code(train_from_buffer_fast_cover(
                &mut small, &samples, &sizes, large_k
            )),
            Err(ErrorCode::ParameterOutOfBound)
        );
        let fits = FastCoverParams { k: 100, ..params };
        assert_eq!(
            code(train_from_buffer_fast_cover(
                &mut small, &samples, &sizes, fits
            )),
            Err(ErrorCode::DstSizeTooSmall)
        );
        // Sizes past the samples.
        assert_eq!(
            code(train_from_buffer_fast_cover(
                &mut dict,
                &samples,
                &[600, 600],
                params
            )),
            Err(ErrorCode::SrcSizeWrong)
        );
        // In the optimizer: d other than 6 and 8 makes no trial.
        let mut seven = FastCoverParams { d: 7, ..params };
        assert_eq!(
            code(optimize_train_from_buffer_fast_cover(
                &mut dict, &samples, &sizes, &mut seven
            )),
            Err(ErrorCode::Generic)
        );
        let mut f32 = FastCoverParams { f: 32, ..params };
        assert_eq!(
            code(optimize_train_from_buffer_fast_cover(
                &mut dict, &samples, &sizes, &mut f32
            )),
            Err(ErrorCode::ParameterOutOfBound)
        );
    }
}
