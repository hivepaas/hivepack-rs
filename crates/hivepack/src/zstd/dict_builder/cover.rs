//! Port of `dictBuilder/cover.c` (and `cover.h`): the COVER trainer, from
//! Liao, Petri, Moffat and Wirth, "Effective Construction of Relative
//! Lempel-Ziv Dictionaries" (WWW 2016), and its optimizer.
//!
//! The samples are cut into epochs; from each, in turn, the trainer takes
//! the segment of `k` bytes whose dmers (`d`-byte substrings) are in the
//! most samples, counting each dmer once, then forgets those dmers, until
//! the dictionary is full. The segments go from the end of the dictionary
//! to its start, the best last, where they are cheapest to reach. The
//! dmers are found with a partial suffix array: every position, sorted by
//! its first `d` bytes.
//!
//! The optimizer tries values of `k` for each `d`, each trial on its own
//! dictionary, and keeps the one that compresses the test samples
//! smallest. The parts both trainers share are here too
//! (`COVER_computeEpochs`, `COVER_selectDict`,
//! `COVER_checkTotalCompressedSize`, `COVER_best_t`), and the running of
//! the trials, which libzstd puts on a pool of threads (`POOL_create`,
//! `POOL_add`): here [`std::thread::scope`].
//!
//! `COVER_best_t`'s mutex and condition (`COVER_best_start`,
//! `COVER_best_wait`, `COVER_best_destroy`) are the threads' scope, which
//! returns once every trial is done; `COVER_best_finish` is
//! [`CoverBest::finish`]. `COVER_warnOnSmallCorpus` only prints, and is
//! left out with the notifications.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::zstd::common::bits::highbit32;
use crate::zstd::common::error_private::{Error, ErrorCode, Result, error};
use crate::zstd::common::mem::read_le64;
use crate::zstd::compress::zstd_cdict::CDict;
use crate::zstd::compress::zstd_compress::{CCtx, zstd_compress_bound};
use crate::zstd::dict_builder::zdict::{
    Content, DictParams, ZDICT_DICTSIZE_MIN, zdict_finalize_dictionary,
};
use crate::zstd::dict_builder::{check_samples, zeroed};

/// `COVER_MAX_SAMPLES_SIZE`: the samples are indexed with 32 bits, up to
/// 4 GB on 64-bit machines, and 1 GB on 32-bit ones, which would not have
/// much more room for one buffer.
pub(crate) const COVER_MAX_SAMPLES_SIZE: usize = if cfg!(target_pointer_width = "64") {
    u32::MAX as usize
} else {
    1 << 30
};

/// `COVER_DEFAULT_SPLITPOINT`: all the samples train, and all test.
const COVER_DEFAULT_SPLITPOINT: f64 = 1.0;

/// `ZDICT_cover_params_t`: the parameters of the COVER trainers.
///
/// [`train_from_buffer_cover`] needs `k` and `d`; the others are for
/// [`optimize_train_from_buffer_cover`], where 0 (0.0) means the default
/// for each, and `k` and `d` too. `Default` is all zeros.
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub struct CoverParams {
    /// The size of the segments, from `d` to the dictionary's size; 16 to
    /// 2048 and more is reasonable. The optimizer tries `steps` values from
    /// 50 to 2000 when it is 0.
    pub k: u32,
    /// The size of the dmers, from 1 to `k`; 6 to 16 is reasonable. The
    /// optimizer tries 6 and 8 when it is 0.
    pub d: u32,
    /// The optimizer's number of values of `k` to try: 40 for 0.
    pub steps: u32,
    /// The optimizer's threads, for its trials: 0 and 1 for none.
    pub nb_threads: u32,
    /// The optimizer's share of samples to train on, in (0, 1]: the first
    /// ones train, the others test the dictionaries; all of them do both at
    /// 1.0, the default (0.0).
    pub split_point: f64,
    /// Whether to shrink the dictionary to the smallest one within
    /// `shrink_dict_max_regression` percent of the largest's compressed
    /// size. Taken and ignored, as libzstd 1.5.7's optimizers ignore it
    /// (they set it to 0 for every trial); the trainers never shrink.
    pub shrink_dict: bool,
    /// How much worse, in percent, a smaller dictionary may compress, when
    /// shrinking.
    pub shrink_dict_max_regression: u32,
    /// The parameters of the dictionary's header.
    pub z_params: DictParams,
}

// ---------------------------------------------------------------------------
// Hash table

/// `MAP_EMPTY_VALUE`
const MAP_EMPTY_VALUE: u32 = u32::MAX;

/// `COVER_prime4bytes`
const COVER_PRIME4BYTES: u32 = 2_654_435_761;

/// `COVER_map_t`: a small hash map of the dmers in the active segment and
/// how often they are in it, with linear probing. It never resizes: it is
/// made for the most dmers a segment has, at a load of under a half.
pub(crate) struct CoverMap {
    /// `(key, value)` pairs (`COVER_map_pair_t`).
    data: Vec<(u32, u32)>,
    size_log: u32,
    size_mask: u32,
}

impl CoverMap {
    /// `COVER_map_init`: a map for `size` keys. Fails with
    /// `MemoryAllocation` where the table cannot be had.
    ///
    /// Differs from libzstd: for 2^30 keys or more, libzstd's size,
    /// `(U32)1 << sizeLog`, is undefined; the port fails with
    /// `MemoryAllocation`.
    pub(crate) fn new(size: u32) -> Result<CoverMap> {
        let size_log = highbit32(size.max(1)) + 2;
        if size_log > 31 {
            return error!(MemoryAllocation);
        }
        let map_size = 1usize << size_log;
        let mut data = zeroed::<(u32, u32)>(map_size)?;
        data.fill((MAP_EMPTY_VALUE, MAP_EMPTY_VALUE));
        Ok(CoverMap {
            data,
            size_log,
            size_mask: (map_size - 1) as u32,
        })
    }

    /// `COVER_map_clear`
    fn clear(&mut self) {
        self.data.fill((MAP_EMPTY_VALUE, MAP_EMPTY_VALUE));
    }

    /// `COVER_map_hash`
    fn hash(&self, key: u32) -> u32 {
        key.wrapping_mul(COVER_PRIME4BYTES) >> (32 - self.size_log)
    }

    /// `COVER_map_index`: where `key` is, or would go.
    fn index(&self, key: u32) -> usize {
        let mut i = self.hash(key);
        loop {
            let (pos_key, pos_value) = self.data[i as usize];
            if pos_value == MAP_EMPTY_VALUE || pos_key == key {
                return i as usize;
            }
            i = (i + 1) & self.size_mask;
        }
    }

    /// `COVER_map_at`: the value of `key`, inserted as 0 if it is not in
    /// the map.
    fn at(&mut self, key: u32) -> &mut u32 {
        let i = self.index(key);
        let pos = &mut self.data[i];
        if pos.1 == MAP_EMPTY_VALUE {
            *pos = (key, 0);
        }
        &mut pos.1
    }

    /// `COVER_map_remove`: `key` out of the map, the keys after it moved
    /// back where their probing allows.
    fn remove(&mut self, key: u32) {
        let mut i = self.index(key) as u32;
        let mut del = i as usize;
        let mut shift = 1;
        if self.data[del].1 == MAP_EMPTY_VALUE {
            return;
        }
        i = (i + 1) & self.size_mask;
        loop {
            let pos = self.data[i as usize];
            // An empty slot: done.
            if pos.1 == MAP_EMPTY_VALUE {
                self.data[del].1 = MAP_EMPTY_VALUE;
                return;
            }
            // The pair at `i` can move back to `del`.
            if (i.wrapping_sub(self.hash(pos.0)) & self.size_mask) >= shift {
                self.data[del] = pos;
                del = i as usize;
                shift = 1;
            } else {
                shift += 1;
            }
            i = (i + 1) & self.size_mask;
        }
    }
}

// ---------------------------------------------------------------------------
// Context

/// `COVER_ctx_t`: the samples, with the frequency of each dmer, which only
/// depends on `d`: one context serves every `k`.
pub(crate) struct CoverCtx<'a> {
    pub(crate) samples: &'a [u8],
    /// Where each sample starts, and the end of the last one.
    pub(crate) offsets: Vec<usize>,
    pub(crate) samples_sizes: &'a [usize],
    pub(crate) nb_samples: usize,
    pub(crate) nb_train_samples: usize,
    pub(crate) nb_test_samples: usize,
    /// The positions of the training samples that start a dmer, all but
    /// the last `max(d, 8) - 1`.
    pub(crate) suffix_size: usize,
    /// The number of training samples each dmer is in, by dmer ID.
    pub(crate) freqs: Vec<u32>,
    /// The ID of the dmer at each position: the index of its group in the
    /// sorted suffix array.
    pub(crate) dmer_at: Vec<u32>,
    pub(crate) d: u32,
}

/// `COVER_sum`: the samples' total size.
pub(crate) fn cover_sum(samples_sizes: &[usize]) -> usize {
    samples_sizes
        .iter()
        .fold(0usize, |sum, &size| sum.wrapping_add(size))
}

/// `COVER_lower_bound`: the first index in `first..last` of `offsets`
/// whose value is not less than `value`, or `last`.
fn cover_lower_bound(offsets: &[usize], mut first: usize, last: usize, value: usize) -> usize {
    debug_assert!(last >= first);
    // Positions in order never pass the end (see cover_group).
    first = first.min(last);
    let mut count = last - first;
    while count != 0 {
        let step = count / 2;
        let ptr = first + step;
        if offsets[ptr] < value {
            first = ptr + 1;
            count -= step + 1;
        } else {
            count = step;
        }
    }
    first
}

/// `COVER_group`: the positions of one dmer, in `group`, its first
/// `group_start` in the suffix array: each gets the dmer's ID, and the
/// dmer's frequency, the number of samples it is in, replaces its first
/// position (which is not read again).
///
/// The positions must be in order, as the stable sort leaves them: a
/// position before the end of the sample of the last one counted is in the
/// same sample. A dmer at the very start of a sample counts again at its
/// next position in that sample, as in libzstd (`COVER_lower_bound` finds
/// that sample's start, not its end).
fn cover_group(
    offsets: &[usize],
    nb_samples: usize,
    dmer_at: &mut [u32],
    group: &[u32],
    group_start: usize,
) -> u32 {
    let dmer_id = group_start as u32;
    let mut freq = 0u32;
    let mut cur_offset = 0;
    let offsets_end = nb_samples;
    // Once a position reaches it, the dmer is in another sample.
    let mut cur_sample_end = offsets[0];
    for (i, &pos) in group.iter().enumerate() {
        // Save the dmer's ID for this position, to get back to it.
        dmer_at[pos as usize] = dmer_id;
        // Dictionaries only help the first reference to the dmer in a
        // sample: zstd can then reference the earlier one. Each dmer counts
        // once per sample it is in.
        if (pos as usize) < cur_sample_end {
            continue;
        }
        freq = freq.wrapping_add(1);
        // The end of this position's sample, but for the last position.
        if i + 1 != group.len() {
            let sample_end = cover_lower_bound(offsets, cur_offset, offsets_end, pos as usize);
            cur_sample_end = offsets[sample_end];
            cur_offset = sample_end + 1;
        }
    }
    freq
}

/// The dmers at positions `l` and `r`: libzstd's `COVER_cmp8` for `d` up
/// to 8 (their bytes as little-endian numbers), `COVER_cmp` (`memcmp`)
/// above.
#[inline(always)]
fn cover_cmp(samples: &[u8], d: u32, l: u32, r: u32) -> std::cmp::Ordering {
    if d <= 8 {
        let mask = if d == 8 {
            u64::MAX
        } else {
            (1u64 << (8 * d)) - 1
        };
        let lhs = read_le64(samples, l as usize) & mask;
        let rhs = read_le64(samples, r as usize) & mask;
        lhs.cmp(&rhs)
    } else {
        let d = d as usize;
        samples[l as usize..l as usize + d].cmp(&samples[r as usize..r as usize + d])
    }
}

/// `COVER_checkParameters`: whether the parameters are valid for a
/// dictionary of `max_dict_size` bytes: `0 < d <= k <= max_dict_size`, and
/// `0 < split_point <= 1`.
fn cover_check_parameters(parameters: &CoverParams, max_dict_size: usize) -> bool {
    // k and d are required.
    if parameters.d == 0 || parameters.k == 0 {
        return false;
    }
    if parameters.k as usize > max_dict_size {
        return false;
    }
    if parameters.d > parameters.k {
        return false;
    }
    // 0 < splitPoint <= 1; NaN passes, as in libzstd, and is then taken as
    // 1.
    if parameters.split_point <= 0.0 || parameters.split_point > 1.0 {
        return false;
    }
    true
}

/// The training and test sets of `ctx_init`: how many samples, and their
/// sizes.
pub(crate) struct Split {
    pub(crate) total_samples_size: usize,
    pub(crate) nb_train_samples: usize,
    pub(crate) nb_test_samples: usize,
    pub(crate) training_samples_size: usize,
}

/// The first `nb_samples * split_point` samples to train on, the others to
/// test, or all of them for both at 1, as `COVER_ctx_init` and
/// `FASTCOVER_ctx_init` split them; checked as they check: enough samples
/// in total (`d` bytes, and 8 at least), under `COVER_MAX_SAMPLES_SIZE`, 5
/// training samples at least, and a test sample. Fails with `SrcSizeWrong`.
///
/// Differs from libzstd: with training samples shorter than `max(d, 8)`
/// in total, which only a split point under 1 allows, the number of dmers
/// goes below 0 and wraps around. libzstd then fails to allocate the
/// COVER context (`MemoryAllocation`), as the port's
/// [`cover_ctx_init`] does; or, for one byte short, divides by zero (a
/// crash on x86-64); or, for the fast COVER context, reads past the
/// samples. The port fails with `SrcSizeWrong` for those two.
pub(crate) fn split_samples(
    samples_sizes: &[usize],
    d: u32,
    split_point: f64,
    max_samples_size: usize,
) -> Result<Split> {
    let nb_samples = samples_sizes.len();
    let total_samples_size = cover_sum(samples_sizes);
    // Split the samples into training and test sets.
    let nb_train_samples = if split_point < 1.0 {
        ((nb_samples as f64) * split_point) as u32 as usize
    } else {
        nb_samples
    };
    let nb_test_samples = if split_point < 1.0 {
        nb_samples - nb_train_samples
    } else {
        nb_samples
    };
    let training_samples_size = if split_point < 1.0 {
        cover_sum(&samples_sizes[..nb_train_samples])
    } else {
        total_samples_size
    };
    let dmer_size = (d as usize).max(8);
    if total_samples_size < dmer_size || total_samples_size >= max_samples_size {
        // Too small, or too large.
        return error!(SrcSizeWrong);
    }
    // At least 5 training samples.
    if nb_train_samples < 5 {
        return error!(SrcSizeWrong);
    }
    // And a test sample.
    if nb_test_samples < 1 {
        return error!(SrcSizeWrong);
    }
    Ok(Split {
        total_samples_size,
        nb_train_samples,
        nb_test_samples,
        training_samples_size,
    })
}

/// The start of each sample, and the end of the last one: `offsets` of
/// the contexts.
pub(crate) fn sample_offsets(samples_sizes: &[usize]) -> Result<Vec<usize>> {
    let mut offsets = zeroed::<usize>(samples_sizes.len() + 1)?;
    for i in 1..=samples_sizes.len() {
        offsets[i] = offsets[i - 1] + samples_sizes[i - 1];
    }
    Ok(offsets)
}

/// `COVER_ctx_init`: the context for dmers of `d` bytes: the samples split
/// (see [`split_samples`]), the partial suffix array of the training
/// samples sorted, and each dmer's frequency.
///
/// Differs from libzstd: libzstd sorts with the C library's `qsort_r`
/// (`qsort_s` on Windows), and breaks ties between positions of the same
/// dmer by their addresses during the sort: only a merge sort, glibc's,
/// leaves each dmer's positions in order, as `COVER_group` needs and the
/// comments say ("The sort is stable"). The port sorts stably, giving
/// libzstd's dictionaries on Linux; elsewhere (macOS, Windows, the BSDs),
/// libzstd's frequencies, and dictionaries, depend on its `qsort`.
pub(crate) fn cover_ctx_init<'a>(
    samples: &'a [u8],
    samples_sizes: &'a [usize],
    d: u32,
    split_point: f64,
) -> Result<CoverCtx<'a>> {
    let split = split_samples(samples_sizes, d, split_point, COVER_MAX_SAMPLES_SIZE)?;
    let dmer_size = (d as usize).max(8);
    if split.training_samples_size + 1 < dmer_size {
        // The suffix array's size wraps around: libzstd fails to allocate
        // it.
        return error!(MemoryAllocation);
    }
    if split.training_samples_size + 1 == dmer_size {
        // No dmer: libzstd divides by zero in COVER_computeEpochs.
        return error!(SrcSizeWrong);
    }
    // The partial suffix array.
    let suffix_size = split.training_samples_size - dmer_size + 1;
    // The ID of the dmer at each position.
    let mut dmer_at = zeroed::<u32>(suffix_size)?;
    let offsets = sample_offsets(samples_sizes)?;

    // The partial suffix array sorts the positions by their first d bytes
    // only. The sort is stable: each dmer's positions stay in order.
    let mut suffix = zeroed::<u32>(suffix_size)?;
    for (i, position) in suffix.iter_mut().enumerate() {
        *position = i as u32;
    }
    suffix.sort_by(|&l, &r| cover_cmp(samples, d, l, r));

    // For each group of positions of the same dmer: dmerAt of each, the
    // group's start in the suffix array as the dmer's ID, and the number
    // of samples the dmer is in, written over the group's first position,
    // never read again. COVER_groupBy, with COVER_group.
    let nb_samples = samples_sizes.len();
    let mut num = 0;
    while num < suffix_size {
        let start = num;
        num += 1;
        while num < suffix_size
            && cover_cmp(samples, d, suffix[start], suffix[num]) == std::cmp::Ordering::Equal
        {
            num += 1;
        }
        let freq = cover_group(
            &offsets,
            nb_samples,
            &mut dmer_at,
            &suffix[start..num],
            start,
        );
        suffix[start] = freq;
    }

    Ok(CoverCtx {
        samples,
        offsets,
        samples_sizes,
        nb_samples,
        nb_train_samples: split.nb_train_samples,
        nb_test_samples: split.nb_test_samples,
        suffix_size,
        freqs: suffix,
        dmer_at,
        d,
    })
}

/// `COVER_segment_t`: positions `begin..end` and their score.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct CoverSegment {
    pub(crate) begin: u32,
    pub(crate) end: u32,
    pub(crate) score: u32,
}

/// `COVER_selectSegment`: the best segment of the epoch `begin..end`: the
/// one of `k - d + 1` dmers whose frequencies add up the highest, each
/// dmer once:
///
/// ```text
/// Score(S) = F(S_1) + F(S_2) + ... + F(S_{k-d+1})
/// ```
///
/// trimmed of the dmers of no frequency at both ends. The frequencies of
/// its dmers then become 0: once in the dictionary, a dmer helps no more.
fn cover_select_segment(
    ctx: &CoverCtx<'_>,
    freqs: &mut [u32],
    active_dmers: &mut CoverMap,
    begin: u32,
    end: u32,
    parameters: &CoverParams,
) -> CoverSegment {
    let dmers_in_k = parameters.k - parameters.d + 1;
    // Try each segment (active) and keep the best.
    let mut best_segment = CoverSegment::default();
    // The active segment starts at the start of the epoch, with no dmers.
    active_dmers.clear();
    let mut active_segment = CoverSegment {
        begin,
        end: begin,
        score: 0,
    };
    // Slide it through the whole epoch.
    while active_segment.end < end {
        // The dmer at the next position.
        let new_dmer = ctx.dmer_at[active_segment.end as usize];
        let new_dmer_occ = active_dmers.at(new_dmer);
        // A dmer new to the segment adds its score. (The paper suggests
        // the L-0.5 norm, but experiments show that it does not help.)
        if *new_dmer_occ == 0 {
            active_segment.score = active_segment.score.wrapping_add(freqs[new_dmer as usize]);
        }
        // Add the dmer to the segment.
        active_segment.end += 1;
        *new_dmer_occ = new_dmer_occ.wrapping_add(1);

        // Too large a window: drop its first position.
        if active_segment.end - active_segment.begin == dmers_in_k.wrapping_add(1) {
            let del_dmer = ctx.dmer_at[active_segment.begin as usize];
            let del_dmer_occ = active_dmers.at(del_dmer);
            active_segment.begin += 1;
            *del_dmer_occ = del_dmer_occ.wrapping_sub(1);
            // Its last occurrence: subtract its score.
            if *del_dmer_occ == 0 {
                active_dmers.remove(del_dmer);
                active_segment.score = active_segment.score.wrapping_sub(freqs[del_dmer as usize]);
            }
        }

        if active_segment.score > best_segment.score {
            best_segment = active_segment;
        }
    }
    {
        // Trim the dmers of no frequency at the head and tail.
        let mut new_begin = best_segment.end;
        let mut new_end = best_segment.begin;
        for pos in best_segment.begin..best_segment.end {
            let freq = freqs[ctx.dmer_at[pos as usize] as usize];
            if freq != 0 {
                new_begin = new_begin.min(pos);
                new_end = pos + 1;
            }
        }
        best_segment.begin = new_begin;
        best_segment.end = new_end;
    }
    // The segment's dmers are in the dictionary: no frequency any more.
    for pos in best_segment.begin..best_segment.end {
        freqs[ctx.dmer_at[pos as usize] as usize] = 0;
    }
    best_segment
}

/// `COVER_epoch_info_t`: the number of epochs and their size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EpochInfo {
    pub(crate) num: u32,
    pub(crate) size: u32,
}

/// `COVER_computeEpochs`: how to cut `nb_dmers` dmers into epochs, one
/// segment of `k` taken from each in turn, for `passes` passes over them
/// (more is a better dictionary) to fill `max_dict_size` bytes; each epoch
/// at least `10 * k` dmers, if there are that many. `nb_dmers` must not be
/// 0.
pub(crate) fn cover_compute_epochs(
    max_dict_size: u32,
    nb_dmers: u32,
    k: u32,
    passes: u32,
) -> EpochInfo {
    debug_assert!(nb_dmers != 0);
    let min_epoch_size = k.wrapping_mul(10);
    let num = (max_dict_size / k / passes).max(1);
    let mut epochs = EpochInfo {
        num,
        size: nb_dmers / num,
    };
    if epochs.size >= min_epoch_size {
        debug_assert!(u64::from(epochs.size) * u64::from(epochs.num) <= u64::from(nb_dmers));
        return epochs;
    }
    epochs.size = min_epoch_size.min(nb_dmers);
    epochs.num = nb_dmers / epochs.size.max(1);
    debug_assert!(u64::from(epochs.size) * u64::from(epochs.num) <= u64::from(nb_dmers));
    epochs
}

/// `COVER_buildDictionary`: the dictionary's content, a segment from each
/// epoch in turn, into the end of `dict`, the first at the very end, until
/// it is full or no segment adds anything. Returns where the content
/// starts (`tail`).
fn cover_build_dictionary(
    ctx: &CoverCtx<'_>,
    freqs: &mut [u32],
    active_dmers: &mut CoverMap,
    dict: &mut [u8],
    parameters: &CoverParams,
) -> usize {
    let capacity = dict.len();
    let mut tail = capacity;
    // Cut the dmers into epochs: a segment from each.
    let epochs = cover_compute_epochs(capacity as u32, ctx.suffix_size as u32, parameters.k, 4);
    let max_zero_score_run = (epochs.num as usize >> 3).clamp(10, 100);
    let mut zero_score_run = 0;
    let mut epoch = 0usize;
    // Until the dictionary is full, or no segment is left.
    while tail > 0 {
        let epoch_begin = (epoch * epochs.size as usize) as u32;
        let epoch_end = epoch_begin.wrapping_add(epochs.size);
        let segment =
            cover_select_segment(ctx, freqs, active_dmers, epoch_begin, epoch_end, parameters);
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

/// `ZDICT_trainFromBuffer_cover`: a dictionary trained on the samples with
/// the COVER algorithm, for segments of `parameters.k` bytes and dmers of
/// `parameters.d`, into `dict`. Returns its size, at most `dict.len()`.
///
/// All the samples train (`split_point`, `steps`, `nb_threads` and the
/// shrinking are the optimizer's). It needs about 9 bytes of memory for
/// each byte of samples. Fails with [`ErrorCode::ParameterOutOfBound`] for
/// parameters out of their bounds (see [`CoverParams`]),
/// [`ErrorCode::SrcSizeWrong`] without samples, with fewer than 5, or
/// under 8 bytes of them, [`ErrorCode::DstSizeTooSmall`] for room under 256
/// bytes, and as [`finalize_dictionary`](crate::zstd::finalize_dictionary) fails.
///
/// Differs from libzstd: on macOS, Windows and the BSDs, libzstd's
/// dictionaries can differ; see `docs/porting.md`. They are those of
/// libzstd on Linux.
pub fn train_from_buffer_cover(
    dict: &mut [u8],
    samples: &[u8],
    sample_sizes: &[usize],
    mut parameters: CoverParams,
) -> Result<usize> {
    check_samples(samples, sample_sizes)?;
    let capacity = dict.len();
    parameters.split_point = 1.0;
    if !cover_check_parameters(&parameters, capacity) {
        return error!(ParameterOutOfBound);
    }
    if sample_sizes.is_empty() {
        // At least one sample.
        return error!(SrcSizeWrong);
    }
    if capacity < ZDICT_DICTSIZE_MIN {
        return error!(DstSizeTooSmall);
    }
    let mut ctx = cover_ctx_init(samples, sample_sizes, parameters.d, parameters.split_point)?;
    let mut active_dmers = CoverMap::new(parameters.k - parameters.d + 1)?;
    // The context's frequencies, used up: it serves no other trial.
    let mut freqs = std::mem::take(&mut ctx.freqs);
    let tail = cover_build_dictionary(&ctx, &mut freqs, &mut active_dmers, dict, &parameters);
    zdict_finalize_dictionary(
        dict,
        Content::Within(tail),
        samples,
        sample_sizes,
        parameters.z_params,
    )
}

/// `COVER_checkTotalCompressedSize`: the size of the dictionary `dict`, and
/// of the test samples compressed with it (all the samples, at a split
/// point of 1) at the level of `parameters`, each frame with a `CDict`
/// (`ZSTD_compress_usingCDict`). Fails with `Generic` when the dictionary
/// cannot be made a `CDict` or a sample does not compress.
pub(crate) fn cover_check_total_compressed_size(
    parameters: &CoverParams,
    samples_sizes: &[usize],
    samples: &[u8],
    offsets: &[usize],
    nb_train_samples: usize,
    nb_samples: usize,
    dict: &[u8],
) -> Result<usize> {
    let first = if parameters.split_point < 1.0 {
        nb_train_samples
    } else {
        0
    };
    // Room for the largest sample.
    let max_sample_size = samples_sizes[first..nb_samples]
        .iter()
        .copied()
        .max()
        .unwrap_or(0);
    let dst_capacity =
        zstd_compress_bound(max_sample_size).map_err(|_| Error::from(ErrorCode::Generic))?;
    let mut dst = zeroed::<u8>(dst_capacity).map_err(|_| Error::from(ErrorCode::Generic))?;
    let mut cctx = CCtx::new();
    let cdict = CDict::new(dict, parameters.z_params.compression_level)
        .map_err(|_| Error::from(ErrorCode::Generic))?;
    // Compress each sample, and add up their sizes.
    let mut total_compressed_size = dict.len();
    for i in first..nb_samples {
        let sample = &samples[offsets[i]..offsets[i] + samples_sizes[i]];
        let size = cctx.compress_using_cdict(&mut dst, sample, &cdict)?;
        total_compressed_size += size;
    }
    Ok(total_compressed_size)
}

/// `COVER_dictSelection_t`: a trial's dictionary, and the total compressed
/// size it was judged by.
#[derive(Debug)]
pub(crate) struct DictSelection {
    pub(crate) dict_content: Vec<u8>,
    pub(crate) total_compressed_size: usize,
}

/// `COVER_selectDict`: the dictionary of the content `dict_buffer[tail..]`,
/// finalized for the first `nb_finalize_samples` samples and judged by the
/// compressed size of the test samples ([`cover_check_total_compressed_size`],
/// `nb_check_samples` training ones). With `params.shrink_dict`, the
/// smallest of the dictionaries of its last 256 bytes, then of twice the
/// size of the dictionary before (the header included), and so on, whose
/// compressed size is within `shrink_dict_max_regression` percent of the
/// whole content's; or the whole content's.
///
/// Differs from libzstd: shrinking can take more bytes than the content,
/// the doubled sizes counting the header: libzstd's then start in the part
/// of its buffer that it never wrote (`malloc`ed), the port's in zeros.
/// libzstd's optimizers never shrink (they set `shrinkDict` to 0), so no
/// dictionary changes.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cover_select_dict(
    dict_buffer: &[u8],
    tail: usize,
    samples: &[u8],
    samples_sizes: &[usize],
    nb_finalize_samples: usize,
    nb_check_samples: usize,
    nb_samples: usize,
    params: &CoverParams,
    offsets: &[usize],
) -> Result<DictSelection> {
    let capacity = dict_buffer.len();
    let custom_dict_content = &dict_buffer[tail..];
    let regression_tolerance = (f64::from(params.shrink_dict_max_regression) / 100.0) + 1.00;
    let finalize_sizes = &samples_sizes[..nb_finalize_samples];

    // The dictionary of the whole content, and its compressed size.
    let mut largest_dict_buffer = zeroed::<u8>(capacity)?;
    let largest_dict = zdict_finalize_dictionary(
        &mut largest_dict_buffer,
        Content::Apart(custom_dict_content),
        samples,
        finalize_sizes,
        params.z_params,
    )?;
    let largest_compressed = cover_check_total_compressed_size(
        params,
        samples_sizes,
        samples,
        offsets,
        nb_check_samples,
        nb_samples,
        &largest_dict_buffer[..largest_dict],
    )?;
    largest_dict_buffer.truncate(largest_dict);
    if !params.shrink_dict {
        return Ok(DictSelection {
            dict_content: largest_dict_buffer,
            total_compressed_size: largest_compressed,
        });
    }

    // From ZDICT_DICTSIZE_MIN bytes of content up.
    let mut candidate_dict_buffer = zeroed::<u8>(capacity)?;
    let mut dict_content_size = ZDICT_DICTSIZE_MIN;
    while dict_content_size < largest_dict {
        // libzstd copies the largest dictionary in first, which the
        // finalized one then covers: only its own bytes are read.
        let candidate_content = &dict_buffer[capacity - dict_content_size..];
        dict_content_size = zdict_finalize_dictionary(
            &mut candidate_dict_buffer,
            Content::Apart(candidate_content),
            samples,
            finalize_sizes,
            params.z_params,
        )?;
        let total_compressed_size = cover_check_total_compressed_size(
            params,
            samples_sizes,
            samples,
            offsets,
            nb_check_samples,
            nb_samples,
            &candidate_dict_buffer[..dict_content_size],
        )?;
        if (total_compressed_size as f64) <= (largest_compressed as f64) * regression_tolerance {
            candidate_dict_buffer.truncate(dict_content_size);
            return Ok(DictSelection {
                dict_content: candidate_dict_buffer,
                total_compressed_size,
            });
        }
        // Twice the dictionary's size, not the content's, as in libzstd.
        dict_content_size *= 2;
    }
    Ok(DictSelection {
        dict_content: largest_dict_buffer,
        total_compressed_size: largest_compressed,
    })
}

/// `COVER_best_t`: the best trial so far: its dictionary, parameters and
/// compressed size.
#[derive(Debug, Default)]
pub(crate) struct CoverBest {
    dict: Vec<u8>,
    parameters: CoverParams,
    /// `None` until a trial succeeds: libzstd's `(size_t)-1`, which no
    /// trial beats and which reads as `ERROR(GENERIC)`.
    compressed_size: Option<usize>,
}

impl CoverBest {
    /// `COVER_best_finish`, the end of a trial: its dictionary and
    /// parameters become the best if its compressed size is smaller than
    /// the best's. A trial that failed changes nothing.
    pub(crate) fn finish(&mut self, parameters: CoverParams, selection: Result<DictSelection>) {
        let Ok(selection) = selection else {
            return;
        };
        if self
            .compressed_size
            .is_none_or(|best| selection.total_compressed_size < best)
        {
            self.dict = selection.dict_content;
            self.parameters = parameters;
            self.compressed_size = Some(selection.total_compressed_size);
        }
    }

    /// The best trial's dictionary and parameters; `Generic` when every
    /// trial failed, or none was tried.
    pub(crate) fn into_result(self) -> Result<(Vec<u8>, CoverParams)> {
        match self.compressed_size {
            Some(_) => Ok((self.dict, self.parameters)),
            None => error!(Generic),
        }
    }
}

/// Runs `try_parameters` on each of `trials`, on `nb_threads` threads when
/// there are more than one (libzstd's pool of `POOL_create(nbThreads, 1)`),
/// and gives the results to `best` as the trials come, in order.
///
/// Differs from libzstd: libzstd's threads give their results to
/// `COVER_best_finish` as they end, and among trials of the same compressed
/// size the first to end wins, which depends on the threads' timing. The
/// port takes them in the trials' order, as libzstd does on one thread: the
/// dictionary is then the same for any number of threads.
pub(crate) fn cover_run_trials(
    best: &mut CoverBest,
    nb_threads: u32,
    trials: &[CoverParams],
    try_parameters: &(dyn Fn(&CoverParams) -> Result<DictSelection> + Sync),
) -> Result<()> {
    if nb_threads <= 1 || trials.len() <= 1 {
        for parameters in trials {
            best.finish(*parameters, try_parameters(parameters));
        }
        return Ok(());
    }
    // Each thread takes the next trial, and keeps the best of its own, the
    // first in order among equals: the best of those is the best of all.
    let next = AtomicUsize::new(0);
    let work = || {
        let mut own: Option<(usize, usize, DictSelection)> = None;
        loop {
            let i = next.fetch_add(1, Ordering::Relaxed);
            let Some(parameters) = trials.get(i) else {
                return own;
            };
            if let Ok(selection) = try_parameters(parameters) {
                let size = selection.total_compressed_size;
                if own.as_ref().is_none_or(|(best, _, _)| size < *best) {
                    own = Some((size, i, selection));
                }
            }
        }
    };
    let results = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        let mut spawned = Ok(());
        for _ in 0..(nb_threads as usize).min(trials.len()) {
            match std::thread::Builder::new()
                .name("hivepack-zstd".into())
                .spawn_scoped(scope, work)
            {
                Ok(handle) => handles.push(handle),
                // As libzstd's pool fails to start (POOL_create).
                Err(_) => spawned = error!(MemoryAllocation),
            }
        }
        let results: Vec<_> = handles.into_iter().map(|handle| handle.join()).collect();
        spawned.map(|()| results)
    })?;
    let mut winner: Option<(usize, usize, DictSelection)> = None;
    for result in results {
        // A thread that panicked: a bug, reported as libzstd's generic
        // error rather than passed on.
        let own = result.map_err(|_| Error::from(ErrorCode::Generic))?;
        if let Some((size, i, selection)) = own
            && winner
                .as_ref()
                .is_none_or(|(best, j, _)| (size, i) < (*best, *j))
        {
            winner = Some((size, i, selection));
        }
    }
    if let Some((_, i, selection)) = winner {
        best.finish(trials[i], Ok(selection));
    }
    Ok(())
}

/// The values of `k` the optimizers try: from `min_k` to `max_k` by
/// `step`.
///
/// Differs from libzstd: libzstd's loop goes on past `u32::MAX`, wrapping
/// around to 0, forever; the port's stops there.
pub(crate) fn k_values(min_k: u32, max_k: u32, step: u32) -> impl Iterator<Item = u32> {
    let mut k = Some(min_k);
    std::iter::from_fn(move || {
        let current = k.filter(|&k| k <= max_k)?;
        k = current.checked_add(step);
        Some(current)
    })
}

/// `COVER_tryParameters`: a trial: the dictionary of `parameters` built
/// with the context's frequencies (a copy, which the segments chosen
/// change), finalized and judged ([`cover_select_dict`]).
fn cover_try_parameters(
    ctx: &CoverCtx<'_>,
    dict_buffer_capacity: usize,
    parameters: &CoverParams,
) -> Result<DictSelection> {
    let mut active_dmers = CoverMap::new(parameters.k - parameters.d + 1)?;
    let mut dict = zeroed::<u8>(dict_buffer_capacity)?;
    // A copy of the frequencies, which the segments chosen change.
    let mut freqs = zeroed::<u32>(ctx.suffix_size)?;
    freqs.copy_from_slice(&ctx.freqs);
    let tail = cover_build_dictionary(ctx, &mut freqs, &mut active_dmers, &mut dict, parameters);
    cover_select_dict(
        &dict,
        tail,
        ctx.samples,
        ctx.samples_sizes,
        ctx.nb_train_samples,
        ctx.nb_train_samples,
        ctx.nb_samples,
        parameters,
        &ctx.offsets,
    )
}

/// `ZDICT_optimizeTrainFromBuffer_cover`: the dictionary of the COVER
/// trainer for the best `k` and `d` among those it tries, into `dict`; the
/// parameters it was made with go into `parameters`. Returns its size, at
/// most `dict.len()`.
///
/// It tries `d` = 6 and 8 when `parameters.d` is 0 (only that value
/// otherwise), and for each, `steps` values of `k` from 50 to 2000 when
/// `parameters.k` is 0 (only that value otherwise), 40 when `steps` is 0.
/// Each trial's dictionary is made from the training samples (the first
/// `split_point` of them, all by default) and judged by the size of the
/// test samples (the others, or all) compressed with it; the smallest
/// wins, the first one tried among equals. With `nb_threads` over 1, the
/// trials of each `d` run on that many threads; the dictionary does not
/// depend on their number. It needs about 8 bytes of memory per byte of
/// samples, and 5 more per byte of dictionary for each thread.
///
/// On success, `parameters` holds those of the dictionary: its `k` and
/// `d`, the split point and steps used, no shrinking, and the notification
/// level lowered by one. It fails as [`train_from_buffer_cover`] does,
/// with [`ErrorCode::ParameterOutOfBound`] for a split point out of
/// (0, 1] or a `k` under `d`, and [`ErrorCode::Generic`] when no trial
/// succeeds.
///
/// Differs from libzstd: on macOS, Windows and the BSDs, libzstd's
/// dictionaries can differ; see `docs/porting.md`. With threads,
/// libzstd's choice among trials of the same compressed size depends on
/// their timing; the port's is the first in order, as libzstd's on one
/// thread.
pub fn optimize_train_from_buffer_cover(
    dict: &mut [u8],
    samples: &[u8],
    sample_sizes: &[usize],
    parameters: &mut CoverParams,
) -> Result<usize> {
    check_samples(samples, sample_sizes)?;
    let capacity = dict.len();
    let nb_threads = parameters.nb_threads;
    let split_point = if parameters.split_point <= 0.0 {
        COVER_DEFAULT_SPLITPOINT
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
    let shrink_dict = false;
    let display_level = parameters.z_params.notification_level;

    if split_point <= 0.0 || split_point > 1.0 {
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
    let mut best = CoverBest::default();
    // The trials' notification level, lowered (libzstd's g_displayLevel).
    let trial_display_level = display_level.saturating_sub(1);
    // d first: each value needs a new context.
    let mut d = k_min_d;
    while d <= k_max_d {
        let ctx = cover_ctx_init(samples, sample_sizes, d, split_point)?;
        // k next, on the same context.
        let mut trials = Vec::new();
        for k in k_values(k_min_k, k_max_k, k_step_size) {
            let mut trial = *parameters;
            trial.k = k;
            trial.d = d;
            trial.split_point = split_point;
            trial.steps = k_steps;
            trial.shrink_dict = shrink_dict;
            trial.z_params.notification_level = trial_display_level;
            // Parameters out of their bounds are skipped.
            if cover_check_parameters(&trial, capacity) {
                trials.push(trial);
            }
        }
        cover_run_trials(&mut best, nb_threads, &trials, &|trial| {
            cover_try_parameters(&ctx, capacity, trial)
        })?;
        match d.checked_add(2) {
            Some(next) => d = next,
            None => break,
        }
    }
    // The best trial's dictionary and parameters.
    let (best_dict, best_parameters) = best.into_result()?;
    *parameters = best_parameters;
    dict[..best_dict.len()].copy_from_slice(&best_dict);
    Ok(best_dict.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_map_counts_and_forgets_keys() {
        let mut map = CoverMap::new(5).expect("a map");
        // Keys that collide and probe past each other.
        let keys: Vec<u32> = (0..20u32).map(|i| i.wrapping_mul(0x1000_0001)).collect();
        for (i, &key) in keys.iter().enumerate() {
            for _ in 0..=i % 3 {
                *map.at(key) += 1;
            }
            if i >= 5 {
                map.remove(keys[i - 5]);
            }
        }
        // Looked up without inserting: the map holds no more than its five
        // keys and a few, as COVER's never holds more than its dmers.
        let get = |map: &CoverMap, key: u32| {
            let (k, v) = map.data[map.index(key)];
            (v != MAP_EMPTY_VALUE && k == key).then_some(v)
        };
        for (i, &key) in keys.iter().enumerate() {
            let want = (i >= 15).then_some((i % 3 + 1) as u32);
            assert_eq!(get(&map, key), want, "key {i}");
        }
    }

    #[test]
    fn epochs_are_ten_segments_long_at_least() {
        assert_eq!(
            cover_compute_epochs(1000, 100_000, 50, 4),
            EpochInfo {
                num: 5,
                size: 20_000
            }
        );
        // Fewer dmers than 10 segments in each epoch: fewer epochs.
        assert_eq!(
            cover_compute_epochs(100_000, 10_000, 50, 4),
            EpochInfo { num: 20, size: 500 }
        );
        // Fewer dmers than one epoch of them.
        assert_eq!(
            cover_compute_epochs(100_000, 300, 50, 1),
            EpochInfo { num: 1, size: 300 }
        );
    }

    #[test]
    fn the_values_of_k_stop_at_the_largest() {
        assert_eq!(
            k_values(50, 2000, 487).collect::<Vec<_>>(),
            [50, 537, 1024, 1511, 1998]
        );
        assert_eq!(
            k_values(u32::MAX, u32::MAX, 1).collect::<Vec<_>>(),
            [u32::MAX]
        );
        assert_eq!(k_values(10, 9, 1).count(), 0);
    }
}
