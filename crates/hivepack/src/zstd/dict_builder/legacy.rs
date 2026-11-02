//! The legacy dictionary trainer: port of the part of
//! `dictBuilder/zdict.c` that is its own, `ZDICT_trainFromBuffer_legacy`,
//! `ZDICT_trainFromBuffer_unsafe_legacy` and `ZDICT_trainBuffer_legacy`
//! with the functions they call, up to the entropy tables.
//!
//! The trainer sorts the suffixes of the samples ([`divsufsort`]), then
//! walks the samples: at each position no segment covers yet,
//! `ZDICT_analyzePos` looks at the suffixes sorted next to the one there,
//! which share a prefix with it, and picks the longest segment that
//! repeats often enough, with what it would save; `ZDICT_insertDictItem`
//! keeps the segments in a list, best first, merging those that overlap.
//! The dictionary's content is the best segments that fit, the best one
//! last, nearest the data.
//!
//! The samples are followed by a "noisy guard band" of `NOISELENGTH` bytes
//! (`ZDICT_fillNoise`), at which comparisons that reach the end of the
//! samples stop, as they find bytes that differ: libzstd does not check
//! where they are. The port reads only within the buffer it is given, and
//! stops where libzstd would read past it, which it does only when samples
//! repeat the guard band itself, for 7 bytes or more: each place is marked.
//!
//! The trainer ends with `ZDICT_addEntropyTablesFromBuffer_advanced`, of
//! `dict_builder/zdict.rs`. libzstd's messages to stderr (`DISPLAYLEVEL`)
//! are left out, which change nothing; the notification level is still
//! taken, for the one check that depends on it.

use crate::zstd::common::error_private::{Result, error};
use crate::zstd::common::mem::read_le64;
use crate::zstd::dict_builder::divsufsort::divsufsort;
use crate::zstd::dict_builder::zdict::{DictParams, zdict_add_entropy_tables_from_buffer_advanced};

/// `MINRATIO`: the fewest times a segment must appear to be selected.
const MINRATIO: u32 = 4;
/// `ZDICT_MAX_SAMPLES_SIZE`: the most samples sorted, a limit of
/// divsufsort's `int` positions.
const ZDICT_MAX_SAMPLES_SIZE: usize = 2000 << 20;
/// `ZDICT_DICTSIZE_MIN`, of `zdict.h`: the smallest dictionary.
const ZDICT_DICTSIZE_MIN: usize = 256;
/// `ZDICT_CONTENTSIZE_MIN`, of `zdict.h`: the least content a dictionary
/// can have.
const ZDICT_CONTENTSIZE_MIN: usize = 128;
/// `ZDICT_MIN_SAMPLES_SIZE`: the fewest bytes of samples to train on.
const ZDICT_MIN_SAMPLES_SIZE: usize = ZDICT_CONTENTSIZE_MIN * MINRATIO as usize;
/// `DICTLISTSIZE_DEFAULT`: the shortest list of segments.
const DICTLISTSIZE_DEFAULT: u32 = 10000;
/// `NOISELENGTH`: the length of the guard band after the samples.
pub(crate) const NOISELENGTH: usize = 32;
/// `g_selectivity_default`
const SELECTIVITY_DEFAULT: u32 = 9;
/// `LLIMIT`: the longest match length `ZDICT_analyzePos` counts apart.
const LLIMIT: usize = 64;
/// `MINMATCHLENGTH`: the shortest match `ZDICT_analyzePos` counts.
const MINMATCHLENGTH: usize = 7;

/// `ZDICT_legacy_params_t`: the legacy trainer's parameters
/// ([`train_from_buffer_legacy`]). `Default` is all zeros, libzstd's
/// defaults.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LegacyParams {
    /// `selectivityLevel`: 0 means the default, 9; the larger, the more
    /// segments are selected, and the larger the dictionary.
    pub selectivity_level: u32,
    /// `zParams`: the level the entropy tables are made for, and the ID.
    pub z_params: DictParams,
}

/// `dictItem`: a segment of the samples, at `pos`, of `length` bytes, and
/// what it would save. A list of them keeps its length in the first one's
/// `pos`, and `u32::MAX` in its `savings` (`ZDICT_initDictItem`), which
/// ends the insertion sorts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DictItem {
    /// `pos`
    pub(crate) pos: u32,
    /// `length`
    pub(crate) length: u32,
    /// `savings`
    pub(crate) savings: u32,
}

/// How often each path of the trainer ran, so the tests can check they
/// reach all of them: in `ZDICT_analyzePos`, a trivial repetition skipped,
/// too few repetitions, no segment long enough, and a segment; in
/// `ZDICT_tryMerge`, a tail overlap, a front overlap, and a segment
/// included; in `ZDICT_insertDictItem`, a merge that merges again, and an
/// insertion into a full list.
#[cfg(test)]
pub(crate) static PATH_RUNS: [std::sync::atomic::AtomicUsize; 9] =
    [const { std::sync::atomic::AtomicUsize::new(0) }; 9];

/// Counts a run of the path `which` (see `PATH_RUNS`).
#[cfg(test)]
fn count_path(which: usize) {
    PATH_RUNS[which].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Nothing, outside the tests.
#[cfg(not(test))]
#[inline(always)]
fn count_path(_which: usize) {}

/// `ZDICT_initDictItem`: the head of an empty list.
fn init_dict_item(d: &mut DictItem) {
    d.pos = 1;
    d.length = 0;
    d.savings = u32::MAX;
}

/// `ZDICT_count`: how many bytes from `p_in` on are the same as from
/// `p_match` on.
///
/// Differs from libzstd: libzstd compares a word at a time until one
/// differs, reading on into the guard band and, if the samples repeat it,
/// past it. The port compares a word at a time while both words are in
/// `buffer`, then byte by byte, and stops at its end, which gives the same
/// count where libzstd stays within its buffer.
fn count(buffer: &[u8], p_in: usize, p_match: usize) -> usize {
    let mut n = 0;
    while p_in.max(p_match) + n + 8 <= buffer.len() {
        let diff = read_le64(buffer, p_match + n) ^ read_le64(buffer, p_in + n);
        if diff != 0 {
            return n + diff.trailing_zeros() as usize / 8;
        }
        n += 8;
    }
    while p_in.max(p_match) + n < buffer.len() && buffer[p_in + n] == buffer[p_match + n] {
        n += 1;
    }
    n
}

/// `MEM_read16(b + a) == MEM_read16(b + c)`, false where either is past
/// the end of `b`.
fn same16(b: &[u8], a: usize, c: usize) -> bool {
    matches!((b.get(a..a + 2), b.get(c..c + 2)), (Some(x), Some(y)) if x == y)
}

/// The sorted suffixes, as `ZDICT_trainBuffer_legacy` keeps them: with
/// one more before the first and one after the last, which both lead into
/// the guard band, the position after the samples.
struct Suffixes(Vec<i32>);

impl Suffixes {
    /// `suffix[id]`, for `id` from -1 (`suffix0[0]`) to the number of
    /// samples, or `None` past them, where libzstd reads past its buffer.
    #[inline(always)]
    fn at(&self, id: i64) -> Option<usize> {
        let at = usize::try_from(id + 1).ok()?;
        self.0.get(at).map(|&p| p as usize)
    }
}

/// `doneMarks[at] = 1`, where `at` is within the marks.
///
/// Differs from libzstd: libzstd keeps 16 marks more than the samples,
/// which are never read, and can write past those when samples repeat the
/// guard band. The port keeps one per byte of the samples, and leaves out
/// the marks past them.
#[inline(always)]
fn mark(done_marks: &mut [u8], at: usize) {
    if let Some(m) = done_marks.get_mut(at) {
        *m = 1;
    }
}

/// `ZDICT_analyzePos`: the best segment at the suffix of rank `start`,
/// marking the positions it covers as done; a segment of no length where
/// there is none.
fn analyze_pos(
    done_marks: &mut [u8],
    suffix: &Suffixes,
    start: u32,
    b: &[u8],
    min_ratio: u32,
    _notification_level: u32,
) -> DictItem {
    let mut length_list = [0u32; LLIMIT];
    let mut cumul_length = [0u32; LLIMIT];
    let mut savings = [0u32; LLIMIT];
    let mut max_length = LLIMIT;
    let Some(mut pos) = suffix.at(i64::from(start)) else {
        return DictItem::default();
    };
    let mut start = start;
    let mut end = start;
    let mut solution = DictItem::default();

    // Init.
    mark(done_marks, pos);

    // Trivial repetition cases.
    if same16(b, pos, pos + 2) || same16(b, pos + 1, pos + 3) || same16(b, pos + 2, pos + 4) {
        // Skip and mark the segment. Differs from libzstd: the reads stop at
        // the end of `b`, as unequal.
        let pattern16 = b.get(pos + 4..pos + 6);
        let mut pattern_end = 6;
        while pattern16.is_some() && b.get(pos + pattern_end..pos + pattern_end + 2) == pattern16 {
            pattern_end += 2;
        }
        if matches!((b.get(pos + pattern_end), b.get(pos + pattern_end - 1)), (Some(x), Some(y)) if x == y)
        {
            pattern_end += 1;
        }
        for u in 1..pattern_end {
            mark(done_marks, pos + u);
        }
        count_path(0);
        return solution;
    }

    // The length of the match with the suffix of rank `id`, 0 past the
    // suffixes (where libzstd reads past them, see `Suffixes::at`).
    let length_at = |id: i64| suffix.at(id).map_or(0, |p| count(b, pos, p));

    // Look forward.
    loop {
        end += 1;
        if length_at(i64::from(end)) < MINMATCHLENGTH {
            break;
        }
    }

    // Look backward.
    loop {
        let length = length_at(i64::from(start) - 1);
        // Differs from libzstd: libzstd goes on below the first suffix,
        // when the samples repeat the guard band, which wraps `start`
        // around; the port stops there.
        if length >= MINMATCHLENGTH && start > 0 {
            start -= 1;
        } else {
            break;
        }
    }

    // Exit if not found a minimum number of repetitions.
    if end.wrapping_sub(start) < min_ratio {
        for idx in start..end {
            if let Some(p) = suffix.at(i64::from(idx)) {
                mark(done_marks, p);
            }
        }
        count_path(1);
        return solution;
    }

    {
        let mut refined_start = start;
        let mut refined_end = end;

        let mut mml = MINMATCHLENGTH;
        'refine: loop {
            let mut current_char = 0u8;
            let mut current_count = 0u32;
            let mut current_id = refined_start;
            let mut selected_count = 0u32;
            let mut selected_id = current_id;
            for id in refined_start..refined_end {
                // Differs from libzstd: past the end of `b`, where libzstd
                // reads on when the samples repeat the guard band, the port
                // stops refining.
                let Some(&c) = suffix.at(i64::from(id)).and_then(|p| b.get(p + mml)) else {
                    break 'refine;
                };
                if c != current_char {
                    if current_count > selected_count {
                        selected_count = current_count;
                        selected_id = current_id;
                    }
                    current_id = id;
                    current_char = c;
                    current_count = 0;
                }
                current_count += 1;
            }
            if current_count > selected_count {
                // For the last.
                selected_count = current_count;
                selected_id = current_id;
            }

            if selected_count < min_ratio {
                break;
            }
            refined_start = selected_id;
            refined_end = refined_start + selected_count;
            mml += 1;
        }

        // Evaluate the gain based on the new dictionary.
        start = refined_start;
        let Some(refined_pos) = suffix.at(i64::from(refined_start)) else {
            return solution;
        };
        pos = refined_pos;
        end = start;
        length_list.fill(0);
        let length_at = |id: i64| suffix.at(id).map_or(0, |p| count(b, pos, p));

        // Look forward.
        loop {
            end += 1;
            let length = length_at(i64::from(end)).min(LLIMIT - 1);
            length_list[length] += 1;
            if length < MINMATCHLENGTH {
                break;
            }
        }

        // Look backward.
        let mut length = MINMATCHLENGTH;
        while length >= MINMATCHLENGTH && start > 0 {
            length = length_at(i64::from(start) - 1).min(LLIMIT - 1);
            length_list[length] += 1;
            if length >= MINMATCHLENGTH {
                start -= 1;
            }
        }

        // The largest useful length.
        cumul_length.fill(0);
        cumul_length[max_length - 1] = length_list[max_length - 1];
        for i in (0..max_length - 1).rev() {
            cumul_length[i] = cumul_length[i + 1].wrapping_add(length_list[i]);
        }

        let mut i = LLIMIT - 1;
        while i >= MINMATCHLENGTH {
            if cumul_length[i] >= min_ratio {
                break;
            }
            i -= 1;
        }
        max_length = i;

        // Reduce maxLength in case of final into repetitive data. Differs
        // from libzstd: the reads stop at the ends of `b`, as unequal.
        {
            let mut l = max_length;
            let c = b.get(pos + max_length - 1);
            while l >= 2 && c.is_some() && b.get(pos + l - 2) == c {
                l -= 1;
            }
            max_length = l;
        }
        if max_length < MINMATCHLENGTH {
            // Skip: no long-enough solution.
            count_path(2);
            return solution;
        }

        // Calculate the savings.
        savings[5] = 0;
        for i in MINMATCHLENGTH..=max_length {
            savings[i] = savings[i - 1].wrapping_add(length_list[i].wrapping_mul(i as u32 - 3));
        }

        count_path(3);
        solution.pos = pos as u32;
        solution.length = max_length as u32;
        solution.savings = savings[max_length];

        // Mark the positions done.
        for id in start..end {
            let Some(tested_pos) = suffix.at(i64::from(id)) else {
                continue;
            };
            let length = if tested_pos == pos {
                solution.length as usize
            } else {
                count(b, pos, tested_pos).min(solution.length as usize)
            };
            let p_end = (tested_pos as u32).wrapping_add(length as u32);
            for p in tested_pos as u32..p_end {
                mark(done_marks, p as usize);
            }
        }
    }

    solution
}

/// `isIncluded`: whether the `length` bytes at `in_pos` are the same as
/// those at `container`.
///
/// Differs from libzstd: libzstd relies on the guard band to stop at the
/// end of the samples, and reads past it when they repeat it; the port
/// stops at the end of `buffer`, as unequal.
fn is_included(buffer: &[u8], in_pos: usize, container: usize, length: usize) -> bool {
    let mut u = 0;
    while u < length {
        match (buffer.get(in_pos + u), buffer.get(container + u)) {
            (Some(a), Some(b)) if a == b => u += 1,
            _ => break,
        }
    }
    u == length
}

/// `x / y` as `U32`s, for the lengths of segments, which are never 0.
#[inline(always)]
fn div(x: u32, y: u32) -> u32 {
    x.checked_div(y).unwrap_or(0)
}

/// `ZDICT_tryMerge`: merges `elt` into the segment of `table` it overlaps,
/// other than the one at `elt_nb_to_skip`, if there is one, and returns
/// where that one is then, or 0 when there is none.
fn try_merge(table: &mut [DictItem], mut elt: DictItem, elt_nb_to_skip: u32, buffer: &[u8]) -> u32 {
    let table_size = table[0].pos as usize;
    let elt_end = elt.pos.wrapping_add(elt.length);

    // Tail overlap.
    for u in 1..table_size {
        if u == elt_nb_to_skip as usize {
            continue;
        }
        if table[u].pos > elt.pos && table[u].pos <= elt_end {
            // Overlap, existing > new: append.
            count_path(4);
            let added_length = table[u].pos - elt.pos;
            table[u].length = table[u].length.wrapping_add(added_length);
            table[u].pos = elt.pos;
            // Rough approximations, and a bonus.
            table[u].savings = table[u]
                .savings
                .wrapping_add(div(elt.savings.wrapping_mul(added_length), elt.length));
            table[u].savings = table[u].savings.wrapping_add(elt.length / 8);
            elt = table[u];
            // Sort: improve the rank.
            let mut u = u;
            while u > 1 && table[u - 1].savings < elt.savings {
                table[u] = table[u - 1];
                u -= 1;
            }
            table[u] = elt;
            return u as u32;
        }
    }

    // Front overlap.
    for u in 1..table_size {
        if u == elt_nb_to_skip as usize {
            continue;
        }

        if table[u].pos.wrapping_add(table[u].length) >= elt.pos && table[u].pos < elt.pos {
            // Overlap, existing < new: append.
            count_path(5);
            let added_length =
                (elt_end as i32).wrapping_sub(table[u].pos.wrapping_add(table[u].length) as i32);
            // A rough approximation's bonus.
            table[u].savings = table[u].savings.wrapping_add(elt.length / 8);
            if added_length > 0 {
                // Otherwise, elt is fully included into the existing one.
                table[u].length = table[u].length.wrapping_add(added_length as u32);
                table[u].savings = table[u].savings.wrapping_add(div(
                    elt.savings.wrapping_mul(added_length as u32),
                    elt.length,
                ));
            }
            // Sort: improve the rank.
            elt = table[u];
            let mut u = u;
            while u > 1 && table[u - 1].savings < elt.savings {
                table[u] = table[u - 1];
                u -= 1;
            }
            table[u] = elt;
            return u as u32;
        }

        // Differs from libzstd: the words are read only within `buffer`;
        // libzstd reads past it when the samples repeat the guard band.
        let (at, from) = (table[u].pos as usize, elt.pos as usize + 1);
        if at + 8 <= buffer.len()
            && from + 8 <= buffer.len()
            && read_le64(buffer, at) == read_le64(buffer, from)
            && is_included(buffer, at, from, table[u].length as usize)
        {
            count_path(6);
            // `size_t` arithmetic, on 64 bits as libzstd on 64-bit machines.
            let added_length = (elt.length as i32)
                .wrapping_sub(table[u].length as i32)
                .max(1) as u64;
            table[u].pos = elt.pos;
            table[u].savings = table[u].savings.wrapping_add(
                (u64::from(elt.savings) * added_length)
                    .checked_div(u64::from(elt.length))
                    .unwrap_or(0) as u32,
            );
            table[u].length = elt.length.min(table[u].length.wrapping_add(1));
            return u as u32;
        }
    }

    0
}

/// `ZDICT_removeDictItem`: removes the segment at `id` from the list.
fn remove_dict_item(table: &mut [DictItem], id: u32) {
    // Convention: table[0].pos stores the number of elements.
    let max = table[0].pos;
    if id == 0 {
        // Protection, should never happen.
        return;
    }
    for u in id..max.saturating_sub(1) {
        table[u as usize] = table[u as usize + 1];
    }
    table[0].pos -= 1;
}

/// `ZDICT_insertDictItem`: adds `elt` to the list, which holds at most
/// `max_size`, merged with the segments it overlaps, or in its place by
/// its savings.
fn insert_dict_item(table: &mut [DictItem], max_size: u32, elt: DictItem, buffer: &[u8]) {
    // Merge if possible.
    let mut merge_id = try_merge(table, elt, 0, buffer);
    if merge_id != 0 {
        let mut new_merge = 1;
        while new_merge != 0 {
            new_merge = try_merge(table, table[merge_id as usize], merge_id, buffer);
            if new_merge != 0 {
                count_path(7);
                remove_dict_item(table, merge_id);
            }
            merge_id = new_merge;
        }
        return;
    }

    // Insert.
    let mut next_elt = table[0].pos;
    if next_elt >= max_size {
        count_path(8);
        next_elt = max_size - 1;
    }
    let mut current = next_elt as usize - 1;
    // The head's savings, u32::MAX, end the loop.
    while table[current].savings < elt.savings {
        table[current + 1] = table[current];
        current -= 1;
    }
    table[current + 1] = elt;
    table[0].pos = next_elt + 1;
}

/// `ZDICT_dictSize`: the total length of the segments of the list.
fn dict_size(dict_list: &[DictItem]) -> u32 {
    let mut dict_size = 0u32;
    for u in 1..dict_list[0].pos as usize {
        dict_size = dict_size.wrapping_add(dict_list[u].length);
    }
    dict_size
}

/// `malloc` of `len` cells, as a vector of `fill`: `MemoryAllocation`
/// where there is not the room.
fn allocate<T: Clone>(len: usize, fill: T) -> Result<Vec<T>> {
    let mut v = Vec::new();
    if v.try_reserve_exact(len).is_err() {
        return error!(MemoryAllocation);
    }
    v.resize(len, fill);
    Ok(v)
}

/// `ZDICT_trainBuffer_legacy`: finds the segments of the first
/// `buffer_size` bytes of `buffer`, the samples followed by the guard
/// band, that repeat at least `min_ratio` times, into `dict_list`, of
/// `dict_list_size`.
///
/// Differs from libzstd: libzstd also works out where each sample starts
/// (`filePos`), which it does not use.
#[allow(clippy::too_many_arguments)]
fn train_buffer_legacy(
    dict_list: &mut [DictItem],
    dict_list_size: u32,
    buffer: &[u8],
    mut buffer_size: usize,
    file_sizes: &[usize],
    mut nb_files: u32,
    mut min_ratio: u32,
    notification_level: u32,
) -> Result<usize> {
    let mut suffix0 = allocate(buffer_size + 2, 0i32)?;
    let mut reverse_suffix = allocate(buffer_size, 0u32)?;
    let mut done_marks = allocate(buffer_size, 0u8)?;

    // Init.
    if min_ratio < MINRATIO {
        min_ratio = MINRATIO;
    }

    // Limit the sample set size (divsufsort limitation). The sizes add up
    // to `buffer_size`, so that the checks never fail.
    while buffer_size > ZDICT_MAX_SAMPLES_SIZE {
        let Some(last) = nb_files.checked_sub(1) else {
            return error!(Generic);
        };
        nb_files = last;
        let Some(rest) = file_sizes
            .get(last as usize)
            .and_then(|&size| buffer_size.checked_sub(size))
        else {
            return error!(Generic);
        };
        buffer_size = rest;
    }

    // Sort.
    let Some(samples) = buffer.get(..buffer_size) else {
        return error!(Generic);
    };
    if divsufsort(samples, &mut suffix0[1..]).is_err() {
        return error!(Generic);
    }
    // Both lead into the noise.
    suffix0[buffer_size + 1] = buffer_size as i32;
    suffix0[0] = buffer_size as i32;
    let suffix = Suffixes(suffix0);
    // Build the reverse suffix sort.
    for pos in 0..buffer_size {
        reverse_suffix[suffix.0[pos + 1] as usize] = pos as u32;
    }

    let mut cursor = 0usize;
    while cursor < buffer_size {
        if done_marks[cursor] != 0 {
            cursor += 1;
            continue;
        }
        let solution = analyze_pos(
            &mut done_marks,
            &suffix,
            reverse_suffix[cursor],
            buffer,
            min_ratio,
            notification_level,
        );
        if solution.length == 0 {
            cursor += 1;
            continue;
        }
        insert_dict_item(dict_list, dict_list_size, solution, buffer);
        cursor += solution.length as usize;
    }
    Ok(0)
}

/// `ZDICT_fillNoise`: the guard band.
pub(crate) fn fill_noise(buffer: &mut [u8]) {
    let prime1: u32 = 2_654_435_761;
    let prime2: u32 = 2_246_822_519;
    let mut acc = prime1;
    for byte in buffer {
        acc = acc.wrapping_mul(prime2);
        *byte = (acc >> 21) as u8;
    }
}

/// `ZDICT_totalSampleSize`
fn total_sample_size(file_sizes: &[usize]) -> usize {
    file_sizes
        .iter()
        .fold(0, |total, &size| total.wrapping_add(size))
}

/// The first part of `ZDICT_trainFromBuffer_unsafe_legacy`: its checks, for
/// a dictionary of `max_dict_size`, and the list of segments that
/// `ZDICT_trainBuffer_legacy` finds in the samples, the guard band after
/// them in `samples_buffer`. The list is as libzstd keeps it, its length in
/// the first one.
///
/// Differs from libzstd: a `samples_buffer` shorter than the samples'
/// sizes fails with `SrcSizeWrong`, where libzstd reads past it.
pub(crate) fn legacy_segments(
    max_dict_size: usize,
    samples_buffer: &[u8],
    samples_sizes: &[usize],
    params: &LegacyParams,
) -> Result<Vec<DictItem>> {
    let Ok(nb_samples) = u32::try_from(samples_sizes.len()) else {
        return error!(SrcSizeWrong);
    };
    let dict_list_size = DICTLISTSIZE_DEFAULT
        .max(nb_samples)
        .max((max_dict_size / 16) as u32);
    let selectivity = if params.selectivity_level == 0 {
        SELECTIVITY_DEFAULT
    } else {
        params.selectivity_level
    };
    let min_rep = if selectivity > 30 {
        MINRATIO
    } else {
        nb_samples >> selectivity
    };
    let samples_buff_size = total_sample_size(samples_sizes);
    let notification_level = params.z_params.notification_level;

    // Checks.
    let mut dict_list = allocate(dict_list_size as usize, DictItem::default())?;
    if max_dict_size < ZDICT_DICTSIZE_MIN {
        // The requested dictionary size is too small.
        return error!(DstSizeTooSmall);
    }
    if samples_buff_size < ZDICT_MIN_SAMPLES_SIZE {
        // Not enough source to create a dictionary.
        return error!(DictionaryCreationFailed);
    }
    if samples_buffer.len() < samples_buff_size {
        return error!(SrcSizeWrong);
    }

    // Init.
    init_dict_item(&mut dict_list[0]);

    // Build the dictionary. libzstd leaves out its result: on a failure,
    // the list stays empty.
    let _ = train_buffer_legacy(
        &mut dict_list,
        dict_list_size,
        samples_buffer,
        samples_buff_size,
        samples_sizes,
        nb_samples,
        min_rep,
        notification_level,
    );

    // Display the best matches: libzstd checks them as it does.
    if notification_level >= 3 {
        let nb = dict_list[0].pos.min(25) as usize;
        for item in &dict_list[1..nb.max(1)] {
            if item.pos as usize > samples_buff_size
                || item.pos.wrapping_add(item.length) as usize > samples_buff_size
            {
                // Should never happen.
                return error!(Generic);
            }
        }
    }

    Ok(dict_list)
}

/// The second part of `ZDICT_trainFromBuffer_unsafe_legacy`, up to the
/// entropy tables: the best segments of `dict_list` that fit in
/// `dict_buffer`, which the list keeps (its length in the first one), with
/// their bytes from `samples_buffer` at the end of `dict_buffer`, the best
/// last. Returns the size of that content.
pub(crate) fn legacy_content(
    dict_list: &mut [DictItem],
    dict_buffer: &mut [u8],
    samples_buffer: &[u8],
) -> Result<usize> {
    let max_dict_size = dict_buffer.len();
    let target_dict_size = max_dict_size;

    // Create the dictionary.
    let dict_content_size = dict_size(dict_list);
    if (dict_content_size as usize) < ZDICT_CONTENTSIZE_MIN {
        // The dictionary content is too small.
        return error!(DictionaryCreationFailed);
    }

    // Limit the dictionary size.
    let max = dict_list[0].pos;
    let mut current_size = 0u32;
    let mut n = 1;
    while n < max {
        current_size = current_size.wrapping_add(dict_list[n as usize].length);
        if current_size as usize > target_dict_size {
            current_size = current_size.wrapping_sub(dict_list[n as usize].length);
            break;
        }
        n += 1;
    }
    dict_list[0].pos = n;
    let dict_content_size = current_size as usize;

    // Build the dictionary content.
    let mut ptr = max_dict_size;
    for item in &dict_list[1..n as usize] {
        let l = item.length as usize;
        let pos = item.pos as usize;
        let Some(at) = ptr.checked_sub(l) else {
            // Should not happen.
            return error!(Generic);
        };
        ptr = at;
        // Differs from libzstd: a segment past `samples_buffer`, which
        // libzstd would copy from past it, fails as above.
        let Some(segment) = samples_buffer.get(pos..pos + l) else {
            return error!(Generic);
        };
        dict_buffer[ptr..ptr + l].copy_from_slice(segment);
    }
    Ok(dict_content_size)
}

/// `ZDICT_trainFromBuffer_unsafe_legacy`: a dictionary for the samples into
/// `dict_buffer`, whose size is the largest it can be; returns its size.
/// The samples are followed by the guard band in `samples_buffer`
/// ([`train_from_buffer_legacy`] adds it).
pub(crate) fn train_from_buffer_unsafe_legacy(
    dict_buffer: &mut [u8],
    samples_buffer: &[u8],
    samples_sizes: &[usize],
    params: &LegacyParams,
) -> Result<usize> {
    let mut dict_list = legacy_segments(dict_buffer.len(), samples_buffer, samples_sizes, params)?;
    let dict_content_size = legacy_content(&mut dict_list, dict_buffer, samples_buffer)?;
    zdict_add_entropy_tables_from_buffer_advanced(
        dict_buffer,
        dict_content_size,
        samples_buffer,
        samples_sizes,
        params.z_params,
    )
}

/// `ZDICT_trainFromBuffer_legacy`: a dictionary for the samples, one after
/// the other in `samples_buffer`, of the sizes `samples_sizes`, into
/// `dict_buffer`, whose size is the largest it can be; returns its size,
/// or 0 when there are too few samples to train on.
///
/// Differs from libzstd: a `samples_buffer` shorter than the samples'
/// sizes fails with `SrcSizeWrong`, where libzstd reads past it.
pub fn train_from_buffer_legacy(
    dict_buffer: &mut [u8],
    samples_buffer: &[u8],
    samples_sizes: &[usize],
    params: LegacyParams,
) -> Result<usize> {
    let s_buff_size = total_sample_size(samples_sizes);
    if s_buff_size < ZDICT_MIN_SAMPLES_SIZE {
        // Not enough content: no dictionary.
        return Ok(0);
    }
    let Some(samples) = samples_buffer.get(..s_buff_size) else {
        return error!(SrcSizeWrong);
    };
    let mut new_buff = allocate(s_buff_size + NOISELENGTH, 0u8)?;
    new_buff[..s_buff_size].copy_from_slice(samples);
    // The guard band, for the end of buffer condition.
    fill_noise(&mut new_buff[s_buff_size..]);
    train_from_buffer_unsafe_legacy(dict_buffer, &new_buff, samples_sizes, &params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noise_is_libzstd_s() {
        // The first bytes of ZDICT_fillNoise's band, worked out by hand:
        // acc = 2654435761 * 2246822519^k mod 2^32, then acc >> 21.
        let mut band = [0u8; 4];
        fill_noise(&mut band);
        let mut acc = 2_654_435_761u32;
        for byte in band {
            acc = acc.wrapping_mul(2_246_822_519);
            assert_eq!(byte, (acc >> 21) as u8);
        }
    }

    #[test]
    fn count_stops_at_the_end() {
        let buffer = b"abcdefghabcdefghabcdefghXabcdefgh";
        assert_eq!(count(buffer, 0, 8), 16);
        assert_eq!(count(buffer, 0, 25), 8);
        assert_eq!(count(buffer, 3, 3), buffer.len() - 3);
        assert_eq!(count(buffer, 1, 0), 0);
    }

    #[test]
    fn trains_or_fails_as_its_samples_allow() {
        let samples: Vec<u8> = (0..4000u32).map(|i| (i % 7 * 31 + i / 500) as u8).collect();
        let sizes = vec![400; 10];
        let mut dict = vec![0u8; 1024];
        let params = LegacyParams::default();
        let size = train_from_buffer_legacy(&mut dict, &samples, &sizes, params).expect("trains");
        assert!(crate::zstd::get_dict_id(&dict[..size]) != 0);
        assert_eq!(
            train_from_buffer_legacy(&mut dict, &samples[..100], &[100], params),
            Ok(0)
        );
        assert_eq!(
            train_from_buffer_legacy(&mut dict, &samples[..100], &[600], params)
                .map_err(|e| e.code()),
            Err(crate::zstd::ErrorCode::SrcSizeWrong)
        );
    }

    /// Samples that repeat the guard band, where libzstd reads past its
    /// buffers: the port stops at their ends, without a panic, and with no
    /// band at all too.
    #[test]
    fn samples_that_repeat_the_guard_band() {
        let mut band = [0u8; NOISELENGTH];
        fill_noise(&mut band);
        let mut rng = crate::zstd::oracle::Rng::new(0xBA5D);
        for round in 0..40 {
            let mut samples = Vec::new();
            while samples.len() < 3000 + round * 100 {
                match rng.range(0, 3) {
                    0 => samples.extend_from_slice(&band),
                    1 => samples.extend_from_slice(&band[..rng.range(1, 31) as usize]),
                    2 => samples.extend_from_slice(&band[rng.range(1, 31) as usize..]),
                    _ => {
                        let len = rng.range(0, 9) as usize;
                        samples.extend(rng.bytes(len));
                    }
                }
            }
            // The band itself at the very end, as long as it can be.
            samples.extend_from_slice(&band);
            let sizes: Vec<usize> = samples.chunks(97).map(<[u8]>::len).collect();
            let params = LegacyParams {
                selectivity_level: rng.range(0, 12) as u32,
                ..LegacyParams::default()
            };
            let total = samples.len();
            for with_band in [true, false] {
                let mut buffer = samples.clone();
                if with_band {
                    buffer.extend_from_slice(&band);
                }
                let mut dict = vec![0u8; 2048];
                if let Ok(mut list) = legacy_segments(dict.len(), &buffer, &sizes, &params) {
                    for item in &list[1..list[0].pos as usize] {
                        assert!(item.length > 0);
                        assert!(item.pos as usize <= total + NOISELENGTH);
                    }
                    let _ = legacy_content(&mut list, &mut dict, &buffer);
                }
            }
        }
    }
}
