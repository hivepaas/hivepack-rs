//! The `greedy`, `lazy`, `lazy2` and `btlazy2` strategies: port of
//! `compress/zstd_lazy.c`: the parser they share, the hash chain match
//! finder, the row match finder, and `btlazy2`'s binary tree; without a
//! dictionary, with the window's older segment (`extDict`), and with an
//! attached `CDict` (`dictMatchState`, and `dedicatedDictSearch` for a
//! `CDict` made with `ZSTD_c_enableDedicatedDictSearch`).
//!
//! Positions are indices into `src`, the buffer the window's prefix is in,
//! and `dict`, the one its older segment is in; the tables hold window
//! indices, `position + window.base` (or `window.dict_base`). An attached
//! `CDict`'s tables hold indices of its own window, over its content (see
//! [`DictMatchState`]).

use crate::zstd::common::bits::highbit32;
use crate::zstd::common::prefetch::{PREFETCH, prefetch_l1};
use crate::zstd::common::zstd_internal::ZSTD_REP_NUM;
use crate::zstd::compress::zstd_compress_internal::{
    DictMatchState, K_SEARCH_STRENGTH, MatchState, REPCODE1_TO_OFFBASE, SeqStore,
    ZSTD_DEDICATED_DICT_SEARCH, ZSTD_DICT_MATCH_STATE, ZSTD_DUBT_UNSORTED_MARK, ZSTD_EXT_DICT,
    ZSTD_NO_DICT, ZSTD_ROW_HASH_CACHE_SIZE, mem_read32, offset_to_offbase, zstd_count,
    zstd_count_2segments, zstd_hash_ptr, zstd_hash_ptr_salted, zstd_index_overlap_check,
};

/// `kLazySkippingStep`: past steps this long over input without matches,
/// the tables get only the positions searched.
const K_LAZY_SKIPPING_STEP: usize = 8;

/// `searchMethod_e`, as the const parameter of the parser.
pub(crate) const SEARCH_HASH_CHAIN: u8 = 0;
pub(crate) const SEARCH_ROW_HASH: u8 = 2;

/// `ZSTD_dictMode_e`, as the const parameter of the parser and the search
/// functions: no dictionary, the window's older segment, an attached
/// `CDict`'s tables, or an attached `CDict`'s tables laid out for the
/// dedicated dictionary search.
pub(crate) const NO_DICT: u8 = ZSTD_NO_DICT;
pub(crate) const EXT_DICT: u8 = ZSTD_EXT_DICT;
pub(crate) const DICT_MATCH_STATE: u8 = ZSTD_DICT_MATCH_STATE;
pub(crate) const DEDICATED_DICT_SEARCH: u8 = ZSTD_DEDICATED_DICT_SEARCH;

/// `ZSTD_LAZY_DDSS_BUCKET_LOG`: a `CDict` with the dedicated dictionary
/// search has buckets of `1 << ZSTD_LAZY_DDSS_BUCKET_LOG` entries in its
/// hash table, rather than one entry per hash: the latest positions of the
/// hash, and where the rest of its chain is in the chain table.
pub(crate) const ZSTD_LAZY_DDSS_BUCKET_LOG: u32 = 2;

/// The offset base the parser sets before each search, 999999999: what
/// `ZSTD_searchMax` gives when it finds no match, with a length under 4.
/// The binary tree weighs its first match against it.
const NO_OFFBASE: u32 = 999_999_999;

/// `OFFBASE_IS_OFFSET`
#[inline(always)]
fn offbase_is_offset(off_base: u32) -> bool {
    off_base > ZSTD_REP_NUM as u32
}

/// `OFFBASE_TO_OFFSET`
#[inline(always)]
fn offbase_to_offset(off_base: u32) -> u32 {
    debug_assert!(offbase_is_offset(off_base));
    off_base - ZSTD_REP_NUM as u32
}

// ---------------------------------------------------------------------------
// Binary tree
//
// `btlazy2`'s match finder, the deferred-update binary tree (DUBT). The
// chain table holds two entries per position, `bt[2 * (i & bt_mask)]` and
// the one after, for the `1 << (chain_log - 1)` positions before the
// current one. A position is first inserted unsorted, as in a hash chain:
// its first entry is the previous position of its hash, its second
// `ZSTD_DUBT_UNSORTED_MARK`. It is sorted when a search reaches it: its
// entries then point to the positions smaller and larger than it, in the
// order of the bytes that follow them.

/// `search_binaryTree`, the search method of the parser.
pub(crate) const SEARCH_BINARY_TREE: u8 = 1;

/// libzstd's `dummy32`: where a search that stops early ends the side it
/// stopped on.
///
/// Differs from libzstd: the write there is left out. Nothing reads it, so
/// the tree is the same.
const DUMMY32: usize = usize::MAX;

/// `ZSTD_updateDUBT`: inserts the positions from `next_to_update` up to
/// `ip`, not included, into the hash table and the tree, unsorted. The
/// positions are in the prefix.
#[inline(always)]
fn update_dubt<const MLS: u32>(ms: &mut MatchState, src: &[u8], ip: usize) {
    let hash_log = ms.c_params.hash_log;
    let bt_mask = (1u32 << (ms.c_params.chain_log - 1)) - 1;
    let base = ms.window.base;
    let target = ms.window.index(ip);
    let mut idx = ms.next_to_update;
    debug_assert!(idx >= ms.window.dict_limit);

    while idx < target {
        let h = zstd_hash_ptr(src, (i64::from(idx) - base) as usize, hash_log, MLS);
        let match_index = ms.hash_table[h];
        let next_candidate = 2 * (idx & bt_mask) as usize;
        ms.hash_table[h] = idx;
        // Linked as in a hash chain, and marked unsorted.
        ms.chain_table[next_candidate] = match_index;
        ms.chain_table[next_candidate + 1] = ZSTD_DUBT_UNSORTED_MARK;
        idx += 1;
    }
    ms.next_to_update = target;
}

/// `ZSTD_insertDUBT1`: sorts `curr`, inserted but unsorted, into the tree,
/// comparing at most `nb_compares` positions, down to `bt_low`. Its bytes
/// end at `input_end` of `src` in the prefix. With `DICT_MODE`
/// [`ZSTD_EXT_DICT`], `curr` and the positions it is compared with may be
/// in the older segment, `dict`, where its bytes end at the segment's end;
/// the tree holds no position of an attached `CDict`.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn insert_dubt1<const DICT_MODE: u8>(
    ms: &mut MatchState,
    src: &[u8],
    dict: &[u8],
    curr: u32,
    input_end: usize,
    mut nb_compares: u32,
    bt_low: u32,
) {
    let c_params = ms.c_params;
    let bt_mask = (1u32 << (c_params.chain_log - 1)) - 1;
    let base = ms.window.base;
    let dict_base = ms.window.dict_base;
    let dict_limit = ms.window.dict_limit;
    let prefix_start = (i64::from(dict_limit) - base) as usize;
    let dict_end = (i64::from(dict_limit) - dict_base) as usize;
    // Where `curr` is: its segment, the index of the segment's first byte,
    // and where the bytes after `curr` end.
    let ext = DICT_MODE == ZSTD_EXT_DICT;
    let (ibuf, ibase, iend) = if !ext || curr >= dict_limit {
        (src, base, input_end)
    } else {
        (dict, dict_base, dict_end)
    };
    let ip = (i64::from(curr) - ibase) as usize;
    let window_valid = ms.window.low_limit;
    let max_distance = 1u32 << c_params.window_log;
    let window_low = if curr.wrapping_sub(window_valid) > max_distance {
        curr - max_distance
    } else {
        window_valid
    };
    let bt = &mut ms.chain_table;
    let mut common_length_smaller = 0;
    let mut common_length_larger = 0;
    let mut smaller_ptr = 2 * (curr & bt_mask) as usize;
    let mut larger_ptr = smaller_ptr + 1;
    // `curr` is unsorted: its first entry leads to the next candidate,
    // sorted; its second holds the previous unsorted one, already saved,
    // and is written over.
    let mut match_index = bt[smaller_ptr];
    debug_assert!(curr >= bt_low);
    debug_assert!(ip < iend);

    while nb_compares > 0 && match_index > window_low {
        let next_ptr = 2 * (match_index & bt_mask) as usize;
        // The bytes it has in common with `curr` at least.
        let mut match_length = common_length_smaller.min(common_length_larger);
        debug_assert!(match_index < curr);

        // The candidate's segment, and the index of its first byte, for
        // the byte after the common run.
        let (mbuf, mbase) = if !ext
            || match_index as usize + match_length >= dict_limit as usize
            || curr < dict_limit
        {
            // Both in one segment: the prefix (where a candidate of the
            // older segment is from its byte `match_length` on), or the
            // older one.
            //
            // Differs from libzstd: the candidate is read in `curr`'s
            // segment, where libzstd picks the prefix when the run reaches
            // it. The same: with `curr` in the older segment, the common
            // run ends before the segment's end, as `curr`'s bytes do, and
            // the candidate is before `curr`.
            debug_assert!(
                !ext || curr >= dict_limit
                    || match_index as usize + match_length < dict_limit as usize
            );
            let m = (i64::from(match_index) + match_length as i64 - ibase) as usize;
            match_length += zstd_count(ibuf, ip + match_length, m, iend);
            (ibuf, ibase)
        } else {
            // A candidate of the older segment, `curr` in the prefix.
            let m = (i64::from(match_index) - dict_base) as usize;
            match_length += zstd_count_2segments(
                src,
                ip + match_length,
                dict,
                m + match_length,
                iend,
                dict_end,
                prefix_start,
            );
            if match_index as usize + match_length >= dict_limit as usize {
                // The match runs on into the prefix: its next byte is
                // there.
                (src, base)
            } else {
                (dict, dict_base)
            }
        };

        if ip + match_length == iend {
            // Equal up to the end: no way to know if smaller or larger.
            // Dropped, to keep the tree consistent: a bit less compression,
            // where other ways can corrupt the tree.
            break;
        }

        let match_byte = mbuf[(i64::from(match_index) + match_length as i64 - mbase) as usize];
        if match_byte < ibuf[ip + match_length] {
            // The candidate is smaller than `curr`.
            bt[smaller_ptr] = match_index;
            // Every smaller one has at least this in common.
            common_length_smaller = match_length;
            if match_index <= bt_low {
                // Beyond the tree's size: stop.
                smaller_ptr = DUMMY32;
                break;
            }
            // The next one is larger than the candidate.
            smaller_ptr = next_ptr + 1;
            match_index = bt[next_ptr + 1];
        } else {
            // The candidate is larger than `curr`.
            bt[larger_ptr] = match_index;
            common_length_larger = match_length;
            if match_index <= bt_low {
                // Beyond the tree's size: stop.
                larger_ptr = DUMMY32;
                break;
            }
            larger_ptr = next_ptr;
            match_index = bt[next_ptr];
        }
        nb_compares -= 1;
    }

    // *smallerPtr = *largerPtr = 0
    for ptr in [smaller_ptr, larger_ptr] {
        if ptr != DUMMY32 {
            bt[ptr] = 0;
        }
    }
}

/// `ZSTD_DUBT_findBetterDictMatch`: the search of the binary tree goes on
/// in the attached `CDict`'s, `dms`, for a match at `ip` longer than
/// `best_length`, the longest found in the frame's, with at most
/// `nb_compares` comparisons, the rest of the search's. A match there is
/// weighed as in the frame's tree against `off_base`, the best so far,
/// which it then replaces. Returns the best length.
///
/// The `CDict`'s tree is sorted: its content was inserted with
/// `ZSTD_updateTree`, as the optimal parser's are. It is read only. Its
/// indices, from its `low_limit` to its `next_src`, are the frame's less
/// `dict_index_delta`: the frame's window starts where the `CDict`'s ends.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn dubt_find_better_dict_match<const MLS: u32>(
    ms: &MatchState,
    dms: DictMatchState<'_>,
    src: &[u8],
    ip: usize,
    iend: usize,
    off_base: &mut u32,
    mut best_length: usize,
    mut nb_compares: u32,
) -> usize {
    let dms_c_params = dms.ms.c_params;
    let h = zstd_hash_ptr(src, ip, dms_c_params.hash_log, MLS);
    let mut dict_match_index = dms.ms.hash_table[h];

    let base = ms.window.base;
    let prefix_start = (i64::from(ms.window.dict_limit) - base) as usize;
    let curr = ms.window.index(ip);
    let dict_base = dms.ms.window.base;
    let content = dms.content;
    // The content's end, in it and as an index.
    let dict_end = (dms.ms.window.next_src - dict_base) as usize;
    let dict_high_limit = dms.ms.window.next_src as u32;
    let dict_low_limit = dms.ms.window.low_limit;
    let dict_index_delta = ms.window.low_limit.wrapping_sub(dict_high_limit);

    let dict_bt = &dms.ms.chain_table;
    let bt_mask = (1u32 << (dms_c_params.chain_log - 1)) - 1;
    let bt_low = if bt_mask >= dict_high_limit - dict_low_limit {
        dict_low_limit
    } else {
        dict_high_limit - bt_mask
    };

    let mut common_length_smaller = 0;
    let mut common_length_larger = 0;

    while nb_compares > 0 && dict_match_index > dict_low_limit {
        let next_ptr = 2 * (dict_match_index & bt_mask) as usize;
        // The bytes it has in common with `ip` at least.
        let mut match_length = common_length_smaller.min(common_length_larger);
        let m = (i64::from(dict_match_index) - dict_base) as usize;
        // Past the content's end, on into the frame's prefix.
        match_length += zstd_count_2segments(
            src,
            ip + match_length,
            content,
            m + match_length,
            iend,
            dict_end,
            prefix_start,
        );

        if match_length > best_length {
            let match_index = dict_match_index.wrapping_add(dict_index_delta);
            // Longer, unless its offset costs more than the bytes gained;
            // the best so far weighs as `off_base + 1` here.
            if 4 * (match_length - best_length) as i32
                > highbit32(curr - match_index + 1) as i32 - highbit32(*off_base + 1) as i32
            {
                best_length = match_length;
                *off_base = offset_to_offbase(curr - match_index);
            }
            if ip + match_length == iend {
                // Equal up to the end: no way to know if smaller or
                // larger. Dropped.
                break;
            }
        }

        // The byte after the common run: in the prefix, when the run went
        // past the content.
        let match_byte = if dict_match_index as usize + match_length >= dict_high_limit as usize {
            let at =
                i64::from(dict_match_index.wrapping_add(dict_index_delta)) + match_length as i64;
            src[(at - base) as usize]
        } else {
            content[m + match_length]
        };
        if match_byte < src[ip + match_length] {
            // The candidate is smaller than `ip`.
            if dict_match_index <= bt_low {
                // Beyond the tree's size: stop.
                break;
            }
            // Every smaller one has at least this in common.
            common_length_smaller = match_length;
            // The next one is larger than the candidate.
            dict_match_index = dict_bt[next_ptr + 1];
        } else {
            // The candidate is larger than `ip`.
            if dict_match_index <= bt_low {
                // Beyond the tree's size: stop.
                break;
            }
            common_length_larger = match_length;
            dict_match_index = dict_bt[next_ptr];
        }
        nb_compares -= 1;
    }

    best_length
}

/// `ZSTD_DUBT_findBestMatch`: sorts the unsorted positions of `ip`'s hash
/// (up to `1 << search_log` of them, the oldest first), then inserts `ip`
/// into the tree, sorted, and returns the best match the way down gave, up
/// to `iend`, and its offset base. With `DICT_MODE` [`ZSTD_EXT_DICT`],
/// candidates below the prefix are in `dict`; with
/// [`ZSTD_DICT_MATCH_STATE`], the comparisons left go on in the tree of the
/// attached `CDict`, `dms` ([`dubt_find_better_dict_match`]).
#[allow(clippy::too_many_lines)]
#[inline(always)]
fn dubt_find_best_match<const MLS: u32, const DICT_MODE: u8>(
    ms: &mut MatchState,
    src: &[u8],
    dict: &[u8],
    dms: Option<DictMatchState<'_>>,
    ip: usize,
    iend: usize,
) -> (usize, u32) {
    debug_assert!(DICT_MODE != ZSTD_DEDICATED_DICT_SEARCH);
    let ext = DICT_MODE == ZSTD_EXT_DICT;
    let c_params = ms.c_params;
    let h = zstd_hash_ptr(src, ip, c_params.hash_log, MLS);
    let mut match_index = ms.hash_table[h];

    let base = ms.window.base;
    let curr = ms.window.index(ip);
    let window_low = ms.lowest_match_index(curr, c_params.window_log);

    let bt_mask = (1u32 << (c_params.chain_log - 1)) - 1;
    // The oldest position the tree holds, or 0.
    let bt_low = curr.saturating_sub(bt_mask);
    let unsort_limit = bt_low.max(window_low);

    let mut nb_compares = 1u32 << c_params.search_log;
    let mut nb_candidates = nb_compares;
    let mut previous_candidate = 0;
    debug_assert!(ip + 8 <= iend);

    // The end of the list of unsorted candidates: on the way, their marks
    // become a chain back up.
    {
        let bt = &mut ms.chain_table;
        let mut next_candidate = 2 * (match_index & bt_mask) as usize;
        let mut unsorted_mark = next_candidate + 1;
        while match_index > unsort_limit
            && bt[unsorted_mark] == ZSTD_DUBT_UNSORTED_MARK
            && nb_candidates > 1
        {
            bt[unsorted_mark] = previous_candidate;
            previous_candidate = match_index;
            match_index = bt[next_candidate];
            next_candidate = 2 * (match_index & bt_mask) as usize;
            unsorted_mark = next_candidate + 1;
            nb_candidates -= 1;
        }

        // The last candidate, if still unsorted, is cut off: worse
        // compression, but faster.
        if match_index > unsort_limit && bt[unsorted_mark] == ZSTD_DUBT_UNSORTED_MARK {
            bt[unsorted_mark] = 0;
            bt[next_candidate] = 0;
        }
    }

    // Sorts the candidates stacked, the oldest first, back up the chain;
    // it ends at 0.
    match_index = previous_candidate;
    while match_index != 0 {
        let next_candidate_idx = ms.chain_table[2 * (match_index & bt_mask) as usize + 1];
        insert_dubt1::<DICT_MODE>(
            ms,
            src,
            dict,
            match_index,
            iend,
            nb_candidates,
            unsort_limit,
        );
        match_index = next_candidate_idx;
        nb_candidates += 1;
    }

    // The longest match.
    let dict_base = ms.window.dict_base;
    let dict_limit = ms.window.dict_limit;
    let dict_end = (i64::from(dict_limit) - dict_base) as usize;
    let prefix_start = (i64::from(dict_limit) - base) as usize;
    let mut common_length_smaller = 0;
    let mut common_length_larger = 0;
    let mut smaller_ptr = 2 * (curr & bt_mask) as usize;
    let mut larger_ptr = smaller_ptr + 1;
    let mut match_end_idx = curr + 8 + 1;
    let mut best_length = 0;
    // What the parser's offset base is before the search: the first match
    // is weighed against it.
    let mut off_base = NO_OFFBASE;

    match_index = ms.hash_table[h];
    ms.hash_table[h] = curr;

    let bt = &mut ms.chain_table;
    while nb_compares > 0 && match_index > window_low {
        let next_ptr = 2 * (match_index & bt_mask) as usize;
        // The bytes it has in common with `ip` at least.
        let mut match_length = common_length_smaller.min(common_length_larger);

        // The candidate's segment, and the index of its first byte, for
        // the byte after the common run.
        let (mbuf, mbase) = if !ext || match_index as usize + match_length >= dict_limit as usize {
            let m = (i64::from(match_index) + match_length as i64 - base) as usize;
            match_length += zstd_count(src, ip + match_length, m, iend);
            (src, base)
        } else {
            let m = (i64::from(match_index) - dict_base) as usize;
            match_length += zstd_count_2segments(
                src,
                ip + match_length,
                dict,
                m + match_length,
                iend,
                dict_end,
                prefix_start,
            );
            if match_index as usize + match_length >= dict_limit as usize {
                // The match runs on into the prefix: its next byte is
                // there.
                (src, base)
            } else {
                (dict, dict_base)
            }
        };

        if match_length > best_length {
            if match_length > (match_end_idx - match_index) as usize {
                match_end_idx = match_index + match_length as u32;
            }
            // Longer, unless its offset costs more than the bytes gained.
            if 4 * (match_length - best_length) as i32
                > highbit32(curr - match_index + 1) as i32 - highbit32(off_base) as i32
            {
                best_length = match_length;
                off_base = offset_to_offbase(curr - match_index);
            }
            if ip + match_length == iend {
                // Equal up to the end: no way to know if smaller or
                // larger. Dropped, to keep the tree consistent; nor is an
                // attached dictionary searched.
                if DICT_MODE == ZSTD_DICT_MATCH_STATE {
                    nb_compares = 0;
                }
                break;
            }
        }

        let match_byte = mbuf[(i64::from(match_index) + match_length as i64 - mbase) as usize];
        if match_byte < src[ip + match_length] {
            // The candidate is smaller than `ip`.
            bt[smaller_ptr] = match_index;
            // Every smaller one has at least this in common.
            common_length_smaller = match_length;
            if match_index <= bt_low {
                // Beyond the tree's size: stop.
                smaller_ptr = DUMMY32;
                break;
            }
            // The next one is larger than the candidate.
            smaller_ptr = next_ptr + 1;
            match_index = bt[next_ptr + 1];
        } else {
            // The candidate is larger than `ip`.
            bt[larger_ptr] = match_index;
            common_length_larger = match_length;
            if match_index <= bt_low {
                // Beyond the tree's size: stop.
                larger_ptr = DUMMY32;
                break;
            }
            larger_ptr = next_ptr;
            match_index = bt[next_ptr];
        }
        nb_compares -= 1;
    }

    // *smallerPtr = *largerPtr = 0
    for ptr in [smaller_ptr, larger_ptr] {
        if ptr != DUMMY32 {
            bt[ptr] = 0;
        }
    }

    // The comparisons left, in the attached CDict's tree.
    if DICT_MODE == ZSTD_DICT_MATCH_STATE
        && nb_compares > 0
        && let Some(dms) = dms
    {
        best_length = dubt_find_better_dict_match::<MLS>(
            ms,
            dms,
            src,
            ip,
            iend,
            &mut off_base,
            best_length,
            nb_compares,
        );
    }

    // Past the longest match: repetitive data is not inserted again.
    debug_assert!(match_end_idx > curr + 8);
    ms.next_to_update = match_end_idx - 8;
    (best_length, off_base)
}

/// `ZSTD_BtFindBestMatch`: the tree updated up to `ip`, then searched at
/// `ip`. Nothing for a position a long match skipped. Not inlined, as
/// libzstd's search functions: one copy serves the parser's three
/// searches.
#[inline(never)]
fn bt_find_best_match<const MLS: u32, const DICT_MODE: u8>(
    ms: &mut MatchState,
    src: &[u8],
    dict: &[u8],
    dms: Option<DictMatchState<'_>>,
    ip: usize,
    i_limit: usize,
) -> (usize, u32) {
    if ms.window.index(ip) < ms.next_to_update {
        // A skipped area.
        return (0, NO_OFFBASE);
    }
    update_dubt::<MLS>(ms, src, ip);
    dubt_find_best_match::<MLS, DICT_MODE>(ms, src, dict, dms, ip, i_limit)
}

// ---------------------------------------------------------------------------
// Hash chain

/// `ZSTD_insertAndFindFirstIndex_internal`: inserts the positions from
/// `next_to_update` up to `ip`, not included, into the hash and chain
/// tables (only the first in the lazy skipping mode), and returns the
/// first candidate for `ip`. The positions are in the prefix.
#[inline(always)]
fn insert_and_find_first_index<const MLS: u32>(ms: &mut MatchState, src: &[u8], ip: usize) -> u32 {
    let hash_log = ms.c_params.hash_log;
    let chain_mask = (1u32 << ms.c_params.chain_log) - 1;
    let base = ms.window.base;
    let target = ms.window.index(ip);
    let mut idx = ms.next_to_update;

    while idx < target {
        let h = zstd_hash_ptr(src, (i64::from(idx) - base) as usize, hash_log, MLS);
        ms.chain_table[(idx & chain_mask) as usize] = ms.hash_table[h];
        ms.hash_table[h] = idx;
        idx += 1;
        // Not every position in the lazy skipping mode.
        if ms.lazy_skipping {
            break;
        }
    }

    ms.next_to_update = target;
    ms.hash_table[zstd_hash_ptr(src, ip, hash_log, MLS)]
}

/// `ZSTD_insertAndFindFirstIndex`: [`insert_and_find_first_index`] with the
/// hash of `minMatch` bytes, as loading a dictionary inserts its positions
/// up to `ip`.
///
/// libzstd hashes with `ZSTD_hashPtr` of `minMatch` itself here, 7 bytes
/// included (3 takes 4), where the block compressors take 4 to 6: a
/// dictionary loaded with a shortest match of 7 is in the hash table under
/// other hashes than they look for, and the port does the same.
pub(crate) fn zstd_insert_and_find_first_index(ms: &mut MatchState, src: &[u8], ip: usize) -> u32 {
    match ms.c_params.min_match {
        5 => insert_and_find_first_index::<5>(ms, src, ip),
        6 => insert_and_find_first_index::<6>(ms, src, ip),
        7 => insert_and_find_first_index::<7>(ms, src, ip),
        // 3 and 4, and anything else, as ZSTD_hashPtr.
        _ => insert_and_find_first_index::<4>(ms, src, ip),
    }
}

/// `ZSTD_dedicatedDictSearch_lazy_loadDictionary`: the tables of a `CDict`
/// laid out for the dedicated dictionary search, with the positions of its
/// content from `next_to_update` up to `ip`, not included; `src` is the
/// buffer of its window.
///
/// The hash table, of `hash_log` bits (2 more than the level's: see
/// `zstd_dedicated_dict_search_get_cparams`), is cut into buckets of
/// `1 << ZSTD_LAZY_DDSS_BUCKET_LOG` entries, one bucket per hash of
/// `hash_log - ZSTD_LAZY_DDSS_BUCKET_LOG` bits: the 3 latest positions of
/// the hash, newest first (0 for none), then where the rest of its chain
/// is in the chain table: its start shifted by 8, plus its length, up to
/// 255. The chains lie one after another in the chain table, each newest
/// first, and hold no more positions in all than the chain table's size.
pub(crate) fn zstd_dedicated_dict_search_lazy_load_dictionary(
    ms: &mut MatchState,
    src: &[u8],
    ip: usize,
) {
    let base = ms.window.base;
    let target = ms.window.index(ip);
    let chain_size = 1u32 << ms.c_params.chain_log;
    let mut idx = ms.next_to_update;
    let min_chain = if chain_size < target - idx {
        target - chain_size
    } else {
        idx
    };
    let bucket_size = 1u32 << ZSTD_LAZY_DDSS_BUCKET_LOG;
    let cache_size = bucket_size - 1;
    // On 32 bits: 2 - 3 for a search log of 1, which the cap takes to 255.
    let chain_attempts = (1u32 << ms.c_params.search_log).wrapping_sub(cache_size);
    let chain_limit = chain_attempts.min(255);
    let min_match = ms.c_params.min_match;

    // The hash table is 1 << ZSTD_LAZY_DDSS_BUCKET_LOG times too large for
    // one entry per hash. First, with one entry per hash at its start, the
    // rest of it is a chain table of the latest positions.
    let hash_log = ms.c_params.hash_log - ZSTD_LAZY_DDSS_BUCKET_LOG;
    let tmp_chain_start = 1usize << hash_log;
    let tmp_chain_size = ((1u32 << ZSTD_LAZY_DDSS_BUCKET_LOG) - 1) << hash_log;
    let tmp_min_chain = if tmp_chain_size < target {
        target - tmp_chain_size
    } else {
        idx
    };
    debug_assert!(ms.c_params.chain_log <= 24);
    debug_assert!(ms.c_params.hash_log > ms.c_params.chain_log);
    debug_assert!(idx != 0);
    debug_assert!(tmp_min_chain <= min_chain);

    let MatchState {
        hash_table,
        chain_table,
        ..
    } = ms;

    // A hash table and a chain table, as the hash chain's, with the hash of
    // `minMatch` bytes as ZSTD_hashPtr makes it (3 takes 4).
    while idx < target {
        let h = zstd_hash_ptr(src, (i64::from(idx) - base) as usize, hash_log, min_match);
        if idx >= tmp_min_chain {
            hash_table[tmp_chain_start + (idx - tmp_min_chain) as usize] = hash_table[h];
        }
        hash_table[h] = idx;
        idx += 1;
    }

    // Each chain, past the positions its bucket will hold, into the chain
    // table; and in the entry of its hash, where it went.
    {
        let mut chain_pos = 0u32;
        for hash_idx in 0..1usize << hash_log {
            let mut count = 0;
            let mut count_beyond_min_chain = 0;
            let mut i = hash_table[hash_idx];
            // Past the first positions, which the bucket holds.
            while i >= tmp_min_chain && count < cache_size {
                if i < min_chain {
                    count_beyond_min_chain += 1;
                }
                i = hash_table[tmp_chain_start + (i - tmp_min_chain) as usize];
                count += 1;
            }
            if count == cache_size {
                count = 0;
                while count < chain_limit {
                    if i < min_chain {
                        // Only as many positions before `min_chain`, in the
                        // bucket and the chain, as the bucket took from
                        // after it: the chains then reach further back, and
                        // still fit in the chain table.
                        if i == 0 {
                            break;
                        }
                        count_beyond_min_chain += 1;
                        if count_beyond_min_chain > cache_size {
                            break;
                        }
                    }
                    chain_table[chain_pos as usize] = i;
                    chain_pos += 1;
                    count += 1;
                    if i < tmp_min_chain {
                        break;
                    }
                    i = hash_table[tmp_chain_start + (i - tmp_min_chain) as usize];
                }
            } else {
                count = 0;
            }
            hash_table[hash_idx] = if count != 0 {
                ((chain_pos - count) << 8) + count
            } else {
                0
            };
        }
        debug_assert!(chain_pos <= chain_size);
    }

    // Each hash's entry into the last of its bucket, from the last hash
    // down: a bucket is written over entries already read.
    for hash_idx in (0..1usize << hash_log).rev() {
        let bucket_idx = hash_idx << ZSTD_LAZY_DDSS_BUCKET_LOG;
        let chain_packed_pointer = hash_table[hash_idx];
        hash_table[bucket_idx..bucket_idx + cache_size as usize].fill(0);
        hash_table[bucket_idx + bucket_size as usize - 1] = chain_packed_pointer;
    }

    // The buckets: each position in front of its hash's, the oldest
    // falling off.
    for idx in ms.next_to_update..target {
        let h = zstd_hash_ptr(src, (i64::from(idx) - base) as usize, hash_log, min_match)
            << ZSTD_LAZY_DDSS_BUCKET_LOG;
        hash_table.copy_within(h..h + cache_size as usize - 1, h + 1);
        hash_table[h] = idx;
    }

    ms.next_to_update = target;
}

/// `ZSTD_dedicatedDictSearch_lazy_search`: the longest match at `ip` of
/// those in the bucket at `dds_idx` of the attached `CDict`'s hash table,
/// then in its chain, if longer than `ml`, up to `i_limit`, in at most
/// `nb_attempts` candidates; and its offset base, or `ml` and `off_base`
/// as they were. `curr` is `ip`'s index; the frame's prefix starts at
/// index `dict_limit`, at `prefix_start` in `src`, where a match through
/// the end of the content goes on.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn dedicated_dict_search_lazy_search(
    mut ml: usize,
    mut off_base: u32,
    nb_attempts: u32,
    dms: DictMatchState<'_>,
    src: &[u8],
    ip: usize,
    i_limit: usize,
    prefix_start: usize,
    curr: u32,
    dict_limit: u32,
    dds_idx: usize,
) -> (usize, u32) {
    let window = &dms.ms.window;
    let dds_lowest_index = window.dict_limit;
    let dds_base = window.base;
    let dds_size = window.next_src as u32;
    let dds_end = (window.next_src - dds_base) as usize;
    // From the CDict's indices to the frame's.
    let dds_index_delta = dict_limit.wrapping_sub(dds_size);
    let bucket_size = 1u32 << ZSTD_LAZY_DDSS_BUCKET_LOG;
    let bucket_limit = nb_attempts.min(bucket_size - 1);
    let hash_table = &dms.ms.hash_table;
    let content = dms.content;

    // The length of the match with index `match_index` of the CDict, or 0.
    let match_length = |match_index: u32| {
        // In the content, with 8 bytes after it, by the table's making.
        debug_assert!(match_index >= dds_lowest_index);
        let m = (i64::from(match_index) - dds_base) as usize;
        debug_assert!(m + 4 <= dds_end);
        if mem_read32(content, m) == mem_read32(src, ip) {
            zstd_count_2segments(src, ip + 4, content, m + 4, i_limit, dds_end, prefix_start) + 4
        } else {
            0
        }
    };

    if PREFETCH {
        // The bucket's positions, and the start of its chain.
        for &match_index in &hash_table[dds_idx..dds_idx + bucket_size as usize - 1] {
            prefetch_l1(content, (i64::from(match_index) - dds_base) as usize);
        }
        let chain_packed_pointer = hash_table[dds_idx + bucket_size as usize - 1];
        prefetch_l1(&dms.ms.chain_table, (chain_packed_pointer >> 8) as usize);
    }

    // The bucket's positions, newest first, up to the first empty one.
    let mut dds_attempt = 0;
    while dds_attempt < bucket_limit {
        let match_index = hash_table[dds_idx + dds_attempt as usize];
        if match_index == 0 {
            return (ml, off_base);
        }
        let current_ml = match_length(match_index);
        // The best so far.
        if current_ml > ml {
            ml = current_ml;
            off_base = offset_to_offbase(curr - (match_index + dds_index_delta));
            if ip + current_ml == i_limit {
                // As long as it can be, and the next test would read past
                // the end.
                return (ml, off_base);
            }
        }
        dds_attempt += 1;
    }

    // Then its chain, with the attempts left.
    let chain_packed_pointer = hash_table[dds_idx + bucket_size as usize - 1];
    let chain_index = (chain_packed_pointer >> 8) as usize;
    let chain_length = chain_packed_pointer & 0xFF;
    let chain_attempts = nb_attempts - dds_attempt;
    let chain_limit = chain_attempts.min(chain_length) as usize;
    let chain = &dms.ms.chain_table[chain_index..chain_index + chain_limit];
    if PREFETCH {
        for &match_index in chain {
            prefetch_l1(content, (i64::from(match_index) - dds_base) as usize);
        }
    }
    for &match_index in chain {
        let current_ml = match_length(match_index);
        if current_ml > ml {
            ml = current_ml;
            off_base = offset_to_offbase(curr - (match_index + dds_index_delta));
            if ip + current_ml == i_limit {
                break;
            }
        }
    }
    (ml, off_base)
}

/// `ZSTD_HcFindBestMatch`: the longest match at `ip`, up to `i_limit`, of
/// those the hash chain gives, and its offset base; a length under 4 for
/// none. With `EXT_DICT`, candidates below the prefix are in `dict`. With
/// `DICT_MATCH_STATE` and `DEDICATED_DICT_SEARCH`, the attached `CDict`'s
/// tables are searched next, with the attempts left, over `dms`.
#[inline(always)]
fn hc_find_best_match<const MLS: u32, const DICT_MODE: u8>(
    ms: &mut MatchState,
    src: &[u8],
    dict: &[u8],
    dms: Option<DictMatchState<'_>>,
    ip: usize,
    i_limit: usize,
) -> (usize, u32) {
    let c_params = ms.c_params;
    let chain_size = 1u32 << c_params.chain_log;
    let chain_mask = chain_size - 1;
    let base = ms.window.base;
    let dict_base = ms.window.dict_base;
    let dict_limit = ms.window.dict_limit;
    let prefix_start = (i64::from(dict_limit) - base) as usize;
    let dict_end = (i64::from(dict_limit) - dict_base) as usize;
    let curr = ms.window.index(ip);
    let low_limit = ms.lowest_match_index(curr, c_params.window_log);
    let min_chain = curr.saturating_sub(chain_size);
    let mut nb_attempts = 1u32 << c_params.search_log;
    let mut ml = 4 - 1;
    let mut off_base = NO_OFFBASE;

    let mut match_index = insert_and_find_first_index::<MLS>(ms, src, ip);

    while match_index >= low_limit && nb_attempts > 0 {
        let mut current_ml = 0;
        if DICT_MODE != EXT_DICT || match_index >= dict_limit {
            let m = (i64::from(match_index) - base) as usize;
            // The 4 bytes that end one past the best length so far: a
            // match must have them to be longer.
            if mem_read32(src, m + ml - 3) == mem_read32(src, ip + ml - 3) {
                current_ml = zstd_count(src, ip, m, i_limit);
            }
        } else {
            // A candidate in the older segment has its 4 bytes there: it
            // was inserted with 8 bytes after it in its block.
            let m = (i64::from(match_index) - dict_base) as usize;
            if mem_read32(dict, m) == mem_read32(src, ip) {
                current_ml =
                    zstd_count_2segments(src, ip + 4, dict, m + 4, i_limit, dict_end, prefix_start)
                        + 4;
            }
        }

        // The best so far.
        if current_ml > ml {
            ml = current_ml;
            off_base = offset_to_offbase(curr - match_index);
            if ip + current_ml == i_limit {
                // As long as it can be, and the next test would read past
                // the end.
                break;
            }
        }

        if match_index <= min_chain {
            break;
        }
        match_index = ms.chain_table[(match_index & chain_mask) as usize];
        nb_attempts -= 1;
    }

    if DICT_MODE == DEDICATED_DICT_SEARCH {
        let Some(dms) = dms else {
            unreachable!("the dedicated dictionary search without a CDict")
        };
        // The bucket of ip's hash in the CDict's table.
        //
        // Differs from libzstd: the bucket is found here, not before the
        // search of the frame's tables, to prefetch it. The hash reads only
        // the input.
        let dds_hash_log = dms.ms.c_params.hash_log - ZSTD_LAZY_DDSS_BUCKET_LOG;
        let dds_idx = zstd_hash_ptr(src, ip, dds_hash_log, MLS) << ZSTD_LAZY_DDSS_BUCKET_LOG;
        (ml, off_base) = dedicated_dict_search_lazy_search(
            ml,
            off_base,
            nb_attempts,
            dms,
            src,
            ip,
            i_limit,
            prefix_start,
            curr,
            dict_limit,
            dds_idx,
        );
    } else if DICT_MODE == DICT_MATCH_STATE {
        let Some(dms) = dms else {
            unreachable!("the dictMatchState search without a CDict")
        };
        // The CDict's hash chain, as the frame's, in its own indices: index
        // i of its window is byte i - dms_base of its content, and index
        // i + dms_index_delta of the frame's.
        let dms_chain_table = &dms.ms.chain_table;
        let dms_chain_size = 1u32 << dms.ms.c_params.chain_log;
        let dms_chain_mask = dms_chain_size - 1;
        let dms_lowest_index = dms.ms.window.dict_limit;
        let dms_base = dms.ms.window.base;
        let dms_size = dms.ms.window.next_src as u32;
        let dms_end = (dms.ms.window.next_src - dms_base) as usize;
        let dms_index_delta = dict_limit.wrapping_sub(dms_size);
        let dms_min_chain = dms_size.saturating_sub(dms_chain_size);

        match_index = dms.ms.hash_table[zstd_hash_ptr(src, ip, dms.ms.c_params.hash_log, MLS)];

        while match_index >= dms_lowest_index && nb_attempts > 0 {
            let m = (i64::from(match_index) - dms_base) as usize;
            // In the content, with 8 bytes after it, by the table's making.
            debug_assert!(m + 4 <= dms_end);
            let mut current_ml = 0;
            if mem_read32(dms.content, m) == mem_read32(src, ip) {
                current_ml = zstd_count_2segments(
                    src,
                    ip + 4,
                    dms.content,
                    m + 4,
                    i_limit,
                    dms_end,
                    prefix_start,
                ) + 4;
            }

            // The best so far.
            if current_ml > ml {
                ml = current_ml;
                debug_assert!(curr > match_index + dms_index_delta);
                off_base = offset_to_offbase(curr - (match_index + dms_index_delta));
                if ip + current_ml == i_limit {
                    // As long as it can be, and the next test would read
                    // past the end.
                    break;
                }
            }

            if match_index <= dms_min_chain {
                break;
            }
            match_index = dms_chain_table[(match_index & dms_chain_mask) as usize];
            nb_attempts -= 1;
        }
    }

    (ml, off_base)
}

// ---------------------------------------------------------------------------
// The row match finder
//
// The hash table is cut into rows of 16, 32 or 64 entries (`1 << ROW_LOG`).
// A position's salted hash, `row_hash_log + 8` bits long, picks a row with
// its top bits, and its low 8 bits are its tag. Each row is a circular
// buffer of the latest positions with that row's hashes, newest first from
// its head; the tag table holds the head at entry 0 and each entry's tag,
// so that a search compares the tags of a whole row at once and only reads
// the positions whose tag is the one sought.

/// `ZSTD_ROW_HASH_TAG_BITS`: the bits of the tag.
pub(crate) const ZSTD_ROW_HASH_TAG_BITS: u32 = 8;
/// `ZSTD_ROW_HASH_TAG_MASK`
const ZSTD_ROW_HASH_TAG_MASK: u32 = (1 << ZSTD_ROW_HASH_TAG_BITS) - 1;
/// `ZSTD_ROW_HASH_CACHE_MASK`
const ZSTD_ROW_HASH_CACHE_MASK: u32 = ZSTD_ROW_HASH_CACHE_SIZE as u32 - 1;
/// `ZSTD_ROW_HASH_MAX_ENTRIES`: the entries of the longest rows.
const ZSTD_ROW_HASH_MAX_ENTRIES: usize = 64;

/// `ZSTD_row_nextIndex`: the entry of the row to write next, which becomes
/// its head: from the head back, around the row, never entry 0.
#[inline(always)]
fn row_next_index(tag_row: &mut [u8], row_mask: u32) -> u32 {
    let mut next = u32::from(tag_row[0]).wrapping_sub(1) & row_mask;
    // Skip the first entry.
    next += if next == 0 { row_mask } else { 0 };
    tag_row[0] = next as u8;
    next
}

/// `ZSTD_row_prefetch`: the row at `rel_row` of the hash table and of the
/// tag table, which a search or an insertion is about to read, prefetched
/// (see [`prefetch_l1`]): the first 16 and, in longer rows, the next 16
/// entries of the hash table (more does not help, libzstd notes), and the
/// whole row of tags.
#[inline(always)]
fn row_prefetch(hash_table: &[u32], tag_table: &[u8], rel_row: usize, row_log: u32) {
    if !PREFETCH {
        return;
    }
    prefetch_l1(hash_table, rel_row);
    if row_log >= 5 {
        prefetch_l1(hash_table, rel_row + 16);
    }
    prefetch_l1(tag_table, rel_row);
    if row_log == 6 {
        prefetch_l1(tag_table, rel_row + 32);
    }
}

/// `ZSTD_row_fillHashCache`: the hashes of the positions from index `idx`
/// on into the hash cache, `ZSTD_ROW_HASH_CACHE_SIZE` of them but none past
/// `i_limit`, a position of `src` (before it for small blocks), and their
/// rows prefetched.
#[inline(always)]
fn row_fill_hash_cache<const MLS: u32>(ms: &mut MatchState, src: &[u8], idx: u32, i_limit: i64) {
    let hash_log = ms.row_hash_log;
    let row_log = ms.c_params.search_log.clamp(4, 6);
    let base = ms.window.base;
    let at = i64::from(idx) - base;
    let max_elems_to_prefetch = if at > i_limit {
        0
    } else {
        (i_limit - at + 1) as u32
    };
    let lim = idx + (ZSTD_ROW_HASH_CACHE_SIZE as u32).min(max_elems_to_prefetch);

    for idx in idx..lim {
        let hash = zstd_hash_ptr_salted(
            src,
            (i64::from(idx) - base) as usize,
            hash_log + ZSTD_ROW_HASH_TAG_BITS,
            MLS,
            ms.hash_salt,
        );
        let rel_row = ((hash >> ZSTD_ROW_HASH_TAG_BITS) << row_log) as usize;
        row_prefetch(&ms.hash_table, &ms.tag_table, rel_row, row_log);
        ms.hash_cache[(idx & ZSTD_ROW_HASH_CACHE_MASK) as usize] = hash;
    }
}

/// `ZSTD_row_nextCachedHash`: the hash of index `idx` (at `base`), from the
/// cache, where the hash of `ZSTD_ROW_HASH_CACHE_SIZE` positions later
/// takes its place, its row prefetched.
///
/// Differs from libzstd: in a context used again, the indices are not libzstd's (see
/// `CCtx::reset_cctx_internal`), so a hash may sit in another slot of the
/// cache. That changes nothing: the cache is filled at each block's start
/// and after the lazy skipping mode, and each slot read holds the hash of
/// its position, which the fill or the turn 8 positions before wrote.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn row_next_cached_hash<const MLS: u32, const ROW_LOG: u32>(
    cache: &mut [u32; ZSTD_ROW_HASH_CACHE_SIZE],
    hash_table: &[u32],
    tag_table: &[u8],
    src: &[u8],
    base: i64,
    idx: u32,
    hash_log: u32,
    hash_salt: u64,
) -> u32 {
    let new_hash = zstd_hash_ptr_salted(
        src,
        (i64::from(idx) - base) as usize + ZSTD_ROW_HASH_CACHE_SIZE,
        hash_log + ZSTD_ROW_HASH_TAG_BITS,
        MLS,
        hash_salt,
    );
    let rel_row = ((new_hash >> ZSTD_ROW_HASH_TAG_BITS) << ROW_LOG) as usize;
    row_prefetch(hash_table, tag_table, rel_row, ROW_LOG);
    let slot = (idx & ZSTD_ROW_HASH_CACHE_MASK) as usize;
    let hash = cache[slot];
    cache[slot] = new_hash;
    hash
}

/// `ZSTD_row_update_internalImpl`, with the hash cache: inserts the
/// positions of indices `update_start_idx` to `update_end_idx`, not
/// included. libzstd hashes without the cache only to load a dictionary.
#[inline(always)]
fn row_update_internal_impl<const MLS: u32, const ROW_LOG: u32>(
    ms: &mut MatchState,
    src: &[u8],
    mut update_start_idx: u32,
    update_end_idx: u32,
) {
    let row_mask = (1u32 << ROW_LOG) - 1;
    let hash_log = ms.row_hash_log;
    let base = ms.window.base;
    let hash_salt = ms.hash_salt;
    let MatchState {
        hash_table,
        tag_table,
        hash_cache,
        ..
    } = ms;

    while update_start_idx < update_end_idx {
        let hash = row_next_cached_hash::<MLS, ROW_LOG>(
            hash_cache,
            hash_table,
            tag_table,
            src,
            base,
            update_start_idx,
            hash_log,
            hash_salt,
        );
        let rel_row = ((hash >> ZSTD_ROW_HASH_TAG_BITS) << ROW_LOG) as usize;
        let row = &mut hash_table[rel_row..rel_row + (1 << ROW_LOG)];
        let tag_row = &mut tag_table[rel_row..rel_row + (1 << ROW_LOG)];
        let pos = (row_next_index(tag_row, row_mask) & row_mask) as usize;
        tag_row[pos] = (hash & ZSTD_ROW_HASH_TAG_MASK) as u8;
        row[pos] = update_start_idx;
        update_start_idx += 1;
    }
}

/// `ZSTD_row_update_internal`, with the hash cache: inserts the positions
/// from `next_to_update` up to `ip`, not included. After a long match, only
/// the 96 positions at its start and the 32 at its end.
#[inline(always)]
fn row_update_internal<const MLS: u32, const ROW_LOG: u32>(
    ms: &mut MatchState,
    src: &[u8],
    ip: usize,
) {
    const K_SKIP_THRESHOLD: u32 = 384;
    const K_MAX_MATCH_START_POSITIONS_TO_UPDATE: u32 = 96;
    const K_MAX_MATCH_END_POSITIONS_TO_UPDATE: u32 = 32;
    let mut idx = ms.next_to_update;
    let target = ms.window.index(ip);

    // Past a long match, only its start and its end. libzstd skips only
    // with the hash cache, which is always the case here: it goes without
    // only to load a dictionary.
    if target.wrapping_sub(idx) > K_SKIP_THRESHOLD {
        let bound = idx + K_MAX_MATCH_START_POSITIONS_TO_UPDATE;
        row_update_internal_impl::<MLS, ROW_LOG>(ms, src, idx, bound);
        idx = target - K_MAX_MATCH_END_POSITIONS_TO_UPDATE;
        row_fill_hash_cache::<MLS>(ms, src, idx, ip as i64 + 1);
    }
    debug_assert!(target >= idx);
    row_update_internal_impl::<MLS, ROW_LOG>(ms, src, idx, target);
    ms.next_to_update = target;
}

/// `ZSTD_row_update`: inserts the positions from `nextToUpdate` up to
/// `ip`, not included, all of them, as loading a dictionary does: without
/// the hash cache (`ZSTD_row_update_internal` with `useCache` 0), each
/// position hashed as it is inserted, with the salt.
///
/// The hashes are of `min(minMatch, 6)` bytes, 3 taking 4, as the block
/// compressors'.
pub(crate) fn zstd_row_update(ms: &mut MatchState, src: &[u8], ip: usize) {
    macro_rules! with {
        ($mls:literal, $row_log:literal) => {
            row_update_uncached::<$mls, $row_log>(ms, src, ip)
        };
    }
    let row_log = ms.c_params.search_log.clamp(4, 6);
    match (ms.c_params.min_match.min(6), row_log) {
        (5, 4) => with!(5, 4),
        (5, 5) => with!(5, 5),
        (5, 6) => with!(5, 6),
        (6, 4) => with!(6, 4),
        (6, 5) => with!(6, 5),
        (6, 6) => with!(6, 6),
        // 3 and 4, as ZSTD_hashPtrSalted.
        (_, 4) => with!(4, 4),
        (_, 5) => with!(4, 5),
        _ => with!(4, 6),
    }
}

/// `ZSTD_row_update_internal` without the hash cache: every position from
/// `nextToUpdate` up to `ip`, not included, its hash made as it is
/// inserted (`ZSTD_row_update_internalImpl` with `useCache` 0).
fn row_update_uncached<const MLS: u32, const ROW_LOG: u32>(
    ms: &mut MatchState,
    src: &[u8],
    ip: usize,
) {
    let row_mask = (1u32 << ROW_LOG) - 1;
    let hash_log = ms.row_hash_log;
    let base = ms.window.base;
    let hash_salt = ms.hash_salt;
    let target = ms.window.index(ip);
    let MatchState {
        hash_table,
        tag_table,
        ..
    } = ms;
    let mut idx = ms.next_to_update;
    debug_assert!(target >= idx);
    while idx < target {
        let hash = zstd_hash_ptr_salted(
            src,
            (i64::from(idx) - base) as usize,
            hash_log + ZSTD_ROW_HASH_TAG_BITS,
            MLS,
            hash_salt,
        );
        let rel_row = ((hash >> ZSTD_ROW_HASH_TAG_BITS) << ROW_LOG) as usize;
        let row = &mut hash_table[rel_row..rel_row + (1 << ROW_LOG)];
        let tag_row = &mut tag_table[rel_row..rel_row + (1 << ROW_LOG)];
        let pos = (row_next_index(tag_row, row_mask) & row_mask) as usize;
        tag_row[pos] = (hash & ZSTD_ROW_HASH_TAG_MASK) as u8;
        row[pos] = idx;
        idx += 1;
    }
    ms.next_to_update = target;
}

/// `ip` into its row, `row` and `tag_row`, with its tag: as the entry
/// after the head, which becomes the head, of index `next_to_update`, then
/// one more.
#[inline(always)]
fn row_insert(
    row: &mut [u32],
    tag_row: &mut [u8],
    row_mask: u32,
    tag: u8,
    next_to_update: &mut u32,
) {
    let pos = (row_next_index(tag_row, row_mask) & row_mask) as usize;
    tag_row[pos] = tag;
    row[pos] = *next_to_update;
    *next_to_update += 1;
}

/// `ZSTD_row_getMatchMask`: the entries of a row whose tag is `tag`, as a
/// mask in which bit `i` is entry `(head + i) % entries`: from the newest
/// entry to the oldest, around the row.
///
/// Differs from libzstd: libzstd compares the tags 16 at a time with SSE2
/// or NEON; here 8 at a time in a `u64`, as libzstd's own fallback for
/// other machines does (SWAR), with the same mask. On NEON, libzstd's mask
/// for rows of 16 or 32 entries has 4 or 2 bits per entry
/// (`ZSTD_row_matchMaskGroupWidth`), rotated by `head` times that, with one
/// bit of each entry kept; each entry's bits are together and the entries
/// in order, so its bits come in the same order as here and name the same
/// entries, `(headGrouped + bit) / groupWidth`.
#[inline(always)]
pub(crate) fn row_get_match_mask<const ROW_LOG: u32>(tag_row: &[u8], tag: u8, head: u32) -> u64 {
    const X01: u64 = u64::MAX / 0xFF;
    const X80: u64 = X01 << 7;
    // Gathers the top bit of each byte into the top byte.
    const EXTRACT_MAGIC: u64 = (u64::MAX / 0x7F) >> 8;
    let splat_char = u64::from(tag) * X01;
    let mut matches = 0u64;
    // From the last 8 tags to the first, for entry i to be bit i.
    for chunk in tag_row[..1 << ROW_LOG].as_chunks::<8>().0.iter().rev() {
        let mut chunk = u64::from_le_bytes(*chunk) ^ splat_char;
        // 0x80 in each byte that is not 0: the tags that differ.
        chunk = (((chunk | X80) - X01) | chunk) & X80;
        matches <<= 8;
        matches |= chunk.wrapping_mul(EXTRACT_MAGIC) >> 56;
    }
    matches = !matches;
    match ROW_LOG {
        4 => u64::from((matches as u16).rotate_right(head)),
        5 => u64::from((matches as u32).rotate_right(head)),
        _ => matches.rotate_right(head),
    }
}

/// `ZSTD_RowFindBestMatch`: the longest match at `ip`, up to `i_limit`, of
/// those in its row with its tag, and its offset base; a length under 4 for
/// none. The row is first brought up to `ip`, and `ip` inserted after the
/// search. With `EXT_DICT`, candidates below the prefix are in `dict`. With
/// `DICT_MATCH_STATE`, the row of `ip`'s hash in the attached `CDict`'s
/// tables is searched next, with the attempts left; with
/// `DEDICATED_DICT_SEARCH`, its bucket and chain, with more attempts.
///
/// Outlined, as libzstd's search functions are: inlined at each search of
/// each parser, it would be many copies.
///
/// As libzstd: with prefetching ([`PREFETCH`]), the `CDict`'s row or bucket
/// is prefetched first; the candidates of a row are gathered into a buffer,
/// each prefetched, then `ip` is inserted, then they are compared.
///
/// Differs from libzstd: without prefetching, a read of each candidate takes
/// the place of its prefetch.
#[inline(never)]
fn row_find_best_match<const MLS: u32, const ROW_LOG: u32, const DICT_MODE: u8>(
    ms: &mut MatchState,
    src: &[u8],
    dict: &[u8],
    dms: Option<DictMatchState<'_>>,
    ip: usize,
    i_limit: usize,
) -> (usize, u32) {
    let hash_log = ms.row_hash_log;
    let c_params = ms.c_params;
    let base = ms.window.base;
    let dict_base = ms.window.dict_base;
    let dict_limit = ms.window.dict_limit;
    let prefix_start = (i64::from(dict_limit) - base) as usize;
    let dict_end = (i64::from(dict_limit) - dict_base) as usize;
    let curr = ms.window.index(ip);
    let low_limit = ms.lowest_match_index(curr, c_params.window_log);
    let row_entries = 1usize << ROW_LOG;
    let row_mask = (1u32 << ROW_LOG) - 1;
    // No more searches than entries in a row.
    let capped_search_log = c_params.search_log.min(ROW_LOG);
    let hash_salt = ms.hash_salt;
    let mut nb_attempts = 1u32 << capped_search_log;
    let mut ml = 4 - 1;
    let mut off_base = NO_OFFBASE;

    // With prefetching, the CDict's bucket or row, searched last, now.
    if PREFETCH && let Some(dms) = &dms {
        if DICT_MODE == DEDICATED_DICT_SEARCH {
            let dds_hash_log = dms.ms.c_params.hash_log - ZSTD_LAZY_DDSS_BUCKET_LOG;
            let dds_idx = zstd_hash_ptr(src, ip, dds_hash_log, MLS) << ZSTD_LAZY_DDSS_BUCKET_LOG;
            prefetch_l1(&dms.ms.hash_table, dds_idx);
        } else if DICT_MODE == DICT_MATCH_STATE {
            let dms_hash =
                zstd_hash_ptr(src, ip, dms.ms.row_hash_log + ZSTD_ROW_HASH_TAG_BITS, MLS) as u32;
            let dms_rel_row = ((dms_hash >> ZSTD_ROW_HASH_TAG_BITS) << ROW_LOG) as usize;
            row_prefetch(&dms.ms.hash_table, &dms.ms.tag_table, dms_rel_row, ROW_LOG);
        }
    }

    // Update the hash table and the tag table up to ip, not included.
    let hash = if ms.lazy_skipping {
        // In the lazy skipping mode, only the positions searched are
        // inserted, and the hash cache is not kept up to date.
        let hash = zstd_hash_ptr_salted(src, ip, hash_log + ZSTD_ROW_HASH_TAG_BITS, MLS, hash_salt);
        ms.next_to_update = curr;
        hash
    } else {
        row_update_internal::<MLS, ROW_LOG>(ms, src, ip);
        row_next_cached_hash::<MLS, ROW_LOG>(
            &mut ms.hash_cache,
            &ms.hash_table,
            &ms.tag_table,
            src,
            base,
            curr,
            hash_log,
            hash_salt,
        )
    };
    // Entropy for the next salt.
    ms.hash_salt_entropy = ms.hash_salt_entropy.wrapping_add(hash);

    // The row of ip's hash.
    let rel_row = ((hash >> ZSTD_ROW_HASH_TAG_BITS) << ROW_LOG) as usize;
    let tag = hash & ZSTD_ROW_HASH_TAG_MASK;
    let MatchState {
        hash_table,
        tag_table,
        next_to_update,
        ..
    } = ms;
    let row = &mut hash_table[rel_row..rel_row + row_entries];
    let tag_row = &mut tag_table[rel_row..rel_row + row_entries];
    let head = u32::from(tag_row[0]) & row_mask;
    let mut matches = row_get_match_mask::<ROW_LOG>(tag_row, tag as u8, head);

    // How long a candidate's match is: 0 where it cannot be longer than
    // `ml`.
    let match_length = |match_index: u32, ml: usize| {
        debug_assert!(match_index < curr && match_index >= low_limit);
        if DICT_MODE != EXT_DICT || match_index >= dict_limit {
            let m = (i64::from(match_index) - base) as usize;
            // The 4 bytes that end one past the best length so far: a
            // match must have them to be longer.
            if mem_read32(src, m + ml - 3) == mem_read32(src, ip + ml - 3) {
                return zstd_count(src, ip, m, i_limit);
            }
        } else {
            // A candidate in the older segment has its 4 bytes there: it
            // was inserted with 16 bytes after it in its block.
            let m = (i64::from(match_index) - dict_base) as usize;
            if mem_read32(dict, m) == mem_read32(src, ip) {
                return zstd_count_2segments(
                    src,
                    ip + 4,
                    dict,
                    m + 4,
                    i_limit,
                    dict_end,
                    prefix_start,
                ) + 4;
            }
        }
        0
    };

    // The candidates, newest first, up to the first out of the window, and
    // the longest match; and ip into the row too, which saves the next
    // search a turn of the update.
    //
    // Without prefetching, a read of each candidate stands in for it: no
    // branch waits on these, so the processor takes their cache misses side
    // by side, where comparing one by one takes them in turn.
    let mut match_buffer = [0u32; ZSTD_ROW_HASH_MAX_ENTRIES];
    let mut num_matches = 0;
    let mut read = 0u8;
    while matches > 0 && nb_attempts > 0 {
        let match_pos = (head + matches.trailing_zeros()) & row_mask;
        let match_index = row[match_pos as usize];
        matches &= matches - 1;
        if match_pos == 0 {
            // The head, not an entry.
            continue;
        }
        if match_index < low_limit {
            break;
        }
        let (content, at) = if DICT_MODE != EXT_DICT || match_index >= dict_limit {
            (src, (i64::from(match_index) - base) as usize)
        } else {
            (dict, (i64::from(match_index) - dict_base) as usize)
        };
        if PREFETCH {
            prefetch_l1(content, at);
        } else {
            read ^= content[at];
        }
        match_buffer[num_matches] = match_index;
        num_matches += 1;
        nb_attempts -= 1;
    }
    std::hint::black_box(read);
    row_insert(row, tag_row, row_mask, tag as u8, next_to_update);
    for &match_index in &match_buffer[..num_matches] {
        let current_ml = match_length(match_index, ml);
        if current_ml > ml {
            ml = current_ml;
            off_base = offset_to_offbase(curr - match_index);
            if ip + current_ml == i_limit {
                // As long as it can be, and the next test would read past
                // the end.
                break;
            }
        }
    }

    if DICT_MODE == DEDICATED_DICT_SEARCH {
        let Some(dms) = dms else {
            unreachable!("the dedicated dictionary search without a CDict")
        };
        // The bucket of ip's hash in the CDict's table. The frame's rows
        // hold fewer candidates than the search log asks for: the CDict
        // gets the difference.
        //
        // Differs from libzstd: the bucket is found here, not before the
        // search of the frame's tables, to prefetch it. The hash reads only
        // the input.
        let dds_hash_log = dms.ms.c_params.hash_log - ZSTD_LAZY_DDSS_BUCKET_LOG;
        let dds_idx = zstd_hash_ptr(src, ip, dds_hash_log, MLS) << ZSTD_LAZY_DDSS_BUCKET_LOG;
        let dds_extra_attempts = if c_params.search_log > ROW_LOG {
            1u32 << (c_params.search_log - ROW_LOG)
        } else {
            0
        };
        (ml, off_base) = dedicated_dict_search_lazy_search(
            ml,
            off_base,
            nb_attempts + dds_extra_attempts,
            dms,
            src,
            ip,
            i_limit,
            prefix_start,
            curr,
            dict_limit,
            dds_idx,
        );
    } else if DICT_MODE == DICT_MATCH_STATE {
        let Some(dms) = dms else {
            unreachable!("the dictMatchState search without a CDict")
        };
        // The row of ip's hash in the CDict's tables, of rows as long as
        // the frame's (they have the same search log), hashed without a
        // salt: index i of its window is byte i - dms_base of its content,
        // and index i + dms_index_delta of the frame's.
        //
        // Differs from libzstd: the row is found here, not before the
        // search of the frame's tables, to prefetch it. The hash reads only
        // the input.
        let dms_hash =
            zstd_hash_ptr(src, ip, dms.ms.row_hash_log + ZSTD_ROW_HASH_TAG_BITS, MLS) as u32;
        let dms_rel_row = ((dms_hash >> ZSTD_ROW_HASH_TAG_BITS) << ROW_LOG) as usize;
        let dms_tag = dms_hash & ZSTD_ROW_HASH_TAG_MASK;
        let dms_row = &dms.ms.hash_table[dms_rel_row..dms_rel_row + row_entries];
        let dms_tag_row = &dms.ms.tag_table[dms_rel_row..dms_rel_row + row_entries];
        let dms_lowest_index = dms.ms.window.dict_limit;
        let dms_base = dms.ms.window.base;
        let dms_size = dms.ms.window.next_src as u32;
        let dms_end = (dms.ms.window.next_src - dms_base) as usize;
        let dms_index_delta = dict_limit.wrapping_sub(dms_size);

        let head = u32::from(dms_tag_row[0]) & row_mask;
        let mut matches = row_get_match_mask::<ROW_LOG>(dms_tag_row, dms_tag as u8, head);
        // How long a candidate's match is, 0 for none.
        let match_length = |match_index: u32| {
            let m = (i64::from(match_index) - dms_base) as usize;
            // In the content, with 8 bytes after it, by the table's making.
            debug_assert!(m + 4 <= dms_end);
            if mem_read32(dms.content, m) == mem_read32(src, ip) {
                return zstd_count_2segments(
                    src,
                    ip + 4,
                    dms.content,
                    m + 4,
                    i_limit,
                    dms_end,
                    prefix_start,
                ) + 4;
            }
            0
        };
        // As in the frame's row: newest first, up to the first out of the
        // CDict's window; gathered first with prefetching.
        let mut match_buffer = [0u32; ZSTD_ROW_HASH_MAX_ENTRIES];
        let mut num_matches = 0;
        if PREFETCH {
            while matches > 0 && nb_attempts > 0 {
                let match_pos = (head + matches.trailing_zeros()) & row_mask;
                let match_index = dms_row[match_pos as usize];
                matches &= matches - 1;
                if match_pos == 0 {
                    continue;
                }
                if match_index < dms_lowest_index {
                    break;
                }
                prefetch_l1(dms.content, (i64::from(match_index) - dms_base) as usize);
                match_buffer[num_matches] = match_index;
                num_matches += 1;
                nb_attempts -= 1;
            }
        }
        let mut gathered = match_buffer[..num_matches].iter();
        loop {
            let match_index = if PREFETCH {
                let Some(&match_index) = gathered.next() else {
                    break;
                };
                match_index
            } else {
                if matches == 0 || nb_attempts == 0 {
                    break;
                }
                let match_pos = (head + matches.trailing_zeros()) & row_mask;
                let match_index = dms_row[match_pos as usize];
                matches &= matches - 1;
                if match_pos == 0 {
                    // The head, not an entry.
                    continue;
                }
                if match_index < dms_lowest_index {
                    break;
                }
                nb_attempts -= 1;
                match_index
            };
            let current_ml = match_length(match_index);

            // The best so far.
            if current_ml > ml {
                ml = current_ml;
                debug_assert!(curr > match_index + dms_index_delta);
                off_base = offset_to_offbase(curr - (match_index + dms_index_delta));
                if ip + current_ml == i_limit {
                    break;
                }
            }
        }
    }

    (ml, off_base)
}

// ---------------------------------------------------------------------------
// The parser

/// `ZSTD_searchMax`: the longest match at `ip` the search method finds,
/// and its offset base; a length under 4 for none. The window's older
/// segment is `dict` with `EXT_DICT`; the attached `CDict` is `dms` with
/// `DICT_MATCH_STATE` and `DEDICATED_DICT_SEARCH`.
#[inline(always)]
fn search_max<const SEARCH: u8, const MLS: u32, const DICT_MODE: u8>(
    ms: &mut MatchState,
    src: &[u8],
    dict: &[u8],
    dms: Option<DictMatchState<'_>>,
    ip: usize,
    iend: usize,
) -> (usize, u32) {
    match SEARCH {
        SEARCH_HASH_CHAIN => hc_find_best_match::<MLS, DICT_MODE>(ms, src, dict, dms, ip, iend),
        SEARCH_BINARY_TREE => bt_find_best_match::<MLS, DICT_MODE>(ms, src, dict, dms, ip, iend),
        // Rows of 16 entries up to a search log of 4, then 32, then 64.
        SEARCH_ROW_HASH => match ms.c_params.search_log.clamp(4, 6) {
            5 => row_find_best_match::<MLS, 5, DICT_MODE>(ms, src, dict, dms, ip, iend),
            6 => row_find_best_match::<MLS, 6, DICT_MODE>(ms, src, dict, dms, ip, iend),
            _ => row_find_best_match::<MLS, 4, DICT_MODE>(ms, src, dict, dms, ip, iend),
        },
        _ => unreachable!("a search method the port does not have"),
    }
}

/// How much sooner than 8 bytes before the end the parser stops: by
/// `ZSTD_ROW_HASH_CACHE_SIZE` with the row match finder, which hashes the
/// positions that far ahead.
#[inline(always)]
const fn row_hash_lookahead<const SEARCH: u8>() -> i64 {
    if SEARCH == SEARCH_ROW_HASH {
        ZSTD_ROW_HASH_CACHE_SIZE as i64
    } else {
        0
    }
}

/// libzstd's gain of a match: its length times `scale`, less what its
/// offset costs, plus `bonus`; as the `int` libzstd makes of it.
#[inline(always)]
fn gain(length: usize, scale: usize, off_base: u32, bonus: usize) -> i64 {
    (length * scale + bonus) as i64 - i64::from(highbit32(off_base))
}

/// `ZSTD_compressBlock_lazy_generic`: the sequences of the block
/// `src[istart..iend]` into `seq_store`, searching `DEPTH` positions past
/// each match found (0 for `greedy`, 1 for `lazy`, 2 for `lazy2`), without
/// a dictionary (`NO_DICT`) or with the attached `CDict` `dms`
/// (`DICT_MATCH_STATE`, `DEDICATED_DICT_SEARCH`), whose content is a
/// segment before the prefix: its matches and repcodes may be there, and a
/// match there may run on into the prefix. Returns the size of the
/// literals left after the last sequence.
#[allow(clippy::too_many_lines)]
fn zstd_compress_block_lazy_generic<
    const SEARCH: u8,
    const DEPTH: u32,
    const MLS: u32,
    const DICT_MODE: u8,
>(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dms: Option<DictMatchState<'_>>,
    istart: usize,
    iend: usize,
) -> usize {
    let is_dxs = DICT_MODE == DICT_MATCH_STATE || DICT_MODE == DEDICATED_DICT_SEARCH;
    debug_assert!(DICT_MODE != EXT_DICT);
    debug_assert!(is_dxs == dms.is_some());
    let mut ip = istart;
    let mut anchor = istart;
    // Before the block for small blocks, where libzstd's pointer goes
    // before the buffer and the search ends at once. The row match finder
    // hashes positions ahead, and stops sooner.
    let ilimit = iend as i64 - 8 - row_hash_lookahead::<SEARCH>();
    let base = ms.window.base;
    let prefix_lowest_index = ms.window.dict_limit;
    let prefix_lowest = (i64::from(prefix_lowest_index) - base) as usize;

    // The attached CDict's content, where index i of its window is byte
    // i - dict_base: where it starts and ends there, and dictIndexDelta,
    // what its indices take to be the frame's. Its end is right before the
    // frame's prefix, in the frame's indices.
    let (dict, dict_base, dict_lowest, dict_end, dict_index_delta) = match dms {
        Some(dms) if is_dxs => {
            let window = &dms.ms.window;
            (
                dms.content,
                window.base,
                (i64::from(window.dict_limit) - window.base) as usize,
                (window.next_src - window.base) as usize,
                prefix_lowest_index.wrapping_sub(window.next_src as u32),
            )
        }
        _ => (&[][..], 0, 0, 0, 0),
    };
    let dict_and_prefix_length = (ip - prefix_lowest) + (dict_end - dict_lowest);

    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];
    let mut offset_saved1 = 0;
    let mut offset_saved2 = 0;

    ip += usize::from(dict_and_prefix_length == 0);
    if DICT_MODE == NO_DICT {
        let curr = ms.window.index(ip);
        let window_low = ms.lowest_prefix_index(curr, ms.c_params.window_log);
        let max_rep = curr - window_low;
        if offset_2 > max_rep {
            offset_saved2 = offset_2;
            offset_2 = 0;
        }
        if offset_1 > max_rep {
            offset_saved1 = offset_1;
            offset_1 = 0;
        }
    }
    if is_dxs {
        // The repcodes reach into the CDict at most, and none is 0: those
        // of the CDict are within its content, and every match found since
        // within it or the prefix. The checks below count on it.
        debug_assert!(offset_1 as usize <= dict_and_prefix_length);
        debug_assert!(offset_2 as usize <= dict_and_prefix_length);
    }

    // Reset the lazy skipping state.
    ms.lazy_skipping = false;

    if SEARCH == SEARCH_ROW_HASH {
        row_fill_hash_cache::<MLS>(ms, src, ms.next_to_update, ilimit);
    }

    // Where index `i` of the frame is, with a CDict attached: before the
    // prefix, in the CDict's content; its position there, and where its
    // segment ends.
    let locate = |i: u32| {
        if i < prefix_lowest_index {
            (
                dict,
                (i64::from(i.wrapping_sub(dict_index_delta)) - dict_base) as usize,
                dict_end,
            )
        } else {
            (src, (i64::from(i) - base) as usize, iend)
        }
    };
    // The repcode `offset` at `at`: its length, or 0. With a CDict
    // attached, it may be in its content, with its 4 bytes in one segment,
    // and run on into the prefix.
    let rep_at = |at: usize, offset: u32| {
        if is_dxs {
            let rep_index = ((at as i64 + base) as u32).wrapping_sub(offset);
            if zstd_index_overlap_check(prefix_lowest_index, rep_index) {
                let (rbuf, rpos, rep_end) = locate(rep_index);
                if mem_read32(rbuf, rpos) == mem_read32(src, at) {
                    return zstd_count_2segments(
                        src,
                        at + 4,
                        rbuf,
                        rpos + 4,
                        iend,
                        rep_end,
                        prefix_lowest,
                    ) + 4;
                }
            }
            0
        } else if offset > 0 && mem_read32(src, at - offset as usize) == mem_read32(src, at) {
            zstd_count(src, at + 4, at + 4 - offset as usize, iend) + 4
        } else {
            0
        }
    };

    'match_loop: while (ip as i64) < ilimit {
        let mut match_length = 0;
        let mut off_base = REPCODE1_TO_OFFBASE;
        let mut start = ip + 1;

        'store: {
            // The repcode at ip + 1.
            let rep_length = rep_at(ip + 1, offset_1);
            if rep_length != 0 {
                match_length = rep_length;
                if DEPTH == 0 {
                    break 'store;
                }
            }

            // The first search (depth 0).
            {
                let (ml2, off_found) =
                    search_max::<SEARCH, MLS, DICT_MODE>(ms, src, &[], dms, ip, iend);
                if ml2 > match_length {
                    match_length = ml2;
                    start = ip;
                    off_base = off_found;
                }
            }

            if match_length < 4 {
                // Faster over input without matches.
                let step = ((ip - anchor) >> K_SEARCH_STRENGTH) + 1;
                ip += step;
                // Past steps of 8, about 2 KB without a match, only the
                // positions searched go into the tables.
                ms.lazy_skipping = step > K_LAZY_SKIPPING_STEP;
                continue 'match_loop;
            }

            // A better match at the next positions.
            if DEPTH >= 1 {
                while (ip as i64) < ilimit {
                    ip += 1;
                    let ml_rep = rep_at(ip, offset_1);
                    if ml_rep >= 4 && gain(ml_rep, 3, 1, 0) > gain(match_length, 3, off_base, 1) {
                        match_length = ml_rep;
                        off_base = REPCODE1_TO_OFFBASE;
                        start = ip;
                    }
                    {
                        let (ml2, off_candidate) =
                            search_max::<SEARCH, MLS, DICT_MODE>(ms, src, &[], dms, ip, iend);
                        if ml2 >= 4
                            && gain(ml2, 4, off_candidate, 0) > gain(match_length, 4, off_base, 4)
                        {
                            match_length = ml2;
                            off_base = off_candidate;
                            start = ip;
                            // And one better still.
                            continue;
                        }
                    }

                    // An even better one.
                    if DEPTH == 2 && (ip as i64) < ilimit {
                        ip += 1;
                        let ml_rep = rep_at(ip, offset_1);
                        if ml_rep >= 4 && gain(ml_rep, 4, 1, 0) > gain(match_length, 4, off_base, 1)
                        {
                            match_length = ml_rep;
                            off_base = REPCODE1_TO_OFFBASE;
                            start = ip;
                        }
                        let (ml2, off_candidate) =
                            search_max::<SEARCH, MLS, DICT_MODE>(ms, src, &[], dms, ip, iend);
                        if ml2 >= 4
                            && gain(ml2, 4, off_candidate, 0) > gain(match_length, 4, off_base, 7)
                        {
                            match_length = ml2;
                            off_base = off_candidate;
                            start = ip;
                            continue;
                        }
                    }
                    // Nothing better: the match found.
                    break;
                }
            }

            // Catch up: within the prefix, or with a CDict attached within
            // the match's segment.
            if offbase_is_offset(off_base) {
                let offset = offbase_to_offset(off_base);
                if is_dxs {
                    let match_index = ((start as i64 + base) as u32).wrapping_sub(offset);
                    let (mbuf, mut m, _) = locate(match_index);
                    let m_start = if match_index < prefix_lowest_index {
                        dict_lowest
                    } else {
                        prefix_lowest
                    };
                    while start > anchor && m > m_start && src[start - 1] == mbuf[m - 1] {
                        start -= 1;
                        m -= 1;
                        match_length += 1;
                    }
                } else {
                    let offset = offset as usize;
                    while start > anchor
                        && start - offset > prefix_lowest
                        && src[start - 1] == src[start - offset - 1]
                    {
                        start -= 1;
                        match_length += 1;
                    }
                }
                offset_2 = offset_1;
                offset_1 = offset;
            }
        }

        // _storeSequence
        seq_store.store_seq(src, anchor, start - anchor, off_base, match_length);
        ip = start + match_length;
        anchor = ip;
        if ms.lazy_skipping {
            // A match: out of the lazy skipping mode, with the hash cache
            // filled again.
            if SEARCH == SEARCH_ROW_HASH {
                row_fill_hash_cache::<MLS>(ms, src, ms.next_to_update, ilimit);
            }
            ms.lazy_skipping = false;
        }

        // Immediate repcodes.
        if is_dxs {
            // In the CDict's content too.
            while (ip as i64) <= ilimit {
                let rep_length = rep_at(ip, offset_2);
                if rep_length == 0 {
                    break;
                }
                // Swap offset_2 and offset_1.
                std::mem::swap(&mut offset_1, &mut offset_2);
                seq_store.store_seq(src, anchor, 0, REPCODE1_TO_OFFBASE, rep_length);
                ip += rep_length;
                anchor = ip;
            }
        } else {
            while (ip as i64) <= ilimit && offset_2 > 0 {
                if mem_read32(src, ip) != mem_read32(src, ip - offset_2 as usize) {
                    break;
                }
                match_length = zstd_count(src, ip + 4, ip + 4 - offset_2 as usize, iend) + 4;
                // Swap offset_2 and offset_1.
                std::mem::swap(&mut offset_1, &mut offset_2);
                seq_store.store_seq(src, anchor, 0, REPCODE1_TO_OFFBASE, match_length);
                ip += match_length;
                anchor = ip;
            }
        }
    }

    // Without a dictionary, the repcodes outside the prefix were set to
    // zero before the loop; those still zero are restored, as in the fast
    // strategy. With a CDict attached, none was.
    offset_saved2 = if offset_saved1 != 0 && offset_1 != 0 {
        offset_saved1
    } else {
        offset_saved2
    };

    // The repcodes for the next block.
    rep[0] = if offset_1 != 0 {
        offset_1
    } else {
        offset_saved1
    };
    rep[1] = if offset_2 != 0 {
        offset_2
    } else {
        offset_saved2
    };

    // The size of the last literals.
    iend - anchor
}

/// `ZSTD_compressBlock_lazy_extDict_generic`: as the parser without a
/// dictionary, with matches in the window's older segment too, `dict`; a
/// match there may run on into the prefix.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn zstd_compress_block_lazy_ext_dict_generic<const SEARCH: u8, const DEPTH: u32, const MLS: u32>(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: &[u8],
    istart: usize,
    iend: usize,
) -> usize {
    let mut ip = istart;
    let mut anchor = istart;
    let ilimit = iend as i64 - 8 - row_hash_lookahead::<SEARCH>();
    let base = ms.window.base;
    let dict_base = ms.window.dict_base;
    let dict_limit = ms.window.dict_limit;
    let prefix_start = (i64::from(dict_limit) - base) as usize;
    let dict_end = (i64::from(dict_limit) - dict_base) as usize;
    let dict_start = (i64::from(ms.window.low_limit) - dict_base) as usize;
    let window_log = ms.c_params.window_log;

    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];

    // Reset the lazy skipping state.
    ms.lazy_skipping = false;

    ip += usize::from(ip == prefix_start);
    if SEARCH == SEARCH_ROW_HASH {
        row_fill_hash_cache::<MLS>(ms, src, ms.next_to_update, ilimit);
    }

    // Where index `i` is: its segment, its position there, and where the
    // segment ends.
    let locate = |i: u32| {
        if i < dict_limit {
            (dict, (i64::from(i) - dict_base) as usize, dict_end)
        } else {
            (src, (i64::from(i) - base) as usize, iend)
        }
    };
    // The repcode `offset` at `at`, whose index is `curr`: its length, or
    // 0. It is valid within the window, with its 4 bytes in one segment.
    let rep_at = |ms: &MatchState, at: usize, curr: u32, offset: u32| {
        let window_low = ms.lowest_match_index(curr, window_log);
        let rep_index = curr.wrapping_sub(offset);
        if zstd_index_overlap_check(dict_limit, rep_index)
            & (offset <= curr.wrapping_sub(window_low))
        {
            let (rbuf, rpos, rep_end) = locate(rep_index);
            if mem_read32(src, at) == mem_read32(rbuf, rpos) {
                return zstd_count_2segments(
                    src,
                    at + 4,
                    rbuf,
                    rpos + 4,
                    iend,
                    rep_end,
                    prefix_start,
                ) + 4;
            }
        }
        0
    };

    'match_loop: while (ip as i64) < ilimit {
        let mut match_length = 0;
        let mut off_base = REPCODE1_TO_OFFBASE;
        let mut start = ip + 1;
        let mut curr = ms.window.index(ip);

        'store: {
            // The repcode, searching at curr + 1.
            let rep_length = rep_at(ms, ip + 1, curr + 1, offset_1);
            if rep_length != 0 {
                match_length = rep_length;
                if DEPTH == 0 {
                    break 'store;
                }
            }

            // The first search (depth 0).
            {
                let (ml2, off_candidate) =
                    search_max::<SEARCH, MLS, EXT_DICT>(ms, src, dict, None, ip, iend);
                if ml2 > match_length {
                    match_length = ml2;
                    start = ip;
                    off_base = off_candidate;
                }
            }

            if match_length < 4 {
                // Faster over input without matches.
                let step = (ip - anchor) >> K_SEARCH_STRENGTH;
                ip += step + 1;
                // See the parser without a dictionary.
                ms.lazy_skipping = step > K_LAZY_SKIPPING_STEP;
                continue 'match_loop;
            }

            // A better match at the next positions.
            if DEPTH >= 1 {
                while (ip as i64) < ilimit {
                    ip += 1;
                    curr += 1;
                    let rep_length = rep_at(ms, ip, curr, offset_1);
                    if rep_length >= 4
                        && gain(rep_length, 3, 1, 0) > gain(match_length, 3, off_base, 1)
                    {
                        match_length = rep_length;
                        off_base = REPCODE1_TO_OFFBASE;
                        start = ip;
                    }

                    // The search, depth 1.
                    {
                        let (ml2, off_candidate) =
                            search_max::<SEARCH, MLS, EXT_DICT>(ms, src, dict, None, ip, iend);
                        if ml2 >= 4
                            && gain(ml2, 4, off_candidate, 0) > gain(match_length, 4, off_base, 4)
                        {
                            match_length = ml2;
                            off_base = off_candidate;
                            start = ip;
                            // And one better still.
                            continue;
                        }
                    }

                    // An even better one.
                    if DEPTH == 2 && (ip as i64) < ilimit {
                        ip += 1;
                        curr += 1;
                        let rep_length = rep_at(ms, ip, curr, offset_1);
                        if rep_length >= 4
                            && gain(rep_length, 4, 1, 0) > gain(match_length, 4, off_base, 1)
                        {
                            match_length = rep_length;
                            off_base = REPCODE1_TO_OFFBASE;
                            start = ip;
                        }

                        // The search, depth 2.
                        let (ml2, off_candidate) =
                            search_max::<SEARCH, MLS, EXT_DICT>(ms, src, dict, None, ip, iend);
                        if ml2 >= 4
                            && gain(ml2, 4, off_candidate, 0) > gain(match_length, 4, off_base, 7)
                        {
                            match_length = ml2;
                            off_base = off_candidate;
                            start = ip;
                            continue;
                        }
                    }
                    // Nothing better: the match found.
                    break;
                }
            }

            // Catch up, within the match's segment.
            if offbase_is_offset(off_base) {
                let offset = offbase_to_offset(off_base);
                let match_index = ms.window.index(start).wrapping_sub(offset);
                let (mbuf, mut m, _) = locate(match_index);
                let m_start = if match_index < dict_limit {
                    dict_start
                } else {
                    prefix_start
                };
                while start > anchor && m > m_start && src[start - 1] == mbuf[m - 1] {
                    start -= 1;
                    m -= 1;
                    match_length += 1;
                }
                offset_2 = offset_1;
                offset_1 = offset;
            }
        }

        // _storeSequence
        seq_store.store_seq(src, anchor, start - anchor, off_base, match_length);
        ip = start + match_length;
        anchor = ip;
        if ms.lazy_skipping {
            // A match: out of the lazy skipping mode, with the hash cache
            // filled again.
            if SEARCH == SEARCH_ROW_HASH {
                row_fill_hash_cache::<MLS>(ms, src, ms.next_to_update, ilimit);
            }
            ms.lazy_skipping = false;
        }

        // Immediate repcodes.
        while (ip as i64) <= ilimit {
            let rep_length = rep_at(ms, ip, ms.window.index(ip), offset_2);
            if rep_length == 0 {
                break;
            }
            // Swap offset_2 and offset_1.
            std::mem::swap(&mut offset_1, &mut offset_2);
            seq_store.store_seq(src, anchor, 0, REPCODE1_TO_OFFBASE, rep_length);
            ip += rep_length;
            anchor = ip;
        }
    }

    // The repcodes for the next block.
    rep[0] = offset_1;
    rep[1] = offset_2;

    // The size of the last literals.
    iend - anchor
}

// ---------------------------------------------------------------------------
// The block compressors

/// The parser for `DEPTH` and the shortest match, 4 to 6 bytes (libzstd
/// takes 3 as 4 and 7 as 6 here).
#[allow(clippy::too_many_arguments)]
fn lazy<const SEARCH: u8, const DEPTH: u32>(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: Option<&[u8]>,
    istart: usize,
    iend: usize,
) -> usize {
    macro_rules! with_mls {
        ($mls:literal) => {
            match dict {
                None => zstd_compress_block_lazy_generic::<SEARCH, DEPTH, $mls, NO_DICT>(
                    ms, seq_store, rep, src, None, istart, iend,
                ),
                Some(dict) => zstd_compress_block_lazy_ext_dict_generic::<SEARCH, DEPTH, $mls>(
                    ms, seq_store, rep, src, dict, istart, iend,
                ),
            }
        };
    }
    match ms.c_params.min_match.clamp(4, 6) {
        5 => with_mls!(5),
        6 => with_mls!(6),
        _ => with_mls!(4),
    }
}

/// The parser for `DEPTH` and the shortest match, with the attached
/// `CDict` `dms`: its `dedicatedDictSearch` variant when the `CDict`'s
/// tables are laid out for it, its `dictMatchState` one otherwise
/// (`ZSTD_matchState_dictMode`).
#[allow(clippy::too_many_arguments)]
fn lazy_dict_match_state<const SEARCH: u8, const DEPTH: u32>(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dms: DictMatchState<'_>,
    istart: usize,
    iend: usize,
) -> usize {
    macro_rules! with_mls {
        ($mls:literal) => {
            if dms.ms.dedicated_dict_search {
                zstd_compress_block_lazy_generic::<SEARCH, DEPTH, $mls, DEDICATED_DICT_SEARCH>(
                    ms,
                    seq_store,
                    rep,
                    src,
                    Some(dms),
                    istart,
                    iend,
                )
            } else {
                zstd_compress_block_lazy_generic::<SEARCH, DEPTH, $mls, DICT_MATCH_STATE>(
                    ms,
                    seq_store,
                    rep,
                    src,
                    Some(dms),
                    istart,
                    iend,
                )
            }
        };
    }
    match ms.c_params.min_match.clamp(4, 6) {
        5 => with_mls!(5),
        6 => with_mls!(6),
        _ => with_mls!(4),
    }
}

#[cfg(test)]
thread_local! {
    /// For the tests: the blocks this thread compressed with greedy, lazy
    /// or lazy2 and a `CDict` attached, with the hash chain, with the row
    /// match finder, and with the dedicated dictionary search.
    pub(crate) static DICT_MATCH_STATE_BLOCKS: std::cell::Cell<[usize; 3]> =
        const { std::cell::Cell::new([0; 3]) };
}

/// `ZSTD_compressBlock_greedy_dictMatchState`, `_lazy_dictMatchState` and
/// `_lazy2_dictMatchState`, with the hash chain, or with the row match
/// finder (`row`, their `_row` variants); and their `_dedicatedDictSearch`
/// variants for a `CDict` made for it: the sequences of the block
/// `src[istart..iend]` into `seq_store`, with matches in the attached
/// `CDict` `dms` too. Returns the size of the literals left after the last
/// sequence.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_compress_block_lazy_dict_match_state(
    depth: u32,
    row: bool,
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dms: DictMatchState<'_>,
    istart: usize,
    iend: usize,
) -> usize {
    #[cfg(test)]
    DICT_MATCH_STATE_BLOCKS.with(|blocks| {
        let mut counts = blocks.get();
        counts[if dms.ms.dedicated_dict_search {
            2
        } else {
            usize::from(row)
        }] += 1;
        blocks.set(counts);
    });
    macro_rules! with {
        ($search:expr, $depth:literal) => {
            lazy_dict_match_state::<{ $search }, $depth>(ms, seq_store, rep, src, dms, istart, iend)
        };
    }
    match (row, depth) {
        (true, 0) => with!(SEARCH_ROW_HASH, 0),
        (true, 1) => with!(SEARCH_ROW_HASH, 1),
        (true, _) => with!(SEARCH_ROW_HASH, 2),
        (false, 0) => with!(SEARCH_HASH_CHAIN, 0),
        (false, 1) => with!(SEARCH_HASH_CHAIN, 1),
        (false, _) => with!(SEARCH_HASH_CHAIN, 2),
    }
}

/// `ZSTD_compressBlock_greedy_row`, `_lazy_row` and `_lazy2_row`, with the
/// row match finder, and their `_extDict` variants when `dict` is given:
/// the sequences of the block `src[istart..iend]` into `seq_store`.
/// Returns the size of the literals left after the last sequence.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_compress_block_lazy_row(
    depth: u32,
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: Option<&[u8]>,
    istart: usize,
    iend: usize,
) -> usize {
    match depth {
        0 => lazy::<SEARCH_ROW_HASH, 0>(ms, seq_store, rep, src, dict, istart, iend),
        1 => lazy::<SEARCH_ROW_HASH, 1>(ms, seq_store, rep, src, dict, istart, iend),
        _ => lazy::<SEARCH_ROW_HASH, 2>(ms, seq_store, rep, src, dict, istart, iend),
    }
}

/// `ZSTD_compressBlock_greedy`, `_lazy` and `_lazy2`, with the hash chain,
/// and their `_extDict` variants when `dict` is given: the sequences of
/// the block `src[istart..iend]` into `seq_store`. Returns the size of the
/// literals left after the last sequence.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_compress_block_lazy_hc(
    depth: u32,
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: Option<&[u8]>,
    istart: usize,
    iend: usize,
) -> usize {
    match depth {
        0 => lazy::<SEARCH_HASH_CHAIN, 0>(ms, seq_store, rep, src, dict, istart, iend),
        1 => lazy::<SEARCH_HASH_CHAIN, 1>(ms, seq_store, rep, src, dict, istart, iend),
        _ => lazy::<SEARCH_HASH_CHAIN, 2>(ms, seq_store, rep, src, dict, istart, iend),
    }
}

/// `ZSTD_compressBlock_btlazy2`, and `ZSTD_compressBlock_btlazy2_extDict`
/// when `dict` is given: the parser of `lazy2` with the binary tree.
/// Returns the size of the literals left after the last sequence.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_compress_block_btlazy2(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: Option<&[u8]>,
    istart: usize,
    iend: usize,
) -> usize {
    lazy::<SEARCH_BINARY_TREE, 2>(ms, seq_store, rep, src, dict, istart, iend)
}

/// `ZSTD_compressBlock_btlazy2_dictMatchState`: the parser of `lazy2` with
/// the binary tree, the frame attached to a `CDict`, `dms`. The sequences
/// of the block `src[istart..iend]` into `seq_store`. Returns the size of
/// the literals left after the last sequence.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_compress_block_btlazy2_dict_match_state(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dms: DictMatchState<'_>,
    istart: usize,
    iend: usize,
) -> usize {
    lazy_dict_match_state::<SEARCH_BINARY_TREE, 2>(ms, seq_store, rep, src, dms, istart, iend)
}
