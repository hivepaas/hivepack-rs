//! The `dfast` strategy's match finder: port of
//! `compress/zstd_double_fast.c`.
//!
//! Two hash tables: a long one, of 8-byte hashes (the match state's hash
//! table), and a short one of `minMatch`-byte hashes (its chain table).
//! Positions are indices into `src`, the buffer the window's prefix is in,
//! and `dict`, the one its older segment is in; the tables hold window
//! indices, `position + window.base` (or `window.dict_base`). The extDict
//! variant cuts the two segments out of those buffers, and its positions
//! are in the segments. The dictMatchState variant also reads the content
//! of the `CDict` the frame is attached to, at its own indices.

use crate::zstd::common::mem::idx;
use crate::zstd::common::zstd_internal::ZSTD_REP_NUM;
use crate::zstd::compress::zstd_compress_internal::{
    DictMatchState, HASH_READ_SIZE, HashTable, K_SEARCH_STRENGTH, MatchState, REPCODE1_TO_OFFBASE,
    SeqStore, ZSTD_SHORT_CACHE_TAG_BITS, mem_read32, mem_read32_within, mem_read64,
    mem_read64_within, offset_to_offbase, zstd_compare_packed_tags, zstd_count,
    zstd_count_2segments, zstd_hash_ptr, zstd_hash_u64, zstd_index_overlap_check,
    zstd_write_tagged_index,
};

/// `ZSTD_fillDoubleHashTable` for a context
/// (`ZSTD_fillDoubleHashTableForCCtx`), with `ZSTD_dtlm_fast`, the only way
/// libzstd calls it for one: every third position from `nextToUpdate` into
/// both tables, while 8 bytes from the third after it fit before `end`, a
/// position of `src`, the prefix's buffer. `nextToUpdate` stays.
pub(crate) fn zstd_fill_double_hash_table(ms: &mut MatchState, src: &[u8], end: usize) {
    const FAST_HASH_FILL_STEP: i64 = 3;
    let h_bits_l = ms.c_params.hash_log;
    let mls = ms.c_params.min_match;
    let h_bits_s = ms.c_params.chain_log;
    let base = ms.window.base;
    let mut ip = i64::from(ms.next_to_update) - base;
    debug_assert!(ip >= 0);
    // libzstd's iend, end - HASH_READ_SIZE, which can be before the buffer.
    let iend = end as i64 - HASH_READ_SIZE as i64;
    while ip + FAST_HASH_FILL_STEP - 1 <= iend {
        let curr = (ip + base) as u32;
        // With ZSTD_dtlm_fast, only the first of every three positions, in
        // both tables.
        let sm_hash = zstd_hash_ptr(src, ip as usize, h_bits_s, mls);
        let lg_hash = zstd_hash_ptr(src, ip as usize, h_bits_l, 8);
        ms.chain_table[sm_hash] = curr;
        ms.hash_table[lg_hash] = curr;
        ip += FAST_HASH_FILL_STEP;
    }
}

/// `ZSTD_fillDoubleHashTable` for a `CDict`
/// (`ZSTD_fillDoubleHashTableForCDict`), with `ZSTD_dtlm_full`, the only way
/// libzstd calls it for one: every third position from `nextToUpdate` into
/// both tables, and the two after it into the long one where their entry
/// is still empty, while 8 bytes from the third fit before `end`, a
/// position of `src`, the buffer of the `CDict`'s window. The entries hold
/// tagged indices (see [`ZSTD_SHORT_CACHE_TAG_BITS`]). `nextToUpdate`
/// stays.
pub(crate) fn zstd_fill_double_hash_table_for_cdict(ms: &mut MatchState, src: &[u8], end: usize) {
    const FAST_HASH_FILL_STEP: i64 = 3;
    let h_bits_l = ms.c_params.hash_log + ZSTD_SHORT_CACHE_TAG_BITS;
    let mls = ms.c_params.min_match;
    let h_bits_s = ms.c_params.chain_log + ZSTD_SHORT_CACHE_TAG_BITS;
    let base = ms.window.base;
    let mut ip = i64::from(ms.next_to_update) - base;
    debug_assert!(ip >= 0);
    // libzstd's iend, end - HASH_READ_SIZE, which can be before the buffer.
    let iend = end as i64 - HASH_READ_SIZE as i64;
    let MatchState {
        hash_table: hash_large,
        chain_table: hash_small,
        ..
    } = ms;
    while ip + FAST_HASH_FILL_STEP - 1 <= iend {
        let curr = (ip + base) as u32;
        for i in 0..FAST_HASH_FILL_STEP {
            let at = (ip + i) as usize;
            let sm_hash_and_tag = zstd_hash_ptr(src, at, h_bits_s, mls);
            let lg_hash_and_tag = zstd_hash_ptr(src, at, h_bits_l, 8);
            if i == 0 {
                zstd_write_tagged_index(hash_small, sm_hash_and_tag, curr);
            }
            if i == 0 || hash_large[lg_hash_and_tag >> ZSTD_SHORT_CACHE_TAG_BITS] == 0 {
                zstd_write_tagged_index(hash_large, lg_hash_and_tag, curr + i as u32);
            }
        }
        ip += FAST_HASH_FILL_STEP;
    }
}

/// How the inner search loop ended: which test found a match. `hl1` is
/// the long hash of the next position.
enum Found {
    /// The repcode, at the next position.
    Rep,
    /// A long match, at `matchl0`.
    Long { matchl0: usize, hl1: usize },
    /// A short match, at `matchs0`.
    Short { matchs0: usize, hl1: usize },
    /// The end of the block.
    End,
}

/// How the extDict search loop ended: which test found a match, with the
/// index of the candidate.
enum FoundExt {
    /// The repcode, at the next position.
    Rep,
    /// A long match.
    Long(u32),
    /// A short match; a long one at the next position is tried after.
    Short(u32),
    /// The end of the block.
    End,
}

/// `ZSTD_compressBlock_doubleFast_noDict_generic`: the sequences of the
/// block `src[istart..iend]` into `seq_store`. Returns the size of the
/// literals left after the last sequence.
///
/// libzstd tests its candidates without branching on whether they are in
/// the window, reading from a dummy array when they are not
/// (`ZSTD_selectAddr`); that gives the same answers as testing the window
/// first: a long candidate counts from `prefixLowestIndex` on, the long
/// candidate at the next position only above it.
#[allow(clippy::too_many_lines)]
fn zstd_compress_block_double_fast_no_dict_generic<const MLS: u32>(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    istart: usize,
    iend: usize,
) -> usize {
    // The shortest match, a constant in each copy, as libzstd's templates
    // make it.
    let mls = MLS;
    let c_params = ms.c_params;
    let h_bits_l = c_params.hash_log;
    let h_bits_s = c_params.chain_log;
    let base = ms.window.base;
    let mut anchor = istart;
    let end_index = ms.window.index(iend);
    // With a dictionary, it would be attached.
    let prefix_lowest_index = ms.lowest_prefix_index(end_index, c_params.window_log);
    let prefix_lowest = (i64::from(prefix_lowest_index) - base) as usize;
    // Before the block for blocks under 8 bytes, where libzstd's pointer
    // goes before the buffer and the search ends at once; 0 does the same.
    let ilimit = iend.saturating_sub(HASH_READ_SIZE);
    // Differs from libzstd: the search loop tests `ip1 <= ilimit` as
    // whether 8 bytes fit at ip1 in the block, the same test as the bounds
    // check of the read there, which the compiler then drops. It gives the
    // same answers, for blocks under 8 bytes too.
    let block = &src[..iend];
    let in_limit = |position: usize| idx(position) + HASH_READ_SIZE <= block.len();
    // Differs from libzstd: the candidates at ip are read from the prefix,
    // at their index less prefix_lowest_index, so that one test tells both
    // whether they are in the window and whether the bytes are there. An
    // index below the window wraps past the prefix's end, as end_index is
    // under 2^32; one in it is before ip, so its bytes are there.
    let prefix = &src[prefix_lowest..iend];
    let in_prefix = |index: u32| index.wrapping_sub(prefix_lowest_index) as usize;
    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];
    let mut offset_saved1 = 0;
    let mut offset_saved2 = 0;

    // How many positions to search before taking bigger steps.
    let k_step_incr = 1usize << K_SEARCH_STRENGTH;

    let index = |position: usize| (position as i64 + base) as u32;
    let at = |index: u32| (i64::from(index) - base) as usize;

    // The current position.
    let mut ip = istart;

    // Initialization.
    ip += usize::from(ip == prefix_lowest);
    {
        let current = index(ip);
        let window_low = ms.lowest_prefix_index(current, c_params.window_log);
        let max_rep = current.wrapping_sub(window_low);
        if offset_2 > max_rep {
            offset_saved2 = offset_2;
            offset_2 = 0;
        }
        if offset_1 > max_rep {
            offset_saved1 = offset_1;
            offset_1 = 0;
        }
    }

    let mut hash_long = HashTable::new(&mut ms.hash_table, h_bits_l);
    let mut hash_small = HashTable::new(&mut ms.chain_table, h_bits_s);

    // The outer loop: one turn per match found and stored.
    'outer: loop {
        // The current step size.
        let mut step = 1;
        // Where to take a bigger step if no match is found.
        let mut next_step = ip + k_step_incr;
        // The next position.
        let mut ip1 = ip + step;

        if !in_limit(ip1) {
            break;
        }

        // Differs from libzstd: the 8 bytes at ip and at ip1 are read once
        // each, those at ip1 kept for when it becomes ip; the 4 bytes at
        // ip and at ip + 1 are taken from those at ip.
        let mut val0 = mem_read64(block, ip);
        let mut val1 = mem_read64(block, ip1);

        // The long hash at ip.
        let mut hl0 = hash_long.hash_u64(val0, 8);
        let mut curr;

        // How far back the repcode is. Differs from libzstd, which tests
        // that offset_1 is not 0: for 0, the repcode is read at
        // ip + 1 + iend, past the block, where no bytes are and no match is
        // found. The compiler then makes one search loop instead of two.
        let rep_back = if offset_1 > 0 {
            offset_1 as usize
        } else {
            iend.wrapping_neg()
        };

        // The inner loop: one turn per position searched, until a test
        // finds a match.
        let found = loop {
            // The long candidate at ip. Differs from libzstd: it is read
            // here instead of as the candidate at ip1 of the position
            // before, which only the short match needs; no write to the
            // table comes in between.
            let idxl0 = hash_long.get(hl0);
            let hs0 = hash_small.hash_u64(val0, mls);
            let idxs0 = hash_small.get(hs0);
            curr = index(ip);

            // Update the hash tables.
            hash_long.set(hl0, curr);
            hash_small.set(hs0, curr);

            // The repcode, without a dictionary.
            if mem_read32_within(block, (ip + 1).wrapping_sub(rep_back)) == Some((val0 >> 8) as u32)
            {
                break Found::Rep;
            }

            // The long hash at ip1.
            let hl1 = hash_long.hash_u64(val1, 8);

            // A long match in the prefix.
            if mem_read64_within(prefix, in_prefix(idxl0)) == Some(val0) {
                break Found::Long {
                    matchl0: at(idxl0),
                    hl1,
                };
            }

            // A short match in the prefix.
            if mem_read32_within(prefix, in_prefix(idxs0)) == Some(val0 as u32) {
                break Found::Short {
                    matchs0: at(idxs0),
                    hl1,
                };
            }

            if ip1 >= next_step {
                step += 1;
                next_step += k_step_incr;
            }
            ip = ip1;
            ip1 += step;

            hl0 = hl1;
            val0 = val1;

            if !in_limit(ip1) {
                break Found::End;
            }
            val1 = mem_read64(block, ip1);
        };

        let m_length = 'match_stored: {
            // The match, and its length so far.
            let (mut match_pos, mut m_length, hl1) = match found {
                Found::End => break 'outer,
                Found::Rep => {
                    let m_length =
                        zstd_count(src, ip + 1 + 4, ip + 1 + 4 - offset_1 as usize, iend) + 4;
                    ip += 1;
                    seq_store.store_seq(src, anchor, ip - anchor, REPCODE1_TO_OFFBASE, m_length);
                    break 'match_stored m_length;
                }
                Found::Long { matchl0, hl1 } => {
                    let m_length = zstd_count(src, ip + 8, matchl0 + 8, iend) + 8;
                    (matchl0, m_length, hl1)
                }
                Found::Short { mut matchs0, hl1 } => {
                    // The long candidate at ip1.
                    let idxl1 = hash_long.get(hl1);

                    // _search_next_long: a short match; try a longer one.
                    let mut m_length = zstd_count(src, ip + 4, matchs0 + 4, iend) + 4;

                    // A long match at the next position.
                    if idxl1 > prefix_lowest_index && mem_read64(src, at(idxl1)) == val1 {
                        let matchl1 = at(idxl1);
                        let l1len = zstd_count(src, ip1 + 8, matchl1 + 8, iend) + 8;
                        if l1len > m_length {
                            // Take the long match instead.
                            ip = ip1;
                            m_length = l1len;
                            matchs0 = matchl1;
                        }
                    }
                    (matchs0, m_length, hl1)
                }
            };
            let offset = (ip - match_pos) as u32;

            // Catch up. Differs from libzstd: one loop for both kinds of
            // match.
            while (ip > anchor) & (match_pos > prefix_lowest) && src[ip - 1] == src[match_pos - 1] {
                ip -= 1;
                match_pos -= 1;
                m_length += 1;
            }

            // _match_found: needs ip, offset, m_length.
            offset_2 = offset_1;
            offset_1 = offset;

            if step < 4 {
                // Writing ip1 back is unsafe once it is at or past where
                // the match ends; with a step under 4, the distance from
                // ip to ip1, and matches of 4 bytes at least, it is
                // before.
                hash_long.set(hl1, index(ip1));
            }

            seq_store.store_seq(
                src,
                anchor,
                ip - anchor,
                offset_to_offbase(offset),
                m_length,
            );
            m_length
        };

        // _match_stored
        ip += m_length;
        anchor = ip;

        if ip <= ilimit {
            // Complementary insertion, after the ilimit test, as candidates
            // could be past iend - 8.
            {
                let index_to_insert = curr + 2;
                hash_long.set(hash_long.hash(src, at(index_to_insert), 8), index_to_insert);
                hash_long.set(hash_long.hash(src, ip - 2, 8), index(ip - 2));
                hash_small.set(
                    hash_small.hash(src, at(index_to_insert), mls),
                    index_to_insert,
                );
                hash_small.set(hash_small.hash(src, ip - 1, mls), index(ip - 1));
            }

            // An immediate repcode.
            while ip <= ilimit
                && ((offset_2 > 0)
                    & (mem_read32(src, ip) == mem_read32(src, ip - offset_2 as usize)))
            {
                // Store the sequence.
                let r_length = zstd_count(src, ip + 4, ip + 4 - offset_2 as usize, iend) + 4;
                // Swap offset_2 and offset_1.
                std::mem::swap(&mut offset_1, &mut offset_2);
                hash_small.set(hash_small.hash(src, ip, mls), index(ip));
                hash_long.set(hash_long.hash(src, ip, 8), index(ip));
                seq_store.store_seq(src, anchor, 0, REPCODE1_TO_OFFBASE, r_length);
                ip += r_length;
                anchor = ip;
            }
        }
    }

    // _cleanup: if offset_1 started invalid (offsetSaved1 != 0) and became
    // valid (offset_1 != 0), rotate the saved offsets; see the fast
    // strategy.
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

/// `ZSTD_compressBlock_doubleFast`, without a dictionary: dispatches on the
/// shortest match, 4 to 7 bytes (3 counts as 4).
pub(crate) fn zstd_compress_block_double_fast(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    istart: usize,
    iend: usize,
) -> usize {
    let f = match ms.c_params.min_match {
        5 => zstd_compress_block_double_fast_no_dict_generic::<5>,
        6 => zstd_compress_block_double_fast_no_dict_generic::<6>,
        7 => zstd_compress_block_double_fast_no_dict_generic::<7>,
        _ => zstd_compress_block_double_fast_no_dict_generic::<4>,
    };
    f(ms, seq_store, rep, src, istart, iend)
}

/// `ZSTD_compressBlock_doubleFast_extDict_generic`: the sequences of the
/// block, with matches in the window's older segment too, `dict`; a match
/// there may run on into the prefix. Without that segment in reach, the
/// noDict variant.
///
/// Differs from libzstd: the two segments are cut out of their buffers
/// once, and positions are in them; see below. The table reads and writes,
/// in their order, and the sequences are libzstd's.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn zstd_compress_block_double_fast_ext_dict_generic<const MLS: u32>(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: &[u8],
    istart: usize,
    iend: usize,
) -> usize {
    // The shortest match, a constant in each copy, as libzstd's templates
    // make it.
    let mls = MLS;
    let c_params = ms.c_params;
    let h_bits_l = c_params.hash_log;
    let h_bits_s = c_params.chain_log;
    let base = ms.window.base;
    let end_index = ms.window.index(iend);
    let low_limit = ms.lowest_match_index(end_index, c_params.window_log);
    let dict_start_index = low_limit;
    let dict_limit = ms.window.dict_limit;
    let prefix_start_index = dict_limit.max(low_limit);
    let prefix_start = (i64::from(prefix_start_index) - base) as usize;
    let dict_base = ms.window.dict_base;
    let dict_start = (i64::from(dict_start_index) - dict_base) as usize;
    let dict_end = (i64::from(prefix_start_index) - dict_base) as usize;
    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];

    // Back to the noDict variant if the older segment is out of the window.
    if prefix_start_index == dict_start_index {
        return zstd_compress_block_double_fast(ms, seq_store, rep, src, istart, iend);
    }

    // Differs from libzstd: the prefix, up to the block's end, and the
    // older segment are cut out of their buffers, which the window checks
    // hold them, and positions from here on are in them. `ip`, `anchor`
    // and `iend` are libzstd's less prefixStart; a match in the older
    // segment is at its index less dictStartIndex. The bytes read are the
    // same, as libzstd's reads stay in the segments: its counts stop at
    // their ends, its catch-ups at their starts, and for the candidates,
    // see below. The literals are stored from the prefix too, which
    // decides how they are copied against iend, as libzstd's litLimit does;
    // the literals stored are the same either way.
    let prefix = &src[prefix_start..iend];
    let dict_segment = &dict[dict_start..dict_end];
    // Its length, prefixStartIndex - dictStartIndex: not 0, as the noDict
    // variant takes that case.
    let dict_len = dict_segment.len();
    let mut ip = istart - prefix_start;
    let mut anchor = ip;
    let iend = prefix.len();
    // Before the block for blocks under 8 bytes; see the noDict variant.
    let ilimit = iend.saturating_sub(HASH_READ_SIZE);
    let index = |position: usize| (position as u32).wrapping_add(prefix_start_index);
    // Where index `i` is: its segment, its position there, and where the
    // segment ends. Each segment starts at 0, libzstd's lowMatchPtr; a
    // match past the older segment's end goes on at 0 of the prefix,
    // libzstd's prefixStart.
    let locate = |i: u32| {
        if i < prefix_start_index {
            (
                dict_segment,
                i.wrapping_sub(dict_start_index) as usize,
                dict_len,
            )
        } else {
            (prefix, (i - prefix_start_index) as usize, iend)
        }
    };

    // Differs from libzstd: the search loop tests `ip < ilimit` as whether
    // more than 8 bytes are left at ip in the prefix. It is the same test,
    // and the compiler then drops the bounds check of the read at ip.
    let in_limit = |position: usize| idx(position) + HASH_READ_SIZE < prefix.len();
    // Differs from libzstd: a candidate is read from its segment, at its
    // index less the segment's first, so that one test tells both whether
    // it is in the window and whether its bytes are there. Those of the
    // older segment are read from the byte after its start, as libzstd
    // takes the ones above dictStartIndex only; an index at or below it
    // wraps past that slice's end, as indices are under 2^32. As in
    // libzstd, an index below prefixStartIndex is in the older segment.
    //
    // This gives libzstd's answers because a table entry above
    // dictStartIndex is a position with its 8 bytes in its segment. The
    // tables are written only at positions at or before ilimit, iend - 8,
    // in both variants: those searched, the one after a short match, the
    // complementary insertions and the immediate repcodes. The older
    // segment ends where the input before it did, so where its last block
    // did. And an entry in the prefix is a position before ip. libzstd
    // reads no byte past a segment's end then, and neither does the port.
    let dict_candidates = &dict_segment[1..];
    let dict_candidates_len = dict_candidates.len() as u32;
    let candidate = |i: u32| {
        let at = i.wrapping_sub(prefix_start_index);
        if i < prefix_start_index {
            (
                dict_candidates,
                at.wrapping_add(dict_candidates_len) as usize,
            )
        } else {
            (prefix, at as usize)
        }
    };
    // The 4 bytes `offset` back from `position`, where the repcode is.
    // Differs from libzstd: they are read from the prefix if they are all
    // in it, else from the older segment if they are all in it, in place
    // of libzstd's tests of repIndex: in the window, offset <=
    // curr - dictStartIndex, and its 4 bytes in one segment,
    // ZSTD_index_overlap_check. It is the same test. repIndex is in the
    // prefix when offset <= position, and then so are its bytes, as they
    // start at or before `position`, whose 4 bytes are in the prefix
    // wherever this is called.
    // Otherwise it is position + dict_len - offset into the older segment,
    // libzstd's two tests being that it is at least 0 and at most
    // dict_len - 4: the bounds of the read there. An offset past the
    // prefix's start wraps the position past its end, as it is computed
    // on 64 bits, then masked so that the read's end does not overflow;
    // one past the older segment's start wraps past both ends.
    let rep_read = |position: usize, offset: u32| {
        let at = position.wrapping_sub(offset as usize);
        match mem_read32_within(prefix, idx(at)) {
            Some(rep) => Some(rep),
            None => mem_read32_within(dict_segment, idx(at.wrapping_add(dict_len))),
        }
    };

    let mut hash_long = HashTable::new(&mut ms.hash_table, h_bits_l);
    let mut hash_small = HashTable::new(&mut ms.chain_table, h_bits_s);

    // The outer loop: one turn per match found and stored.
    'outer: loop {
        // The search loop: one turn per position searched, until a test
        // finds a match. Differs from libzstd: it only searches; the match
        // is counted and stored after it, as libzstd does after its tests.
        let found = loop {
            // ip < ilimit: < instead of <=, because of ip + 1.
            if !in_limit(ip) {
                break FoundExt::End;
            }
            // Differs from libzstd: the 8 bytes at ip are read once, and
            // the 4 bytes at ip and at ip + 1 (and those of the hash of
            // `mls` bytes) taken from them.
            let val0 = mem_read64(prefix, ip);
            let h_small = hash_small.hash_u64(val0, mls);
            let match_index = hash_small.get(h_small);

            let h_long = hash_long.hash_u64(val0, 8);
            let match_long_index = hash_long.get(h_long);

            let curr = index(ip);
            // Update the hash tables.
            hash_small.set(h_small, curr);
            hash_long.set(h_long, curr);

            // The repcode, searching at curr + 1.
            if rep_read(ip + 1, offset_1) == Some((val0 >> 8) as u32) {
                break FoundExt::Rep;
            }

            // A long match.
            let (segment, at) = candidate(match_long_index);
            if mem_read64_within(segment, at) == Some(val0) {
                break FoundExt::Long(match_long_index);
            }

            // A short match.
            let (segment, at) = candidate(match_index);
            if mem_read32_within(segment, at) == Some(val0 as u32) {
                break FoundExt::Short(match_index);
            }

            ip += ((ip - anchor) >> K_SEARCH_STRENGTH) + 1;
        };

        let curr = index(ip);
        let m_length = match found {
            FoundExt::End => break 'outer,
            FoundExt::Rep => {
                let rep_index = (curr + 1).wrapping_sub(offset_1);
                let (rbuf, rpos, rep_match_end) = locate(rep_index);
                let m_length = zstd_count_2segments(
                    prefix,
                    ip + 1 + 4,
                    rbuf,
                    rpos + 4,
                    iend,
                    rep_match_end,
                    0,
                ) + 4;
                ip += 1;
                seq_store.store_seq(prefix, anchor, ip - anchor, REPCODE1_TO_OFFBASE, m_length);
                m_length
            }
            FoundExt::Long(match_long_index) => {
                let (lbuf, mut lpos, match_end) = locate(match_long_index);
                let mut length =
                    zstd_count_2segments(prefix, ip + 8, lbuf, lpos + 8, iend, match_end, 0) + 8;
                let offset = curr - match_long_index;
                // Catch up.
                while (ip > anchor) & (lpos > 0) && prefix[ip - 1] == lbuf[lpos - 1] {
                    ip -= 1;
                    lpos -= 1;
                    length += 1;
                }
                offset_2 = offset_1;
                offset_1 = offset;
                seq_store.store_seq(
                    prefix,
                    anchor,
                    ip - anchor,
                    offset_to_offbase(offset),
                    length,
                );
                length
            }
            FoundExt::Short(match_index) => {
                let val1 = mem_read64(prefix, ip + 1);
                let h3 = hash_long.hash_u64(val1, 8);
                let match_index3 = hash_long.get(h3);
                let offset;
                let mut length;
                hash_long.set(h3, curr + 1);
                let (segment, at) = candidate(match_index3);
                if mem_read64_within(segment, at) == Some(val1) {
                    let (buf3, mut pos3, match_end) = locate(match_index3);
                    length =
                        zstd_count_2segments(prefix, ip + 9, buf3, pos3 + 8, iend, match_end, 0)
                            + 8;
                    ip += 1;
                    offset = curr + 1 - match_index3;
                    // Catch up.
                    while (ip > anchor) & (pos3 > 0) && prefix[ip - 1] == buf3[pos3 - 1] {
                        ip -= 1;
                        pos3 -= 1;
                        length += 1;
                    }
                } else {
                    let (sbuf, mut spos, match_end) = locate(match_index);
                    length =
                        zstd_count_2segments(prefix, ip + 4, sbuf, spos + 4, iend, match_end, 0)
                            + 4;
                    offset = curr - match_index;
                    // Catch up.
                    while (ip > anchor) & (spos > 0) && prefix[ip - 1] == sbuf[spos - 1] {
                        ip -= 1;
                        spos -= 1;
                        length += 1;
                    }
                }
                offset_2 = offset_1;
                offset_1 = offset;
                seq_store.store_seq(
                    prefix,
                    anchor,
                    ip - anchor,
                    offset_to_offbase(offset),
                    length,
                );
                length
            }
        };

        // The next sequence starts after the match.
        ip += m_length;
        anchor = ip;

        if ip <= ilimit {
            // Complementary insertion, after the ilimit test, as candidates
            // could be past iend - 8.
            {
                let index_to_insert = curr + 2;
                let at = (index_to_insert - prefix_start_index) as usize;
                hash_long.set(hash_long.hash(prefix, at, 8), index_to_insert);
                hash_long.set(hash_long.hash(prefix, ip - 2, 8), index(ip - 2));
                hash_small.set(hash_small.hash(prefix, at, mls), index_to_insert);
                hash_small.set(hash_small.hash(prefix, ip - 1, mls), index(ip - 1));
            }

            // An immediate repcode.
            while ip <= ilimit && rep_read(ip, offset_2) == Some(mem_read32(prefix, ip)) {
                let current2 = index(ip);
                let rep_index2 = current2.wrapping_sub(offset_2);
                let (rbuf, rpos, rep_end2) = locate(rep_index2);
                let rep_length2 =
                    zstd_count_2segments(prefix, ip + 4, rbuf, rpos + 4, iend, rep_end2, 0) + 4;
                // Swap offset_2 and offset_1.
                std::mem::swap(&mut offset_1, &mut offset_2);
                seq_store.store_seq(prefix, anchor, 0, REPCODE1_TO_OFFBASE, rep_length2);
                hash_small.set(hash_small.hash(prefix, ip, mls), current2);
                hash_long.set(hash_long.hash(prefix, ip, 8), current2);
                ip += rep_length2;
                anchor = ip;
            }
        }
    }

    // The repcodes for the next block.
    rep[0] = offset_1;
    rep[1] = offset_2;

    // The size of the last literals.
    iend - anchor
}

/// `ZSTD_compressBlock_doubleFast_extDict`: dispatches on the shortest
/// match, 4 to 7 bytes (3 counts as 4).
pub(crate) fn zstd_compress_block_double_fast_ext_dict(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: &[u8],
    istart: usize,
    iend: usize,
) -> usize {
    let f = match ms.c_params.min_match {
        5 => zstd_compress_block_double_fast_ext_dict_generic::<5>,
        6 => zstd_compress_block_double_fast_ext_dict_generic::<6>,
        7 => zstd_compress_block_double_fast_ext_dict_generic::<7>,
        _ => zstd_compress_block_double_fast_ext_dict_generic::<4>,
    };
    f(ms, seq_store, rep, src, dict, istart, iend)
}

/// `ZSTD_compressBlock_doubleFast_dictMatchState_generic`: the sequences
/// of the block `src[istart..iend]`, with matches in the window's prefix
/// and in `dms`, the `CDict` the frame is attached to: its two tables, of
/// tagged indices, over its content, which comes right before the prefix
/// in the frame's indices. A match in the dictionary may run on into the
/// prefix. Returns the size of the literals left after the last sequence.
///
/// As in libzstd, at each position: the repcode at the next one; a long
/// match in the prefix, else one in the dictionary; then a short match, in
/// the prefix if its candidate is in the window, else in the dictionary;
/// a short match is followed by a look for a long one at the next
/// position, in the prefix, else in the dictionary. The dictionary's bytes
/// are read only where the tags match (`ZSTD_comparePackedTags`). The
/// repcodes are not checked against the window first: libzstd asserts
/// that they reach no further back than the dictionary's start (see the
/// fast strategy's variant).
///
/// Differs from libzstd: positions are indices into `src`, the prefix's
/// buffer, and into the `CDict`'s content, `dms.content`; libzstd's
/// `dictBase` is `dms.ms.window.base` there. A repcode is read where
/// libzstd reads it, and one out of the content is no match, as in the
/// fast strategy's variant. The 8 bytes at each position searched, and at
/// the one after it for a long match there, are read once, for the hashes
/// and the comparisons; the bytes are the same. The dictionary's tables
/// are not prefetched (`ms->prefetchCDictTables`), which changes nothing
/// they read.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn zstd_compress_block_double_fast_dict_match_state_generic<const MLS: u32>(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dms: DictMatchState<'_>,
    istart: usize,
    iend: usize,
) -> usize {
    // The shortest match, a constant in each copy, as libzstd's templates
    // make it.
    let mls = MLS;
    let c_params = ms.c_params;
    let h_bits_l = c_params.hash_log;
    let h_bits_s = c_params.chain_log;
    let base = ms.window.base;
    // Nothing past the block is read, as in libzstd.
    let src = &src[..iend];
    let mut ip = istart;
    let mut anchor = istart;
    let end_index = ms.window.index(iend);
    // With a dictionary, it is attached: the prefix starts at dictLimit.
    let prefix_lowest_index = ms.lowest_prefix_index(end_index, c_params.window_log);
    let prefix_lowest = (i64::from(prefix_lowest_index) - base) as usize;
    // Before the block for blocks under 8 bytes; see the noDict variant.
    let ilimit = iend.saturating_sub(HASH_READ_SIZE);
    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];

    // The dictionary: its tables, its window over its content (one
    // segment, from dictStartIndex to dictEnd), and how far its indices are
    // below the frame's.
    // Differs from libzstd: an entry's index, the hash with its tag
    // shifted out, is masked with the table's size, which changes none and
    // saves the bounds check.
    let dict_mask_l = (1usize << dms.ms.c_params.hash_log) - 1;
    let dict_mask_s = (1usize << dms.ms.c_params.chain_log) - 1;
    let dict_hash_long = &dms.ms.hash_table[..=dict_mask_l];
    let dict_hash_small = &dms.ms.chain_table[..=dict_mask_s];
    let dict_entry_l = |hash_and_tag: usize| {
        dict_hash_long[(hash_and_tag >> ZSTD_SHORT_CACHE_TAG_BITS) & dict_mask_l]
    };
    let dict_entry_s = |hash_and_tag: usize| {
        dict_hash_small[(hash_and_tag >> ZSTD_SHORT_CACHE_TAG_BITS) & dict_mask_s]
    };
    let dict_start_index = dms.ms.window.dict_limit;
    let dict_base = dms.ms.window.base;
    let dict_end_index = dms.ms.window.next_src as u32;
    let dict_start = (i64::from(dict_start_index) - dict_base) as usize;
    let dict_end = (i64::from(dict_end_index) - dict_base) as usize;
    let dict = &dms.content[..dict_end];
    // The frame's window starts at or past the dictionary's end.
    debug_assert!(prefix_lowest_index >= dict_end_index);
    let dict_index_delta = prefix_lowest_index.wrapping_sub(dict_end_index);
    let dict_h_bits_l = dms.ms.c_params.hash_log + ZSTD_SHORT_CACHE_TAG_BITS;
    let dict_h_bits_s = dms.ms.c_params.chain_log + ZSTD_SHORT_CACHE_TAG_BITS;
    let dict_and_prefix_length = (ip - prefix_lowest + dict_end - dict_start) as u32;

    // A dictionary still attached is within the window.
    debug_assert!(
        u64::from(ms.window.dict_limit) + (1u64 << c_params.window_log) >= u64::from(end_index)
    );

    let index = |position: usize| (position as i64 + base) as u32;
    let at = |index: u32| (i64::from(index) - base) as usize;
    // The position in the content of the dictionary's index `i`.
    let dict_at = |i: u32| (i64::from(i) - dict_base) as usize;
    // Where the frame's index `i` is: its segment, its position there, and
    // where the segment ends; see the fast strategy's variant.
    let locate = |i: u32| {
        if i < prefix_lowest_index {
            let at = i64::from(i) - i64::from(dict_index_delta) - dict_base;
            (dict, at as usize, dict_end)
        } else {
            (src, at(i), iend)
        }
    };
    // The tag in an entry of the dictionary's tables, and its index.
    let tags_match =
        |entry: u32, hash_and_tag: usize| zstd_compare_packed_tags(entry as usize, hash_and_tag);
    let entry_index = |entry: u32| entry >> ZSTD_SHORT_CACHE_TAG_BITS;

    // Init.
    ip += usize::from(dict_and_prefix_length == 0);
    // The repcode checks do not disable a repcode of 0, or one out of
    // reach.
    debug_assert!(offset_1 <= dict_and_prefix_length);
    debug_assert!(offset_2 <= dict_and_prefix_length);

    let mut hash_long = HashTable::new(&mut ms.hash_table, h_bits_l);
    let mut hash_small = HashTable::new(&mut ms.chain_table, h_bits_s);

    // The main search loop: < instead of <=, because of the repcode check
    // at ip + 1.
    'search: while ip < ilimit {
        // The 8 bytes at ip, before ilimit.
        let val0 = mem_read64(src, ip);
        let h2 = hash_long.hash_u64(val0, 8);
        let h = hash_small.hash_u64(val0, mls);
        let dict_hash_and_tag_l = zstd_hash_u64(val0, dict_h_bits_l, 8);
        let dict_hash_and_tag_s = zstd_hash_u64(val0, dict_h_bits_s, mls);
        let dict_match_index_and_tag_l = dict_entry_l(dict_hash_and_tag_l);
        let dict_match_index_and_tag_s = dict_entry_s(dict_hash_and_tag_s);
        let dict_tags_match_l = tags_match(dict_match_index_and_tag_l, dict_hash_and_tag_l);
        let dict_tags_match_s = tags_match(dict_match_index_and_tag_s, dict_hash_and_tag_s);
        let curr = index(ip);
        let match_index_l = hash_long.get(h2);
        let mut match_index_s = hash_small.get(h);
        let rep_index = (curr + 1).wrapping_sub(offset_1);
        // Update the hash tables.
        hash_long.set(h2, curr);
        hash_small.set(h, curr);

        // The match's length, once stored (_match_stored).
        let m_length = 'match_stored: {
            // The repcode.
            let (rbuf, rpos, rep_match_end) = locate(rep_index);
            if zstd_index_overlap_check(prefix_lowest_index, rep_index)
                && mem_read32_within(rbuf, rpos) == Some((val0 >> 8) as u32)
            {
                let m_length = zstd_count_2segments(
                    src,
                    ip + 1 + 4,
                    rbuf,
                    rpos + 4,
                    iend,
                    rep_match_end,
                    prefix_lowest,
                ) + 4;
                ip += 1;
                seq_store.store_seq(src, anchor, ip - anchor, REPCODE1_TO_OFFBASE, m_length);
                break 'match_stored m_length;
            }

            // The match's offset and length, before it is stored
            // (_match_found). ip moves back with the catch-ups.
            let (offset, m_length) = 'match_found: {
                if match_index_l >= prefix_lowest_index
                    && mem_read64(src, at(match_index_l)) == val0
                {
                    // A long match in the prefix.
                    let mut match_long = at(match_index_l);
                    let mut m_length = zstd_count(src, ip + 8, match_long + 8, iend) + 8;
                    let offset = (ip - match_long) as u32;
                    // Catch up.
                    while (ip > anchor) & (match_long > prefix_lowest)
                        && src[ip - 1] == src[match_long - 1]
                    {
                        ip -= 1;
                        match_long -= 1;
                        m_length += 1;
                    }
                    break 'match_found (offset, m_length);
                } else if dict_tags_match_l {
                    // A long match in the dictionary. Its tables hold
                    // positions with 8 bytes in the content, or 0, which is
                    // not above dictStartIndex.
                    let dict_match_index_l = entry_index(dict_match_index_and_tag_l);
                    let mut dict_match_l = dict_at(dict_match_index_l);
                    debug_assert!(dict_match_index_l < dict_end_index);
                    if dict_match_index_l > dict_start_index
                        && mem_read64(dict, dict_match_l) == val0
                    {
                        let mut m_length = zstd_count_2segments(
                            src,
                            ip + 8,
                            dict,
                            dict_match_l + 8,
                            iend,
                            dict_end,
                            prefix_lowest,
                        ) + 8;
                        let offset = curr
                            .wrapping_sub(dict_match_index_l)
                            .wrapping_sub(dict_index_delta);
                        // Catch up.
                        while (ip > anchor) & (dict_match_l > dict_start)
                            && src[ip - 1] == dict[dict_match_l - 1]
                        {
                            ip -= 1;
                            dict_match_l -= 1;
                            m_length += 1;
                        }
                        break 'match_found (offset, m_length);
                    }
                }

                // A short match: its position, in the prefix, or in the
                // dictionary where match_index_s is then below the prefix,
                // as libzstd moves it to the frame's indices.
                let short_match = if match_index_s > prefix_lowest_index {
                    // A short candidate in the prefix.
                    let match0 = at(match_index_s);
                    (mem_read32(src, match0) == val0 as u32).then_some(match0)
                } else if dict_tags_match_s {
                    // A short match in the dictionary.
                    let dict_match_index_s = entry_index(dict_match_index_and_tag_s);
                    let match0 = dict_at(dict_match_index_s);
                    match_index_s = dict_match_index_s.wrapping_add(dict_index_delta);
                    (dict_match_index_s > dict_start_index
                        && mem_read32(dict, match0) == val0 as u32)
                        .then_some(match0)
                } else {
                    None
                };
                let Some(mut match0) = short_match else {
                    ip += ((ip - anchor) >> K_SEARCH_STRENGTH) + 1;
                    continue 'search;
                };

                // _search_next_long. The 8 bytes at ip + 1, at or before
                // ilimit.
                let val1 = mem_read64(src, ip + 1);
                let hl3 = hash_long.hash_u64(val1, 8);
                let dict_hash_and_tag_l3 = zstd_hash_u64(val1, dict_h_bits_l, 8);
                let match_index_l3 = hash_long.get(hl3);
                let dict_match_index_and_tag_l3 = dict_entry_l(dict_hash_and_tag_l3);
                let dict_tags_match_l3 =
                    tags_match(dict_match_index_and_tag_l3, dict_hash_and_tag_l3);
                hash_long.set(hl3, curr + 1);

                if match_index_l3 >= prefix_lowest_index
                    && mem_read64(src, at(match_index_l3)) == val1
                {
                    // A long match in the prefix, at the next position.
                    let mut match_l3 = at(match_index_l3);
                    let mut m_length = zstd_count(src, ip + 9, match_l3 + 8, iend) + 8;
                    ip += 1;
                    let offset = (ip - match_l3) as u32;
                    // Catch up.
                    while (ip > anchor) & (match_l3 > prefix_lowest)
                        && src[ip - 1] == src[match_l3 - 1]
                    {
                        ip -= 1;
                        match_l3 -= 1;
                        m_length += 1;
                    }
                    break 'match_found (offset, m_length);
                } else if dict_tags_match_l3 {
                    // A long match in the dictionary, at the next position.
                    let dict_match_index_l3 = entry_index(dict_match_index_and_tag_l3);
                    let mut dict_match_l3 = dict_at(dict_match_index_l3);
                    debug_assert!(dict_match_index_l3 < dict_end_index);
                    if dict_match_index_l3 > dict_start_index
                        && mem_read64(dict, dict_match_l3) == val1
                    {
                        let mut m_length = zstd_count_2segments(
                            src,
                            ip + 1 + 8,
                            dict,
                            dict_match_l3 + 8,
                            iend,
                            dict_end,
                            prefix_lowest,
                        ) + 8;
                        ip += 1;
                        let offset = (curr + 1)
                            .wrapping_sub(dict_match_index_l3)
                            .wrapping_sub(dict_index_delta);
                        // Catch up.
                        while (ip > anchor) & (dict_match_l3 > dict_start)
                            && src[ip - 1] == dict[dict_match_l3 - 1]
                        {
                            ip -= 1;
                            dict_match_l3 -= 1;
                            m_length += 1;
                        }
                        break 'match_found (offset, m_length);
                    }
                }

                // No long match at the next position: the short match.
                if match_index_s < prefix_lowest_index {
                    // In the dictionary.
                    let mut m_length = zstd_count_2segments(
                        src,
                        ip + 4,
                        dict,
                        match0 + 4,
                        iend,
                        dict_end,
                        prefix_lowest,
                    ) + 4;
                    let offset = curr.wrapping_sub(match_index_s);
                    // Catch up.
                    while (ip > anchor) & (match0 > dict_start) && src[ip - 1] == dict[match0 - 1] {
                        ip -= 1;
                        match0 -= 1;
                        m_length += 1;
                    }
                    (offset, m_length)
                } else {
                    // In the prefix.
                    let mut m_length = zstd_count(src, ip + 4, match0 + 4, iend) + 4;
                    let offset = (ip - match0) as u32;
                    // Catch up.
                    while (ip > anchor) & (match0 > prefix_lowest) && src[ip - 1] == src[match0 - 1]
                    {
                        ip -= 1;
                        match0 -= 1;
                        m_length += 1;
                    }
                    (offset, m_length)
                }
            };

            // _match_found
            offset_2 = offset_1;
            offset_1 = offset;
            seq_store.store_seq(
                src,
                anchor,
                ip - anchor,
                offset_to_offbase(offset),
                m_length,
            );
            m_length
        };

        // _match_stored
        ip += m_length;
        anchor = ip;

        if ip <= ilimit {
            // Complementary insertion, after the ilimit test, as candidates
            // could be past iend - 8.
            {
                let index_to_insert = curr + 2;
                hash_long.set(hash_long.hash(src, at(index_to_insert), 8), index_to_insert);
                hash_long.set(hash_long.hash(src, ip - 2, 8), index(ip - 2));
                hash_small.set(
                    hash_small.hash(src, at(index_to_insert), mls),
                    index_to_insert,
                );
                hash_small.set(hash_small.hash(src, ip - 1, mls), index(ip - 1));
            }

            // An immediate repcode.
            while ip <= ilimit {
                let current2 = index(ip);
                let rep_index2 = current2.wrapping_sub(offset_2);
                let (rbuf, rpos, rep_end2) = locate(rep_index2);
                if zstd_index_overlap_check(prefix_lowest_index, rep_index2)
                    && mem_read32_within(rbuf, rpos) == Some(mem_read32(src, ip))
                {
                    let rep_length2 = zstd_count_2segments(
                        src,
                        ip + 4,
                        rbuf,
                        rpos + 4,
                        iend,
                        rep_end2,
                        prefix_lowest,
                    ) + 4;
                    // Swap offset_2 and offset_1.
                    std::mem::swap(&mut offset_1, &mut offset_2);
                    seq_store.store_seq(src, anchor, 0, REPCODE1_TO_OFFBASE, rep_length2);
                    hash_small.set(hash_small.hash(src, ip, mls), current2);
                    hash_long.set(hash_long.hash(src, ip, 8), current2);
                    ip += rep_length2;
                    anchor = ip;
                    continue;
                }
                break;
            }
        }
    }

    // The repcodes for the next block.
    rep[0] = offset_1;
    rep[1] = offset_2;

    // The size of the last literals.
    iend - anchor
}

/// `ZSTD_compressBlock_doubleFast_dictMatchState`: dispatches on the
/// shortest match, 4 to 7 bytes (3 counts as 4).
pub(crate) fn zstd_compress_block_double_fast_dict_match_state(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dms: DictMatchState<'_>,
    istart: usize,
    iend: usize,
) -> usize {
    let f = match ms.c_params.min_match {
        5 => zstd_compress_block_double_fast_dict_match_state_generic::<5>,
        6 => zstd_compress_block_double_fast_dict_match_state_generic::<6>,
        7 => zstd_compress_block_double_fast_dict_match_state_generic::<7>,
        _ => zstd_compress_block_double_fast_dict_match_state_generic::<4>,
    };
    f(ms, seq_store, rep, src, dms, istart, iend)
}
