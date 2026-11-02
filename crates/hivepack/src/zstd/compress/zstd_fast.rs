//! The `fast` strategy's match finder: port of `compress/zstd_fast.c`.
//!
//! Positions are indices into `src`, the buffer the window's prefix is in,
//! and `dict`, the one its older segment is in; the hash table holds window
//! indices, `position + window.base` (or `window.dict_base`). The
//! dictMatchState variant also reads the content of the `CDict` the frame
//! is attached to, at its own indices.

use crate::zstd::common::mem::idx as mem_idx;
use crate::zstd::common::zstd_internal::ZSTD_REP_NUM;
use crate::zstd::compress::zstd_compress_internal::{
    DictMatchState, HASH_READ_SIZE, HashTable, K_SEARCH_STRENGTH, MatchState, REPCODE1_TO_OFFBASE,
    SeqStore, ZSTD_SHORT_CACHE_TAG_BITS, mem_read32, mem_read32_within, mem_read64,
    offset_to_offbase, zstd_compare_packed_tags, zstd_count, zstd_count_2segments, zstd_hash_ptr,
    zstd_hash_u64, zstd_index_overlap_check, zstd_write_tagged_index,
};

/// `ZSTD_fillHashTable` for a context (`ZSTD_fillHashTableForCCtx`), with
/// `ZSTD_dtlm_fast`, the only way libzstd calls it for one: every third
/// position from `nextToUpdate` into the hash table, while 8 bytes from the
/// next one fit before `end`, a position of `src`, the prefix's buffer.
/// `nextToUpdate` stays.
pub(crate) fn zstd_fill_hash_table(ms: &mut MatchState, src: &[u8], end: usize) {
    const FAST_HASH_FILL_STEP: i64 = 3;
    let h_bits = ms.c_params.hash_log;
    let mls = ms.c_params.min_match;
    let base = ms.window.base;
    let mut ip = i64::from(ms.next_to_update) - base;
    debug_assert!(ip >= 0);
    // libzstd's iend, end - HASH_READ_SIZE, which can be before the buffer.
    let iend = end as i64 - HASH_READ_SIZE as i64;
    while ip + FAST_HASH_FILL_STEP < iend + 2 {
        let curr = (ip + base) as u32;
        let hash0 = zstd_hash_ptr(src, ip as usize, h_bits, mls);
        ms.hash_table[hash0] = curr;
        ip += FAST_HASH_FILL_STEP;
    }
}

/// `ZSTD_fillHashTable` for a `CDict` (`ZSTD_fillHashTableForCDict`), with
/// `ZSTD_dtlm_full`, the only way libzstd calls it for one: every third
/// position from `nextToUpdate`, and the two after it where their entry is
/// still empty, while 8 bytes from the third fit before `end`, a position
/// of `src`, the buffer of the `CDict`'s window. The entries hold tagged
/// indices (see [`ZSTD_SHORT_CACHE_TAG_BITS`]). `nextToUpdate` stays.
pub(crate) fn zstd_fill_hash_table_for_cdict(ms: &mut MatchState, src: &[u8], end: usize) {
    const FAST_HASH_FILL_STEP: i64 = 3;
    let h_bits = ms.c_params.hash_log + ZSTD_SHORT_CACHE_TAG_BITS;
    let mls = ms.c_params.min_match;
    let base = ms.window.base;
    let mut ip = i64::from(ms.next_to_update) - base;
    debug_assert!(ip >= 0);
    // libzstd's iend, end - HASH_READ_SIZE, which can be before the buffer.
    let iend = end as i64 - HASH_READ_SIZE as i64;
    let hash_table = &mut ms.hash_table;
    while ip + FAST_HASH_FILL_STEP < iend + 2 {
        let curr = (ip + base) as u32;
        let hash_and_tag = zstd_hash_ptr(src, ip as usize, h_bits, mls);
        zstd_write_tagged_index(hash_table, hash_and_tag, curr);
        // ZSTD_dtlm_full: the other positions too, where the entry is
        // still empty.
        for p in 1..FAST_HASH_FILL_STEP {
            let hash_and_tag = zstd_hash_ptr(src, (ip + p) as usize, h_bits, mls);
            if hash_table[hash_and_tag >> ZSTD_SHORT_CACHE_TAG_BITS] == 0 {
                zstd_write_tagged_index(hash_table, hash_and_tag, curr + p as u32);
            }
        }
        ip += FAST_HASH_FILL_STEP;
    }
}

/// `ZSTD_compressBlock_fast_noDict_generic`: the sequences of the block
/// `src[istart..iend]` into `seq_store`. Returns the size of the literals
/// left after the last sequence.
///
/// libzstd interleaves the work on the next few positions: hashing one,
/// looking up the next, comparing the one after, two positions at a time,
/// and starts that pipeline again after each match. The port does the same
/// steps in the same order, which the tables and the sequences depend on.
///
/// libzstd's two ways of testing a candidate (`ZSTD_match4Found_cmov` and
/// `_branch`, chosen by the window log) give the same answer: the candidate
/// is in the window and its first 4 bytes are the same.
///
/// Differs from libzstd: the search keeps ip0 and ip2 only, ip1 and ip3
/// being always one after them, and reads the bytes at them through
/// `at0` and `at2`, the 10 bytes from ip0 and from ip2. libzstd's test
/// that ip3 is before ilimit is the test that those from ip2 fit before
/// iend, which makes every read at the four positions one the compiler
/// sees in bounds.
#[allow(clippy::too_many_lines)]
fn zstd_compress_block_fast_no_dict_generic<const MLS: u32>(
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
    let hlog = c_params.hash_log;
    // At least 2.
    let step_size = c_params.target_length as usize + usize::from(c_params.target_length == 0) + 1;
    let base = ms.window.base;
    let end_index = ms.window.index(iend);
    let prefix_start_index = ms.lowest_prefix_index(end_index, c_params.window_log);
    let prefix_start = (i64::from(prefix_start_index) - base) as usize;
    // Nothing past the block is read, as in libzstd; this makes iend the
    // end of `src`, for `fits_hash_window`.
    let src = &src[..iend];
    // Before the block for blocks under 8 bytes, where libzstd's pointer
    // goes before the buffer and the search ends at once; 0 does the same.
    let ilimit = iend.saturating_sub(HASH_READ_SIZE);

    let mut anchor = istart;
    let mut ip0 = istart;
    let mut ip2;
    let mut at0: &[u8];
    let mut at2: &[u8];
    let mut current0: u32;

    let mut rep_offset1 = rep[0];
    let mut rep_offset2 = rep[1];
    let mut offset_saved1 = 0;
    let mut offset_saved2 = 0;

    let mut hash0;
    let mut hash1;
    let mut match_idx: u32;

    let mut offcode: u32;
    let mut match0: usize;
    let mut m_length: usize;

    // ip0 and ip1 are always adjacent. The targetLength skipping and the
    // acceleration over incompressible data apply to every other position,
    // so `step` is the gap between pairs of positions, from ip0 to ip2 or
    // ip1 to ip3.
    let mut step;
    let mut next_step;
    let k_step_incr = 1usize << (K_SEARCH_STRENGTH - 1);
    let index = |position: usize| (position as i64 + base) as u32;
    // ZSTD_match4Found, given the 4 bytes at the current position.
    let match_found = |current: u32, match_idx: u32| {
        match_idx >= prefix_start_index
            && current == mem_read32(src, (i64::from(match_idx) - base) as usize)
    };

    ip0 += usize::from(ip0 == prefix_start);
    {
        let curr = index(ip0);
        let window_low = ms.lowest_prefix_index(curr, c_params.window_log);
        let max_rep = curr.wrapping_sub(window_low);
        if rep_offset2 > max_rep {
            offset_saved2 = rep_offset2;
            rep_offset2 = 0;
        }
        if rep_offset1 > max_rep {
            offset_saved1 = rep_offset1;
            rep_offset1 = 0;
        }
    }

    let mut hash_table = HashTable::new(&mut ms.hash_table, hlog);

    'start: loop {
        // Needs ip0.
        step = step_size;
        next_step = ip0 + k_step_incr;

        // The positions; ip0 - anchor == 0, so no step to work out.
        ip2 = ip0 + step;

        // ip3 at or past ilimit.
        if !fits_hash_window(src, ip2) {
            break 'start;
        }
        at2 = &src[ip2..][..HASH_WINDOW];
        // Before ip2, so in the block too: this test never fails.
        if !fits_hash_window(src, ip0) {
            break 'start;
        }
        at0 = &src[ip0..][..HASH_WINDOW];

        hash0 = hash_table.hash(at0, 0, mls);
        hash1 = hash_table.hash(at0, 1, mls);

        match_idx = hash_table.get(hash0);

        'search: loop {
            let ip1 = ip0 + 1;

            // The repcode match for ip2.
            let rval = mem_read32(src, ip2 - rep_offset1 as usize);

            // Write back the hash table entry.
            current0 = index(ip0);
            hash_table.set(hash0, current0);

            // Check the repcode at ip2.
            if (mem_read32(at2, 0) == rval) & (rep_offset1 > 0) {
                ip0 = ip2;
                match0 = ip0 - rep_offset1 as usize;
                m_length = usize::from(src[ip0 - 1] == src[match0 - 1]);
                ip0 -= m_length;
                match0 -= m_length;
                offcode = REPCODE1_TO_OFFBASE;
                m_length += 4;

                // The next hash table entry, already computed. Safe to
                // write, since ip1 is before the repcode (ip2).
                hash_table.set(hash1, index(ip1));

                break 'search;
            }

            if match_found(mem_read32(at0, 0), match_idx) {
                // The next hash table entry, already computed. Safe since
                // ip1 == ip0 + 1, and the search resumes after ip1.
                hash_table.set(hash1, index(ip1));
                (offcode, match0, m_length) = offset_match(
                    &mut rep_offset1,
                    &mut rep_offset2,
                    src,
                    ip0,
                    match_idx,
                    base,
                    anchor,
                    prefix_start,
                    &mut ip0,
                );
                break 'search;
            }

            // Look up ip1.
            match_idx = hash_table.get(hash1);

            // Hash ip2.
            hash0 = hash1;
            hash1 = hash_table.hash(at2, 0, mls);

            // Advance to the next positions: ip0 to ip1, ip1 to ip2 and ip2
            // to ip3. Until the next advance, libzstd's ip1 is the port's
            // ip2, and the bytes at its ip0 and ip2 are those at 1 in `at0`
            // and `at2`.
            ip0 = ip1;

            // Write back the hash table entry.
            current0 = index(ip0);
            hash_table.set(hash0, current0);

            if match_found(mem_read32(at0, 1), match_idx) {
                // The next hash table entry, already computed. Not written
                // if it is at or past where the search will resume: the
                // shortest match has 4 bytes, so it resumes at ip0 + 4.
                if step <= 4 {
                    // ip1, now.
                    hash_table.set(hash1, index(ip2));
                }
                (offcode, match0, m_length) = offset_match(
                    &mut rep_offset1,
                    &mut rep_offset2,
                    src,
                    ip0,
                    match_idx,
                    base,
                    anchor,
                    prefix_start,
                    &mut ip0,
                );
                break 'search;
            }

            // Look up ip1.
            match_idx = hash_table.get(hash1);

            // Hash ip2.
            hash0 = hash1;
            hash1 = hash_table.hash(at2, 1, mls);

            // Advance to the next positions: ip0 to ip2 (ip1 now), and ip2
            // to ip0 + step.
            ip0 = ip2;
            ip2 = ip0 + step;
            at0 = at2;

            // The step.
            if ip2 >= next_step {
                step += 1;
                next_step += k_step_incr;
            }

            // ip3 at or past ilimit.
            if !fits_hash_window(src, ip2) {
                break 'start;
            }
            at2 = &src[ip2..][..HASH_WINDOW];
        }

        // _match: needs ip0, match0, offcode.

        // The forward length.
        m_length += zstd_count(src, ip0 + m_length, match0 + m_length, iend);

        seq_store.store_seq(src, anchor, ip0 - anchor, offcode, m_length);

        ip0 += m_length;
        anchor = ip0;

        // Fill the table, and check for an immediate repcode.
        if ip0 <= ilimit {
            // Here because current + 2 could be past iend - 8.
            let at = (i64::from(current0 + 2) - base) as usize;
            hash_table.set(hash_table.hash(src, at, mls), current0 + 2);
            hash_table.set(hash_table.hash(src, ip0 - 2, mls), index(ip0 - 2));

            if rep_offset2 > 0 {
                // rep_offset2 == 0 means it is invalid.
                while ip0 <= ilimit
                    && mem_read32(src, ip0) == mem_read32(src, ip0 - rep_offset2 as usize)
                {
                    // Store the sequence.
                    let r_length =
                        zstd_count(src, ip0 + 4, ip0 + 4 - rep_offset2 as usize, iend) + 4;
                    // Swap rep_offset2 and rep_offset1.
                    std::mem::swap(&mut rep_offset1, &mut rep_offset2);
                    hash_table.set(hash_table.hash(src, ip0, mls), index(ip0));
                    ip0 += r_length;
                    seq_store.store_seq(src, anchor, 0, REPCODE1_TO_OFFBASE, r_length);
                    anchor = ip0;
                }
            }
        }
    }

    // _cleanup: a couple of positions could still be searched, but it costs
    // speed for little.

    // The repcodes outside the prefix were set to zero before the loop;
    // those still zero are restored, so that the history stays right. When
    // both were invalid, which to restore: if rep_offset1 became valid, it
    // is rep[0], and offsetSaved1 rep[1].
    offset_saved2 = if offset_saved1 != 0 && rep_offset1 != 0 {
        offset_saved1
    } else {
        offset_saved2
    };

    // The repcodes for the next block.
    rep[0] = if rep_offset1 != 0 {
        rep_offset1
    } else {
        offset_saved1
    };
    rep[1] = if rep_offset2 != 0 {
        rep_offset2
    } else {
        offset_saved2
    };

    // The size of the last literals.
    iend - anchor
}

/// The bytes from ip2 that libzstd's test, ip3 (ip2 + 1) before ilimit
/// (iend - 8), keeps in the block: one more than the hashes at ip2 and ip3
/// read.
const HASH_WINDOW: usize = HASH_READ_SIZE + 2;

/// Whether the `HASH_WINDOW` bytes from `at` are all in `src`: from ip2,
/// with `src` ending at iend, whether ip3 is before ilimit.
#[inline(always)]
fn fits_hash_window(src: &[u8], at: usize) -> bool {
    at <= src.len() && src.len() - at >= HASH_WINDOW
}

/// `_offset`: a match found in the hash table at `match_idx`, extended
/// backwards. Needs ip0 and the index; returns the offset code, the match
/// and its length so far, and moves `ip0` back with it.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn offset_match(
    rep_offset1: &mut u32,
    rep_offset2: &mut u32,
    src: &[u8],
    ip0_in: usize,
    match_idx: u32,
    base: i64,
    anchor: usize,
    prefix_start: usize,
    ip0: &mut usize,
) -> (u32, usize, usize) {
    let mut ip = ip0_in;
    let mut match0 = (i64::from(match_idx) - base) as usize;
    *rep_offset2 = *rep_offset1;
    *rep_offset1 = (ip - match0) as u32;
    let offcode = offset_to_offbase(*rep_offset1);
    let mut m_length = 4;

    // The backwards match length.
    while (ip > anchor) & (match0 > prefix_start) && src[ip - 1] == src[match0 - 1] {
        ip -= 1;
        match0 -= 1;
        m_length += 1;
    }
    *ip0 = ip;
    (offcode, match0, m_length)
}

/// `ZSTD_compressBlock_fast`, without a dictionary: dispatches on the
/// shortest match, 4 to 7 bytes (3 counts as 4).
pub(crate) fn zstd_compress_block_fast(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    istart: usize,
    iend: usize,
) -> usize {
    let f = match ms.c_params.min_match {
        5 => zstd_compress_block_fast_no_dict_generic::<5>,
        6 => zstd_compress_block_fast_no_dict_generic::<6>,
        7 => zstd_compress_block_fast_no_dict_generic::<7>,
        _ => zstd_compress_block_fast_no_dict_generic::<4>,
    };
    f(ms, seq_store, rep, src, istart, iend)
}

/// `ZSTD_compressBlock_fast_extDict_generic`: as the noDict variant, with
/// matches in the window's older segment too, `dict`; a match there may run
/// on into the prefix. Without that segment in reach, the noDict variant.
///
/// Differs from libzstd: the search keeps ip0 and ip2 only and reads the
/// bytes at the four positions through `at0` and `at2`, as the noDict
/// variant does. A candidate or a repcode is read only where its 4 bytes
/// are all in its segment, the older one cut out of `dict` or the prefix,
/// and that test stands for libzstd's tests that it is in the window. The
/// comments in the search say why the answers are the same.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn zstd_compress_block_fast_ext_dict_generic<const MLS: u32>(
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
    let hlog = c_params.hash_log;
    // At least 2.
    let step_size = c_params.target_length as usize + usize::from(c_params.target_length == 0) + 1;
    let base = ms.window.base;
    let dict_base = ms.window.dict_base;
    let mut anchor = istart;
    let end_index = ms.window.index(iend);
    let low_limit = ms.lowest_match_index(end_index, c_params.window_log);
    let dict_start_index = low_limit;
    let dict_start = (i64::from(dict_start_index) - dict_base) as usize;
    let dict_limit = ms.window.dict_limit;
    let prefix_start_index = dict_limit.max(low_limit);
    let prefix_start = (i64::from(prefix_start_index) - base) as usize;
    let dict_end = (i64::from(prefix_start_index) - dict_base) as usize;
    // Before the block for blocks under 8 bytes; see the noDict variant.
    let ilimit = iend.saturating_sub(HASH_READ_SIZE);
    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];
    let mut offset_saved1 = 0;
    let mut offset_saved2 = 0;

    let mut ip0 = istart;
    let mut ip2;
    let mut at0: &[u8];
    let mut at2: &[u8];
    let mut current0: u32;

    let mut hash0;
    let mut hash1;
    // The candidate for ip0.
    let mut idx: u32;

    let mut step;
    let mut next_step;
    let k_step_incr = 1usize << (K_SEARCH_STRENGTH - 1);

    // Back to the noDict variant if the older segment is out of the window.
    if prefix_start_index == dict_start_index {
        return zstd_compress_block_fast(ms, seq_store, rep, src, istart, iend);
    }

    // Nothing past the block is read, as in libzstd; this makes iend the
    // end of `src`, for `fits_hash_window`.
    let src = &src[..iend];
    // The two segments: the older one from dictStart to dictEnd, and the
    // prefix from prefixStart to iend. Each ends where libzstd's matchEnd
    // is, and starts where its lowMatchPtr is. The prefix starts at
    // dictLimit, which here is prefixStartIndex (above lowLimit), at or
    // before the block.
    let dict = &dict[dict_start..dict_end];
    let prefix = &src[prefix_start..];

    let index = |position: usize| (position as i64 + base) as u32;
    // Where index `i` is: its segment, and its position there.
    let locate = |i: u32| {
        if i < prefix_start_index {
            (dict, i.wrapping_sub(dict_start_index) as usize)
        } else {
            (prefix, (i - prefix_start_index) as usize)
        }
    };
    // The 4 bytes at index `i`, if they are all in its segment: the older
    // one if `in_dict`, else the prefix, read in `src` so that the search
    // needs no other slice. An index below dictStartIndex wraps past the
    // older segment's end, as indices are under 2^32 and the segment is
    // shorter. The position in `src` is masked as `mem_read32` does, which
    // changes none from prefixStart on.
    let read_at = |i: u32, in_dict: bool| {
        let (buf, pos) = if in_dict {
            (dict, i.wrapping_sub(dict_start_index) as usize)
        } else {
            (src, mem_idx((i64::from(i) - base) as usize))
        };
        mem_read32_within(buf, pos)
    };

    {
        let curr = index(ip0);
        let max_rep = curr - dict_start_index;
        if offset_2 >= max_rep {
            offset_saved2 = offset_2;
            offset_2 = 0;
        }
        if offset_1 >= max_rep {
            offset_saved1 = offset_1;
            offset_1 = 0;
        }
    }

    let mut hash_table = HashTable::new(&mut ms.hash_table, hlog);

    'start: loop {
        // Needs ip0.
        step = step_size;
        next_step = ip0 + k_step_incr;

        // The positions; ip0 - anchor == 0, so no step to work out.
        ip2 = ip0 + step;

        // ip3 at or past ilimit.
        if !fits_hash_window(src, ip2) {
            break 'start;
        }
        at2 = &src[ip2..][..HASH_WINDOW];
        // Before ip2, so in the block too: this test never fails.
        if !fits_hash_window(src, ip0) {
            break 'start;
        }
        at0 = &src[ip0..][..HASH_WINDOW];

        hash0 = hash_table.hash(at0, 0, mls);
        hash1 = hash_table.hash(at0, 1, mls);

        idx = hash_table.get(hash0);

        // The match: its segment, where it is there, its offset code, its
        // length so far, and libzstd's ip1 when it was found.
        let (mbuf, match0, offcode, mut m_length, ip1) = 'search: loop {
            let ip1 = ip0 + 1;

            // The repcode match for ip2. libzstd reads it where offset_1 is
            // not 0 and the index is not prefixStartIndex nor one of the 3
            // before it. Differs from libzstd: an index up to
            // prefixStartIndex is read in the older segment, which has not
            // 4 bytes at those 4, so the read stands for the second test.
            // Where libzstd reads, so does the port: offset_1 is under the
            // distance from dictStartIndex to the block (tested above) or
            // the offset of a match found since, so the index is past
            // dictStartIndex, and before ip2. That also leaves a byte
            // before the match, for the test below.
            let rep_index = index(ip2).wrapping_sub(offset_1);
            let rval = read_at(rep_index, rep_index <= prefix_start_index);

            // Write back the hash table entry.
            current0 = index(ip0);
            hash_table.set(hash0, current0);

            // Check the repcode at ip2.
            if (offset_1 > 0) & (rval == Some(mem_read32(at2, 0))) {
                let (rbuf, rpos) = locate(rep_index);
                ip0 = ip2;
                let mut match0 = rpos;
                let mut m_length = usize::from(src[ip0 - 1] == rbuf[match0 - 1]);
                ip0 -= m_length;
                match0 -= m_length;
                m_length += 4;
                break 'search (rbuf, match0, REPCODE1_TO_OFFBASE, m_length, ip1);
            }

            // The match for ip0. libzstd reads the candidate from
            // dictStartIndex on. Differs from libzstd: the read in its
            // segment stands for that test. Where libzstd reads, so does
            // the port: every table entry is a position before ip0, hashed
            // when 8 bytes from it were in the input. One in the older
            // segment has its 4 bytes in it; one in the prefix is before
            // ip0.
            if read_at(idx, idx < prefix_start_index) == Some(mem_read32(at0, 0)) {
                let (mbuf, match0, offcode, m_length) = offset_match_ext(
                    &mut offset_1,
                    &mut offset_2,
                    src,
                    &mut ip0,
                    anchor,
                    current0,
                    idx,
                    locate(idx),
                );
                break 'search (mbuf, match0, offcode, m_length, ip1);
            }

            // Look up ip1.
            idx = hash_table.get(hash1);

            // Hash ip2.
            hash0 = hash1;
            hash1 = hash_table.hash(at2, 0, mls);

            // Advance to the next positions: ip0 to ip1, ip1 to ip2 and ip2
            // to ip3. Until the next advance, libzstd's ip1 is the port's
            // ip2, and the bytes at its ip0 and ip2 are those at 1 in `at0`
            // and `at2`.
            ip0 = ip1;

            // Write back the hash table entry.
            current0 = index(ip0);
            hash_table.set(hash0, current0);

            // The match for ip0, as above.
            if read_at(idx, idx < prefix_start_index) == Some(mem_read32(at0, 1)) {
                let (mbuf, match0, offcode, m_length) = offset_match_ext(
                    &mut offset_1,
                    &mut offset_2,
                    src,
                    &mut ip0,
                    anchor,
                    current0,
                    idx,
                    locate(idx),
                );
                // libzstd's ip1, now.
                break 'search (mbuf, match0, offcode, m_length, ip2);
            }

            // Look up ip1.
            idx = hash_table.get(hash1);

            // Hash ip2.
            hash0 = hash1;
            hash1 = hash_table.hash(at2, 1, mls);

            // Advance to the next positions: ip0 to ip2 (ip1 now), and ip2
            // to ip0 + step.
            ip0 = ip2;
            ip2 = ip0 + step;
            at0 = at2;

            // The step.
            if ip2 >= next_step {
                step += 1;
                next_step += k_step_incr;
            }

            // ip3 at or past ilimit.
            if !fits_hash_window(src, ip2) {
                break 'start;
            }
            at2 = &src[ip2..][..HASH_WINDOW];
        };

        // _match: needs ip0, the match and offcode.

        // The forward length.
        m_length += zstd_count_2segments(
            src,
            ip0 + m_length,
            mbuf,
            match0 + m_length,
            iend,
            mbuf.len(),
            prefix_start,
        );

        seq_store.store_seq(src, anchor, ip0 - anchor, offcode, m_length);

        ip0 += m_length;
        anchor = ip0;

        // Write the next hash table entry.
        if ip1 < ip0 {
            hash_table.set(hash1, index(ip1));
        }

        // Fill the table, and check for an immediate repcode.
        if ip0 <= ilimit {
            // Here because current + 2 could be past iend - 8.
            let at = (i64::from(current0 + 2) - base) as usize;
            hash_table.set(hash_table.hash(src, at, mls), current0 + 2);
            hash_table.set(hash_table.hash(src, ip0 - 2, mls), index(ip0 - 2));

            while ip0 <= ilimit {
                // libzstd reads the repcode where offset_2 is not 0 and its
                // 4 bytes are in one segment. Differs from libzstd: the read
                // in its segment stands for the second test, as in the
                // search; prefixStartIndex itself is in the prefix here.
                let rep_index2 = index(ip0).wrapping_sub(offset_2);
                let (rbuf, rpos) = locate(rep_index2);
                if (offset_2 > 0) & (mem_read32_within(rbuf, rpos) == Some(mem_read32(src, ip0))) {
                    let rep_length2 = zstd_count_2segments(
                        src,
                        ip0 + 4,
                        rbuf,
                        rpos + 4,
                        iend,
                        rbuf.len(),
                        prefix_start,
                    ) + 4;
                    // Swap offset_2 and offset_1.
                    std::mem::swap(&mut offset_1, &mut offset_2);
                    seq_store.store_seq(src, anchor, 0, REPCODE1_TO_OFFBASE, rep_length2);
                    hash_table.set(hash_table.hash(src, ip0, mls), index(ip0));
                    ip0 += rep_length2;
                    anchor = ip0;
                    continue;
                }
                break;
            }
        }
    }

    // _cleanup: see the noDict variant.
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

/// `_offset` of the extDict variant: the match at `idx`, found at `ip0`,
/// extended backwards in its segment, which starts at position 0. Returns
/// its segment, its position there, its offset code and its length so far,
/// and moves `ip0` back with it.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn offset_match_ext<'a>(
    offset_1: &mut u32,
    offset_2: &mut u32,
    src: &[u8],
    ip0: &mut usize,
    anchor: usize,
    current0: u32,
    idx: u32,
    (mbuf, mut match0): (&'a [u8], usize),
) -> (&'a [u8], usize, u32, usize) {
    let offset = current0 - idx;
    *offset_2 = *offset_1;
    *offset_1 = offset;
    let offcode = offset_to_offbase(offset);
    let mut m_length = 4;

    // The backwards match length, down to the segment's start.
    let mut ip = *ip0;
    while (ip > anchor) & (match0 > 0) && src[ip - 1] == mbuf[match0 - 1] {
        ip -= 1;
        match0 -= 1;
        m_length += 1;
    }
    *ip0 = ip;
    (mbuf, match0, offcode, m_length)
}

/// `ZSTD_compressBlock_fast_extDict`: dispatches on the shortest match, 4
/// to 7 bytes (3 counts as 4).
pub(crate) fn zstd_compress_block_fast_ext_dict(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: &[u8],
    istart: usize,
    iend: usize,
) -> usize {
    let f = match ms.c_params.min_match {
        5 => zstd_compress_block_fast_ext_dict_generic::<5>,
        6 => zstd_compress_block_fast_ext_dict_generic::<6>,
        7 => zstd_compress_block_fast_ext_dict_generic::<7>,
        _ => zstd_compress_block_fast_ext_dict_generic::<4>,
    };
    f(ms, seq_store, rep, src, dict, istart, iend)
}

/// `ZSTD_compressBlock_fast_dictMatchState_generic`: the sequences of the
/// block `src[istart..iend]`, with matches in the window's prefix and in
/// `dms`, the `CDict` the frame is attached to: its hash table, of tagged
/// indices, over its content, which comes right before the prefix in the
/// frame's indices. A match in the dictionary may run on into the prefix.
/// Returns the size of the literals left after the last sequence.
///
/// One position at a time, as in libzstd: the repcode at the next
/// position, then the dictionary's candidate, taken only where the
/// prefix's is not in the window (as the extDict variant parses), then
/// the prefix's. The dictionary's bytes are read only where the tags
/// match (`ZSTD_comparePackedTags`). The repcodes are not checked against
/// the window first: libzstd asserts that they reach no further back than
/// the dictionary's start, which holds as a frame starts with the
/// `CDict`'s repcodes (checked to be within its content, or 1, 4 and 8
/// for raw content of 8 bytes at least), and every offset found since is
/// within the dictionary and the prefix.
///
/// Differs from libzstd: positions are indices into `src`, the prefix's
/// buffer, and into the `CDict`'s content, `dms.content`; libzstd's
/// `dictBase` is `dms.ms.window.base` there. A repcode is read where
/// libzstd reads it, in the content when its index is below the prefix,
/// less `dictIndexDelta`, and a read out of the content is no match: in
/// libzstd there is none (see above). The 8 bytes at each position are
/// read once, for its two hashes and the comparisons at it and at the
/// position after; the bytes are the same. The dictionary's table is not
/// prefetched (`ms->prefetchCDictTables`), which changes nothing it reads.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn zstd_compress_block_fast_dict_match_state_generic<const MLS: u32>(
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
    let hlog = c_params.hash_log;
    // At least 1: a target length of 0 counts as 1.
    let step_size = c_params.target_length as usize + usize::from(c_params.target_length == 0);
    let base = ms.window.base;
    // Nothing past the block is read, as in libzstd.
    let src = &src[..iend];
    let mut ip0 = istart;
    let mut ip1 = ip0 + step_size;
    let mut anchor = istart;
    let prefix_start_index = ms.window.dict_limit;
    let prefix_start = (i64::from(prefix_start_index) - base) as usize;
    // Before the block for blocks under 8 bytes, where libzstd's pointer
    // goes before the buffer and the search ends at once; 0 does the same,
    // as ip1 is past istart.
    let ilimit = iend.saturating_sub(HASH_READ_SIZE);
    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];

    // The dictionary: its table, its window over its content (one segment,
    // from dictStartIndex to dictEnd), and how far its indices are below
    // the frame's. Differs from libzstd: an entry's index, the hash with
    // its tag shifted out, is masked with the table's size, which changes
    // none and saves the bounds check.
    let dict_mask = (1usize << dms.ms.c_params.hash_log) - 1;
    let dict_hash_table = &dms.ms.hash_table[..=dict_mask];
    let dict_entry = |hash_and_tag: usize| {
        dict_hash_table[(hash_and_tag >> ZSTD_SHORT_CACHE_TAG_BITS) & dict_mask]
    };
    let dict_start_index = dms.ms.window.dict_limit;
    let dict_base = dms.ms.window.base;
    let dict_end_index = dms.ms.window.next_src as u32;
    let dict_start = (i64::from(dict_start_index) - dict_base) as usize;
    let dict_end = (i64::from(dict_end_index) - dict_base) as usize;
    let dict = &dms.content[..dict_end];
    // No underflow when a dictionary index becomes one of the frame's: the
    // frame's window starts at or past the dictionary's end.
    debug_assert!(prefix_start_index >= dict_end_index);
    let dict_index_delta = prefix_start_index.wrapping_sub(dict_end_index);
    let dict_and_prefix_length = (istart - prefix_start + dict_end - dict_start) as u32;
    let dict_h_bits = dms.ms.c_params.hash_log + ZSTD_SHORT_CACHE_TAG_BITS;

    // A dictionary still attached is within the window.
    debug_assert!(
        ms.window.index(iend).wrapping_sub(prefix_start_index) <= 1u32 << c_params.window_log
    );

    let index = |position: usize| (position as i64 + base) as u32;
    let at = |index: u32| (i64::from(index) - base) as usize;
    // The position in the content of the dictionary's index `i`.
    let dict_at = |i: u32| (i64::from(i) - dict_base) as usize;
    // Where the frame's index `i` is: its segment, its position there, and
    // where the segment ends. Below the prefix, in the dictionary, at
    // `i - dictIndexDelta` in its indices; libzstd computes that on 32 bits
    // in the search and in full in the immediate repcodes, which differ
    // only for an index below the dictionary's, where libzstd reads none
    // (see above), and the port reads none either: on 64 bits, it is before
    // the content.
    let locate = |i: u32| {
        if i < prefix_start_index {
            let at = i64::from(i) - i64::from(dict_index_delta) - dict_base;
            (dict, at as usize, dict_end)
        } else {
            (src, at(i), iend)
        }
    };

    // Init.
    ip0 += usize::from(dict_and_prefix_length == 0);
    // The repcode checks do not disable a repcode of 0, or one out of
    // reach.
    debug_assert!(offset_1 <= dict_and_prefix_length);
    debug_assert!(offset_2 <= dict_and_prefix_length);

    let mut hash_table = HashTable::new(&mut ms.hash_table, hlog);
    let k_step_incr = 1usize << K_SEARCH_STRENGTH;

    // The outer search loop. The repcode check at ip0 + 1 is safe because
    // ip0 < ip1.
    debug_assert!(step_size >= 1);
    'outer: while ip1 <= ilimit {
        // The 8 bytes at ip0, before ip1, so in the block.
        let mut val0 = mem_read64(src, ip0);
        let mut hash0 = hash_table.hash_u64(val0, mls);

        let dict_hash_and_tag0 = zstd_hash_u64(val0, dict_h_bits, mls);
        let mut dict_match_index_and_tag = dict_entry(dict_hash_and_tag0);
        let mut dict_tags_match =
            zstd_compare_packed_tags(dict_match_index_and_tag as usize, dict_hash_and_tag0);

        let mut match_index = hash_table.get(hash0);
        let mut curr = index(ip0);
        let mut step = step_size;
        let mut next_step = ip0 + k_step_incr;

        // The inner search loop, until a match is found and stored: its
        // length.
        let m_length = loop {
            let rep_index = (curr + 1).wrapping_sub(offset_1);
            // The 8 bytes at ip1, at or before ilimit.
            let val1 = mem_read64(src, ip1);
            let hash1 = hash_table.hash_u64(val1, mls);
            let dict_hash_and_tag1 = zstd_hash_u64(val1, dict_h_bits, mls);
            // Update the hash table.
            hash_table.set(hash0, curr);

            // The repcode at ip0 + 1.
            let (rbuf, rpos, rep_match_end) = locate(rep_index);
            if zstd_index_overlap_check(prefix_start_index, rep_index)
                && mem_read32_within(rbuf, rpos) == Some((val0 >> 8) as u32)
            {
                let m_length = zstd_count_2segments(
                    src,
                    ip0 + 1 + 4,
                    rbuf,
                    rpos + 4,
                    iend,
                    rep_match_end,
                    prefix_start,
                ) + 4;
                ip0 += 1;
                seq_store.store_seq(src, anchor, ip0 - anchor, REPCODE1_TO_OFFBASE, m_length);
                break m_length;
            }

            if dict_tags_match {
                // A possible match in the dictionary. Its table holds
                // positions with 8 bytes in the content, or 0, which is
                // not above dictStartIndex.
                let dict_match_index = dict_match_index_and_tag >> ZSTD_SHORT_CACHE_TAG_BITS;
                let mut dict_match = dict_at(dict_match_index);
                if dict_match_index > dict_start_index
                    && mem_read32(dict, dict_match) == val0 as u32
                {
                    // To do as the extDict variant parses, only where the
                    // prefix's candidate is not in the window.
                    if match_index <= prefix_start_index {
                        let offset = curr
                            .wrapping_sub(dict_match_index)
                            .wrapping_sub(dict_index_delta);
                        let mut m_length = zstd_count_2segments(
                            src,
                            ip0 + 4,
                            dict,
                            dict_match + 4,
                            iend,
                            dict_end,
                            prefix_start,
                        ) + 4;
                        // Catch up.
                        while (ip0 > anchor) & (dict_match > dict_start)
                            && src[ip0 - 1] == dict[dict_match - 1]
                        {
                            ip0 -= 1;
                            dict_match -= 1;
                            m_length += 1;
                        }
                        offset_2 = offset_1;
                        offset_1 = offset;
                        seq_store.store_seq(
                            src,
                            anchor,
                            ip0 - anchor,
                            offset_to_offbase(offset),
                            m_length,
                        );
                        break m_length;
                    }
                }
            }

            // ZSTD_match4Found_cmov: a match of 4 bytes or more in the
            // prefix. libzstd reads a dummy for a candidate out of the
            // window, which gives the same answer as testing it first.
            if match_index >= prefix_start_index && mem_read32(src, at(match_index)) == val0 as u32
            {
                let mut match0 = at(match_index);
                let offset = (ip0 - match0) as u32;
                let mut m_length = zstd_count(src, ip0 + 4, match0 + 4, iend) + 4;
                // Catch up.
                while (ip0 > anchor) & (match0 > prefix_start) && src[ip0 - 1] == src[match0 - 1] {
                    ip0 -= 1;
                    match0 -= 1;
                    m_length += 1;
                }
                offset_2 = offset_1;
                offset_1 = offset;
                seq_store.store_seq(
                    src,
                    anchor,
                    ip0 - anchor,
                    offset_to_offbase(offset),
                    m_length,
                );
                break m_length;
            }

            // Prepare for the next position.
            dict_match_index_and_tag = dict_entry(dict_hash_and_tag1);
            dict_tags_match =
                zstd_compare_packed_tags(dict_match_index_and_tag as usize, dict_hash_and_tag1);
            match_index = hash_table.get(hash1);

            if ip1 >= next_step {
                step += 1;
                next_step += k_step_incr;
            }
            ip0 = ip1;
            val0 = val1;
            ip1 += step;
            if ip1 > ilimit {
                // _cleanup
                break 'outer;
            }

            curr = index(ip0);
            hash0 = hash1;
        };

        // A match was found.
        debug_assert!(m_length > 0);
        ip0 += m_length;
        anchor = ip0;

        if ip0 <= ilimit {
            // Fill the table. Here because curr + 2 could be past iend - 8.
            hash_table.set(hash_table.hash(src, at(curr + 2), mls), curr + 2);
            hash_table.set(hash_table.hash(src, ip0 - 2, mls), index(ip0 - 2));

            // Check for an immediate repcode.
            while ip0 <= ilimit {
                let current2 = index(ip0);
                let rep_index2 = current2.wrapping_sub(offset_2);
                let (rbuf, rpos, rep_end2) = locate(rep_index2);
                if zstd_index_overlap_check(prefix_start_index, rep_index2)
                    && mem_read32_within(rbuf, rpos) == Some(mem_read32(src, ip0))
                {
                    let rep_length2 = zstd_count_2segments(
                        src,
                        ip0 + 4,
                        rbuf,
                        rpos + 4,
                        iend,
                        rep_end2,
                        prefix_start,
                    ) + 4;
                    // Swap offset_2 and offset_1.
                    std::mem::swap(&mut offset_1, &mut offset_2);
                    seq_store.store_seq(src, anchor, 0, REPCODE1_TO_OFFBASE, rep_length2);
                    hash_table.set(hash_table.hash(src, ip0, mls), current2);
                    ip0 += rep_length2;
                    anchor = ip0;
                    continue;
                }
                break;
            }
        }

        // Prepare for the next search.
        debug_assert!(ip0 == anchor);
        ip1 = ip0 + step_size;
    }

    // _cleanup: the repcodes for the next block.
    rep[0] = offset_1;
    rep[1] = offset_2;

    // The size of the last literals.
    iend - anchor
}

/// `ZSTD_compressBlock_fast_dictMatchState`: dispatches on the shortest
/// match, 4 to 7 bytes (3 counts as 4).
pub(crate) fn zstd_compress_block_fast_dict_match_state(
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dms: DictMatchState<'_>,
    istart: usize,
    iend: usize,
) -> usize {
    let f = match ms.c_params.min_match {
        5 => zstd_compress_block_fast_dict_match_state_generic::<5>,
        6 => zstd_compress_block_fast_dict_match_state_generic::<6>,
        7 => zstd_compress_block_fast_dict_match_state_generic::<7>,
        _ => zstd_compress_block_fast_dict_match_state_generic::<4>,
    };
    f(ms, seq_store, rep, src, dms, istart, iend)
}
