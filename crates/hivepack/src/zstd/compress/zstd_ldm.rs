//! Long distance matching: port of `compress/zstd_ldm.c`.
//!
//! A gear hash over the input picks split points, about one in
//! `1 << hashRateLog`; the `minMatchLength` bytes before each one go into a
//! hash table of buckets, by their XXH64, and are looked up there, the
//! window being that of the frame. The matches found are sequences of the
//! block ([`RawSeqStore`]); the strategy's block compressor finds the
//! sequences between them.
//!
//! Positions are indices into `src`, the buffer the window's prefix is in,
//! and `dict`, the one its older segment is in. The hash table holds
//! indices of the window of long distance matching ([`LdmState`]), which
//! sees the same input as the match state's window but keeps its own
//! indices: `position + window.base` (or `window.dict_base`).

use crate::zstd::common::error_private::{Result, error};
use crate::zstd::common::xxhash::xxh64;
use crate::zstd::common::zstd_internal::ZSTD_REP_NUM;
use crate::zstd::compress::zstd_compress::BlockCompressor;
use crate::zstd::compress::zstd_compress_internal::{
    CompressionParameters, HASH_READ_SIZE, LDM_BATCH_SIZE, LdmEntry, LdmParams, LdmState,
    MatchState, ParamSwitch, RawSeq, RawSeqStore, SeqStore, Strategy, ZSTD_HASHLOG_MIN,
    offset_to_offbase, zstd_count, zstd_count_2segments,
};
use crate::zstd::compress::zstd_double_fast::zstd_fill_double_hash_table;
use crate::zstd::compress::zstd_fast::zstd_fill_hash_table;
use crate::zstd::compress::zstd_ldm_geartab::ZSTD_LDM_GEAR_TAB;
use crate::zstd::decompress::zstd_decompress_internal::ZSTD_WINDOWLOG_LIMIT_DEFAULT;

/// `ZSTD_LDM_DEFAULT_WINDOW_LOG`: the window log of a frame with long
/// distance matching when none is set.
pub(crate) const ZSTD_LDM_DEFAULT_WINDOW_LOG: u32 = ZSTD_WINDOWLOG_LIMIT_DEFAULT;

/// `LDM_BUCKET_SIZE_LOG`: the smallest default bucket size log.
const LDM_BUCKET_SIZE_LOG: u32 = 4;
/// `LDM_MIN_MATCH_LENGTH`: the default shortest match.
const LDM_MIN_MATCH_LENGTH: u32 = 64;
/// `ZSTD_HASHLOG_MAX` on 64-bit machines.
const ZSTD_HASHLOG_MAX: u32 = 30;
/// `ZSTD_LDM_BUCKETSIZELOG_MAX`
pub(crate) const ZSTD_LDM_BUCKETSIZELOG_MAX: u32 = 8;
const _: () = assert!(LDM_BUCKET_SIZE_LOG <= ZSTD_LDM_BUCKETSIZELOG_MAX);

/// `ldmRollingHashState_t`: the gear hash, and which of its bits make a
/// split point when they are all 0.
struct LdmRollingHashState {
    rolling: u64,
    stop_mask: u64,
}

/// `ZSTD_ldm_gear_init`: a hash that splits about every
/// `1 << hashRateLog` bytes, on the bits that depend on the last
/// `minMatchLength` bytes.
fn zstd_ldm_gear_init(params: &LdmParams) -> LdmRollingHashState {
    let max_bits_in_mask = params.min_match_length.min(64);
    let hash_rate_log = params.hash_rate_log;
    // Bit n of the gear hash depends on the last n bytes: the mask has
    // `hash_rate_log` bits, the highest that still depend on no more than
    // `minMatchLength` bytes.
    let stop_mask = if hash_rate_log > 0 && hash_rate_log <= max_bits_in_mask {
        ((1u64 << hash_rate_log) - 1) << (max_bits_in_mask - hash_rate_log)
    } else {
        // In this degenerate case, only the rate counts.
        (1u64 << hash_rate_log) - 1
    };
    LdmRollingHashState {
        rolling: u64::from(u32::MAX),
        stop_mask,
    }
}

/// `ZSTD_ldm_gear_reset`: meant to feed `data`, the `minMatchLength` bytes
/// before where hashing resumes, into the hash without registering split
/// points. libzstd's computes the hash and never stores it back
/// (`state->rolling` is read, not written): the state stays as it was.
///
/// Differs from libzstd: the port leaves the state alone without computing
/// the hash. The state, and so the split points after, are the same.
fn zstd_ldm_gear_reset(_state: &mut LdmRollingHashState, _data: &[u8]) {}

/// `ZSTD_ldm_gear_feed`: the split points in `data` into `splits`, after
/// the `*num_splits` there, each as the position past it (from 1), until
/// `data` ends or the batch is full. Returns how many bytes were hashed.
///
/// Differs from libzstd: one byte per turn, where libzstd's loop takes four
/// at a time, then the rest one by one; each byte is tested as it comes in
/// both.
fn zstd_ldm_gear_feed(
    state: &mut LdmRollingHashState,
    data: &[u8],
    splits: &mut [usize; LDM_BATCH_SIZE],
    num_splits: &mut usize,
) -> usize {
    let mut hash = state.rolling;
    let mask = state.stop_mask;
    let mut n = 0;
    while n < data.len() {
        hash = (hash << 1).wrapping_add(ZSTD_LDM_GEAR_TAB[usize::from(data[n])]);
        n += 1;
        if hash & mask == 0 {
            splits[*num_splits] = n;
            *num_splits += 1;
            if *num_splits == LDM_BATCH_SIZE {
                break;
            }
        }
    }
    state.rolling = hash;
    n
}

/// `ZSTD_ldm_adjustParameters`: the parameters left at 0 from the frame's
/// compression parameters, and the window. The hash rate log is the window
/// log less the hash log, if that is set, otherwise from the strategy;
/// buckets are no larger than the table.
pub(crate) fn zstd_ldm_adjust_parameters(params: &mut LdmParams, c_params: &CompressionParameters) {
    params.window_log = c_params.window_log;
    let strategy = c_params.strategy as u32;
    if params.hash_rate_log == 0 {
        if params.hash_log > 0 {
            // From the hash log, if set.
            debug_assert!(params.hash_log <= ZSTD_HASHLOG_MAX);
            if params.window_log > params.hash_log {
                params.hash_rate_log = params.window_log - params.hash_log;
            }
        } else {
            // From 7 for fast to 4 for btultra2.
            params.hash_rate_log = 7 - strategy / 3;
        }
    }
    if params.hash_log == 0 {
        // libzstd's U32 subtraction wraps around for a hash rate log over
        // the window log, which then takes the largest table.
        params.hash_log = params
            .window_log
            .wrapping_sub(params.hash_rate_log)
            .clamp(ZSTD_HASHLOG_MIN, ZSTD_HASHLOG_MAX);
    }
    if params.min_match_length == 0 {
        params.min_match_length = LDM_MIN_MATCH_LENGTH;
        if c_params.strategy >= Strategy::Btultra {
            params.min_match_length /= 2;
        }
    }
    if params.bucket_size_log == 0 {
        params.bucket_size_log = strategy.clamp(LDM_BUCKET_SIZE_LOG, ZSTD_LDM_BUCKETSIZELOG_MAX);
    }
    params.bucket_size_log = params.bucket_size_log.min(params.hash_log);
}

/// `ZSTD_ldm_getTableSize`: the bytes of the tables, the hash table and the
/// buckets' offsets; 0 without long distance matching.
pub(crate) fn zstd_ldm_get_table_size(enable: ParamSwitch, params: &LdmParams) -> usize {
    let ldm_h_size = 1usize << params.hash_log;
    let ldm_bucket_size_log = params.bucket_size_log.min(params.hash_log);
    let ldm_bucket_size = 1usize << (params.hash_log - ldm_bucket_size_log);
    let total_size = ldm_bucket_size + ldm_h_size * std::mem::size_of::<LdmEntry>();
    if enable == ParamSwitch::Enable {
        total_size
    } else {
        0
    }
}

/// `ZSTD_ldm_getMaxNbSeq`: the most sequences long distance matching can
/// find in `max_chunk_size` bytes; 0 without it.
pub(crate) fn zstd_ldm_get_max_nb_seq(
    enable: ParamSwitch,
    params: &LdmParams,
    max_chunk_size: usize,
) -> usize {
    if enable == ParamSwitch::Enable {
        max_chunk_size / params.min_match_length as usize
    } else {
        0
    }
}

/// `ZSTD_ldm_getBucket`: the first entry of the bucket of `hash`.
#[inline(always)]
fn zstd_ldm_get_bucket(hash: u32, bucket_size_log: u32) -> usize {
    (hash as usize) << bucket_size_log
}

/// `ZSTD_ldm_insertEntry`: `entry` into the bucket of `hash`, over its
/// oldest entry.
#[inline(always)]
fn zstd_ldm_insert_entry(
    ldm_state: &mut LdmState,
    hash: u32,
    entry: LdmEntry,
    bucket_size_log: u32,
) {
    let offset = ldm_state.bucket_offsets[hash as usize];
    ldm_state.hash_table[zstd_ldm_get_bucket(hash, bucket_size_log) + usize::from(offset)] = entry;
    ldm_state.bucket_offsets[hash as usize] =
        ((u32::from(offset) + 1) & ((1u32 << bucket_size_log) - 1)) as u8;
}

/// `ZSTD_ldm_fillHashTable`: the split points of `src[ip..iend]` into the
/// hash table, as loading a dictionary does, but those less than
/// `minMatchLength` from `ip`.
pub(crate) fn zstd_ldm_fill_hash_table(
    ldm_state: &mut LdmState,
    src: &[u8],
    mut ip: usize,
    iend: usize,
    params: &LdmParams,
) {
    let min_match_length = params.min_match_length as usize;
    let bucket_size_log = params.bucket_size_log;
    let h_bits = params.hash_log - bucket_size_log;
    let base = ldm_state.window.base;
    let istart = ip;
    let mut splits = [0usize; LDM_BATCH_SIZE];

    let mut hash_state = zstd_ldm_gear_init(params);
    while ip < iend {
        let mut num_splits = 0;
        let hashed = zstd_ldm_gear_feed(
            &mut hash_state,
            &src[ip..iend],
            &mut splits,
            &mut num_splits,
        );
        for &split in &splits[..num_splits] {
            if ip + split >= istart + min_match_length {
                let split = ip + split - min_match_length;
                let xxhash = xxh64(&src[split..split + min_match_length], 0);
                let hash = (xxhash as u32) & ((1u32 << h_bits) - 1);
                let entry = LdmEntry {
                    offset: (split as i64 + base) as u32,
                    checksum: (xxhash >> 32) as u32,
                };
                zstd_ldm_insert_entry(ldm_state, hash, entry, bucket_size_log);
            }
        }
        ip += hashed;
    }
}

/// `ZSTD_ldm_countBackwardsMatch`: how many bytes before `p_in` of `src`
/// equal those before `p_match` of `mbuf`, counting only those from
/// `p_anchor` and from `p_match_base` on.
#[inline(always)]
fn zstd_ldm_count_backwards_match(
    src: &[u8],
    mut p_in: usize,
    p_anchor: usize,
    mbuf: &[u8],
    mut p_match: usize,
    p_match_base: usize,
) -> usize {
    let mut match_length = 0;
    while p_in > p_anchor && p_match > p_match_base && src[p_in - 1] == mbuf[p_match - 1] {
        p_in -= 1;
        p_match -= 1;
        match_length += 1;
    }
    match_length
}

/// `ZSTD_ldm_countBackwardsMatch_2segments`: as
/// [`zstd_ldm_count_backwards_match`], but a match in the prefix that
/// reaches its start, `p_match_base`, goes on back from the older
/// segment's end, `dict[dict_start..dict_end]`.
///
/// Differs from libzstd: libzstd tells a match in the older segment by its
/// lowest position being that segment's start (`pMatchBase ==
/// pExtDictStart`); the port is told, `in_dict`. The prefix never starts
/// where the older segment does, so the answers are the same.
#[allow(clippy::too_many_arguments)]
fn zstd_ldm_count_backwards_match_2segments(
    src: &[u8],
    p_in: usize,
    p_anchor: usize,
    mbuf: &[u8],
    p_match: usize,
    p_match_base: usize,
    in_dict: bool,
    dict: &[u8],
    dict_start: usize,
    dict_end: usize,
) -> usize {
    let mut match_length =
        zstd_ldm_count_backwards_match(src, p_in, p_anchor, mbuf, p_match, p_match_base);
    if p_match - match_length != p_match_base || in_dict {
        // All in the older segment, or in the prefix.
        return match_length;
    }
    match_length += zstd_ldm_count_backwards_match(
        src,
        p_in - match_length,
        p_anchor,
        dict,
        dict_end,
        dict_start,
    );
    match_length
}

/// `ZSTD_ldm_fillFastTables`: the tables of `fast` and `dfast` filled up to
/// `end`, from `nextToUpdate`, as loading a dictionary does. The other
/// strategies fill their tables in their block compressors.
fn zstd_ldm_fill_fast_tables(ms: &mut MatchState, src: &[u8], end: usize) {
    match ms.c_params.strategy {
        Strategy::Fast => zstd_fill_hash_table(ms, src, end),
        Strategy::Dfast => zstd_fill_double_hash_table(ms, src, end),
        _ => {}
    }
}

/// `ZSTD_ldm_limitTableUpdate`: after a long match, `nextToUpdate` brought
/// closer to `anchor`, so that only a limited stretch of it goes into the
/// tables.
fn zstd_ldm_limit_table_update(ms: &mut MatchState, anchor: usize) {
    let curr = ms.window.index(anchor);
    if curr > ms.next_to_update + 1024 {
        ms.next_to_update = curr - 512.min(curr - ms.next_to_update - 1024);
    }
}

/// `ldmMatchCandidate_t`: a split point, its hash and its checksum.
///
/// Differs from libzstd: without the pointer to the hash's bucket, which
/// libzstd keeps to prefetch it; the bucket is found from the hash again.
#[derive(Clone, Copy, Default)]
struct LdmMatchCandidate {
    split: usize,
    hash: u32,
    checksum: u32,
}

/// `ZSTD_ldm_generateSequences_internal`: the sequences of
/// `src[istart..iend]` into `raw_seq_store`, its positions into the hash
/// table. Returns the size of the literals after the last sequence, or
/// `DstSizeTooSmall` when the store is full.
#[allow(clippy::too_many_lines)]
fn zstd_ldm_generate_sequences_internal(
    ldm_state: &mut LdmState,
    raw_seq_store: &mut RawSeqStore,
    params: &LdmParams,
    src: &[u8],
    dict: &[u8],
    istart: usize,
    iend: usize,
) -> Result<usize> {
    // The parameters of long distance matching.
    let window = ldm_state.window;
    let ext_dict = window.has_ext_dict();
    let min_match_length = params.min_match_length as usize;
    let bucket_size_log = params.bucket_size_log;
    let ents_per_bucket = 1usize << bucket_size_log;
    let h_bits = params.hash_log - bucket_size_log;
    // The prefix and the older segment: dictStart to dictEnd in `dict`, when
    // there is one.
    let dict_limit = window.dict_limit;
    let lowest_index = if ext_dict {
        window.low_limit
    } else {
        dict_limit
    };
    let base = window.base;
    let dict_base = window.dict_base;
    let (dict_start, dict_end) = if ext_dict {
        (
            (i64::from(lowest_index) - dict_base) as usize,
            (i64::from(dict_limit) - dict_base) as usize,
        )
    } else {
        (0, 0)
    };
    let low_prefix_ptr = (i64::from(dict_limit) - base) as usize;
    // The input's bounds. libzstd's ilimit goes before the input for chunks
    // under 8 bytes; 0 does the same, as ip is past it.
    let ilimit = iend.saturating_sub(HASH_READ_SIZE);
    // The positions.
    let mut anchor = istart;
    let mut ip = istart;
    // The batch: split points, then candidates.
    let mut splits = [0usize; LDM_BATCH_SIZE];
    let mut candidates = [LdmMatchCandidate::default(); LDM_BATCH_SIZE];
    let index = |position: usize| (position as i64 + base) as u32;

    if iend - istart < min_match_length {
        return Ok(iend - anchor);
    }

    // The rolling hash, over the first minMatchLength bytes.
    let mut hash_state = zstd_ldm_gear_init(params);
    zstd_ldm_gear_reset(&mut hash_state, &src[ip..ip + min_match_length]);
    ip += min_match_length;

    while ip < ilimit {
        let mut num_splits = 0;
        let hashed = zstd_ldm_gear_feed(
            &mut hash_state,
            &src[ip..ilimit],
            &mut splits,
            &mut num_splits,
        );

        for n in 0..num_splits {
            let split = ip + splits[n] - min_match_length;
            let xxhash = xxh64(&src[split..split + min_match_length], 0);
            candidates[n] = LdmMatchCandidate {
                split,
                hash: (xxhash as u32) & ((1u32 << h_bits) - 1),
                checksum: (xxhash >> 32) as u32,
            };
        }

        for n in 0..num_splits {
            let LdmMatchCandidate {
                split,
                hash,
                checksum,
            } = candidates[n];
            let bucket = zstd_ldm_get_bucket(hash, bucket_size_log);
            let new_entry = LdmEntry {
                offset: index(split),
                checksum,
            };

            // A split point that would give a sequence overlapping the one
            // before only goes into the table.
            if split < anchor {
                zstd_ldm_insert_entry(ldm_state, hash, new_entry, bucket_size_log);
                continue;
            }

            // The longest match in the bucket, counted both ways.
            let mut best_match_length = 0;
            let mut forward_match_length = 0;
            let mut backward_match_length = 0;
            let mut best_entry = None;
            for &cur in &ldm_state.hash_table[bucket..bucket + ents_per_bucket] {
                if cur.checksum != checksum || cur.offset <= lowest_index {
                    continue;
                }
                let (cur_forward_match_length, cur_backward_match_length);
                if ext_dict {
                    // In the older segment, the match ends at its end, and
                    // may go on into the prefix.
                    let in_dict = cur.offset < dict_limit;
                    let (mbuf, p_match, match_end, low_match_ptr) = if in_dict {
                        (
                            dict,
                            (i64::from(cur.offset) - dict_base) as usize,
                            dict_end,
                            dict_start,
                        )
                    } else {
                        (
                            src,
                            (i64::from(cur.offset) - base) as usize,
                            iend,
                            low_prefix_ptr,
                        )
                    };
                    cur_forward_match_length = zstd_count_2segments(
                        src,
                        split,
                        mbuf,
                        p_match,
                        iend,
                        match_end,
                        low_prefix_ptr,
                    );
                    if cur_forward_match_length < min_match_length {
                        continue;
                    }
                    cur_backward_match_length = zstd_ldm_count_backwards_match_2segments(
                        src,
                        split,
                        anchor,
                        mbuf,
                        p_match,
                        low_match_ptr,
                        in_dict,
                        dict,
                        dict_start,
                        dict_end,
                    );
                } else {
                    let p_match = (i64::from(cur.offset) - base) as usize;
                    cur_forward_match_length = zstd_count(src, split, p_match, iend);
                    if cur_forward_match_length < min_match_length {
                        continue;
                    }
                    cur_backward_match_length = zstd_ldm_count_backwards_match(
                        src,
                        split,
                        anchor,
                        src,
                        p_match,
                        low_prefix_ptr,
                    );
                }
                let cur_total_match_length = cur_forward_match_length + cur_backward_match_length;

                if cur_total_match_length > best_match_length {
                    best_match_length = cur_total_match_length;
                    forward_match_length = cur_forward_match_length;
                    backward_match_length = cur_backward_match_length;
                    best_entry = Some(cur);
                }
            }

            // No match: the entry into the table, and on to the next
            // candidate.
            let Some(best_entry) = best_entry else {
                zstd_ldm_insert_entry(ldm_state, hash, new_entry, bucket_size_log);
                continue;
            };

            // A match.
            let offset = index(split) - best_entry.offset;
            let m_length = forward_match_length + backward_match_length;
            if raw_seq_store.size() == raw_seq_store.capacity {
                // Out of room for sequences.
                return error!(DstSizeTooSmall);
            }
            raw_seq_store.seq.push(RawSeq {
                offset,
                lit_length: (split - backward_match_length - anchor) as u32,
                match_length: m_length as u32,
            });

            // The entry into the table, after the match was read from it.
            zstd_ldm_insert_entry(ldm_state, hash, new_entry, bucket_size_log);

            anchor = split + forward_match_length;

            // A match ending past what was hashed is a pattern that repeats
            // and overlaps itself, like zeros. If one repetition splits, all
            // do: insert only the first, and go on from the match's end.
            // That is much faster on a byte repeated that ends up in the
            // table.
            if anchor > ip + hashed {
                zstd_ldm_gear_reset(&mut hash_state, &src[anchor - min_match_length..anchor]);
                // The outer loop goes on at the anchor (ip + hashed).
                ip = anchor - hashed;
                break;
            }
        }

        ip += hashed;
    }

    Ok(iend - anchor)
}

/// `ZSTD_ldm_reduceTable`: lowers the indices of the hash table by
/// `reducer_value`; those it would take below 0 become 0.
fn zstd_ldm_reduce_table(table: &mut [LdmEntry], reducer_value: u32) {
    for entry in table {
        if entry.offset < reducer_value {
            entry.offset = 0;
        } else {
            entry.offset -= reducer_value;
        }
    }
}

/// `ZSTD_ldm_generateSequences`: the sequences of `src[istart..iend]` found
/// by long distance matching, after those in `sequences`, which they parse
/// a prefix of. The window must have taken the input already.
///
/// The input goes in chunks of 1 MiB, for each of which the window's
/// indices are lowered if needed and its maximum distance enforced. A
/// block is one chunk. Fails with `DstSizeTooSmall` when `sequences` is
/// full.
pub(crate) fn zstd_ldm_generate_sequences(
    ldm_state: &mut LdmState,
    sequences: &mut RawSeqStore,
    params: &LdmParams,
    src: &[u8],
    dict: &[u8],
    istart: usize,
    iend: usize,
) -> Result<()> {
    const K_MAX_CHUNK_SIZE: usize = 1 << 20;
    let max_dist = 1u32 << params.window_log;
    let src_size = iend - istart;
    let nb_chunks =
        src_size / K_MAX_CHUNK_SIZE + usize::from(!src_size.is_multiple_of(K_MAX_CHUNK_SIZE));
    let mut leftover_size = 0;

    debug_assert!(ldm_state.window.next_src >= iend as i64 + ldm_state.window.base);
    debug_assert!(sequences.pos <= sequences.size());
    debug_assert!(sequences.size() <= sequences.capacity);
    let mut chunk = 0;
    while chunk < nb_chunks && sequences.size() < sequences.capacity {
        let chunk_start = istart + chunk * K_MAX_CHUNK_SIZE;
        let remaining = iend - chunk_start;
        let chunk_end = if remaining < K_MAX_CHUNK_SIZE {
            iend
        } else {
            chunk_start + K_MAX_CHUNK_SIZE
        };
        let chunk_size = chunk_end - chunk_start;
        let prev_size = sequences.size();

        debug_assert!(chunk_start < iend);
        // 1. Lower the indices if needed.
        let window = &mut ldm_state.window;
        if window.need_overflow_correction(
            0,
            max_dist,
            ldm_state.loaded_dict_end,
            window.index(chunk_start),
            window.index(chunk_end),
        ) {
            let correction = window.correct_overflow(0, max_dist, window.index(chunk_start));
            zstd_ldm_reduce_table(&mut ldm_state.hash_table, correction);
            // Dictionaries are invalid after a correction.
            ldm_state.loaded_dict_end = 0;
        }
        // 2. The maximum distance, enforced by chunk, from its end. An
        // offset must be valid at the end of its sequence, which may be
        // split in two; that holds here. A dictionary loaded is valid
        // whole until the window is past its end.
        if window.enforce_max_dist(window.index(chunk_end), max_dist, ldm_state.loaded_dict_end) {
            ldm_state.loaded_dict_end = 0;
        }
        // 3. The sequences of the chunk.
        let new_leftover_size = zstd_ldm_generate_sequences_internal(
            ldm_state,
            sequences,
            params,
            src,
            dict,
            chunk_start,
            chunk_end,
        )?;
        // 4. The literals left from the chunks before go to the first new
        // sequence; without one, they and the chunk are all literals.
        if prev_size < sequences.size() {
            sequences.seq[prev_size].lit_length += leftover_size as u32;
            leftover_size = new_leftover_size;
        } else {
            debug_assert!(new_leftover_size == chunk_size);
            leftover_size += chunk_size;
        }
        chunk += 1;
    }
    Ok(())
}

/// `ZSTD_ldm_skipSequences`: past `src_size` bytes of the sequences in
/// `raw_seq_store`, leaving no match shorter than `min_match`. For the
/// bytes not given to [`zstd_ldm_block_compress`].
pub(crate) fn zstd_ldm_skip_sequences(
    raw_seq_store: &mut RawSeqStore,
    mut src_size: usize,
    min_match: u32,
) {
    while src_size > 0 && raw_seq_store.pos < raw_seq_store.size() {
        let pos = raw_seq_store.pos;
        let seq = &mut raw_seq_store.seq[pos];
        if src_size <= seq.lit_length as usize {
            // Past src_size literals.
            seq.lit_length -= src_size as u32;
            return;
        }
        src_size -= seq.lit_length as usize;
        seq.lit_length = 0;
        if src_size < seq.match_length as usize {
            // Past the first src_size bytes of the match.
            seq.match_length -= src_size as u32;
            if seq.match_length < min_match {
                // Too short: its bytes become the next one's literals.
                let match_length = seq.match_length;
                if pos + 1 < raw_seq_store.size() {
                    raw_seq_store.seq[pos + 1].lit_length += match_length;
                }
                raw_seq_store.pos += 1;
            }
            return;
        }
        src_size -= seq.match_length as usize;
        seq.match_length = 0;
        raw_seq_store.pos += 1;
    }
}

/// `maybeSplitSequence`: the next sequence, cut to the `remaining` bytes of
/// the block if longer, the rest left for the next block. A sequence with
/// offset 0 means the rest of the block is literals.
fn maybe_split_sequence(raw_seq_store: &mut RawSeqStore, remaining: u32, min_match: u32) -> RawSeq {
    let mut sequence = raw_seq_store.seq[raw_seq_store.pos];
    debug_assert!(sequence.offset > 0);
    // Likely: all of it.
    if remaining >= sequence.lit_length + sequence.match_length {
        raw_seq_store.pos += 1;
        return sequence;
    }
    // Cut short; offset 0 for literals only.
    if remaining <= sequence.lit_length {
        sequence.offset = 0;
    } else if remaining < sequence.lit_length + sequence.match_length {
        sequence.match_length = remaining - sequence.lit_length;
        if sequence.match_length < min_match {
            sequence.offset = 0;
        }
    }
    // Past `remaining` bytes, for the next sequences.
    zstd_ldm_skip_sequences(raw_seq_store, remaining as usize, min_match);
    sequence
}

/// `ZSTD_ldm_skipRawSeqStoreBytes`: `nb_bytes` further in `raw_seq_store`,
/// moving `pos` and `pos_in_sequence`. Not to be mixed with
/// [`zstd_ldm_skip_sequences`]. For the bytes not given to
/// [`zstd_ldm_block_compress`], with the optimal parser.
pub(crate) fn zstd_ldm_skip_raw_seq_store_bytes(raw_seq_store: &mut RawSeqStore, nb_bytes: usize) {
    let mut curr_pos = (raw_seq_store.pos_in_sequence + nb_bytes) as u32;
    while curr_pos != 0 && raw_seq_store.pos < raw_seq_store.size() {
        let curr_seq = raw_seq_store.seq[raw_seq_store.pos];
        if curr_pos >= curr_seq.lit_length + curr_seq.match_length {
            curr_pos -= curr_seq.lit_length + curr_seq.match_length;
            raw_seq_store.pos += 1;
        } else {
            raw_seq_store.pos_in_sequence = curr_pos as usize;
            break;
        }
    }
    if curr_pos == 0 || raw_seq_store.pos == raw_seq_store.size() {
        raw_seq_store.pos_in_sequence = 0;
    }
}

/// `ZSTD_ldm_blockCompress`: the block `istart..iend` of the prefix, with
/// the sequences of `raw_seq_store` and, on the literals before each and
/// after the last, `block_compressor`, whose sequences go between them.
/// Moves `raw_seq_store.pos` past the sequences used, and may cut the last
/// one in two, between this block and the next. Returns the size of the
/// last literals.
///
/// Fails only for a block compressor the port does not have: the context
/// refuses those frames first.
pub(crate) fn zstd_ldm_block_compress(
    raw_seq_store: &mut RawSeqStore,
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    block_compressor: &BlockCompressor<'_>,
    istart: usize,
    iend: usize,
) -> Result<usize> {
    let min_match = ms.c_params.min_match;
    let src = block_compressor.src;
    let mut ip = istart;

    // With the optimal parser (btopt and up), the sequences are candidates
    // only: libzstd points ms->ldmSeqStore at them, runs the block
    // compressor on the whole block, then moves past its bytes in them.
    if ms.c_params.strategy >= Strategy::Btopt {
        let last_ll_size =
            block_compressor.compress_opt(ms, seq_store, rep, istart, iend, Some(raw_seq_store))?;
        zstd_ldm_skip_raw_seq_store_bytes(raw_seq_store, iend - istart);
        return Ok(last_ll_size);
    }

    debug_assert!(raw_seq_store.pos <= raw_seq_store.size());
    debug_assert!(raw_seq_store.size() <= raw_seq_store.capacity);
    // Each sequence, and the block compressor on its literals.
    while raw_seq_store.pos < raw_seq_store.size() && ip < iend {
        // Moves raw_seq_store.pos on.
        let sequence = maybe_split_sequence(raw_seq_store, (iend - ip) as u32, min_match);
        // The rest is literals.
        if sequence.offset == 0 {
            break;
        }
        let lit_length = sequence.lit_length as usize;
        let match_length = sequence.match_length as usize;
        debug_assert!(ip + lit_length + match_length <= iend);

        // The tables of the block compressor, up to the literals.
        zstd_ldm_limit_table_update(ms, ip);
        zstd_ldm_fill_fast_tables(ms, src, ip);
        // The block compressor, on the literals.
        let new_lit_length = block_compressor.compress(ms, seq_store, rep, ip, ip + lit_length)?;
        ip += lit_length;
        // The repcodes.
        for i in (1..ZSTD_REP_NUM).rev() {
            rep[i] = rep[i - 1];
        }
        rep[0] = sequence.offset;
        // The sequence, after the literals the block compressor left.
        seq_store.store_seq(
            src,
            ip - new_lit_length,
            new_lit_length,
            offset_to_offbase(sequence.offset),
            match_length,
        );
        ip += match_length;
    }
    // The tables, and the last literals through the block compressor.
    zstd_ldm_limit_table_update(ms, ip);
    zstd_ldm_fill_fast_tables(ms, src, ip);
    block_compressor.compress(ms, seq_store, rep, ip, iend)
}
