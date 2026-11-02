//! The `btopt`, `btultra` and `btultra2` strategies: port of
//! `compress/zstd_opt.c`: the prices of literals and sequences from the
//! statistics of the blocks before (or a dictionary's tables), the binary
//! tree that finds every match at a position, and the optimal parser, with
//! the matches of long distance matching among its candidates. With the
//! window's older segment (`extDict`), or an attached `CDict`
//! (`dictMatchState`).
//!
//! Positions are indices into `src`, the buffer the window's prefix is in,
//! and `dict`, the one its older segment is in; the tables hold window
//! indices, `position + window.base` (or `window.dict_base`). An attached
//! `CDict`'s tables hold its own window's indices, into its content.

use crate::zstd::common::bits::highbit32;
use crate::zstd::common::fse::{FseCState, fse_get_max_nb_bits};
use crate::zstd::common::zstd_internal::{
    LL_BITS, MAX_LIT, MAX_LL, MAX_ML, MAX_OFF, MINMATCH, ML_BITS, ZSTD_BLOCKSIZE_MAX, ZSTD_OPT_NUM,
    ZSTD_REP_NUM,
};
use crate::zstd::compress::hist::hist_count_simple;
use crate::zstd::compress::huf_compress::{HufRepeat, huf_get_nb_bits_from_ctable};
use crate::zstd::compress::zstd_compress_internal::{
    DictMatchState, EntropyCTables, MatchState, OptMatch, OptPrice, OptState, Optimal, ParamSwitch,
    RawSeq, RawSeqStore, SeqStore, Strategy, ZSTD_DICT_MATCH_STATE, ZSTD_EXT_DICT, ZSTD_NO_DICT,
    ZSTD_OPT_SIZE, mem_read32, offset_to_offbase, zstd_count, zstd_count_2segments, zstd_hash_ptr,
    zstd_hash3_ptr, zstd_index_overlap_check, zstd_ll_code, zstd_ml_code, zstd_new_rep,
};

/// `ZSTD_LITFREQ_ADD`: what a literal adds to its frequency, for the
/// statistics to follow new data sooner.
const ZSTD_LITFREQ_ADD: u32 = 2;
/// `ZSTD_MAX_PRICE`: the price of a position not reached.
const ZSTD_MAX_PRICE: i32 = 1 << 30;
/// `ZSTD_PREDEF_THRESHOLD`: the first block of a frame, up to this size,
/// prices its symbols from fixed costs, without statistics.
const ZSTD_PREDEF_THRESHOLD: usize = 8;

// ---------------------------------------------------------------------------
// Prices
//
// A price is a cost in bits, with `BITCOST_ACCURACY` fractional bits. The
// cost of a symbol is about `log2(sum / frequency)`: the weight of the sum
// of its kind's frequencies, `*_sum_base_price`, less the weight of its
// own. libzstd's prices are integers; it uses `double` only to print them
// in its debug logs.

/// `BITCOST_ACCURACY`: the fractional bits of a price.
const BITCOST_ACCURACY: u32 = 8;
/// `BITCOST_MULTIPLIER`: one bit, as a price.
const BITCOST_MULTIPLIER: u32 = 1 << BITCOST_ACCURACY;

/// `ZSTD_bitWeight`: about `log2(stat + 1)`, in whole bits.
#[inline(always)]
fn bit_weight(stat: u32) -> u32 {
    highbit32(stat + 1) * BITCOST_MULTIPLIER
}

/// `ZSTD_fracWeight`: about `log2(stat + 1)`, with fractional bits, by a
/// linear interpolation between powers of 2.
#[inline(always)]
fn frac_weight(raw_stat: u32) -> u32 {
    let stat = raw_stat + 1;
    let hb = highbit32(stat);
    let b_weight = hb * BITCOST_MULTIPLIER;
    // Between 1 and 2, in fixed point: "fractional weight".
    let f_weight = (stat << BITCOST_ACCURACY) >> hb;
    debug_assert!(hb + BITCOST_ACCURACY < 31);
    b_weight + f_weight
}

/// `WEIGHT`: in whole bits for `btopt` (`OPT_LEVEL` 0), with fractional
/// bits for `btultra` and `btultra2` (2).
#[inline(always)]
fn weight<const OPT_LEVEL: u32>(stat: u32) -> u32 {
    if OPT_LEVEL != 0 {
        frac_weight(stat)
    } else {
        bit_weight(stat)
    }
}

impl OptState {
    /// `ZSTD_compressedLiterals`: whether the literals will be compressed.
    #[inline(always)]
    fn compressed_literals(&self) -> bool {
        self.literal_compression_mode != ParamSwitch::Disable
    }
}

/// `ZSTD_setBasePrices`: the prices of the sums.
fn set_base_prices<const OPT_LEVEL: u32>(opt: &mut OptState) {
    if opt.compressed_literals() {
        opt.lit_sum_base_price = weight::<OPT_LEVEL>(opt.lit_sum);
    }
    opt.lit_length_sum_base_price = weight::<OPT_LEVEL>(opt.lit_length_sum);
    opt.match_length_sum_base_price = weight::<OPT_LEVEL>(opt.match_length_sum);
    opt.off_code_sum_base_price = weight::<OPT_LEVEL>(opt.off_code_sum);
}

/// `sum_u32`
fn sum_u32(table: &[u32]) -> u32 {
    table.iter().fold(0u32, |total, &n| total.wrapping_add(n))
}

/// `ZSTD_downscaleStats`: each frequency of `table` (its entries up to
/// `last_elt_index`) shifted down by `shift`, plus 1, or, unless
/// `base1`, plus 1 only if it was not 0. Returns their sum.
fn downscale_stats(table: &mut [u32], last_elt_index: u32, shift: u32, base1: bool) -> u32 {
    debug_assert!(shift < 30);
    let mut sum = 0u32;
    for stat in &mut table[..=last_elt_index as usize] {
        let base = if base1 { 1 } else { u32::from(*stat > 0) };
        let new_stat = base + (*stat >> shift);
        sum = sum.wrapping_add(new_stat);
        *stat = new_stat;
    }
    sum
}

/// `ZSTD_scaleStats`: the frequencies of `table` scaled down when their
/// sum is over `1 << log_target`, to about that. Returns their sum.
fn scale_stats(table: &mut [u32], last_elt_index: u32, log_target: u32) -> u32 {
    let prevsum = sum_u32(&table[..=last_elt_index as usize]);
    let factor = prevsum >> log_target;
    debug_assert!(log_target < 30);
    if factor <= 1 {
        return prevsum;
    }
    downscale_stats(table, last_elt_index, highbit32(factor), true)
}

/// The frequencies a table's costs stand for: `1 << (scale_log - bits)` for
/// a symbol of `bits` bits, 1 for one the table does not have, at least
/// for the cost to be worked out.
#[inline(always)]
fn frequency_of_cost(bit_cost: u32, scale_log: u32) -> u32 {
    if bit_cost != 0 {
        1 << (scale_log - bit_cost)
    } else {
        1
    }
}

/// `ZSTD_rescaleFreqs`: the statistics for a new block, `src`. For the
/// frame's first block (no statistics yet): from a dictionary's tables when
/// the previous block's Huffman table, `symbol_costs`, is valid (a
/// dictionary's); otherwise from the block's literals and fixed
/// frequencies for the sequences' codes. For a later block: the statistics
/// so far, scaled down.
fn rescale_freqs<const OPT_LEVEL: u32>(
    opt: &mut OptState,
    src: &[u8],
    symbol_costs: &EntropyCTables,
) {
    let compressed_literals = opt.compressed_literals();
    opt.price_type = OptPrice::Dynamic;

    if opt.lit_length_sum == 0 {
        // No statistics yet: the first block.

        // Fixed prices for inputs too small.
        if src.len() <= ZSTD_PREDEF_THRESHOLD {
            opt.price_type = OptPrice::Predef;
        }

        if symbol_costs.huf.repeat_mode == HufRepeat::Valid {
            // A Huffman table of every symbol: a dictionary's.
            opt.price_type = OptPrice::Dynamic;

            if compressed_literals {
                // The literals' statistics from the Huffman table, scaled
                // to 2K.
                opt.lit_sum = 0;
                for lit in 0..=MAX_LIT {
                    const SCALE_LOG: u32 = 11;
                    let bit_cost = huf_get_nb_bits_from_ctable(&symbol_costs.huf.ctable, lit);
                    debug_assert!(bit_cost <= SCALE_LOG);
                    opt.lit_freq[lit as usize] = frequency_of_cost(bit_cost, SCALE_LOG);
                    opt.lit_sum += opt.lit_freq[lit as usize];
                }
            }

            // The codes' statistics from the FSE tables, scaled to 1K.
            const SCALE_LOG: u32 = 10;
            let fse = &symbol_costs.fse;
            {
                let ct = &fse.litlength_ctable[..];
                let ll_state = FseCState::new(ct);
                opt.lit_length_sum = 0;
                for ll in 0..=MAX_LL {
                    let bit_cost = fse_get_max_nb_bits(ct, ll_state.symbol_tt(), ll);
                    debug_assert!(bit_cost < SCALE_LOG);
                    opt.lit_length_freq[ll as usize] = frequency_of_cost(bit_cost, SCALE_LOG);
                    opt.lit_length_sum += opt.lit_length_freq[ll as usize];
                }
            }
            {
                let ct = &fse.matchlength_ctable[..];
                let ml_state = FseCState::new(ct);
                opt.match_length_sum = 0;
                for ml in 0..=MAX_ML {
                    let bit_cost = fse_get_max_nb_bits(ct, ml_state.symbol_tt(), ml);
                    debug_assert!(bit_cost < SCALE_LOG);
                    opt.match_length_freq[ml as usize] = frequency_of_cost(bit_cost, SCALE_LOG);
                    opt.match_length_sum += opt.match_length_freq[ml as usize];
                }
            }
            {
                let ct = &fse.offcode_ctable[..];
                let of_state = FseCState::new(ct);
                opt.off_code_sum = 0;
                for of in 0..=MAX_OFF {
                    let bit_cost = fse_get_max_nb_bits(ct, of_state.symbol_tt(), of);
                    debug_assert!(bit_cost < SCALE_LOG);
                    opt.off_code_freq[of as usize] = frequency_of_cost(bit_cost, SCALE_LOG);
                    opt.off_code_sum += opt.off_code_freq[of as usize];
                }
            }
        } else {
            // The first block, without a dictionary.
            if compressed_literals {
                // The literals' statistics from the block itself.
                let mut lit = MAX_LIT;
                hist_count_simple(&mut opt.lit_freq, &mut lit, src);
                opt.lit_sum = downscale_stats(&mut opt.lit_freq, MAX_LIT, 8, false);
            }

            {
                const BASE_LL_FREQS: [u32; MAX_LL as usize + 1] = [
                    4, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                ];
                opt.lit_length_freq = BASE_LL_FREQS;
                opt.lit_length_sum = sum_u32(&BASE_LL_FREQS);
            }

            opt.match_length_freq = [1; MAX_ML as usize + 1];
            opt.match_length_sum = MAX_ML + 1;

            {
                const BASE_OFC_FREQS: [u32; MAX_OFF as usize + 1] = [
                    6, 2, 1, 1, 2, 3, 4, 4, 4, 3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 1, 1,
                ];
                opt.off_code_freq = BASE_OFC_FREQS;
                opt.off_code_sum = sum_u32(&BASE_OFC_FREQS);
            }
        }
    } else {
        // A new block: the statistics so far, scaled down.
        if compressed_literals {
            opt.lit_sum = scale_stats(&mut opt.lit_freq, MAX_LIT, 12);
        }
        opt.lit_length_sum = scale_stats(&mut opt.lit_length_freq, MAX_LL, 11);
        opt.match_length_sum = scale_stats(&mut opt.match_length_freq, MAX_ML, 11);
        opt.off_code_sum = scale_stats(&mut opt.off_code_freq, MAX_OFF, 11);
    }

    set_base_prices::<OPT_LEVEL>(opt);
}

/// `ZSTD_rawLiteralsCost`: the price of `literals`, without their length's.
#[inline(always)]
fn raw_literals_cost<const OPT_LEVEL: u32>(literals: &[u8], opt: &OptState) -> u32 {
    let lit_length = literals.len() as u32;
    if lit_length == 0 {
        return 0;
    }

    if !opt.compressed_literals() {
        // Not compressed: 8 bits each.
        return (lit_length << 3) * BITCOST_MULTIPLIER;
    }

    if opt.price_type == OptPrice::Predef {
        // 6 bits each, no statistics.
        return (lit_length * 6) * BITCOST_MULTIPLIER;
    }

    // From the statistics.
    let mut price = opt.lit_sum_base_price.wrapping_mul(lit_length);
    let lit_price_max = opt.lit_sum_base_price.wrapping_sub(BITCOST_MULTIPLIER);
    debug_assert!(opt.lit_sum_base_price >= BITCOST_MULTIPLIER);
    for &literal in literals {
        let lit_price = weight::<OPT_LEVEL>(opt.lit_freq[usize::from(literal)]).min(lit_price_max);
        price = price.wrapping_sub(lit_price);
    }
    price
}

/// `LIT_PRICE`: the price of one literal.
#[inline(always)]
fn lit_price<const OPT_LEVEL: u32>(literal: u8, opt: &OptState) -> i32 {
    raw_literals_cost::<OPT_LEVEL>(&[literal], opt) as i32
}

/// `ZSTD_litLengthPrice`: the price of the code of a literal length.
#[inline(always)]
fn lit_length_price<const OPT_LEVEL: u32>(lit_length: u32, opt: &OptState) -> u32 {
    debug_assert!(lit_length as usize <= ZSTD_BLOCKSIZE_MAX);
    if opt.price_type == OptPrice::Predef {
        return weight::<OPT_LEVEL>(lit_length);
    }

    // ZSTD_LLcode() cannot take a length of ZSTD_BLOCKSIZE_MAX, which the
    // format cannot hold: a bit more than one less, for a block of
    // literals only.
    if lit_length as usize == ZSTD_BLOCKSIZE_MAX {
        return BITCOST_MULTIPLIER.wrapping_add(lit_length_price::<OPT_LEVEL>(
            ZSTD_BLOCKSIZE_MAX as u32 - 1,
            opt,
        ));
    }

    // From the statistics.
    let ll_code = zstd_ll_code(lit_length) as usize;
    (u32::from(LL_BITS[ll_code]) * BITCOST_MULTIPLIER)
        .wrapping_add(opt.lit_length_sum_base_price)
        .wrapping_sub(weight::<OPT_LEVEL>(opt.lit_length_freq[ll_code]))
}

/// `LL_PRICE`
#[inline(always)]
fn ll_price<const OPT_LEVEL: u32>(lit_length: u32, opt: &OptState) -> i32 {
    lit_length_price::<OPT_LEVEL>(lit_length, opt) as i32
}

/// `LL_INCPRICE`: what one more literal adds to the price of the length.
#[inline(always)]
fn ll_inc_price<const OPT_LEVEL: u32>(lit_length: u32, opt: &OptState) -> i32 {
    ll_price::<OPT_LEVEL>(lit_length, opt) - ll_price::<OPT_LEVEL>(lit_length - 1, opt)
}

/// `ZSTD_getMatchPrice`: the price of a match, its offset and its length,
/// without its literals. `btopt` makes far offsets dearer, for the decoder
/// to stay in its cache.
#[inline(always)]
fn get_match_price<const OPT_LEVEL: u32>(off_base: u32, match_length: u32, opt: &OptState) -> u32 {
    let off_code = highbit32(off_base);
    debug_assert!(match_length >= MINMATCH);
    let ml_base = match_length - MINMATCH;

    if opt.price_type == OptPrice::Predef {
        // Fixed costs, no statistics; the offset's emulated.
        return weight::<OPT_LEVEL>(ml_base).wrapping_add((16 + off_code) * BITCOST_MULTIPLIER);
    }

    // From the statistics.
    let mut price = (off_code * BITCOST_MULTIPLIER).wrapping_add(
        opt.off_code_sum_base_price
            .wrapping_sub(weight::<OPT_LEVEL>(opt.off_code_freq[off_code as usize])),
    );
    if OPT_LEVEL < 2 && off_code >= 20 {
        // A handicap for long distances, for the decoder's speed.
        price = price.wrapping_add((off_code - 19) * 2 * BITCOST_MULTIPLIER);
    }

    // The match length.
    {
        let ml_code = zstd_ml_code(ml_base) as usize;
        price = price.wrapping_add(
            (u32::from(ML_BITS[ml_code]) * BITCOST_MULTIPLIER).wrapping_add(
                opt.match_length_sum_base_price
                    .wrapping_sub(weight::<OPT_LEVEL>(opt.match_length_freq[ml_code])),
            ),
        );
    }

    // Matches a bit dearer, for fewer sequences: faster to decode.
    price.wrapping_add(BITCOST_MULTIPLIER / 5)
}

/// `ZSTD_updateStats`: the statistics with a sequence stored: its
/// literals, `literals[..lit_length]`, and its codes.
#[inline(always)]
fn update_stats(
    opt: &mut OptState,
    lit_length: u32,
    literals: &[u8],
    off_base: u32,
    match_length: u32,
) {
    // The literals.
    if opt.compressed_literals() {
        for &literal in &literals[..lit_length as usize] {
            opt.lit_freq[usize::from(literal)] += ZSTD_LITFREQ_ADD;
        }
        opt.lit_sum += lit_length * ZSTD_LITFREQ_ADD;
    }

    // The literal length.
    {
        let ll_code = zstd_ll_code(lit_length) as usize;
        opt.lit_length_freq[ll_code] += 1;
        opt.lit_length_sum += 1;
    }

    // The offset code, of the offset base.
    {
        let off_code = highbit32(off_base) as usize;
        debug_assert!(off_code <= MAX_OFF as usize);
        opt.off_code_freq[off_code] += 1;
        opt.off_code_sum += 1;
    }

    // The match length.
    {
        let ml_base = match_length - MINMATCH;
        let ml_code = zstd_ml_code(ml_base) as usize;
        opt.match_length_freq[ml_code] += 1;
        opt.match_length_sum += 1;
    }
}

// ---------------------------------------------------------------------------
// The binary tree
//
// The chain table holds two entries per position, `bt[2 * (i & bt_mask)]`
// and the one after, for the `1 << (chain_log - 1)` positions before the
// current one: the positions smaller and larger than it, in the order of
// the bytes that follow them. Unlike `btlazy2`'s, the tree is sorted as
// positions are inserted, and a search gives every match longer than the
// ones before it, from the repcodes and the 3-byte hash table first.

/// libzstd's `dummy32`: where a search that stops early ends the side it
/// stopped on.
///
/// Differs from libzstd: the write there is left out. Nothing reads it, so
/// the tree is the same.
const DUMMY32: usize = usize::MAX;

/// `ZSTD_readMINMATCH`: 4 bytes at `at`, or 3 for `length` 3, for
/// comparing.
///
/// libzstd reads in the machine's order, and keeps the first 3 bytes in
/// memory of the 4 on any machine; the port reads little-endian and keeps
/// the same 3.
#[inline(always)]
fn read_minmatch(src: &[u8], at: usize, length: u32) -> u32 {
    let value = mem_read32(src, at);
    if length == 3 { value << 8 } else { value }
}

/// `ZSTD_insertAndFindFirstIndexHash3`: inserts the positions from
/// `next_to_update3` up to `ip`, not included, into the 3-byte hash table,
/// and returns the last position with `ip`'s hash. The positions are in
/// the prefix.
#[inline(always)]
fn insert_and_find_first_index_hash3(
    ms: &mut MatchState,
    next_to_update3: &mut u32,
    src: &[u8],
    ip: usize,
) -> u32 {
    let hash_log3 = ms.hash_log3;
    let base = ms.window.base;
    let mut idx = *next_to_update3;
    let target = ms.window.index(ip);
    let hash3 = zstd_hash3_ptr(src, ip, hash_log3);
    debug_assert!(hash_log3 > 0);

    while idx < target {
        let at = (i64::from(idx) - base) as usize;
        ms.hash_table3[zstd_hash3_ptr(src, at, hash_log3)] = idx;
        idx += 1;
    }

    *next_to_update3 = target;
    ms.hash_table3[hash3]
}

/// `ZSTD_insertBt1`: inserts `ip`, a position of the prefix, into the hash
/// table and the tree, comparing it with at most `1 << search_log`
/// positions, down to the lowest the window keeps at `target`, the
/// position the tree is brought up to. Returns how far to go on: past a
/// long match, the positions it covers are not inserted. With `EXT`,
/// candidates below the prefix are in `dict`.
#[inline(always)]
fn insert_bt1<const MLS: u32, const EXT: bool>(
    ms: &mut MatchState,
    src: &[u8],
    dict: &[u8],
    ip: usize,
    iend: usize,
    target: u32,
) -> u32 {
    let c_params = ms.c_params;
    let h = zstd_hash_ptr(src, ip, c_params.hash_log, MLS);
    let bt_log = c_params.chain_log - 1;
    let bt_mask = (1u32 << bt_log) - 1;
    let mut match_index = ms.hash_table[h];
    let mut common_length_smaller = 0;
    let mut common_length_larger = 0;
    let base = ms.window.base;
    let dict_base = ms.window.dict_base;
    let dict_limit = ms.window.dict_limit;
    let dict_end = (i64::from(dict_limit) - dict_base) as usize;
    let prefix_start = (i64::from(dict_limit) - base) as usize;
    let curr = ms.window.index(ip);
    let bt_low = curr.saturating_sub(bt_mask);
    let mut smaller_ptr = 2 * (curr & bt_mask) as usize;
    let mut larger_ptr = smaller_ptr + 1;
    // The window's lowest at `target`: only the positions still in the
    // window when the tree is brought up to it are needed.
    let window_low = ms.lowest_match_index(target, c_params.window_log);
    let mut match_end_idx = curr + 8 + 1;
    let mut best_length = 8;
    let mut nb_compares = 1u32 << c_params.search_log;

    debug_assert!(curr <= target);
    // For the hash.
    debug_assert!(ip + 8 <= iend);
    ms.hash_table[h] = curr;

    debug_assert!(window_low > 0);
    let bt = &mut ms.chain_table;
    while nb_compares > 0 && match_index >= window_low {
        let next_ptr = 2 * (match_index & bt_mask) as usize;
        // The bytes it has in common with `ip` at least.
        let mut match_length = common_length_smaller.min(common_length_larger);
        debug_assert!(match_index < curr);

        // The candidate's segment, and the index of its first byte, for
        // the byte after the common run.
        let (mbuf, mbase) = if !EXT || match_index as usize + match_length >= dict_limit as usize {
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
            best_length = match_length;
            if match_length > (match_end_idx - match_index) as usize {
                match_end_idx = match_index + match_length as u32;
            }
        }

        if ip + match_length == iend {
            // Equal up to the end: no way to know if smaller or larger.
            // Dropped, to keep the tree consistent: a bit less compression,
            // where other ways can corrupt the tree.
            break;
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

    // Past a match longer than 384, up to 192 of the positions it covers
    // are skipped (for speed); past the longest match, those of the
    // repetition.
    let positions = if best_length > 384 {
        192.min((best_length - 384) as u32)
    } else {
        0
    };
    debug_assert!(match_end_idx > curr + 8);
    positions.max(match_end_idx - (curr + 8))
}

/// `ZSTD_updateTree_internal`: inserts the positions from `next_to_update`
/// up to `ip`, not included, into the tree. The positions are in the
/// prefix, whose bytes end at `iend`.
#[inline(always)]
fn update_tree_internal<const MLS: u32, const EXT: bool>(
    ms: &mut MatchState,
    src: &[u8],
    dict: &[u8],
    ip: usize,
    iend: usize,
) {
    let base = ms.window.base;
    let target = ms.window.index(ip);
    let mut idx = ms.next_to_update;
    debug_assert!(idx >= ms.window.dict_limit || idx >= target);

    while idx < target {
        let at = (i64::from(idx) - base) as usize;
        let forward = insert_bt1::<MLS, EXT>(ms, src, dict, at, iend, target);
        debug_assert!(idx < idx + forward);
        idx += forward;
    }
    ms.next_to_update = target;
}

/// `ZSTD_updateTree`: inserts the positions from `next_to_update` up to
/// `ip`, not included, into the tree, sorted, without an older segment, as
/// loading a dictionary does for `btlazy2` and the optimal parser. The
/// positions are in `src`, whose bytes end at `iend`.
///
/// libzstd hashes with `ZSTD_hashPtr` of `minMatch` itself here, 7 bytes
/// included (3 takes 4), where the block compressors take 3 to 6 (4 to 6
/// for `btlazy2`): the port does the same.
pub(crate) fn zstd_update_tree(ms: &mut MatchState, src: &[u8], ip: usize, iend: usize) {
    match ms.c_params.min_match {
        5 => update_tree_internal::<5, false>(ms, src, &[], ip, iend),
        6 => update_tree_internal::<6, false>(ms, src, &[], ip, iend),
        7 => update_tree_internal::<7, false>(ms, src, &[], ip, iend),
        // 3 and 4, and anything else, as ZSTD_hashPtr.
        _ => update_tree_internal::<4, false>(ms, src, &[], ip, iend),
    }
}

/// `ZSTD_insertBtAndGetAllMatches`: inserts `ip` into the tree, and writes
/// into `matches` the matches it finds, each longer than the one before
/// and than `length_to_beat - 1`: first the repcodes (with a literal
/// length of 0, `ll0`, the first one is left out and `rep[0] - 1` is
/// tried), then with a shortest match of 3 bytes the last position with
/// the same 3 bytes, then the tree's. Returns how many. A match of more
/// than the target length, or up to `i_limit`, ends the search early.
///
/// With `DICT_MODE` [`ZSTD_EXT_DICT`], candidates and repcodes below the
/// prefix are in `dict`. With [`ZSTD_DICT_MATCH_STATE`], the repcodes
/// below the prefix are in the attached `CDict`'s content, `dms`, and the
/// comparisons left after the frame's tree go on in the `CDict`'s, whose
/// index `i` is the frame's `i + dms_index_delta`; its 3-byte hash table
/// is empty.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
#[inline(always)]
fn insert_bt_and_get_all_matches<const MLS: u32, const DICT_MODE: u8>(
    matches: &mut [OptMatch],
    ms: &mut MatchState,
    next_to_update3: &mut u32,
    src: &[u8],
    dict: &[u8],
    dms: Option<DictMatchState<'_>>,
    ip: usize,
    i_limit: usize,
    rep: &[u32; ZSTD_REP_NUM],
    ll0: u32,
    length_to_beat: u32,
) -> u32 {
    let c_params = ms.c_params;
    let sufficient_len = c_params.target_length.min(ZSTD_OPT_NUM as u32 - 1);
    let base = ms.window.base;
    let curr = ms.window.index(ip);
    let min_match: u32 = if MLS == 3 { 3 } else { 4 };
    let h = zstd_hash_ptr(src, ip, c_params.hash_log, MLS);
    let mut match_index = ms.hash_table[h];
    let bt_log = c_params.chain_log - 1;
    let bt_mask = (1u32 << bt_log) - 1;
    let mut common_length_smaller = 0;
    let mut common_length_larger = 0;
    let dict_base = ms.window.dict_base;
    let dict_limit = ms.window.dict_limit;
    let dict_end = (i64::from(dict_limit) - dict_base) as usize;
    let prefix_start = (i64::from(dict_limit) - base) as usize;
    let bt_low = curr.saturating_sub(bt_mask);
    let window_low = ms.lowest_match_index(curr, c_params.window_log);
    let match_low = if window_low != 0 { window_low } else { 1 };
    let mut smaller_ptr = 2 * (curr & bt_mask) as usize;
    let mut larger_ptr = smaller_ptr + 1;
    // The farthest position any match reaches, to detect repetitions.
    let mut match_end_idx = curr + 8 + 1;
    let mut mnum = 0u32;
    let mut nb_compares = 1u32 << c_params.search_log;

    // The attached CDict's window and tables: its indices are the frame's
    // less dms_index_delta, from dms_low_limit to dms_high_limit; dms_end is
    // where its content ends.
    let dms = if DICT_MODE == ZSTD_DICT_MATCH_STATE {
        dms
    } else {
        None
    };
    let (dms_content, dms_base, dms_end, dms_high_limit, dms_low_limit) = match dms {
        Some(dms) => {
            let window = &dms.ms.window;
            (
                dms.content,
                window.base,
                (window.next_src - window.base) as usize,
                window.next_src as u32,
                window.low_limit,
            )
        }
        None => (&[][..], 0, 0, 0, 0),
    };
    let dms_index_delta = window_low.wrapping_sub(dms_high_limit);
    debug_assert!(dms.is_none() || window_low == dict_limit);

    let mut best_length = (length_to_beat - 1) as usize;

    // The repcodes.
    debug_assert!(ll0 <= 1);
    {
        let last_r = ZSTD_REP_NUM as u32 + ll0;
        for rep_code in ll0..last_r {
            let rep_offset = if rep_code == ZSTD_REP_NUM as u32 {
                rep[0].wrapping_sub(1)
            } else {
                rep[rep_code as usize]
            };
            let rep_index = curr.wrapping_sub(rep_offset);
            let mut rep_len = 0;
            debug_assert!(curr >= dict_limit);
            // The wrap around leaves out 0 and -1.
            if rep_offset.wrapping_sub(1) < curr - dict_limit {
                // curr > repIndex >= dictLimit. The offset is checked: with
                // a dictionary, offsets shrink as it leaves the window.
                if rep_index >= window_low
                    && read_minmatch(src, ip, min_match)
                        == read_minmatch(src, ip - rep_offset as usize, min_match)
                {
                    let at = ip + min_match as usize;
                    rep_len =
                        zstd_count(src, at, at - rep_offset as usize, i_limit) as u32 + min_match;
                }
            } else if DICT_MODE == ZSTD_EXT_DICT {
                // repIndex < dictLimit, or repIndex >= curr. curr >
                // repIndex >= windowLow, and the 4 bytes in one segment:
                // in the older one.
                debug_assert!(curr >= window_low);
                if rep_offset.wrapping_sub(1) < curr - window_low
                    && zstd_index_overlap_check(dict_limit, rep_index)
                {
                    let rep_match = (i64::from(rep_index) - dict_base) as usize;
                    if read_minmatch(src, ip, min_match)
                        == read_minmatch(dict, rep_match, min_match)
                    {
                        rep_len = zstd_count_2segments(
                            src,
                            ip + min_match as usize,
                            dict,
                            rep_match + min_match as usize,
                            i_limit,
                            dict_end,
                            prefix_start,
                        ) as u32
                            + min_match;
                    }
                }
            } else if DICT_MODE == ZSTD_DICT_MATCH_STATE {
                // In the CDict's content: curr > repIndex >= its lowest,
                // and the 4 bytes in it. A match there goes on into the
                // prefix.
                if rep_offset.wrapping_sub(1)
                    < curr.wrapping_sub(dms_low_limit.wrapping_add(dms_index_delta))
                    && zstd_index_overlap_check(dict_limit, rep_index)
                {
                    let dms_index = rep_index.wrapping_sub(dms_index_delta);
                    let rep_match = (i64::from(dms_index) - dms_base) as usize;
                    if read_minmatch(src, ip, min_match)
                        == read_minmatch(dms_content, rep_match, min_match)
                    {
                        rep_len = zstd_count_2segments(
                            src,
                            ip + min_match as usize,
                            dms_content,
                            rep_match + min_match as usize,
                            i_limit,
                            dms_end,
                            prefix_start,
                        ) as u32
                            + min_match;
                    }
                }
            }
            // The longer ones.
            if rep_len as usize > best_length {
                best_length = rep_len as usize;
                // REPCODE_TO_OFFBASE, 1 to 3.
                matches[mnum as usize] = OptMatch {
                    off: rep_code - ll0 + 1,
                    len: rep_len,
                };
                mnum += 1;
                if rep_len > sufficient_len || ip + rep_len as usize == i_limit {
                    // As good as it gets.
                    return mnum;
                }
            }
        }
    }

    // The 3-byte hash table.
    if MLS == 3 && best_length < MLS as usize {
        let match_index3 = insert_and_find_first_index_hash3(ms, next_to_update3, src, ip);
        // Longer distances are likely too dear.
        if match_index3 >= match_low && curr.wrapping_sub(match_index3) < (1 << 18) {
            let mlen = if DICT_MODE != ZSTD_EXT_DICT || match_index3 >= dict_limit {
                let m = (i64::from(match_index3) - base) as usize;
                zstd_count(src, ip, m, i_limit)
            } else {
                let m = (i64::from(match_index3) - dict_base) as usize;
                zstd_count_2segments(src, ip, dict, m, i_limit, dict_end, prefix_start)
            };

            // The best so far: 3 > best_length.
            if mlen >= MLS as usize {
                best_length = mlen;
                debug_assert!(curr > match_index3);
                // No match before.
                debug_assert!(mnum == 0);
                matches[0] = OptMatch {
                    off: offset_to_offbase(curr - match_index3),
                    len: mlen as u32,
                };
                mnum = 1;
                if mlen > sufficient_len as usize || ip + mlen == i_limit {
                    // As long as it gets: `ip` is not inserted.
                    ms.next_to_update = curr + 1;
                    return 1;
                }
            }
        }
        // No search of an attached CDict: its 3-byte hash table is empty.
    }

    ms.hash_table[h] = curr;

    let bt = &mut ms.chain_table;
    while nb_compares > 0 && match_index >= match_low {
        let next_ptr = 2 * (match_index & bt_mask) as usize;
        // The bytes it has in common with `ip` at least.
        let mut match_length = common_length_smaller.min(common_length_larger);
        debug_assert!(curr > match_index);

        // The candidate's segment, and the index of its first byte, for
        // the byte after the common run.
        let (mbuf, mbase) = if DICT_MODE != ZSTD_EXT_DICT
            || match_index as usize + match_length >= dict_limit as usize
        {
            let m = (i64::from(match_index) + match_length as i64 - base) as usize;
            match_length += zstd_count(src, ip + match_length, m, i_limit);
            (src, base)
        } else {
            let m = (i64::from(match_index) - dict_base) as usize;
            match_length += zstd_count_2segments(
                src,
                ip + match_length,
                dict,
                m + match_length,
                i_limit,
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
            debug_assert!(match_end_idx > match_index);
            if match_length > (match_end_idx - match_index) as usize {
                match_end_idx = match_index + match_length as u32;
            }
            best_length = match_length;
            matches[mnum as usize] = OptMatch {
                off: offset_to_offbase(curr - match_index),
                len: match_length as u32,
            };
            mnum += 1;
            if match_length > ZSTD_OPT_NUM || ip + match_length == i_limit {
                // Equal up to the end: no way to know if smaller or larger.
                // Dropped, to keep the tree consistent (a bit less
                // compression); nor is an attached CDict searched.
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

    // The comparisons left, in the attached CDict's tree: sorted, read
    // only.
    if let Some(dms) = dms
        && nb_compares > 0
    {
        let dms_c_params = dms.ms.c_params;
        let dms_bt_mask = (1u32 << (dms_c_params.chain_log - 1)) - 1;
        let dms_bt_low = if dms_bt_mask < dms_high_limit - dms_low_limit {
            dms_high_limit - dms_bt_mask
        } else {
            dms_low_limit
        };
        let dms_h = zstd_hash_ptr(src, ip, dms_c_params.hash_log, MLS);
        let mut dict_match_index = dms.ms.hash_table[dms_h];
        let dms_bt = &dms.ms.chain_table;
        common_length_smaller = 0;
        common_length_larger = 0;
        while nb_compares > 0 && dict_match_index > dms_low_limit {
            let next_ptr = 2 * (dict_match_index & dms_bt_mask) as usize;
            // The bytes it has in common with `ip` at least.
            let mut match_length = common_length_smaller.min(common_length_larger);
            let m = (i64::from(dict_match_index) - dms_base) as usize;
            // Past the content's end, on into the prefix.
            match_length += zstd_count_2segments(
                src,
                ip + match_length,
                dms_content,
                m + match_length,
                i_limit,
                dms_end,
                prefix_start,
            );

            if match_length > best_length {
                let match_index = dict_match_index.wrapping_add(dms_index_delta);
                if match_length > (match_end_idx - match_index) as usize {
                    match_end_idx = match_index + match_length as u32;
                }
                best_length = match_length;
                matches[mnum as usize] = OptMatch {
                    off: offset_to_offbase(curr - match_index),
                    len: match_length as u32,
                };
                mnum += 1;
                if match_length > ZSTD_OPT_NUM || ip + match_length == i_limit {
                    // Equal up to the end: no way to know if smaller or
                    // larger. Dropped.
                    break;
                }
            }

            if dict_match_index <= dms_bt_low {
                // Beyond the tree's size: stop.
                break;
            }
            // The byte after the common run: in the prefix, when the run
            // went past the content.
            let match_byte = if dict_match_index as usize + match_length >= dms_high_limit as usize
            {
                let at =
                    i64::from(dict_match_index.wrapping_add(dms_index_delta)) + match_length as i64;
                src[(at - base) as usize]
            } else {
                dms_content[m + match_length]
            };
            if match_byte < src[ip + match_length] {
                // Every smaller one has at least this in common.
                common_length_smaller = match_length;
                // The next one is larger than the candidate.
                dict_match_index = dms_bt[next_ptr + 1];
            } else {
                // The candidate is larger than `ip`.
                common_length_larger = match_length;
                dict_match_index = dms_bt[next_ptr];
            }
            nb_compares -= 1;
        }
    }

    // Past the longest match: repetitions are not inserted again.
    debug_assert!(match_end_idx > curr + 8);
    ms.next_to_update = match_end_idx - 8;
    mnum
}

/// `ZSTD_getAllMatchesFn`: a [`bt_get_all_matches`] for a shortest match.
type GetAllMatchesFn = fn(
    &mut [OptMatch],
    &mut MatchState,
    &mut u32,
    &[u8],
    &[u8],
    Option<DictMatchState<'_>>,
    usize,
    usize,
    &[u32; ZSTD_REP_NUM],
    u32,
    u32,
) -> u32;

/// `ZSTD_btGetAllMatches_internal`: the tree brought up to `ip`, then
/// [`insert_bt_and_get_all_matches`] at `ip`. Nothing for a position a
/// long match skipped.
#[allow(clippy::too_many_arguments)]
fn bt_get_all_matches<const MLS: u32, const DICT_MODE: u8>(
    matches: &mut [OptMatch],
    ms: &mut MatchState,
    next_to_update3: &mut u32,
    src: &[u8],
    dict: &[u8],
    dms: Option<DictMatchState<'_>>,
    ip: usize,
    i_high_limit: usize,
    rep: &[u32; ZSTD_REP_NUM],
    ll0: u32,
    length_to_beat: u32,
) -> u32 {
    debug_assert!(ms.c_params.min_match.clamp(3, 6) == MLS);
    if ms.window.index(ip) < ms.next_to_update {
        // A skipped area.
        return 0;
    }
    // The tree holds no position of an attached CDict: as without one.
    if DICT_MODE == ZSTD_EXT_DICT {
        update_tree_internal::<MLS, true>(ms, src, dict, ip, i_high_limit);
    } else {
        update_tree_internal::<MLS, false>(ms, src, dict, ip, i_high_limit);
    }
    insert_bt_and_get_all_matches::<MLS, DICT_MODE>(
        matches,
        ms,
        next_to_update3,
        src,
        dict,
        dms,
        ip,
        i_high_limit,
        rep,
        ll0,
        length_to_beat,
    )
}

/// `ZSTD_selectBtGetAllMatches`: the search for the shortest match, 3 to
/// 6 bytes (libzstd takes 7 as 6 here).
fn select_bt_get_all_matches<const DICT_MODE: u8>(min_match: u32) -> GetAllMatchesFn {
    match min_match.clamp(3, 6) {
        3 => bt_get_all_matches::<3, DICT_MODE>,
        4 => bt_get_all_matches::<4, DICT_MODE>,
        5 => bt_get_all_matches::<5, DICT_MODE>,
        _ => bt_get_all_matches::<6, DICT_MODE>,
    }
}

// ---------------------------------------------------------------------------
// The optimal parser

// ---------------------------------------------------------------------------
// Long distance matching

/// `ZSTD_optLdm_t`: the matches long distance matching found in the block,
/// which the parser takes among its candidates, and where it is in them:
/// a copy of the store's position (the context moves the store past the
/// block after the parser), and the next match's place in the block.
struct OptLdm<'a> {
    seq: &'a [RawSeq],
    pos: usize,
    pos_in_sequence: usize,
    /// Where the next match starts and ends in the block; `u32::MAX` for
    /// no more.
    start_pos_in_block: u32,
    end_pos_in_block: u32,
    /// Its offset.
    offset: u32,
}

impl<'a> OptLdm<'a> {
    /// The store's matches from its position, or none (`kNullRawSeqStore`).
    fn new(store: Option<&'a RawSeqStore>) -> Self {
        let (seq, pos, pos_in_sequence) = match store {
            Some(store) => (&store.seq[..], store.pos, store.pos_in_sequence),
            None => (&[][..], 0, 0),
        };
        OptLdm {
            seq,
            pos,
            pos_in_sequence,
            start_pos_in_block: 0,
            end_pos_in_block: 0,
            offset: 0,
        }
    }

    /// Whether the store has no more matches.
    fn is_empty(&self) -> bool {
        self.seq.is_empty() || self.pos >= self.seq.len()
    }

    /// `ZSTD_optLdm_skipRawSeqStoreBytes`: on by `nb_bytes` in the matches.
    fn skip_raw_seq_store_bytes(&mut self, nb_bytes: usize) {
        let mut curr_pos = (self.pos_in_sequence + nb_bytes) as u32;
        while curr_pos != 0 && self.pos < self.seq.len() {
            let curr_seq = self.seq[self.pos];
            if curr_pos >= curr_seq.lit_length + curr_seq.match_length {
                curr_pos -= curr_seq.lit_length + curr_seq.match_length;
                self.pos += 1;
            } else {
                self.pos_in_sequence = curr_pos as usize;
                break;
            }
        }
        if curr_pos == 0 || self.pos == self.seq.len() {
            self.pos_in_sequence = 0;
        }
    }

    /// `ZSTD_opt_getNextMatchAndUpdateSeqStore`: where the next match starts
    /// and ends in the block, from `curr_pos_in_block` with
    /// `block_bytes_remaining` left, and the store's position after it.
    fn get_next_match_and_update_seq_store(
        &mut self,
        curr_pos_in_block: u32,
        block_bytes_remaining: u32,
    ) {
        // No match for the rest of the block.
        if self.is_empty() {
            self.start_pos_in_block = u32::MAX;
            self.end_pos_in_block = u32::MAX;
            return;
        }
        // What is left of the match's literals and of the match, from the
        // position in the sequence.
        let curr_seq = self.seq[self.pos];
        debug_assert!(
            self.pos_in_sequence <= (curr_seq.lit_length + curr_seq.match_length) as usize
        );
        let curr_block_end_pos = curr_pos_in_block + block_bytes_remaining;
        let pos_in_sequence = self.pos_in_sequence as u32;
        let literals_bytes_remaining = curr_seq.lit_length.saturating_sub(pos_in_sequence);
        let match_bytes_remaining = if literals_bytes_remaining == 0 {
            curr_seq.match_length - (pos_in_sequence - curr_seq.lit_length)
        } else {
            curr_seq.match_length
        };

        // More literals than the block has left: no match in it.
        if literals_bytes_remaining >= block_bytes_remaining {
            self.start_pos_in_block = u32::MAX;
            self.end_pos_in_block = u32::MAX;
            self.skip_raw_seq_store_bytes(block_bytes_remaining as usize);
            return;
        }

        // Shorter than the shortest match, it may be: the parser then
        // leaves it.
        self.start_pos_in_block = curr_pos_in_block + literals_bytes_remaining;
        self.end_pos_in_block = self.start_pos_in_block + match_bytes_remaining;
        self.offset = curr_seq.offset;

        if self.end_pos_in_block > curr_block_end_pos {
            // Past the block's end: up to it.
            self.end_pos_in_block = curr_block_end_pos;
            self.skip_raw_seq_store_bytes((curr_block_end_pos - curr_pos_in_block) as usize);
        } else {
            // All of what is left of the sequence.
            self.skip_raw_seq_store_bytes(
                (literals_bytes_remaining + match_bytes_remaining) as usize,
            );
        }
    }

    /// `ZSTD_optLdm_maybeAddMatch`: the match, if `curr_pos_in_block` is in
    /// it and it is long enough, after the others in `matches` when it is
    /// the longest (or the only one).
    fn maybe_add_match(
        &self,
        matches: &mut [OptMatch],
        nb_matches: &mut usize,
        curr_pos_in_block: u32,
        min_match: u32,
    ) {
        let pos_diff = curr_pos_in_block.wrapping_sub(self.start_pos_in_block);
        let candidate_match_length = self
            .end_pos_in_block
            .wrapping_sub(self.start_pos_in_block)
            .wrapping_sub(pos_diff);

        // In the match, and long enough.
        if curr_pos_in_block < self.start_pos_in_block
            || curr_pos_in_block >= self.end_pos_in_block
            || candidate_match_length < min_match
        {
            return;
        }

        if *nb_matches == 0
            || (candidate_match_length > matches[*nb_matches - 1].len && *nb_matches < ZSTD_OPT_NUM)
        {
            matches[*nb_matches] = OptMatch {
                off: offset_to_offbase(self.offset),
                len: candidate_match_length,
            };
            *nb_matches += 1;
        }
    }

    /// `ZSTD_optLdm_processMatchCandidate`: the match of long distance
    /// matching at `curr_pos_in_block`, if any, among `matches`, the
    /// store moved on as needed.
    fn process_match_candidate(
        &mut self,
        matches: &mut [OptMatch],
        nb_matches: &mut usize,
        curr_pos_in_block: u32,
        remaining_bytes: u32,
        min_match: u32,
    ) {
        if self.is_empty() {
            return;
        }
        if curr_pos_in_block >= self.end_pos_in_block {
            if curr_pos_in_block > self.end_pos_in_block {
                // The parser asks past the match's end, often: the store
                // moves on by as much.
                let pos_overshoot = curr_pos_in_block - self.end_pos_in_block;
                self.skip_raw_seq_store_bytes(pos_overshoot as usize);
            }
            self.get_next_match_and_update_seq_store(curr_pos_in_block, remaining_bytes);
        }
        self.maybe_add_match(matches, nb_matches, curr_pos_in_block, min_match);
    }
}

// ---------------------------------------------------------------------------
// The parser

/// `ZSTD_compressBlock_opt_generic`: the sequences of the block
/// `src[istart..iend]` into `seq_store`, at `OPT_LEVEL` 0 (`btopt`) or 2
/// (`btultra`, `btultra2`). With `DICT_MODE` [`ZSTD_EXT_DICT`], matches may
/// be in the window's older segment, `dict`; with
/// [`ZSTD_DICT_MATCH_STATE`], in the attached `CDict`, `dms`. Returns the
/// size of the literals left after the last sequence.
///
/// From a match found, the parser looks ahead for the cheapest way to each
/// position up to the end of the longest matches found on the way: as a
/// match, followed by literals (a "stretch"), priced with the statistics.
/// Then it goes back from the end of the last stretch to store the
/// sequences of the cheapest way, and starts again after them.
///
/// The matches of long distance matching, `ldm` (`ms->ldmSeqStore`), are
/// among the candidates of each position.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn compress_block_opt_generic<const OPT_LEVEL: u32, const DICT_MODE: u8>(
    ms: &mut MatchState,
    opt_state: &mut OptState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: &[u8],
    dms: Option<DictMatchState<'_>>,
    istart: usize,
    iend: usize,
    symbol_costs: &EntropyCTables,
    ldm: Option<&RawSeqStore>,
) -> usize {
    let mut ip = istart;
    let mut anchor = istart;
    // Before the block for small blocks, where libzstd's pointer goes
    // before the buffer and the parser ends at once.
    let ilimit = iend as i64 - 8;
    let base = ms.window.base;
    let prefix_start = (i64::from(ms.window.dict_limit) - base) as usize;
    let c_params = ms.c_params;

    let get_all_matches = select_bt_get_all_matches::<DICT_MODE>(c_params.min_match);

    let sufficient_len = c_params.target_length.min(ZSTD_OPT_NUM as u32 - 1);
    let min_match = if c_params.min_match == 3 { 3 } else { 4 };
    let mut next_to_update3 = ms.next_to_update;

    // The tables, out of the state while the prices read it.
    let mut opt = std::mem::take(&mut opt_state.price_table);
    let mut matches = std::mem::take(&mut opt_state.match_table);
    opt.resize(ZSTD_OPT_SIZE, Optimal::default());
    matches.resize(ZSTD_OPT_SIZE, OptMatch::default());
    let mut last_stretch = Optimal::default();

    let mut opt_ldm = OptLdm::new(ldm);
    opt_ldm.get_next_match_and_update_seq_store((ip - istart) as u32, (iend - ip) as u32);

    // Init.
    debug_assert!(OPT_LEVEL <= 2);
    rescale_freqs::<OPT_LEVEL>(opt_state, &src[istart..iend], symbol_costs);
    // The frame's first position, even with a CDict attached.
    ip += usize::from(ip == prefix_start);

    // The match loop.
    'match_loop: while (ip as i64) < ilimit {
        let mut cur: u32;
        let mut last_pos: u32;

        'shortest_path: {
            // The first match.
            {
                let litlen = (ip - anchor) as u32;
                let ll0 = u32::from(litlen == 0);
                let mut nb_matches = get_all_matches(
                    &mut matches,
                    ms,
                    &mut next_to_update3,
                    src,
                    dict,
                    dms,
                    ip,
                    iend,
                    rep,
                    ll0,
                    min_match,
                ) as usize;
                opt_ldm.process_match_candidate(
                    &mut matches,
                    &mut nb_matches,
                    (ip - istart) as u32,
                    (iend - ip) as u32,
                    min_match,
                );
                if nb_matches == 0 {
                    ip += 1;
                    continue 'match_loop;
                }

                // A match: the start of a series. From here, `opt` holds
                // stretches, a match followed by literals, rather than
                // sequences, literals followed by a match: each literal
                // position keeps the match it comes after.

                // opt[0]: only literals so far. Their price is the same
                // for every way, and left out; their length's is not, as
                // it changes with the literals after them.
                opt[0].mlen = 0;
                opt[0].litlen = litlen;
                opt[0].price = ll_price::<OPT_LEVEL>(litlen, opt_state);
                opt[0].rep = *rep;

                // A long match: taken at once.
                {
                    let max_ml = matches[nb_matches - 1].len;
                    let max_off_base = matches[nb_matches - 1].off;
                    if max_ml > sufficient_len {
                        last_stretch.litlen = 0;
                        last_stretch.mlen = max_ml;
                        last_stretch.off = max_off_base;
                        cur = 0;
                        last_pos = max_ml;
                        break 'shortest_path;
                    }
                }

                // The prices of the first matches, from position 0.
                debug_assert!(opt[0].price >= 0);
                {
                    let mut pos = 1;
                    while pos < min_match {
                        let entry = &mut opt[pos as usize];
                        entry.price = ZSTD_MAX_PRICE;
                        entry.mlen = 0;
                        entry.litlen = litlen + pos;
                        pos += 1;
                    }
                    for found in &matches[..nb_matches] {
                        let off_base = found.off;
                        let end = found.len;
                        while pos <= end {
                            let match_price =
                                get_match_price::<OPT_LEVEL>(off_base, pos, opt_state) as i32;
                            let sequence_price = opt[0].price + match_price;
                            let entry = &mut opt[pos as usize];
                            entry.mlen = pos;
                            entry.off = off_base;
                            // The end of a match.
                            entry.litlen = 0;
                            entry.price = sequence_price + ll_price::<OPT_LEVEL>(0, opt_state);
                            pos += 1;
                        }
                    }
                    last_pos = pos - 1;
                    opt[pos as usize].price = ZSTD_MAX_PRICE;
                }
            }

            // The positions after.
            cur = 1;
            'forward: while cur <= last_pos {
                'next_position: {
                    let c = cur as usize;
                    let inr = ip + c;
                    debug_assert!(c <= ZSTD_OPT_NUM);

                    // A literal here, if cheaper.
                    {
                        let litlen = opt[c - 1].litlen + 1;
                        let price = opt[c - 1].price
                            + lit_price::<OPT_LEVEL>(src[ip + c - 1], opt_state)
                            + ll_inc_price::<OPT_LEVEL>(litlen, opt_state);
                        // Overflow check.
                        debug_assert!(price < 1_000_000_000);
                        if price <= opt[c].price {
                            let prev_match = opt[c];
                            opt[c] = opt[c - 1];
                            opt[c].litlen = litlen;
                            opt[c].price = price;
                            if OPT_LEVEL >= 1
                                // A match replaced,
                                && prev_match.litlen == 0
                                // a length of 1 cheaper than 0,
                                && ll_inc_price::<OPT_LEVEL>(1, opt_state) < 0
                                && ip + c < iend
                            {
                                // and the match, then a literal, may be
                                // cheaper at the next position.
                                let with1literal = prev_match.price
                                    + lit_price::<OPT_LEVEL>(src[ip + c], opt_state)
                                    + ll_inc_price::<OPT_LEVEL>(1, opt_state);
                                let with_more_literals = price
                                    + lit_price::<OPT_LEVEL>(src[ip + c], opt_state)
                                    + ll_inc_price::<OPT_LEVEL>(litlen + 1, opt_state);
                                if with1literal < with_more_literals
                                    && with1literal < opt[c + 1].price
                                {
                                    // The repeat offsets after the match,
                                    // before they are lost.
                                    let prev = (cur - prev_match.mlen) as usize;
                                    let new_reps = zstd_new_rep(
                                        &opt[prev].rep,
                                        prev_match.off,
                                        opt[prev].litlen == 0,
                                    );
                                    debug_assert!(cur >= prev_match.mlen);
                                    // Its length and offset base.
                                    opt[c + 1] = prev_match;
                                    opt[c + 1].rep = new_reps;
                                    opt[c + 1].litlen = 1;
                                    opt[c + 1].price = with1literal;
                                    if last_pos < cur + 1 {
                                        last_pos = cur + 1;
                                    }
                                }
                            }
                        }
                    }

                    // The repeat offsets change only now that the match
                    // is chosen, not as matches are compared.
                    debug_assert!(cur >= opt[c].mlen);
                    if opt[c].litlen == 0 {
                        // The end of a match.
                        let prev = (cur - opt[c].mlen) as usize;
                        opt[c].rep =
                            zstd_new_rep(&opt[prev].rep, opt[c].off, opt[prev].litlen == 0);
                    }

                    // The last match starts 8 bytes or more before the end.
                    if inr as i64 > ilimit {
                        break 'next_position;
                    }

                    if cur == last_pos {
                        break 'forward;
                    }

                    if OPT_LEVEL == 0
                        && opt[c + 1].price <= opt[c].price + (BITCOST_MULTIPLIER / 2) as i32
                    {
                        // Not worth searching: the next position is cheaper
                        // (about 6% faster, 0.01 less ratio).
                        break 'next_position;
                    }

                    debug_assert!(opt[c].price >= 0);
                    {
                        let ll0 = u32::from(opt[c].litlen == 0);
                        let previous_price = opt[c].price;
                        let base_price = previous_price + ll_price::<OPT_LEVEL>(0, opt_state);
                        let cur_rep = opt[c].rep;
                        let mut nb_matches = get_all_matches(
                            &mut matches,
                            ms,
                            &mut next_to_update3,
                            src,
                            dict,
                            dms,
                            inr,
                            iend,
                            &cur_rep,
                            ll0,
                            min_match,
                        ) as usize;
                        opt_ldm.process_match_candidate(
                            &mut matches,
                            &mut nb_matches,
                            (inr - istart) as u32,
                            (iend - inr) as u32,
                            min_match,
                        );

                        if nb_matches == 0 {
                            break 'next_position;
                        }

                        {
                            let longest_ml = matches[nb_matches - 1].len;
                            if longest_ml > sufficient_len
                                || cur + longest_ml >= ZSTD_OPT_NUM as u32
                                || ip + (cur + longest_ml) as usize >= iend
                            {
                                last_stretch.mlen = longest_ml;
                                last_stretch.off = matches[nb_matches - 1].off;
                                last_stretch.litlen = 0;
                                last_pos = cur + longest_ml;
                                break 'shortest_path;
                            }
                        }

                        // The prices of the matches found here.
                        for match_nb in 0..nb_matches {
                            let offset = matches[match_nb].off;
                            let last_ml = matches[match_nb].len;
                            let start_ml = if match_nb > 0 {
                                matches[match_nb - 1].len + 1
                            } else {
                                min_match
                            };

                            // Downward.
                            let mut mlen = last_ml;
                            while mlen >= start_ml {
                                let pos = cur + mlen;
                                let price = base_price
                                    + get_match_price::<OPT_LEVEL>(offset, mlen, opt_state) as i32;

                                if pos > last_pos || price < opt[pos as usize].price {
                                    while last_pos < pos {
                                        // The positions not reached yet,
                                        // for the comparisons to come.
                                        last_pos += 1;
                                        opt[last_pos as usize].price = ZSTD_MAX_PRICE;
                                        // Not the end of a match.
                                        opt[last_pos as usize].litlen = 1;
                                    }
                                    let entry = &mut opt[pos as usize];
                                    entry.mlen = mlen;
                                    entry.off = offset;
                                    entry.litlen = 0;
                                    entry.price = price;
                                } else if OPT_LEVEL == 0 {
                                    // Stop early (about 10% faster, 0.01
                                    // less ratio).
                                    break;
                                }
                                mlen -= 1;
                            }
                        }
                    }
                    opt[last_pos as usize + 1].price = ZSTD_MAX_PRICE;
                }
                cur += 1;
            }

            last_stretch = opt[last_pos as usize];
            debug_assert!(cur >= last_stretch.mlen);
            cur = last_pos - last_stretch.mlen;
        }

        // _shortestPath: cur, last_pos and last_stretch are set.
        debug_assert!(opt[0].mlen == 0);
        debug_assert!(last_pos >= last_stretch.mlen);
        debug_assert!(cur == last_pos - last_stretch.mlen);

        if last_stretch.mlen == 0 {
            // No match: they all turned into literals.
            debug_assert!(last_stretch.litlen as usize == (ip - anchor) + last_pos as usize);
            ip += last_pos as usize;
            continue 'match_loop;
        }
        debug_assert!(last_stretch.off > 0);

        // The repeat offsets.
        if last_stretch.litlen == 0 {
            // Ending on a match.
            *rep = zstd_new_rep(
                &opt[cur as usize].rep,
                last_stretch.off,
                opt[cur as usize].litlen == 0,
            );
        } else {
            *rep = last_stretch.rep;
            debug_assert!(cur >= last_stretch.litlen);
            cur -= last_stretch.litlen;
        }

        // The cheapest way, back from its end: in `opt` from `store_end`
        // (cur + 2) down, over what the forward pass left there, as
        // sequences, literals then a match, where the forward pass had
        // stretches. The last stretch's literals are left for the next
        // series.
        //
        // Differs from libzstd: libzstd first writes the last stretch's
        // literals into opt[storeEnd] and the stretch into
        // opt[storeEnd - 1], then the stretch into opt[storeEnd]: the block
        // after its `if` is not an `else`, and always runs. The port only
        // does the last write. The others change nothing: opt[storeEnd]
        // is written over, and opt[storeEnd - 1] is past every stretch the
        // way back reads, and stored only once the way back writes it.
        {
            let store_end = cur as usize + 2;
            let mut store_start = store_end;
            let mut stretch_pos = cur as usize;
            debug_assert!(store_end < ZSTD_OPT_SIZE);
            // Its literal length is fixed below.
            opt[store_end] = last_stretch;
            loop {
                let next_stretch = opt[stretch_pos];
                opt[store_start].litlen = next_stretch.litlen;
                if next_stretch.mlen == 0 {
                    // The start of the series.
                    break;
                }
                store_start -= 1;
                // Its literal length is fixed at the next turn.
                opt[store_start] = next_stretch;
                debug_assert!((next_stretch.litlen + next_stretch.mlen) as usize <= stretch_pos);
                stretch_pos -= (next_stretch.litlen + next_stretch.mlen) as usize;
            }

            // The sequences into the store.
            for store_pos in store_start..=store_end {
                let llen = opt[store_pos].litlen;
                let mlen = opt[store_pos].mlen;
                let off_base = opt[store_pos].off;
                let advance = (llen + mlen) as usize;

                if mlen == 0 {
                    // Only literals: the last, which start the next series.
                    debug_assert!(store_pos == store_end);
                    ip = anchor + llen as usize;
                    continue;
                }

                debug_assert!(anchor + llen as usize <= iend);
                update_stats(opt_state, llen, &src[anchor..], off_base, mlen);
                seq_store.store_seq(src, anchor, llen as usize, off_base, mlen as usize);
                anchor += advance;
                ip = anchor;
            }

            // The prices with the new statistics.
            set_base_prices::<OPT_LEVEL>(opt_state);
        }
    }

    opt_state.price_table = opt;
    opt_state.match_table = matches;

    // The size of the last literals.
    iend - anchor
}

/// `ZSTD_initStats_ultra`: a first pass over the frame's first block, only
/// for its statistics, as the start of the second. Without a dictionary
/// or anything in the window before the block.
///
/// The window then forgets the first pass: its indices move on by the
/// block's size, which takes the block out of the window.
#[allow(clippy::too_many_arguments)]
fn init_stats_ultra(
    ms: &mut MatchState,
    opt_state: &mut OptState,
    seq_store: &mut SeqStore,
    rep: &[u32; ZSTD_REP_NUM],
    src: &[u8],
    istart: usize,
    iend: usize,
    symbol_costs: &EntropyCTables,
    ldm: Option<&RawSeqStore>,
) {
    let src_size = iend - istart;
    // The repeat offsets the first pass leaves are dropped.
    let mut tmp_rep = *rep;

    // The first block.
    debug_assert!(opt_state.lit_length_sum == 0);
    // No sequences of long distance matching stored; its matches as the
    // parser's candidates, it may have.
    debug_assert!(seq_store.sequences.is_empty());
    // No dictionary.
    debug_assert!(ms.window.dict_limit == ms.window.low_limit);
    // No prefix (the wrap around is libzstd's).
    debug_assert!(ms.window.dict_limit.wrapping_sub(ms.next_to_update) <= 1);

    // The statistics into the state.
    compress_block_opt_generic::<2, ZSTD_NO_DICT>(
        ms,
        opt_state,
        seq_store,
        &mut tmp_rep,
        src,
        &[],
        None,
        istart,
        iend,
        symbol_costs,
        ldm,
    );

    // The first pass out of the window; only its statistics stay.
    //
    // libzstd moves `base` back by the block's size. The port's `base` is
    // the index of the buffer's first byte, which moves forward, as does
    // `next_src`, an index here where libzstd keeps a pointer.
    seq_store.reset();
    ms.window.base += src_size as i64;
    ms.window.next_src += src_size as i64;
    ms.window.dict_limit += src_size as u32;
    ms.window.low_limit = ms.window.dict_limit;
    ms.next_to_update = ms.window.dict_limit;
}

/// The block compressors: `ZSTD_compressBlock_btopt`, `_btultra` and
/// `_btultra2`, and their `_extDict` variants when `dict` is given
/// (`btultra2` has none: it takes `btultra`'s). The sequences of the block
/// `src[istart..iend]` into `seq_store`. Returns the size of the literals
/// left after the last sequence.
///
/// `symbol_costs` are the tables of the block before (`ms->opt.symbolCosts`,
/// which libzstd points at them), and `literal_compression_mode` the
/// frame's (`ms->opt.literalCompressionMode`), which libzstd sets for each
/// block.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_compress_block_opt(
    strategy: Strategy,
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dict: Option<&[u8]>,
    istart: usize,
    iend: usize,
    symbol_costs: &EntropyCTables,
    literal_compression_mode: ParamSwitch,
    ldm: Option<&RawSeqStore>,
) -> usize {
    with_opt_state(ms, literal_compression_mode, |ms, opt| {
        match (strategy, dict) {
            (Strategy::Btopt, None) => compress_block_opt_generic::<0, ZSTD_NO_DICT>(
                ms,
                opt,
                seq_store,
                rep,
                src,
                &[],
                None,
                istart,
                iend,
                symbol_costs,
                ldm,
            ),
            (Strategy::Btopt, Some(dict)) => compress_block_opt_generic::<0, ZSTD_EXT_DICT>(
                ms,
                opt,
                seq_store,
                rep,
                src,
                dict,
                None,
                istart,
                iend,
                symbol_costs,
                ldm,
            ),
            (Strategy::Btultra2, None) => {
                // ZSTD_compressBlock_btultra2: two passes over the first
                // block, the first to gather statistics for the second.
                // Only with nothing in the tables before (no dictionary, no
                // prefix, no long distance matching). About 0.5% smaller
                // for the first block, at twice the time.
                let curr = ms.window.index(istart);
                debug_assert!(iend - istart <= ZSTD_BLOCKSIZE_MAX);
                if opt.lit_length_sum == 0
                    // No long distance matching.
                    && seq_store.sequences.is_empty()
                    // No dictionary.
                    && ms.window.dict_limit == ms.window.low_limit
                    // The frame's start, nothing loaded or skipped.
                    && curr == ms.window.dict_limit
                    // Large enough for statistics.
                    && iend - istart > ZSTD_PREDEF_THRESHOLD
                {
                    init_stats_ultra(
                        ms,
                        opt,
                        seq_store,
                        rep,
                        src,
                        istart,
                        iend,
                        symbol_costs,
                        ldm,
                    );
                }
                compress_block_opt_generic::<2, ZSTD_NO_DICT>(
                    ms,
                    opt,
                    seq_store,
                    rep,
                    src,
                    &[],
                    None,
                    istart,
                    iend,
                    symbol_costs,
                    ldm,
                )
            }
            (_, None) => compress_block_opt_generic::<2, ZSTD_NO_DICT>(
                ms,
                opt,
                seq_store,
                rep,
                src,
                &[],
                None,
                istart,
                iend,
                symbol_costs,
                ldm,
            ),
            (_, Some(dict)) => compress_block_opt_generic::<2, ZSTD_EXT_DICT>(
                ms,
                opt,
                seq_store,
                rep,
                src,
                dict,
                None,
                istart,
                iend,
                symbol_costs,
                ldm,
            ),
        }
    })
}

/// `ZSTD_compressBlock_btopt_dictMatchState` and
/// `ZSTD_compressBlock_btultra_dictMatchState`, which `btultra2` takes too
/// (libzstd has no `btultra2` of its own for a dictionary: its first pass
/// is for frames with nothing before them). The frame is attached to a
/// `CDict`, `dms`. Otherwise as [`zstd_compress_block_opt`], `ldm` among
/// the candidates as without a dictionary.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_compress_block_opt_dict_match_state(
    strategy: Strategy,
    ms: &mut MatchState,
    seq_store: &mut SeqStore,
    rep: &mut [u32; ZSTD_REP_NUM],
    src: &[u8],
    dms: DictMatchState<'_>,
    istart: usize,
    iend: usize,
    symbol_costs: &EntropyCTables,
    literal_compression_mode: ParamSwitch,
    ldm: Option<&RawSeqStore>,
) -> usize {
    with_opt_state(ms, literal_compression_mode, |ms, opt| {
        if strategy == Strategy::Btopt {
            compress_block_opt_generic::<0, ZSTD_DICT_MATCH_STATE>(
                ms,
                opt,
                seq_store,
                rep,
                src,
                &[],
                Some(dms),
                istart,
                iend,
                symbol_costs,
                ldm,
            )
        } else {
            compress_block_opt_generic::<2, ZSTD_DICT_MATCH_STATE>(
                ms,
                opt,
                seq_store,
                rep,
                src,
                &[],
                Some(dms),
                istart,
                iend,
                symbol_costs,
                ldm,
            )
        }
    })
}

/// `f` with the optimal parser's state, taken out of `ms` while it runs
/// (see [`MatchState::opt`]), for a block whose literals are compressed as
/// `literal_compression_mode` says.
fn with_opt_state(
    ms: &mut MatchState,
    literal_compression_mode: ParamSwitch,
    f: impl FnOnce(&mut MatchState, &mut OptState) -> usize,
) -> usize {
    // The context reserves the state for these strategies.
    let mut opt_state = ms.opt.take().unwrap_or_else(|| Box::new(OptState::new()));
    opt_state.literal_compression_mode = literal_compression_mode;
    let last_ll_size = f(ms, &mut opt_state);
    ms.opt = Some(opt_state);
    last_ll_size
}
