//! A block's sequences section: port of `compress/zstd_compress_sequences.c`.
//!
//! The port writes sequences as libzstd does on 64-bit machines, where an
//! offset's extra bits always fit the register (`longOffsets` is only ever
//! set on 32-bit machines, for windows over 2^25).

use crate::zstd::common::bitstream::BitCStream;
use crate::zstd::common::error_private::{Error, ErrorCode, Result, error};
use crate::zstd::common::fse::{FSE_NCOUNTBOUND, FseCState, ctable_u16, fse_bit_cost};
use crate::zstd::common::zstd_internal::{
    LL_BITS, LL_FSE_LOG, MAX_LL, MAX_ML, MAX_OFF, MAX_SEQ, ML_BITS, ML_FSE_LOG, OFF_FSE_LOG,
    SymbolEncodingType,
};
use crate::zstd::compress::fse_compress::{
    fse_build_ctable_rle, fse_build_ctable_wksp, fse_normalize_count, fse_optimal_table_log,
    fse_write_ncount,
};
use crate::zstd::compress::zstd_compress_internal::{FseRepeat, SeqDef, Strategy};

/// `kInverseProbabilityLog256`: `floor(-log2(x / 256) * 256)` for `x` in
/// `[0, 256)`, and 0 for 0.
const K_INVERSE_PROBABILITY_LOG256: [u32; 256] = [
    0, 2048, 1792, 1642, 1536, 1453, 1386, 1329, 1280, 1236, 1197, 1162, 1130, 1100, 1073, 1047,
    1024, 1001, 980, 960, 941, 923, 906, 889, 874, 859, 844, 830, 817, 804, 791, 779, 768, 756,
    745, 734, 724, 714, 704, 694, 685, 676, 667, 658, 650, 642, 633, 626, 618, 610, 603, 595, 588,
    581, 574, 567, 561, 554, 548, 542, 535, 529, 523, 517, 512, 506, 500, 495, 489, 484, 478, 473,
    468, 463, 458, 453, 448, 443, 438, 434, 429, 424, 420, 415, 411, 407, 402, 398, 394, 390, 386,
    382, 377, 373, 370, 366, 362, 358, 354, 350, 347, 343, 339, 336, 332, 329, 325, 322, 318, 315,
    311, 308, 305, 302, 298, 295, 292, 289, 286, 282, 279, 276, 273, 270, 267, 264, 261, 258, 256,
    253, 250, 247, 244, 241, 239, 236, 233, 230, 228, 225, 222, 220, 217, 215, 212, 209, 207, 204,
    202, 199, 197, 194, 192, 190, 187, 185, 182, 180, 178, 175, 173, 171, 168, 166, 164, 162, 159,
    157, 155, 153, 151, 149, 146, 144, 142, 140, 138, 136, 134, 132, 130, 128, 126, 123, 121, 119,
    117, 115, 114, 112, 110, 108, 106, 104, 102, 100, 98, 96, 94, 93, 91, 89, 87, 85, 83, 82, 80,
    78, 76, 74, 73, 71, 69, 67, 66, 64, 62, 61, 59, 57, 55, 54, 52, 50, 49, 47, 46, 44, 42, 41, 39,
    37, 36, 34, 33, 31, 30, 28, 26, 25, 23, 22, 20, 19, 17, 16, 14, 13, 11, 10, 8, 7, 5, 4, 2, 1,
];

/// `ZSTD_getFSEMaxSymbolValue`: the largest symbol of a table.
fn zstd_get_fse_max_symbol_value(ctable: &[u32]) -> u32 {
    u32::from(ctable_u16(ctable, 1))
}

/// `ZSTD_useLowProbCount`: whether the rarest symbols get -1 rather than 1.
/// A heuristic for blocks up to about 16 KB, fading out by 32 KB.
fn zstd_use_low_prob_count(nb_seq: usize) -> bool {
    nb_seq >= 2048
}

/// `ZSTD_NCountCost`: the bytes of the table description of `count`.
fn zstd_ncount_cost(count: &[u32], max: u32, nb_seq: usize, fse_log: u32) -> Result<usize> {
    let mut wksp = [0u8; FSE_NCOUNTBOUND];
    let mut norm = [0i16; MAX_SEQ as usize + 1];
    let table_log = fse_optimal_table_log(fse_log, nb_seq, max);
    fse_normalize_count(
        &mut norm,
        table_log,
        count,
        nb_seq,
        max,
        zstd_use_low_prob_count(nb_seq),
    )?;
    fse_write_ncount(&mut wksp, &norm, max, table_log)
}

/// `ZSTD_entropyCost`: the bits of `count` at the entropy bound.
fn zstd_entropy_cost(count: &[u32], max: u32, total: usize) -> usize {
    let mut cost: u32 = 0;
    debug_assert!(total > 0);
    for &c in &count[..=max as usize] {
        let mut norm = ((256 * c as usize) / total) as u32;
        if c != 0 && norm == 0 {
            norm = 1;
        }
        debug_assert!((c as usize) < total);
        cost = cost.wrapping_add(c.wrapping_mul(K_INVERSE_PROBABILITY_LOG256[norm as usize]));
    }
    (cost >> 8) as usize
}

/// `ZSTD_fseBitCost`: the bits of `count` with `ctable`, or an error when
/// the table lacks one of its symbols.
pub(crate) fn zstd_fse_bit_cost(ctable: &[u32], count: &[u32], max: u32) -> Result<usize> {
    const K_ACCURACY_LOG: u32 = 8;
    let mut cost: usize = 0;
    let cstate = FseCState::new(ctable);
    if zstd_get_fse_max_symbol_value(ctable) < max {
        return error!(Generic);
    }
    let table_log = u32::from(ctable_u16(ctable, 0));
    for s in 0..=max {
        let bad_cost = (table_log + 1) << K_ACCURACY_LOG;
        let bit_cost = fse_bit_cost(ctable, cstate.symbol_tt(), table_log, s, K_ACCURACY_LOG);
        if count[s as usize] == 0 {
            continue;
        }
        if bit_cost >= bad_cost {
            return error!(Generic);
        }
        cost += count[s as usize] as usize * bit_cost as usize;
    }
    Ok(cost >> K_ACCURACY_LOG)
}

/// `ZSTD_crossEntropyCost`: the bits of `count` with the table of `norm`,
/// which has every symbol of `count`.
pub(crate) fn zstd_cross_entropy_cost(
    norm: &[i16],
    accuracy_log: u32,
    count: &[u32],
    max: u32,
) -> usize {
    let shift = 8 - accuracy_log;
    let mut cost: usize = 0;
    debug_assert!(accuracy_log <= 8);
    for s in 0..=max as usize {
        let norm_acc = if norm[s] != -1 { norm[s] as u32 } else { 1 };
        let norm256 = norm_acc << shift;
        debug_assert!(norm256 > 0 && norm256 < 256);
        cost += count[s] as usize * K_INVERSE_PROBABILITY_LOG256[norm256 as usize] as usize;
    }
    cost >> 8
}

/// `ZSTD_DefaultPolicy_e`: whether the default table may be used.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DefaultPolicy {
    Disallowed = 0,
    Allowed = 1,
}

/// A cost, or libzstd's error code (`(size_t)-code`) standing in for "not
/// possible", which compares larger than any cost.
fn cost_or_max(cost: Result<usize>) -> usize {
    match cost {
        Ok(cost) => cost,
        Err(error) => (error.code().number() as usize).wrapping_neg(),
    }
}

/// `ZSTD_selectEncodingType`: how to encode one kind of code: the default
/// table, one symbol, the previous block's table, or a new one. Sets
/// `*repeat_mode` for the next block.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_select_encoding_type(
    repeat_mode: &mut FseRepeat,
    count: &[u32],
    max: u32,
    most_frequent: usize,
    nb_seq: usize,
    fse_log: u32,
    prev_ctable: &[u32],
    default_norm: &[i16],
    default_norm_log: u32,
    is_default_allowed: DefaultPolicy,
    strategy: Strategy,
) -> SymbolEncodingType {
    let default_allowed = is_default_allowed == DefaultPolicy::Allowed;
    if most_frequent == nb_seq {
        *repeat_mode = FseRepeat::None;
        if default_allowed && nb_seq <= 2 {
            // set_basic rather than set_rle for 2 symbols or fewer: RLE
            // takes 1 byte, basic 5 or 6 bits per symbol. When basic is not
            // possible, RLE.
            return SymbolEncodingType::Basic;
        }
        return SymbolEncodingType::Rle;
    }
    if strategy < Strategy::Lazy {
        if default_allowed {
            let static_fse_nb_seq_max = 1000;
            let mult = 10 - strategy as usize;
            let base_log = 3;
            // 28-36 for offsets, 56-72 for lengths.
            let dynamic_fse_nb_seq_min = ((1usize << default_norm_log) * mult) >> base_log;
            debug_assert!((5..=6).contains(&default_norm_log));
            debug_assert!((7..=9).contains(&mult));
            if *repeat_mode == FseRepeat::Valid && nb_seq < static_fse_nb_seq_max {
                return SymbolEncodingType::Repeat;
            }
            if nb_seq < dynamic_fse_nb_seq_min || most_frequent < (nb_seq >> (default_norm_log - 1))
            {
                // The format allows repeating the default tables, but it
                // does not help, and with simple heuristics they must not be
                // taken for a dictionary's.
                *repeat_mode = FseRepeat::None;
                return SymbolEncodingType::Basic;
            }
        }
    } else {
        let basic_cost = if default_allowed {
            zstd_cross_entropy_cost(default_norm, default_norm_log, count, max)
        } else {
            cost_or_max(error!(Generic))
        };
        let repeat_cost = if *repeat_mode != FseRepeat::None {
            cost_or_max(zstd_fse_bit_cost(prev_ctable, count, max))
        } else {
            cost_or_max(error!(Generic))
        };
        let ncount_cost = zstd_ncount_cost(count, max, nb_seq, fse_log);
        debug_assert!(ncount_cost.is_ok());
        let compressed_cost =
            (cost_or_max(ncount_cost) << 3).wrapping_add(zstd_entropy_cost(count, max, nb_seq));

        if basic_cost <= repeat_cost && basic_cost <= compressed_cost {
            debug_assert!(default_allowed);
            *repeat_mode = FseRepeat::None;
            return SymbolEncodingType::Basic;
        }
        if repeat_cost <= compressed_cost {
            return SymbolEncodingType::Repeat;
        }
    }
    *repeat_mode = FseRepeat::Check;
    SymbolEncodingType::Compressed
}

/// `ZSTD_buildCTable`: the table of one kind of code into `next_ctable`,
/// and its description, if any, into `dst`. Returns the description's size.
/// For a new table, the last code's count is lowered by one first, as
/// libzstd does.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_build_ctable(
    dst: &mut [u8],
    next_ctable: &mut [u32],
    fse_log: u32,
    encoding_type: SymbolEncodingType,
    count: &mut [u32],
    max: u32,
    code_table: &[u8],
    nb_seq: usize,
    default_norm: &[i16],
    default_norm_log: u32,
    default_max: u32,
    prev_ctable: &[u32],
) -> Result<usize> {
    match encoding_type {
        SymbolEncodingType::Rle => {
            fse_build_ctable_rle(next_ctable, max as u8);
            if dst.is_empty() {
                return error!(DstSizeTooSmall);
            }
            dst[0] = code_table[0];
            Ok(1)
        }
        SymbolEncodingType::Repeat => {
            next_ctable.copy_from_slice(prev_ctable);
            Ok(0)
        }
        SymbolEncodingType::Basic => {
            // Could be computed once.
            fse_build_ctable_wksp(next_ctable, default_norm, default_max, default_norm_log)?;
            Ok(0)
        }
        SymbolEncodingType::Compressed => {
            let mut norm = [0i16; MAX_SEQ as usize + 1];
            let mut nb_seq_1 = nb_seq;
            let table_log = fse_optimal_table_log(fse_log, nb_seq, max);
            let last = usize::from(code_table[nb_seq - 1]);
            if count[last] > 1 {
                count[last] -= 1;
                nb_seq_1 -= 1;
            }
            debug_assert!(nb_seq_1 > 1);
            fse_normalize_count(
                &mut norm,
                table_log,
                count,
                nb_seq_1,
                max,
                zstd_use_low_prob_count(nb_seq_1),
            )?;
            // Protected from overflow.
            let ncount_size = fse_write_ncount(dst, &norm, max, table_log)?;
            fse_build_ctable_wksp(next_ctable, &norm, max, table_log)?;
            Ok(ncount_size)
        }
    }
}

/// `table`, padded with zeros to 256 entries, so that a code, a byte,
/// indexes it without a bounds check.
const fn padded<const N: usize>(table: [u8; N]) -> [u8; 256] {
    let mut out = [0u8; 256];
    let mut i = 0;
    while i < N {
        out[i] = table[i];
        i += 1;
    }
    out
}

/// `LL_bits` and `ML_bits`, padded.
const LL_BITS_256: [u8; 256] = padded(LL_BITS);
const ML_BITS_256: [u8; 256] = padded(ML_BITS);

/// `ZSTD_encodeSequences_body`: the sequences' bitstream, from the last to
/// the first, with the three tables.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_encode_sequences(
    dst: &mut [u8],
    ctable_match_length: &[u32],
    ml_code_table: &[u8],
    ctable_offset_bits: &[u32],
    of_code_table: &[u8],
    ctable_lit_length: &[u32],
    ll_code_table: &[u8],
    sequences: &[SeqDef],
) -> Result<usize> {
    let nb_seq = sequences.len();
    let Ok(mut block_stream) = BitCStream::new(dst) else {
        return Err(Error::from(ErrorCode::DstSizeTooSmall));
    };

    // The first symbols. The tables are cut at the sizes of the largest
    // ones, which the arrays they live in have room for, and their states
    // copied out.
    let last = nb_seq - 1;
    let mut ml_states = [[0; 2]; 1 << (ML_FSE_LOG - 1)];
    let mut of_states = [[0; 2]; 1 << (OFF_FSE_LOG - 1)];
    let mut ll_states = [[0; 2]; 1 << (LL_FSE_LOG - 1)];
    let mut state_match_length =
        FseCState::new2_copied::<{ 1 << (ML_FSE_LOG - 1) }, { MAX_ML as usize + 1 }>(
            ctable_match_length,
            u32::from(ml_code_table[last]),
            &mut ml_states,
        )?;
    let mut state_offset_bits =
        FseCState::new2_copied::<{ 1 << (OFF_FSE_LOG - 1) }, { MAX_OFF as usize + 1 }>(
            ctable_offset_bits,
            u32::from(of_code_table[last]),
            &mut of_states,
        )?;
    let mut state_lit_length =
        FseCState::new2_copied::<{ 1 << (LL_FSE_LOG - 1) }, { MAX_LL as usize + 1 }>(
            ctable_lit_length,
            u32::from(ll_code_table[last]),
            &mut ll_states,
        )?;
    block_stream.add_bits(
        u64::from(sequences[last].lit_length),
        u32::from(LL_BITS[usize::from(ll_code_table[last])]),
    );
    block_stream.add_bits(
        u64::from(sequences[last].ml_base),
        u32::from(ML_BITS[usize::from(ml_code_table[last])]),
    );
    block_stream.add_bits(
        u64::from(sequences[last].off_base),
        u32::from(of_code_table[last]),
    );
    block_stream.flush_bits();

    // The other sequences, from the last but one back to the first.
    for (((sequence, &ll_code), &of_code), &ml_code) in sequences[..last]
        .iter()
        .zip(&ll_code_table[..last])
        .zip(&of_code_table[..last])
        .zip(&ml_code_table[..last])
        .rev()
    {
        let ll_bits = u32::from(LL_BITS_256[usize::from(ll_code)]);
        let of_bits = u32::from(of_code);
        let ml_bits = u32::from(ML_BITS_256[usize::from(ml_code)]);
        // Bits in the register: (7), then 15, 24, 33, ... 31 at most.
        state_offset_bits.encode_symbol(&mut block_stream, u32::from(of_code));
        state_match_length.encode_symbol(&mut block_stream, u32::from(ml_code));
        state_lit_length.encode_symbol(&mut block_stream, u32::from(ll_code));
        if of_bits + ml_bits + ll_bits >= 64 - 7 - (LL_FSE_LOG + ML_FSE_LOG + OFF_FSE_LOG) {
            block_stream.flush_bits();
        }
        block_stream.add_bits(u64::from(sequence.lit_length), ll_bits);
        block_stream.add_bits(u64::from(sequence.ml_base), ml_bits);
        if of_bits + ml_bits + ll_bits > 56 {
            block_stream.flush_bits();
        }
        block_stream.add_bits(u64::from(sequence.off_base), of_bits);
        block_stream.flush_bits();
    }

    state_match_length.flush(&mut block_stream);
    state_offset_bits.flush(&mut block_stream);
    state_lit_length.flush(&mut block_stream);

    let stream_size = block_stream.close();
    if stream_size == 0 {
        // Not enough room.
        return error!(DstSizeTooSmall);
    }
    Ok(stream_size)
}
