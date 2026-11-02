//! Finite State Entropy encoding: port of `compress/fse_compress.c`.
//!
//! The tables are `FSE_CTable` word arrays laid out as libzstd lays them
//! out; see [`crate::zstd::common::fse`].

use crate::zstd::common::bits::highbit32;
use crate::zstd::common::bitstream::BitCStream;
use crate::zstd::common::error_private::{Result, error};
use crate::zstd::common::fse::{
    FSE_DEFAULT_TABLELOG, FSE_MAX_SYMBOL_VALUE, FSE_MAX_TABLELOG, FSE_MAX_TABLESIZE,
    FSE_MIN_TABLELOG, FSE_NCOUNTBOUND, FseCState, FseSymbolTransform, fse_blockbound,
    fse_tablestep, set_ctable_u16, set_symbol_transform, symbol_tt_start,
};

/// `FSE_buildCTable_wksp`: the encoding table of a normalized distribution
/// (from [`fse_normalize_count`]), into `ct`, which has room for
/// `fse_ctable_size_u32(table_log, max_symbol_value)` words.
///
/// libzstd fails when its caller's workspace is too small for the table;
/// the port has its own, large enough for every table.
pub(crate) fn fse_build_ctable_wksp(
    ct: &mut [u32],
    normalized_counter: &[i16],
    max_symbol_value: u32,
    table_log: u32,
) -> Result<()> {
    let table_size = 1u32 << table_log;
    let table_mask = table_size - 1;
    let symbol_tt = symbol_tt_start(table_log);
    let step = fse_tablestep(table_size);
    let max_sv1 = max_symbol_value as usize + 1;

    let mut cumul = [0u16; FSE_MAX_SYMBOL_VALUE as usize + 2];
    let mut table_symbol = [0u8; FSE_MAX_TABLESIZE];

    let mut high_threshold = table_size - 1;

    // The header.
    set_ctable_u16(ct, 0, table_log as u16);
    set_ctable_u16(ct, 1, max_symbol_value as u16);
    debug_assert!(table_log < 16);

    // Where each symbol starts.
    cumul[0] = 0;
    for u in 1..=max_sv1 {
        if normalized_counter[u - 1] == -1 {
            // A low-probability symbol.
            cumul[u] = cumul[u - 1] + 1;
            table_symbol[high_threshold as usize] = (u - 1) as u8;
            high_threshold = high_threshold.wrapping_sub(1);
        } else {
            debug_assert!(normalized_counter[u - 1] >= 0);
            cumul[u] = cumul[u - 1].wrapping_add(normalized_counter[u - 1] as u16);
        }
    }
    cumul[max_sv1] = (table_size + 1) as u16;

    // Spread the symbols.
    if high_threshold == table_size - 1 {
        // No low-probability symbol: lay the symbols down in order, then
        // spread them in steps, two at a time, as libzstd does.
        let mut spread = [0u8; FSE_MAX_TABLESIZE];
        let mut pos = 0;
        for (s, &n) in normalized_counter[..max_sv1].iter().enumerate() {
            debug_assert!(n >= 0);
            spread[pos..pos + n as usize].fill(s as u8);
            pos += n as usize;
        }
        let mut position = 0usize;
        let unroll = 2;
        debug_assert!(table_size.is_multiple_of(unroll));
        for s in (0..table_size as usize).step_by(unroll as usize) {
            for u in 0..unroll as usize {
                let u_position = (position + u * step as usize) & table_mask as usize;
                table_symbol[u_position] = spread[s + u];
            }
            position = (position + unroll as usize * step as usize) & table_mask as usize;
        }
        debug_assert!(position == 0);
    } else {
        let mut position = 0u32;
        for (symbol, &freq) in normalized_counter[..max_sv1].iter().enumerate() {
            for _ in 0..freq.max(0) {
                table_symbol[position as usize] = symbol as u8;
                position = (position + step) & table_mask;
                while position > high_threshold {
                    // The low-probability area.
                    position = (position + step) & table_mask;
                }
            }
        }
        debug_assert!(position == 0);
    }

    // The state table, sorted by symbol: the next state of each.
    for u in 0..table_size {
        let s = usize::from(table_symbol[u as usize]);
        set_ctable_u16(ct, 2 + usize::from(cumul[s]), (table_size + u) as u16);
        cumul[s] += 1;
    }

    // The symbol transforms.
    let mut total: u32 = 0;
    for s in 0..=max_symbol_value {
        let n = normalized_counter[s as usize];
        let transform = match n {
            // Filled anyway, for FSE_getMaxNbBits.
            0 => FseSymbolTransform {
                delta_find_state: crate::zstd::common::fse::symbol_transform(ct, symbol_tt, s)
                    .delta_find_state,
                delta_nb_bits: ((table_log + 1) << 16).wrapping_sub(1 << table_log),
            },
            -1 | 1 => {
                let transform = FseSymbolTransform {
                    delta_find_state: total.wrapping_sub(1) as i32,
                    delta_nb_bits: (table_log << 16).wrapping_sub(1 << table_log),
                };
                total += 1;
                transform
            }
            _ => {
                debug_assert!(n > 1);
                let max_bits_out = table_log - highbit32(n as u32 - 1);
                let min_state_plus = (n as u32) << max_bits_out;
                let transform = FseSymbolTransform {
                    delta_find_state: total.wrapping_sub(n as u32) as i32,
                    delta_nb_bits: (max_bits_out << 16).wrapping_sub(min_state_plus),
                };
                total += n as u32;
                transform
            }
        };
        set_symbol_transform(ct, symbol_tt, s, transform);
    }
    Ok(())
}

/// `FSE_NCountWriteBound`: the most bytes [`fse_write_ncount`] can write.
pub(crate) fn fse_ncount_write_bound(max_symbol_value: u32, table_log: u32) -> usize {
    let max_header_size = ((max_symbol_value as usize + 1) * table_log as usize
        + 4 // the bit count starts at 4
        + 2) // the first two symbols may use one more bit each
        / 8
        + 1 // round up to whole bytes
        + 2; // two more bytes for the flush
    if max_symbol_value != 0 {
        max_header_size
    } else {
        // maxSymbolValue == 0: the default.
        FSE_NCOUNTBOUND
    }
}

/// `FSE_writeNCount_generic`. With `write_is_safe`, the buffer is known to
/// be large enough and is not checked.
fn fse_write_ncount_generic(
    header: &mut [u8],
    normalized_counter: &[i16],
    max_symbol_value: u32,
    table_log: u32,
    write_is_safe: bool,
) -> Result<usize> {
    let oend = header.len();
    let mut out = 0usize;
    let table_size: i32 = 1 << table_log;
    let mut bit_stream: u32 = 0;
    let mut bit_count: i32 = 0;
    let mut symbol: u32 = 0;
    let alphabet_size = max_symbol_value + 1;
    let mut previous_is0 = false;

    // Two bytes of the bitstream; with `write_is_safe` unchecked.
    let flush16 = |header: &mut [u8], out: &mut usize, bit_stream: u32| -> Result<()> {
        if !write_is_safe && *out + 2 > oend {
            return error!(DstSizeTooSmall);
        }
        header[*out] = bit_stream as u8;
        header[*out + 1] = (bit_stream >> 8) as u8;
        *out += 2;
        Ok(())
    };

    // The table size.
    bit_stream = bit_stream.wrapping_add((table_log - FSE_MIN_TABLELOG) << bit_count);
    bit_count += 4;

    let mut remaining = table_size + 1; // +1 for extra accuracy
    let mut threshold = table_size;
    let mut nb_bits = table_log as i32 + 1;

    while symbol < alphabet_size && remaining > 1 {
        // It stops at 1.
        if previous_is0 {
            let mut start = symbol;
            while symbol < alphabet_size && normalized_counter[symbol as usize] == 0 {
                symbol += 1;
            }
            if symbol == alphabet_size {
                // An incorrect distribution.
                break;
            }
            while symbol >= start + 24 {
                start += 24;
                bit_stream = bit_stream.wrapping_add(0xFFFFu32.wrapping_shl(bit_count as u32));
                flush16(header, &mut out, bit_stream)?;
                bit_stream >>= 16;
            }
            while symbol >= start + 3 {
                start += 3;
                bit_stream = bit_stream.wrapping_add(3u32.wrapping_shl(bit_count as u32));
                bit_count += 2;
            }
            bit_stream = bit_stream.wrapping_add((symbol - start).wrapping_shl(bit_count as u32));
            bit_count += 2;
            if bit_count > 16 {
                flush16(header, &mut out, bit_stream)?;
                bit_stream >>= 16;
                bit_count -= 16;
            }
        }
        {
            let mut count = i32::from(normalized_counter[symbol as usize]);
            symbol += 1;
            let max = (2 * threshold - 1) - remaining;
            remaining -= count.abs();
            count += 1; // +1 for extra accuracy
            if count >= threshold {
                // [0..max[ [max..threshold[ (...) [threshold+max 2*threshold[
                count += max;
            }
            bit_stream = bit_stream.wrapping_add((count as u32).wrapping_shl(bit_count as u32));
            bit_count += nb_bits;
            bit_count -= i32::from(count < max);
            previous_is0 = count == 1;
            if remaining < 1 {
                return error!(Generic);
            }
            while remaining < threshold {
                nb_bits -= 1;
                threshold >>= 1;
            }
        }
        if bit_count > 16 {
            flush16(header, &mut out, bit_stream)?;
            bit_stream >>= 16;
            bit_count -= 16;
        }
    }

    if remaining != 1 {
        // An incorrect normalized distribution.
        return error!(Generic);
    }
    debug_assert!(symbol <= alphabet_size);

    // Flush the rest of the bitstream.
    if !write_is_safe && out + 2 > oend {
        return error!(DstSizeTooSmall);
    }
    header[out] = bit_stream as u8;
    header[out + 1] = (bit_stream >> 8) as u8;
    out += ((bit_count + 7) / 8) as usize;

    Ok(out)
}

/// `FSE_writeNCount`: the description of a normalized distribution, as
/// `FSE_readNCount` reads it.
pub(crate) fn fse_write_ncount(
    buffer: &mut [u8],
    normalized_counter: &[i16],
    max_symbol_value: u32,
    table_log: u32,
) -> Result<usize> {
    if table_log > FSE_MAX_TABLELOG {
        return error!(TableLogTooLarge);
    }
    if table_log < FSE_MIN_TABLELOG {
        return error!(Generic);
    }
    let write_is_safe = buffer.len() >= fse_ncount_write_bound(max_symbol_value, table_log);
    fse_write_ncount_generic(
        buffer,
        normalized_counter,
        max_symbol_value,
        table_log,
        write_is_safe,
    )
}

/// `FSE_minTableLog`: the smallest table that can represent the
/// distribution safely.
fn fse_min_table_log(src_size: usize, max_symbol_value: u32) -> u32 {
    let min_bits_src = highbit32(src_size as u32) + 1;
    let min_bits_symbols = highbit32(max_symbol_value) + 2;
    debug_assert!(src_size > 1); // not supported: RLE should be used instead
    min_bits_src.min(min_bits_symbols)
}

/// `FSE_optimalTableLog_internal`
pub(crate) fn fse_optimal_table_log_internal(
    max_table_log: u32,
    src_size: usize,
    max_symbol_value: u32,
    minus: u32,
) -> u32 {
    let max_bits_src = highbit32((src_size - 1) as u32).wrapping_sub(minus);
    let mut table_log = max_table_log;
    let min_bits = fse_min_table_log(src_size, max_symbol_value);
    debug_assert!(src_size > 1); // not supported: RLE should be used instead
    if table_log == 0 {
        table_log = FSE_DEFAULT_TABLELOG;
    }
    if max_bits_src < table_log {
        // Accuracy can be reduced.
        table_log = max_bits_src;
    }
    if min_bits > table_log {
        // Enough to represent every symbol safely.
        table_log = min_bits;
    }
    table_log.clamp(FSE_MIN_TABLELOG, FSE_MAX_TABLELOG)
}

/// `FSE_optimalTableLog`
pub(crate) fn fse_optimal_table_log(
    max_table_log: u32,
    src_size: usize,
    max_symbol_value: u32,
) -> u32 {
    fse_optimal_table_log_internal(max_table_log, src_size, max_symbol_value, 2)
}

/// `FSE_normalizeM2`: the second normalization method, for when the first
/// one fails.
fn fse_normalize_m2(
    norm: &mut [i16],
    table_log: u32,
    count: &[u32],
    mut total: usize,
    max_symbol_value: u32,
    low_prob_count: i16,
) -> Result<()> {
    const NOT_YET_ASSIGNED: i16 = -2;
    let mut distributed: u32 = 0;

    let low_threshold = (total >> table_log) as u32;
    let mut low_one = ((total * 3) >> (table_log + 1)) as u32;

    for s in 0..=max_symbol_value as usize {
        if count[s] == 0 {
            norm[s] = 0;
            continue;
        }
        if count[s] <= low_threshold {
            norm[s] = low_prob_count;
            distributed += 1;
            total -= count[s] as usize;
            continue;
        }
        if count[s] <= low_one {
            norm[s] = 1;
            distributed += 1;
            total -= count[s] as usize;
            continue;
        }
        norm[s] = NOT_YET_ASSIGNED;
    }
    let mut to_distribute = (1u32 << table_log).wrapping_sub(distributed);

    if to_distribute == 0 {
        return Ok(());
    }

    if total / to_distribute as usize > low_one as usize {
        // Risk of rounding to zero.
        low_one = ((total * 3) / (to_distribute as usize * 2)) as u32;
        for s in 0..=max_symbol_value as usize {
            if norm[s] == NOT_YET_ASSIGNED && count[s] <= low_one {
                norm[s] = 1;
                distributed += 1;
                total -= count[s] as usize;
            }
        }
        to_distribute = (1u32 << table_log).wrapping_sub(distributed);
    }

    if distributed == max_symbol_value + 1 {
        // Every value is poor, probably incompressible data (which should
        // have been found already): give all the rest to the largest.
        let (mut max_v, mut max_c) = (0, 0);
        for s in 0..=max_symbol_value as usize {
            if count[s] > max_c {
                max_v = s;
                max_c = count[s];
            }
        }
        norm[max_v] = norm[max_v].wrapping_add(to_distribute as i16);
        return Ok(());
    }

    if total == 0 {
        // Every symbol was low enough for lowOne or lowThreshold.
        let mut s = 0;
        while to_distribute > 0 {
            if norm[s] > 0 {
                to_distribute -= 1;
                norm[s] += 1;
            }
            s = (s + 1) % (max_symbol_value as usize + 1);
        }
        return Ok(());
    }

    let v_step_log = 62 - u64::from(table_log);
    let mid = (1u64 << (v_step_log - 1)) - 1;
    // Scaled on what remains.
    let r_step = ((1u64 << v_step_log) * u64::from(to_distribute) + mid) / u64::from(total as u32);
    let mut tmp_total = mid;
    for s in 0..=max_symbol_value as usize {
        if norm[s] == NOT_YET_ASSIGNED {
            let end = tmp_total + u64::from(count[s]) * r_step;
            let s_start = (tmp_total >> v_step_log) as u32;
            let s_end = (end >> v_step_log) as u32;
            let weight = s_end.wrapping_sub(s_start);
            if weight < 1 {
                return error!(Generic);
            }
            norm[s] = weight as i16;
            tmp_total = end;
        }
    }
    Ok(())
}

/// `FSE_normalizeCount`: scales `count`, whose sum is `total`, to sum to
/// `1 << table_log`. Returns the table log, or 0 when one symbol has all of
/// it (then `normalized_counter` is only partly written). With
/// `use_low_prob_count`, the rarest symbols get -1, otherwise 1.
pub(crate) fn fse_normalize_count(
    normalized_counter: &mut [i16],
    mut table_log: u32,
    count: &[u32],
    total: usize,
    max_symbol_value: u32,
    use_low_prob_count: bool,
) -> Result<u32> {
    if table_log == 0 {
        table_log = FSE_DEFAULT_TABLELOG;
    }
    if table_log < FSE_MIN_TABLELOG {
        return error!(Generic);
    }
    if table_log > FSE_MAX_TABLELOG {
        return error!(TableLogTooLarge);
    }
    if table_log < fse_min_table_log(total, max_symbol_value) {
        // Too small: compression is potentially impossible.
        return error!(Generic);
    }

    const RTB_TABLE: [u32; 8] = [0, 473195, 504333, 520860, 550000, 700000, 750000, 830000];
    let low_prob_count: i16 = if use_low_prob_count { -1 } else { 1 };
    let scale = 62 - u64::from(table_log);
    // The one division.
    let step = (1u64 << 62) / u64::from(total as u32);
    let v_step = 1u64 << (scale - 20);
    let mut still_to_distribute: i32 = 1 << table_log;
    let mut largest = 0usize;
    let mut largest_p: i16 = 0;
    let low_threshold = (total >> table_log) as u32;

    for s in 0..=max_symbol_value as usize {
        if count[s] as usize == total {
            // The RLE special case.
            return Ok(0);
        }
        if count[s] == 0 {
            normalized_counter[s] = 0;
            continue;
        }
        if count[s] <= low_threshold {
            normalized_counter[s] = low_prob_count;
            still_to_distribute -= 1;
        } else {
            let scaled = u64::from(count[s]).wrapping_mul(step);
            let mut proba = (scaled >> scale) as i16;
            if proba < 8 {
                let rest_to_beat = v_step * u64::from(RTB_TABLE[proba as usize]);
                proba += i16::from(scaled - ((proba as u64) << scale) > rest_to_beat);
            }
            if proba > largest_p {
                largest_p = proba;
                largest = s;
            }
            normalized_counter[s] = proba;
            still_to_distribute -= i32::from(proba);
        }
    }
    if -still_to_distribute >= i32::from(normalized_counter[largest] >> 1) {
        // A corner case: another normalization method is needed.
        fse_normalize_m2(
            normalized_counter,
            table_log,
            count,
            total,
            max_symbol_value,
            low_prob_count,
        )?;
    } else {
        normalized_counter[largest] =
            normalized_counter[largest].wrapping_add(still_to_distribute as i16);
    }
    Ok(table_log)
}

/// `FSE_buildCTable_rle`: a table for input that is one symbol repeated.
/// Only the header, two cells and that symbol's transform are written.
pub(crate) fn fse_build_ctable_rle(ct: &mut [u32], symbol_value: u8) {
    // The header.
    set_ctable_u16(ct, 0, 0);
    set_ctable_u16(ct, 1, u16::from(symbol_value));
    // The table.
    set_ctable_u16(ct, 2, 0);
    set_ctable_u16(ct, 3, 0); // just in case
    // The symbol transform.
    set_symbol_transform(
        ct,
        2,
        u32::from(symbol_value),
        FseSymbolTransform {
            delta_find_state: 0,
            delta_nb_bits: 0,
        },
    );
}

/// `FSE_compress_usingCTable_generic`. With `fast`, the output is known to
/// be large enough and the flushes are not checked.
fn fse_compress_using_ctable_generic(dst: &mut [u8], src: &[u8], ct: &[u32], fast: bool) -> usize {
    if src.len() <= 2 {
        return 0;
    }
    let Ok(mut bit_c) = BitCStream::new(dst) else {
        // Not enough room for a bitstream.
        return 0;
    };
    let flush = |bit_c: &mut BitCStream<'_>| {
        if fast {
            bit_c.flush_bits_fast()
        } else {
            bit_c.flush_bits()
        }
    };

    let mut ip = src.len();
    let mut state1;
    let mut state2;
    if src.len() & 1 != 0 {
        ip -= 1;
        state1 = FseCState::new2(ct, u32::from(src[ip]));
        ip -= 1;
        state2 = FseCState::new2(ct, u32::from(src[ip]));
        ip -= 1;
        state1.encode_symbol(&mut bit_c, u32::from(src[ip]));
        flush(&mut bit_c);
    } else {
        ip -= 1;
        state2 = FseCState::new2(ct, u32::from(src[ip]));
        ip -= 1;
        state1 = FseCState::new2(ct, u32::from(src[ip]));
    }

    // Join to a multiple of 4. With a 64-bit register, four symbols fit
    // between flushes (FSE_MAX_TABLELOG*4+7 < 64).
    let src_size = src.len() - 2;
    if src_size & 2 != 0 {
        ip -= 1;
        state2.encode_symbol(&mut bit_c, u32::from(src[ip]));
        ip -= 1;
        state1.encode_symbol(&mut bit_c, u32::from(src[ip]));
        flush(&mut bit_c);
    }

    // Four symbols per loop.
    while ip > 0 {
        ip -= 1;
        state2.encode_symbol(&mut bit_c, u32::from(src[ip]));
        ip -= 1;
        state1.encode_symbol(&mut bit_c, u32::from(src[ip]));
        ip -= 1;
        state2.encode_symbol(&mut bit_c, u32::from(src[ip]));
        ip -= 1;
        state1.encode_symbol(&mut bit_c, u32::from(src[ip]));
        flush(&mut bit_c);
    }

    state2.flush(&mut bit_c);
    state1.flush(&mut bit_c);
    bit_c.close()
}

/// `FSE_compress_usingCTable`: `src` compressed with the table `ct`, into
/// `dst`. Returns the size, or 0 if it does not fit or `src` is 2 bytes or
/// fewer.
pub(crate) fn fse_compress_using_ctable(dst: &mut [u8], src: &[u8], ct: &[u32]) -> usize {
    let fast = dst.len() >= fse_blockbound(src.len());
    fse_compress_using_ctable_generic(dst, src, ct, fast)
}

/// `FSE_compressBound`
pub(crate) fn fse_compress_bound(size: usize) -> usize {
    crate::zstd::common::fse::fse_compressbound(size)
}
