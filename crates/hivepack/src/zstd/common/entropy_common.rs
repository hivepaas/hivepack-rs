//! Reading table descriptions: port of `common/entropy_common.c`.
//!
//! libzstd compiles each function twice, with and without BMI2, and picks one
//! at run time. Both give the same results, so the port has one.

use super::bits::{count_trailing_zeros32, highbit32};
use super::error_private::{Result, error};
use super::fse::{FSE_MIN_TABLELOG, FSE_TABLELOG_ABSOLUTE_MAX};
use super::fse_decompress::{FseDecompressWksp, fse_decompress_wksp};
use super::huf::HUF_TABLELOG_MAX;
use super::mem::read_le32;

/// `FSE_readNCount`: reads the normalized counts that describe an FSE table.
///
/// `normalized_counter` needs room for `*max_sv_ptr + 1` counts. On input,
/// `*max_sv_ptr` is the largest symbol allowed; on success it is the largest
/// symbol present, and `*table_log_ptr` is the table's log. Returns the size
/// of the description in bytes.
pub(crate) fn fse_read_ncount(
    normalized_counter: &mut [i16],
    max_sv_ptr: &mut u32,
    table_log_ptr: &mut u32,
    header_buffer: &[u8],
) -> Result<usize> {
    let hb_size = header_buffer.len();
    if hb_size < 8 {
        // The body only works on at least 8 bytes.
        let mut buffer = [0u8; 8];
        buffer[..hb_size].copy_from_slice(header_buffer);
        let count_size = fse_read_ncount(normalized_counter, max_sv_ptr, table_log_ptr, &buffer)?;
        if count_size > hb_size {
            return error!(CorruptionDetected);
        }
        return Ok(count_size);
    }
    fse_read_ncount_body(normalized_counter, max_sv_ptr, table_log_ptr, header_buffer)
}

/// `FSE_readNCount_body`, for descriptions of at least 8 bytes.
///
/// The input position `ip` is an index; libzstd's `iend - 7` and `iend - 4`
/// become `ip + 7 <= iend` and `ip + 4 <= iend`. `ip` never passes
/// `iend - 4`, so every 4-byte read is inside the buffer.
fn fse_read_ncount_body(
    normalized_counter: &mut [i16],
    max_sv_ptr: &mut u32,
    table_log_ptr: &mut u32,
    header_buffer: &[u8],
) -> Result<usize> {
    let iend = header_buffer.len();
    debug_assert!(iend >= 8);
    let mut ip = 0usize;
    let mut charnum: u32 = 0;
    let max_sv1 = *max_sv_ptr + 1;
    let mut previous0 = false;

    // Init: all symbols not in the description have a count of 0.
    normalized_counter[..max_sv1 as usize].fill(0);
    let mut bit_stream = read_le32(header_buffer, ip);
    let mut nb_bits = (bit_stream & 0xF) as i32 + FSE_MIN_TABLELOG as i32; // tableLog
    if nb_bits > FSE_TABLELOG_ABSOLUTE_MAX as i32 {
        return error!(TableLogTooLarge);
    }
    bit_stream >>= 4;
    let mut bit_count: i32 = 4;
    *table_log_ptr = nb_bits as u32;
    let mut remaining: i32 = (1 << nb_bits) + 1;
    let mut threshold: i32 = 1 << nb_bits;
    nb_bits += 1;

    // Moves to where the next count starts and reads from there.
    let advance = |ip: &mut usize, bit_count: &mut i32| {
        if *ip + 7 <= iend || *ip + (*bit_count >> 3) as usize + 4 <= iend {
            *ip += (*bit_count >> 3) as usize;
            *bit_count &= 7;
        } else {
            *bit_count -= 8 * (iend as i32 - 4 - *ip as i32);
            *bit_count &= 31;
            *ip = iend - 4;
        }
        read_le32(header_buffer, *ip) >> *bit_count
    };

    loop {
        if previous0 {
            // Count the repeats: each 2-bit repeat code of 0b11 means
            // another one. Setting the high bit stops the count at 15.
            let mut repeats = count_trailing_zeros32(!bit_stream | 0x8000_0000) >> 1;
            while repeats >= 12 {
                charnum += 3 * 12;
                if ip + 7 <= iend {
                    ip += 3;
                } else {
                    bit_count -= 8 * (iend as i32 - 7 - ip as i32);
                    bit_count &= 31;
                    ip = iend - 4;
                }
                bit_stream = read_le32(header_buffer, ip) >> bit_count;
                repeats = count_trailing_zeros32(!bit_stream | 0x8000_0000) >> 1;
            }
            charnum += 3 * repeats;
            bit_stream >>= 2 * repeats;
            bit_count += 2 * repeats as i32;

            // The final repeat, which isn't 0b11.
            debug_assert!((bit_stream & 3) < 3);
            charnum += bit_stream & 3;
            bit_count += 2;

            // An error, reported after the loop, as in C.
            if charnum >= max_sv1 {
                break;
            }
            // The counts were already set to 0.
            bit_stream = advance(&mut ip, &mut bit_count);
        }
        {
            let max: i32 = (2 * threshold - 1) - remaining;
            let mut count: i32;
            if (bit_stream & (threshold - 1) as u32) < max as u32 {
                count = (bit_stream & (threshold - 1) as u32) as i32;
                bit_count += nb_bits - 1;
            } else {
                count = (bit_stream & (2 * threshold - 1) as u32) as i32;
                if count >= threshold {
                    count -= max;
                }
                bit_count += nb_bits;
            }

            count -= 1; // extra accuracy
            if count >= 0 {
                remaining -= count;
            } else {
                debug_assert!(count == -1);
                remaining += count;
            }
            // libzstd stores `(short)count`, which wraps the same way.
            normalized_counter[charnum as usize] = count as i16;
            charnum += 1;
            previous0 = count == 0;

            debug_assert!(threshold > 1);
            if remaining < threshold {
                if remaining <= 1 {
                    break;
                }
                nb_bits = highbit32(remaining as u32) as i32 + 1;
                threshold = 1 << (nb_bits - 1);
            }
            if charnum >= max_sv1 {
                break;
            }
            bit_stream = advance(&mut ip, &mut bit_count);
        }
    }
    if remaining != 1 {
        return error!(CorruptionDetected);
    }
    // Only possible with too many zeros.
    if charnum > max_sv1 {
        return error!(MaxSymbolValueTooSmall);
    }
    if bit_count > 32 {
        return error!(CorruptionDetected);
    }
    *max_sv_ptr = charnum - 1;

    ip += ((bit_count + 7) >> 3) as usize;
    Ok(ip)
}

/// `HUF_readStats_wksp`: reads the weights of a Huffman tree, as written by
/// `HUF_writeCTable`.
///
/// `huff_weight` is `hwSize` long; `rank_stats` gets the number of symbols of
/// each weight. On success, `*nb_symbols_ptr` and `*table_log_ptr` describe
/// the tree, and the size read from `src` is returned. `wksp` stands for
/// libzstd's workspace of `HUF_READ_STATS_WORKSPACE_SIZE` bytes.
pub(crate) fn huf_read_stats_wksp(
    huff_weight: &mut [u8],
    rank_stats: &mut [u32; HUF_TABLELOG_MAX as usize + 1],
    nb_symbols_ptr: &mut u32,
    table_log_ptr: &mut u32,
    src: &[u8],
    wksp: &mut FseDecompressWksp<64>,
) -> Result<usize> {
    let hw_size = huff_weight.len();
    if src.is_empty() {
        return error!(SrcSizeWrong);
    }
    let mut i_size = usize::from(src[0]);
    let o_size;

    if i_size >= 128 {
        // Special header: the weights are stored as 4-bit values.
        o_size = i_size - 127;
        i_size = o_size.div_ceil(2);
        if i_size + 1 > src.len() {
            return error!(SrcSizeWrong);
        }
        if o_size >= hw_size {
            return error!(CorruptionDetected);
        }
        let ip = &src[1..];
        let mut n = 0;
        while n < o_size {
            huff_weight[n] = ip[n / 2] >> 4;
            huff_weight[n + 1] = ip[n / 2] & 15;
            n += 2;
        }
    } else {
        // The weights are compressed with FSE (the normal case).
        if i_size + 1 > src.len() {
            return error!(SrcSizeWrong);
        }
        // At most hwSize - 1 values are decoded, as the last one is implied.
        o_size = fse_decompress_wksp(
            &mut huff_weight[..hw_size - 1],
            &src[1..1 + i_size],
            6,
            wksp,
            HUF_READ_STATS_WORKSPACE_SIZE,
        )?;
    }

    // Collect weight stats.
    rank_stats.fill(0);
    let mut weight_total: u32 = 0;
    for &weight in &huff_weight[..o_size] {
        if u32::from(weight) > HUF_TABLELOG_MAX {
            return error!(CorruptionDetected);
        }
        rank_stats[usize::from(weight)] += 1;
        weight_total += (1 << weight) >> 1;
    }
    if weight_total == 0 {
        return error!(CorruptionDetected);
    }

    // The last symbol's weight is implied: the total must be a power of 2.
    {
        let table_log = highbit32(weight_total) + 1;
        if table_log > HUF_TABLELOG_MAX {
            return error!(CorruptionDetected);
        }
        *table_log_ptr = table_log;
        let total: u32 = 1 << table_log;
        let rest = total - weight_total;
        let verif: u32 = 1 << highbit32(rest);
        let last_weight = highbit32(rest) + 1;
        if verif != rest {
            // The last value must be a clean power of 2.
            return error!(CorruptionDetected);
        }
        huff_weight[o_size] = last_weight as u8;
        rank_stats[last_weight as usize] += 1;
    }

    // A valid tree has an even number of weight-1 symbols, at least 2.
    if rank_stats[1] < 2 || rank_stats[1] & 1 != 0 {
        return error!(CorruptionDetected);
    }

    *nb_symbols_ptr = (o_size + 1) as u32;
    Ok(i_size + 1)
}

/// `HUF_READ_STATS_WORKSPACE_SIZE`, in bytes: what libzstd gives
/// `FSE_decompress_wksp` when reading Huffman weights. It decides which
/// tables are refused as too large.
pub(crate) const HUF_READ_STATS_WORKSPACE_SIZE: usize =
    super::fse::fse_decompress_wksp_size(6, HUF_TABLELOG_MAX - 1);
