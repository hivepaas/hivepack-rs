//! A block's literals section: port of `compress/zstd_compress_literals.c`.

use crate::zstd::common::error_private::{Result, error};
use crate::zstd::common::huf::{
    HUF_FLAGS_BMI2, HUF_FLAGS_OPTIMAL_DEPTH, HUF_FLAGS_PREFER_REPEAT,
    HUF_FLAGS_SUSPECT_UNCOMPRESSIBLE, HUF_SYMBOLVALUE_MAX,
};
use crate::zstd::common::mem::{write_le16, write_le32};
use crate::zstd::common::zstd_internal::{
    LIT_HUF_LOG, MIN_LITERALS_FOR_4_STREAMS, SymbolEncodingType,
};
use crate::zstd::compress::huf_compress::{
    HufRepeat, huf_compress1x_repeat, huf_compress4x_repeat,
};
use crate::zstd::compress::zstd_compress_internal::{HufCTables, Strategy, zstd_min_gain};

/// `HUF_OPTIMAL_DEPTH_THRESHOLD`: from this strategy on, Huffman tables are
/// built at their best depth.
pub(crate) const HUF_OPTIMAL_DEPTH_THRESHOLD: Strategy = Strategy::Btultra;

/// `ZSTD_noCompressLiterals`: the literals stored raw.
pub(crate) fn zstd_no_compress_literals(dst: &mut [u8], src: &[u8]) -> Result<usize> {
    let src_size = src.len();
    let fl_size = 1 + usize::from(src_size > 31) + usize::from(src_size > 4095);

    if src_size + fl_size > dst.len() {
        return error!(DstSizeTooSmall);
    }

    let basic = SymbolEncodingType::Basic as u32;
    match fl_size {
        // 2 - 1 - 5
        1 => dst[0] = (basic + ((src_size as u32) << 3)) as u8,
        // 2 - 2 - 12
        2 => write_le16(dst, 0, (basic + (1 << 2) + ((src_size as u32) << 4)) as u16),
        // 2 - 2 - 20
        _ => write_le32(dst, 0, basic + (3 << 2) + ((src_size as u32) << 4)),
    }

    dst[fl_size..fl_size + src_size].copy_from_slice(src);
    Ok(src_size + fl_size)
}

/// `allBytesIdentical`
fn all_bytes_identical(src: &[u8]) -> bool {
    debug_assert!(!src.is_empty());
    src.iter().all(|&b| b == src[0])
}

/// `ZSTD_compressRleLiteralsBlock`: literals that are one byte repeated.
/// `dst` has room for at least 4 bytes.
pub(crate) fn zstd_compress_rle_literals_block(dst: &mut [u8], src: &[u8]) -> usize {
    let src_size = src.len();
    let fl_size = 1 + usize::from(src_size > 31) + usize::from(src_size > 4095);

    debug_assert!(dst.len() >= 4);
    debug_assert!(all_bytes_identical(src));

    let rle = SymbolEncodingType::Rle as u32;
    match fl_size {
        // 2 - 1 - 5
        1 => dst[0] = (rle + ((src_size as u32) << 3)) as u8,
        // 2 - 2 - 12
        2 => write_le16(dst, 0, (rle + (1 << 2) + ((src_size as u32) << 4)) as u16),
        // 2 - 2 - 20
        _ => write_le32(dst, 0, rle + (3 << 2) + ((src_size as u32) << 4)),
    }

    dst[fl_size] = src[0];
    fl_size + 1
}

/// `ZSTD_minLiteralsToCompress`: the fewest literals worth compressing,
/// fewer for stronger strategies: 8 for `btultra2`, twice as many for each
/// strategy below, at most 64; 6 with a valid table to use again.
fn zstd_min_literals_to_compress(strategy: Strategy, huf_repeat: HufRepeat) -> usize {
    let shift = (9 - strategy as u32).min(3);
    if huf_repeat == HufRepeat::Valid {
        6
    } else {
        8 << shift
    }
}

/// `ZSTD_compressLiterals`: the literals section of a block: Huffman-
/// compressed with a new table or the previous one, one byte repeated, or
/// raw. `next_huf` gets the table the section uses, for the next block.
#[allow(clippy::too_many_arguments)]
pub(crate) fn zstd_compress_literals(
    dst: &mut [u8],
    src: &[u8],
    prev_huf: &HufCTables,
    next_huf: &mut HufCTables,
    strategy: Strategy,
    disable_literal_compression: bool,
    suspect_uncompressible: bool,
    bmi2: bool,
) -> Result<usize> {
    let src_size = src.len();
    let lh_size = 3 + usize::from(src_size >= 1024) + usize::from(src_size >= 16 * 1024);
    let mut single_stream = src_size < 256;
    let mut h_type = SymbolEncodingType::Compressed;

    // Prepare the next tables as if the previous ones were used again.
    next_huf.clone_from(prev_huf);

    if disable_literal_compression {
        return zstd_no_compress_literals(dst, src);
    }

    // Too few to try compressing (a speed optimization).
    if src_size < zstd_min_literals_to_compress(strategy, prev_huf.repeat_mode) {
        return zstd_no_compress_literals(dst, src);
    }

    if dst.len() < lh_size + 1 {
        // Not enough room to compress.
        return error!(DstSizeTooSmall);
    }
    let c_lit_size = {
        let mut repeat = prev_huf.repeat_mode;
        let flags = (if bmi2 { HUF_FLAGS_BMI2 } else { 0 })
            | (if strategy < Strategy::Lazy && src_size <= 1024 {
                HUF_FLAGS_PREFER_REPEAT
            } else {
                0
            })
            | (if strategy >= HUF_OPTIMAL_DEPTH_THRESHOLD {
                HUF_FLAGS_OPTIMAL_DEPTH
            } else {
                0
            })
            | (if suspect_uncompressible {
                HUF_FLAGS_SUSPECT_UNCOMPRESSIBLE
            } else {
                0
            });

        if repeat == HufRepeat::Valid && lh_size == 3 {
            single_stream = true;
        }
        let huf_compress = if single_stream {
            huf_compress1x_repeat
        } else {
            huf_compress4x_repeat
        };
        let c_lit_size = huf_compress(
            &mut dst[lh_size..],
            src,
            HUF_SYMBOLVALUE_MAX,
            LIT_HUF_LOG,
            Some(&mut next_huf.ctable),
            Some(&mut repeat),
            flags,
        );
        if repeat != HufRepeat::None {
            // The existing table was used again.
            h_type = SymbolEncodingType::Repeat;
        }
        c_lit_size
    };

    {
        let min_gain = zstd_min_gain(src_size, strategy);
        match c_lit_size {
            Ok(size) if size != 0 && size < src_size - min_gain => {}
            _ => {
                next_huf.clone_from(prev_huf);
                return zstd_no_compress_literals(dst, src);
            }
        }
    }
    let c_lit_size = c_lit_size?;
    if c_lit_size == 1 {
        // 1 means the literals are one symbol. In rare cases it could be
        // the compressed size, a single byte, which takes fewer than 8
        // literals (and no statistics): then check that all are the same.
        if src_size >= 8 || all_bytes_identical(src) {
            next_huf.clone_from(prev_huf);
            return Ok(zstd_compress_rle_literals_block(dst, src));
        }
    }

    if h_type == SymbolEncodingType::Compressed {
        // A new table.
        next_huf.repeat_mode = HufRepeat::Check;
    }

    // The header.
    let h_type = h_type as u32;
    match lh_size {
        // 2 - 2 - 10 - 10
        3 => {
            if !single_stream {
                debug_assert!(src_size >= MIN_LITERALS_FOR_4_STREAMS);
            }
            let lhc = h_type
                + (u32::from(!single_stream) << 2)
                + ((src_size as u32) << 4)
                + ((c_lit_size as u32) << 14);
            dst[..3].copy_from_slice(&lhc.to_le_bytes()[..3]);
        }
        // 2 - 2 - 14 - 14
        4 => {
            debug_assert!(src_size >= MIN_LITERALS_FOR_4_STREAMS);
            let lhc = h_type + (2 << 2) + ((src_size as u32) << 4) + ((c_lit_size as u32) << 18);
            write_le32(dst, 0, lhc);
        }
        // 2 - 2 - 18 - 18
        _ => {
            debug_assert!(src_size >= MIN_LITERALS_FOR_4_STREAMS);
            let lhc = h_type + (3 << 2) + ((src_size as u32) << 4) + ((c_lit_size as u32) << 22);
            write_le32(dst, 0, lhc);
            dst[4] = (c_lit_size >> 10) as u8;
        }
    }
    Ok(lh_size + c_lit_size)
}
