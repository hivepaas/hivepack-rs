//! Histograms of bytes: port of `compress/hist.c`.

use crate::zstd::common::error_private::{Result, error};
use crate::zstd::common::mem::read_le32;

/// `HIST_WKSP_SIZE_U32`: the workspace of [`hist_count_wksp`] and
/// [`hist_count_fast_wksp`], four tables of 256 counts.
pub(crate) const HIST_WKSP_SIZE_U32: usize = 1024;

/// `HIST_add`: adds the bytes of `src` to `count`, which has room for every
/// byte value.
pub(crate) fn hist_add(count: &mut [u32], src: &[u8]) {
    for &byte in src {
        count[usize::from(byte)] += 1;
    }
}

/// `HIST_count_simple`: counts the bytes of `src` into
/// `count[..=*max_symbol_value]`, sets `*max_symbol_value` to the largest
/// byte, and returns the largest count. Every byte must be at most
/// `*max_symbol_value`.
pub(crate) fn hist_count_simple(count: &mut [u32], max_symbol_value: &mut u32, src: &[u8]) -> u32 {
    let mut max_sv = *max_symbol_value as usize;
    count[..=max_sv].fill(0);
    if src.is_empty() {
        *max_symbol_value = 0;
        return 0;
    }
    for &byte in src {
        debug_assert!(usize::from(byte) <= max_sv);
        count[usize::from(byte)] += 1;
    }
    while count[max_sv] == 0 {
        max_sv -= 1;
    }
    *max_symbol_value = max_sv as u32;
    count[..=max_sv].iter().copied().max().unwrap_or(0)
}

/// `HIST_checkInput_e`
#[derive(Clone, Copy, PartialEq, Eq)]
enum HistCheckInput {
    TrustInput,
    CheckMaxSymbolValue,
}

/// `HIST_count_parallel_wksp`: [`hist_count_simple`] in four tables, which
/// is faster on bytes that repeat a lot. With `CheckMaxSymbolValue`, a byte
/// above `*max_symbol_value` is an error and `count` is left alone.
fn hist_count_parallel_wksp(
    count: &mut [u32],
    max_symbol_value: &mut u32,
    src: &[u8],
    check: HistCheckInput,
    wksp: &mut [u32; HIST_WKSP_SIZE_U32],
) -> Result<usize> {
    let count_size = *max_symbol_value as usize + 1;
    debug_assert!(*max_symbol_value <= 255);
    if src.is_empty() {
        count[..count_size].fill(0);
        *max_symbol_value = 0;
        return Ok(0);
    }
    wksp.fill(0);
    let (counting1, rest) = wksp.split_at_mut(256);
    let (counting2, rest) = rest.split_at_mut(256);
    let (counting3, counting4) = rest.split_at_mut(256);

    // By stripes of 16 bytes. libzstd reads one word ahead, which can read
    // past the end of inputs shorter than 4 bytes; the port only reads
    // words it counts, which gives the same counts.
    let mut ip = 0;
    if src.len() >= 4 {
        let iend = src.len();
        let mut cached = read_le32(src, ip);
        ip += 4;
        while ip + 15 < iend {
            for _ in 0..4 {
                let c = cached;
                cached = read_le32(src, ip);
                ip += 4;
                counting1[(c & 0xFF) as usize] += 1;
                counting2[((c >> 8) & 0xFF) as usize] += 1;
                counting3[((c >> 16) & 0xFF) as usize] += 1;
                counting4[(c >> 24) as usize] += 1;
            }
        }
        ip -= 4;
    }

    // The last symbols.
    for &byte in &src[ip..] {
        counting1[usize::from(byte)] += 1;
    }

    let mut max = 0;
    for s in 0..256 {
        counting1[s] += counting2[s] + counting3[s] + counting4[s];
        if counting1[s] > max {
            max = counting1[s];
        }
    }

    let mut max_sv = 255;
    while counting1[max_sv] == 0 {
        max_sv -= 1;
    }
    if check == HistCheckInput::CheckMaxSymbolValue && max_sv > *max_symbol_value as usize {
        return error!(MaxSymbolValueTooSmall);
    }
    *max_symbol_value = max_sv as u32;
    count[..count_size].copy_from_slice(&counting1[..count_size]);
    Ok(max as usize)
}

/// `HIST_countFast_wksp`: like [`hist_count_simple`], trusting every byte
/// to be at most `*max_symbol_value`, and faster on large inputs.
pub(crate) fn hist_count_fast_wksp(
    count: &mut [u32],
    max_symbol_value: &mut u32,
    src: &[u8],
    wksp: &mut [u32; HIST_WKSP_SIZE_U32],
) -> Result<usize> {
    if src.len() < 1500 {
        // A heuristic threshold.
        return Ok(hist_count_simple(count, max_symbol_value, src) as usize);
    }
    hist_count_parallel_wksp(
        count,
        max_symbol_value,
        src,
        HistCheckInput::TrustInput,
        wksp,
    )
}

/// `HIST_count_wksp`: counts the bytes of `src`; a byte above
/// `*max_symbol_value` is an error.
pub(crate) fn hist_count_wksp(
    count: &mut [u32],
    max_symbol_value: &mut u32,
    src: &[u8],
    wksp: &mut [u32; HIST_WKSP_SIZE_U32],
) -> Result<usize> {
    if *max_symbol_value < 255 {
        return hist_count_parallel_wksp(
            count,
            max_symbol_value,
            src,
            HistCheckInput::CheckMaxSymbolValue,
            wksp,
        );
    }
    *max_symbol_value = 255;
    hist_count_fast_wksp(count, max_symbol_value, src, wksp)
}

/// `HIST_countFast`
pub(crate) fn hist_count_fast(
    count: &mut [u32],
    max_symbol_value: &mut u32,
    src: &[u8],
) -> Result<usize> {
    let mut wksp = [0u32; HIST_WKSP_SIZE_U32];
    hist_count_fast_wksp(count, max_symbol_value, src, &mut wksp)
}

/// `HIST_count`
pub(crate) fn hist_count(
    count: &mut [u32],
    max_symbol_value: &mut u32,
    src: &[u8],
) -> Result<usize> {
    let mut wksp = [0u32; HIST_WKSP_SIZE_U32];
    hist_count_wksp(count, max_symbol_value, src, &mut wksp)
}
