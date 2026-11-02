//! Huffman decoding: port of `decompress/huf_decompress.c`.
//!
//! libzstd keeps both kinds of table in one `HUF_DTable` array, with a
//! descriptor in its first cell that says which kind it holds: X1 tables
//! decode one symbol per lookup, X2 tables up to two. Streams come alone
//! ("1X") or as four interleaved streams with a jump table ("4X").
//!
//! For 4-stream input, libzstd first tries a fast loop (`_fast_c_loop`, or
//! the same loop in assembly on x86-64) and falls back to the older loop when
//! the input does not suit it. The two do not check the input the same way:
//! the fast loop does not check where each stream ends. libzstd skips the
//! fast loop on processors without BMI2 and on big-endian or 32-bit
//! machines. The port always tries it, as libzstd does on the 64-bit
//! little-endian machines it mostly runs on, so its results match theirs
//! everywhere.

use crate::zstd::common::bits::highbit32;
use crate::zstd::common::bitstream::{BitDStatus, BitDStream};
use crate::zstd::common::entropy_common::huf_read_stats_wksp;
use crate::zstd::common::error_private::{Result, error};
use crate::zstd::common::fse_decompress::FseDecompressWksp;
use crate::zstd::common::huf::{
    HUF_FLAGS_DISABLE_FAST, HUF_SYMBOLVALUE_MAX, HUF_TABLELOG_ABSOLUTEMAX, HUF_TABLELOG_MAX,
};
use crate::zstd::common::mem::{idx, read_le16, read_le64};

/// How often each 4-stream loop ran, so the tests can check that they reach
/// both: [fast X1, fallback X1, fast X2, fallback X2].
#[cfg(test)]
pub(crate) static LOOP_RUNS: [std::sync::atomic::AtomicUsize; 4] =
    [const { std::sync::atomic::AtomicUsize::new(0) }; 4];

#[cfg(test)]
fn count_run(which: usize) {
    LOOP_RUNS[which].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(not(test))]
#[inline(always)]
fn count_run(_which: usize) {}

/// `HUF_DECODER_FAST_TABLELOG`: the table log of the fast decoding loops.
pub(crate) const HUF_DECODER_FAST_TABLELOG: u32 = 11;

/// The cells a table holds: `1 << HUF_TABLELOG_MAX`, like the decoder's
/// table of `ZSTD_HUFFDTABLE_CAPACITY_LOG`.
pub(crate) const HUF_DTABLE_CELLS: usize = 1 << HUF_TABLELOG_MAX;

/// `DTableDesc`, the first cell of a `HUF_DTable`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct DTableDesc {
    pub(crate) max_table_log: u8,
    pub(crate) table_type: u8,
    pub(crate) table_log: u8,
}

/// `HUF_DEltX1`: one symbol per lookup. Its two bytes, `nbBits` and then
/// `byte`, are kept as one `u16` that the decoder reads at once, as
/// libzstd's fast loop does.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct HufDEltX1(u16);

impl HufDEltX1 {
    pub(crate) const fn new(nb_bits: u8, byte: u8) -> Self {
        HufDEltX1(nb_bits as u16 | (byte as u16) << 8)
    }

    /// `nbBits`
    #[inline(always)]
    pub(crate) const fn nb_bits(self) -> u8 {
        self.0 as u8
    }

    /// `byte`
    #[inline(always)]
    pub(crate) const fn byte(self) -> u8 {
        (self.0 >> 8) as u8
    }
}

impl std::fmt::Debug for HufDEltX1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HufDEltX1")
            .field("nb_bits", &self.nb_bits())
            .field("byte", &self.byte())
            .finish()
    }
}

/// `HUF_DEltX2`: up to two symbols per lookup. `sequence` holds them as the
/// two bytes to write, in little-endian order: the first symbol in the low
/// byte. The fields are kept in one `u32`, in libzstd's layout, so that the
/// decoder reads a cell at once.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct HufDEltX2(u32);

impl HufDEltX2 {
    pub(crate) const fn new(sequence: u16, nb_bits: u8, length: u8) -> Self {
        HufDEltX2(sequence as u32 | (nb_bits as u32) << 16 | (length as u32) << 24)
    }

    /// `sequence`
    #[inline(always)]
    pub(crate) const fn sequence(self) -> u16 {
        self.0 as u16
    }

    /// `nbBits`
    #[inline(always)]
    pub(crate) const fn nb_bits(self) -> u8 {
        (self.0 >> 16) as u8
    }

    /// `length`
    #[inline(always)]
    pub(crate) const fn length(self) -> u8 {
        (self.0 >> 24) as u8
    }
}

impl std::fmt::Debug for HufDEltX2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HufDEltX2")
            .field("sequence", &self.sequence())
            .field("nb_bits", &self.nb_bits())
            .field("length", &self.length())
            .finish()
    }
}

/// `HUF_DTable`.
///
/// Differs from libzstd: the two kinds of cell are kept in two typed arrays
/// instead of sharing one `U32` array, so a table takes 24 KiB instead of
/// 16 KiB.
#[derive(Clone)]
pub(crate) struct HufDTable {
    pub(crate) desc: DTableDesc,
    pub(crate) x1: [HufDEltX1; HUF_DTABLE_CELLS],
    pub(crate) x2: [HufDEltX2; HUF_DTABLE_CELLS],
}

impl HufDTable {
    /// The descriptor of an empty table that allows `max_table_log`.
    pub(crate) fn new_desc(max_table_log: u32) -> DTableDesc {
        DTableDesc {
            max_table_log: max_table_log as u8,
            table_type: 0,
            table_log: 0,
        }
    }

    /// A table whose descriptor allows `max_table_log`, as
    /// `HUF_CREATE_STATIC_DTABLEX1` and the decoder set it up.
    pub(crate) fn new(max_table_log: u32) -> Self {
        HufDTable {
            desc: Self::new_desc(max_table_log),
            x1: [HufDEltX1::default(); HUF_DTABLE_CELLS],
            x2: [HufDEltX2::default(); HUF_DTABLE_CELLS],
        }
    }
}

/// `HUF_rescaleStats`: raises the table log to `target_table_log`, if it is
/// below, and rescales the weights to match. Returns the new table log.
fn huf_rescale_stats(
    huff_weight: &mut [u8],
    rank_val: &mut [u32],
    nb_symbols: u32,
    table_log: u32,
    target_table_log: u32,
) -> u32 {
    if table_log > target_table_log {
        return table_log;
    }
    if table_log < target_table_log {
        let scale = target_table_log - table_log;
        // Raise the weight of every symbol that has one.
        for weight in &mut huff_weight[..nb_symbols as usize] {
            *weight += if *weight == 0 { 0 } else { scale as u8 };
        }
        // Move the counts: every weight but 0 goes to weight + scale, and
        // weights 1 to scale are now empty.
        let mut s = target_table_log as usize;
        while s > scale as usize {
            rank_val[s] = rank_val[s - scale as usize];
            s -= 1;
        }
        for s in (1..=scale as usize).rev() {
            rank_val[s] = 0;
        }
    }
    target_table_log
}

/// `HUF_ReadDTableX1_Workspace`
pub(crate) struct HufReadDTableX1Workspace {
    rank_val: [u32; HUF_TABLELOG_ABSOLUTEMAX as usize + 1],
    rank_start: [u32; HUF_TABLELOG_ABSOLUTEMAX as usize + 1],
    stats_wksp: FseDecompressWksp<64>,
    symbols: [u8; HUF_SYMBOLVALUE_MAX as usize + 1],
    huff_weight: [u8; HUF_SYMBOLVALUE_MAX as usize + 1],
}

impl Default for HufReadDTableX1Workspace {
    fn default() -> Self {
        HufReadDTableX1Workspace {
            rank_val: [0; HUF_TABLELOG_ABSOLUTEMAX as usize + 1],
            rank_start: [0; HUF_TABLELOG_ABSOLUTEMAX as usize + 1],
            stats_wksp: FseDecompressWksp::default(),
            symbols: [0; HUF_SYMBOLVALUE_MAX as usize + 1],
            huff_weight: [0; HUF_SYMBOLVALUE_MAX as usize + 1],
        }
    }
}

/// `HUF_readDTableX1_wksp`: reads a Huffman tree description from `src` and
/// builds a single-symbol table from it. Returns the size of the description.
pub(crate) fn huf_read_dtable_x1_wksp(
    dtable: &mut HufDTable,
    src: &[u8],
    wksp: &mut HufReadDTableX1Workspace,
) -> Result<usize> {
    let mut table_log = 0u32;
    let mut nb_symbols = 0u32;

    let rank_val: &mut [u32; HUF_TABLELOG_MAX as usize + 1] = &mut wksp.rank_val;
    let i_size = huf_read_stats_wksp(
        &mut wksp.huff_weight,
        rank_val,
        &mut nb_symbols,
        &mut table_log,
        src,
        &mut wksp.stats_wksp,
    )?;

    // Table header.
    {
        let mut dtd = dtable.desc;
        let max_table_log = u32::from(dtd.max_table_log) + 1;
        let target_table_log = max_table_log.min(HUF_DECODER_FAST_TABLELOG);
        table_log = huf_rescale_stats(
            &mut wksp.huff_weight,
            &mut wksp.rank_val,
            nb_symbols,
            table_log,
            target_table_log,
        );
        if table_log > u32::from(dtd.max_table_log) + 1 {
            // The table is too small for this tree.
            return error!(TableLogTooLarge);
        }
        dtd.table_type = 0;
        dtd.table_log = table_log as u8;
        dtable.desc = dtd;
    }
    // Differs from libzstd: C trusts its callers' tables to have room for a
    // log of max_table_log + 1; the port's tables have room for
    // HUF_TABLELOG_MAX, which every caller in libzstd passes.
    if (1usize << table_log) > HUF_DTABLE_CELLS {
        return error!(TableLogTooLarge);
    }

    // Order the symbols by weight (symbols), and find where each weight
    // starts in the table (rank_start). symbols[0] is filled but unused.
    {
        let mut next_rank_start = 0u32;
        let unroll = 4;
        let n_limit = nb_symbols as i32 - unroll + 1;
        for n in 0..(table_log as usize + 1) {
            let curr = next_rank_start;
            next_rank_start += wksp.rank_val[n];
            wksp.rank_start[n] = curr;
        }
        let mut n = 0i32;
        while n < n_limit {
            for u in 0..unroll {
                let w = usize::from(wksp.huff_weight[(n + u) as usize]);
                wksp.symbols[wksp.rank_start[w] as usize] = (n + u) as u8;
                wksp.rank_start[w] += 1;
            }
            n += unroll;
        }
        while n < nb_symbols as i32 {
            let w = usize::from(wksp.huff_weight[n as usize]);
            wksp.symbols[wksp.rank_start[w] as usize] = n as u8;
            wksp.rank_start[w] += 1;
            n += 1;
        }
    }

    // Fill the table, all the cells of each weight in turn. libzstd writes
    // four cells at a time where it can; the cells end up the same.
    {
        let dt = &mut dtable.x1;
        let mut symbol = wksp.rank_val[0] as usize;
        let mut rank_start = 0usize;
        for w in 1..(table_log + 1) {
            let symbol_count = wksp.rank_val[w as usize] as usize;
            let length = (1usize << w) >> 1;
            let nb_bits = (table_log + 1 - w) as u8;
            let mut u_start = rank_start;
            for s in 0..symbol_count {
                let d = HufDEltX1::new(nb_bits, wksp.symbols[symbol + s]);
                dt[u_start..u_start + length].fill(d);
                u_start += length;
            }
            symbol += symbol_count;
            rank_start += symbol_count * length;
        }
    }
    Ok(i_size)
}

/// `HUF_buildDEltX2`
#[inline(always)]
fn huf_build_delt_x2(symbol: u32, nb_bits: u32, base_seq: u32, level: u32) -> HufDEltX2 {
    let sequence = if level == 1 {
        symbol
    } else {
        base_seq + (symbol << 8)
    };
    HufDEltX2::new(sequence as u16, nb_bits as u8, level as u8)
}

/// `HUF_fillDTableX2ForWeight`: fills the cells from `at` for the symbols
/// `sorted_symbols[begin..end]`, each `nb_bits` long.
#[allow(clippy::too_many_arguments)]
fn huf_fill_dtable_x2_for_weight(
    dtable: &mut [HufDEltX2],
    mut at: usize,
    sorted_symbols: &[u8],
    begin: usize,
    end: usize,
    nb_bits: u32,
    table_log: u32,
    base_seq: u16,
    level: u32,
) {
    let length = 1usize << ((table_log.wrapping_sub(nb_bits)) & 0x1F);
    debug_assert!((1..=2).contains(&level));
    for &symbol in &sorted_symbols[begin..end] {
        let d_elt = huf_build_delt_x2(u32::from(symbol), nb_bits, u32::from(base_seq), level);
        dtable[at..at + length].fill(d_elt);
        at += length;
    }
}

/// `HUF_fillDTableX2Level2`
#[allow(clippy::too_many_arguments)]
fn huf_fill_dtable_x2_level2(
    dtable: &mut [HufDEltX2],
    at: usize,
    target_log: u32,
    consumed_bits: u32,
    rank_val: &[u32; HUF_TABLELOG_MAX as usize + 1],
    min_weight: i32,
    max_weight1: i32,
    sorted_symbols: &[u8],
    rank_start: &[u32],
    nb_bits_baseline: u32,
    base_seq: u16,
) {
    // Fill the skipped cells, up to rankVal[minWeight]: they only get one
    // symbol, as the combined length would be too long.
    if min_weight > 1 {
        let length = 1usize << (target_log.wrapping_sub(consumed_bits) & 0x1F);
        let d_elt = huf_build_delt_x2(u32::from(base_seq), consumed_bits, 0, 1);
        let skip_size = rank_val[min_weight as usize] as usize;
        debug_assert!(length > 1);
        debug_assert!(skip_size < length);
        // libzstd writes 2, 4, or groups of 8 cells; the same cells, as the
        // rest of these are written again below.
        let written = match length {
            2 => 2,
            4 => 4,
            _ => skip_size.div_ceil(8) * 8,
        };
        dtable[at..at + written].fill(d_elt);
    }

    // Fill each of the second-level symbols, by weight.
    for w in min_weight..max_weight1 {
        let begin = rank_start[w as usize] as usize;
        let end = rank_start[w as usize + 1] as usize;
        let nb_bits = nb_bits_baseline - w as u32;
        let total_bits = nb_bits + consumed_bits;
        huf_fill_dtable_x2_for_weight(
            dtable,
            at + rank_val[w as usize] as usize,
            sorted_symbols,
            begin,
            end,
            total_bits,
            target_log,
            base_seq,
            2,
        );
    }
}

/// `HUF_fillDTableX2`. `rank_start` is libzstd's `rankStart0`: the start of
/// weight `w`'s symbols is `rank_start[w]`.
fn huf_fill_dtable_x2(
    dtable: &mut [HufDEltX2],
    target_log: u32,
    sorted_list: &[u8],
    rank_start: &[u32],
    rank_val_origin: &[[u32; HUF_TABLELOG_MAX as usize + 1]; HUF_TABLELOG_MAX as usize],
    max_weight: u32,
    nb_bits_baseline: u32,
) {
    let rank_val = &rank_val_origin[0];
    // targetLog >= srcLog, so scaleLog <= 1.
    let scale_log = nb_bits_baseline as i32 - target_log as i32;
    let min_bits = nb_bits_baseline - max_weight;
    let w_end = max_weight as i32 + 1;

    // Fill the table in order of weight.
    for w in 1..w_end {
        let begin = rank_start[w as usize] as usize;
        let end = rank_start[w as usize + 1] as usize;
        let nb_bits = nb_bits_baseline - w as u32;

        if target_log - nb_bits >= min_bits {
            // Room for a second symbol.
            let mut start = rank_val[w as usize] as usize;
            let length = 1usize << ((target_log - nb_bits) & 0x1F);
            let mut min_weight = nb_bits as i32 + scale_log;
            if min_weight < 1 {
                min_weight = 1;
            }
            // Every symbol of weight w gets at least one second symbol.
            for &symbol in &sorted_list[begin..end] {
                huf_fill_dtable_x2_level2(
                    dtable,
                    start,
                    target_log,
                    nb_bits,
                    &rank_val_origin[nb_bits as usize],
                    min_weight,
                    w_end,
                    sorted_list,
                    rank_start,
                    nb_bits_baseline,
                    u16::from(symbol),
                );
                start += length;
            }
        } else {
            // Only one symbol.
            huf_fill_dtable_x2_for_weight(
                dtable,
                rank_val[w as usize] as usize,
                sorted_list,
                begin,
                end,
                nb_bits,
                target_log,
                0,
                1,
            );
        }
    }
}

/// `HUF_ReadDTableX2_Workspace`
pub(crate) struct HufReadDTableX2Workspace {
    rank_val: [[u32; HUF_TABLELOG_MAX as usize + 1]; HUF_TABLELOG_MAX as usize],
    rank_stats: [u32; HUF_TABLELOG_MAX as usize + 1],
    rank_start0: [u32; HUF_TABLELOG_MAX as usize + 3],
    sorted_symbol: [u8; HUF_SYMBOLVALUE_MAX as usize + 1],
    weight_list: [u8; HUF_SYMBOLVALUE_MAX as usize + 1],
    callee_wksp: FseDecompressWksp<64>,
}

impl Default for HufReadDTableX2Workspace {
    fn default() -> Self {
        HufReadDTableX2Workspace {
            rank_val: [[0; HUF_TABLELOG_MAX as usize + 1]; HUF_TABLELOG_MAX as usize],
            rank_stats: [0; HUF_TABLELOG_MAX as usize + 1],
            rank_start0: [0; HUF_TABLELOG_MAX as usize + 3],
            sorted_symbol: [0; HUF_SYMBOLVALUE_MAX as usize + 1],
            weight_list: [0; HUF_SYMBOLVALUE_MAX as usize + 1],
            callee_wksp: FseDecompressWksp::default(),
        }
    }
}

/// `HUF_readDTableX2_wksp`: reads a Huffman tree description from `src` and
/// builds a double-symbol table from it. Returns the size of the description.
pub(crate) fn huf_read_dtable_x2_wksp(
    dtable: &mut HufDTable,
    src: &[u8],
    wksp: &mut HufReadDTableX2Workspace,
) -> Result<usize> {
    let mut table_log = 0u32;
    let mut nb_symbols = 0u32;
    let mut dtd = dtable.desc;
    let mut max_table_log = u32::from(dtd.max_table_log);

    wksp.rank_stats.fill(0);
    wksp.rank_start0.fill(0);

    if max_table_log > HUF_TABLELOG_MAX {
        return error!(TableLogTooLarge);
    }

    let i_size = huf_read_stats_wksp(
        &mut wksp.weight_list,
        &mut wksp.rank_stats,
        &mut nb_symbols,
        &mut table_log,
        src,
        &mut wksp.callee_wksp,
    )?;

    // Check the result.
    if table_log > max_table_log {
        // The table cannot hold codes this long.
        return error!(TableLogTooLarge);
    }
    if table_log <= HUF_DECODER_FAST_TABLELOG && max_table_log > HUF_DECODER_FAST_TABLELOG {
        max_table_log = HUF_DECODER_FAST_TABLELOG;
    }

    // Find the largest weight; there is necessarily one before 0.
    let mut max_w = table_log;
    while wksp.rank_stats[max_w as usize] == 0 {
        max_w -= 1;
    }

    // rankStart is rankStart0 + 1, as in C.
    {
        let rank_start = &mut wksp.rank_start0[1..];

        // The start of each weight.
        let mut next_rank_start = 0u32;
        for w in 1..(max_w as usize + 1) {
            let curr = next_rank_start;
            next_rank_start += wksp.rank_stats[w];
            rank_start[w] = curr;
        }
        rank_start[0] = next_rank_start; // weight-0 symbols go at the end
        rank_start[max_w as usize + 1] = next_rank_start;

        // Sort the symbols by weight.
        for s in 0..nb_symbols as usize {
            let w = usize::from(wksp.weight_list[s]);
            let r = rank_start[w] as usize;
            rank_start[w] += 1;
            wksp.sorted_symbol[r] = s as u8;
        }
        rank_start[0] = 0; // forget weight-0 symbols: this is where weight 1 starts
    }

    // Build rankVal.
    {
        let rescale = (max_table_log - table_log) as i32 - 1; // tableLog <= maxTableLog
        let mut next_rank_val = 0u32;
        for w in 1..(max_w as usize + 1) {
            let curr = next_rank_val;
            next_rank_val += wksp.rank_stats[w] << (w as i32 + rescale);
            wksp.rank_val[0][w] = curr;
        }
        let min_bits = table_log + 1 - max_w;
        let mut consumed = min_bits;
        while consumed < max_table_log - min_bits + 1 {
            for w in 1..(max_w as usize + 1) {
                wksp.rank_val[consumed as usize][w] = wksp.rank_val[0][w] >> consumed;
            }
            consumed += 1;
        }
    }

    huf_fill_dtable_x2(
        &mut dtable.x2,
        max_table_log,
        &wksp.sorted_symbol,
        &wksp.rank_start0,
        &wksp.rank_val,
        max_w,
        table_log + 1,
    );

    dtd.table_log = max_table_log as u8;
    dtd.table_type = 1;
    dtable.desc = dtd;
    Ok(i_size)
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// `HUF_DecompressFastArgs`: the state of the fast loop. Input positions are
/// indices into the whole input, whose start is libzstd's `ilowest`; output
/// positions are indices into the output.
struct HufDecompressFastArgs {
    ip: [usize; 4],
    op: [usize; 4],
    bits: [u64; 4],
    iend: [usize; 4],
    oend: usize,
}

/// `HUF_initFastDStream`: the fast loop's register for the stream whose last
/// 8 bytes start at `ip`. The bits are read from the top down, and a 1 below
/// the lowest valid bit counts how many have been read.
#[inline(always)]
fn huf_init_fast_dstream(src: &[u8], ip: usize) -> u64 {
    let last_byte = src[ip + 7];
    let bits_consumed = if last_byte != 0 {
        8 - highbit32(u32::from(last_byte))
    } else {
        0
    };
    let value = read_le64(src, ip) | 1;
    debug_assert!(bits_consumed <= 8);
    value << bits_consumed
}

/// `HUF_DecompressFastArgs_init`: the fast loop's state, `Ok(None)` when the
/// input does not suit the fast loop, or an error.
fn huf_decompress_fast_args_init(
    dst_size: usize,
    src: &[u8],
    dtable: &HufDTable,
) -> Result<Option<HufDecompressFastArgs>> {
    let dt_log = u32::from(dtable.desc.table_log);
    let src_size = src.len();

    // libzstd also gives up here on big-endian and 32-bit machines; see the
    // module documentation.
    if dst_size == 0 {
        return Ok(None);
    }
    // The strict minimum: the jump table and 1 byte per stream.
    if src_size < 10 {
        return error!(CorruptionDetected);
    }
    // At least 8 bytes per stream, and a table of the fast loop's log.
    if dt_log != HUF_DECODER_FAST_TABLELOG {
        return Ok(None);
    }

    // The jump table.
    let length1 = usize::from(read_le16(src, 0));
    let length2 = usize::from(read_le16(src, 2));
    let length3 = usize::from(read_le16(src, 4));
    let length4 = src_size.wrapping_sub(length1 + length2 + length3 + 6);
    let mut iend = [6, 0, 0, 0];
    iend[1] = iend[0] + length1;
    iend[2] = iend[1] + length2;
    iend[3] = iend[2] + length3;
    // HUF_initFastDStream needs 8 bytes, and inputs this small would not
    // benefit anyway.
    if length1 < 8 || length2 < 8 || length3 < 8 || length4 < 8 {
        return Ok(None);
    }
    if length4 > src_size {
        // Overflow.
        return error!(CorruptionDetected);
    }

    // ip[] is where each register was read from.
    let ip = [iend[1] - 8, iend[2] - 8, iend[3] - 8, src_size - 8];

    // op[] is where each stream's output starts.
    let segment = dst_size.div_ceil(4);
    let op = [0, segment, 2 * segment, 3 * segment];

    // Not worth it for tiny outputs.
    if op[3] >= dst_size {
        return Ok(None);
    }

    let bits = ip.map(|ip| huf_init_fast_dstream(src, ip));
    Ok(Some(HufDecompressFastArgs {
        ip,
        op,
        bits,
        iend,
        oend: dst_size,
    }))
}

/// `HUF_initRemainingDStream`: a bitstream reader to finish `stream` after
/// the fast loop, checking that the loop did not go too far.
fn huf_init_remaining_dstream<'a>(
    src: &'a [u8],
    args: &HufDecompressFastArgs,
    stream: usize,
    segment_end: usize,
) -> Result<BitDStream<'a>> {
    // The loop must not have written past the segment.
    if args.op[stream] > segment_end {
        return error!(CorruptionDetected);
    }
    // Nor read past the stream's start; ip[] may be up to 8 bytes before it,
    // as the register's top bit is the next one to read.
    if args.ip[stream] + 8 < args.iend[stream] {
        return error!(CorruptionDetected);
    }
    // The reader may go back as far as the start of the whole input, like
    // libzstd's, whose `start` is `ilowest`.
    Ok(BitDStream::from_parts(
        src,
        args.ip[stream],
        args.bits[stream].trailing_zeros(),
    ))
}

/// `HUF_decodeSymbolX1`
#[inline(always)]
fn huf_decode_symbol_x1(
    bit_d: &mut BitDStream<'_>,
    dt: &[HufDEltX1; HUF_DTABLE_CELLS],
    dt_log: u32,
) -> u8 {
    // dtLog >= 1
    let val = bit_d.look_bits_fast(dt_log) as usize;
    let cell = dt[val];
    bit_d.skip_bits(u32::from(cell.nb_bits()));
    cell.byte()
}

/// `HUF_decodeStreamX1`: decodes into `dst[p..p_end]`, which it always fills.
/// Returns `p_end - p`.
#[inline(always)]
fn huf_decode_stream_x1(
    dst: &mut [u8],
    mut p: usize,
    bit_d: &mut BitDStream<'_>,
    p_end: usize,
    dt: &[HufDEltX1; HUF_DTABLE_CELLS],
    dt_log: u32,
) -> usize {
    let p_start = p;

    // Up to 4 symbols at a time. `&` and not `&&`: the reload always runs.
    if p_end - p > 3 {
        while (bit_d.reload() == BitDStatus::Unfinished) & (p + 3 < p_end) {
            dst[p] = huf_decode_symbol_x1(bit_d, dt, dt_log);
            dst[p + 1] = huf_decode_symbol_x1(bit_d, dt, dt_log);
            dst[p + 2] = huf_decode_symbol_x1(bit_d, dt, dt_log);
            dst[p + 3] = huf_decode_symbol_x1(bit_d, dt, dt_log);
            p += 4;
        }
    } else {
        bit_d.reload();
    }

    // No more data to read from the bitstream: no need to reload.
    while p < p_end {
        dst[p] = huf_decode_symbol_x1(bit_d, dt, dt_log);
        p += 1;
    }

    p_end - p_start
}

/// `HUF_decompress1X1_usingDTable_internal`
fn huf_decompress1x1_using_dtable_internal(
    dst: &mut [u8],
    c_src: &[u8],
    dtable: &HufDTable,
) -> Result<usize> {
    let dst_size = dst.len();
    let dt_log = u32::from(dtable.desc.table_log);
    let mut bit_d = BitDStream::new(c_src)?;
    huf_decode_stream_x1(dst, 0, &mut bit_d, dst_size, &dtable.x1, dt_log);
    if !bit_d.end_of_dstream() {
        return error!(CorruptionDetected);
    }
    Ok(dst_size)
}

/// The jump table of a 4-stream input: where each stream starts and how
/// long it is, and where each stream's output starts. Shared by the X1 and
/// X2 fallback loops.
struct FourStreams {
    starts: [usize; 4],
    lengths: [usize; 4],
    op_starts: [usize; 4],
}

/// The checks and jump table reading that start
/// `HUF_decompress4X{1,2}_usingDTable_internal_body`.
fn huf_read_four_streams(dst_size: usize, c_src: &[u8]) -> Result<FourStreams> {
    let c_src_size = c_src.len();
    if c_src_size < 10 {
        // The strict minimum: the jump table and 1 byte per stream.
        return error!(CorruptionDetected);
    }
    if dst_size < 6 {
        // The 4-way split does not work.
        return error!(CorruptionDetected);
    }
    let length1 = usize::from(read_le16(c_src, 0));
    let length2 = usize::from(read_le16(c_src, 2));
    let length3 = usize::from(read_le16(c_src, 4));
    let length4 = c_src_size.wrapping_sub(length1 + length2 + length3 + 6);
    let istart1 = 6;
    let istart2 = istart1 + length1;
    let istart3 = istart2 + length2;
    let istart4 = istart3 + length3;
    let segment_size = dst_size.div_ceil(4);
    let op_start2 = segment_size;
    let op_start3 = op_start2 + segment_size;
    let op_start4 = op_start3 + segment_size;
    if length4 > c_src_size {
        // Overflow.
        return error!(CorruptionDetected);
    }
    if op_start4 > dst_size {
        // Overflow.
        return error!(CorruptionDetected);
    }
    Ok(FourStreams {
        starts: [istart1, istart2, istart3, istart4],
        lengths: [length1, length2, length3, length4],
        op_starts: [0, op_start2, op_start3, op_start4],
    })
}

/// `HUF_decompress4X1_usingDTable_internal_body`: the fallback loop.
fn huf_decompress4x1_using_dtable_internal_body(
    dst: &mut [u8],
    c_src: &[u8],
    dtable: &HufDTable,
) -> Result<usize> {
    count_run(1);
    let dst_size = dst.len();
    let streams = huf_read_four_streams(dst_size, c_src)?;
    let dt = &dtable.x1;
    let dt_log = u32::from(dtable.desc.table_log);
    let oend = dst_size;
    let olimit = oend - 3;
    let [op_start1, op_start2, op_start3, op_start4] = streams.op_starts;
    let stream = |i: usize| &c_src[streams.starts[i]..streams.starts[i] + streams.lengths[i]];
    let mut bit_d1 = BitDStream::new(stream(0))?;
    let mut bit_d2 = BitDStream::new(stream(1))?;
    let mut bit_d3 = BitDStream::new(stream(2))?;
    let mut bit_d4 = BitDStream::new(stream(3))?;
    let (mut op1, mut op2, mut op3, mut op4) = (op_start1, op_start2, op_start3, op_start4);
    let mut end_signal = true;

    // Up to 16 symbols per loop, 4 per stream.
    if oend - op4 >= 8 {
        while end_signal & (op4 < olimit) {
            for k in 0..4 {
                dst[op1 + k] = huf_decode_symbol_x1(&mut bit_d1, dt, dt_log);
                dst[op2 + k] = huf_decode_symbol_x1(&mut bit_d2, dt, dt_log);
                dst[op3 + k] = huf_decode_symbol_x1(&mut bit_d3, dt, dt_log);
                dst[op4 + k] = huf_decode_symbol_x1(&mut bit_d4, dt, dt_log);
            }
            op1 += 4;
            op2 += 4;
            op3 += 4;
            op4 += 4;
            end_signal &= bit_d1.reload_fast() == BitDStatus::Unfinished;
            end_signal &= bit_d2.reload_fast() == BitDStatus::Unfinished;
            end_signal &= bit_d3.reload_fast() == BitDStatus::Unfinished;
            end_signal &= bit_d4.reload_fast() == BitDStatus::Unfinished;
        }
    }

    // Check for corruption; op4 was checked by the loop.
    if op1 > op_start2 || op2 > op_start3 || op3 > op_start4 {
        return error!(CorruptionDetected);
    }

    // Finish the streams one by one.
    huf_decode_stream_x1(dst, op1, &mut bit_d1, op_start2, dt, dt_log);
    huf_decode_stream_x1(dst, op2, &mut bit_d2, op_start3, dt, dt_log);
    huf_decode_stream_x1(dst, op3, &mut bit_d3, op_start4, dt, dt_log);
    huf_decode_stream_x1(dst, op4, &mut bit_d4, oend, dt, dt_log);

    let end_check = bit_d1.end_of_dstream()
        & bit_d2.end_of_dstream()
        & bit_d3.end_of_dstream()
        & bit_d4.end_of_dstream();
    if !end_check {
        return error!(CorruptionDetected);
    }
    Ok(dst_size)
}

/// `HUF_decompress4X1_usingDTable_internal_fast_c_loop`
fn huf_decompress4x1_using_dtable_internal_fast_c_loop(
    args: &mut HufDecompressFastArgs,
    dst: &mut [u8],
    src: &[u8],
    dt: &[HufDEltX1; HUF_DTABLE_CELLS],
) {
    let mut bits = args.bits;
    let mut ip = args.ip;
    let mut op = args.op;
    let oend = args.oend;

    'out: loop {
        // Each iteration produces 5 symbols per stream, and reads at most
        // 5 * 11 = 55 bits, so under 7 bytes, per stream.
        let oiters = (oend - op[3]) / 5;
        // ip[0] - ilowest
        let iiters = ip[0] / 7;
        let iters = oiters.min(iiters);
        let symbols = iters * 5;

        // Checking op[3] is enough: no other bound can be reached before
        // op[3] reaches olimit.
        let olimit = op[3] + symbols;
        if op[3] == olimit {
            break;
        }

        // An input position below the one before it means corruption, and
        // the loop relies on ip[i] >= ip[0].
        for stream in 1..4 {
            if ip[stream] < ip[stream - 1] {
                break 'out;
            }
        }

        loop {
            // Decode 5 symbols in each of the 4 streams. libzstd writes each
            // symbol as it goes; the port gathers each stream's five in a
            // register and writes them at once, the same bytes with one
            // bounds check instead of five.
            let mut symbols = [0u64; 4];
            for symbol in 0..5 {
                for stream in 0..4 {
                    let index = (bits[stream] >> 53) as usize;
                    let entry = dt[index].0;
                    bits[stream] <<= entry & 0x3F;
                    symbols[stream] |= u64::from(entry >> 8) << (8 * symbol);
                }
            }
            for stream in 0..4 {
                let bytes = symbols[stream].to_le_bytes();
                dst[op[stream]..op[stream] + 5].copy_from_slice(&bytes[..5]);
            }
            // Reload each of the 4 bitstreams.
            for stream in 0..4 {
                let ctz = bits[stream].trailing_zeros();
                let nb_bits = ctz & 7;
                let nb_bytes = (ctz >> 3) as usize;
                op[stream] += 5;
                ip[stream] -= nb_bytes;
                bits[stream] = read_le64(src, ip[stream]) | 1;
                bits[stream] <<= nb_bits;
            }
            if op[3] >= olimit {
                break;
            }
        }
    }

    args.bits = bits;
    args.ip = ip;
    args.op = op;
}

/// `HUF_decompress4X1_usingDTable_internal_fast`: `Ok(0)` when the input
/// does not suit the fast loop.
fn huf_decompress4x1_using_dtable_internal_fast(
    dst: &mut [u8],
    c_src: &[u8],
    dtable: &HufDTable,
) -> Result<usize> {
    let dst_size = dst.len();
    let Some(mut args) = huf_decompress_fast_args_init(dst_size, c_src, dtable)? else {
        return Ok(0);
    };
    count_run(0);
    huf_decompress4x1_using_dtable_internal_fast_c_loop(&mut args, dst, c_src, &dtable.x1);

    // Finish the streams one by one.
    let segment_size = dst_size.div_ceil(4);
    let mut segment_end = 0usize;
    for i in 0..4 {
        if segment_size <= dst_size - segment_end {
            segment_end += segment_size;
        } else {
            segment_end = dst_size;
        }
        let mut bit = huf_init_remaining_dstream(c_src, &args, i, segment_end)?;
        // Decode, and check that exactly the expected length came out.
        args.op[i] += huf_decode_stream_x1(
            dst,
            args.op[i],
            &mut bit,
            segment_end,
            &dtable.x1,
            HUF_DECODER_FAST_TABLELOG,
        );
        if args.op[i] != segment_end {
            return error!(CorruptionDetected);
        }
    }
    Ok(dst_size)
}

/// `HUF_decompress4X1_usingDTable_internal`
fn huf_decompress4x1_using_dtable_internal(
    dst: &mut [u8],
    c_src: &[u8],
    dtable: &HufDTable,
    flags: i32,
) -> Result<usize> {
    if flags & HUF_FLAGS_DISABLE_FAST == 0 {
        let ret = huf_decompress4x1_using_dtable_internal_fast(dst, c_src, dtable)?;
        if ret != 0 {
            return Ok(ret);
        }
    }
    huf_decompress4x1_using_dtable_internal_body(dst, c_src, dtable)
}

/// `HUF_decodeSymbolX2`: writes two bytes at `p`, of which the first
/// `length` are the symbols. Returns the length.
#[inline(always)]
fn huf_decode_symbol_x2(
    dst: &mut [u8],
    p: usize,
    bit_d: &mut BitDStream<'_>,
    dt: &[HufDEltX2; HUF_DTABLE_CELLS],
    dt_log: u32,
) -> usize {
    // dtLog >= 1
    let val = bit_d.look_bits_fast(dt_log) as usize;
    let cell = dt[val];
    dst[p..p + 2].copy_from_slice(&cell.sequence().to_le_bytes());
    bit_d.skip_bits(u32::from(cell.nb_bits()));
    usize::from(cell.length())
}

/// `HUF_decodeLastSymbolX2`: writes one byte at `p`.
#[inline(always)]
fn huf_decode_last_symbol_x2(
    dst: &mut [u8],
    p: usize,
    bit_d: &mut BitDStream<'_>,
    dt: &[HufDEltX2; HUF_DTABLE_CELLS],
    dt_log: u32,
) -> usize {
    // dtLog >= 1
    let val = bit_d.look_bits_fast(dt_log) as usize;
    let cell = dt[val];
    dst[p] = cell.sequence() as u8;
    if cell.length() == 1 {
        bit_d.skip_bits(u32::from(cell.nb_bits()));
    } else if bit_d.bits_consumed < 64 {
        bit_d.skip_bits(u32::from(cell.nb_bits()));
        if bit_d.bits_consumed > 64 {
            // libzstd's "ugly hack": it works only because this is the last
            // symbol.
            bit_d.bits_consumed = 64;
        }
    }
    1
}

/// `HUF_decodeStreamX2`: decodes into `dst[p..p_end]`. Returns how many bytes
/// it wrote.
#[inline(always)]
fn huf_decode_stream_x2(
    dst: &mut [u8],
    mut p: usize,
    bit_d: &mut BitDStream<'_>,
    p_end: usize,
    dt: &[HufDEltX2; HUF_DTABLE_CELLS],
    dt_log: u32,
) -> usize {
    let p_start = p;

    // Up to 8 symbols at a time (10 with a table log up to 11).
    if p_end - p >= 8 {
        if dt_log <= 11 {
            while (bit_d.reload() == BitDStatus::Unfinished) & (p + 9 < p_end) {
                for _ in 0..5 {
                    p += huf_decode_symbol_x2(dst, p, bit_d, dt, dt_log);
                }
            }
        } else {
            while (bit_d.reload() == BitDStatus::Unfinished) & (p + 7 < p_end) {
                for _ in 0..4 {
                    p += huf_decode_symbol_x2(dst, p, bit_d, dt, dt_log);
                }
            }
        }
    } else {
        bit_d.reload();
    }

    // Closer to the end: up to 2 symbols at a time.
    if p_end - p >= 2 {
        while (bit_d.reload() == BitDStatus::Unfinished) & (p + 2 <= p_end) {
            p += huf_decode_symbol_x2(dst, p, bit_d, dt, dt_log);
        }
        while p + 2 <= p_end {
            // No need to reload: the stream has reached its end.
            p += huf_decode_symbol_x2(dst, p, bit_d, dt, dt_log);
        }
    }

    if p < p_end {
        p += huf_decode_last_symbol_x2(dst, p, bit_d, dt, dt_log);
    }

    p - p_start
}

/// `HUF_decompress1X2_usingDTable_internal`
fn huf_decompress1x2_using_dtable_internal(
    dst: &mut [u8],
    c_src: &[u8],
    dtable: &HufDTable,
) -> Result<usize> {
    let mut bit_d = BitDStream::new(c_src)?;
    let dst_size = dst.len();
    huf_decode_stream_x2(
        dst,
        0,
        &mut bit_d,
        dst_size,
        &dtable.x2,
        u32::from(dtable.desc.table_log),
    );
    if !bit_d.end_of_dstream() {
        return error!(CorruptionDetected);
    }
    Ok(dst_size)
}

/// `HUF_decompress4X2_usingDTable_internal_body`: the fallback loop.
fn huf_decompress4x2_using_dtable_internal_body(
    dst: &mut [u8],
    c_src: &[u8],
    dtable: &HufDTable,
) -> Result<usize> {
    count_run(3);
    let dst_size = dst.len();
    let streams = huf_read_four_streams(dst_size, c_src)?;
    let dt = &dtable.x2;
    let dt_log = u32::from(dtable.desc.table_log);
    let oend = dst_size;
    let olimit = oend - 7;
    let [op_start1, op_start2, op_start3, op_start4] = streams.op_starts;
    let stream = |i: usize| &c_src[streams.starts[i]..streams.starts[i] + streams.lengths[i]];
    let mut bit_d1 = BitDStream::new(stream(0))?;
    let mut bit_d2 = BitDStream::new(stream(1))?;
    let mut bit_d3 = BitDStream::new(stream(2))?;
    let mut bit_d4 = BitDStream::new(stream(3))?;
    let (mut op1, mut op2, mut op3, mut op4) = (op_start1, op_start2, op_start3, op_start4);
    let mut end_signal = true;

    // 16 to 32 symbols per loop, 4 to 8 per stream. libzstd orders the
    // streams one way for clang on x86 and another elsewhere; the streams are
    // independent, so the results are the same.
    if oend - op4 >= 8 {
        while end_signal & (op4 < olimit) {
            for _ in 0..4 {
                op1 += huf_decode_symbol_x2(dst, op1, &mut bit_d1, dt, dt_log);
                op2 += huf_decode_symbol_x2(dst, op2, &mut bit_d2, dt, dt_log);
                op3 += huf_decode_symbol_x2(dst, op3, &mut bit_d3, dt, dt_log);
                op4 += huf_decode_symbol_x2(dst, op4, &mut bit_d4, dt, dt_log);
            }
            end_signal = (bit_d1.reload_fast() == BitDStatus::Unfinished)
                & (bit_d2.reload_fast() == BitDStatus::Unfinished)
                & (bit_d3.reload_fast() == BitDStatus::Unfinished)
                & (bit_d4.reload_fast() == BitDStatus::Unfinished);
        }
    }

    // Check for corruption; op4 was checked by the loop.
    if op1 > op_start2 || op2 > op_start3 || op3 > op_start4 {
        return error!(CorruptionDetected);
    }

    // Finish the streams one by one.
    huf_decode_stream_x2(dst, op1, &mut bit_d1, op_start2, dt, dt_log);
    huf_decode_stream_x2(dst, op2, &mut bit_d2, op_start3, dt, dt_log);
    huf_decode_stream_x2(dst, op3, &mut bit_d3, op_start4, dt, dt_log);
    huf_decode_stream_x2(dst, op4, &mut bit_d4, oend, dt, dt_log);

    let end_check = bit_d1.end_of_dstream()
        & bit_d2.end_of_dstream()
        & bit_d3.end_of_dstream()
        & bit_d4.end_of_dstream();
    if !end_check {
        return error!(CorruptionDetected);
    }
    Ok(dst_size)
}

/// `HUF_decompress4X2_usingDTable_internal_fast_c_loop`
fn huf_decompress4x2_using_dtable_internal_fast_c_loop(
    args: &mut HufDecompressFastArgs,
    dst: &mut [u8],
    src: &[u8],
    dt: &[HufDEltX2; HUF_DTABLE_CELLS],
) {
    let mut bits = args.bits;
    let mut ip = args.ip;
    let mut op = args.op;
    let oend = [op[1], op[2], op[3], args.oend];

    // HUF_4X2_DECODE_SYMBOL: writes two bytes, of which `length` count.
    let decode = |stream: usize, bits: &mut [u64; 4], op: &mut [usize; 4], dst: &mut [u8]| {
        let index = (bits[stream] >> 53) as usize;
        let entry = dt[index];
        let at = idx(op[stream]);
        dst[at..at + 2].copy_from_slice(&entry.sequence().to_le_bytes());
        bits[stream] <<= entry.nb_bits() & 0x3F;
        op[stream] += usize::from(entry.length());
    };

    'out: loop {
        // Each iteration reads at most 7 bytes per stream, and every ip[i]
        // is at least ip[0].
        let mut iters = ip[0] / 7;
        // And writes at most 10 bytes per stream, each at its own pace.
        for stream in 0..4 {
            let oiters = (oend[stream] - op[stream]) / 10;
            iters = iters.min(oiters);
        }

        // Each iteration writes at least 5 symbols, so until op[3] passes
        // olimit, fewer than iters iterations have run.
        let olimit = op[3] + iters * 5;
        if op[3] == olimit {
            break;
        }

        for stream in 1..4 {
            if ip[stream] < ip[stream - 1] {
                break 'out;
            }
        }

        loop {
            // 5 symbols from each of the first 3 streams, and one from the
            // last; its other 4 are decoded while reloading.
            for _ in 0..5 {
                for stream in 0..3 {
                    decode(stream, &mut bits, &mut op, dst);
                }
            }
            decode(3, &mut bits, &mut op, dst);

            // HUF_4X2_RELOAD_STREAM, which also decodes one symbol of the
            // last stream each time, so that stream reloads last.
            for stream in 0..4 {
                decode(3, &mut bits, &mut op, dst);
                let ctz = bits[stream].trailing_zeros();
                let nb_bits = ctz & 7;
                let nb_bytes = (ctz >> 3) as usize;
                ip[stream] -= nb_bytes;
                bits[stream] = read_le64(src, ip[stream]) | 1;
                bits[stream] <<= nb_bits;
            }
            if op[3] >= olimit {
                break;
            }
        }
    }

    args.bits = bits;
    args.ip = ip;
    args.op = op;
}

/// `HUF_decompress4X2_usingDTable_internal_fast`: `Ok(0)` when the input
/// does not suit the fast loop.
fn huf_decompress4x2_using_dtable_internal_fast(
    dst: &mut [u8],
    c_src: &[u8],
    dtable: &HufDTable,
) -> Result<usize> {
    let dst_size = dst.len();
    let Some(mut args) = huf_decompress_fast_args_init(dst_size, c_src, dtable)? else {
        return Ok(0);
    };
    count_run(2);
    huf_decompress4x2_using_dtable_internal_fast_c_loop(&mut args, dst, c_src, &dtable.x2);

    // Finish the streams one by one.
    let segment_size = dst_size.div_ceil(4);
    let mut segment_end = 0usize;
    for i in 0..4 {
        if segment_size <= dst_size - segment_end {
            segment_end += segment_size;
        } else {
            segment_end = dst_size;
        }
        let mut bit = huf_init_remaining_dstream(c_src, &args, i, segment_end)?;
        args.op[i] += huf_decode_stream_x2(
            dst,
            args.op[i],
            &mut bit,
            segment_end,
            &dtable.x2,
            HUF_DECODER_FAST_TABLELOG,
        );
        if args.op[i] != segment_end {
            return error!(CorruptionDetected);
        }
    }
    Ok(dst_size)
}

/// `HUF_decompress4X2_usingDTable_internal`
fn huf_decompress4x2_using_dtable_internal(
    dst: &mut [u8],
    c_src: &[u8],
    dtable: &HufDTable,
    flags: i32,
) -> Result<usize> {
    if flags & HUF_FLAGS_DISABLE_FAST == 0 {
        let ret = huf_decompress4x2_using_dtable_internal_fast(dst, c_src, dtable)?;
        if ret != 0 {
            return Ok(ret);
        }
    }
    huf_decompress4x2_using_dtable_internal_body(dst, c_src, dtable)
}

/// The workspace of the `_DCtx_wksp` functions: what the table builders
/// need, in libzstd's `HUF_DECOMPRESS_WORKSPACE_SIZE`.
#[derive(Default)]
pub(crate) struct HufDecompressWksp {
    pub(crate) x1: HufReadDTableX1Workspace,
    pub(crate) x2: HufReadDTableX2Workspace,
}

/// `HUF_decompress1X1_DCtx_wksp`: reads the table from `c_src`, then
/// decodes the single stream after it.
pub(crate) fn huf_decompress1x1_dctx_wksp(
    dtable: &mut HufDTable,
    dst: &mut [u8],
    c_src: &[u8],
    wksp: &mut HufDecompressWksp,
    _flags: i32,
) -> Result<usize> {
    let h_size = huf_read_dtable_x1_wksp(dtable, c_src, &mut wksp.x1)?;
    if h_size >= c_src.len() {
        return error!(SrcSizeWrong);
    }
    huf_decompress1x1_using_dtable_internal(dst, &c_src[h_size..], dtable)
}

/// `HUF_decompress1X2_DCtx_wksp`
pub(crate) fn huf_decompress1x2_dctx_wksp(
    dtable: &mut HufDTable,
    dst: &mut [u8],
    c_src: &[u8],
    wksp: &mut HufDecompressWksp,
    _flags: i32,
) -> Result<usize> {
    let h_size = huf_read_dtable_x2_wksp(dtable, c_src, &mut wksp.x2)?;
    if h_size >= c_src.len() {
        return error!(SrcSizeWrong);
    }
    huf_decompress1x2_using_dtable_internal(dst, &c_src[h_size..], dtable)
}

/// `HUF_decompress4X1_DCtx_wksp`
fn huf_decompress4x1_dctx_wksp(
    dtable: &mut HufDTable,
    dst: &mut [u8],
    c_src: &[u8],
    wksp: &mut HufDecompressWksp,
    flags: i32,
) -> Result<usize> {
    let h_size = huf_read_dtable_x1_wksp(dtable, c_src, &mut wksp.x1)?;
    if h_size >= c_src.len() {
        return error!(SrcSizeWrong);
    }
    huf_decompress4x1_using_dtable_internal(dst, &c_src[h_size..], dtable, flags)
}

/// `HUF_decompress4X2_DCtx_wksp`
fn huf_decompress4x2_dctx_wksp(
    dtable: &mut HufDTable,
    dst: &mut [u8],
    c_src: &[u8],
    wksp: &mut HufDecompressWksp,
    flags: i32,
) -> Result<usize> {
    let h_size = huf_read_dtable_x2_wksp(dtable, c_src, &mut wksp.x2)?;
    if h_size >= c_src.len() {
        return error!(SrcSizeWrong);
    }
    huf_decompress4x2_using_dtable_internal(dst, &c_src[h_size..], dtable, flags)
}

/// `algoTime`: libzstd's measured cost of building each table and of
/// decoding 256 bytes with it, by compression ratio (`Q`).
const ALGO_TIME: [[(u32, u32); 2]; 16] = [
    [(0, 0), (1, 1)], // Q == 0: impossible
    [(0, 0), (1, 1)], // Q == 1: impossible
    [(150, 216), (381, 119)],
    [(170, 205), (514, 112)],
    [(177, 199), (539, 110)],
    [(197, 194), (644, 107)],
    [(221, 192), (735, 107)],
    [(256, 189), (881, 106)],
    [(359, 188), (1167, 109)],
    [(582, 187), (1570, 114)],
    [(688, 187), (1712, 122)],
    [(825, 186), (1965, 136)],
    [(976, 185), (2131, 150)],
    [(1180, 186), (2070, 175)],
    [(1377, 185), (1731, 202)],
    [(1412, 185), (1695, 202)],
];

/// `HUF_selectDecoder`: which table is likely to decode faster, 0 for X1 and
/// 1 for X2. Needs `0 < dst_size <= 128 KiB`.
pub(crate) fn huf_select_decoder(dst_size: usize, c_src_size: usize) -> u32 {
    debug_assert!(dst_size > 0 && dst_size <= 128 * 1024);
    let q = if c_src_size >= dst_size {
        15
    } else {
        c_src_size * 16 / dst_size
    };
    let d256 = (dst_size >> 8) as u32;
    let d_time0 = ALGO_TIME[q][0].0 + ALGO_TIME[q][0].1 * d256;
    let mut d_time1 = ALGO_TIME[q][1].0 + ALGO_TIME[q][1].1 * d256;
    // A small advantage to the table that uses less memory, to reduce cache
    // eviction.
    d_time1 += d_time1 >> 5;
    u32::from(d_time1 < d_time0)
}

/// `HUF_decompress1X_DCtx_wksp`: decodes a single stream, with a table it
/// reads first, or stored or RLE data.
pub(crate) fn huf_decompress1x_dctx_wksp(
    dtable: &mut HufDTable,
    dst: &mut [u8],
    c_src: &[u8],
    wksp: &mut HufDecompressWksp,
    flags: i32,
) -> Result<usize> {
    let dst_size = dst.len();
    if dst_size == 0 {
        return error!(DstSizeTooSmall);
    }
    if c_src.len() > dst_size {
        return error!(CorruptionDetected);
    }
    if c_src.len() == dst_size {
        // Not compressed.
        dst.copy_from_slice(c_src);
        return Ok(dst_size);
    }
    if c_src.len() == 1 {
        // RLE.
        dst.fill(c_src[0]);
        return Ok(dst_size);
    }
    if huf_select_decoder(dst_size, c_src.len()) == 1 {
        huf_decompress1x2_dctx_wksp(dtable, dst, c_src, wksp, flags)
    } else {
        huf_decompress1x1_dctx_wksp(dtable, dst, c_src, wksp, flags)
    }
}

/// `HUF_decompress1X_usingDTable`: decodes a single stream with the table
/// already in `dtable`.
pub(crate) fn huf_decompress1x_using_dtable(
    dst: &mut [u8],
    c_src: &[u8],
    dtable: &HufDTable,
    _flags: i32,
) -> Result<usize> {
    if dtable.desc.table_type != 0 {
        huf_decompress1x2_using_dtable_internal(dst, c_src, dtable)
    } else {
        huf_decompress1x1_using_dtable_internal(dst, c_src, dtable)
    }
}

/// `HUF_decompress4X_usingDTable`: decodes four streams with the table
/// already in `dtable`.
pub(crate) fn huf_decompress4x_using_dtable(
    dst: &mut [u8],
    c_src: &[u8],
    dtable: &HufDTable,
    flags: i32,
) -> Result<usize> {
    if dtable.desc.table_type != 0 {
        huf_decompress4x2_using_dtable_internal(dst, c_src, dtable, flags)
    } else {
        huf_decompress4x1_using_dtable_internal(dst, c_src, dtable, flags)
    }
}

/// `HUF_decompress4X_hufOnly_wksp`: decodes four streams, with a table it
/// reads first.
pub(crate) fn huf_decompress4x_huf_only_wksp(
    dtable: &mut HufDTable,
    dst: &mut [u8],
    c_src: &[u8],
    wksp: &mut HufDecompressWksp,
    flags: i32,
) -> Result<usize> {
    if dst.is_empty() {
        return error!(DstSizeTooSmall);
    }
    if c_src.is_empty() {
        return error!(CorruptionDetected);
    }
    if huf_select_decoder(dst.len(), c_src.len()) == 1 {
        huf_decompress4x2_dctx_wksp(dtable, dst, c_src, wksp, flags)
    } else {
        huf_decompress4x1_dctx_wksp(dtable, dst, c_src, wksp, flags)
    }
}
