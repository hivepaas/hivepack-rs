//! Huffman encoding: port of `compress/huf_compress.c`.
//!
//! A table (`HUF_CElt` array) holds a header in its first element, then one
//! element per symbol: the code length in the low byte and the code in the
//! top bits. libzstd keeps a table from block to block and only rewrites
//! the elements of the symbols a new table has, so the port keeps whole
//! tables too, of [`HUF_CTABLE_SIZE`] elements. The elements are 64 bits
//! (`size_t` on 64-bit machines); the bytes compressed are the same as with
//! 32-bit ones.

use crate::zstd::common::bits::highbit32;
use crate::zstd::common::entropy_common::huf_read_stats_wksp;
use crate::zstd::common::error_private::{Result, error};
use crate::zstd::common::fse::fse_ctable_size_u32;
use crate::zstd::common::fse_decompress::FseDecompressWksp;
use crate::zstd::common::huf::{
    HUF_BLOCKSIZE_MAX, HUF_FLAGS_OPTIMAL_DEPTH, HUF_FLAGS_PREFER_REPEAT,
    HUF_FLAGS_SUSPECT_UNCOMPRESSIBLE, HUF_SYMBOLVALUE_MAX, HUF_TABLELOG_ABSOLUTEMAX,
    HUF_TABLELOG_DEFAULT, HUF_TABLELOG_MAX,
};
use crate::zstd::common::mem::{write_le16, write_le64};
use crate::zstd::compress::fse_compress::{
    fse_build_ctable_wksp, fse_compress_using_ctable, fse_normalize_count, fse_optimal_table_log,
    fse_optimal_table_log_internal, fse_write_ncount,
};
use crate::zstd::compress::hist::{HIST_WKSP_SIZE_U32, hist_count_simple, hist_count_wksp};

/// `HUF_CElt`: a symbol's code length (low byte) and code (top bits).
pub(crate) type HufCElt = u64;

/// `HUF_CTABLE_SIZE_ST(HUF_SYMBOLVALUE_MAX)`: a table with its header.
pub(crate) const HUF_CTABLE_SIZE: usize = HUF_SYMBOLVALUE_MAX as usize + 2;

/// `HUF_CElt[HUF_CTABLE_SIZE_ST(HUF_SYMBOLVALUE_MAX)]`
pub(crate) type HufCTable = [HufCElt; HUF_CTABLE_SIZE];

/// `HUF_repeat`: whether the previous table may be used again.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum HufRepeat {
    /// It cannot.
    None = 0,
    /// It can, once checked against the new symbols.
    Check = 1,
    /// It can, and is assumed to have every symbol.
    Valid = 2,
}

/// `HUF_CTableHeader`, kept in the first element of a table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct HufCTableHeader {
    pub(crate) table_log: u8,
    pub(crate) max_symbol_value: u8,
}

/// `HUF_readCTableHeader`
pub(crate) fn huf_read_ctable_header(ctable: &HufCTable) -> HufCTableHeader {
    // The header's bytes, as libzstd copies them into the element.
    HufCTableHeader {
        table_log: ctable[0] as u8,
        max_symbol_value: (ctable[0] >> 8) as u8,
    }
}

/// `HUF_writeCTableHeader`
fn huf_write_ctable_header(ctable: &mut HufCTable, table_log: u32, max_symbol_value: u32) {
    debug_assert!(table_log < 256 && max_symbol_value < 256);
    ctable[0] = u64::from(table_log) | (u64::from(max_symbol_value) << 8);
}

/// `HUF_getNbBits`
#[inline(always)]
fn get_nb_bits(elt: HufCElt) -> usize {
    (elt & 0xFF) as usize
}

/// `HUF_getNbBitsFast`: the code length in the low byte, with the code
/// above it.
#[inline(always)]
fn get_nb_bits_fast(elt: HufCElt) -> u64 {
    elt
}

/// `HUF_getValue`
#[inline(always)]
fn get_value(elt: HufCElt) -> u64 {
    elt & !0xFF
}

/// `HUF_getValueFast`: the code, with the length in the low byte.
#[inline(always)]
fn get_value_fast(elt: HufCElt) -> u64 {
    elt
}

/// `HUF_setNbBits`
#[inline(always)]
fn set_nb_bits(elt: &mut HufCElt, nb_bits: usize) {
    debug_assert!(nb_bits <= HUF_TABLELOG_ABSOLUTEMAX as usize);
    *elt = nb_bits as u64;
}

/// `HUF_setValue`
#[inline(always)]
fn set_value(elt: &mut HufCElt, value: u64) {
    let nb_bits = get_nb_bits(*elt);
    if nb_bits > 0 {
        debug_assert!(value >> nb_bits == 0);
        *elt |= value << (64 - nb_bits);
    }
}

/// `MAX_FSE_TABLELOG_FOR_HUFF_HEADER`
const MAX_FSE_TABLELOG_FOR_HUFF_HEADER: u32 = 6;

/// `HUF_compressWeights`: the weights compressed with FSE, as
/// `FSE_compress` would but with less memory. Returns 0 when they do not
/// compress, 1 when they are all the same.
fn huf_compress_weights(dst: &mut [u8], weight_table: &[u8]) -> Result<usize> {
    let mut op = 0;
    let mut max_symbol_value = HUF_TABLELOG_MAX;
    let mut table_log = MAX_FSE_TABLELOG_FOR_HUFF_HEADER;
    let mut ctable =
        [0u32; fse_ctable_size_u32(MAX_FSE_TABLELOG_FOR_HUFF_HEADER, HUF_TABLELOG_MAX)];
    let mut count = [0u32; HUF_TABLELOG_MAX as usize + 1];
    let mut norm = [0i16; HUF_TABLELOG_MAX as usize + 1];

    let wt_size = weight_table.len();
    if wt_size <= 1 {
        // Not compressible.
        return Ok(0);
    }

    // The symbol statistics.
    {
        // Never fails.
        let max_count = hist_count_simple(&mut count, &mut max_symbol_value, weight_table);
        if max_count as usize == wt_size {
            // A single symbol: RLE.
            return Ok(1);
        }
        if max_count == 1 {
            // Each symbol at most once: not compressible.
            return Ok(0);
        }
    }

    table_log = fse_optimal_table_log(table_log, wt_size, max_symbol_value);
    fse_normalize_count(
        &mut norm,
        table_log,
        &count,
        wt_size,
        max_symbol_value,
        false,
    )?;

    // The table description.
    let h_size = fse_write_ncount(&mut dst[op..], &norm, max_symbol_value, table_log)?;
    op += h_size;

    // The weights.
    fse_build_ctable_wksp(&mut ctable, &norm, max_symbol_value, table_log)?;
    let c_size = fse_compress_using_ctable(&mut dst[op..], weight_table, &ctable);
    if c_size == 0 {
        // Not enough room.
        return Ok(0);
    }
    op += c_size;

    Ok(op)
}

/// `HUF_writeCTable_wksp`: the table's description, as `HUF_readStats`
/// reads it: its weights, compressed with FSE when that is shorter, else 4
/// bits each.
pub(crate) fn huf_write_ctable_wksp(
    dst: &mut [u8],
    ctable: &HufCTable,
    max_symbol_value: u32,
    huff_log: u32,
) -> Result<usize> {
    let ct = &ctable[1..];
    let mut bits_to_weight = [0u8; HUF_TABLELOG_MAX as usize + 1];
    let mut huff_weight = [0u8; HUF_SYMBOLVALUE_MAX as usize + 1];

    debug_assert!(u32::from(huf_read_ctable_header(ctable).max_symbol_value) == max_symbol_value);
    debug_assert!(u32::from(huf_read_ctable_header(ctable).table_log) == huff_log);

    if max_symbol_value > HUF_SYMBOLVALUE_MAX {
        return error!(MaxSymbolValueTooLarge);
    }

    // The code lengths as weights.
    bits_to_weight[0] = 0;
    for n in 1..huff_log + 1 {
        bits_to_weight[n as usize] = (huff_log + 1 - n) as u8;
    }
    for n in 0..max_symbol_value as usize {
        huff_weight[n] = bits_to_weight[get_nb_bits(ct[n])];
    }

    // Try compressing the weights with FSE.
    if dst.is_empty() {
        return error!(DstSizeTooSmall);
    }
    {
        let h_size =
            huf_compress_weights(&mut dst[1..], &huff_weight[..max_symbol_value as usize])?;
        if h_size > 1 && h_size < max_symbol_value as usize / 2 {
            // FSE-compressed.
            dst[0] = h_size as u8;
            return Ok(h_size + 1);
        }
    }

    // The weights as 4-bit values (at most 15).
    if max_symbol_value > 256 - 128 {
        // Should not happen: the source likely cannot be compressed.
        return error!(Generic);
    }
    if (max_symbol_value as usize).div_ceil(2) + 1 > dst.len() {
        // Not enough room.
        return error!(DstSizeTooSmall);
    }
    dst[0] = (128 /* the special case */ + (max_symbol_value - 1)) as u8;
    // So that the last pair is defined.
    huff_weight[max_symbol_value as usize] = 0;
    for n in (0..max_symbol_value as usize).step_by(2) {
        dst[n / 2 + 1] = (huff_weight[n] << 4) + huff_weight[n + 1];
    }
    Ok((max_symbol_value as usize).div_ceil(2) + 1)
}

/// `HUF_readCTable`: a table from its description, as in a dictionary.
/// Returns the size read; `*max_symbol_value` becomes the table's largest
/// symbol, and `*has_zero_weights` whether some symbol has no code.
pub(crate) fn huf_read_ctable(
    ctable: &mut HufCTable,
    max_symbol_value: &mut u32,
    src: &[u8],
    has_zero_weights: &mut bool,
) -> Result<usize> {
    let mut huff_weight = [0u8; HUF_SYMBOLVALUE_MAX as usize + 1];
    // Large enough for values from 0 to 16.
    let mut rank_val = [0u32; HUF_TABLELOG_ABSOLUTEMAX as usize + 1];
    let mut table_log = 0;
    let mut nb_symbols = 0;

    // The symbols' weights.
    let mut wksp = Box::new(FseDecompressWksp::<64>::default());
    let read_size = huf_read_stats_wksp(
        &mut huff_weight,
        &mut rank_val,
        &mut nb_symbols,
        &mut table_log,
        src,
        &mut wksp,
    )?;
    *has_zero_weights = rank_val[0] > 0;

    // Check the result.
    if table_log > HUF_TABLELOG_MAX {
        return error!(TableLogTooLarge);
    }
    if nb_symbols > *max_symbol_value + 1 {
        return error!(MaxSymbolValueTooSmall);
    }

    *max_symbol_value = nb_symbols - 1;

    huf_write_ctable_header(ctable, table_log, *max_symbol_value);

    // The first value of each rank.
    {
        let mut next_rank_start = 0u32;
        for n in 1..=table_log as usize {
            let curr = next_rank_start;
            next_rank_start += rank_val[n] << (n - 1);
            rank_val[n] = curr;
        }
    }

    let ct = &mut ctable[1..];
    // The code lengths.
    for n in 0..nb_symbols as usize {
        let w = u32::from(huff_weight[n]);
        let nb_bits = if w != 0 { (table_log + 1 - w) as u8 } else { 0 };
        set_nb_bits(&mut ct[n], usize::from(nb_bits));
    }

    // The codes.
    {
        // Room for w == 0, as n == tableLog + 1.
        let mut nb_per_rank = [0u16; HUF_TABLELOG_MAX as usize + 2];
        let mut val_per_rank = [0u16; HUF_TABLELOG_MAX as usize + 2];
        for n in 0..nb_symbols as usize {
            nb_per_rank[get_nb_bits(ct[n])] += 1;
        }
        // The first value of each rank.
        val_per_rank[table_log as usize + 1] = 0; // for w == 0
        {
            let mut min = 0u16;
            // From n == tableLog, w == 1.
            for n in (1..=table_log as usize).rev() {
                val_per_rank[n] = min;
                min = min.wrapping_add(nb_per_rank[n]);
                min >>= 1;
            }
        }
        // The values within each rank, in symbol order.
        for n in 0..nb_symbols as usize {
            let rank = get_nb_bits(ct[n]);
            set_value(&mut ct[n], u64::from(val_per_rank[rank]));
            val_per_rank[rank] = val_per_rank[rank].wrapping_add(1);
        }
    }

    Ok(read_size)
}

/// `HUF_getNbBitsFromCTable`
pub(crate) fn huf_get_nb_bits_from_ctable(ctable: &HufCTable, symbol_value: u32) -> u32 {
    debug_assert!(symbol_value <= HUF_SYMBOLVALUE_MAX);
    if symbol_value > u32::from(huf_read_ctable_header(ctable).max_symbol_value) {
        return 0;
    }
    get_nb_bits(ctable[1 + symbol_value as usize]) as u32
}

/// `nodeElt`: a node of the Huffman tree being built.
#[derive(Clone, Copy, Default, Debug)]
struct NodeElt {
    count: u32,
    parent: u16,
    byte: u8,
    nb_bits: u8,
}

/// `huffNodeTable`, and libzstd's `huffNode` pointer one past its start:
/// index `i` of `huffNode` is element `i + 1` here, so that `huffNode[-1]`,
/// a barrier the tree building reads, is element 0.
struct HuffNodes([NodeElt; 2 * (HUF_SYMBOLVALUE_MAX as usize + 1)]);

impl std::ops::Index<i32> for HuffNodes {
    type Output = NodeElt;
    #[inline(always)]
    fn index(&self, at: i32) -> &NodeElt {
        &self.0[(at + 1) as usize]
    }
}

impl std::ops::IndexMut<i32> for HuffNodes {
    #[inline(always)]
    fn index_mut(&mut self, at: i32) -> &mut NodeElt {
        &mut self.0[(at + 1) as usize]
    }
}

/// `HUF_setMaxHeight`: makes the tree of the sorted nodes, the last
/// non-empty one at `last_non_null`, at most `target_nb_bits` deep, keeping
/// it a valid canonical Huffman tree. Returns the largest code length.
fn huf_set_max_height(huff_node: &mut HuffNodes, last_non_null: u32, target_nb_bits: u32) -> u32 {
    let largest_bits = u32::from(huff_node[last_non_null as i32].nb_bits);
    // Early exit: no element is too long, so the tree is already valid.
    if largest_bits <= target_nb_bits {
        return largest_bits;
    }

    // Several elements are too long (at least 2).
    let mut total_cost: i32 = 0;
    let base_cost = 1i32 << (largest_bits - target_nb_bits);
    let mut n = last_non_null as i32;

    // Cut the codes longer than targetNbBits, and count how far that puts
    // the sum of the ranks over 2^largestBits.
    while u32::from(huff_node[n].nb_bits) > target_nb_bits {
        total_cost += base_cost - (1 << (largest_bits - u32::from(huff_node[n].nb_bits)));
        huff_node[n].nb_bits = target_nb_bits as u8;
        n -= 1;
    }
    // n stops at huffNode[n].nbBits <= targetNbBits.
    debug_assert!(u32::from(huff_node[n].nb_bits) <= target_nb_bits);
    // n ends at the smallest symbol using fewer than targetNbBits.
    while u32::from(huff_node[n].nb_bits) == target_nb_bits {
        n -= 1;
    }

    // Renormalize totalCost from 2^largestBits to 2^targetNbBits; it is a
    // multiple of baseCost.
    debug_assert!((total_cost as u32) & (base_cost as u32 - 1) == 0);
    total_cost >>= largest_bits - target_nb_bits;
    debug_assert!(total_cost > 0);

    // Repay the normalized cost.
    const NO_SYMBOL: u32 = 0xF0F0_F0F0;
    let mut rank_last = [NO_SYMBOL; HUF_TABLELOG_MAX as usize + 2];

    // The position of the last (smallest) symbol of each rank.
    {
        let mut current_nb_bits = target_nb_bits;
        let mut pos = n;
        while pos >= 0 {
            if u32::from(huff_node[pos].nb_bits) < current_nb_bits {
                current_nb_bits = u32::from(huff_node[pos].nb_bits); // < targetNbBits
                rank_last[(target_nb_bits - current_nb_bits) as usize] = pos as u32;
            }
            pos -= 1;
        }
    }

    while total_cost > 0 {
        // Reduce the next power of 2 above totalCost, which gains back half
        // the rank.
        let mut n_bits_to_decrease = highbit32(total_cost as u32) + 1;
        while n_bits_to_decrease > 1 {
            let high_pos = rank_last[n_bits_to_decrease as usize];
            let low_pos = rank_last[n_bits_to_decrease as usize - 1];
            if high_pos == NO_SYMBOL {
                n_bits_to_decrease -= 1;
                continue;
            }
            // Decrease highPos if lowPos has no symbols, or if removing two
            // of lowPos is not cheaper than one of highPos.
            if low_pos == NO_SYMBOL {
                break;
            }
            let high_total = huff_node[high_pos as i32].count;
            let low_total = 2 * huff_node[low_pos as i32].count;
            if high_total <= low_total {
                break;
            }
            n_bits_to_decrease -= 1;
        }
        // Only when no rank-1 symbol is left: find the closest one (there is
        // necessarily one).
        debug_assert!(
            rank_last[n_bits_to_decrease as usize] != NO_SYMBOL || n_bits_to_decrease == 1
        );
        while n_bits_to_decrease <= HUF_TABLELOG_MAX
            && rank_last[n_bits_to_decrease as usize] == NO_SYMBOL
        {
            n_bits_to_decrease += 1;
        }
        debug_assert!(rank_last[n_bits_to_decrease as usize] != NO_SYMBOL);
        // One more bit, which gains back half the rank cost.
        total_cost -= 1 << (n_bits_to_decrease - 1);
        huff_node[rank_last[n_bits_to_decrease as usize] as i32].nb_bits += 1;

        // Fix up the new rank: if it was empty, this symbol is now its
        // smallest; otherwise it is the largest, which changes nothing.
        if rank_last[n_bits_to_decrease as usize - 1] == NO_SYMBOL {
            rank_last[n_bits_to_decrease as usize - 1] = rank_last[n_bits_to_decrease as usize];
        }
        // Fix up the old rank. At position 0, the symbol of the largest
        // weight, it was alone in its rank, which is now empty. Otherwise the
        // previous position, the nodes being sorted, is now the smallest of
        // the rank, unless it belongs to another rank, and the rank is empty.
        if rank_last[n_bits_to_decrease as usize] == 0 {
            // The special case: the largest symbol was reached.
            rank_last[n_bits_to_decrease as usize] = NO_SYMBOL;
        } else {
            rank_last[n_bits_to_decrease as usize] -= 1;
            if u32::from(huff_node[rank_last[n_bits_to_decrease as usize] as i32].nb_bits)
                != target_nb_bits.wrapping_sub(n_bits_to_decrease)
            {
                // This rank is now empty.
                rank_last[n_bits_to_decrease as usize] = NO_SYMBOL;
            }
        }
    }

    // Too much was removed: add it back, adjusting only the smallest rank,
    // by moving its largest nodes from rank 0 to rank 1.
    while total_cost < 0 {
        // The cost correction sometimes overshoots.
        if rank_last[1] == NO_SYMBOL {
            // No rank-1 symbol (using targetNbBits-1): make one from the
            // largest of rank 0 (using targetNbBits).
            while u32::from(huff_node[n].nb_bits) == target_nb_bits {
                n -= 1;
            }
            huff_node[n + 1].nb_bits -= 1;
            debug_assert!(n >= 0);
            rank_last[1] = (n + 1) as u32;
            total_cost += 1;
            continue;
        }
        huff_node[rank_last[1] as i32 + 1].nb_bits -= 1;
        rank_last[1] += 1;
        total_cost += 1;
    }

    target_nb_bits
}

/// `rankPos`
#[derive(Clone, Copy, Default)]
struct RankPos {
    base: u16,
    curr: u16,
}

/// `RANK_POSITION_TABLE_SIZE`: the buckets of [`huf_sort`].
const RANK_POSITION_TABLE_SIZE: usize = 192;
/// `RANK_POSITION_MAX_COUNT_LOG`
const RANK_POSITION_MAX_COUNT_LOG: u32 = 32;
/// `RANK_POSITION_LOG_BUCKETS_BEGIN`: 158.
const RANK_POSITION_LOG_BUCKETS_BEGIN: u32 =
    (RANK_POSITION_TABLE_SIZE as u32 - 1) - RANK_POSITION_MAX_COUNT_LOG - 1;
/// `RANK_POSITION_DISTINCT_COUNT_CUTOFF`: 166. Counts below it have a
/// bucket each; larger ones share a bucket per power of 2.
const RANK_POSITION_DISTINCT_COUNT_CUTOFF: u32 =
    RANK_POSITION_LOG_BUCKETS_BEGIN + RANK_POSITION_LOG_BUCKETS_BEGIN.ilog2();

/// `HUF_getIndex`: the bucket of a count.
#[inline(always)]
fn huf_get_index(count: u32) -> u32 {
    if count < RANK_POSITION_DISTINCT_COUNT_CUTOFF {
        count
    } else {
        highbit32(count) + RANK_POSITION_LOG_BUCKETS_BEGIN
    }
}

/// `HUF_insertionSort`: by decreasing count.
fn huf_insertion_sort(huff_node: &mut [NodeElt], low: i32, high: i32) {
    let size = high - low + 1;
    let huff_node = &mut huff_node[low as usize..];
    for i in 1..size {
        let key = huff_node[i as usize];
        let mut j = i - 1;
        while j >= 0 && huff_node[j as usize].count < key.count {
            huff_node[(j + 1) as usize] = huff_node[j as usize];
            j -= 1;
        }
        huff_node[(j + 1) as usize] = key;
    }
}

/// `HUF_quickSortPartition`: around the last element.
fn huf_quick_sort_partition(arr: &mut [NodeElt], low: i32, high: i32) -> i32 {
    // The rightmost element: better pivots do not appear to help.
    let pivot = arr[high as usize].count;
    let mut i = low - 1;
    for j in low..high {
        if arr[j as usize].count > pivot {
            i += 1;
            arr.swap(i as usize, j as usize);
        }
    }
    arr.swap((i + 1) as usize, high as usize);
    i + 1
}

/// `HUF_simpleQuickSort`: by decreasing count, recursing on the smaller
/// part. Its order of equal counts is libzstd's, which the tables depend
/// on.
fn huf_simple_quick_sort(arr: &mut [NodeElt], mut low: i32, mut high: i32) {
    const K_INSERTION_SORT_THRESHOLD: i32 = 8;
    if high - low < K_INSERTION_SORT_THRESHOLD {
        huf_insertion_sort(arr, low, high);
        return;
    }
    while low < high {
        let idx = huf_quick_sort_partition(arr, low, high);
        if idx - low < high - idx {
            huf_simple_quick_sort(arr, low, idx - 1);
            low = idx + 1;
        } else {
            huf_simple_quick_sort(arr, idx + 1, high);
            high = idx - 1;
        }
    }
}

/// `HUF_sort`: the symbols `0..=max_symbol_value` into `huff_node` by
/// decreasing count, in buckets, each sorted with quicksort or insertion
/// sort. Only `count` and `byte` are set.
fn huf_sort(huff_node: &mut [NodeElt], count: &[u32], max_symbol_value: u32) {
    let max_symbol_value1 = max_symbol_value as usize + 1;
    let mut rank_position = [RankPos::default(); RANK_POSITION_TABLE_SIZE];

    // Each symbol counts towards the base of the bucket below its own, so
    // that bucket R starts after the buckets above it.
    for &c in &count[..max_symbol_value1] {
        let lower_rank = huf_get_index(c) as usize;
        debug_assert!(lower_rank < RANK_POSITION_TABLE_SIZE - 1);
        rank_position[lower_rank].base += 1;
    }

    debug_assert!(rank_position[RANK_POSITION_TABLE_SIZE - 1].base == 0);
    // Where each bucket starts.
    for n in (1..RANK_POSITION_TABLE_SIZE).rev() {
        rank_position[n - 1].base += rank_position[n].base;
        rank_position[n - 1].curr = rank_position[n - 1].base;
    }

    // Each symbol into its bucket.
    for (n, &c) in count[..max_symbol_value1].iter().enumerate() {
        let r = huf_get_index(c) as usize + 1;
        let pos = usize::from(rank_position[r].curr);
        rank_position[r].curr += 1;
        debug_assert!(pos < max_symbol_value1);
        huff_node[pos].count = c;
        huff_node[pos].byte = n as u8;
    }

    // Sort each bucket.
    for n in RANK_POSITION_DISTINCT_COUNT_CUTOFF as usize..RANK_POSITION_TABLE_SIZE - 1 {
        let bucket_size = i32::from(rank_position[n].curr) - i32::from(rank_position[n].base);
        let bucket_start_idx = usize::from(rank_position[n].base);
        if bucket_size > 1 {
            debug_assert!(bucket_start_idx < max_symbol_value1);
            huf_simple_quick_sort(&mut huff_node[bucket_start_idx..], 0, bucket_size - 1);
        }
    }
}

/// `STARTNODE`: where the tree's inner nodes start.
const STARTNODE: i32 = HUF_SYMBOLVALUE_MAX as i32 + 1;

/// `HUF_buildTree`: a Huffman tree of unlimited depth from the sorted
/// nodes. Returns the position of the smallest node.
fn huf_build_tree(huff_node: &mut HuffNodes, max_symbol_value: u32) -> i32 {
    let mut node_nb = STARTNODE;
    // Initialize for the parents.
    let mut non_null_rank = max_symbol_value as i32;
    while huff_node[non_null_rank].count == 0 {
        non_null_rank -= 1;
    }
    let mut low_s = non_null_rank;
    let node_root = node_nb + low_s - 1;
    let mut low_n = node_nb;
    huff_node[node_nb].count = huff_node[low_s].count + huff_node[low_s - 1].count;
    huff_node[low_s].parent = node_nb as u16;
    huff_node[low_s - 1].parent = node_nb as u16;
    node_nb += 1;
    low_s -= 2;
    for n in node_nb..=node_root {
        huff_node[n].count = 1 << 30;
    }
    // A fake entry, a strong barrier.
    huff_node[-1].count = 1 << 31;

    // The parents.
    while node_nb <= node_root {
        let n1 = if huff_node[low_s].count < huff_node[low_n].count {
            low_s -= 1;
            low_s + 1
        } else {
            low_n += 1;
            low_n - 1
        };
        let n2 = if huff_node[low_s].count < huff_node[low_n].count {
            low_s -= 1;
            low_s + 1
        } else {
            low_n += 1;
            low_n - 1
        };
        huff_node[node_nb].count = huff_node[n1].count.wrapping_add(huff_node[n2].count);
        huff_node[n1].parent = node_nb as u16;
        huff_node[n2].parent = node_nb as u16;
        node_nb += 1;
    }

    // The code lengths, at unlimited depth.
    huff_node[node_root].nb_bits = 0;
    let mut n = node_root - 1;
    while n >= STARTNODE {
        let parent = i32::from(huff_node[n].parent);
        huff_node[n].nb_bits = huff_node[parent].nb_bits.wrapping_add(1);
        n -= 1;
    }
    for n in 0..=non_null_rank {
        let parent = i32::from(huff_node[n].parent);
        huff_node[n].nb_bits = huff_node[parent].nb_bits.wrapping_add(1);
    }

    non_null_rank
}

/// `HUF_buildCTableFromTree`: the table of the tree, whose codes are at
/// most `max_nb_bits` long.
fn huf_build_ctable_from_tree(
    ctable: &mut HufCTable,
    huff_node: &HuffNodes,
    non_null_rank: i32,
    max_symbol_value: u32,
    max_nb_bits: u32,
) {
    let mut nb_per_rank = [0u16; HUF_TABLELOG_MAX as usize + 1];
    let mut val_per_rank = [0u16; HUF_TABLELOG_MAX as usize + 1];
    let alphabet_size = max_symbol_value as i32 + 1;
    for n in 0..=non_null_rank {
        nb_per_rank[usize::from(huff_node[n].nb_bits)] += 1;
    }
    // The first value of each rank.
    {
        let mut min = 0u16;
        for n in (1..=max_nb_bits as usize).rev() {
            val_per_rank[n] = min;
            min = min.wrapping_add(nb_per_rank[n]);
            min >>= 1;
        }
    }
    {
        let ct = &mut ctable[1..];
        // The code lengths, in symbol order.
        for n in 0..alphabet_size {
            set_nb_bits(
                &mut ct[usize::from(huff_node[n].byte)],
                usize::from(huff_node[n].nb_bits),
            );
        }
        // The codes within each rank, in symbol order.
        for n in 0..alphabet_size as usize {
            let rank = get_nb_bits(ct[n]);
            set_value(&mut ct[n], u64::from(val_per_rank[rank]));
            val_per_rank[rank] = val_per_rank[rank].wrapping_add(1);
        }
    }
    huf_write_ctable_header(ctable, max_nb_bits, max_symbol_value);
}

/// `HUF_buildCTable_wksp`: a table for `count`, its codes at most
/// `max_nb_bits` long (`HUF_TABLELOG_DEFAULT` for 0). Returns the longest.
/// Only the elements of the symbols `0..=max_symbol_value` are written.
pub(crate) fn huf_build_ctable_wksp(
    ctable: &mut HufCTable,
    count: &[u32],
    max_symbol_value: u32,
    mut max_nb_bits: u32,
) -> Result<u32> {
    if max_nb_bits == 0 {
        max_nb_bits = HUF_TABLELOG_DEFAULT;
    }
    if max_symbol_value > HUF_SYMBOLVALUE_MAX {
        return error!(MaxSymbolValueTooLarge);
    }
    let mut huff_node = HuffNodes([NodeElt::default(); 2 * (HUF_SYMBOLVALUE_MAX as usize + 1)]);

    // Sort, by decreasing count.
    huf_sort(&mut huff_node.0[1..], count, max_symbol_value);

    // The tree.
    let non_null_rank = huf_build_tree(&mut huff_node, max_symbol_value);

    // Limit its depth.
    max_nb_bits = huf_set_max_height(&mut huff_node, non_null_rank as u32, max_nb_bits);
    if max_nb_bits > HUF_TABLELOG_MAX {
        // It does not fit the table.
        return error!(Generic);
    }

    huf_build_ctable_from_tree(
        ctable,
        &huff_node,
        non_null_rank,
        max_symbol_value,
        max_nb_bits,
    );

    Ok(max_nb_bits)
}

/// `HUF_estimateCompressedSize`: the bytes the symbols of `count` take
/// with `ctable`, rounded down.
pub(crate) fn huf_estimate_compressed_size(
    ctable: &HufCTable,
    count: &[u32],
    max_symbol_value: u32,
) -> usize {
    let ct = &ctable[1..];
    let mut nb_bits: usize = 0;
    for s in 0..=max_symbol_value as usize {
        nb_bits = nb_bits.wrapping_add(get_nb_bits(ct[s]) * count[s] as usize);
    }
    nb_bits >> 3
}

/// `HUF_validateCTable`: whether `ctable` has a code for every symbol of
/// `count`.
pub(crate) fn huf_validate_ctable(
    ctable: &HufCTable,
    count: &[u32],
    max_symbol_value: u32,
) -> bool {
    let header = huf_read_ctable_header(ctable);
    let ct = &ctable[1..];
    debug_assert!(u32::from(header.table_log) <= HUF_TABLELOG_ABSOLUTEMAX);
    if u32::from(header.max_symbol_value) < max_symbol_value {
        return false;
    }
    let mut bad = false;
    for s in 0..=max_symbol_value as usize {
        bad |= (count[s] != 0) & (get_nb_bits(ct[s]) == 0);
    }
    !bad
}

/// `HUF_CTABLEBOUND`: the largest table description.
pub(crate) const HUF_CTABLEBOUND: usize = 129;

/// `HUF_BLOCKBOUND`: the largest Huffman-compressed size of `size` bytes,
/// when they compress.
pub(crate) const fn huf_blockbound(size: usize) -> usize {
    size + (size >> 8) + 8
}

/// `HUF_compressBound`, `HUF_COMPRESSBOUND`
pub(crate) const fn huf_compress_bound(size: usize) -> usize {
    HUF_CTABLEBOUND + huf_blockbound(size)
}

/// `HUF_CStream_t`: Huffman's own bitstream writer. Unlike `BIT_CStream_t`,
/// it adds whole table elements, builds its register from the top bits
/// down, and has a second register to fill while the first one flushes.
///
/// The upper bits of `bit_pos` hold noise from the elements; only the low
/// byte counts.
struct HufCStream<'a> {
    bit_container: [u64; 2],
    bit_pos: [u64; 2],
    dst: &'a mut [u8],
    ptr: usize,
    end_ptr: usize,
}

/// `HUF_BITS_IN_CONTAINER`
const HUF_BITS_IN_CONTAINER: u64 = 64;

impl<'a> HufCStream<'a> {
    /// `HUF_initCStream`
    fn new(dst: &'a mut [u8]) -> Result<Self> {
        if dst.len() <= 8 {
            return error!(DstSizeTooSmall);
        }
        let end_ptr = dst.len() - 8;
        Ok(HufCStream {
            bit_container: [0; 2],
            bit_pos: [0; 2],
            dst,
            ptr: 0,
            end_ptr,
        })
    }

    /// `HUF_addBits`: the element's code into register `idx`. `FAST` when
    /// the register keeps at least 4 bits unused afterwards: the length's
    /// bits then come along with the code, below the bits that count.
    #[inline(always)]
    fn add_bits<const FAST: bool>(&mut self, elt: HufCElt, idx: usize) {
        debug_assert!(idx <= 1);
        debug_assert!(get_nb_bits(elt) <= HUF_TABLELOG_ABSOLUTEMAX as usize);
        self.bit_container[idx] >>= get_nb_bits(elt);
        self.bit_container[idx] |= if FAST {
            get_value_fast(elt)
        } else {
            get_value(elt)
        };
        // Only the low 8 bits of bitPos count, so noise above them from
        // the value does not matter.
        self.bit_pos[idx] = self.bit_pos[idx].wrapping_add(get_nb_bits_fast(elt));
        debug_assert!(self.bit_pos[idx] & 0xFF <= HUF_BITS_IN_CONTAINER);
    }

    /// `HUF_zeroIndex1`
    #[inline(always)]
    fn zero_index1(&mut self) {
        self.bit_container[1] = 0;
        self.bit_pos[1] = 0;
    }

    /// `HUF_mergeIndex1`: register 1 into register 0.
    #[inline(always)]
    fn merge_index1(&mut self) {
        debug_assert!(self.bit_pos[1] & 0xFF < HUF_BITS_IN_CONTAINER);
        self.bit_container[0] >>= self.bit_pos[1] & 0xFF;
        self.bit_container[0] |= self.bit_container[1];
        self.bit_pos[0] = self.bit_pos[0].wrapping_add(self.bit_pos[1]);
        debug_assert!(self.bit_pos[0] & 0xFF <= HUF_BITS_IN_CONTAINER);
    }

    /// `HUF_flushBits`: the whole bytes of register 0, leaving fewer than
    /// 8 bits. `FAST` when the stream is known to fit: then the position
    /// is not checked.
    #[inline(always)]
    fn flush_bits<const FAST: bool>(&mut self) {
        // The upper bits of bitPos are noise.
        let nb_bits = self.bit_pos[0] & 0xFF;
        let nb_bytes = (nb_bits >> 3) as usize;
        // The top nbBits bits of the register are the ones to write. libzstd
        // shifts by the register's size when nbBits is 0, which it never is
        // here; the processors it runs on then shift by 0.
        let bit_container =
            self.bit_container[0].wrapping_shr((HUF_BITS_IN_CONTAINER - nb_bits) as u32);
        // Count the bytes written.
        self.bit_pos[0] &= 7;
        debug_assert!(nb_bits > 0);
        debug_assert!(nb_bits <= 64);
        debug_assert!(self.ptr <= self.end_ptr);
        write_le64(self.dst, self.ptr, bit_container);
        self.ptr += nb_bytes;
        debug_assert!(!FAST || self.ptr <= self.end_ptr);
        if !FAST && self.ptr > self.end_ptr {
            self.ptr = self.end_ptr;
        }
        // The register keeps its bits: the ones left are its top bitPos
        // bits, and the noise below them does not matter.
    }

    /// `HUF_closeCStream`: adds the end mark and flushes. Returns the size,
    /// or 0 if the stream did not fit.
    fn close(mut self) -> usize {
        self.add_bits::<false>(huf_end_mark(), 0);
        self.flush_bits::<false>();
        let nb_bits = self.bit_pos[0] & 0xFF;
        if self.ptr >= self.end_ptr {
            // An overflow.
            return 0;
        }
        self.ptr + usize::from(nb_bits > 0)
    }

    /// `HUF_encodeSymbol`
    #[inline(always)]
    fn encode_symbol<const FAST: bool>(&mut self, symbol: u8, ct: &[HufCElt], idx: usize) {
        self.add_bits::<FAST>(ct[usize::from(symbol)], idx);
    }
}

/// `HUF_endMark`: the end mark, one bit set.
fn huf_end_mark() -> HufCElt {
    let mut end_mark = 0;
    set_nb_bits(&mut end_mark, 1);
    set_value(&mut end_mark, 1);
    end_mark
}

/// `HUF_compress1X_usingCTable_internal_body_loop`: the symbols from last
/// to first, `UNROLL` at a time per register, alternating the two.
/// `FAST_FLUSH` when the stream is known to fit; `LAST_FAST` when the last
/// symbol of each group may add bits the fast way too.
#[inline(always)]
fn huf_compress1x_body_loop<const UNROLL: i32, const FAST_FLUSH: bool, const LAST_FAST: bool>(
    bit_c: &mut HufCStream<'_>,
    ip: &[u8],
    ct: &[HufCElt],
) {
    // Join to a multiple of UNROLL.
    let mut n = ip.len() as i32;
    let mut rem = n % UNROLL;
    if rem > 0 {
        while rem > 0 {
            n -= 1;
            bit_c.encode_symbol::<false>(ip[n as usize], ct, 0);
            rem -= 1;
        }
        bit_c.flush_bits::<FAST_FLUSH>();
    }
    debug_assert!(n % UNROLL == 0);

    // Join to a multiple of 2 * UNROLL.
    if n % (2 * UNROLL) != 0 {
        for u in 1..UNROLL {
            bit_c.encode_symbol::<true>(ip[(n - u) as usize], ct, 0);
        }
        bit_c.encode_symbol::<LAST_FAST>(ip[(n - UNROLL) as usize], ct, 0);
        bit_c.flush_bits::<FAST_FLUSH>();
        n -= UNROLL;
    }
    debug_assert!(n % (2 * UNROLL) == 0);

    while n > 0 {
        // UNROLL symbols into register 0.
        for u in 1..UNROLL {
            bit_c.encode_symbol::<true>(ip[(n - u) as usize], ct, 0);
        }
        bit_c.encode_symbol::<LAST_FAST>(ip[(n - UNROLL) as usize], ct, 0);
        bit_c.flush_bits::<FAST_FLUSH>();
        // UNROLL symbols into register 1, which starts filling without
        // waiting for register 0.
        bit_c.zero_index1();
        for u in 1..UNROLL {
            bit_c.encode_symbol::<true>(ip[(n - UNROLL - u) as usize], ct, 1);
        }
        bit_c.encode_symbol::<LAST_FAST>(ip[(n - UNROLL - UNROLL) as usize], ct, 1);
        // Register 1 into register 0.
        bit_c.merge_index1();
        bit_c.flush_bits::<FAST_FLUSH>();
        n -= 2 * UNROLL;
    }
    debug_assert!(n == 0);
}

/// `HUF_tightCompressBound`: an upper bound of the output, with 8 bytes for
/// the flushes to write past it. With that much room, the stream is not
/// checked.
fn huf_tight_compress_bound(src_size: usize, table_log: usize) -> usize {
    ((src_size * table_log) >> 3) + 8
}

/// `HUF_compress1X_usingCTable_internal_body`, as on 64-bit machines.
fn huf_compress1x_using_ctable_internal(dst: &mut [u8], src: &[u8], ctable: &HufCTable) -> usize {
    let table_log = u32::from(huf_read_ctable_header(ctable).table_log);
    let ct = &ctable[1..];
    let dst_size = dst.len();

    if dst_size < 8 {
        // Not enough room to compress.
        return 0;
    }
    let Ok(mut bit_c) = HufCStream::new(dst) else {
        return 0;
    };

    if dst_size < huf_tight_compress_bound(src.len(), table_log as usize) || table_log > 11 {
        huf_compress1x_body_loop::<4, false, false>(&mut bit_c, src, ct);
    } else {
        match table_log {
            11 => huf_compress1x_body_loop::<5, true, false>(&mut bit_c, src, ct),
            10 => huf_compress1x_body_loop::<5, true, true>(&mut bit_c, src, ct),
            9 => huf_compress1x_body_loop::<6, true, false>(&mut bit_c, src, ct),
            8 => huf_compress1x_body_loop::<7, true, false>(&mut bit_c, src, ct),
            7 => huf_compress1x_body_loop::<8, true, false>(&mut bit_c, src, ct),
            _ => huf_compress1x_body_loop::<9, true, true>(&mut bit_c, src, ct),
        }
    }
    debug_assert!(bit_c.ptr <= bit_c.end_ptr);

    bit_c.close()
}

/// `HUF_compress1X_usingCTable`: one stream. Returns the size, or 0 if it
/// does not fit. The flags change nothing in the port.
pub(crate) fn huf_compress1x_using_ctable(
    dst: &mut [u8],
    src: &[u8],
    ctable: &HufCTable,
    _flags: i32,
) -> usize {
    huf_compress1x_using_ctable_internal(dst, src, ctable)
}

/// `HUF_compress4X_usingCTable_internal`: four streams, after a jump table
/// of three 16-bit sizes. Returns the size, or 0 if it does not fit or
/// cannot save anything.
fn huf_compress4x_using_ctable_internal(dst: &mut [u8], src: &[u8], ctable: &HufCTable) -> usize {
    let src_size = src.len();
    // The first three segments.
    let segment_size = src_size.div_ceil(4);
    let dst_size = dst.len();

    if dst_size < 6 + 1 + 1 + 1 + 8 {
        // The least room to compress in.
        return 0;
    }
    if src_size < 12 {
        // Too small to save anything.
        return 0;
    }
    let mut op = 6; // the jump table

    let mut ip = 0;
    for jump in 0..3 {
        let c_size = huf_compress1x_using_ctable_internal(
            &mut dst[op..],
            &src[ip..ip + segment_size],
            ctable,
        );
        if c_size == 0 || c_size > 65535 {
            return 0;
        }
        write_le16(dst, 2 * jump, c_size as u16);
        op += c_size;
        ip += segment_size;
    }

    debug_assert!(ip <= src_size);
    let c_size = huf_compress1x_using_ctable_internal(&mut dst[op..], &src[ip..], ctable);
    if c_size == 0 || c_size > 65535 {
        return 0;
    }
    op += c_size;

    op
}

/// `HUF_compress4X_usingCTable`
pub(crate) fn huf_compress4x_using_ctable(
    dst: &mut [u8],
    src: &[u8],
    ctable: &HufCTable,
    _flags: i32,
) -> usize {
    huf_compress4x_using_ctable_internal(dst, src, ctable)
}

/// `HUF_nbStreams_e`
#[derive(Clone, Copy, PartialEq, Eq)]
enum HufNbStreams {
    SingleStream,
    FourStreams,
}

/// `HUF_compressCTable_internal`: the streams, after the `op` bytes of
/// `dst` already written. Returns the whole size, or 0 if that saves less
/// than 2 bytes over `src`.
fn huf_compress_ctable_internal(
    dst: &mut [u8],
    op: usize,
    src: &[u8],
    nb_streams: HufNbStreams,
    ctable: &HufCTable,
) -> usize {
    let c_size = match nb_streams {
        HufNbStreams::SingleStream => {
            huf_compress1x_using_ctable_internal(&mut dst[op..], src, ctable)
        }
        HufNbStreams::FourStreams => {
            huf_compress4x_using_ctable_internal(&mut dst[op..], src, ctable)
        }
    };
    if c_size == 0 {
        // Not compressible.
        return 0;
    }
    let op = op + c_size;
    // Check that it compresses.
    if op >= src.len() - 1 {
        return 0;
    }
    op
}

/// `SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE`
const SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE: usize = 4096;
/// `SUSPECT_INCOMPRESSIBLE_SAMPLE_RATIO`
const SUSPECT_INCOMPRESSIBLE_SAMPLE_RATIO: usize = 10;

/// `HUF_cardinality`: how many symbols are present.
pub(crate) fn huf_cardinality(count: &[u32], max_symbol_value: u32) -> u32 {
    count[..=max_symbol_value as usize]
        .iter()
        .filter(|&&c| c != 0)
        .count() as u32
}

/// `HUF_minTableLog`: the shortest codes for that many symbols.
pub(crate) fn huf_min_table_log(symbol_cardinality: u32) -> u32 {
    highbit32(symbol_cardinality) + 1
}

/// `HUF_optimalTableLog`: the table log to build with. With
/// `HUF_flags_optimalDepth`, each depth is tried, building its table into
/// `table`, until the size grows.
pub(crate) fn huf_optimal_table_log(
    max_table_log: u32,
    src_size: usize,
    max_symbol_value: u32,
    table: &mut HufCTable,
    count: &[u32],
    flags: i32,
) -> u32 {
    debug_assert!(src_size > 1); // not supported: RLE should be used instead

    if flags & HUF_FLAGS_OPTIMAL_DEPTH == 0 {
        // A cheap evaluation, based on FSE.
        return fse_optimal_table_log_internal(max_table_log, src_size, max_symbol_value, 1);
    }

    // libzstd writes the probed descriptions into the rest of its
    // workspace, far larger than any description.
    let mut dst = [0u8; 4096];
    let symbol_cardinality = huf_cardinality(count, max_symbol_value);
    let min_table_log = huf_min_table_log(symbol_cardinality);
    let mut opt_size = usize::MAX - 1;
    let mut opt_log = max_table_log;

    // Search until the size grows.
    let mut opt_log_guess = min_table_log;
    while opt_log_guess <= max_table_log {
        let h_size;
        {
            let Ok(max_bits) = huf_build_ctable_wksp(table, count, max_symbol_value, opt_log_guess)
            else {
                opt_log_guess += 1;
                continue;
            };

            if max_bits < opt_log_guess && opt_log_guess > min_table_log {
                break;
            }

            h_size = huf_write_ctable_wksp(&mut dst, table, max_symbol_value, max_bits);
        }

        let Ok(h_size) = h_size else {
            opt_log_guess += 1;
            continue;
        };

        let new_size = huf_estimate_compressed_size(table, count, max_symbol_value) + h_size;

        if new_size > opt_size.wrapping_add(1) {
            break;
        }

        if new_size < opt_size {
            opt_size = new_size;
            opt_log = opt_log_guess;
        }
        opt_log_guess += 1;
    }
    debug_assert!(opt_log <= HUF_TABLELOG_MAX);
    opt_log
}

/// `HUF_compress_internal`: `src` Huffman-compressed into `dst`, with a
/// table description unless the previous table is used again. Returns the
/// size, 1 for a single repeated symbol (written alone), or 0 when it does
/// not compress. `old_huf_table` and `repeat` are the previous table and
/// whether it may be used; the new table, when there is one, replaces it.
#[allow(clippy::too_many_arguments)]
fn huf_compress_internal(
    dst: &mut [u8],
    src: &[u8],
    mut max_symbol_value: u32,
    mut huff_log: u32,
    nb_streams: HufNbStreams,
    mut old_huf_table: Option<&mut HufCTable>,
    mut repeat: Option<&mut HufRepeat>,
    flags: i32,
) -> Result<usize> {
    let src_size = src.len();
    let dst_size = dst.len();
    let mut count = [0u32; HUF_SYMBOLVALUE_MAX as usize + 1];
    let mut table: HufCTable = [0; HUF_CTABLE_SIZE];
    let mut hist_wksp = [0u32; HIST_WKSP_SIZE_U32];
    let mut op = 0;

    // Checks and initialization.
    if src_size == 0 {
        // Uncompressed.
        return Ok(0);
    }
    if dst_size == 0 {
        // Nothing fits.
        return Ok(0);
    }
    if src_size > HUF_BLOCKSIZE_MAX {
        // The block size limit.
        return error!(SrcSizeWrong);
    }
    if huff_log > HUF_TABLELOG_MAX {
        return error!(TableLogTooLarge);
    }
    if max_symbol_value > HUF_SYMBOLVALUE_MAX {
        return error!(MaxSymbolValueTooLarge);
    }
    if max_symbol_value == 0 {
        max_symbol_value = HUF_SYMBOLVALUE_MAX;
    }
    if huff_log == 0 {
        huff_log = HUF_TABLELOG_DEFAULT;
    }

    // A heuristic: if the old table is valid, use it for small inputs.
    if flags & HUF_FLAGS_PREFER_REPEAT != 0
        && repeat.as_deref() == Some(&HufRepeat::Valid)
        && let Some(old) = old_huf_table.as_deref()
    {
        return Ok(huf_compress_ctable_internal(dst, op, src, nb_streams, old));
    }

    // When the input is suspected not to compress, sample it first.
    if flags & HUF_FLAGS_SUSPECT_UNCOMPRESSIBLE != 0
        && src_size >= SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE * SUSPECT_INCOMPRESSIBLE_SAMPLE_RATIO
    {
        let mut largest_total = 0;
        {
            let mut max_symbol_value_begin = max_symbol_value;
            let largest_begin = hist_count_simple(
                &mut count,
                &mut max_symbol_value_begin,
                &src[..SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE],
            );
            largest_total += largest_begin as usize;
        }
        {
            let mut max_symbol_value_end = max_symbol_value;
            let largest_end = hist_count_simple(
                &mut count,
                &mut max_symbol_value_end,
                &src[src_size - SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE..],
            );
            largest_total += largest_end as usize;
        }
        if largest_total <= ((2 * SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE) >> 7) + 4 {
            // A heuristic: probably not compressible enough.
            return Ok(0);
        }
    }

    // The symbol statistics.
    {
        let largest = hist_count_wksp(&mut count, &mut max_symbol_value, src, &mut hist_wksp)?;
        if largest == src_size {
            // A single symbol: RLE.
            dst[0] = src[0];
            return Ok(1);
        }
        if largest <= (src_size >> 7) + 4 {
            // A heuristic: probably not compressible enough.
            return Ok(0);
        }
    }

    // Check the previous table.
    if let Some(repeat) = repeat.as_deref_mut()
        && *repeat == HufRepeat::Check
        && let Some(old) = old_huf_table.as_deref()
        && !huf_validate_ctable(old, &count, max_symbol_value)
    {
        *repeat = HufRepeat::None;
    }
    // A heuristic: use the existing table for small inputs.
    if flags & HUF_FLAGS_PREFER_REPEAT != 0
        && repeat.as_deref().is_some_and(|r| *r != HufRepeat::None)
        && let Some(old) = old_huf_table.as_deref()
    {
        return Ok(huf_compress_ctable_internal(dst, op, src, nb_streams, old));
    }

    // The Huffman tree.
    huff_log = huf_optimal_table_log(
        huff_log,
        src_size,
        max_symbol_value,
        &mut table,
        &count,
        flags,
    );
    {
        let max_bits = huf_build_ctable_wksp(&mut table, &count, max_symbol_value, huff_log)?;
        huff_log = max_bits;
    }

    // The table description.
    {
        let h_size = huf_write_ctable_wksp(&mut dst[op..], &table, max_symbol_value, huff_log)?;
        // Is the previous table better?
        if repeat.as_deref().is_some_and(|r| *r != HufRepeat::None)
            && let Some(old) = old_huf_table.as_deref()
        {
            let old_size = huf_estimate_compressed_size(old, &count, max_symbol_value);
            let new_size = huf_estimate_compressed_size(&table, &count, max_symbol_value);
            if old_size <= h_size + new_size || h_size + 12 >= src_size {
                return Ok(huf_compress_ctable_internal(dst, op, src, nb_streams, old));
            }
        }

        // Use the new table.
        if h_size + 12 >= src_size {
            return Ok(0);
        }
        op += h_size;
        if let Some(repeat) = repeat.as_mut() {
            **repeat = HufRepeat::None;
        }
        if let Some(old) = old_huf_table.as_mut() {
            // Save the new table.
            **old = table;
        }
    }
    Ok(huf_compress_ctable_internal(
        dst, op, src, nb_streams, &table,
    ))
}

/// `HUF_compress1X_repeat`: one stream; see [`huf_compress_internal`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn huf_compress1x_repeat(
    dst: &mut [u8],
    src: &[u8],
    max_symbol_value: u32,
    huff_log: u32,
    huf_table: Option<&mut HufCTable>,
    repeat: Option<&mut HufRepeat>,
    flags: i32,
) -> Result<usize> {
    huf_compress_internal(
        dst,
        src,
        max_symbol_value,
        huff_log,
        HufNbStreams::SingleStream,
        huf_table,
        repeat,
        flags,
    )
}

/// `HUF_compress4X_repeat`: four streams; see [`huf_compress_internal`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn huf_compress4x_repeat(
    dst: &mut [u8],
    src: &[u8],
    max_symbol_value: u32,
    huff_log: u32,
    huf_table: Option<&mut HufCTable>,
    repeat: Option<&mut HufRepeat>,
    flags: i32,
) -> Result<usize> {
    huf_compress_internal(
        dst,
        src,
        max_symbol_value,
        huff_log,
        HufNbStreams::FourStreams,
        huf_table,
        repeat,
        flags,
    )
}
