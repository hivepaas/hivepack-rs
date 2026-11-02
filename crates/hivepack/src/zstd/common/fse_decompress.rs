//! Building FSE decoding tables and decoding FSE streams: port of
//! `common/fse_decompress.c`.

use super::bits::highbit32;
use super::bitstream::{BitDStatus, BitDStream};
use super::entropy_common::fse_read_ncount;
use super::error_private::{Result, error};
use super::fse::{
    FSE_MAX_SYMBOL_VALUE, FSE_MAX_TABLELOG, FSE_MAX_TABLESIZE, FseDState, FseDTable,
    fse_build_dtable_wksp_size, fse_decompress_wksp_size, fse_dtable_size_u32, fse_tablestep,
};

/// The workspace of `FSE_buildDTable_internal`: `symbolNext`, then `spread`
/// with 8 bytes to spare for its 8-byte writes.
pub(crate) struct FseBuildDTableWksp {
    pub(crate) symbol_next: [u16; FSE_MAX_SYMBOL_VALUE as usize + 1],
    pub(crate) spread: [u8; FSE_MAX_TABLESIZE + 8],
}

impl Default for FseBuildDTableWksp {
    fn default() -> Self {
        FseBuildDTableWksp {
            symbol_next: [0; FSE_MAX_SYMBOL_VALUE as usize + 1],
            spread: [0; FSE_MAX_TABLESIZE + 8],
        }
    }
}

/// `FSE_buildDTable_internal`: builds the decoding table for
/// `normalized_counter`, which must come from [`fse_read_ncount`] (libzstd
/// relies on the counts adding up to the table size, too).
///
/// `wksp_size` is the size in bytes of the workspace libzstd's caller would
/// pass: libzstd refuses tables that do not fit in it.
pub(crate) fn fse_build_dtable_internal<const N: usize>(
    dt: &mut FseDTable<N>,
    normalized_counter: &[i16],
    max_symbol_value: u32,
    table_log: u32,
    wksp: &mut FseBuildDTableWksp,
    wksp_size: usize,
) -> Result<()> {
    let max_sv1 = max_symbol_value + 1;
    let table_size: u32 = 1 << table_log;
    let mut high_threshold = table_size - 1;

    // Sanity checks.
    if fse_build_dtable_wksp_size(table_log, max_symbol_value) > wksp_size {
        return error!(MaxSymbolValueTooLarge);
    }
    if max_symbol_value > FSE_MAX_SYMBOL_VALUE {
        return error!(MaxSymbolValueTooLarge);
    }
    if table_log > FSE_MAX_TABLELOG {
        return error!(TableLogTooLarge);
    }
    // Differs from libzstd: C trusts the caller to pass a table big enough.
    if table_size as usize > N {
        return error!(TableLogTooLarge);
    }

    let table_decode = &mut dt.table;
    let symbol_next = &mut wksp.symbol_next;

    // Init, lay down low-probability symbols.
    {
        dt.table_log = table_log as u16;
        dt.fast_mode = true;
        let large_limit = (1i32 << (table_log - 1)) as i16;
        for s in 0..max_sv1 as usize {
            if normalized_counter[s] == -1 {
                table_decode[high_threshold as usize].symbol = s as u8;
                high_threshold = high_threshold.wrapping_sub(1);
                symbol_next[s] = 1;
            } else {
                if normalized_counter[s] >= large_limit {
                    dt.fast_mode = false;
                }
                symbol_next[s] = normalized_counter[s] as u16;
            }
        }
    }

    // Spread symbols.
    if high_threshold == table_size - 1 {
        let table_mask = (table_size - 1) as usize;
        let step = fse_tablestep(table_size) as usize;
        // First lay down the symbols in order, eight bytes at a time; the
        // spread buffer has 8 bytes to spare for the last write.
        {
            let spread = &mut wksp.spread;
            let mut pos = 0usize;
            for s in 0..max_sv1 as usize {
                let n = normalized_counter[s] as i32;
                spread[pos..pos + 8].fill(s as u8);
                let mut i = 8;
                while i < n {
                    spread[pos + i as usize..pos + i as usize + 8].fill(s as u8);
                    i += 8;
                }
                pos += n as usize;
            }
        }
        // Then spread those positions across the table, two at a time.
        {
            let mut position = 0usize;
            let unroll = 2;
            debug_assert!(table_size.is_multiple_of(unroll));
            let mut s = 0usize;
            while s < table_size as usize {
                for u in 0..unroll as usize {
                    let u_position = (position + u * step) & table_mask;
                    table_decode[u_position].symbol = wksp.spread[s + u];
                }
                position = (position + unroll as usize * step) & table_mask;
                s += unroll as usize;
            }
            debug_assert!(position == 0);
        }
    } else {
        let table_mask = table_size - 1;
        let step = fse_tablestep(table_size);
        let mut position: u32 = 0;
        for s in 0..max_sv1 as usize {
            let mut i = 0;
            while i < i32::from(normalized_counter[s]) {
                table_decode[position as usize].symbol = s as u8;
                position = (position + step) & table_mask;
                while position > high_threshold {
                    // The low-probability area.
                    position = (position + step) & table_mask;
                }
                i += 1;
            }
        }
        if position != 0 {
            // Every cell must be reached once, or the counts are wrong.
            return error!(Generic);
        }
    }

    // Build the decoding table.
    for u in 0..table_size as usize {
        let symbol = usize::from(table_decode[u].symbol);
        let next_state = u32::from(symbol_next[symbol]);
        symbol_next[symbol] = symbol_next[symbol].wrapping_add(1);
        let nb_bits = (table_log - highbit32(next_state)) as u8;
        table_decode[u].nb_bits = nb_bits;
        table_decode[u].new_state = ((next_state << nb_bits) - table_size) as u16;
    }

    Ok(())
}

/// `FSE_decompress_usingDTable_generic`: decodes `c_src` into `dst`, whose
/// length is the capacity. Returns the number of symbols decoded.
fn fse_decompress_using_dtable_generic<const N: usize, const FAST: bool>(
    dst: &mut [u8],
    c_src: &[u8],
    dt: &FseDTable<N>,
) -> Result<usize> {
    let omax = dst.len();
    let mut op = 0usize;

    let mut bit_d = BitDStream::new(c_src)?;
    let mut state1 = FseDState::new(&mut bit_d, dt);
    let mut state2 = FseDState::new(&mut bit_d, dt);

    if bit_d.reload() == BitDStatus::Overflow {
        return error!(CorruptionDetected);
    }

    let get_symbol = |state: &mut FseDState, bit_d: &mut BitDStream<'_>| {
        if FAST {
            state.decode_symbol_fast(dt, bit_d)
        } else {
            state.decode_symbol(dt, bit_d)
        }
    };

    // Four symbols per loop. libzstd reloads between the symbols only when
    // its register is 32 bits; with 64 bits, FSE_MAX_TABLELOG*4+7 bits fit.
    // `&` and not `&&`: the reload runs even when the output is full, as in C.
    while (bit_d.reload() == BitDStatus::Unfinished) & (op + 3 < omax) {
        dst[op] = get_symbol(&mut state1, &mut bit_d);
        dst[op + 1] = get_symbol(&mut state2, &mut bit_d);
        dst[op + 2] = get_symbol(&mut state1, &mut bit_d);
        dst[op + 3] = get_symbol(&mut state2, &mut bit_d);
        op += 4;
    }

    // The tail. The stream ends at exactly BitDStatus::Completed.
    loop {
        if op + 2 > omax {
            return error!(DstSizeTooSmall);
        }
        dst[op] = get_symbol(&mut state1, &mut bit_d);
        op += 1;
        if bit_d.reload() == BitDStatus::Overflow {
            dst[op] = get_symbol(&mut state2, &mut bit_d);
            op += 1;
            break;
        }

        if op + 2 > omax {
            return error!(DstSizeTooSmall);
        }
        dst[op] = get_symbol(&mut state2, &mut bit_d);
        op += 1;
        if bit_d.reload() == BitDStatus::Overflow {
            dst[op] = get_symbol(&mut state1, &mut bit_d);
            op += 1;
            break;
        }
    }

    Ok(op)
}

/// `FSE_DecompressWksp` and the rest of the workspace `FSE_decompress_wksp`
/// carves from it: the counts, a decoding table of up to `N` cells, and the
/// table builder's workspace.
pub(crate) struct FseDecompressWksp<const N: usize> {
    ncount: [i16; FSE_MAX_SYMBOL_VALUE as usize + 1],
    dtable: FseDTable<N>,
    build: FseBuildDTableWksp,
}

impl<const N: usize> Default for FseDecompressWksp<N> {
    fn default() -> Self {
        FseDecompressWksp {
            ncount: [0; FSE_MAX_SYMBOL_VALUE as usize + 1],
            dtable: FseDTable::default(),
            build: FseBuildDTableWksp::default(),
        }
    }
}

/// The size of `FSE_DecompressWksp` in libzstd: the counts.
const FSE_DECOMPRESS_WKSP_NCOUNT_SIZE: usize = 2 * (FSE_MAX_SYMBOL_VALUE as usize + 1);

/// `FSE_decompress_wksp_bmi2`: reads a table description from `c_src`, then
/// decodes the rest of `c_src` with it into `dst`, whose length is the
/// capacity. Tables with a log over `max_log` are refused.
///
/// `wksp_size` is the size in bytes of the workspace libzstd's caller passes:
/// libzstd refuses tables whose workspace would not fit in it, and the port
/// does the same.
pub(crate) fn fse_decompress_wksp<const N: usize>(
    dst: &mut [u8],
    c_src: &[u8],
    max_log: u32,
    wksp: &mut FseDecompressWksp<N>,
    wksp_size: usize,
) -> Result<usize> {
    let mut ip = 0usize;
    let mut table_log = 0u32;
    let mut max_symbol_value = FSE_MAX_SYMBOL_VALUE;

    if wksp_size < FSE_DECOMPRESS_WKSP_NCOUNT_SIZE {
        return error!(Generic);
    }

    // The normal FSE decoding mode.
    {
        let ncount_length = fse_read_ncount(
            &mut wksp.ncount,
            &mut max_symbol_value,
            &mut table_log,
            c_src,
        )?;
        if table_log > max_log {
            return error!(TableLogTooLarge);
        }
        debug_assert!(ncount_length <= c_src.len());
        ip += ncount_length;
    }

    if fse_decompress_wksp_size(table_log, max_symbol_value) > wksp_size {
        return error!(TableLogTooLarge);
    }
    let build_wksp_size =
        wksp_size - FSE_DECOMPRESS_WKSP_NCOUNT_SIZE - fse_dtable_size_u32(table_log) * 4;

    fse_build_dtable_internal(
        &mut wksp.dtable,
        &wksp.ncount,
        max_symbol_value,
        table_log,
        &mut wksp.build,
        build_wksp_size,
    )?;

    // Select the fast mode.
    if wksp.dtable.fast_mode {
        fse_decompress_using_dtable_generic::<N, true>(dst, &c_src[ip..], &wksp.dtable)
    } else {
        fse_decompress_using_dtable_generic::<N, false>(dst, &c_src[ip..], &wksp.dtable)
    }
}
