//! Finite State Entropy: port of `common/fse.h`.

use super::bitstream::{BitCStream, BitDStream};
use super::error_private::{Result, error};

/// `FSE_MAX_MEMORY_USAGE`
pub(crate) const FSE_MAX_MEMORY_USAGE: u32 = 14;
/// `FSE_DEFAULT_MEMORY_USAGE`
pub(crate) const FSE_DEFAULT_MEMORY_USAGE: u32 = 13;
/// `FSE_MAX_SYMBOL_VALUE`
pub(crate) const FSE_MAX_SYMBOL_VALUE: u32 = 255;
/// `FSE_MAX_TABLELOG`
pub(crate) const FSE_MAX_TABLELOG: u32 = FSE_MAX_MEMORY_USAGE - 2;
/// `FSE_MAX_TABLESIZE`
pub(crate) const FSE_MAX_TABLESIZE: usize = 1 << FSE_MAX_TABLELOG;
/// `FSE_DEFAULT_TABLELOG`
pub(crate) const FSE_DEFAULT_TABLELOG: u32 = FSE_DEFAULT_MEMORY_USAGE - 2;
/// `FSE_MIN_TABLELOG`
pub(crate) const FSE_MIN_TABLELOG: u32 = 5;
/// `FSE_TABLELOG_ABSOLUTE_MAX`
pub(crate) const FSE_TABLELOG_ABSOLUTE_MAX: u32 = 15;

/// `FSE_TABLESTEP`
pub(crate) const fn fse_tablestep(table_size: u32) -> u32 {
    (table_size >> 1) + (table_size >> 3) + 3
}

/// `FSE_DTABLE_SIZE_U32`
pub(crate) const fn fse_dtable_size_u32(max_table_log: u32) -> usize {
    1 + (1 << max_table_log)
}

/// `FSE_BUILD_DTABLE_WKSP_SIZE`, in bytes.
pub(crate) const fn fse_build_dtable_wksp_size(max_table_log: u32, max_symbol_value: u32) -> usize {
    2 * (max_symbol_value as usize + 1) + (1 << max_table_log) + 8
}

/// `FSE_BUILD_DTABLE_WKSP_SIZE_U32`
pub(crate) const fn fse_build_dtable_wksp_size_u32(
    max_table_log: u32,
    max_symbol_value: u32,
) -> usize {
    fse_build_dtable_wksp_size(max_table_log, max_symbol_value).div_ceil(4)
}

/// `FSE_DECOMPRESS_WKSP_SIZE_U32`
pub(crate) const fn fse_decompress_wksp_size_u32(
    max_table_log: u32,
    max_symbol_value: u32,
) -> usize {
    fse_dtable_size_u32(max_table_log)
        + 1
        + fse_build_dtable_wksp_size_u32(max_table_log, max_symbol_value)
        + (FSE_MAX_SYMBOL_VALUE as usize + 1) * 2 / 4 // the counts, in U32
        + 1
}

/// `FSE_DECOMPRESS_WKSP_SIZE`, in bytes.
pub(crate) const fn fse_decompress_wksp_size(max_table_log: u32, max_symbol_value: u32) -> usize {
    fse_decompress_wksp_size_u32(max_table_log, max_symbol_value) * 4
}

/// `FSE_decode_t`: one cell of a decoding table.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct FseDecode {
    pub(crate) new_state: u16,
    pub(crate) symbol: u8,
    pub(crate) nb_bits: u8,
}

/// `FSE_DTable`: the header (`FSE_DTableHeader`) and room for `N` cells,
/// the table of a `tableLog` of at most `log2(N)`.
///
/// Differs from libzstd: the cells are typed instead of living in a `U32`
/// array after the header.
#[derive(Clone)]
pub(crate) struct FseDTable<const N: usize> {
    pub(crate) table_log: u16,
    pub(crate) fast_mode: bool,
    pub(crate) table: [FseDecode; N],
}

impl<const N: usize> Default for FseDTable<N> {
    fn default() -> Self {
        FseDTable {
            table_log: 0,
            fast_mode: false,
            table: [FseDecode::default(); N],
        }
    }
}

/// `FSE_DState_t`. The table is passed to each call instead of being kept
/// in the state.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FseDState {
    pub(crate) state: usize,
}

impl FseDState {
    /// `FSE_initDState`
    #[inline(always)]
    pub(crate) fn new<const N: usize>(bit_d: &mut BitDStream<'_>, dt: &FseDTable<N>) -> Self {
        let state = bit_d.read_bits(u32::from(dt.table_log)) as usize;
        bit_d.reload();
        FseDState { state }
    }

    /// `FSE_peekSymbol`
    #[inline(always)]
    pub(crate) fn peek_symbol<const N: usize>(&self, dt: &FseDTable<N>) -> u8 {
        dt.table[self.state].symbol
    }

    /// `FSE_updateState`
    #[inline(always)]
    pub(crate) fn update_state<const N: usize>(
        &mut self,
        dt: &FseDTable<N>,
        bit_d: &mut BitDStream<'_>,
    ) {
        let d_info = dt.table[self.state];
        let low_bits = bit_d.read_bits(u32::from(d_info.nb_bits));
        self.state = usize::from(d_info.new_state) + low_bits as usize;
    }

    /// `FSE_decodeSymbol`
    #[inline(always)]
    pub(crate) fn decode_symbol<const N: usize>(
        &mut self,
        dt: &FseDTable<N>,
        bit_d: &mut BitDStream<'_>,
    ) -> u8 {
        let d_info = dt.table[self.state];
        let low_bits = bit_d.read_bits(u32::from(d_info.nb_bits));
        self.state = usize::from(d_info.new_state) + low_bits as usize;
        d_info.symbol
    }

    /// `FSE_decodeSymbolFast`: only when no symbol has a probability over
    /// 50%, so that every cell reads at least one bit.
    #[inline(always)]
    pub(crate) fn decode_symbol_fast<const N: usize>(
        &mut self,
        dt: &FseDTable<N>,
        bit_d: &mut BitDStream<'_>,
    ) -> u8 {
        let d_info = dt.table[self.state];
        let low_bits = bit_d.read_bits_fast(u32::from(d_info.nb_bits));
        self.state = usize::from(d_info.new_state) + low_bits as usize;
        d_info.symbol
    }

    /// `FSE_endOfDState`
    #[inline(always)]
    pub(crate) fn end_of_dstate(&self) -> bool {
        self.state == 0
    }
}

// ---------------------------------------------------------------------------
// Encoding

/// `FSE_NCOUNTBOUND`: the largest table description.
pub(crate) const FSE_NCOUNTBOUND: usize = 512;

/// `FSE_BLOCKBOUND`: the largest FSE-compressed size of `size` bytes, with
/// a 64-bit register.
pub(crate) const fn fse_blockbound(size: usize) -> usize {
    size + (size >> 7) + 4 + 8
}

/// `FSE_COMPRESSBOUND`
pub(crate) const fn fse_compressbound(size: usize) -> usize {
    FSE_NCOUNTBOUND + fse_blockbound(size)
}

/// `FSE_CTABLE_SIZE_U32`: the words of an `FSE_CTable` for tables up to
/// `max_table_log` and symbols up to `max_symbol_value`.
pub(crate) const fn fse_ctable_size_u32(max_table_log: u32, max_symbol_value: u32) -> usize {
    1 + (1 << (max_table_log - 1)) + (max_symbol_value as usize + 1) * 2
}

// An `FSE_CTable` is an array of `U32` words, laid out as libzstd lays it
// out, since libzstd keeps tables from block to block and reads them back
// through the same layout: a header of two `U16` (the table log and the
// largest symbol), then the state table, `1 << tableLog` `U16`, then from
// word `1 + (1 << (tableLog - 1))` (word 2 for the RLE table of log 0) an
// `FSE_symbolCompressionTransform` of two words per symbol. The `U16` are
// the halves of the words, the low half first, as on the little-endian
// machines where libzstd runs.

/// The `U16` at index `at` of an `FSE_CTable`.
#[inline(always)]
pub(crate) fn ctable_u16(ct: &[u32], at: usize) -> u16 {
    (ct[at / 2] >> (16 * (at % 2))) as u16
}

/// Sets the `U16` at index `at` of an `FSE_CTable`.
#[inline(always)]
pub(crate) fn set_ctable_u16(ct: &mut [u32], at: usize, value: u16) {
    let shift = 16 * (at % 2);
    let word = &mut ct[at / 2];
    *word = (*word & !(0xFFFF << shift)) | (u32::from(value) << shift);
}

/// The word index of the symbol transforms in a table of `table_log`.
#[inline(always)]
pub(crate) const fn symbol_tt_start(table_log: u32) -> usize {
    1 + if table_log > 0 {
        1 << (table_log - 1)
    } else {
        1
    }
}

/// `FSE_symbolCompressionTransform`
#[derive(Clone, Copy, Debug)]
pub(crate) struct FseSymbolTransform {
    pub(crate) delta_find_state: i32,
    pub(crate) delta_nb_bits: u32,
}

/// The transform of `symbol`, from the transforms at word `symbol_tt`.
#[inline(always)]
pub(crate) fn symbol_transform(ct: &[u32], symbol_tt: usize, symbol: u32) -> FseSymbolTransform {
    let at = symbol_tt + 2 * symbol as usize;
    FseSymbolTransform {
        delta_find_state: ct[at] as i32,
        delta_nb_bits: ct[at + 1],
    }
}

/// Sets the transform of `symbol`.
#[inline(always)]
pub(crate) fn set_symbol_transform(
    ct: &mut [u32],
    symbol_tt: usize,
    symbol: u32,
    transform: FseSymbolTransform,
) {
    let at = symbol_tt + 2 * symbol as usize;
    ct[at] = transform.delta_find_state as u32;
    ct[at + 1] = transform.delta_nb_bits;
}

/// The state table an [`FseCState`] reads: the words of an `FSE_CTable`,
/// whose halves are the `U16` states, or the states copied out of them.
pub(crate) trait FseStateTable {
    /// The state at `at`.
    fn state(&self, at: usize) -> u16;
}

impl FseStateTable for [u32] {
    #[inline(always)]
    fn state(&self, at: usize) -> u16 {
        (self[at / 2] >> (16 * (at % 2))) as u16
    }
}

impl FseStateTable for [u16] {
    #[inline(always)]
    fn state(&self, at: usize) -> u16 {
        self[at]
    }
}

/// `FSE_CState_t`: an encoder's state, over the table it encodes with.
///
/// Differs from libzstd: the state table and the symbol transforms are two
/// slices, where libzstd keeps pointers into the table, so that each
/// lookup takes one bounds check. The state table is the table's words
/// from word 1, or with [`FseCState::new2_copied`] a copy of the states.
pub(crate) struct FseCState<'a, S: ?Sized = [u32]> {
    value: i64,
    /// `stateTable`
    states: &'a S,
    /// `symbolTT`: the symbol transforms, two words each.
    transforms: &'a [[u32; 2]],
    state_log: u32,
}

impl<'a> FseCState<'a> {
    /// `FSE_initCState`
    #[inline(always)]
    pub(crate) fn new(ct: &'a [u32]) -> Self {
        let table_log = u32::from(ctable_u16(ct, 0));
        let symbol_tt = symbol_tt_start(table_log);
        FseCState {
            value: 1 << table_log,
            states: ct.get(1..).unwrap_or_default(),
            transforms: ct.get(symbol_tt..).unwrap_or_default().as_chunks().0,
            state_log: table_log,
        }
    }

    /// `FSE_initCState2`: starts with `symbol`, the last one the decoder
    /// will read, at the smallest state that has it, which saves its bits.
    #[inline(always)]
    pub(crate) fn new2(ct: &'a [u32], symbol: u32) -> Self {
        let mut state = FseCState::new(ct);
        state.start_with(symbol);
        state
    }

    /// The word where the symbol transforms start, for [`fse_bit_cost`] and
    /// [`fse_get_max_nb_bits`].
    pub(crate) fn symbol_tt(&self) -> usize {
        symbol_tt_start(self.state_log)
    }
}

impl<'a> FseCState<'a, [u16]> {
    /// [`FseCState::new2`] for a table in an array with room for tables of
    /// up to `2 * S` states and `T` symbols, reading its states from
    /// `states`, where it copies the first `2 * S`. Every symbol encoded
    /// must be under `T`. An error when the table's log is too large for
    /// the array, which a table the encoder built never is.
    ///
    /// Differs from libzstd, which reads the states from the table: from a
    /// copy, each is one load rather than a load and a shift, and with the
    /// lengths fixed the bounds checks compare with constants.
    #[inline(always)]
    pub(crate) fn new2_copied<const S: usize, const T: usize>(
        ct: &'a [u32],
        symbol: u32,
        states: &'a mut [[u16; 2]; S],
    ) -> Result<Self> {
        let table_log = u32::from(ctable_u16(ct, 0));
        let symbol_tt = symbol_tt_start(table_log);
        let Some(words) = ct.get(1..).and_then(|words| words.first_chunk::<S>()) else {
            return error!(Generic);
        };
        let Some(transforms) = ct
            .get(symbol_tt..)
            .and_then(|words| words.as_chunks().0.first_chunk::<T>())
        else {
            return error!(Generic);
        };
        for (pair, &word) in states.iter_mut().zip(words) {
            *pair = [word as u16, (word >> 16) as u16];
        }
        let states: &'a [[u16; 2]; S] = states;
        let mut state = FseCState {
            value: 1 << table_log,
            states: states.as_flattened(),
            transforms,
            state_log: table_log,
        };
        state.start_with(symbol);
        Ok(state)
    }
}

impl<S: ?Sized + FseStateTable> FseCState<'_, S> {
    /// The rest of `FSE_initCState2`, after `FSE_initCState`.
    #[inline(always)]
    fn start_with(&mut self, symbol: u32) {
        let transform = self.transform(symbol);
        let nb_bits_out = transform.delta_nb_bits.wrapping_add(1 << 15) >> 16;
        let value = (nb_bits_out << 16).wrapping_sub(transform.delta_nb_bits);
        self.value = self.next_state(i64::from(value) >> nb_bits_out, transform);
    }

    /// The transform of `symbol`.
    #[inline(always)]
    fn transform(&self, symbol: u32) -> FseSymbolTransform {
        let [delta_find_state, delta_nb_bits] = self.transforms[symbol as usize];
        FseSymbolTransform {
            delta_find_state: delta_find_state as i32,
            delta_nb_bits,
        }
    }

    /// The state table's entry for `base` plus the symbol's offset. The sum
    /// is a state's index, under 2^15, so it is worked out in 32 bits.
    #[inline(always)]
    fn next_state(&self, base: i64, transform: FseSymbolTransform) -> i64 {
        let at = (base as u32).wrapping_add(transform.delta_find_state as u32);
        i64::from(self.states.state(at as usize))
    }

    /// `FSE_encodeSymbol`
    #[inline(always)]
    pub(crate) fn encode_symbol(&mut self, bit_c: &mut BitCStream<'_>, symbol: u32) {
        let transform = self.transform(symbol);
        let nb_bits_out = ((self.value + i64::from(transform.delta_nb_bits)) >> 16) as u32;
        bit_c.add_bits(self.value as u64, nb_bits_out);
        self.value = self.next_state(self.value >> nb_bits_out, transform);
    }

    /// `FSE_flushCState`
    #[inline(always)]
    pub(crate) fn flush(&self, bit_c: &mut BitCStream<'_>) {
        bit_c.add_bits(self.value as u64, self.state_log);
        bit_c.flush_bits();
    }
}

/// `FSE_getMaxNbBits`: about the most bits `symbol` costs, rounded up; for
/// a symbol absent from the table, `tableLog + 1`.
#[inline(always)]
pub(crate) fn fse_get_max_nb_bits(ct: &[u32], symbol_tt: usize, symbol: u32) -> u32 {
    symbol_transform(ct, symbol_tt, symbol)
        .delta_nb_bits
        .wrapping_add((1 << 16) - 1)
        >> 16
}

/// `FSE_bitCost`: about the cost of `symbol`, in bits with `accuracy_log`
/// fractional bits; for a symbol absent from the table, `tableLog + 1`.
#[inline(always)]
pub(crate) fn fse_bit_cost(
    ct: &[u32],
    symbol_tt: usize,
    table_log: u32,
    symbol: u32,
    accuracy_log: u32,
) -> u32 {
    let delta_nb_bits = symbol_transform(ct, symbol_tt, symbol).delta_nb_bits;
    let min_nb_bits = delta_nb_bits >> 16;
    let threshold = (min_nb_bits + 1) << 16;
    debug_assert!(table_log < 16);
    debug_assert!(accuracy_log < 31 - table_log);
    let table_size = 1u32 << table_log;
    let delta_from_threshold = threshold.wrapping_sub(delta_nb_bits.wrapping_add(table_size));
    // A linear interpolation, very approximate.
    let normalized_delta_from_threshold =
        delta_from_threshold.wrapping_shl(accuracy_log) >> table_log;
    let bit_multiplier = 1u32 << accuracy_log;
    ((min_nb_bits + 1) * bit_multiplier).wrapping_sub(normalized_delta_from_threshold)
}
