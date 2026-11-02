//! The encoder's shared types: port of the parts of
//! `compress/zstd_compress_internal.h` the port needs so far.

use crate::zstd::common::bits::{highbit32, nb_common_bytes};
use crate::zstd::common::error_private::{Result, error};
use crate::zstd::common::fse::fse_ctable_size_u32;
use crate::zstd::common::mem::{idx, read_le16, read_le32, read_le64};
use crate::zstd::common::zstd_internal::{
    LITBITS, LL_FSE_LOG, MAX_LL, MAX_ML, MAX_OFF, ML_FSE_LOG, OFF_FSE_LOG, REP_START_VALUE,
    ZSTD_BLOCKHEADERSIZE, ZSTD_OPT_NUM, ZSTD_REP_NUM,
};
use crate::zstd::compress::huf_compress::{HUF_CTABLE_SIZE, HufCTable, HufRepeat};
use crate::zstd::compress::zstd_cdict::CDict;

/// `ZSTD_strategy`: how hard the match finder searches, from `Fast` (1) to
/// `Btultra2` (9).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Strategy {
    /// One hash table, one candidate per position.
    Fast = 1,
    /// Two hash tables, of short and long matches.
    Dfast = 2,
    /// The first match of a hash chain or row.
    Greedy = 3,
    /// A match, or a better one at the next position.
    Lazy = 4,
    /// The same, up to two positions on.
    Lazy2 = 5,
    /// `Lazy2` over a binary tree.
    Btlazy2 = 6,
    /// The optimal parser.
    Btopt = 7,
    /// The optimal parser, counting costs more precisely.
    Btultra = 8,
    /// `Btultra`, with a first pass to gather statistics.
    Btultra2 = 9,
}

impl Strategy {
    /// The strategy of libzstd's number for it, 1 to 9.
    pub(crate) fn from_number(number: u32) -> Option<Strategy> {
        Some(match number {
            1 => Strategy::Fast,
            2 => Strategy::Dfast,
            3 => Strategy::Greedy,
            4 => Strategy::Lazy,
            5 => Strategy::Lazy2,
            6 => Strategy::Btlazy2,
            7 => Strategy::Btopt,
            8 => Strategy::Btultra,
            9 => Strategy::Btultra2,
            _ => return None,
        })
    }
}

/// `ZSTD_ParamSwitch_e`: a feature on, off, or left to the library.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParamSwitch {
    /// The library's choice.
    Auto = 0,
    Enable = 1,
    Disable = 2,
}

/// `ZSTD_dictAttachPref_e`: whether a frame compressed with a [`CDict`]
/// uses its tables where they are (attaches it), copies them into the
/// context, or loads its content again.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DictAttachPref {
    /// The library's choice: attached for small inputs (up to 8 to 32 KB,
    /// by strategy) and inputs of unknown size, copied otherwise; loaded
    /// again for large inputs, when the `CDict` was made for a level
    /// (`ZSTD_dictDefaultAttach`).
    #[default]
    DefaultAttach = 0,
    /// Attached, whatever the size (`ZSTD_dictForceAttach`).
    ForceAttach = 1,
    /// Copied, whatever the size (`ZSTD_dictForceCopy`).
    ForceCopy = 2,
    /// Its content loaded again, with the frame's parameters
    /// (`ZSTD_dictForceLoad`).
    ForceLoad = 3,
}

/// `FSE_repeat`: whether a block's FSE table may be used again.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum FseRepeat {
    /// It cannot.
    None = 0,
    /// It can, once checked against the new symbols.
    Check = 1,
    /// It can, and has every symbol.
    Valid = 2,
}

/// `ZSTD_hufCTables_t`
#[derive(Clone)]
pub(crate) struct HufCTables {
    pub(crate) ctable: HufCTable,
    pub(crate) repeat_mode: HufRepeat,
}

/// The words of the offset codes' table: `FSE_CTABLE_SIZE_U32(OffFSELog, MaxOff)`.
pub(crate) const OFFCODE_CTABLE_SIZE: usize = fse_ctable_size_u32(OFF_FSE_LOG, MAX_OFF);
/// The words of the match lengths' table.
pub(crate) const MATCHLENGTH_CTABLE_SIZE: usize = fse_ctable_size_u32(ML_FSE_LOG, MAX_ML);
/// The words of the literal lengths' table.
pub(crate) const LITLENGTH_CTABLE_SIZE: usize = fse_ctable_size_u32(LL_FSE_LOG, MAX_LL);

/// `ZSTD_fseCTables_t`
#[derive(Clone)]
pub(crate) struct FseCTables {
    pub(crate) offcode_ctable: [u32; OFFCODE_CTABLE_SIZE],
    pub(crate) matchlength_ctable: [u32; MATCHLENGTH_CTABLE_SIZE],
    pub(crate) litlength_ctable: [u32; LITLENGTH_CTABLE_SIZE],
    pub(crate) offcode_repeat_mode: FseRepeat,
    pub(crate) matchlength_repeat_mode: FseRepeat,
    pub(crate) litlength_repeat_mode: FseRepeat,
}

/// `ZSTD_entropyCTables_t`: the tables a block was compressed with, which
/// the next block may use again.
#[derive(Clone)]
pub(crate) struct EntropyCTables {
    pub(crate) huf: HufCTables,
    pub(crate) fse: FseCTables,
}

impl EntropyCTables {
    /// Tables filled with `fill`, none of them to be used again. libzstd's
    /// start as whatever its workspace held; nothing reads them before a
    /// block writes them.
    pub(crate) fn filled(fill: u32) -> Box<Self> {
        Box::new(EntropyCTables {
            huf: HufCTables {
                ctable: [(u64::from(fill) << 32) | u64::from(fill); HUF_CTABLE_SIZE],
                repeat_mode: HufRepeat::None,
            },
            fse: FseCTables {
                offcode_ctable: [fill; OFFCODE_CTABLE_SIZE],
                matchlength_ctable: [fill; MATCHLENGTH_CTABLE_SIZE],
                litlength_ctable: [fill; LITLENGTH_CTABLE_SIZE],
                offcode_repeat_mode: FseRepeat::None,
                matchlength_repeat_mode: FseRepeat::None,
                litlength_repeat_mode: FseRepeat::None,
            },
        })
    }
}

/// `SeqDef`: one sequence, as the match finder stores it.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct SeqDef {
    /// The offset plus `ZSTD_REP_NUM`, or the repeat code 1, 2 or 3.
    pub(crate) off_base: u32,
    pub(crate) lit_length: u16,
    /// The match length minus `MINMATCH`.
    pub(crate) ml_base: u16,
}

/// `ZSTD_longLengthType_e`: which length of one sequence is 0x10000 more
/// than its `U16` holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LongLengthType {
    None = 0,
    LiteralLength = 1,
    MatchLength = 2,
}

/// `SeqStore_t`: a block's sequences and literals, and the codes of the
/// sequences' lengths and offsets.
///
/// Differs from libzstd: the buffers are vectors, and the positions their
/// lengths (or, for the literals, `lit_len`), instead of pointers into the
/// context's workspace.
#[derive(Clone)]
pub(crate) struct SeqStore {
    pub(crate) sequences: Vec<SeqDef>,
    /// The literals, `lit_buffer[..lit_len]`, with `WILDCOPY_OVERLENGTH`
    /// bytes more for the copies in pieces of 16 that may run past them.
    lit_buffer: Vec<u8>,
    lit_len: usize,
    pub(crate) ll_code: Vec<u8>,
    pub(crate) ml_code: Vec<u8>,
    pub(crate) of_code: Vec<u8>,
    pub(crate) long_length_type: LongLengthType,
    /// The sequence with the long length.
    pub(crate) long_length_pos: u32,
    /// `maxNbSeq`: the most sequences a block may have, which the
    /// sequences given by the caller are checked against.
    pub(crate) max_nb_seq: usize,
}

/// `ZSTD_LLcode`: the code of a literal length.
pub(crate) fn zstd_ll_code(lit_length: u32) -> u32 {
    const LL_CODE: [u8; 64] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16, 17, 17, 18, 18, 19, 19, 20,
        20, 20, 20, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23,
        24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    ];
    const LL_DELTA_CODE: u32 = 19;
    if lit_length > 63 {
        highbit32(lit_length) + LL_DELTA_CODE
    } else {
        u32::from(LL_CODE[lit_length as usize])
    }
}

/// `ZSTD_MLcode`: the code of a match length, given less `MINMATCH`.
pub(crate) fn zstd_ml_code(ml_base: u32) -> u32 {
    const ML_CODE: [u8; 128] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 32, 33, 33, 34, 34, 35, 35, 36, 36, 36, 36, 37, 37, 37, 37,
        38, 38, 38, 38, 38, 38, 38, 38, 39, 39, 39, 39, 39, 39, 39, 39, 40, 40, 40, 40, 40, 40, 40,
        40, 40, 40, 40, 40, 40, 40, 40, 40, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
        41, 41, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
        42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
    ];
    const ML_DELTA_CODE: u32 = 36;
    if ml_base > 127 {
        highbit32(ml_base) + ML_DELTA_CODE
    } else {
        u32::from(ML_CODE[ml_base as usize])
    }
}

/// `ZSTD_minGain`: how much a compressed block or literals section must
/// save to be kept.
pub(crate) fn zstd_min_gain(src_size: usize, strategy: Strategy) -> usize {
    let min_log = if strategy >= Strategy::Btultra {
        strategy as u32 - 1
    } else {
        6
    };
    (src_size >> min_log) + 2
}

/// `ZSTD_literalsCompressionIsDisabled`, from the parameters it reads.
pub(crate) fn zstd_literals_compression_is_disabled(
    literal_compression_mode: ParamSwitch,
    strategy: Strategy,
    target_length: u32,
) -> bool {
    match literal_compression_mode {
        ParamSwitch::Enable => false,
        ParamSwitch::Disable => true,
        ParamSwitch::Auto => strategy == Strategy::Fast && target_length > 0,
    }
}

// ---------------------------------------------------------------------------
// Parameters

/// `ZSTD_compressionParameters`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct CompressionParameters {
    /// The largest match distance is `1 << window_log`.
    pub(crate) window_log: u32,
    /// The size of the chain or binary tree tables.
    pub(crate) chain_log: u32,
    /// The size of the hash table.
    pub(crate) hash_log: u32,
    /// The number of searches.
    pub(crate) search_log: u32,
    /// The shortest match.
    pub(crate) min_match: u32,
    /// How long a match must be to stop searching (or, for `fast`, the
    /// acceleration).
    pub(crate) target_length: u32,
    pub(crate) strategy: Strategy,
}

/// `ZSTD_frameParameters`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct FrameParameters {
    /// Write the content size in the frame header, when known.
    pub(crate) content_size_flag: bool,
    /// Write a checksum of the content at the end of the frame.
    pub(crate) checksum_flag: bool,
    /// Leave the dictionary ID out of the frame header.
    pub(crate) no_dict_id_flag: bool,
}

/// `ZSTD_WINDOWLOG_MAX` on 64-bit machines.
pub(crate) const ZSTD_WINDOWLOG_MAX: u32 = 31;
/// `ZSTD_HASHLOG_MIN`
pub(crate) const ZSTD_HASHLOG_MIN: u32 = 6;
/// `ZSTD_WINDOW_START_INDEX`: the index of the first byte a fresh context
/// sees, above 0 so that every position is valid.
pub(crate) const ZSTD_WINDOW_START_INDEX: u32 = 2;
/// `ZSTD_DUBT_UNSORTED_MARK`: in the binary tree of `btlazy2`, the second
/// entry of a position inserted but not sorted yet. No index is 1: they
/// start at `ZSTD_WINDOW_START_INDEX`.
pub(crate) const ZSTD_DUBT_UNSORTED_MARK: u32 = 1;
const _: () = assert!(ZSTD_DUBT_UNSORTED_MARK < ZSTD_WINDOW_START_INDEX);
/// `HASH_READ_SIZE`: the bytes the hashes read at a position.
pub(crate) const HASH_READ_SIZE: usize = 8;
/// `kSearchStrength`: how quickly the search speeds up over data without
/// matches.
pub(crate) const K_SEARCH_STRENGTH: u32 = 8;

/// `REPCODE1_TO_OFFBASE`
pub(crate) const REPCODE1_TO_OFFBASE: u32 = 1;

/// `OFFSET_TO_OFFBASE`
#[inline(always)]
pub(crate) fn offset_to_offbase(offset: u32) -> u32 {
    debug_assert!(offset > 0);
    offset + ZSTD_REP_NUM as u32
}

/// `ZSTD_updateRep`: the repeat offsets `rep` after a sequence of offset
/// base `off_base`, whose literal length is 0 if `ll0`.
#[inline(always)]
pub(crate) fn zstd_update_rep(rep: &mut [u32; ZSTD_REP_NUM], off_base: u32, ll0: bool) {
    if off_base > ZSTD_REP_NUM as u32 {
        // A full offset.
        rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = off_base - ZSTD_REP_NUM as u32;
    } else {
        // A repcode.
        let rep_code = off_base - 1 + u32::from(ll0);
        if rep_code > 0 {
            // With repCode 0, no change.
            let current_offset = if rep_code == ZSTD_REP_NUM as u32 {
                rep[0].wrapping_sub(1)
            } else {
                rep[rep_code as usize]
            };
            rep[2] = if rep_code >= 2 { rep[1] } else { rep[2] };
            rep[1] = rep[0];
            rep[0] = current_offset;
        }
    }
}

/// `ZSTD_newRep`: [`zstd_update_rep`] on a copy.
#[inline(always)]
pub(crate) fn zstd_new_rep(
    rep: &[u32; ZSTD_REP_NUM],
    off_base: u32,
    ll0: bool,
) -> [u32; ZSTD_REP_NUM] {
    let mut new_reps = *rep;
    zstd_update_rep(&mut new_reps, off_base, ll0);
    new_reps
}

// ---------------------------------------------------------------------------
// The window and the match state

/// Which buffer a window's segment lies in: the caller's input, the
/// context's own input buffer when streaming with one, or the content of
/// the frame's dictionary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum WindowBuffer {
    /// None yet: the window is new.
    None,
    Input,
    InBuff,
    /// The dictionary's content, loaded into the window or copied in with a
    /// `CDict`'s window: the dictionary given to `CCtx::compress_using_dict`,
    /// the prefix of `CCtx::ref_prefix`, or a `CDict`'s content. In a
    /// `CDict`'s own window, its content.
    Dict,
}

/// The buffers a window's segments can lie in, for one call, and the
/// `CDict` of the frame.
#[derive(Clone, Copy)]
pub(crate) struct Buffers<'a> {
    /// The caller's input.
    pub(crate) input: &'a [u8],
    /// The context's input buffer.
    pub(crate) in_buff: &'a [u8],
    /// The dictionary's content, [`WindowBuffer::Dict`]; empty without one.
    pub(crate) dict: &'a [u8],
    /// The `CDict` the frame was started with, if any: the one its match
    /// state is attached to, when it is ([`MatchState::dict_match_state`]).
    pub(crate) cdict: Option<&'a CDict>,
}

impl<'a> Buffers<'a> {
    /// The caller's input, and the context's input buffer, without a
    /// dictionary.
    pub(crate) fn new(input: &'a [u8], in_buff: &'a [u8]) -> Self {
        Buffers {
            input,
            in_buff,
            dict: &[],
            cdict: None,
        }
    }

    /// The buffer `which` names.
    #[inline(always)]
    pub(crate) fn get(&self, which: WindowBuffer) -> &'a [u8] {
        match which {
            WindowBuffer::None => &[],
            WindowBuffer::Input => self.input,
            WindowBuffer::InBuff => self.in_buff,
            WindowBuffer::Dict => self.dict,
        }
    }

    /// The match state the frame's match state `ms` is attached to
    /// (`ms->dictMatchState`), with the content its window indexes: `None`
    /// without one, or once the input is a window past it.
    #[inline(always)]
    pub(crate) fn dict_match_state(&self, ms: &MatchState) -> Option<DictMatchState<'a>> {
        if !ms.dict_match_state {
            return None;
        }
        // The frame's buffers come with the CDict it is attached to.
        debug_assert!(self.cdict.is_some());
        self.cdict.map(|cdict| DictMatchState {
            ms: &cdict.match_state,
            content: &cdict.content,
        })
    }
}

/// `ms->dictMatchState`: the match state of the `CDict` a frame's match
/// state is attached to, read only, and the content its window indexes.
///
/// Differs from libzstd: there a pointer in the match state. Here the match
/// state only says whether it is attached ([`MatchState::dict_match_state`]),
/// and the `CDict` comes with the buffers of each call ([`Buffers::cdict`]):
/// the match state and the `CDict` are then borrowed apart. It gives the
/// same match state.
///
/// For the `dictMatchState` block compressors: the dictionary's
/// tables are `ms.hash_table`, `ms.chain_table` and `ms.tag_table`, its
/// parameters `ms.c_params` (`fast` and `dfast` tables hold indices tagged
/// with `ZSTD_SHORT_CACHE_TAG_BITS`: see [`zstd_write_tagged_index`]),
/// its window `ms.window`, one segment of [`WindowBuffer::Dict`]: index `i`,
/// from `ms.window.dict_limit` to `ms.window.next_src`, is byte
/// `i - ms.window.base` of `content`. The frame's window starts where the
/// dictionary's ends (its `dict_limit` is at least the dictionary's
/// `next_src`), and its `loaded_dict_end` is its `dict_limit`.
#[derive(Clone, Copy)]
pub(crate) struct DictMatchState<'a> {
    pub(crate) ms: &'a MatchState,
    pub(crate) content: &'a [u8],
}

/// `ZSTD_dictMode_e`, as the const parameter of the block compressors and
/// their searches: where matches are besides the window's prefix. Nowhere
/// (`ZSTD_noDict`), in the window's older segment (`ZSTD_extDict`), or in
/// the attached `CDict`'s match state (`ZSTD_dictMatchState`, a
/// [`DictMatchState`]), whose tables may be laid out for the dedicated
/// dictionary search (`ZSTD_dedicatedDictSearch`).
pub(crate) const ZSTD_NO_DICT: u8 = 0;
pub(crate) const ZSTD_EXT_DICT: u8 = 1;
pub(crate) const ZSTD_DICT_MATCH_STATE: u8 = 2;
pub(crate) const ZSTD_DEDICATED_DICT_SEARCH: u8 = 3;

/// `ZSTD_window_t`: the input seen so far, in two segments. Index `i` of
/// the prefix, from `dict_limit` on, is byte `i - base` of its buffer;
/// index `i` of the older segment (the `extDict`), from `low_limit` to
/// `dict_limit`, is byte `i - dict_base` of its buffer. Below `low_limit`
/// no index is valid.
///
/// Differs from libzstd: positions are indices into buffers instead of
/// pointers. `base` and `dict_base` are the indices of the buffers' first
/// bytes, as libzstd's pointers are the addresses of index 0; they can be
/// negative, as libzstd's can point before the buffer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Window {
    pub(crate) base: i64,
    pub(crate) dict_base: i64,
    /// The buffers the prefix and the older segment lie in.
    pub(crate) buffer: WindowBuffer,
    pub(crate) dict_buffer: WindowBuffer,
    /// The index after the last byte seen; libzstd keeps a pointer, which
    /// can be more than 4 GiB past `base`.
    pub(crate) next_src: i64,
    pub(crate) dict_limit: u32,
    pub(crate) low_limit: u32,
    pub(crate) nb_overflow_corrections: u32,
}

impl Window {
    /// `ZSTD_window_init`: empty, starting at `ZSTD_WINDOW_START_INDEX` so
    /// that every position is valid.
    pub(crate) fn new() -> Self {
        Window {
            base: 0,
            dict_base: 0,
            buffer: WindowBuffer::None,
            dict_buffer: WindowBuffer::None,
            next_src: i64::from(ZSTD_WINDOW_START_INDEX),
            dict_limit: ZSTD_WINDOW_START_INDEX,
            low_limit: ZSTD_WINDOW_START_INDEX,
            nb_overflow_corrections: 0,
        }
    }

    /// The index of byte `position` of the prefix's buffer.
    #[inline(always)]
    pub(crate) fn index(&self, position: usize) -> u32 {
        (position as i64 + self.base) as u32
    }

    /// `ZSTD_window_hasExtDict`
    pub(crate) fn has_ext_dict(&self) -> bool {
        self.low_limit < self.dict_limit
    }

    /// `ZSTD_window_clear`: empty, its indices going on from the end of
    /// the bytes seen so far.
    pub(crate) fn clear(&mut self) {
        let end = self.next_src as u32;
        self.low_limit = end;
        self.dict_limit = end;
    }

    /// `ZSTD_window_isEmpty`: as new.
    pub(crate) fn is_empty(&self) -> bool {
        self.dict_limit == ZSTD_WINDOW_START_INDEX
            && self.low_limit == ZSTD_WINDOW_START_INDEX
            && self.next_src == i64::from(ZSTD_WINDOW_START_INDEX)
    }

    /// `ZSTD_window_update`: the window after `size` bytes at `position` of
    /// `buffer`. Returns whether they follow the bytes before. When they do
    /// not, the prefix becomes the older segment.
    pub(crate) fn update(
        &mut self,
        buffer: WindowBuffer,
        position: usize,
        size: usize,
        force_non_contiguous: bool,
    ) -> bool {
        let mut contiguous = true;
        if size == 0 {
            return contiguous;
        }
        // Do the bytes follow the ones before?
        let next_src_position = self.next_src - self.base;
        if buffer != self.buffer || position as i64 != next_src_position || force_non_contiguous {
            // Not contiguous.
            let distance_from_base = self.next_src;
            debug_assert!(distance_from_base == i64::from(distance_from_base as u32));
            self.low_limit = self.dict_limit;
            self.dict_limit = distance_from_base as u32;
            self.dict_base = self.base;
            self.dict_buffer = self.buffer;
            self.base = distance_from_base - position as i64;
            self.buffer = buffer;
            if self.dict_limit - self.low_limit < HASH_READ_SIZE as u32 {
                // An older segment too small to use.
                self.low_limit = self.dict_limit;
            }
            contiguous = false;
        }
        self.next_src = (position + size) as i64 + self.base;
        // Input over the older segment overwrites it: shrink the segment.
        if self.dict_buffer == buffer {
            let input_start = position as i64 + self.dict_base;
            let input_end = (position + size) as i64 + self.dict_base;
            if input_end > i64::from(self.low_limit) && input_start < i64::from(self.dict_limit) {
                let high_input_idx = input_end;
                let low_limit_max = if high_input_idx > i64::from(self.dict_limit) {
                    self.dict_limit
                } else {
                    high_input_idx as u32
                };
                self.low_limit = low_limit_max;
            }
        }
        contiguous
    }

    /// `ZSTD_window_enforceMaxDist`: makes indices more than `max_dist`
    /// before `block_end_idx` invalid, once past a dictionary that ends at
    /// `loaded_dict_end` (0 for none): a dictionary can be reached whole as
    /// long as its last byte is in the window. Returns whether the window
    /// has moved past it: the caller then drops the dictionary (libzstd's
    /// `*loadedDictEndPtr = 0` and `*dictMatchStatePtr = NULL`).
    ///
    /// `max_dist + loaded_dict_end` is on 32 bits, as in libzstd.
    pub(crate) fn enforce_max_dist(
        &mut self,
        block_end_idx: u32,
        max_dist: u32,
        loaded_dict_end: u32,
    ) -> bool {
        if block_end_idx <= max_dist.wrapping_add(loaded_dict_end) {
            return false;
        }
        let new_low_limit = block_end_idx - max_dist;
        if self.low_limit < new_low_limit {
            self.low_limit = new_low_limit;
        }
        if self.dict_limit < self.low_limit {
            self.dict_limit = self.low_limit;
        }
        // On reaching the window's size, dictionaries are invalid.
        true
    }

    /// `ZSTD_window_canOverflowCorrect`: whether the indices are large
    /// enough to lower them without losing matches.
    fn can_overflow_correct(
        &self,
        cycle_log: u32,
        max_dist: u32,
        loaded_dict_end: u32,
        curr: u32,
    ) -> bool {
        let cycle_size = 1u32 << cycle_log;
        let min_index_to_overflow_correct =
            cycle_size + max_dist.max(cycle_size) + ZSTD_WINDOW_START_INDEX;
        // Back off, so as not to spend too long correcting. If this
        // overflows, it only has to be at least the minimum.
        let adjustment = self.nb_overflow_corrections + 1;
        let adjusted_index = min_index_to_overflow_correct
            .wrapping_mul(adjustment)
            .max(min_index_to_overflow_correct);
        let index_large_enough = curr > adjusted_index;
        // Only early when the dictionary is out of the window already, not
        // to hurt the compression ratio.
        let dictionary_invalidated = curr > max_dist.wrapping_add(loaded_dict_end);
        index_large_enough && dictionary_invalidated
    }

    /// `ZSTD_window_needOverflowCorrection`: whether the indices from
    /// `src` to `src_end` (indices of the prefix) are getting too large.
    pub(crate) fn need_overflow_correction(
        &self,
        cycle_log: u32,
        max_dist: u32,
        loaded_dict_end: u32,
        src: u32,
        src_end: u32,
    ) -> bool {
        if overflow_correct_frequently()
            && self.can_overflow_correct(cycle_log, max_dist, loaded_dict_end, src)
        {
            return true;
        }
        src_end > ZSTD_CURRENT_MAX
    }

    /// `ZSTD_window_correctOverflow`: lowers the indices, keeping their low
    /// `cycle_log` bits and the last `max_dist` of history. Returns the
    /// correction, to subtract from every index stored.
    pub(crate) fn correct_overflow(&mut self, cycle_log: u32, max_dist: u32, src: u32) -> u32 {
        let cycle_size = 1u32 << cycle_log;
        let cycle_mask = cycle_size - 1;
        let curr = src;
        let current_cycle = curr & cycle_mask;
        // Keep newCurrent - maxDist >= ZSTD_WINDOW_START_INDEX.
        let current_cycle_correction = if current_cycle < ZSTD_WINDOW_START_INDEX {
            cycle_size.max(ZSTD_WINDOW_START_INDEX)
        } else {
            0
        };
        let new_current = current_cycle + current_cycle_correction + max_dist.max(cycle_size);
        let correction = curr - new_current;
        debug_assert!(max_dist & (max_dist - 1) == 0);
        debug_assert!(curr & cycle_mask == new_current & cycle_mask);
        debug_assert!(curr > new_current);

        self.base -= i64::from(correction);
        self.dict_base -= i64::from(correction);
        self.next_src -= i64::from(correction);
        if self.low_limit < correction + ZSTD_WINDOW_START_INDEX {
            self.low_limit = ZSTD_WINDOW_START_INDEX;
        } else {
            self.low_limit -= correction;
        }
        if self.dict_limit < correction + ZSTD_WINDOW_START_INDEX {
            self.dict_limit = ZSTD_WINDOW_START_INDEX;
        } else {
            self.dict_limit -= correction;
        }

        // The whole window can still be reached.
        debug_assert!(new_current >= max_dist);
        debug_assert!(new_current - max_dist >= ZSTD_WINDOW_START_INDEX);
        debug_assert!(self.low_limit <= new_current && self.dict_limit <= new_current);

        self.nb_overflow_corrections += 1;
        correction
    }
}

/// `ZSTD_CURRENT_MAX` on 64-bit machines: the largest index before the
/// indices are lowered.
pub(crate) const ZSTD_CURRENT_MAX: u32 = 3500 << 20;
/// `ZSTD_CHUNKSIZE_MAX`: the most input before the indices must be checked
/// again: from the largest index allowed at its start to the largest.
pub(crate) const ZSTD_CHUNKSIZE_MAX: u32 = u32::MAX - ZSTD_CURRENT_MAX;

#[cfg(test)]
thread_local! {
    /// `ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY`, which libzstd sets when
    /// built for fuzzing: lower the indices as soon as possible, for the
    /// tests to reach that code.
    pub(crate) static OVERFLOW_CORRECT_FREQUENTLY: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn overflow_correct_frequently() -> bool {
    OVERFLOW_CORRECT_FREQUENTLY.with(std::cell::Cell::get)
}

#[cfg(not(test))]
#[inline(always)]
fn overflow_correct_frequently() -> bool {
    false
}

/// `ZSTD_reduceTable_internal`: lowers every index of a table by
/// `reducer_value`; those it would take below `ZSTD_WINDOW_START_INDEX`
/// become 0. With `PRESERVE_MARK`, `ZSTD_DUBT_UNSORTED_MARK` stays.
#[inline(always)]
fn zstd_reduce_table_internal<const PRESERVE_MARK: bool>(table: &mut [u32], reducer_value: u32) {
    // Indices below ZSTD_WINDOW_START_INDEX are special.
    let reducer_threshold = reducer_value + ZSTD_WINDOW_START_INDEX;
    for cell in table {
        *cell = if PRESERVE_MARK && *cell == ZSTD_DUBT_UNSORTED_MARK {
            ZSTD_DUBT_UNSORTED_MARK
        } else if *cell < reducer_threshold {
            0
        } else {
            *cell - reducer_value
        };
    }
}

/// `ZSTD_reduceTable`
pub(crate) fn zstd_reduce_table(table: &mut [u32], reducer_value: u32) {
    zstd_reduce_table_internal::<false>(table, reducer_value);
}

/// `ZSTD_reduceTable_btlazy2`: for the binary tree of `btlazy2`, whose
/// unsorted positions stay unsorted.
pub(crate) fn zstd_reduce_table_btlazy2(table: &mut [u32], reducer_value: u32) {
    zstd_reduce_table_internal::<true>(table, reducer_value);
}

/// `ZSTD_ROW_HASH_CACHE_SIZE`: how many positions ahead the row match
/// finder hashes.
pub(crate) const ZSTD_ROW_HASH_CACHE_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// The optimal parser's state

/// `ZSTD_OPT_SIZE`: the entries of the optimal parser's tables.
pub(crate) const ZSTD_OPT_SIZE: usize = ZSTD_OPT_NUM + 3;

/// `ZSTD_match_t`: a match the binary tree found.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct OptMatch {
    /// The offset base, as `ZSTD_storeSeq` takes it.
    pub(crate) off: u32,
    /// The length.
    pub(crate) len: u32,
}

/// `ZSTD_optimal_t`: how the optimal parser reaches a position at best so
/// far: a match, then literals.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct Optimal {
    /// The price from the start of the series to the position.
    pub(crate) price: i32,
    /// The offset base of the match.
    pub(crate) off: u32,
    /// The length of the match.
    pub(crate) mlen: u32,
    /// The literals after the match.
    pub(crate) litlen: u32,
    /// The repeat offsets after the match.
    pub(crate) rep: [u32; ZSTD_REP_NUM],
}

/// `ZSTD_OptPrice_e`: how symbols are priced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum OptPrice {
    /// From the statistics gathered.
    Dynamic,
    /// From fixed costs, for blocks too small for statistics.
    Predef,
}

/// `optState_t`: the optimal parser's statistics, kept from block to block
/// of a frame, and its tables.
pub(crate) struct OptState {
    /// `litFreq`: the frequency of each literal.
    pub(crate) lit_freq: [u32; 1 << LITBITS],
    /// `litLengthFreq`: of each literal length code.
    pub(crate) lit_length_freq: [u32; MAX_LL as usize + 1],
    /// `matchLengthFreq`: of each match length code.
    pub(crate) match_length_freq: [u32; MAX_ML as usize + 1],
    /// `offCodeFreq`: of each offset code.
    pub(crate) off_code_freq: [u32; MAX_OFF as usize + 1],
    /// `matchTable`: the matches found at a position.
    pub(crate) match_table: Vec<OptMatch>,
    /// `priceTable`: how each position of a series is reached at best.
    pub(crate) price_table: Vec<Optimal>,
    /// `litSum`, `litLengthSum`, `matchLengthSum`, `offCodeSum`: the sums
    /// of the frequencies. A `lit_length_sum` of 0 means no statistics yet:
    /// the frame's first block.
    pub(crate) lit_sum: u32,
    pub(crate) lit_length_sum: u32,
    pub(crate) match_length_sum: u32,
    pub(crate) off_code_sum: u32,
    /// The prices of the sums, which the prices of the symbols are taken
    /// from.
    pub(crate) lit_sum_base_price: u32,
    pub(crate) lit_length_sum_base_price: u32,
    pub(crate) match_length_sum_base_price: u32,
    pub(crate) off_code_sum_base_price: u32,
    /// `priceType`
    pub(crate) price_type: OptPrice,
    /// `literalCompressionMode`: how the literals will be compressed, from
    /// the frame's parameters.
    pub(crate) literal_compression_mode: ParamSwitch,
}

impl OptState {
    /// The state of a new context.
    ///
    /// Differs from libzstd: its tables start as whatever its workspace
    /// held. The parser writes every entry it reads in the same series, and
    /// the statistics before reading them, so they start as zeros here.
    pub(crate) fn new() -> Self {
        OptState {
            lit_freq: [0; 1 << LITBITS],
            lit_length_freq: [0; MAX_LL as usize + 1],
            match_length_freq: [0; MAX_ML as usize + 1],
            off_code_freq: [0; MAX_OFF as usize + 1],
            match_table: vec![OptMatch::default(); ZSTD_OPT_SIZE],
            price_table: vec![Optimal::default(); ZSTD_OPT_SIZE],
            lit_sum: 0,
            lit_length_sum: 0,
            match_length_sum: 0,
            off_code_sum: 0,
            lit_sum_base_price: 0,
            lit_length_sum_base_price: 0,
            match_length_sum_base_price: 0,
            off_code_sum_base_price: 0,
            price_type: OptPrice::Dynamic,
            literal_compression_mode: ParamSwitch::Auto,
        }
    }
}

/// `ZSTD_MatchState_t`: what the match finders keep from block to block.
pub(crate) struct MatchState {
    pub(crate) window: Window,
    /// The hash table; for the row match finder, its rows one after
    /// another.
    pub(crate) hash_table: Vec<u32>,
    /// The chain table, or for `dfast` the short hash table; empty for
    /// `fast` and the row match finder.
    pub(crate) chain_table: Vec<u32>,
    pub(crate) next_to_update: u32,
    /// The index after a loaded dictionary, or 0.
    pub(crate) loaded_dict_end: u32,
    /// `lazySkipping`: the lazy strategies, over input without matches,
    /// insert only the positions they search.
    pub(crate) lazy_skipping: bool,
    /// `forceNonContiguous`: whether the next window update starts a new
    /// segment even where the input follows the one before in memory: set
    /// by a dictionary's loading with `deterministicRefPrefix`, cleared by
    /// the update it makes.
    pub(crate) force_non_contiguous: bool,
    pub(crate) c_params: CompressionParameters,

    // The row match finder.
    /// `rowHashLog`: the log of the number of rows.
    pub(crate) row_hash_log: u32,
    /// `tagTable`: a byte for each entry of the hash table. The first of
    /// each row is the row's head; the others are the tags of the row's
    /// entries, the low 8 bits of their hashes.
    pub(crate) tag_table: Vec<u8>,
    /// `hashCache`: the hashes of the next positions to insert, each at
    /// its index modulo the size.
    pub(crate) hash_cache: [u32; ZSTD_ROW_HASH_CACHE_SIZE],
    /// `hashSalt`: mixed into the hashes, new at every frame.
    pub(crate) hash_salt: u64,
    /// `hashSaltEntropy`: the sum of the hashes searched, for the next
    /// salt.
    pub(crate) hash_salt_entropy: u32,

    // The optimal parser.
    /// `hashLog3`: the log of the size of `hash_table3`, 0 for none.
    pub(crate) hash_log3: u32,
    /// `hashTable3`: with a shortest match of 3 bytes, the last position
    /// of each hash of 3 bytes, for the optimal parser.
    pub(crate) hash_table3: Vec<u32>,
    /// `opt`: the optimal parser's state, for `btopt` and up.
    ///
    /// Differs from libzstd: boxed, and taken out while the parser runs, so
    /// that the parser can change it while the match finder changes the
    /// rest of the match state.
    pub(crate) opt: Option<Box<OptState>>,

    // Dictionaries.
    /// `dictMatchState`: whether the match state is attached to a `CDict`'s,
    /// whose tables the `dictMatchState` block compressors search as a
    /// window before this one (see [`Buffers::dict_match_state`]). Dropped
    /// with `loaded_dict_end`, once the input is a window past it.
    pub(crate) dict_match_state: bool,
    /// `dedicatedDictSearch`: for a `CDict`'s match state, whether its
    /// tables are laid out for `ZSTD_dedicatedDictSearch`
    /// (`ZSTD_c_enableDedicatedDictSearch`; see
    /// `zstd_dedicated_dict_search_lazy_load_dictionary`). Never set for a
    /// context's.
    pub(crate) dedicated_dict_search: bool,
}

impl MatchState {
    /// A match state without tables, for `c_params`, until a frame (or a
    /// dictionary) sets them up.
    pub(crate) fn new(c_params: CompressionParameters) -> Self {
        MatchState {
            window: Window::new(),
            hash_table: Vec::new(),
            chain_table: Vec::new(),
            next_to_update: 0,
            loaded_dict_end: 0,
            lazy_skipping: false,
            force_non_contiguous: false,
            c_params,
            row_hash_log: 0,
            tag_table: Vec::new(),
            hash_cache: [0; ZSTD_ROW_HASH_CACHE_SIZE],
            // A new context's salt, before the first frame advances it.
            hash_salt: 0,
            hash_salt_entropy: 0,
            hash_log3: 0,
            hash_table3: Vec::new(),
            opt: None,
            dict_match_state: false,
            dedicated_dict_search: false,
        }
    }

    /// `ZSTD_window_enforceMaxDist` on the match state's window, with its
    /// dictionary, which it drops once past it.
    pub(crate) fn enforce_max_dist(&mut self, block_end_idx: u32, max_dist: u32) {
        if self
            .window
            .enforce_max_dist(block_end_idx, max_dist, self.loaded_dict_end)
        {
            self.loaded_dict_end = 0;
            self.dict_match_state = false;
        }
    }

    /// `ZSTD_checkDictValidity`: drops the dictionary for the whole block
    /// that ends at `block_end_idx` if the window moves past it within the
    /// block (for simplicity), or if the input no longer follows it: the
    /// window has a new segment, and `loaded_dict_end` is no longer its
    /// `dict_limit`.
    ///
    /// `loaded_dict_end + max_dist` is on 32 bits, as in libzstd.
    pub(crate) fn check_dict_validity(&mut self, block_end_idx: u32, max_dist: u32) {
        let loaded_dict_end = self.loaded_dict_end;
        if block_end_idx > loaded_dict_end.wrapping_add(max_dist)
            || loaded_dict_end != self.window.dict_limit
        {
            self.loaded_dict_end = 0;
            self.dict_match_state = false;
        }
    }

    /// `ZSTD_getLowestMatchIndex`: the lowest index a match at `curr` may
    /// reach, in either segment, at most `1 << window_log` back.
    #[inline(always)]
    pub(crate) fn lowest_match_index(&self, curr: u32, window_log: u32) -> u32 {
        let max_distance = 1u32 << window_log;
        let lowest_valid = self.window.low_limit;
        let within_window = if curr.wrapping_sub(lowest_valid) > max_distance {
            curr - max_distance
        } else {
            lowest_valid
        };
        let is_dictionary = self.loaded_dict_end != 0;
        if is_dictionary {
            lowest_valid
        } else {
            within_window
        }
    }

    /// `ZSTD_getLowestPrefixIndex`: the lowest index a match at `curr` may
    /// reach, at most `1 << window_log` back.
    #[inline(always)]
    pub(crate) fn lowest_prefix_index(&self, curr: u32, window_log: u32) -> u32 {
        let max_distance = 1u32 << window_log;
        let lowest_valid = self.window.dict_limit;
        let within_window = if curr.wrapping_sub(lowest_valid) > max_distance {
            curr - max_distance
        } else {
            lowest_valid
        };
        let is_dictionary = self.loaded_dict_end != 0;
        if is_dictionary {
            lowest_valid
        } else {
            within_window
        }
    }
}

/// `ZSTD_compressedBlockState_t`: the tables and repeat offsets a block
/// leaves for the next one.
#[derive(Clone)]
pub(crate) struct CompressedBlockState {
    pub(crate) entropy: Box<EntropyCTables>,
    pub(crate) rep: [u32; ZSTD_REP_NUM],
}

impl CompressedBlockState {
    /// A new state: the tables filled with `fill`, none to be used again,
    /// and the first repeat offsets.
    pub(crate) fn new(fill: u32) -> Self {
        CompressedBlockState {
            entropy: EntropyCTables::filled(fill),
            rep: REP_START_VALUE,
        }
    }

    /// `other` copied in, without a new allocation.
    pub(crate) fn copy_from(&mut self, other: &CompressedBlockState) {
        self.entropy.clone_from(&other.entropy);
        self.rep = other.rep;
    }

    /// `ZSTD_reset_compressedBlockState`: the first repeat offsets, and no
    /// table to use again. The tables stay as they are.
    pub(crate) fn reset(&mut self) {
        self.rep = REP_START_VALUE;
        self.entropy.huf.repeat_mode = HufRepeat::None;
        self.entropy.fse.offcode_repeat_mode = FseRepeat::None;
        self.entropy.fse.matchlength_repeat_mode = FseRepeat::None;
        self.entropy.fse.litlength_repeat_mode = FseRepeat::None;
    }
}

// ---------------------------------------------------------------------------
// Long distance matching

/// `rawSeq`: a match long distance matching found, after its literals.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct RawSeq {
    /// The offset of the match, its distance back; 0 in the sequence
    /// `maybeSplitSequence` returns when the rest of the block is literals.
    pub(crate) offset: u32,
    /// The literals before the match.
    pub(crate) lit_length: u32,
    /// The length of the match, all of it (not less `MINMATCH`).
    pub(crate) match_length: u32,
}

/// `RawSeqStore_t`: the sequences long distance matching found for a
/// block, and how far they have been read.
///
/// Differs from libzstd: the sequences are a vector, `size` its length, the
/// context's `ldmSequences` storage its buffer. libzstd makes a new store
/// over that storage for each block (`kNullRawSeqStore`, then `seq` and
/// `capacity`); the port keeps one in the context and empties it for each
/// block with [`RawSeqStore::reset`]. The default store is
/// `kNullRawSeqStore`: empty, with no room.
#[derive(Clone, Default, Debug)]
pub(crate) struct RawSeqStore {
    /// The sequences, `seq.len()` being libzstd's `size`.
    pub(crate) seq: Vec<RawSeq>,
    /// The index in `seq` where reading stopped: `pos <= size`.
    pub(crate) pos: usize,
    /// Where reading stopped in the sequence at `pos`, from the start of
    /// its literals: up to its literals and its match.
    pub(crate) pos_in_sequence: usize,
    /// The most sequences `seq` may hold.
    pub(crate) capacity: usize,
}

impl RawSeqStore {
    /// `size`: how many sequences there are.
    #[inline(always)]
    pub(crate) fn size(&self) -> usize {
        self.seq.len()
    }

    /// Empty, for the next block, with the same capacity.
    pub(crate) fn reset(&mut self) {
        self.seq.clear();
        self.pos = 0;
        self.pos_in_sequence = 0;
    }
}

/// `ldmParams_t`: the parameters of long distance matching, 0 for those
/// left to `ZSTD_ldm_adjustParameters`.
///
/// Differs from libzstd: `enableLdm` is apart, in the context parameters'
/// `ldm_enable`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct LdmParams {
    /// The log of the hash table's size, in entries.
    pub(crate) hash_log: u32,
    /// The log of the entries in a bucket, at most 8.
    pub(crate) bucket_size_log: u32,
    /// The shortest match.
    pub(crate) min_match_length: u32,
    /// About one position in `1 << hash_rate_log` goes into the table.
    pub(crate) hash_rate_log: u32,
    /// The window of long distance matching: the frame's.
    pub(crate) window_log: u32,
}

/// `ldmEntry_t`: a position in the hash table of long distance matching.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct LdmEntry {
    /// The index of the position, in the window of long distance matching.
    pub(crate) offset: u32,
    /// The top 32 bits of the hash of its `min_match_length` bytes.
    pub(crate) checksum: u32,
}

/// `LDM_BATCH_SIZE`: how many split points the gear hash finds before they
/// are looked up.
pub(crate) const LDM_BATCH_SIZE: usize = 64;

/// `ldmState_t`: what long distance matching keeps from block to block.
///
/// Differs from libzstd: the split points and match candidates of a batch
/// (`splitIndices`, `matchCandidates`) are local to
/// `ZSTD_ldm_generateSequences_internal`, which fills them before it reads
/// them.
pub(crate) struct LdmState {
    /// The window, over the same input as the match state's, apart from it:
    /// it keeps a maximum distance and lowers its indices on its own.
    pub(crate) window: Window,
    /// The buckets, one after another, `1 << bucket_size_log` entries each.
    pub(crate) hash_table: Vec<LdmEntry>,
    /// The index after a loaded dictionary, or 0.
    pub(crate) loaded_dict_end: u32,
    /// For each bucket, the entry to write next.
    pub(crate) bucket_offsets: Vec<u8>,
}

impl LdmState {
    /// No tables, until a frame with long distance matching sets them up.
    pub(crate) fn new() -> Self {
        LdmState {
            window: Window::new(),
            hash_table: Vec::new(),
            loaded_dict_end: 0,
            bucket_offsets: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Rolling hash

/// `ZSTD_ROLL_HASH_CHAR_OFFSET`: added to each byte, so that runs of zeros
/// still change the hash.
const ZSTD_ROLL_HASH_CHAR_OFFSET: u64 = 10;

/// `ZSTD_rollingHash_append`: `hash` with the bytes of `buf` after.
pub(crate) fn zstd_rolling_hash_append(mut hash: u64, buf: &[u8]) -> u64 {
    for &byte in buf {
        hash = hash.wrapping_mul(PRIME8BYTES);
        hash = hash.wrapping_add(u64::from(byte) + ZSTD_ROLL_HASH_CHAR_OFFSET);
    }
    hash
}

/// `ZSTD_rollingHash_compute`: the rolling hash of `buf`.
pub(crate) fn zstd_rolling_hash_compute(buf: &[u8]) -> u64 {
    zstd_rolling_hash_append(0, buf)
}

/// `ZSTD_rollingHash_primePower`: what [`zstd_rolling_hash_rotate`] takes
/// for a hash of `length` bytes (`ZSTD_ipow(prime8bytes, length - 1)`).
pub(crate) fn zstd_rolling_hash_prime_power(length: u32) -> u64 {
    PRIME8BYTES.wrapping_pow(length - 1)
}

/// `ZSTD_rollingHash_rotate`: the hash one byte on, `to_remove` out and
/// `to_add` in.
#[inline(always)]
pub(crate) fn zstd_rolling_hash_rotate(
    mut hash: u64,
    to_remove: u8,
    to_add: u8,
    prime_power: u64,
) -> u64 {
    hash = hash.wrapping_sub(
        (u64::from(to_remove) + ZSTD_ROLL_HASH_CHAR_OFFSET).wrapping_mul(prime_power),
    );
    hash = hash.wrapping_mul(PRIME8BYTES);
    hash.wrapping_add(u64::from(to_add) + ZSTD_ROLL_HASH_CHAR_OFFSET)
}

// ---------------------------------------------------------------------------
// Hashes

/// `MEM_readLE16` on the input, its index masked with `idx`: the compiler
/// then sees that the end of the read does not overflow, which saves a
/// check.
#[inline(always)]
pub(crate) fn mem_read16(src: &[u8], at: usize) -> u16 {
    read_le16(src, idx(at))
}

/// `MEM_readLE32` on the input; see [`mem_read16`].
#[inline(always)]
pub(crate) fn mem_read32(src: &[u8], at: usize) -> u32 {
    read_le32(src, idx(at))
}

/// `MEM_readLE64` on the input; see [`mem_read16`].
#[inline(always)]
pub(crate) fn mem_read64(src: &[u8], at: usize) -> u64 {
    read_le64(src, idx(at))
}

/// `MEM_readLE32` at `at`, or `None` where the 4 bytes are not all in
/// `src`, whatever `at` is.
#[inline(always)]
pub(crate) fn mem_read32_within(src: &[u8], at: usize) -> Option<u32> {
    let bytes: [u8; 4] = src.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// `MEM_readLE64` at `at`, or `None` where the 8 bytes are not all in
/// `src`, whatever `at` is.
#[inline(always)]
pub(crate) fn mem_read64_within(src: &[u8], at: usize) -> Option<u64> {
    let bytes: [u8; 8] = src.get(at..at.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

const PRIME3BYTES: u32 = 506_832_829;
const PRIME4BYTES: u32 = 2_654_435_761;
const PRIME5BYTES: u64 = 889_523_592_379;
const PRIME6BYTES: u64 = 227_718_039_650_203;
const PRIME7BYTES: u64 = 58_295_818_150_454_627;
const PRIME8BYTES: u64 = 0xCF1B_BCDC_B7A5_6463;

/// `ZSTD_hashPtr`: the hash of the `mls` bytes at `at`, `h_bits` long. Reads
/// 4 bytes for `mls` 4 (or less), 8 otherwise.
#[inline(always)]
pub(crate) fn zstd_hash_ptr(src: &[u8], at: usize, h_bits: u32, mls: u32) -> usize {
    debug_assert!(h_bits <= 32);
    (zstd_hash_top(src, at, mls) >> (64 - h_bits)) as usize
}

/// [`zstd_hash_ptr`] of the 8 bytes `u`, read at a position already: the
/// hash of their low `mls` bytes, `h_bits` long.
#[inline(always)]
pub(crate) fn zstd_hash_u64(u: u64, h_bits: u32, mls: u32) -> usize {
    debug_assert!(h_bits <= 32);
    (zstd_hash_top_u64(u, mls) >> (64 - h_bits)) as usize
}

/// The hash of the `mls` bytes at `at` before its shift: the hash `h_bits`
/// long is the top `h_bits` of it.
///
/// Differs from libzstd: `ZSTD_hash4` multiplies on 32 bits and shifts by
/// `32 - h_bits`. Here the 4 bytes are in the top half of a `u64`, where the
/// product has the same 32 bits, so that the hashes of every length shift by
/// `64 - h_bits`, which [`HashTable`] depends on.
#[inline(always)]
fn zstd_hash_top(src: &[u8], at: usize, mls: u32) -> u64 {
    match mls {
        5 => zstd_hash_n::<5>(mem_read64(src, at), PRIME5BYTES),
        6 => zstd_hash_n::<6>(mem_read64(src, at), PRIME6BYTES),
        7 => zstd_hash_n::<7>(mem_read64(src, at), PRIME7BYTES),
        8 => mem_read64(src, at).wrapping_mul(PRIME8BYTES),
        // 4, and anything else
        _ => (u64::from(mem_read32(src, at)) << 32).wrapping_mul(u64::from(PRIME4BYTES)),
    }
}

/// [`zstd_hash_top`] of the 8 bytes `u`, read at a position already: the
/// hash of their low `mls` bytes before its shift.
#[inline(always)]
fn zstd_hash_top_u64(u: u64, mls: u32) -> u64 {
    match mls {
        5 => zstd_hash_n::<5>(u, PRIME5BYTES),
        6 => zstd_hash_n::<6>(u, PRIME6BYTES),
        7 => zstd_hash_n::<7>(u, PRIME7BYTES),
        8 => u.wrapping_mul(PRIME8BYTES),
        // 4, and anything else: the low 4 bytes
        _ => (u << 32).wrapping_mul(u64::from(PRIME4BYTES)),
    }
}

/// `ZSTD_hash5` to `ZSTD_hash7`, before the shift: the low `N` bytes of `u`.
#[inline(always)]
fn zstd_hash_n<const N: u32>(u: u64, prime: u64) -> u64 {
    (u << (64 - 8 * N)).wrapping_mul(prime)
}

/// `ZSTD_hash3Ptr`: the hash of the 3 bytes at `at`, `h` bits long. Reads
/// 4 bytes.
#[inline(always)]
pub(crate) fn zstd_hash3_ptr(src: &[u8], at: usize, h: u32) -> usize {
    debug_assert!((1..=32).contains(&h));
    ((mem_read32(src, at) << (32 - 24)).wrapping_mul(PRIME3BYTES) >> (32 - h)) as usize
}

/// `ZSTD_hashPtrSalted`: [`zstd_hash_ptr`] with `salt` mixed in before the
/// shift, as a `U32`; the 4-byte hash takes the salt's low 32 bits.
///
/// The 4-byte hash is in the top half of [`zstd_hash_top`]'s `u64`, so its
/// salt goes there too: the top 32 bits are then libzstd's `U32`.
#[inline(always)]
pub(crate) fn zstd_hash_ptr_salted(src: &[u8], at: usize, h_bits: u32, mls: u32, salt: u64) -> u32 {
    debug_assert!(h_bits <= 32);
    let salt = match mls {
        5..=8 => salt,
        // 4, and anything else
        _ => u64::from(salt as u32) << 32,
    };
    ((zstd_hash_top(src, at, mls) ^ salt) >> (64 - h_bits)) as u32
}

/// A match finder's hash table of `1 << h_bits` entries, and its hashes.
///
/// Differs from libzstd: the table is cut once to the entries a hash can
/// reach, up to `u64::MAX >> shift`, `shift` being the `64 - h_bits` every
/// hash shifts by. Where the compiler sees how a hash was made, it can then
/// tell that the hash masked with `len - 1` is in bounds and that the mask
/// leaves it as it is, and drops both: indexing costs nothing. A hash kept
/// from one turn of a loop to the next may cost the mask, one `and`,
/// instead of the check.
pub(crate) struct HashTable<'a> {
    table: &'a mut [u32],
    shift: u32,
}

impl<'a> HashTable<'a> {
    /// The first `1 << h_bits` entries of `table`, which has that many.
    #[inline(always)]
    pub(crate) fn new(table: &'a mut [u32], h_bits: u32) -> Self {
        debug_assert!((1..=32).contains(&h_bits));
        let shift = 64 - h_bits;
        let table = &mut table[..=(u64::MAX >> shift) as usize];
        HashTable { table, shift }
    }

    /// `ZSTD_hashPtr`: the hash of the `mls` bytes at `at`.
    #[inline(always)]
    pub(crate) fn hash(&self, src: &[u8], at: usize, mls: u32) -> usize {
        (zstd_hash_top(src, at, mls) >> self.shift) as usize
    }

    /// [`Self::hash`] of the 8 bytes `u`, read at a position already.
    #[inline(always)]
    pub(crate) fn hash_u64(&self, u: u64, mls: u32) -> usize {
        (zstd_hash_top_u64(u, mls) >> self.shift) as usize
    }

    /// The entry of `hash`, one of the table's hashes.
    #[inline(always)]
    pub(crate) fn get(&self, hash: usize) -> u32 {
        self.table[hash & (self.table.len() - 1)]
    }

    /// Sets the entry of `hash`, one of the table's hashes.
    #[inline(always)]
    pub(crate) fn set(&mut self, hash: usize, value: u32) {
        let mask = self.table.len() - 1;
        self.table[hash & mask] = value;
    }
}

// ---------------------------------------------------------------------------
// Short cache

/// `ZSTD_SHORT_CACHE_TAG_BITS`: the low bits of each entry of the hash
/// tables of a `CDict` for `fast` and `dfast` hold a tag, 8 more bits of the
/// position's hash, above them its index. The `dictMatchState` block
/// compressors then read the dictionary's bytes only when the tags match.
/// The hashes of those tables are `ZSTD_SHORT_CACHE_TAG_BITS` longer than
/// the table's log: the entry is at the hash shifted down by the tag's
/// bits. Indices then fit in 24 bits, which bounds the dictionary.
pub(crate) const ZSTD_SHORT_CACHE_TAG_BITS: u32 = 8;
/// `ZSTD_SHORT_CACHE_TAG_MASK`
pub(crate) const ZSTD_SHORT_CACHE_TAG_MASK: u32 = (1 << ZSTD_SHORT_CACHE_TAG_BITS) - 1;

/// `ZSTD_writeTaggedIndex`: `index` and the tag of `hash_and_tag` into
/// the entry of its hash.
#[inline(always)]
pub(crate) fn zstd_write_tagged_index(hash_table: &mut [u32], hash_and_tag: usize, index: u32) {
    let hash = hash_and_tag >> ZSTD_SHORT_CACHE_TAG_BITS;
    let tag = hash_and_tag as u32 & ZSTD_SHORT_CACHE_TAG_MASK;
    debug_assert!(index >> (32 - ZSTD_SHORT_CACHE_TAG_BITS) == 0);
    hash_table[hash] = (index << ZSTD_SHORT_CACHE_TAG_BITS) | tag;
}

/// `ZSTD_comparePackedTags`: whether the tags in the low bits of the two
/// are the same.
#[inline(always)]
pub(crate) fn zstd_compare_packed_tags(packed_tag1: usize, packed_tag2: usize) -> bool {
    let tag1 = packed_tag1 as u32 & ZSTD_SHORT_CACHE_TAG_MASK;
    let tag2 = packed_tag2 as u32 & ZSTD_SHORT_CACHE_TAG_MASK;
    tag1 == tag2
}

/// `ZSTD_count`: how many bytes from `p_in` equal those from `p_match`,
/// stopping at `p_in_limit`. `p_match` is before `p_in`.
#[inline(always)]
pub(crate) fn zstd_count(src: &[u8], p_in: usize, p_match: usize, p_in_limit: usize) -> usize {
    zstd_count_from(src, p_in, src, p_match, p_in_limit)
}

/// `ZSTD_count`, with the match in another buffer, `mbuf`. The match run,
/// as long as the one from `p_in` to `p_in_limit`, must be in `mbuf`.
///
/// Differs from libzstd: the first 8 bytes, where most counts end, are read
/// at the two positions, as in C; past them, the two runs are cut out of
/// their buffers once and compared 8 bytes at a time, then 4, 2 and 1, with
/// no bounds check for each read. `p_in_limit` is never past the end of
/// `src`, so taking the smaller of the two changes nothing, and lets the
/// test of the limit stand for the bounds check on `src`. Cutting the match
/// run is what needs it whole in `mbuf`, where C reads only up to the first
/// difference: every caller's match is before `p_in` in `src`, or in the
/// older segment with the count stopping at its end.
#[inline(always)]
fn zstd_count_from(
    src: &[u8],
    p_in: usize,
    mbuf: &[u8],
    p_match: usize,
    p_in_limit: usize,
) -> usize {
    let p_in_limit = p_in_limit.min(src.len());
    // Masked, so that `p_in + 8` does not overflow; see `idx`.
    let p_in = idx(p_in);
    if p_in + 8 <= p_in_limit {
        let diff = mem_read64(mbuf, p_match) ^ mem_read64(src, p_in);
        if diff != 0 {
            return nb_common_bytes(diff) as usize;
        }
        // The rest of the two runs, as long as each other.
        let input = &src[p_in + 8..p_in_limit];
        let matched = &mbuf[p_match + 8..][..input.len()];
        let (in_words, in_rest) = input.as_chunks::<8>();
        let (m_words, m_rest) = matched.as_chunks::<8>();
        for (i, (a, b)) in in_words.iter().zip(m_words).enumerate() {
            let diff = u64::from_le_bytes(*b) ^ u64::from_le_bytes(*a);
            if diff != 0 {
                return 8 + 8 * i + nb_common_bytes(diff) as usize;
            }
        }
        return 8 + 8 * in_words.len() + zstd_count_end(in_rest, m_rest);
    }
    // Under 8 bytes before the limit.
    if p_in >= p_in_limit {
        return 0;
    }
    let input = &src[p_in..p_in_limit];
    zstd_count_end(input, &mbuf[p_match..][..input.len()])
}

/// The end of `ZSTD_count`, its tests of 4, 2 and 1 bytes: how many leading
/// bytes of `input`, under 8, equal those of `matched`, which is as long.
#[inline(always)]
fn zstd_count_end(mut input: &[u8], mut matched: &[u8]) -> usize {
    debug_assert!(input.len() < 8 && matched.len() == input.len());
    let mut length = 0;
    if input.len() >= 4 && input[..4] == matched[..4] {
        length += 4;
        input = &input[4..];
        matched = &matched[4..];
    }
    if input.len() >= 2 && input[..2] == matched[..2] {
        length += 2;
        input = &input[2..];
        matched = &matched[2..];
    }
    if !input.is_empty() && input[0] == matched[0] {
        length += 1;
    }
    length
}

/// `ZSTD_count_2segments`: the length of a match at `ip` (of `src`, up to
/// `i_end`) with `match_pos` of `mbuf`, which ends at `m_end`, and goes on
/// at `i_start` of `src`: a match in the older segment may run into the
/// prefix.
#[inline(always)]
pub(crate) fn zstd_count_2segments(
    src: &[u8],
    ip: usize,
    mbuf: &[u8],
    match_pos: usize,
    i_end: usize,
    m_end: usize,
    i_start: usize,
) -> usize {
    // libzstd's `ip + (mEnd - match)` goes before `ip` for a match past the
    // segment's end, which counts nothing; so does 0.
    let v_end = (ip + m_end.saturating_sub(match_pos)).min(i_end);
    let match_length = zstd_count_from(src, ip, mbuf, match_pos, v_end);
    if match_pos + match_length != m_end {
        return match_length;
    }
    match_length + zstd_count(src, ip + match_length, i_start, i_end)
}

/// `ZSTD_index_overlap_check`: whether 4 bytes at `rep_index` lie in one
/// segment, before or from `prefix_lowest_index`.
#[inline(always)]
pub(crate) fn zstd_index_overlap_check(prefix_lowest_index: u32, rep_index: u32) -> bool {
    (prefix_lowest_index.wrapping_sub(1)).wrapping_sub(rep_index) >= 3
}

// ---------------------------------------------------------------------------
// Storing sequences

impl SeqStore {
    /// An empty store, for a block of up to `block_size` bytes.
    pub(crate) fn with_capacity(block_size: usize, max_nb_seq: usize) -> Self {
        SeqStore {
            sequences: Vec::with_capacity(max_nb_seq),
            lit_buffer: vec![0; block_size + WILDCOPY_OVERLENGTH],
            lit_len: 0,
            ll_code: Vec::with_capacity(max_nb_seq),
            ml_code: Vec::with_capacity(max_nb_seq),
            of_code: Vec::with_capacity(max_nb_seq),
            long_length_type: LongLengthType::None,
            long_length_pos: 0,
            max_nb_seq,
        }
    }

    /// [`SeqStore::with_capacity`] again, keeping the memory it has: a
    /// context reset for a frame, as libzstd's workspace keeps its own.
    /// Only the literals stored are read, so what the buffer held before
    /// does not matter.
    pub(crate) fn reset_for(&mut self, block_size: usize, max_nb_seq: usize) {
        for codes in [&mut self.ll_code, &mut self.ml_code, &mut self.of_code] {
            codes.clear();
            codes.reserve_exact(max_nb_seq);
        }
        self.sequences.clear();
        self.sequences.reserve_exact(max_nb_seq);
        self.lit_buffer.resize(block_size + WILDCOPY_OVERLENGTH, 0);
        self.lit_len = 0;
        self.long_length_type = LongLengthType::None;
        self.long_length_pos = 0;
        self.max_nb_seq = max_nb_seq;
    }

    /// A store of `literals` and room for `nb_seq` sequences, for tests.
    pub(crate) fn with_literals(literals: &[u8], nb_seq: usize) -> Self {
        let mut store = SeqStore::with_capacity(literals.len(), nb_seq);
        store.lit_buffer[..literals.len()].copy_from_slice(literals);
        store.lit_len = literals.len();
        store
    }

    /// The literals stored.
    #[inline(always)]
    pub(crate) fn literals(&self) -> &[u8] {
        &self.lit_buffer[..self.lit_len]
    }

    /// `ZSTD_resetSeqStore`
    pub(crate) fn reset(&mut self) {
        self.sequences.clear();
        self.lit_len = 0;
        self.long_length_type = LongLengthType::None;
    }

    /// `ZSTD_storeSeq`: a sequence and its `lit_length` literals, at
    /// `literals` in `src`.
    ///
    /// As libzstd, the literals are copied in pieces of 16 bytes when the
    /// source has 32 bytes more (libzstd counts them to the block's end,
    /// the port to its buffer's): the bytes past them land in the store's
    /// margin, where the next literals go.
    #[inline(always)]
    pub(crate) fn store_seq(
        &mut self,
        src: &[u8],
        literals: usize,
        lit_length: usize,
        off_base: u32,
        match_length: usize,
    ) {
        let lit_end = literals + lit_length;
        let op = self.lit_len;
        if lit_end + WILDCOPY_OVERLENGTH <= src.len() {
            // The common case: literals are likely short.
            copy16(&mut self.lit_buffer, op, src, literals);
            if lit_length > 16 {
                wildcopy(
                    &mut self.lit_buffer,
                    op + 16,
                    src,
                    literals + 16,
                    lit_length - 16,
                );
            }
        } else {
            // ZSTD_safecopyLiterals
            self.lit_buffer[op..op + lit_length].copy_from_slice(&src[literals..lit_end]);
        }
        self.lit_len += lit_length;
        self.store_seq_only(lit_length, off_base, match_length);
    }

    /// `ZSTD_storeSeqOnly`: a sequence, its literals already stored.
    #[inline(always)]
    pub(crate) fn store_seq_only(&mut self, lit_length: usize, off_base: u32, match_length: usize) {
        debug_assert!(lit_length <= crate::zstd::common::zstd_internal::ZSTD_BLOCKSIZE_MAX);
        if lit_length > 0xFFFF {
            // A block has at most one long length.
            debug_assert!(self.long_length_type == LongLengthType::None);
            self.long_length_type = LongLengthType::LiteralLength;
            self.long_length_pos = self.sequences.len() as u32;
        }
        debug_assert!(match_length >= crate::zstd::common::zstd_internal::MINMATCH as usize);
        let ml_base = match_length - crate::zstd::common::zstd_internal::MINMATCH as usize;
        if ml_base > 0xFFFF {
            debug_assert!(self.long_length_type == LongLengthType::None);
            self.long_length_type = LongLengthType::MatchLength;
            self.long_length_pos = self.sequences.len() as u32;
        }
        self.sequences.push(SeqDef {
            off_base,
            lit_length: lit_length as u16,
            ml_base: ml_base as u16,
        });
    }

    /// `ZSTD_storeLastLiterals`
    pub(crate) fn store_last_literals(&mut self, src: &[u8], anchor: usize, last_ll_size: usize) {
        let op = self.lit_len;
        self.lit_buffer[op..op + last_ll_size].copy_from_slice(&src[anchor..anchor + last_ll_size]);
        self.lit_len += last_ll_size;
    }

    /// `ZSTD_storeSeq`, for a sequence the caller gives: its `lit_length`
    /// literals at `literals` in `src`, which must lie in it. The lengths
    /// are taken as libzstd's arithmetic takes them, without the checks of
    /// [`SeqStore::store_seq`] that a match finder's sequences make sense:
    /// a match length under `MINMATCH` wraps around to a long one, and of
    /// several long lengths in a block the last is marked.
    pub(crate) fn store_external_seq(
        &mut self,
        src: &[u8],
        literals: usize,
        lit_length: u32,
        off_base: u32,
        match_length: u32,
    ) {
        let lit_length_usize = lit_length as usize;
        let lit_end = literals + lit_length_usize;
        let op = self.lit_len;
        if lit_end + WILDCOPY_OVERLENGTH <= src.len() {
            copy16(&mut self.lit_buffer, op, src, literals);
            if lit_length_usize > 16 {
                wildcopy(
                    &mut self.lit_buffer,
                    op + 16,
                    src,
                    literals + 16,
                    lit_length_usize - 16,
                );
            }
        } else {
            self.lit_buffer[op..op + lit_length_usize].copy_from_slice(&src[literals..lit_end]);
        }
        self.lit_len += lit_length_usize;
        self.push_external_seq(lit_length, off_base, match_length);
    }

    /// `ZSTD_storeSeqOnly`, for a sequence the caller gives, its literals
    /// elsewhere: the lengths taken as [`SeqStore::store_external_seq`]
    /// takes them.
    pub(crate) fn push_external_seq(&mut self, lit_length: u32, off_base: u32, match_length: u32) {
        if lit_length > 0xFFFF {
            self.long_length_type = LongLengthType::LiteralLength;
            self.long_length_pos = self.sequences.len() as u32;
        }
        // libzstd's `size_t` subtraction: under MINMATCH, it wraps around
        // to a length past 0xFFFF.
        let ml_base = (match_length as usize)
            .wrapping_sub(crate::zstd::common::zstd_internal::MINMATCH as usize);
        if ml_base > 0xFFFF {
            self.long_length_type = LongLengthType::MatchLength;
            self.long_length_pos = self.sequences.len() as u32;
        }
        self.sequences.push(SeqDef {
            off_base,
            lit_length: lit_length as u16,
            ml_base: ml_base as u16,
        });
    }
}

/// A run of a block's sequences and their literals, as positions in its
/// store: the whole store, or a chunk of it, as `ZSTD_deriveSeqStoreChunk`
/// derives it (a `SeqStore_t` whose pointers point into the block's).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct SeqStoreChunk {
    /// The sequences: `seq_start..seq_end` of the store's.
    pub(crate) seq_start: usize,
    pub(crate) seq_end: usize,
    /// The literals: `lit_start..lit_end` of the store's.
    pub(crate) lit_start: usize,
    pub(crate) lit_end: usize,
    pub(crate) long_length_type: LongLengthType,
    /// The sequence with the long length, counted from `seq_start`.
    pub(crate) long_length_pos: u32,
}

/// The sequences of a [`SeqStoreChunk`], their literals and their codes:
/// what the entropy coding reads, and the codes it writes.
pub(crate) struct SeqStoreView<'a> {
    pub(crate) sequences: &'a [SeqDef],
    pub(crate) literals: &'a [u8],
    pub(crate) ll_code: &'a mut [u8],
    pub(crate) ml_code: &'a mut [u8],
    pub(crate) of_code: &'a mut [u8],
    pub(crate) long_length_type: LongLengthType,
    pub(crate) long_length_pos: u32,
}

impl SeqStore {
    /// The whole store, as a chunk.
    pub(crate) fn whole(&self) -> SeqStoreChunk {
        SeqStoreChunk {
            seq_start: 0,
            seq_end: self.sequences.len(),
            lit_start: 0,
            lit_end: self.lit_len,
            long_length_type: self.long_length_type,
            long_length_pos: self.long_length_pos,
        }
    }

    /// The sequences, literals and codes of `chunk`. The codes are those
    /// last written there, or 0: `ZSTD_seqToCodes` writes them before they
    /// are read.
    pub(crate) fn view(&mut self, chunk: &SeqStoreChunk) -> SeqStoreView<'_> {
        let nb_seq = self.sequences.len();
        self.ll_code.resize(nb_seq, 0);
        self.ml_code.resize(nb_seq, 0);
        self.of_code.resize(nb_seq, 0);
        let seqs = chunk.seq_start..chunk.seq_end;
        SeqStoreView {
            sequences: &self.sequences[seqs.clone()],
            literals: &self.lit_buffer[chunk.lit_start..chunk.lit_end],
            ll_code: &mut self.ll_code[seqs.clone()],
            ml_code: &mut self.ml_code[seqs.clone()],
            of_code: &mut self.of_code[seqs],
            long_length_type: chunk.long_length_type,
            long_length_pos: chunk.long_length_pos,
        }
    }
}

/// `ZSTD_SequenceLength`: the lengths of a sequence, as it decodes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SequenceLength {
    pub(crate) lit_length: u32,
    pub(crate) match_length: u32,
}

/// `ZSTD_getSequenceLength`: the lengths of the sequence `idx` of `seqs`,
/// with the 0x10000 more of the one with a long length.
pub(crate) fn zstd_get_sequence_length(seqs: &SeqStoreView<'_>, idx: usize) -> SequenceLength {
    let seq = &seqs.sequences[idx];
    let mut seq_len = SequenceLength {
        lit_length: u32::from(seq.lit_length),
        match_length: u32::from(seq.ml_base) + crate::zstd::common::zstd_internal::MINMATCH,
    };
    if seqs.long_length_pos as usize == idx {
        match seqs.long_length_type {
            LongLengthType::LiteralLength => seq_len.lit_length += 0x10000,
            LongLengthType::MatchLength => seq_len.match_length += 0x10000,
            LongLengthType::None => {}
        }
    }
    seq_len
}

/// `WILDCOPY_OVERLENGTH`: how far past their end copies in pieces may
/// write.
pub(crate) const WILDCOPY_OVERLENGTH: usize = 32;

/// `ZSTD_copy16`
#[inline(always)]
fn copy16(dst: &mut [u8], op: usize, src: &[u8], ip: usize) {
    let (op, ip) = (idx(op), idx(ip));
    let mut piece = [0u8; 16];
    piece.copy_from_slice(&src[ip..ip + 16]);
    dst[op..op + 16].copy_from_slice(&piece);
}

/// `ZSTD_wildcopy` with `ZSTD_no_overlap`: `length` bytes and up to 32
/// more, in pieces of 16.
#[inline(always)]
fn wildcopy(dst: &mut [u8], mut op: usize, src: &[u8], mut ip: usize, length: usize) {
    let oend = op + length;
    loop {
        copy16(dst, op, src, ip);
        copy16(dst, op + 16, src, ip + 16);
        op += 32;
        ip += 32;
        if op >= oend {
            break;
        }
    }
}

/// `ZSTD_noCompressBlock`: `src` as a raw block, after its header.
pub(crate) fn zstd_no_compress_block(
    dst: &mut [u8],
    src: &[u8],
    last_block: bool,
) -> Result<usize> {
    let header = u32::from(last_block)
        + ((crate::zstd::common::zstd_internal::BlockType::Raw as u32) << 1)
        + ((src.len() as u32) << 3);
    if src.len() + ZSTD_BLOCKHEADERSIZE > dst.len() {
        return error!(DstSizeTooSmall);
    }
    dst[..3].copy_from_slice(&header.to_le_bytes()[..3]);
    dst[ZSTD_BLOCKHEADERSIZE..ZSTD_BLOCKHEADERSIZE + src.len()].copy_from_slice(src);
    Ok(ZSTD_BLOCKHEADERSIZE + src.len())
}
