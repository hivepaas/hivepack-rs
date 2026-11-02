//! The LZMA decoder: port of `lzma/lzma_decoder.c`.
//!
//! liblzma decodes in two modes, and so does the port: a fast one, the
//! Non-resumable mode, when there is input enough for any symbol
//! (`LZMA_IN_REQUIRED`) and room in the dictionary, and a resumable one,
//! which can stop wherever the input or the output runs out. Both read the
//! same bits and write the same bytes. The resumable mode's `switch`,
//! whose `case` labels sit inside the symbol's code so that a call can
//! start again where the last one stopped, is a `match` on the same
//! sequence values.
//!
//! The fast mode decodes the bits of its bittrees, matched literals and
//! reverse bittrees without branches, as liblzma does on x86-64 in inline
//! assembly and elsewhere in C (`rc_c_bit`); the port has the C.
//!
//! The probabilities are one array, in the order of the fields of
//! liblzma's `lzma_lzma1_decoder`, so that a probability tree is an index
//! into it, as liblzma's `probs` is a pointer.

use crate::xz::common::{Ret, VLI_UNKNOWN};
use crate::xz::lz_decoder::{Dict, LzOptions, lz_decoder_memusage};
use crate::xz::lzma_common::*;
use crate::xz::range_decoder::{
    PROB_INIT, Probability, RC_BIT_MODEL_OFFSET, RC_BIT_MODEL_TOTAL, RC_BIT_MODEL_TOTAL_BITS,
    RC_MOVE_BITS, RC_SHIFT_BITS, RC_TOP_VALUE, RangeDecoder,
};

/// Minimum number of input bytes to safely decode one LZMA symbol. The
/// worst case is that we decode 22 bits using probabilities and 26 direct
/// bits. This may decode at maximum 20 bytes of input.
const LZMA_IN_REQUIRED: usize = 20;

/// `sizeof(lzma_lzma1_decoder)` in liblzma on 64-bit systems, which its
/// memory usage counts.
pub(crate) const LZMA1_DECODER_SIZE: u64 = 28_352;

// The sequence: where to continue the decoder loop.
const SEQ_NORMALIZE: u8 = 0;
const SEQ_IS_MATCH: u8 = 1;
const SEQ_LITERAL: u8 = 2;
const SEQ_LITERAL_MATCHED: u8 = 3;
const SEQ_LITERAL_WRITE: u8 = 4;
const SEQ_IS_REP: u8 = 5;
const SEQ_MATCH_LEN_CHOICE: u8 = 6;
const SEQ_MATCH_LEN_CHOICE2: u8 = 7;
const SEQ_MATCH_LEN_BITTREE: u8 = 8;
const SEQ_DIST_SLOT: u8 = 9;
const SEQ_DIST_MODEL: u8 = 10;
const SEQ_DIRECT: u8 = 11;
const SEQ_ALIGN: u8 = 12;
const SEQ_EOPM: u8 = 13;
const SEQ_IS_REP0: u8 = 14;
const SEQ_SHORTREP: u8 = 15;
const SEQ_IS_REP0_LONG: u8 = 16;
const SEQ_IS_REP1: u8 = 17;
const SEQ_IS_REP2: u8 = 18;
const SEQ_REP_LEN_CHOICE: u8 = 19;
const SEQ_REP_LEN_CHOICE2: u8 = 20;
const SEQ_REP_LEN_BITTREE: u8 = 21;
const SEQ_COPY: u8 = 22;

/// `lzma_lzma1_decoder`.
pub(crate) struct LzmaDecoder {
    /// The probabilities.
    p: Box<[Probability; PROBS]>,

    // Decoder state.
    rc: RangeDecoder,
    /// Types of the most recently seen LZMA symbols.
    state: u32,
    rep0: u32,
    rep1: u32,
    rep2: u32,
    rep3: u32,
    /// (1U << pb) - 1
    pos_mask: u32,
    literal_context_bits: u32,
    literal_mask: u32,
    /// Uncompressed size as bytes, or LZMA_VLI_UNKNOWN if end of payload
    /// marker is expected.
    uncompressed_size: u64,
    /// True if end of payload marker (EOPM) is allowed even when
    /// uncompressed_size is known; false if EOPM must not be present.
    /// This is ignored if uncompressed_size == LZMA_VLI_UNKNOWN.
    allow_eopm: bool,

    // State of incomplete symbol.
    /// Position where to continue the decoder loop.
    sequence: u8,
    /// Base of the current probability tree, as an index into `p`.
    probs: usize,
    /// Symbol being decoded. This is also used as an index variable in
    /// bittree decoders: probs[symbol]
    symbol: u32,
    /// Used as a loop termination condition on bittree decoders and
    /// direct bits decoder.
    limit: u32,
    /// Matched literal decoder: 0x100 or 0 to help avoiding branches.
    /// Bittree reverse decoders: Offset of the next bit: 1 << offset
    offset: u32,
    /// If decoding a literal: match byte. If decoding a match: length of
    /// the match.
    len: u32,
}

impl LzmaDecoder {
    /// `lzma_lzma_decoder_create`, before `lzma_decoder_reset`: the
    /// decoder and the dictionary's options.
    pub(crate) fn create(options: &LzmaOptions) -> (LzmaDecoder, LzOptions<'_>) {
        let decoder = LzmaDecoder {
            p: Box::new([PROB_INIT; PROBS]),
            rc: RangeDecoder::new(),
            state: STATE_LIT_LIT,
            rep0: 0,
            rep1: 0,
            rep2: 0,
            rep3: 0,
            pos_mask: 0,
            literal_context_bits: 0,
            literal_mask: 0,
            uncompressed_size: VLI_UNKNOWN,
            allow_eopm: true,
            sequence: SEQ_IS_MATCH,
            probs: 0,
            symbol: 0,
            limit: 0,
            offset: 0,
            len: 0,
        };
        // All dictionary sizes are OK here. LZ decoder will take care of
        // the special cases.
        let lz_options = LzOptions {
            dict_size: options.dict_size as usize,
            preset_dict: options.preset_dict.as_deref(),
        };
        (decoder, lz_options)
    }

    /// `lzma_decoder_uncompressed`.
    pub(crate) fn set_uncompressed(&mut self, uncompressed_size: u64, allow_eopm: bool) {
        self.uncompressed_size = uncompressed_size;
        self.allow_eopm = allow_eopm;
    }

    /// `lzma_decoder_reset`. We assume that lc/lp/pb are valid since they
    /// were successfully decoded with lzma_lzma_decode_properties().
    pub(crate) fn reset(&mut self, options: &LzmaOptions) {
        // Calculate pos_mask. We don't need pos_bits as is for anything.
        self.pos_mask = (1 << options.pb) - 1;

        // Initialize the literal decoder.
        let coders = LITERAL_CODER_SIZE << (options.lc + options.lp);
        self.p[LITERAL..LITERAL + coders].fill(PROB_INIT);
        self.literal_context_bits = options.lc;
        self.literal_mask = literal_mask_calc(options.lc, options.lp);

        // State
        self.state = STATE_LIT_LIT;
        self.rep0 = 0;
        self.rep1 = 0;
        self.rep2 = 0;
        self.rep3 = 0;

        // Range decoder
        self.rc.reset();

        // Bit and bittree decoders
        for i in 0..STATES {
            for j in 0..=self.pos_mask as usize {
                self.p[IS_MATCH + i * POS_STATES_MAX + j] = PROB_INIT;
                self.p[IS_REP0_LONG + i * POS_STATES_MAX + j] = PROB_INIT;
            }
            self.p[IS_REP + i] = PROB_INIT;
            self.p[IS_REP0 + i] = PROB_INIT;
            self.p[IS_REP1 + i] = PROB_INIT;
            self.p[IS_REP2 + i] = PROB_INIT;
        }
        self.p[DIST_SLOT..POS_ALIGN + ALIGN_SIZE as usize].fill(PROB_INIT);

        // Len decoders (also bit/bittree)
        let num_pos_states = 1usize << options.pb;
        for base in [MATCH_LEN_DECODER, REP_LEN_DECODER] {
            self.p[base + LEN_CHOICE] = PROB_INIT;
            self.p[base + LEN_CHOICE2] = PROB_INIT;
            for pos_state in 0..num_pos_states {
                let low = base + LEN_LOW + pos_state * LEN_LOW_SYMBOLS as usize;
                self.p[low..low + LEN_LOW_SYMBOLS as usize].fill(PROB_INIT);
                let mid = base + LEN_MID + pos_state * LEN_MID_SYMBOLS as usize;
                self.p[mid..mid + LEN_MID_SYMBOLS as usize].fill(PROB_INIT);
            }
            self.p[base + LEN_HIGH..base + LEN_DECODER_SIZE].fill(PROB_INIT);
        }

        self.sequence = SEQ_IS_MATCH;
        self.probs = 0;
        self.symbol = 0;
        self.limit = 0;
        self.offset = 0;
        self.len = 0;
    }

    /// `lzma_decode`: decodes from `input[*in_pos..]` into `dict`, up to
    /// its limit.
    pub(crate) fn decode(&mut self, dictptr: &mut Dict, input: &[u8], in_pos: &mut usize) -> Ret {
        // Initialization
        {
            let ret = self.rc.read_init(input, in_pos);
            if ret != Ret::StreamEnd {
                return ret;
            }
        }

        // Variables. Making local copies of often-used variables improves
        // both speed and readability.
        //
        // The dictionary is moved here, buffer and all, and back at the end,
        // as liblzma copies its lzma_dict.
        let mut dict = core::mem::take(dictptr);
        let dict = &mut dict;
        let dict_start = dict.pos;
        // NOTE: Must not copy dict.limit back.
        let dict_limit = dict.limit;

        // Range decoder
        let mut rc = self.rc;
        let mut rc_in_ptr = *in_pos;
        let rc_in_end = input.len();
        let rc_in_fast_end = if rc_in_end - rc_in_ptr <= LZMA_IN_REQUIRED {
            rc_in_ptr
        } else {
            rc_in_end - LZMA_IN_REQUIRED
        };
        let mut rc_bound: u32;

        // State
        let mut state = self.state;
        let mut rep0 = self.rep0;
        let mut rep1 = self.rep1;
        let mut rep2 = self.rep2;
        let mut rep3 = self.rep3;
        let pos_mask = self.pos_mask;

        // These variables are actually needed only if we last time ran out
        // of input in the middle of the decoder loop.
        let mut probs = self.probs;
        let mut symbol = self.symbol;
        let mut limit = self.limit;
        let mut offset = self.offset;
        let mut len = self.len;

        let literal_mask = self.literal_mask;
        let literal_context_bits = self.literal_context_bits;

        // Temporary variables
        let mut pos_state = dict.pos as u32 & pos_mask;

        let mut ret = Ret::Ok;

        // This is true when the next LZMA symbol is allowed to be EOPM.
        // That is, if this is false, then EOPM is considered an invalid
        // symbol and we will return LZMA_DATA_ERROR.
        //
        // EOPM is always required (not just allowed) when the
        // uncompressed size isn't known. When uncompressed size is known,
        // eopm_is_valid may be set to true later.
        let mut eopm_is_valid = self.uncompressed_size == VLI_UNKNOWN;

        // If uncompressed size is known and there is enough output space to
        // decode all the data, limit the available buffer space so that the
        // main loop won't try to decode past the end of the stream.
        let mut might_finish_without_eopm = false;
        if self.uncompressed_size != VLI_UNKNOWN
            && self.uncompressed_size <= (dict.limit - dict.pos) as u64
        {
            dict.limit = dict.pos + self.uncompressed_size as usize;
            might_finish_without_eopm = true;
        }

        let p: &mut [Probability; PROBS] = &mut self.p;

        // `rc_normalize_safe`: read the next input byte if needed, or stop
        // with the sequence `seq` to continue from.
        macro_rules! normalize_safe {
            ($out:lifetime, $seq:expr) => {
                if rc.range < RC_TOP_VALUE {
                    if rc_in_ptr == rc_in_end {
                        self.sequence = $seq;
                        break $out;
                    }
                    rc.range <<= RC_SHIFT_BITS;
                    rc.code = (rc.code << RC_SHIFT_BITS) | u32::from(input[rc_in_ptr]);
                    rc_in_ptr += 1;
                }
            };
        }
        // `rc_if_0_safe`.
        macro_rules! if_0_safe {
            ($out:lifetime, $prob:expr, $seq:expr) => {{
                normalize_safe!($out, $seq);
                rc_bound = (rc.range >> RC_BIT_MODEL_TOTAL_BITS) * u32::from(p[$prob]);
                rc.code < rc_bound
            }};
        }
        // `rc_update_0`.
        macro_rules! update_0 {
            ($prob:expr) => {{
                let at = $prob;
                rc.range = rc_bound;
                p[at] += ((RC_BIT_MODEL_TOTAL - u32::from(p[at])) >> RC_MOVE_BITS) as Probability;
            }};
        }
        // `rc_update_1`.
        macro_rules! update_1 {
            ($prob:expr) => {{
                let at = $prob;
                rc.range -= rc_bound;
                rc.code -= rc_bound;
                p[at] -= p[at] >> RC_MOVE_BITS;
            }};
        }
        // `rc_bit_safe`: a bit into `symbol`.
        macro_rules! bit_safe {
            ($out:lifetime, $prob:expr, $seq:expr, $action0:block, $action1:block) => {{
                let at = $prob;
                if if_0_safe!($out, at, $seq) {
                    update_0!(at);
                    symbol <<= 1;
                    $action0
                } else {
                    update_1!(at);
                    symbol = (symbol << 1) + 1;
                    $action1
                }
            }};
        }

        // The macros of the Non-resumable mode, which reads input without
        // checking that there is some: there is, LZMA_IN_REQUIRED bytes
        // at least.

        // `rc_normalize`.
        macro_rules! normalize {
            () => {
                if rc.range < RC_TOP_VALUE {
                    rc.range <<= RC_SHIFT_BITS;
                    rc.code = (rc.code << RC_SHIFT_BITS) | u32::from(input[rc_in_ptr]);
                    rc_in_ptr += 1;
                }
            };
        }
        // `rc_if_0`.
        macro_rules! if_0 {
            ($prob:expr) => {{
                normalize!();
                rc_bound = (rc.range >> RC_BIT_MODEL_TOTAL_BITS) * u32::from(p[$prob]);
                rc.code < rc_bound
            }};
        }
        // `rc_c_bit`: decodes a bit without branches, with `$mask` the bit
        // in `$action_bit`, then 0 or all ones in `$action_neg`. liblzma
        // has these on x86-64 in assembly, without branches either, and
        // elsewhere in C, as here; the bits and the probabilities are the
        // same as with `rc_if_0`, `rc_update_0` and `rc_update_1`.
        macro_rules! c_bit {
            ($prob:expr, $mask:ident, $action_bit:expr $(, $action_neg:expr)?) => {{
                let at = $prob;
                normalize!();
                let prob = u32::from(p[at]);
                rc_bound = (rc.range >> RC_BIT_MODEL_TOTAL_BITS) * prob;
                // rc_mask = decoded bit
                #[allow(unused_mut)]
                let mut $mask = u32::from(rc.code >= rc_bound);
                $action_bit;
                // rc_mask becomes 0 if bit is 0 and 0xFFFFFFFF if bit is 1:
                $mask = 0u32.wrapping_sub($mask);
                // If bit 0: set rc.range = 0
                rc.range &= $mask;
                rc_bound ^= $mask;
                // If bit 1: rc_bound = 0U - rc_bound
                rc_bound = rc_bound.wrapping_sub($mask);
                rc.range = rc.range.wrapping_add(rc_bound);
                rc_bound &= $mask;
                rc.code = rc.code.wrapping_add(rc_bound);
                $($action_neg;)?
                // If bit 0: all bits are set in rc_mask
                $mask = !$mask & RC_BIT_MODEL_OFFSET;
                p[at] = prob.wrapping_sub(prob.wrapping_add($mask) >> RC_MOVE_BITS) as Probability;
            }};
        }
        // `rc_bittree3`, `rc_bittree6` and `rc_bittree8`: `$bits` bits of
        // a bittree at `$probs` into `symbol`, then `$final_add` added.
        macro_rules! bittree {
            ($probs:expr, $bits:literal, $final_add:expr) => {{
                let probs = $probs;
                symbol = 1;
                for _ in 0..$bits {
                    c_bit!(probs + symbol as usize, mask, symbol = (symbol << 1) + mask);
                }
                symbol = symbol.wrapping_add(($final_add) as u32);
            }};
        }
        // `rc_bittree_rev4`.
        macro_rules! bittree_rev4 {
            ($probs:expr) => {{
                let probs = $probs;
                symbol = 0;
                c_bit!(probs + symbol as usize + 1, mask, symbol += mask);
                c_bit!(probs + symbol as usize + 2, mask, symbol += mask << 1);
                c_bit!(probs + symbol as usize + 4, mask, symbol += mask << 2);
                c_bit!(probs + symbol as usize + 8, mask, symbol += mask << 3);
            }};
        }
        // `rc_bit_add_if_1`.
        macro_rules! bit_add_if_1 {
            ($probs:expr, $dest:ident, $value_to_add_if_1:expr) => {
                c_bit!(
                    $probs + symbol as usize,
                    mask,
                    symbol = (symbol << 1) + mask,
                    $dest = $dest.wrapping_add($value_to_add_if_1 & mask)
                )
            };
        }
        // `rc_matched_literal`.
        macro_rules! matched_literal {
            ($probs:expr, $match_byte:expr) => {{
                let probs = $probs;
                let mut t_match_byte = u32::from($match_byte);
                let mut t_offset: u32 = 0x100;
                symbol = 1;
                for _ in 0..8 {
                    // `decode_with_match_bit`.
                    t_match_byte <<= 1;
                    let t_match_bit = t_match_byte & t_offset;
                    let t_subcoder_index = t_offset + t_match_bit + symbol;
                    c_bit!(
                        probs + t_subcoder_index as usize,
                        mask,
                        symbol = (symbol << 1) + mask,
                        t_offset &= !t_match_bit ^ mask
                    );
                }
            }};
        }
        // `rc_direct`: `$count` bits without probabilities into `$dest`.
        macro_rules! direct {
            ($dest:ident, $count:ident) => {
                loop {
                    $dest = ($dest << 1).wrapping_add(1);
                    normalize!();
                    rc.range >>= 1;
                    rc.code = rc.code.wrapping_sub(rc.range);
                    rc_bound = 0u32.wrapping_sub(rc.code >> 31);
                    $dest = $dest.wrapping_add(rc_bound);
                    rc.code = rc.code.wrapping_add(rc.range & rc_bound);
                    $count -= 1;
                    if $count == 0 {
                        break;
                    }
                }
            };
        }
        // `len_decode_fast`: the length of a match, unrolled.
        macro_rules! len_decode_fast {
            ($target:ident, $ld:expr, $pos_state:expr) => {{
                // liblzma sets symbol to 1 here too, which each bittree
                // does again.
                let ld = $ld;
                if if_0!(ld + LEN_CHOICE) {
                    update_0!(ld + LEN_CHOICE);
                    bittree!(
                        ld + LEN_LOW + $pos_state as usize * LEN_LOW_SYMBOLS as usize,
                        3,
                        MATCH_LEN_MIN.wrapping_sub(LEN_LOW_SYMBOLS)
                    );
                    $target = symbol;
                } else {
                    update_1!(ld + LEN_CHOICE);
                    if if_0!(ld + LEN_CHOICE2) {
                        update_0!(ld + LEN_CHOICE2);
                        bittree!(
                            ld + LEN_MID + $pos_state as usize * LEN_MID_SYMBOLS as usize,
                            3,
                            (MATCH_LEN_MIN + LEN_LOW_SYMBOLS).wrapping_sub(LEN_MID_SYMBOLS)
                        );
                        $target = symbol;
                    } else {
                        update_1!(ld + LEN_CHOICE2);
                        bittree!(
                            ld + LEN_HIGH,
                            8,
                            (MATCH_LEN_MIN + LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS)
                                .wrapping_sub(LEN_HIGH_SYMBOLS)
                        );
                        $target = symbol;
                    }
                }
            }};
        }

        // The main decoder loop is in two modes, as liblzma's:
        //
        // 1 - Non-resumable mode (fast). This is used when it is guaranteed
        //     there is enough input to decode the next symbol. If the output
        //     limit is reached, then the decoder loop will save the place
        //     for the resumable mode to continue. This is faster than
        //     Resumable mode because it reduces the number of branches
        //     needed and allows for more compiler optimizations.
        //
        // 2 - Resumable mode (slow). This is used when a previous decoder
        //     loop did not have enough space in the input or output buffers
        //     to complete. It uses sequence values to remember where to
        //     resume in the decoder loop.
        //
        // A call starts where the last one stopped, in the Resumable mode,
        // and each symbol that mode finishes is followed by the
        // Non-resumable one, as long as it can go on.
        let mut seq = self.sequence;
        'out: loop {
            match seq {
                SEQ_NORMALIZE | SEQ_IS_MATCH => {
                    if might_finish_without_eopm && dict.pos == dict.limit {
                        // In rare cases there is a useless byte that needs
                        // to be read anyway.
                        normalize_safe!('out, SEQ_NORMALIZE);

                        // If the range decoder state is such that we can be
                        // at the end of the LZMA stream, then the decoding
                        // is finished.
                        if rc.is_finished() {
                            ret = Ret::StreamEnd;
                            break 'out;
                        }

                        // If the caller hasn't allowed EOPM to be present
                        // together with known uncompressed size, then the
                        // LZMA stream is corrupt.
                        if !self.allow_eopm {
                            ret = Ret::DataError;
                            break 'out;
                        }

                        // Otherwise continue decoding with the expectation
                        // that the next LZMA symbol is EOPM.
                        eopm_is_valid = true;
                    }

                    let is_match = IS_MATCH + state as usize * POS_STATES_MAX + pos_state as usize;
                    if if_0_safe!('out, is_match, SEQ_IS_MATCH) {
                        // Decode literal.
                        update_0!(is_match);
                        let prev = u32::from(dict.get0());
                        probs = LITERAL
                            + 3 * ((((dict.pos as u32) << 8).wrapping_add(prev) & literal_mask)
                                << literal_context_bits) as usize;
                        symbol = 1;

                        if is_literal_state(state) {
                            state = update_literal_normal(state);
                            seq = SEQ_LITERAL;
                        } else {
                            state = update_literal_matched(state);
                            len = u32::from(dict.get(rep0)) << 1;
                            offset = 0x100;
                            seq = SEQ_LITERAL_MATCHED;
                        }
                        continue;
                    }

                    // Decode match.
                    update_1!(is_match);
                    seq = SEQ_IS_REP;
                }
                SEQ_LITERAL => {
                    // Decode literal without match byte. The "slow"
                    // version does not unroll the loop.
                    loop {
                        bit_safe!('out, probs + symbol as usize, SEQ_LITERAL, {}, {});
                        if symbol >= 1 << 8 {
                            break;
                        }
                    }
                    seq = SEQ_LITERAL_WRITE;
                }
                SEQ_LITERAL_MATCHED => {
                    // Decode literal with match byte.
                    loop {
                        let match_bit = len & offset;
                        let subcoder_index = offset + match_bit + symbol;
                        bit_safe!(
                            'out,
                            probs + subcoder_index as usize,
                            SEQ_LITERAL_MATCHED,
                            { offset &= !match_bit },
                            { offset &= match_bit }
                        );
                        // It seems to be faster to do this here instead of
                        // putting it to the beginning of the loop and then
                        // putting the "case" in the middle of the loop.
                        len <<= 1;
                        if symbol >= 1 << 8 {
                            break;
                        }
                    }
                    seq = SEQ_LITERAL_WRITE;
                }
                SEQ_LITERAL_WRITE => {
                    if dict.put_safe(symbol as u8) {
                        self.sequence = SEQ_LITERAL_WRITE;
                        break 'out;
                    }
                    pos_state = dict.pos as u32 & pos_mask;
                    seq = SEQ_IS_MATCH;
                }
                SEQ_IS_REP => {
                    let is_rep = IS_REP + state as usize;
                    if if_0_safe!('out, is_rep, SEQ_IS_REP) {
                        // Simple match.
                        update_0!(is_rep);
                        state = update_match(state);
                        rep3 = rep2;
                        rep2 = rep1;
                        rep1 = rep0;
                        seq = SEQ_MATCH_LEN_CHOICE;
                    } else {
                        // Repeated match.
                        update_1!(is_rep);
                        if !dict.is_distance_valid(0) {
                            ret = Ret::DataError;
                            break 'out;
                        }
                        seq = SEQ_IS_REP0;
                    }
                }
                SEQ_MATCH_LEN_CHOICE
                | SEQ_MATCH_LEN_CHOICE2
                | SEQ_MATCH_LEN_BITTREE
                | SEQ_REP_LEN_CHOICE
                | SEQ_REP_LEN_CHOICE2
                | SEQ_REP_LEN_BITTREE => {
                    // `len_decode`: the length of a match or of a repeated
                    // match, into `len`.
                    let rep = seq >= SEQ_REP_LEN_CHOICE;
                    let (ld, choice, choice2, bittree) = if rep {
                        (
                            REP_LEN_DECODER,
                            SEQ_REP_LEN_CHOICE,
                            SEQ_REP_LEN_CHOICE2,
                            SEQ_REP_LEN_BITTREE,
                        )
                    } else {
                        (
                            MATCH_LEN_DECODER,
                            SEQ_MATCH_LEN_CHOICE,
                            SEQ_MATCH_LEN_CHOICE2,
                            SEQ_MATCH_LEN_BITTREE,
                        )
                    };
                    if seq == choice {
                        if if_0_safe!('out, ld + LEN_CHOICE, choice) {
                            update_0!(ld + LEN_CHOICE);
                            probs = ld + LEN_LOW + pos_state as usize * LEN_LOW_SYMBOLS as usize;
                            limit = LEN_LOW_SYMBOLS;
                            len = MATCH_LEN_MIN;
                            symbol = 1;
                            seq = bittree;
                        } else {
                            update_1!(ld + LEN_CHOICE);
                            seq = choice2;
                        }
                    }
                    if seq == choice2 {
                        if if_0_safe!('out, ld + LEN_CHOICE2, choice2) {
                            update_0!(ld + LEN_CHOICE2);
                            probs = ld + LEN_MID + pos_state as usize * LEN_MID_SYMBOLS as usize;
                            limit = LEN_MID_SYMBOLS;
                            len = MATCH_LEN_MIN + LEN_LOW_SYMBOLS;
                        } else {
                            update_1!(ld + LEN_CHOICE2);
                            probs = ld + LEN_HIGH;
                            limit = LEN_HIGH_SYMBOLS;
                            len = MATCH_LEN_MIN + LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS;
                        }
                        symbol = 1;
                    }
                    loop {
                        bit_safe!('out, probs + symbol as usize, bittree, {}, {});
                        if symbol >= limit {
                            break;
                        }
                    }
                    len += symbol - limit;

                    if rep {
                        seq = SEQ_COPY;
                        continue;
                    }
                    probs = DIST_SLOT + (get_dist_state(len) * DIST_SLOTS) as usize;
                    symbol = 1;
                    seq = SEQ_DIST_SLOT;
                }
                SEQ_DIST_SLOT => {
                    loop {
                        bit_safe!('out, probs + symbol as usize, SEQ_DIST_SLOT, {}, {});
                        if symbol >= DIST_SLOTS {
                            break;
                        }
                    }
                    symbol -= DIST_SLOTS;

                    if symbol < DIST_MODEL_START {
                        rep0 = symbol;
                        seq = SEQ_COPY + 1;
                    } else {
                        limit = (symbol >> 1) - 1;
                        rep0 = 2 + (symbol & 1);

                        if symbol < DIST_MODEL_END {
                            rep0 <<= limit;
                            // -1 is fine, because we start decoding at
                            // probs[1], not probs[0].
                            probs = POS_SPECIAL + rep0 as usize - symbol as usize - 1;
                            symbol = 1;
                            offset = 0;
                            seq = SEQ_DIST_MODEL;
                        } else {
                            limit -= ALIGN_BITS;
                            seq = SEQ_DIRECT;
                        }
                    }
                }
                SEQ_DIST_MODEL => {
                    loop {
                        bit_safe!('out, probs + symbol as usize, SEQ_DIST_MODEL, {}, {
                            rep0 += 1 << offset
                        });
                        offset += 1;
                        if offset >= limit {
                            break;
                        }
                    }
                    seq = SEQ_COPY + 1;
                }
                SEQ_DIRECT => {
                    // `rc_direct_safe`.
                    loop {
                        normalize_safe!('out, SEQ_DIRECT);
                        rc.range >>= 1;
                        rc.code = rc.code.wrapping_sub(rc.range);
                        rc_bound = 0u32.wrapping_sub(rc.code >> 31);
                        rc.code = rc.code.wrapping_add(rc.range & rc_bound);
                        rep0 = (rep0 << 1).wrapping_add(rc_bound.wrapping_add(1));
                        limit -= 1;
                        if limit == 0 {
                            break;
                        }
                    }
                    rep0 <<= ALIGN_BITS;
                    symbol = 0;
                    offset = 1;
                    seq = SEQ_ALIGN;
                }
                SEQ_ALIGN => {
                    loop {
                        // `rc_bit_last_safe`.
                        let at = POS_ALIGN + (offset + symbol) as usize;
                        if if_0_safe!('out, at, SEQ_ALIGN) {
                            update_0!(at);
                        } else {
                            update_1!(at);
                            symbol += offset;
                        }
                        offset <<= 1;
                        if offset >= ALIGN_SIZE {
                            break;
                        }
                    }
                    rep0 = rep0.wrapping_add(symbol);

                    if rep0 == u32::MAX {
                        // End of payload marker was found. It may only be
                        // present if
                        //   - uncompressed size is unknown or
                        //   - after known uncompressed size amount of bytes
                        //     has been decompressed and caller has
                        //     indicated that EOPM might be used (it's not
                        //     allowed in LZMA2).
                        if !eopm_is_valid {
                            ret = Ret::DataError;
                            break 'out;
                        }
                        seq = SEQ_EOPM;
                        continue;
                    }
                    seq = SEQ_COPY + 1;
                }
                SEQ_EOPM => {
                    // LZMA1 stream with end-of-payload marker.
                    normalize_safe!('out, SEQ_EOPM);
                    ret = if rc.is_finished() {
                        Ret::StreamEnd
                    } else {
                        Ret::DataError
                    };
                    break 'out;
                }
                // After the distance of a match: its check, then the copy.
                // (Not one of liblzma's sequence values: the code between
                // the end of the distance and the SEQ_COPY label.)
                x if x == SEQ_COPY + 1 => {
                    if !dict.is_distance_valid(rep0 as usize) {
                        ret = Ret::DataError;
                        break 'out;
                    }
                    seq = SEQ_COPY;
                }
                SEQ_IS_REP0 => {
                    let at = IS_REP0 + state as usize;
                    if if_0_safe!('out, at, SEQ_IS_REP0) {
                        update_0!(at);
                        seq = SEQ_IS_REP0_LONG;
                    } else {
                        update_1!(at);
                        seq = SEQ_IS_REP1;
                    }
                }
                SEQ_IS_REP0_LONG => {
                    let at = IS_REP0_LONG + state as usize * POS_STATES_MAX + pos_state as usize;
                    if if_0_safe!('out, at, SEQ_IS_REP0_LONG) {
                        update_0!(at);
                        state = update_short_rep(state);
                        seq = SEQ_SHORTREP;
                    } else {
                        update_1!(at);
                        state = update_long_rep(state);
                        seq = SEQ_REP_LEN_CHOICE;
                    }
                }
                SEQ_SHORTREP => {
                    let byte = dict.get(rep0);
                    if dict.put_safe(byte) {
                        self.sequence = SEQ_SHORTREP;
                        break 'out;
                    }
                    pos_state = dict.pos as u32 & pos_mask;
                    seq = SEQ_IS_MATCH;
                }
                SEQ_IS_REP1 => {
                    let at = IS_REP1 + state as usize;
                    if if_0_safe!('out, at, SEQ_IS_REP1) {
                        update_0!(at);
                        // The distance is rep1: it and rep0 change places.
                        core::mem::swap(&mut rep0, &mut rep1);
                        state = update_long_rep(state);
                        seq = SEQ_REP_LEN_CHOICE;
                    } else {
                        update_1!(at);
                        seq = SEQ_IS_REP2;
                    }
                }
                SEQ_IS_REP2 => {
                    let at = IS_REP2 + state as usize;
                    if if_0_safe!('out, at, SEQ_IS_REP2) {
                        update_0!(at);
                        let distance = rep2;
                        rep2 = rep1;
                        rep1 = rep0;
                        rep0 = distance;
                    } else {
                        update_1!(at);
                        let distance = rep3;
                        rep3 = rep2;
                        rep2 = rep1;
                        rep1 = rep0;
                        rep0 = distance;
                    }
                    state = update_long_rep(state);
                    seq = SEQ_REP_LEN_CHOICE;
                }
                SEQ_COPY => {
                    // Repeat from history buffer.
                    if dict.repeat(rep0, &mut len) {
                        self.sequence = SEQ_COPY;
                        break 'out;
                    }
                    pos_state = dict.pos as u32 & pos_mask;
                    seq = SEQ_IS_MATCH;
                }
                // There are no other sequence values.
                _ => {
                    ret = Ret::ProgError;
                    break 'out;
                }
            }

            if seq != SEQ_IS_MATCH {
                continue;
            }

            ///////////////////////////////
            // Non-resumable Mode (fast) //
            ///////////////////////////////
            loop {
                // Calculate new pos_state.
                pos_state = dict.pos as u32 & pos_mask;

                // Go to Resumable mode (1) if there is not enough input to
                // safely decode any possible LZMA symbol or (2) if the
                // dictionary is full, which may need special checks that are
                // only done in the Resumable mode.
                if rc_in_ptr >= rc_in_fast_end || dict.pos == dict.limit {
                    break;
                }

                // Decode the first bit from the next LZMA symbol. If the bit
                // is a 0, then we handle it as a literal. If the bit is a 1,
                // then it is a match of previously decoded data.
                let is_match = IS_MATCH + state as usize * POS_STATES_MAX + pos_state as usize;
                if if_0!(is_match) {
                    // Decode literal.
                    update_0!(is_match);

                    // Get the correct probability array from lp and lc
                    // params.
                    let prev = u32::from(dict.get0());
                    probs = LITERAL
                        + 3 * ((((dict.pos as u32) << 8).wrapping_add(prev) & literal_mask)
                            << literal_context_bits) as usize;

                    if is_literal_state(state) {
                        state = update_literal_normal(state);
                        // Decode literal without match byte.
                        bittree!(probs, 8, 0);
                    } else {
                        state = update_literal_matched(state);
                        // Decode literal with match byte.
                        matched_literal!(probs, dict.get(rep0));
                    }

                    // Write decoded literal to dictionary
                    dict.put(symbol as u8);
                    continue;
                }

                // Decode match. Instead of a new byte we are going to decode
                // a distance-length pair.
                update_1!(is_match);

                let is_rep = IS_REP + state as usize;
                if if_0!(is_rep) {
                    // Simple match. Not a repeated match. In this case, the
                    // length (how many bytes to copy) must be decoded first.
                    // Then, the distance (where to start copying) is
                    // decoded.
                    update_0!(is_rep);
                    state = update_match(state);

                    // The latest three match distances are kept in memory in
                    // case there are repeated matches.
                    rep3 = rep2;
                    rep2 = rep1;
                    rep1 = rep0;

                    // Decode the length of the match.
                    len_decode_fast!(len, MATCH_LEN_DECODER, pos_state);

                    // Next, decode the distance into rep0. The next 6 bits
                    // determine how to decode the rest of the distance.
                    probs = DIST_SLOT + (get_dist_state(len) * DIST_SLOTS) as usize;
                    bittree!(probs, 6, 0u32.wrapping_sub(DIST_SLOTS));

                    if symbol < DIST_MODEL_START {
                        // If the decoded symbol is < DIST_MODEL_START then
                        // we use its value directly as the match distance.
                        rep0 = symbol;
                    } else {
                        // Use the first two bits of symbol as the highest
                        // bits of the match distance. "limit" represents the
                        // number of low bits to decode.
                        limit = (symbol >> 1) - 1;
                        rep0 = 2 + (symbol & 1);

                        if symbol < DIST_MODEL_END {
                            // Distances between [4, 127].
                            rep0 <<= limit;

                            // -1 is fine, because we start decoding at
                            // probs[1], not probs[0].
                            probs = POS_SPECIAL + rep0 as usize - symbol as usize - 1;
                            symbol = 1;
                            offset = 1;

                            // Variable number (1-5) of bits from a reverse
                            // bittree.
                            loop {
                                bit_add_if_1!(probs, rep0, offset);
                                offset <<= 1;
                                limit -= 1;
                                if limit == 0 {
                                    break;
                                }
                            }
                        } else {
                            // The distance is >= 128. Decode the lower bits
                            // without probabilities except the lowest four
                            // bits.
                            limit -= ALIGN_BITS;
                            direct!(rep0, limit);

                            // Decode the lowest four bits using
                            // probabilities.
                            rep0 <<= ALIGN_BITS;
                            bittree_rev4!(POS_ALIGN);
                            rep0 = rep0.wrapping_add(symbol);

                            // If the end of payload marker (EOPM) is
                            // detected, jump to the safe code. The EOPM
                            // handling isn't speed critical at all.
                            if rep0 == u32::MAX {
                                if !eopm_is_valid {
                                    ret = Ret::DataError;
                                    break 'out;
                                }
                                seq = SEQ_EOPM;
                                continue 'out;
                            }
                        }
                    }

                    // Validate the distance we just decoded.
                    if !dict.is_distance_valid(rep0 as usize) {
                        ret = Ret::DataError;
                        break 'out;
                    }
                } else {
                    update_1!(is_rep);

                    // Repeated match. There cannot be a match if we haven't
                    // produced any output, so check that first.
                    if !dict.is_distance_valid(0) {
                        ret = Ret::DataError;
                        break 'out;
                    }

                    let is_rep0 = IS_REP0 + state as usize;
                    if if_0!(is_rep0) {
                        update_0!(is_rep0);
                        // The distance is rep0. If the next bit is 0, then
                        // it is a "Short Rep Match" and only 1 byte is
                        // copied.
                        let is_rep0_long =
                            IS_REP0_LONG + state as usize * POS_STATES_MAX + pos_state as usize;
                        if if_0!(is_rep0_long) {
                            update_0!(is_rep0_long);
                            state = update_short_rep(state);
                            let byte = dict.get(rep0);
                            dict.put(byte);
                            continue;
                        }
                        // Repeating more than one byte at distance of rep0.
                        update_1!(is_rep0_long);
                    } else {
                        update_1!(is_rep0);
                        // The distance is rep1, rep2 or rep3.
                        let is_rep1 = IS_REP1 + state as usize;
                        if if_0!(is_rep1) {
                            update_0!(is_rep1);
                            // The distance is rep1: it and rep0 change
                            // places.
                            core::mem::swap(&mut rep0, &mut rep1);
                        } else {
                            update_1!(is_rep1);
                            let is_rep2 = IS_REP2 + state as usize;
                            if if_0!(is_rep2) {
                                update_0!(is_rep2);
                                let distance = rep2;
                                rep2 = rep1;
                                rep1 = rep0;
                                rep0 = distance;
                            } else {
                                update_1!(is_rep2);
                                let distance = rep3;
                                rep3 = rep2;
                                rep2 = rep1;
                                rep1 = rep0;
                                rep0 = distance;
                            }
                        }
                    }

                    state = update_long_rep(state);

                    // Decode the length of the repeated match.
                    len_decode_fast!(len, REP_LEN_DECODER, pos_state);
                }

                // Repeat from history buffer: len bytes from distance of
                // rep0.
                if dict.repeat(rep0, &mut len) {
                    self.sequence = SEQ_COPY;
                    break 'out;
                }
            }
        }

        // Save state
        dict.limit = dict_limit;
        let dict_end = dict.pos;
        *dictptr = core::mem::take(dict);
        self.rc = rc;
        *in_pos = rc_in_ptr;
        self.state = state;
        self.rep0 = rep0;
        self.rep1 = rep1;
        self.rep2 = rep2;
        self.rep3 = rep3;
        self.probs = probs;
        self.symbol = symbol;
        self.limit = limit;
        self.offset = offset;
        self.len = len;

        // Update the remaining amount of uncompressed data if uncompressed
        // size was known.
        if self.uncompressed_size != VLI_UNKNOWN {
            self.uncompressed_size -= (dict_end - dict_start) as u64;

            // If we have gotten all the output but the decoder wants to
            // write more output, the file is corrupt. There are three SEQ
            // values where output is produced.
            if self.uncompressed_size == 0
                && ret == Ret::Ok
                && matches!(self.sequence, SEQ_LITERAL_WRITE | SEQ_SHORTREP | SEQ_COPY)
            {
                ret = Ret::DataError;
            }
        }

        if ret == Ret::StreamEnd {
            // Reset the range decoder so that it is ready to reinitialize
            // for a new LZMA2 chunk.
            self.rc.reset();
            self.sequence = SEQ_IS_MATCH;
        }

        ret
    }
}

/// `lzma_lzma_lclppb_decode`: lc, lp and pb from their byte; true if the
/// byte is invalid.
pub(crate) fn lclppb_decode(options: &mut LzmaOptions, mut byte: u8) -> bool {
    if u32::from(byte) > (4 * 5 + 4) * 9 + 8 {
        return true;
    }

    // See the file format specification to understand this.
    options.pb = u32::from(byte) / (9 * 5);
    byte -= (options.pb * 9 * 5) as u8;
    options.lp = u32::from(byte) / 9;
    options.lc = u32::from(byte) - options.lp * 9;

    options.lc + options.lp > LCLP_MAX
}

/// `lzma_lzma_decoder_memusage_nocheck`.
pub(crate) fn decoder_memusage_nocheck(options: &LzmaOptions) -> u64 {
    LZMA1_DECODER_SIZE + lz_decoder_memusage(u64::from(options.dict_size))
}

/// `lzma_lzma_decoder_memusage`.
pub(crate) fn decoder_memusage(options: &LzmaOptions) -> u64 {
    if !is_lclppb_valid(options) {
        return u64::MAX;
    }
    decoder_memusage_nocheck(options)
}

/// `lzma_lzma_props_decode`: the options of an LZMA1 filter from its five
/// bytes of properties.
pub(crate) fn props_decode(props: &[u8]) -> Result<LzmaOptions, Ret> {
    if props.len() != 5 {
        return Err(Ret::OptionsError);
    }
    let mut options = LzmaOptions::default();
    if lclppb_decode(&mut options, props[0]) {
        return Err(Ret::OptionsError);
    }
    // All dictionary sizes are accepted, including zero. LZ decoder will
    // automatically use a dictionary at least a few KiB even if a smaller
    // dictionary is requested.
    options.dict_size = crate::xz::common::read32le(&props[1..]);
    Ok(options)
}
