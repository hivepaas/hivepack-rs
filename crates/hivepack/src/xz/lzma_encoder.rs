//! The LZMA encoder: port of `lzma/lzma_encoder.{h,c}`,
//! `lzma_encoder_private.h`, `lzma_encoder_optimum_fast.c`,
//! `lzma_encoder_optimum_normal.c` and `fastpos.h`.
//!
//! The probabilities are one array, laid out as the decoder's (see
//! `lzma_common.rs`); the range encoder queues indices into it.

use crate::xz::common::{Action, Ret, write32le};
use crate::xz::filter::{FILTER_LZMA1, FILTER_LZMA1EXT, FILTER_LZMA2};
use crate::xz::lz_encoder::{LzEncOptions, Match, Mf, lz_encoder_memusage, mf_get_hash_bytes};
use crate::xz::lzma_common::*;
use crate::xz::range_decoder::{PROB_INIT, Probability};
use crate::xz::range_encoder::{
    RC_INFINITY_PRICE, RangeEncoder, bit_0_price, bit_1_price, bit_price, bittree_price,
    bittree_reverse_price, direct_price,
};

/// Optimal - Number of entries in the optimum array.
pub(crate) const OPTS: usize = 1 << 12;

/// Number of bytes that a single encoding loop in lzma_lzma_encode() can
/// consume from the dictionary. This limit comes from lzma_lzma_optimum()
/// and may need to be updated if that function is significantly modified.
const LOOP_INPUT_MAX: u32 = OPTS as u32 + 1;

/// `LZMA2_CHUNK_MAX`: maximum number of bytes of LZMA compressed data in
/// an LZMA2 chunk.
pub(crate) const LZMA2_CHUNK_MAX: u32 = 1 << 16;

/// `sizeof(lzma_lzma1_encoder)` in liblzma on 64-bit systems, which its
/// memory usage counts.
const LZMA1_ENCODER_SIZE: u64 = 249_552;

/// `lzma_length_encoder`: its prices; its probabilities are in the
/// encoder's array, from `base`.
struct LengthEncoder {
    base: usize,
    prices: [[u32; LEN_SYMBOLS as usize]; POS_STATES_MAX],
    table_size: u32,
    counters: [u32; POS_STATES_MAX],
}

impl LengthEncoder {
    fn new(base: usize) -> LengthEncoder {
        LengthEncoder {
            base,
            prices: [[0; LEN_SYMBOLS as usize]; POS_STATES_MAX],
            table_size: 0,
            counters: [0; POS_STATES_MAX],
        }
    }

    /// `length_update_prices`.
    fn update_prices(&mut self, p: &[Probability], pos_state: u32) {
        let base = self.base;
        let table_size = self.table_size;
        self.counters[pos_state as usize] = table_size;

        let a0 = bit_0_price(p[base + LEN_CHOICE]);
        let a1 = bit_1_price(p[base + LEN_CHOICE]);
        let b0 = a1 + bit_0_price(p[base + LEN_CHOICE2]);
        let b1 = a1 + bit_1_price(p[base + LEN_CHOICE2]);
        let prices = &mut self.prices[pos_state as usize];
        let low = base + LEN_LOW + pos_state as usize * LEN_LOW_SYMBOLS as usize;
        let mid = base + LEN_MID + pos_state as usize * LEN_MID_SYMBOLS as usize;

        let mut i = 0;
        while i < table_size && i < LEN_LOW_SYMBOLS {
            prices[i as usize] = a0 + bittree_price(p, low, LEN_LOW_BITS, i);
            i += 1;
        }
        while i < table_size && i < LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS {
            prices[i as usize] = b0 + bittree_price(p, mid, LEN_MID_BITS, i - LEN_LOW_SYMBOLS);
            i += 1;
        }
        while i < table_size {
            prices[i as usize] = b1
                + bittree_price(
                    p,
                    base + LEN_HIGH,
                    LEN_HIGH_BITS,
                    i - LEN_LOW_SYMBOLS - LEN_MID_SYMBOLS,
                );
            i += 1;
        }
    }

    /// `get_len_price`. NOTE: Unlike the other price tables, length
    /// prices are updated in lzma_encoder.c
    #[inline(always)]
    fn price(&self, len: u32, pos_state: u32) -> u32 {
        self.prices[pos_state as usize][(len - MATCH_LEN_MIN) as usize]
    }
}

/// `lzma_optimal`.
#[derive(Clone, Copy, Debug, Default)]
struct Optimal {
    state: u32,
    prev_1_is_literal: bool,
    prev_2: bool,
    pos_prev_2: u32,
    back_prev_2: u32,
    price: u32,
    pos_prev: u32, // pos_next;
    back_prev: u32,
    backs: [u32; REPS],
}

impl Optimal {
    /// `make_literal`.
    #[inline(always)]
    fn make_literal(&mut self) {
        self.back_prev = u32::MAX;
        self.prev_1_is_literal = false;
    }

    /// `make_short_rep`.
    #[inline(always)]
    fn make_short_rep(&mut self) {
        self.back_prev = 0;
        self.prev_1_is_literal = false;
    }

    /// `is_short_rep`.
    #[inline(always)]
    fn is_short_rep(&self) -> bool {
        self.back_prev == 0
    }
}

/// `get_dist_slot`: the slot of a distance.
///
/// Differs from liblzma, without a difference to see: liblzma looks the
/// slots up in `lzma_fastpos`, an 8 KiB table, unless built with
/// `HAVE_SMALL`, when it computes them as this does.
#[inline(always)]
pub(crate) fn get_dist_slot(dist: u32) -> u32 {
    if dist <= 4 {
        dist
    } else {
        get_dist_slot_2(dist)
    }
}

/// `get_dist_slot_2`: the slot of a distance above 4.
#[inline(always)]
fn get_dist_slot_2(dist: u32) -> u32 {
    let i = 31 - dist.leading_zeros();
    (i + i) + ((dist >> (i - 1)) & 1)
}

/// `not_equal_16`: whether the first two bytes at `a` and `b` differ.
#[inline(always)]
fn not_equal_16(buf: &[u8], a: usize, b: usize) -> bool {
    buf[a] != buf[b] || buf[a + 1] != buf[b + 1]
}

/// `lzma_memcmplen`, for the optimum functions.
#[inline(always)]
fn memcmplen(buf: &[u8], a: usize, b: usize, len: u32, limit: u32) -> u32 {
    let mut i = len as usize;
    let limit = limit as usize;
    while i < limit && buf[a + i] == buf[b + i] {
        i += 1;
    }
    i as u32
}

/// `change_pair`.
#[inline(always)]
fn change_pair(small_dist: u32, big_dist: u32) -> bool {
    (big_dist >> 7) > small_dist
}

/// `literal_subcoder`: where the probabilities of the literal coder for
/// the next byte start.
#[inline(always)]
fn literal_subcoder(lc: u32, literal_mask: u32, pos: u32, prev_byte: u32) -> usize {
    LITERAL + 3 * ((((pos << 8).wrapping_add(prev_byte)) & literal_mask) << lc) as usize
}

/// `lzma_lzma1_encoder`.
pub(crate) struct LzmaEncoder {
    /// Range encoder
    rc: RangeEncoder,
    /// Uncompressed size (doesn't include possible preset dictionary)
    uncomp_size: u64,
    /// State
    state: u32,
    /// The four most recent match distances
    reps: [u32; REPS],
    /// Array of match candidates
    matches: [Match; MATCH_LEN_MAX as usize + 1],
    /// Number of match candidates in matches[]
    matches_count: u32,
    /// Variable to hold the length of the longest match between calls to
    /// lzma_lzma_optimum_*().
    longest_match_length: u32,
    /// True if using getoptimumfast
    fast_mode: bool,
    /// True if the encoder has been initialized by encoding the first
    /// byte as a literal.
    is_initialized: bool,
    /// True if the range encoder has been flushed, but not all bytes have
    /// been written to the output buffer yet.
    is_flushed: bool,
    /// True if end of payload marker will be written.
    use_eopm: bool,
    /// (1 << pos_bits) - 1
    pos_mask: u32,
    literal_context_bits: u32,
    literal_mask: u32,
    /// The probabilities, in the decoder's layout.
    p: Box<[Probability; PROBS]>,
    // These are the same as in lzma_decoder.c except that the encoders
    // include also price tables.
    match_len_encoder: LengthEncoder,
    rep_len_encoder: LengthEncoder,
    // Price tables
    dist_slot_prices: [[u32; DIST_SLOTS as usize]; DIST_STATES as usize],
    dist_prices: [[u32; FULL_DISTANCES as usize]; DIST_STATES as usize],
    dist_table_size: u32,
    match_price_count: u32,
    align_prices: [u32; ALIGN_SIZE as usize],
    align_price_count: u32,
    // Optimal
    opts_end_index: u32,
    opts_current_index: u32,
    opts: Box<[Optimal]>,
}

impl LzmaEncoder {
    /// `lzma_lzma_encoder_create` without an encoder: the encoder of `id`
    /// with `options`, and the LZ encoder's options.
    pub(crate) fn create(
        id: u64,
        options: &LzmaOptions,
    ) -> Result<(LzmaEncoder, LzEncOptions), Ret> {
        let mut coder = LzmaEncoder::blank();
        let lz_options = coder.init(id, options)?;
        Ok((coder, lz_options))
    }

    /// The memory of an encoder, not yet ready to encode.
    pub(crate) fn blank() -> LzmaEncoder {
        LzmaEncoder {
            rc: RangeEncoder::new(),
            uncomp_size: 0,
            state: STATE_LIT_LIT,
            reps: [0; REPS],
            matches: [Match::default(); MATCH_LEN_MAX as usize + 1],
            matches_count: 0,
            longest_match_length: 0,
            fast_mode: false,
            is_initialized: false,
            is_flushed: false,
            use_eopm: false,
            pos_mask: 0,
            literal_context_bits: 0,
            literal_mask: 0,
            p: Box::new([PROB_INIT; PROBS]),
            match_len_encoder: LengthEncoder::new(MATCH_LEN_DECODER),
            rep_len_encoder: LengthEncoder::new(REP_LEN_DECODER),
            dist_slot_prices: [[0; DIST_SLOTS as usize]; DIST_STATES as usize],
            dist_prices: [[0; FULL_DISTANCES as usize]; DIST_STATES as usize],
            dist_table_size: 0,
            match_price_count: 0,
            align_prices: [0; ALIGN_SIZE as usize],
            align_price_count: 0,
            opts_end_index: 0,
            opts_current_index: 0,
            // Differs from liblzma, without a difference to see: liblzma
            // leaves opts[] uninitialised, and only the normal mode uses
            // it; here only the normal mode has it, initialised.
            opts: Box::default(),
        }
    }

    /// `lzma_lzma_encoder_create` with an encoder, whose memory is kept: it
    /// becomes the encoder of `id` with `options`; the LZ encoder's options.
    pub(crate) fn init(&mut self, id: u64, options: &LzmaOptions) -> Result<LzEncOptions, Ret> {
        let coder = self;

        // Set compression mode. Note that we haven't validated the options
        // yet. Invalid options will get rejected by
        // lzma_lzma_encoder_reset() call at the end of this function.
        match options.mode {
            Mode::FAST => coder.fast_mode = true,
            Mode::NORMAL => {
                coder.fast_mode = false;
                if coder.opts.is_empty() {
                    coder.opts = vec![Optimal::default(); OPTS].into_boxed_slice();
                }

                // Set dist_table_size. Round the dictionary size up to
                // next 2^n.
                //
                // Currently the maximum encoder dictionary size is 1.5 GiB
                // due to lz_encoder.c and here we need to be below 2 GiB
                // to make the rounded up value fit in an uint32_t and
                // avoid an infinite while-loop (and undefined behavior due
                // to a too large shift). So do the same check as in LZ
                // encoder, limiting to 1.5 GiB.
                if options.dict_size > (1 << 30) + (1 << 29) {
                    return Err(Ret::OptionsError);
                }

                let mut log_size = 0;
                while (1u32 << log_size) < options.dict_size {
                    log_size += 1;
                }

                coder.dist_table_size = log_size * 2;

                // Length encoders' price table size
                let nice_len = mf_get_hash_bytes(options.mf).max(options.nice_len);

                coder.match_len_encoder.table_size =
                    nice_len.wrapping_add(1).wrapping_sub(MATCH_LEN_MIN);
                coder.rep_len_encoder.table_size =
                    nice_len.wrapping_add(1).wrapping_sub(MATCH_LEN_MIN);
            }
            _ => return Err(Ret::OptionsError),
        }

        // We don't need to write the first byte as literal if there is a
        // non-empty preset dictionary. encode_init() wouldn't even work if
        // there is a non-empty preset dictionary, because encode_init()
        // assumes that position is zero and previous byte is also zero.
        coder.is_initialized = options.preset_dict.as_ref().is_some_and(|d| !d.is_empty());
        coder.is_flushed = false;
        coder.uncomp_size = 0;

        // Determine if end marker is wanted:
        //   - It is never used with LZMA2.
        //   - It is always used with LZMA_FILTER_LZMA1.
        //   - LZMA_FILTER_LZMA1EXT has a flag for it in the options.
        //
        // Differs from liblzma: there is no lzma_lzma_set_out_limit(),
        // which only the MicroLZMA encoder uses, and so no output limit.
        coder.use_eopm = id == FILTER_LZMA1;
        if id == FILTER_LZMA1EXT {
            // Check if unsupported flags are present.
            if options.ext_flags & !LZMA1EXT_ALLOW_EOPM != 0 {
                return Err(Ret::OptionsError);
            }

            coder.use_eopm = options.ext_flags & LZMA1EXT_ALLOW_EOPM != 0;
        }
        debug_assert!(id == FILTER_LZMA1 || id == FILTER_LZMA1EXT || id == FILTER_LZMA2);

        let lz_options = set_lz_options(options);
        coder.reset(options)?;
        Ok(lz_options)
    }

    /// `lzma_lzma_encoder_reset`.
    pub(crate) fn reset(&mut self, options: &LzmaOptions) -> Result<(), Ret> {
        if !is_options_valid(options) {
            return Err(Ret::OptionsError);
        }

        self.pos_mask = (1 << options.pb) - 1;
        self.literal_context_bits = options.lc;
        self.literal_mask = literal_mask_calc(options.lc, options.lp);

        // Range coder
        self.rc.reset();

        // State
        self.state = STATE_LIT_LIT;
        self.reps = [0; REPS];

        // literal_init
        let p = &mut self.p[..];
        p[LITERAL..LITERAL + (LITERAL_CODER_SIZE << (options.lc + options.lp))].fill(PROB_INIT);

        // Bit encoders
        for i in 0..STATES {
            for j in 0..=self.pos_mask as usize {
                p[IS_MATCH + i * POS_STATES_MAX + j] = PROB_INIT;
                p[IS_REP0_LONG + i * POS_STATES_MAX + j] = PROB_INIT;
            }
            p[IS_REP + i] = PROB_INIT;
            p[IS_REP0 + i] = PROB_INIT;
            p[IS_REP1 + i] = PROB_INIT;
            p[IS_REP2 + i] = PROB_INIT;
        }

        p[POS_SPECIAL..POS_ALIGN].fill(PROB_INIT);

        // Bit tree encoders
        p[DIST_SLOT..POS_SPECIAL].fill(PROB_INIT);
        p[POS_ALIGN..POS_ALIGN + ALIGN_SIZE as usize].fill(PROB_INIT);

        // Length encoders
        let num_pos_states = 1u32 << options.pb;
        let fast_mode = self.fast_mode;
        length_encoder_reset(p, &mut self.match_len_encoder, num_pos_states, fast_mode);
        length_encoder_reset(p, &mut self.rep_len_encoder, num_pos_states, fast_mode);

        // Price counts are incremented every time appropriate
        // probabilities are changed. price counts are set to zero when the
        // price tables are updated, which is done when the appropriate
        // price counts have big enough value, and lzma_mf.read_ahead == 0
        // which happens at least every OPTS (a few thousand) possible price
        // count increments.
        //
        // By resetting price counts to UINT32_MAX / 2, we make sure that
        // the price tables will be initialized before they will be used
        // (since the value is definitely big enough), and that it is OK to
        // increment price counts without risk of integer overflow (since
        // UINT32_MAX / 2 is small enough).
        self.match_price_count = u32::MAX / 2;
        self.align_price_count = u32::MAX / 2;

        self.opts_end_index = 0;
        self.opts_current_index = 0;

        Ok(())
    }

    // Literal

    /// `literal_matched`.
    #[inline(always)]
    fn literal_matched(
        rc: &mut RangeEncoder,
        subcoder: usize,
        mut match_byte: u32,
        mut symbol: u32,
    ) {
        let mut offset = 0x100;
        symbol += 1 << 8;

        loop {
            match_byte <<= 1;
            let match_bit = match_byte & offset;
            let subcoder_index = offset + match_bit + (symbol >> 8);
            let bit = (symbol >> 7) & 1;
            rc.bit(subcoder + subcoder_index as usize, bit);

            symbol <<= 1;
            offset &= !(match_byte ^ symbol);
            if symbol >= 1 << 16 {
                break;
            }
        }
    }

    /// `literal`.
    #[inline(always)]
    fn literal(&mut self, mf: &Mf, position: u32) {
        // Locate the literal byte to be encoded and the subcoder.
        let at = (mf.read_pos - mf.read_ahead) as usize;
        let cur_byte = mf.buffer[at];
        let subcoder = literal_subcoder(
            self.literal_context_bits,
            self.literal_mask,
            position,
            u32::from(mf.buffer[at - 1]),
        );

        if is_literal_state(self.state) {
            // Previous LZMA-symbol was a literal. Encode a normal literal
            // without a match byte.
            self.state = update_literal_normal(self.state);
            self.rc.bittree(subcoder, 8, u32::from(cur_byte));
        } else {
            // Previous LZMA-symbol was a match. Use the last byte of the
            // match as a "match byte". That is, compare the bits of the
            // current literal and the match byte.
            self.state = update_literal_matched(self.state);
            let match_byte = mf.buffer[at - self.reps[0] as usize - 1];
            Self::literal_matched(
                &mut self.rc,
                subcoder,
                u32::from(match_byte),
                u32::from(cur_byte),
            );
        }
    }

    // Match length

    /// `length`.
    #[inline(always)]
    fn length(
        rc: &mut RangeEncoder,
        p: &[Probability],
        lc: &mut LengthEncoder,
        pos_state: u32,
        mut len: u32,
        fast_mode: bool,
    ) {
        let base = lc.base;
        len -= MATCH_LEN_MIN;

        if len < LEN_LOW_SYMBOLS {
            rc.bit(base + LEN_CHOICE, 0);
            rc.bittree(
                base + LEN_LOW + pos_state as usize * LEN_LOW_SYMBOLS as usize,
                LEN_LOW_BITS,
                len,
            );
        } else {
            rc.bit(base + LEN_CHOICE, 1);
            len -= LEN_LOW_SYMBOLS;

            if len < LEN_MID_SYMBOLS {
                rc.bit(base + LEN_CHOICE2, 0);
                rc.bittree(
                    base + LEN_MID + pos_state as usize * LEN_MID_SYMBOLS as usize,
                    LEN_MID_BITS,
                    len,
                );
            } else {
                rc.bit(base + LEN_CHOICE2, 1);
                len -= LEN_MID_SYMBOLS;
                rc.bittree(base + LEN_HIGH, LEN_HIGH_BITS, len);
            }
        }

        // Only getoptimum uses the prices so don't update the table when
        // in fast mode. The prices are of the probabilities before the
        // bits above, which the range encoder has only queued.
        if !fast_mode {
            lc.counters[pos_state as usize] -= 1;
            if lc.counters[pos_state as usize] == 0 {
                lc.update_prices(p, pos_state);
            }
        }
    }

    // Match

    /// `match`.
    #[inline(always)]
    fn match_(&mut self, pos_state: u32, distance: u32, len: u32) {
        self.state = update_match(self.state);

        Self::length(
            &mut self.rc,
            &self.p[..],
            &mut self.match_len_encoder,
            pos_state,
            len,
            self.fast_mode,
        );

        let dist_slot = get_dist_slot(distance);
        let dist_state = get_dist_state(len);
        self.rc.bittree(
            DIST_SLOT + (dist_state * DIST_SLOTS) as usize,
            DIST_SLOT_BITS,
            dist_slot,
        );

        if dist_slot >= DIST_MODEL_START {
            let footer_bits = (dist_slot >> 1) - 1;
            let base = (2 | (dist_slot & 1)) << footer_bits;
            let dist_reduced = distance.wrapping_sub(base);

            if dist_slot < DIST_MODEL_END {
                // Careful here: base - dist_slot - 1 can be -1, but
                // rc_bittree_reverse starts at probs[1], not probs[0].
                self.rc.bittree_reverse(
                    POS_SPECIAL + base as usize - dist_slot as usize - 1,
                    footer_bits,
                    dist_reduced,
                );
            } else {
                self.rc
                    .direct(dist_reduced >> ALIGN_BITS, footer_bits - ALIGN_BITS);
                self.rc
                    .bittree_reverse(POS_ALIGN, ALIGN_BITS, dist_reduced & ALIGN_MASK);
                self.align_price_count += 1;
            }
        }

        self.reps[3] = self.reps[2];
        self.reps[2] = self.reps[1];
        self.reps[1] = self.reps[0];
        self.reps[0] = distance;
        self.match_price_count += 1;
    }

    // Repeated match

    /// `rep_match`.
    #[inline(always)]
    fn rep_match(&mut self, pos_state: u32, rep: u32, len: u32) {
        let state = self.state as usize;
        if rep == 0 {
            self.rc.bit(IS_REP0 + state, 0);
            self.rc.bit(
                IS_REP0_LONG + state * POS_STATES_MAX + pos_state as usize,
                u32::from(len != 1),
            );
        } else {
            let distance = self.reps[rep as usize];
            self.rc.bit(IS_REP0 + state, 1);

            if rep == 1 {
                self.rc.bit(IS_REP1 + state, 0);
            } else {
                self.rc.bit(IS_REP1 + state, 1);
                self.rc.bit(IS_REP2 + state, rep - 2);

                if rep == 3 {
                    self.reps[3] = self.reps[2];
                }

                self.reps[2] = self.reps[1];
            }

            self.reps[1] = self.reps[0];
            self.reps[0] = distance;
        }

        if len == 1 {
            self.state = update_short_rep(self.state);
        } else {
            Self::length(
                &mut self.rc,
                &self.p[..],
                &mut self.rep_len_encoder,
                pos_state,
                len,
                self.fast_mode,
            );
            self.state = update_long_rep(self.state);
        }
    }

    // Main

    /// `encode_symbol`.
    fn encode_symbol(&mut self, mf: &mut Mf, back: u32, len: u32, position: u32) {
        let pos_state = position & self.pos_mask;
        let is_match = IS_MATCH + self.state as usize * POS_STATES_MAX + pos_state as usize;

        if back == u32::MAX {
            // Literal i.e. eight-bit byte
            self.rc.bit(is_match, 0);
            self.literal(mf, position);
        } else {
            // Some type of match
            self.rc.bit(is_match, 1);

            if back < REPS as u32 {
                // It's a repeated match i.e. the same distance has been
                // used earlier.
                self.rc.bit(IS_REP + self.state as usize, 1);
                self.rep_match(pos_state, back, len);
            } else {
                // Normal match
                self.rc.bit(IS_REP + self.state as usize, 0);
                self.match_(pos_state, back - REPS as u32, len);
            }
        }

        mf.read_ahead -= len;
    }

    /// `encode_init`: false if there is nothing to do yet.
    fn encode_init(&mut self, mf: &mut Mf) -> bool {
        if mf.read_pos == mf.read_limit {
            if mf.action == Action::Run {
                return false; // We cannot do anything.
            }

            // We are finishing (we cannot get here when flushing).
        } else {
            // Do the actual initialization. The first LZMA symbol must
            // always be a literal.
            mf.skip(1);
            mf.read_ahead = 0;
            self.rc.bit(IS_MATCH, 0);
            self.rc.bittree(LITERAL, 8, u32::from(mf.buffer[0]));
            self.uncomp_size += 1;
        }

        // Initialization is done (except if empty file).
        self.is_initialized = true;

        true
    }

    /// `encode_eopm`.
    fn encode_eopm(&mut self, position: u32) {
        let pos_state = position & self.pos_mask;
        self.rc.bit(
            IS_MATCH + self.state as usize * POS_STATES_MAX + pos_state as usize,
            1,
        );
        self.rc.bit(IS_REP + self.state as usize, 0);
        self.match_(pos_state, u32::MAX, MATCH_LEN_MIN);
    }

    /// `lzma_lzma_encode`: encodes from `mf` to `out` until the input
    /// runs out, or, when `limit` is not u32::MAX (LZMA2), until the chunk
    /// is full.
    pub(crate) fn encode(
        &mut self,
        mf: &mut Mf,
        out: &mut [u8],
        out_pos: &mut usize,
        limit: u32,
    ) -> Ret {
        // Initialize the stream if no data has been encoded yet.
        if !self.is_initialized && !self.encode_init(mf) {
            return Ret::Ok;
        }

        // Encode pending output bytes from the range encoder. At the start
        // of the stream, encode_init() encodes one literal. Later there can
        // be pending output only with LZMA1 because LZMA2 ensures that
        // there is always enough output space. Thus when using LZMA2,
        // rc_encode() calls in this function will always return false.
        if self.rc.encode(&mut self.p[..], out, out_pos) {
            // We don't get here with LZMA2.
            return Ret::Ok;
        }

        // If the range encoder was flushed in an earlier call to this
        // function but there wasn't enough output buffer space, those
        // bytes would have now been encoded by the above rc_encode() call
        // and the stream has now been finished. This can only happen with
        // LZMA1 as LZMA2 always provides enough output buffer space.
        if self.is_flushed {
            return Ret::StreamEnd;
        }

        loop {
            // With LZMA2 we need to take care that compressed size of a
            // chunk doesn't get too big.
            if limit != u32::MAX
                && (mf.read_pos - mf.read_ahead >= limit
                    || *out_pos as u64 + self.rc.pending()
                        >= u64::from(LZMA2_CHUNK_MAX - LOOP_INPUT_MAX))
            {
                break;
            }

            // Check that there is some input to process.
            if mf.read_pos >= mf.read_limit {
                if mf.action == Action::Run {
                    return Ret::Ok;
                }

                if mf.read_ahead == 0 {
                    break;
                }
            }

            // Get optimal match (repeat position and length). Value ranges
            // for pos:
            //   - [0, REPS): repeated match
            //   - [REPS, UINT32_MAX): match at (pos - REPS)
            //   - UINT32_MAX: not a match but a literal
            // Value ranges for len:
            //   - [MATCH_LEN_MIN, MATCH_LEN_MAX]
            let (back, len) = if self.fast_mode {
                self.optimum_fast(mf)
            } else {
                self.optimum_normal(mf, self.uncomp_size as u32)
            };

            self.encode_symbol(mf, back, len, self.uncomp_size as u32);

            // This symbol will be encoded so update the uncompressed size.
            self.uncomp_size += u64::from(len);

            // Encode the LZMA symbol.
            if self.rc.encode(&mut self.p[..], out, out_pos) {
                // Once again, this can only happen with LZMA1.
                return Ret::Ok;
            }
        }

        // LZMA2 doesn't use EOPM at LZMA level.
        //
        // Plain LZMA streams without EOPM aren't supported except when
        // output size limiting is enabled.
        if self.use_eopm {
            self.encode_eopm(self.uncomp_size as u32);
        }

        // Flush the remaining bytes from the range encoder.
        self.rc.flush();

        // Copy the remaining bytes to the output buffer. If there isn't
        // enough output space, we will copy out the remaining bytes on the
        // next call to this function.
        if self.rc.encode(&mut self.p[..], out, out_pos) {
            // This cannot happen with LZMA2.
            self.is_flushed = true;
            return Ret::Ok;
        }

        Ret::StreamEnd
    }

    /// `lzma_encode`: the LZ encoder's `code` for plain LZMA.
    pub(crate) fn lzma_encode(&mut self, mf: &mut Mf, out: &mut [u8], out_pos: &mut usize) -> Ret {
        // Plain LZMA has no support for sync-flushing.
        if mf.action == Action::SyncFlush {
            return Ret::OptionsError;
        }

        self.encode(mf, out, out_pos, u32::MAX)
    }

    // lzma_encoder_optimum_fast.c

    /// `lzma_lzma_optimum_fast`: `(back, len)`.
    fn optimum_fast(&mut self, mf: &mut Mf) -> (u32, u32) {
        let nice_len = mf.nice_len;

        let (mut len_main, mut matches_count) = if mf.read_ahead == 0 {
            mf.find(&mut self.matches)
        } else {
            (self.longest_match_length, self.matches_count)
        };

        let mut buf = mf.ptr() - 1;
        let buf_avail = (mf.avail() + 1).min(MATCH_LEN_MAX);

        if buf_avail < 2 {
            // There's not enough input left to encode a match.
            return (u32::MAX, 1);
        }

        // Look for repeated matches; scan the previous four match
        // distances
        let mut rep_len = 0;
        let mut rep_index = 0;

        for i in 0..REPS as u32 {
            // The beginning of the match candidate
            let buf_back = buf - self.reps[i as usize] as usize - 1;

            // If the first two bytes (2 == MATCH_LEN_MIN) do not match,
            // this rep is not useful.
            if not_equal_16(&mf.buffer, buf, buf_back) {
                continue;
            }

            // The first two bytes matched. Calculate the length of the
            // match.
            let len = memcmplen(&mf.buffer, buf, buf_back, 2, buf_avail);

            // If we have found a repeated match that is at least nice_len
            // long, return it immediately.
            if len >= nice_len {
                mf.skip(len - 1);
                return (i, len);
            }

            if len > rep_len {
                rep_index = i;
                rep_len = len;
            }
        }

        // We didn't find a long enough repeated match. Encode it as a
        // normal match if the match length is at least nice_len.
        if len_main >= nice_len {
            let back = self.matches[matches_count as usize - 1].dist + REPS as u32;
            mf.skip(len_main - 1);
            return (back, len_main);
        }

        let mut back_main = 0;
        if len_main >= 2 {
            back_main = self.matches[matches_count as usize - 1].dist;

            while matches_count > 1 && len_main == self.matches[matches_count as usize - 2].len + 1
            {
                if !change_pair(self.matches[matches_count as usize - 2].dist, back_main) {
                    break;
                }

                matches_count -= 1;
                len_main = self.matches[matches_count as usize - 1].len;
                back_main = self.matches[matches_count as usize - 1].dist;
            }

            if len_main == 2 && back_main >= 0x80 {
                len_main = 1;
            }
        }

        if rep_len >= 2
            && (rep_len + 1 >= len_main
                || (rep_len + 2 >= len_main && back_main > (1 << 9))
                || (rep_len + 3 >= len_main && back_main > (1 << 15)))
        {
            mf.skip(rep_len - 1);
            return (rep_index, rep_len);
        }

        if len_main < 2 || buf_avail <= 2 {
            return (u32::MAX, 1);
        }

        // Get the matches for the next byte. If we find a better match, the
        // current byte is encoded as a literal.
        let (longest, count) = mf.find(&mut self.matches);
        self.longest_match_length = longest;
        self.matches_count = count;

        if self.longest_match_length >= 2 {
            let new_dist = self.matches[self.matches_count as usize - 1].dist;

            if (self.longest_match_length >= len_main && new_dist < back_main)
                || (self.longest_match_length == len_main + 1 && !change_pair(back_main, new_dist))
                || (self.longest_match_length > len_main + 1)
                || (self.longest_match_length + 1 >= len_main
                    && len_main >= 3
                    && change_pair(new_dist, back_main))
            {
                return (u32::MAX, 1);
            }
        }

        // In contrast to LZMA SDK, dictionary could not have been moved
        // between mf_find() calls, thus it is safe to just increment the
        // old buf pointer instead of recalculating it with mf_ptr().
        buf += 1;

        let limit = 2u32.max(len_main - 1) as usize;

        for i in 0..REPS {
            let back = buf - self.reps[i] as usize - 1;
            if mf.buffer[buf..buf + limit] == mf.buffer[back..back + limit] {
                return (u32::MAX, 1);
            }
        }

        mf.skip(len_main - 2);
        (back_main + REPS as u32, len_main)
    }

    // lzma_encoder_optimum_normal.c: Prices

    /// `get_literal_price`.
    fn get_literal_price(
        &self,
        pos: u32,
        prev_byte: u32,
        match_mode: bool,
        mut match_byte: u32,
        mut symbol: u32,
    ) -> u32 {
        let subcoder =
            literal_subcoder(self.literal_context_bits, self.literal_mask, pos, prev_byte);
        let p = &self.p[..];

        let mut price = 0;

        if !match_mode {
            price = bittree_price(p, subcoder, 8, symbol);
        } else {
            let mut offset = 0x100;
            symbol += 1 << 8;

            loop {
                match_byte <<= 1;

                let match_bit = match_byte & offset;
                let subcoder_index = offset + match_bit + (symbol >> 8);
                let bit = (symbol >> 7) & 1;
                price += bit_price(p[subcoder + subcoder_index as usize], bit);

                symbol <<= 1;
                offset &= !(match_byte ^ symbol);
                if symbol >= 1 << 16 {
                    break;
                }
            }
        }

        price
    }

    /// `get_short_rep_price`.
    #[inline(always)]
    fn get_short_rep_price(&self, state: u32, pos_state: u32) -> u32 {
        bit_0_price(self.p[IS_REP0 + state as usize])
            + bit_0_price(
                self.p[IS_REP0_LONG + state as usize * POS_STATES_MAX + pos_state as usize],
            )
    }

    /// `get_pure_rep_price`.
    #[inline(always)]
    fn get_pure_rep_price(&self, rep_index: u32, state: u32, pos_state: u32) -> u32 {
        let p = &self.p[..];
        let state = state as usize;
        let mut price;

        if rep_index == 0 {
            price = bit_0_price(p[IS_REP0 + state]);
            price += bit_1_price(p[IS_REP0_LONG + state * POS_STATES_MAX + pos_state as usize]);
        } else {
            price = bit_1_price(p[IS_REP0 + state]);

            if rep_index == 1 {
                price += bit_0_price(p[IS_REP1 + state]);
            } else {
                price += bit_1_price(p[IS_REP1 + state]);
                price += bit_price(p[IS_REP2 + state], rep_index - 2);
            }
        }

        price
    }

    /// `get_rep_price`.
    #[inline(always)]
    fn get_rep_price(&self, rep_index: u32, len: u32, state: u32, pos_state: u32) -> u32 {
        self.rep_len_encoder.price(len, pos_state)
            + self.get_pure_rep_price(rep_index, state, pos_state)
    }

    /// `get_dist_len_price`.
    #[inline(always)]
    fn get_dist_len_price(&self, dist: u32, len: u32, pos_state: u32) -> u32 {
        let dist_state = get_dist_state(len) as usize;
        let mut price;

        if dist < FULL_DISTANCES {
            price = self.dist_prices[dist_state][dist as usize];
        } else {
            let dist_slot = get_dist_slot_2(dist);
            price = self.dist_slot_prices[dist_state][dist_slot as usize]
                + self.align_prices[(dist & ALIGN_MASK) as usize];
        }

        price += self.match_len_encoder.price(len, pos_state);

        price
    }

    /// `fill_dist_prices`.
    fn fill_dist_prices(&mut self) {
        let p = &self.p[..];
        for dist_state in 0..DIST_STATES as usize {
            let dist_slot_prices = &mut self.dist_slot_prices[dist_state];

            // Price to encode the dist_slot.
            for dist_slot in 0..self.dist_table_size {
                dist_slot_prices[dist_slot as usize] = bittree_price(
                    p,
                    DIST_SLOT + dist_state * DIST_SLOTS as usize,
                    DIST_SLOT_BITS,
                    dist_slot,
                );
            }

            // For matches with distance >= FULL_DISTANCES, add the price
            // of the direct bits part of the match distance. (Align bits
            // are handled by fill_align_prices()).
            for dist_slot in DIST_MODEL_END..self.dist_table_size {
                dist_slot_prices[dist_slot as usize] +=
                    direct_price(((dist_slot >> 1) - 1) - ALIGN_BITS);
            }

            // Distances in the range [0, 3] are fully encoded with
            // dist_slot, so they are used for coder->dist_prices as is.
            let start = DIST_MODEL_START as usize;
            self.dist_prices[dist_state][..start].copy_from_slice(&dist_slot_prices[..start]);
        }

        // Distances in the range [4, 127] depend on dist_slot and
        // dist_special. We do this in a loop separate from the above loop
        // to avoid redundant calls to get_dist_slot().
        for i in DIST_MODEL_START..FULL_DISTANCES {
            let dist_slot = get_dist_slot(i);
            let footer_bits = (dist_slot >> 1) - 1;
            let base = (2 | (dist_slot & 1)) << footer_bits;
            let price = bittree_reverse_price(
                p,
                POS_SPECIAL + base as usize - dist_slot as usize - 1,
                footer_bits,
                i - base,
            );

            for dist_state in 0..DIST_STATES as usize {
                self.dist_prices[dist_state][i as usize] =
                    price + self.dist_slot_prices[dist_state][dist_slot as usize];
            }
        }

        self.match_price_count = 0;
    }

    /// `fill_align_prices`.
    fn fill_align_prices(&mut self) {
        for i in 0..ALIGN_SIZE {
            self.align_prices[i as usize] =
                bittree_reverse_price(&self.p[..], POS_ALIGN, ALIGN_BITS, i);
        }

        self.align_price_count = 0;
    }

    // Optimal

    /// `backward`: `(len, back)`.
    fn backward(&mut self, mut cur: u32) -> (u32, u32) {
        self.opts_end_index = cur;

        let opts = &mut self.opts;
        let mut pos_mem = opts[cur as usize].pos_prev;
        let mut back_mem = opts[cur as usize].back_prev;

        loop {
            if opts[cur as usize].prev_1_is_literal {
                opts[pos_mem as usize].make_literal();
                opts[pos_mem as usize].pos_prev = pos_mem.wrapping_sub(1);

                if opts[cur as usize].prev_2 {
                    let (pos_prev_2, back_prev_2) = (
                        opts[cur as usize].pos_prev_2,
                        opts[cur as usize].back_prev_2,
                    );
                    let before = &mut opts[pos_mem as usize - 1];
                    before.prev_1_is_literal = false;
                    before.pos_prev = pos_prev_2;
                    before.back_prev = back_prev_2;
                }
            }

            let pos_prev = pos_mem;
            let back_cur = back_mem;

            back_mem = opts[pos_prev as usize].back_prev;
            pos_mem = opts[pos_prev as usize].pos_prev;

            opts[pos_prev as usize].back_prev = back_cur;
            opts[pos_prev as usize].pos_prev = cur;
            cur = pos_prev;
            if cur == 0 {
                break;
            }
        }

        self.opts_current_index = self.opts[0].pos_prev;
        (self.opts[0].pos_prev, self.opts[0].back_prev)
    }

    /// `helper1`: the first position; `Err((back, len))` when the result
    /// is already known.
    fn helper1(&mut self, mf: &mut Mf, position: u32) -> Result<u32, (u32, u32)> {
        let nice_len = mf.nice_len;

        let (len_main, matches_count) = if mf.read_ahead == 0 {
            mf.find(&mut self.matches)
        } else {
            (self.longest_match_length, self.matches_count)
        };

        let buf_avail = (mf.avail() + 1).min(MATCH_LEN_MAX);
        if buf_avail < 2 {
            return Err((u32::MAX, 1));
        }

        let buf = mf.ptr() - 1;

        let mut rep_lens = [0u32; REPS];
        let mut rep_max_index = 0;

        for i in 0..REPS {
            let buf_back = buf - self.reps[i] as usize - 1;

            if not_equal_16(&mf.buffer, buf, buf_back) {
                rep_lens[i] = 0;
                continue;
            }

            rep_lens[i] = memcmplen(&mf.buffer, buf, buf_back, 2, buf_avail);

            if rep_lens[i] > rep_lens[rep_max_index] {
                rep_max_index = i;
            }
        }

        if rep_lens[rep_max_index] >= nice_len {
            let len = rep_lens[rep_max_index];
            mf.skip(len - 1);
            return Err((rep_max_index as u32, len));
        }

        if len_main >= nice_len {
            let back = self.matches[matches_count as usize - 1].dist + REPS as u32;
            mf.skip(len_main - 1);
            return Err((back, len_main));
        }

        let current_byte = mf.buffer[buf];
        let match_byte = mf.buffer[buf - self.reps[0] as usize - 1];

        if len_main < 2 && current_byte != match_byte && rep_lens[rep_max_index] < 2 {
            return Err((u32::MAX, 1));
        }

        self.opts[0].state = self.state;

        let pos_state = position & self.pos_mask;
        let is_match = IS_MATCH + self.state as usize * POS_STATES_MAX + pos_state as usize;

        self.opts[1].price = bit_0_price(self.p[is_match])
            + self.get_literal_price(
                position,
                u32::from(mf.buffer[buf - 1]),
                !is_literal_state(self.state),
                u32::from(match_byte),
                u32::from(current_byte),
            );

        self.opts[1].make_literal();

        let match_price = bit_1_price(self.p[is_match]);
        let rep_match_price = match_price + bit_1_price(self.p[IS_REP + self.state as usize]);

        if match_byte == current_byte {
            let short_rep_price = rep_match_price + self.get_short_rep_price(self.state, pos_state);

            if short_rep_price < self.opts[1].price {
                self.opts[1].price = short_rep_price;
                self.opts[1].make_short_rep();
            }
        }

        let len_end = len_main.max(rep_lens[rep_max_index]);

        if len_end < 2 {
            return Err((self.opts[1].back_prev, 1));
        }

        self.opts[1].pos_prev = 0;

        self.opts[0].backs = self.reps;

        let mut len = len_end;
        loop {
            self.opts[len as usize].price = RC_INFINITY_PRICE;
            len -= 1;
            if len < 2 {
                break;
            }
        }

        for (i, &rep_len) in rep_lens.iter().enumerate() {
            let mut rep_len = rep_len;
            if rep_len < 2 {
                continue;
            }

            let price = rep_match_price + self.get_pure_rep_price(i as u32, self.state, pos_state);

            loop {
                let cur_and_len_price = price + self.rep_len_encoder.price(rep_len, pos_state);

                let opt = &mut self.opts[rep_len as usize];
                if cur_and_len_price < opt.price {
                    opt.price = cur_and_len_price;
                    opt.pos_prev = 0;
                    opt.back_prev = i as u32;
                    opt.prev_1_is_literal = false;
                }
                rep_len -= 1;
                if rep_len < 2 {
                    break;
                }
            }
        }

        let normal_match_price = match_price + bit_0_price(self.p[IS_REP + self.state as usize]);

        len = if rep_lens[0] >= 2 { rep_lens[0] + 1 } else { 2 };
        if len <= len_main {
            let mut i = 0;
            while len > self.matches[i].len {
                i += 1;
            }

            loop {
                let dist = self.matches[i].dist;
                let cur_and_len_price =
                    normal_match_price + self.get_dist_len_price(dist, len, pos_state);

                let opt = &mut self.opts[len as usize];
                if cur_and_len_price < opt.price {
                    opt.price = cur_and_len_price;
                    opt.pos_prev = 0;
                    opt.back_prev = dist + REPS as u32;
                    opt.prev_1_is_literal = false;
                }

                if len == self.matches[i].len {
                    i += 1;
                    if i == matches_count as usize {
                        break;
                    }
                }
                len += 1;
            }
        }

        Ok(len_end)
    }

    /// `helper2`: the positions after the first.
    #[allow(clippy::too_many_arguments)]
    fn helper2(
        &mut self,
        mfbuf: &[u8],
        reps: &mut [u32; REPS],
        buf: usize,
        mut len_end: u32,
        position: u32,
        cur: u32,
        nice_len: u32,
        buf_avail_full: u32,
    ) -> u32 {
        let mut matches_count = self.matches_count;
        let mut new_len = self.longest_match_length;
        let cur_u = cur as usize;
        let mut pos_prev = self.opts[cur_u].pos_prev;
        let mut state;

        if self.opts[cur_u].prev_1_is_literal {
            pos_prev -= 1;

            if self.opts[cur_u].prev_2 {
                state = self.opts[self.opts[cur_u].pos_prev_2 as usize].state;

                if self.opts[cur_u].back_prev_2 < REPS as u32 {
                    state = update_long_rep(state);
                } else {
                    state = update_match(state);
                }
            } else {
                state = self.opts[pos_prev as usize].state;
            }

            state = update_literal(state);
        } else {
            state = self.opts[pos_prev as usize].state;
        }

        if pos_prev == cur - 1 {
            if self.opts[cur_u].is_short_rep() {
                state = update_short_rep(state);
            } else {
                state = update_literal(state);
            }
        } else {
            let pos;
            if self.opts[cur_u].prev_1_is_literal && self.opts[cur_u].prev_2 {
                pos_prev = self.opts[cur_u].pos_prev_2;
                pos = self.opts[cur_u].back_prev_2;
                state = update_long_rep(state);
            } else {
                pos = self.opts[cur_u].back_prev;
                if pos < REPS as u32 {
                    state = update_long_rep(state);
                } else {
                    state = update_match(state);
                }
            }

            let backs = self.opts[pos_prev as usize].backs;
            if pos < REPS as u32 {
                reps[0] = backs[pos as usize];

                let mut i = 1;
                while i <= pos as usize {
                    reps[i] = backs[i - 1];
                    i += 1;
                }
                while i < REPS {
                    reps[i] = backs[i];
                    i += 1;
                }
            } else {
                reps[0] = pos - REPS as u32;

                reps[1..].copy_from_slice(&backs[..REPS - 1]);
            }
        }

        self.opts[cur_u].state = state;
        self.opts[cur_u].backs = *reps;

        let cur_price = self.opts[cur_u].price;

        let current_byte = mfbuf[buf];
        let match_byte = mfbuf[buf - reps[0] as usize - 1];

        let pos_state = position & self.pos_mask;
        let is_match = IS_MATCH + state as usize * POS_STATES_MAX + pos_state as usize;

        let cur_and_1_price = cur_price
            + bit_0_price(self.p[is_match])
            + self.get_literal_price(
                position,
                u32::from(mfbuf[buf - 1]),
                !is_literal_state(state),
                u32::from(match_byte),
                u32::from(current_byte),
            );

        let mut next_is_literal = false;

        if cur_and_1_price < self.opts[cur_u + 1].price {
            let opt = &mut self.opts[cur_u + 1];
            opt.price = cur_and_1_price;
            opt.pos_prev = cur;
            opt.make_literal();
            next_is_literal = true;
        }

        let match_price = cur_price + bit_1_price(self.p[is_match]);
        let rep_match_price = match_price + bit_1_price(self.p[IS_REP + state as usize]);

        if match_byte == current_byte
            && !(self.opts[cur_u + 1].pos_prev < cur && self.opts[cur_u + 1].back_prev == 0)
        {
            let short_rep_price = rep_match_price + self.get_short_rep_price(state, pos_state);

            if short_rep_price <= self.opts[cur_u + 1].price {
                let opt = &mut self.opts[cur_u + 1];
                opt.price = short_rep_price;
                opt.pos_prev = cur;
                opt.make_short_rep();
                next_is_literal = true;
            }
        }

        if buf_avail_full < 2 {
            return len_end;
        }

        let buf_avail = buf_avail_full.min(nice_len);

        if !next_is_literal && match_byte != current_byte {
            // speed optimization
            // try literal + rep0
            let buf_back = buf - reps[0] as usize - 1;
            let limit = buf_avail_full.min(nice_len + 1);

            let len_test = memcmplen(mfbuf, buf, buf_back, 1, limit) - 1;

            if len_test >= 2 {
                let state_2 = update_literal(state);

                let pos_state_next = (position + 1) & self.pos_mask;
                let next_rep_match_price = cur_and_1_price
                    + bit_1_price(
                        self.p[IS_MATCH
                            + state_2 as usize * POS_STATES_MAX
                            + pos_state_next as usize],
                    )
                    + bit_1_price(self.p[IS_REP + state_2 as usize]);

                let offset = cur + 1 + len_test;

                while len_end < offset {
                    len_end += 1;
                    self.opts[len_end as usize].price = RC_INFINITY_PRICE;
                }

                let cur_and_len_price =
                    next_rep_match_price + self.get_rep_price(0, len_test, state_2, pos_state_next);

                let opt = &mut self.opts[offset as usize];
                if cur_and_len_price < opt.price {
                    opt.price = cur_and_len_price;
                    opt.pos_prev = cur + 1;
                    opt.back_prev = 0;
                    opt.prev_1_is_literal = true;
                    opt.prev_2 = false;
                }
            }
        }

        let mut start_len = 2; // speed optimization

        for rep_index in 0..REPS as u32 {
            let buf_back = buf - reps[rep_index as usize] as usize - 1;
            if not_equal_16(mfbuf, buf, buf_back) {
                continue;
            }

            let mut len_test = memcmplen(mfbuf, buf, buf_back, 2, buf_avail);

            while len_end < cur + len_test {
                len_end += 1;
                self.opts[len_end as usize].price = RC_INFINITY_PRICE;
            }

            let len_test_temp = len_test;
            let price = rep_match_price + self.get_pure_rep_price(rep_index, state, pos_state);

            loop {
                let cur_and_len_price = price + self.rep_len_encoder.price(len_test, pos_state);

                let opt = &mut self.opts[(cur + len_test) as usize];
                if cur_and_len_price < opt.price {
                    opt.price = cur_and_len_price;
                    opt.pos_prev = cur;
                    opt.back_prev = rep_index;
                    opt.prev_1_is_literal = false;
                }
                len_test -= 1;
                if len_test < 2 {
                    break;
                }
            }

            len_test = len_test_temp;

            if rep_index == 0 {
                start_len = len_test + 1;
            }

            let mut len_test_2 = len_test + 1;
            let limit = buf_avail_full.min(len_test_2 + nice_len);
            // NOTE: len_test_2 may be greater than limit so the call to
            // lzma_memcmplen() must be done conditionally.
            if len_test_2 < limit {
                len_test_2 = memcmplen(mfbuf, buf, buf_back, len_test_2, limit);
            }

            len_test_2 -= len_test + 1;

            if len_test_2 >= 2 {
                let mut state_2 = update_long_rep(state);

                let mut pos_state_next = (position + len_test) & self.pos_mask;

                let cur_and_len_literal_price = price
                    + self.rep_len_encoder.price(len_test, pos_state)
                    + bit_0_price(
                        self.p[IS_MATCH
                            + state_2 as usize * POS_STATES_MAX
                            + pos_state_next as usize],
                    )
                    + self.get_literal_price(
                        position + len_test,
                        u32::from(mfbuf[buf + len_test as usize - 1]),
                        true,
                        u32::from(mfbuf[buf_back + len_test as usize]),
                        u32::from(mfbuf[buf + len_test as usize]),
                    );

                state_2 = update_literal(state_2);

                pos_state_next = (position + len_test + 1) & self.pos_mask;

                let next_rep_match_price = cur_and_len_literal_price
                    + bit_1_price(
                        self.p[IS_MATCH
                            + state_2 as usize * POS_STATES_MAX
                            + pos_state_next as usize],
                    )
                    + bit_1_price(self.p[IS_REP + state_2 as usize]);

                let offset = cur + len_test + 1 + len_test_2;

                while len_end < offset {
                    len_end += 1;
                    self.opts[len_end as usize].price = RC_INFINITY_PRICE;
                }

                let cur_and_len_price = next_rep_match_price
                    + self.get_rep_price(0, len_test_2, state_2, pos_state_next);

                let opt = &mut self.opts[offset as usize];
                if cur_and_len_price < opt.price {
                    opt.price = cur_and_len_price;
                    opt.pos_prev = cur + len_test + 1;
                    opt.back_prev = 0;
                    opt.prev_1_is_literal = true;
                    opt.prev_2 = true;
                    opt.pos_prev_2 = cur;
                    opt.back_prev_2 = rep_index;
                }
            }
        }

        if new_len > buf_avail {
            new_len = buf_avail;

            matches_count = 0;
            while new_len > self.matches[matches_count as usize].len {
                matches_count += 1;
            }

            self.matches[matches_count as usize].len = new_len;
            matches_count += 1;
        }

        if new_len >= start_len {
            let normal_match_price = match_price + bit_0_price(self.p[IS_REP + state as usize]);

            while len_end < cur + new_len {
                len_end += 1;
                self.opts[len_end as usize].price = RC_INFINITY_PRICE;
            }

            let mut i = 0;
            while start_len > self.matches[i].len {
                i += 1;
            }

            let mut len_test = start_len;
            loop {
                let cur_back = self.matches[i].dist;
                let mut cur_and_len_price =
                    normal_match_price + self.get_dist_len_price(cur_back, len_test, pos_state);

                let opt = &mut self.opts[(cur + len_test) as usize];
                if cur_and_len_price < opt.price {
                    opt.price = cur_and_len_price;
                    opt.pos_prev = cur;
                    opt.back_prev = cur_back + REPS as u32;
                    opt.prev_1_is_literal = false;
                }

                if len_test == self.matches[i].len {
                    // Try Match + Literal + Rep0
                    let buf_back = buf - cur_back as usize - 1;
                    let mut len_test_2 = len_test + 1;
                    let limit = buf_avail_full.min(len_test_2 + nice_len);

                    // NOTE: len_test_2 may be greater than limit so the
                    // call to lzma_memcmplen() must be done conditionally.
                    if len_test_2 < limit {
                        len_test_2 = memcmplen(mfbuf, buf, buf_back, len_test_2, limit);
                    }

                    len_test_2 -= len_test + 1;

                    if len_test_2 >= 2 {
                        let mut state_2 = update_match(state);
                        let mut pos_state_next = (position + len_test) & self.pos_mask;

                        let cur_and_len_literal_price = cur_and_len_price
                            + bit_0_price(
                                self.p[IS_MATCH
                                    + state_2 as usize * POS_STATES_MAX
                                    + pos_state_next as usize],
                            )
                            + self.get_literal_price(
                                position + len_test,
                                u32::from(mfbuf[buf + len_test as usize - 1]),
                                true,
                                u32::from(mfbuf[buf_back + len_test as usize]),
                                u32::from(mfbuf[buf + len_test as usize]),
                            );

                        state_2 = update_literal(state_2);
                        pos_state_next = (pos_state_next + 1) & self.pos_mask;

                        let next_rep_match_price = cur_and_len_literal_price
                            + bit_1_price(
                                self.p[IS_MATCH
                                    + state_2 as usize * POS_STATES_MAX
                                    + pos_state_next as usize],
                            )
                            + bit_1_price(self.p[IS_REP + state_2 as usize]);

                        let offset = cur + len_test + 1 + len_test_2;

                        while len_end < offset {
                            len_end += 1;
                            self.opts[len_end as usize].price = RC_INFINITY_PRICE;
                        }

                        cur_and_len_price = next_rep_match_price
                            + self.get_rep_price(0, len_test_2, state_2, pos_state_next);

                        let opt = &mut self.opts[offset as usize];
                        if cur_and_len_price < opt.price {
                            opt.price = cur_and_len_price;
                            opt.pos_prev = cur + len_test + 1;
                            opt.back_prev = 0;
                            opt.prev_1_is_literal = true;
                            opt.prev_2 = true;
                            opt.pos_prev_2 = cur;
                            opt.back_prev_2 = cur_back + REPS as u32;
                        }
                    }

                    i += 1;
                    if i == matches_count as usize {
                        break;
                    }
                }
                len_test += 1;
            }
        }

        len_end
    }

    /// `lzma_lzma_optimum_normal`: `(back, len)`.
    fn optimum_normal(&mut self, mf: &mut Mf, position: u32) -> (u32, u32) {
        // If we have symbols pending, return the next pending symbol.
        if self.opts_end_index != self.opts_current_index {
            let current = self.opts_current_index as usize;
            let len = self.opts[current].pos_prev - self.opts_current_index;
            let back = self.opts[current].back_prev;
            self.opts_current_index = self.opts[current].pos_prev;
            return (back, len);
        }

        // Update the price tables. In LZMA SDK <= 4.60 (and possibly
        // later) this was done in both initialization function and in the
        // main loop. In liblzma they were moved into this single place.
        if mf.read_ahead == 0 {
            if self.match_price_count >= 1 << 7 {
                self.fill_dist_prices();
            }

            if self.align_price_count >= ALIGN_SIZE {
                self.fill_align_prices();
            }
        }

        // TODO: This needs quite a bit of cleaning still. But splitting the
        // original function into two pieces makes it at least a little
        // more readable, since those two parts don't share many variables.

        let mut len_end = match self.helper1(mf, position) {
            Ok(len_end) => len_end,
            Err(result) => return result,
        };

        let mut reps = self.reps;

        let mut cur = 1;
        while cur < len_end {
            let (longest, count) = mf.find(&mut self.matches);
            self.longest_match_length = longest;
            self.matches_count = count;

            if self.longest_match_length >= mf.nice_len {
                break;
            }

            let buf_avail_full = (mf.avail() + 1).min(OPTS as u32 - 1 - cur);
            len_end = self.helper2(
                &mf.buffer,
                &mut reps,
                mf.ptr() - 1,
                len_end,
                position + cur,
                cur,
                mf.nice_len,
                buf_avail_full,
            );
            cur += 1;
        }

        let (len, back) = self.backward(cur);
        (back, len)
    }
}

/// `length_encoder_reset`.
fn length_encoder_reset(
    p: &mut [Probability],
    lencoder: &mut LengthEncoder,
    num_pos_states: u32,
    fast_mode: bool,
) {
    let base = lencoder.base;
    p[base + LEN_CHOICE] = PROB_INIT;
    p[base + LEN_CHOICE2] = PROB_INIT;

    for pos_state in 0..num_pos_states as usize {
        let low = base + LEN_LOW + pos_state * LEN_LOW_SYMBOLS as usize;
        p[low..low + LEN_LOW_SYMBOLS as usize].fill(PROB_INIT);
        let mid = base + LEN_MID + pos_state * LEN_MID_SYMBOLS as usize;
        p[mid..mid + LEN_MID_SYMBOLS as usize].fill(PROB_INIT);
    }

    p[base + LEN_HIGH..base + LEN_HIGH + LEN_HIGH_SYMBOLS as usize].fill(PROB_INIT);

    if !fast_mode {
        for pos_state in 0..num_pos_states {
            lencoder.update_prices(p, pos_state);
        }
    }
}

/// `is_options_valid`.
fn is_options_valid(options: &LzmaOptions) -> bool {
    // Validate some of the options. LZ encoder validates nice_len too but
    // we need a valid value here earlier.
    is_lclppb_valid(options)
        && options.nice_len >= MATCH_LEN_MIN
        && options.nice_len <= MATCH_LEN_MAX
        && (options.mode == Mode::FAST || options.mode == Mode::NORMAL)
}

/// `set_lz_options`.
fn set_lz_options(options: &LzmaOptions) -> LzEncOptions {
    // LZ encoder initialization does the validation for these so we don't
    // need to validate here.
    LzEncOptions {
        before_size: OPTS as u32,
        dict_size: options.dict_size,
        after_size: LOOP_INPUT_MAX,
        match_len_max: MATCH_LEN_MAX,
        nice_len: mf_get_hash_bytes(options.mf).max(options.nice_len),
        match_finder: options.mf,
        depth: options.depth,
        preset_dict: options.preset_dict.clone(),
    }
}

/// `lzma_lzma_encoder_memusage`.
pub(crate) fn encoder_memusage(options: &LzmaOptions) -> u64 {
    if !is_options_valid(options) {
        return u64::MAX;
    }

    let lz_options = set_lz_options(options);

    let lz_memusage = lz_encoder_memusage(&lz_options);
    if lz_memusage == u64::MAX {
        return u64::MAX;
    }

    LZMA1_ENCODER_SIZE + lz_memusage
}

/// `lzma_lzma_lclppb_encode`: lc, lp and pb in one byte; None if they
/// are invalid.
pub(crate) fn lclppb_encode(options: &LzmaOptions) -> Option<u8> {
    if !is_lclppb_valid(options) {
        return None;
    }

    Some(((options.pb * 5 + options.lp) * 9 + options.lc) as u8)
}

/// `lzma_lzma_props_encode`: the five bytes of properties of LZMA1.
pub(crate) fn props_encode(options: &LzmaOptions, out: &mut [u8]) -> Ret {
    let Some(byte) = lclppb_encode(options) else {
        return Ret::ProgError;
    };
    out[0] = byte;
    write32le(&mut out[1..], options.dict_size);
    Ret::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The slots as liblzma's `lzma_fastpos` table gives them, from
    /// `fastpos_tablegen.c`.
    #[test]
    fn dist_slots_are_fastpos() {
        const FASTPOS_BITS: u32 = 13;
        let mut fastpos = vec![0u8; 1 << FASTPOS_BITS];
        fastpos[0] = 0;
        fastpos[1] = 1;
        let mut c = 2;
        for slot_fast in 2..(2 * FASTPOS_BITS) as u8 {
            let k = 1usize << ((slot_fast >> 1) - 1);
            for _ in 0..k {
                fastpos[c] = slot_fast;
                c += 1;
            }
        }
        let get = |dist: u32| -> u32 {
            // fastpos.h without HAVE_SMALL
            let shift = |n: u32| n * (FASTPOS_BITS - 1);
            if dist < 1 << FASTPOS_BITS {
                u32::from(fastpos[dist as usize])
            } else if dist < 1 << (FASTPOS_BITS + shift(1)) {
                u32::from(fastpos[(dist >> shift(1)) as usize]) + 2 * shift(1)
            } else {
                u32::from(fastpos[(dist >> shift(2)) as usize]) + 2 * shift(2)
            }
        };
        let mut dist = 0u32;
        loop {
            assert_eq!(get_dist_slot(dist), get(dist), "{dist}");
            if dist > u32::MAX / 3 {
                break;
            }
            dist = if dist < 100_000 {
                dist + 1
            } else {
                dist * 3 / 2 + 7
            };
        }
        assert_eq!(get_dist_slot(u32::MAX), get(u32::MAX));
    }
}
