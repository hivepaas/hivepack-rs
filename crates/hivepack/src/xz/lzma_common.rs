//! What the LZMA encoder and decoder share: port of
//! `lzma/lzma_common.h`, and the LZMA options of `api/lzma/lzma12.h`.

/// `LZMA_LCLP_MAX`.
pub const LCLP_MAX: u32 = 4;
/// `LZMA_PB_MAX`.
pub const PB_MAX: u32 = 4;
/// `LZMA_DICT_SIZE_MIN`.
pub const DICT_SIZE_MIN: u32 = 4096;
/// `LZMA_LZMA1EXT_ALLOW_EOPM`.
pub const LZMA1EXT_ALLOW_EOPM: u32 = 0x01;

/// `LZMA_DICT_SIZE_DEFAULT`.
pub const DICT_SIZE_DEFAULT: u32 = 1 << 23;
/// `LZMA_LC_DEFAULT`.
pub const LC_DEFAULT: u32 = 3;
/// `LZMA_LP_DEFAULT`.
pub const LP_DEFAULT: u32 = 0;
/// `LZMA_PB_DEFAULT`.
pub const PB_DEFAULT: u32 = 2;
/// `LZMA_PRESET_DEFAULT`.
pub const PRESET_DEFAULT: u32 = 6;
/// `LZMA_PRESET_LEVEL_MASK`.
pub const PRESET_LEVEL_MASK: u32 = 0x1F;
/// `LZMA_PRESET_EXTREME`.
pub const PRESET_EXTREME: u32 = 1 << 31;

/// `lzma_match_finder`: the match finder of the encoder, with liblzma's
/// numbers. The low four bits are the bytes hashed; bit 4 is set for
/// the binary trees. Other numbers can be given, and are refused.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MatchFinder(pub u32);

impl MatchFinder {
    /// `LZMA_MF_HC3`: hash chain, 2- and 3-byte hashing.
    pub const HC3: MatchFinder = MatchFinder(0x03);
    /// `LZMA_MF_HC4`: hash chain, 2-, 3- and 4-byte hashing.
    pub const HC4: MatchFinder = MatchFinder(0x04);
    /// `LZMA_MF_BT2`: binary tree, 2-byte hashing.
    pub const BT2: MatchFinder = MatchFinder(0x12);
    /// `LZMA_MF_BT3`: binary tree, 2- and 3-byte hashing.
    pub const BT3: MatchFinder = MatchFinder(0x13);
    /// `LZMA_MF_BT4`: binary tree, 2-, 3- and 4-byte hashing.
    pub const BT4: MatchFinder = MatchFinder(0x14);

    /// `lzma_mf_is_supported`.
    pub fn is_supported(self) -> bool {
        matches!(
            self,
            Self::HC3 | Self::HC4 | Self::BT2 | Self::BT3 | Self::BT4
        )
    }
}

/// `lzma_mode`: how the LZMA encoder looks for the best way to encode.
/// Other numbers can be given, and are refused.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Mode(pub u32);

impl Mode {
    /// `LZMA_MODE_FAST`: a quick heuristic, for the hash chains.
    pub const FAST: Mode = Mode(1);
    /// `LZMA_MODE_NORMAL`: the prices of the choices, for the trees.
    pub const NORMAL: Mode = Mode(2);

    /// `lzma_mode_is_supported`.
    pub fn is_supported(self) -> bool {
        self == Self::FAST || self == Self::NORMAL
    }
}

/// `lzma_options_lzma`: the options of LZMA1 and LZMA2. The decoders read
/// the dictionary size, the preset dictionary, lc, lp, pb, and for
/// LZMA1EXT the flags and size; the encoders read the others too.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LzmaOptions {
    /// Dictionary size in bytes.
    pub dict_size: u32,
    /// A preset dictionary, or none.
    pub preset_dict: Option<Vec<u8>>,
    /// Number of literal context bits.
    pub lc: u32,
    /// Number of literal position bits.
    pub lp: u32,
    /// Number of position bits.
    pub pb: u32,
    /// Compression mode (encoders).
    pub mode: Mode,
    /// Nice length of a match (encoders).
    pub nice_len: u32,
    /// Match finder (encoders).
    pub mf: MatchFinder,
    /// Maximum search depth in the match finder, 0 for its default
    /// (encoders).
    pub depth: u32,
    /// Flags for LZMA_FILTER_LZMA1EXT.
    pub ext_flags: u32,
    /// For LZMA_FILTER_LZMA1EXT: uncompressed size (low bits).
    pub ext_size_low: u32,
    /// For LZMA_FILTER_LZMA1EXT: uncompressed size (high bits).
    pub ext_size_high: u32,
}

impl LzmaOptions {
    /// `lzma_lzma_preset`: the options of a preset, 0 to 9, with
    /// [`PRESET_EXTREME`] or not; `None` for any other number.
    pub fn preset(preset: u32) -> Option<LzmaOptions> {
        let level = preset & PRESET_LEVEL_MASK;
        let flags = preset & !PRESET_LEVEL_MASK;
        let supported_flags = PRESET_EXTREME;

        if level > 9 || flags & !supported_flags != 0 {
            return None;
        }

        const DICT_POW2: [u8; 10] = [18, 20, 21, 22, 22, 23, 23, 24, 25, 26];
        let mut options = LzmaOptions {
            dict_size: 1 << DICT_POW2[level as usize],
            preset_dict: None,
            lc: LC_DEFAULT,
            lp: LP_DEFAULT,
            pb: PB_DEFAULT,
            ..LzmaOptions::default()
        };
        if level <= 3 {
            options.mode = Mode::FAST;
            options.mf = if level == 0 {
                MatchFinder::HC3
            } else {
                MatchFinder::HC4
            };
            options.nice_len = if level <= 1 { 128 } else { 273 };
            const DEPTHS: [u32; 4] = [4, 8, 24, 48];
            options.depth = DEPTHS[level as usize];
        } else {
            options.mode = Mode::NORMAL;
            options.mf = MatchFinder::BT4;
            options.nice_len = match level {
                4 => 16,
                5 => 32,
                _ => 64,
            };
            options.depth = 0;
        }

        if flags & PRESET_EXTREME != 0 {
            options.mode = Mode::NORMAL;
            options.mf = MatchFinder::BT4;
            if level == 3 || level == 5 {
                options.nice_len = 192;
                options.depth = 0;
            } else {
                options.nice_len = 273;
                options.depth = 512;
            }
        }
        Some(options)
    }
}

/// `POS_STATES_MAX`.
pub(crate) const POS_STATES_MAX: usize = 1 << PB_MAX;

/// `is_lclppb_valid`.
pub(crate) fn is_lclppb_valid(options: &LzmaOptions) -> bool {
    options.lc <= LCLP_MAX
        && options.lp <= LCLP_MAX
        && options.lc + options.lp <= LCLP_MAX
        && options.pb <= PB_MAX
}

// lzma_lzma_state.
pub(crate) const STATE_LIT_LIT: u32 = 0;
pub(crate) const STATE_SHORTREP_LIT_LIT: u32 = 3;
pub(crate) const STATE_LIT_MATCH: u32 = 7;
pub(crate) const STATE_LIT_LONGREP: u32 = 8;
pub(crate) const STATE_LIT_SHORTREP: u32 = 9;
pub(crate) const STATE_NONLIT_MATCH: u32 = 10;
pub(crate) const STATE_NONLIT_REP: u32 = 11;

/// `STATES`.
pub(crate) const STATES: usize = 12;
/// `LIT_STATES`.
pub(crate) const LIT_STATES: u32 = 7;

/// `update_literal`.
#[inline(always)]
pub(crate) fn update_literal(state: u32) -> u32 {
    if state <= STATE_SHORTREP_LIT_LIT {
        STATE_LIT_LIT
    } else if state <= STATE_LIT_SHORTREP {
        state - 3
    } else {
        state - 6
    }
}

/// `update_literal_normal`.
#[inline(always)]
pub(crate) fn update_literal_normal(state: u32) -> u32 {
    if state <= STATE_SHORTREP_LIT_LIT {
        STATE_LIT_LIT
    } else {
        state - 3
    }
}

/// `update_literal_matched`.
#[inline(always)]
pub(crate) fn update_literal_matched(state: u32) -> u32 {
    if state <= STATE_LIT_SHORTREP {
        state - 3
    } else {
        state - 6
    }
}

/// `update_match`.
#[inline(always)]
pub(crate) fn update_match(state: u32) -> u32 {
    if state < LIT_STATES {
        STATE_LIT_MATCH
    } else {
        STATE_NONLIT_MATCH
    }
}

/// `update_long_rep`.
#[inline(always)]
pub(crate) fn update_long_rep(state: u32) -> u32 {
    if state < LIT_STATES {
        STATE_LIT_LONGREP
    } else {
        STATE_NONLIT_REP
    }
}

/// `update_short_rep`.
#[inline(always)]
pub(crate) fn update_short_rep(state: u32) -> u32 {
    if state < LIT_STATES {
        STATE_LIT_SHORTREP
    } else {
        STATE_NONLIT_REP
    }
}

/// `is_literal_state`.
#[inline(always)]
pub(crate) fn is_literal_state(state: u32) -> bool {
    state < LIT_STATES
}

/// `LITERAL_CODER_SIZE`.
pub(crate) const LITERAL_CODER_SIZE: usize = 0x300;
/// `LITERAL_CODERS_MAX`.
pub(crate) const LITERAL_CODERS_MAX: usize = 1 << LCLP_MAX;

/// `literal_mask_calc`.
pub(crate) fn literal_mask_calc(lc: u32, lp: u32) -> u32 {
    (0x100 << lp) - (0x100 >> lc)
}

/// `MATCH_LEN_MIN`.
pub(crate) const MATCH_LEN_MIN: u32 = 2;
pub(crate) const LEN_LOW_BITS: u32 = 3;
pub(crate) const LEN_LOW_SYMBOLS: u32 = 1 << LEN_LOW_BITS;
pub(crate) const LEN_MID_BITS: u32 = 3;
pub(crate) const LEN_MID_SYMBOLS: u32 = 1 << LEN_MID_BITS;
pub(crate) const LEN_HIGH_BITS: u32 = 8;
pub(crate) const LEN_HIGH_SYMBOLS: u32 = 1 << LEN_HIGH_BITS;
pub(crate) const LEN_SYMBOLS: u32 = LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS + LEN_HIGH_SYMBOLS;
pub(crate) const MATCH_LEN_MAX: u32 = MATCH_LEN_MIN + LEN_SYMBOLS - 1;
/// `REPS`: the number of repeated match distances kept.
pub(crate) const REPS: usize = 4;

/// `DIST_STATES`.
pub(crate) const DIST_STATES: u32 = 4;

/// `get_dist_state`.
#[inline(always)]
pub(crate) fn get_dist_state(len: u32) -> u32 {
    if len < DIST_STATES + MATCH_LEN_MIN {
        len - MATCH_LEN_MIN
    } else {
        DIST_STATES - 1
    }
}

pub(crate) const DIST_SLOT_BITS: u32 = 6;
pub(crate) const DIST_SLOTS: u32 = 1 << DIST_SLOT_BITS;
pub(crate) const DIST_MODEL_START: u32 = 4;
pub(crate) const DIST_MODEL_END: u32 = 14;
pub(crate) const FULL_DISTANCES_BITS: u32 = DIST_MODEL_END / 2;
pub(crate) const FULL_DISTANCES: u32 = 1 << FULL_DISTANCES_BITS;
pub(crate) const ALIGN_BITS: u32 = 4;
pub(crate) const ALIGN_SIZE: u32 = 1 << ALIGN_BITS;
pub(crate) const ALIGN_MASK: u32 = ALIGN_SIZE - 1;

// The probabilities of the LZMA decoder and encoder, one array: where each
// of the arrays of lzma_lzma1_decoder and lzma_lzma1_encoder starts, in the
// order of their fields. The encoder's dist_special and dist_align are the
// decoder's pos_special and pos_align, and its length encoders hold the
// length decoders' probabilities (their prices are apart).
pub(crate) const LITERAL: usize = 0;
pub(crate) const IS_MATCH: usize = LITERAL + LITERAL_CODERS_MAX * LITERAL_CODER_SIZE;
pub(crate) const IS_REP: usize = IS_MATCH + STATES * POS_STATES_MAX;
pub(crate) const IS_REP0: usize = IS_REP + STATES;
pub(crate) const IS_REP1: usize = IS_REP0 + STATES;
pub(crate) const IS_REP2: usize = IS_REP1 + STATES;
pub(crate) const IS_REP0_LONG: usize = IS_REP2 + STATES;
pub(crate) const DIST_SLOT: usize = IS_REP0_LONG + STATES * POS_STATES_MAX;
pub(crate) const POS_SPECIAL: usize = DIST_SLOT + (DIST_STATES * DIST_SLOTS) as usize;
pub(crate) const POS_ALIGN: usize = POS_SPECIAL + (FULL_DISTANCES - DIST_MODEL_END) as usize;
pub(crate) const MATCH_LEN_DECODER: usize = POS_ALIGN + ALIGN_SIZE as usize;
pub(crate) const REP_LEN_DECODER: usize = MATCH_LEN_DECODER + LEN_DECODER_SIZE;
pub(crate) const PROBS: usize = REP_LEN_DECODER + LEN_DECODER_SIZE;

// lzma_length_decoder and lzma_length_encoder: choice, choice2, low, mid,
// high.
pub(crate) const LEN_CHOICE: usize = 0;
pub(crate) const LEN_CHOICE2: usize = 1;
pub(crate) const LEN_LOW: usize = 2;
pub(crate) const LEN_MID: usize = LEN_LOW + POS_STATES_MAX * LEN_LOW_SYMBOLS as usize;
pub(crate) const LEN_HIGH: usize = LEN_MID + POS_STATES_MAX * LEN_MID_SYMBOLS as usize;
pub(crate) const LEN_DECODER_SIZE: usize = LEN_HIGH + LEN_HIGH_SYMBOLS as usize;
