//! High compression: `lz4hc.c`. Level 2 (`LZ4MID`), levels 3 to 9 (hash
//! chains) and levels 10 to 12 (the optimal parser), as one-call functions
//! and streams.
//!
//! Differs from liblz4: the context's pointers (`prefixStart`, `end`,
//! `dictStart`) become positions in the buffers each call is given: the
//! prefix, in the buffer that holds the source after it, and the external
//! dictionary, apart (see `View`).

use std::sync::Arc;

use crate::lz4::lz4::{
    KB, LASTLITERALS, MAX_INPUT_SIZE, MFLIMIT, MINMATCH, ML_BITS, ML_MASK, RUN_MASK, compress_bound,
};
use crate::lz4::lz4_compress::{count, read32, wild_copy8_from};

/// `LZ4HC_CLEVEL_MIN`.
pub const CLEVEL_MIN: i32 = 2;
/// `LZ4HC_CLEVEL_DEFAULT`.
pub const CLEVEL_DEFAULT: i32 = 9;
/// `LZ4HC_CLEVEL_OPT_MIN`.
pub const CLEVEL_OPT_MIN: i32 = 10;
/// `LZ4HC_CLEVEL_MAX`.
pub const CLEVEL_MAX: i32 = 12;

const DICTIONARY_LOGSIZE: u32 = 16;
const MAXD: usize = 1 << DICTIONARY_LOGSIZE;
const HASH_LOG: u32 = 15;
const HASHTABLESIZE: usize = 1 << HASH_LOG;
const DISTANCE_MAX: u32 = 65535;
const GB: usize = 1 << 30;

const OPTIMAL_ML: usize = (ML_MASK - 1) + MINMATCH;
const OPT_NUM: usize = 1 << 12;
const TRAILING_LITERALS: usize = 3;
/// `LZ4_minLength`.
const MIN_LENGTH: usize = MFLIMIT + 1;

/*===   Levels definition   ===*/

/// `lz4hc_strat_e`, with liblz4's names.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Strat {
    Lz4Mid,
    Lz4Hc,
    Lz4Opt,
}

#[derive(Clone, Copy)]
struct CParams {
    strat: Strat,
    nb_searches: i32,
    target_length: usize,
}

const CL_TABLE: [CParams; CLEVEL_MAX as usize + 1] = [
    CParams {
        strat: Strat::Lz4Mid,
        nb_searches: 2,
        target_length: 16,
    }, // 0, unused
    CParams {
        strat: Strat::Lz4Mid,
        nb_searches: 2,
        target_length: 16,
    }, // 1, unused
    CParams {
        strat: Strat::Lz4Mid,
        nb_searches: 2,
        target_length: 16,
    }, // 2
    CParams {
        strat: Strat::Lz4Hc,
        nb_searches: 4,
        target_length: 16,
    }, // 3
    CParams {
        strat: Strat::Lz4Hc,
        nb_searches: 8,
        target_length: 16,
    }, // 4
    CParams {
        strat: Strat::Lz4Hc,
        nb_searches: 16,
        target_length: 16,
    }, // 5
    CParams {
        strat: Strat::Lz4Hc,
        nb_searches: 32,
        target_length: 16,
    }, // 6
    CParams {
        strat: Strat::Lz4Hc,
        nb_searches: 64,
        target_length: 16,
    }, // 7
    CParams {
        strat: Strat::Lz4Hc,
        nb_searches: 128,
        target_length: 16,
    }, // 8
    CParams {
        strat: Strat::Lz4Hc,
        nb_searches: 256,
        target_length: 16,
    }, // 9
    CParams {
        strat: Strat::Lz4Opt,
        nb_searches: 96,
        target_length: 64,
    }, // 10 == CLEVEL_OPT_MIN
    CParams {
        strat: Strat::Lz4Opt,
        nb_searches: 512,
        target_length: 128,
    }, // 11
    CParams {
        strat: Strat::Lz4Opt,
        nb_searches: 16384,
        target_length: OPT_NUM,
    }, // 12 == CLEVEL_MAX
];

/// `LZ4HC_getCLevelParams`.
fn clevel_params(c_level: i32) -> CParams {
    let c_level = if c_level < 1 {
        CLEVEL_DEFAULT
    } else {
        c_level.min(CLEVEL_MAX)
    };
    CL_TABLE[c_level as usize]
}

/*===   Hashing   ===*/

const HASHSIZE: usize = 4;

/// `LZ4HC_hashPtr`: the 4 bytes at `p`, read as the machine reads them.
#[inline(always)]
fn hash_ptr(buf: &[u8], p: usize) -> usize {
    (read32(buf, p).wrapping_mul(2_654_435_761) >> ((MINMATCH as u32 * 8) - HASH_LOG)) as usize
}

const MID_HASHSIZE: usize = 8;
const MID_HASHLOG: u32 = HASH_LOG - 1;
const MID_HASHTABLESIZE: usize = 1 << MID_HASHLOG;

#[inline(always)]
fn mid_hash4_ptr(buf: &[u8], p: usize) -> usize {
    (read32(buf, p).wrapping_mul(2_654_435_761) >> (32 - MID_HASHLOG)) as usize
}

/// `LZ4MID_hash8Ptr`: the lower 56 bits of the 8 bytes at `p`, read as
/// little-endian.
#[inline(always)]
fn mid_hash8_ptr(buf: &[u8], p: usize) -> usize {
    let mut word = [0; 8];
    word.copy_from_slice(&buf[p..p + 8]);
    let v = u64::from_le_bytes(word);
    ((v << (64 - 56)).wrapping_mul(58_295_818_150_454_627) >> (64 - MID_HASHLOG)) as usize
}

/*===   Count match length   ===*/

/// `LZ4HC_countBack`: how many bytes before `ip` in `a` are the same as
/// before `mtch` in `b`, down to `i_min` and `m_min`, as a negative number.
#[inline(always)]
fn count_back(a: &[u8], ip: usize, b: &[u8], mtch: usize, i_min: usize, m_min: usize) -> isize {
    let mut back: isize = 0;
    let min = (i_min as isize - ip as isize).max(m_min as isize - mtch as isize);
    debug_assert!(min <= 0);
    while back - min > 3 {
        let at_a = (ip as isize + back - 4) as usize;
        let at_b = (mtch as isize + back - 4) as usize;
        let mut x = [0; 4];
        let mut y = [0; 4];
        x.copy_from_slice(&a[at_a..at_a + 4]);
        y.copy_from_slice(&b[at_b..at_b + 4]);
        // The same bytes at the end, in memory order, whatever the machine.
        let v = u32::from_le_bytes(x) ^ u32::from_le_bytes(y);
        if v != 0 {
            return back - (v.leading_zeros() / 8) as isize;
        }
        // 4-byte step.
        back -= 4;
    }
    // Check the remainder, if any.
    while back > min
        && a[(ip as isize + back - 1) as usize] == b[(mtch as isize + back - 1) as usize]
    {
        back -= 1;
    }
    back
}

/// `DELTANEXTU16`.
#[inline(always)]
fn delta_next(chain: &[u16; MAXD], pos: u32) -> u32 {
    u32::from(chain[(pos & 0xFFFF) as usize])
}

/*===   The context   ===*/

/// `LZ4HC_CCtx_internal`.
#[derive(Clone)]
pub(crate) struct HcState {
    hash_table: Box<[u32; HASHTABLESIZE]>,
    chain_table: Box<[u16; MAXD]>,
    /// `end - prefixStart`.
    prefix_size: usize,
    /// `prefixStart == NULL`.
    prefix_null: bool,
    dict_limit: u32,
    low_limit: u32,
    next_to_update: u32,
    compression_level: i32,
    favor_dec_speed: bool,
    dirty: bool,
}

impl core::fmt::Debug for HcState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HcState")
            .field("prefix_size", &self.prefix_size)
            .field("dict_limit", &self.dict_limit)
            .field("low_limit", &self.low_limit)
            .field("next_to_update", &self.next_to_update)
            .field("compression_level", &self.compression_level)
            .finish_non_exhaustive()
    }
}

impl Default for HcState {
    /// `LZ4_initStreamHC`.
    fn default() -> Self {
        HcState {
            hash_table: Box::new([0; HASHTABLESIZE]),
            chain_table: Box::new([0; MAXD]),
            prefix_size: 0,
            prefix_null: true,
            dict_limit: 0,
            low_limit: 0,
            next_to_update: 0,
            compression_level: CLEVEL_DEFAULT,
            favor_dec_speed: false,
            dirty: false,
        }
    }
}

/// The buffers a call reads: `buf`, with the prefix from `pstart` (and the
/// source after it), and the external dictionary `dict`, `dictLimit -
/// lowLimit` bytes.
#[derive(Clone, Copy)]
pub(crate) struct View<'a> {
    pub buf: &'a [u8],
    pub pstart: usize,
    pub dict: &'a [u8],
}

/// A dictionary attached (`dictCtx`): its context, and its prefix (the
/// dictionary), from which its indexes count.
pub(crate) type DictCtx = Arc<(HcState, Vec<u8>)>;

/// `LZ4HC_match_t`.
#[derive(Clone, Copy, Default, Debug)]
struct Match {
    off: i32,
    len: i32,
    /// Negative.
    back: i32,
}

impl HcState {
    /// `LZ4HC_clearTables`.
    fn clear_tables(&mut self) {
        self.hash_table.fill(0);
        self.chain_table.fill(0xFFFF);
    }

    /// `LZ4HC_init_internal`: a new prefix, starting at the next source.
    fn init_internal(&mut self) {
        let buffer_size = self.prefix_size;
        let mut new_starting_offset = buffer_size + self.dict_limit as usize;
        if new_starting_offset > GB {
            self.clear_tables();
            new_starting_offset = 0;
        }
        new_starting_offset += 64 * KB;
        self.next_to_update = new_starting_offset as u32;
        self.prefix_size = 0;
        self.prefix_null = false;
        self.dict_limit = new_starting_offset as u32;
        self.low_limit = new_starting_offset as u32;
    }

    /// `LZ4_setCompressionLevel`.
    pub(crate) fn set_compression_level(&mut self, compression_level: i32) {
        self.compression_level = if compression_level < 1 {
            CLEVEL_DEFAULT
        } else {
            compression_level.min(CLEVEL_MAX)
        };
    }

    /// `LZ4_favorDecompressionSpeed`.
    pub(crate) fn favor_decompression_speed(&mut self, favor: bool) {
        self.favor_dec_speed = favor;
    }

    /// `LZ4_initStreamHC` (with its compression level, the default).
    pub(crate) fn init_stream(&mut self) {
        self.clear_tables_to_zero();
        self.prefix_size = 0;
        self.prefix_null = true;
        self.dict_limit = 0;
        self.low_limit = 0;
        self.next_to_update = 0;
        self.favor_dec_speed = false;
        self.dirty = false;
        self.compression_level = CLEVEL_DEFAULT;
    }

    /// `MEM_INIT(hcstate, 0, sizeof(*hcstate))`'s tables.
    fn clear_tables_to_zero(&mut self) {
        self.hash_table.fill(0);
        self.chain_table.fill(0);
    }

    /// `LZ4_resetStreamHC_fast`. The attached dictionary is the caller's to
    /// drop.
    pub(crate) fn reset_fast(&mut self, compression_level: i32) {
        if self.dirty {
            self.init_stream();
        } else {
            self.dict_limit = self.dict_limit.wrapping_add(self.prefix_size as u32);
            self.prefix_size = 0;
            self.prefix_null = true;
        }
        self.set_compression_level(compression_level);
    }

    /// `LZ4HC_Insert`: the chains updated up to `ip` (excluded), a position
    /// in `buf`, whose prefix starts at `pstart`.
    #[inline(always)]
    fn insert(&mut self, buf: &[u8], pstart: usize, ip: usize) {
        let prefix_idx = self.dict_limit;
        let target = (ip - pstart) as u32 + prefix_idx;
        let mut idx = self.next_to_update;
        while idx < target {
            let h = hash_ptr(buf, pstart + (idx - prefix_idx) as usize);
            let delta = idx.wrapping_sub(self.hash_table[h]).min(DISTANCE_MAX);
            self.chain_table[(idx & 0xFFFF) as usize] = delta as u16;
            self.hash_table[h] = idx;
            idx += 1;
        }
        self.next_to_update = target;
    }
}

/// The pattern's bytes, as they are in memory when it is read there.
#[inline(always)]
fn pattern_bytes(pattern: u32) -> [u8; 4] {
    pattern.to_ne_bytes()
}

/// `LZ4HC_rotatePattern`.
fn rotate_pattern(rotate: usize, pattern: u32) -> u32 {
    let bits_to_rotate = ((rotate & 3) << 3) as u32;
    if bits_to_rotate == 0 {
        return pattern;
    }
    pattern.rotate_left(bits_to_rotate)
}

/// `LZ4HC_countPattern`: how many bytes from `ip` follow the pattern, from
/// its first byte, up to `i_end`. The pattern repeats every 1, 2 or 4 bytes.
fn count_pattern(buf: &[u8], ip: usize, i_end: usize, pattern32: u32) -> usize {
    let bytes = pattern_bytes(pattern32);
    let word = [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[0], bytes[1], bytes[2], bytes[3],
    ];
    let pattern = u64::from_le_bytes(word);
    let mut p = ip;
    while p + 8 <= i_end {
        let mut w = [0; 8];
        w.copy_from_slice(&buf[p..p + 8]);
        let diff = u64::from_le_bytes(w) ^ pattern;
        if diff == 0 {
            p += 8;
            continue;
        }
        p += (diff.trailing_zeros() / 8) as usize;
        return p - ip;
    }
    let mut k = 0;
    while p < i_end && buf[p] == word[k] {
        p += 1;
        k += 1;
    }
    p - ip
}

/// `LZ4HC_reverseCountPattern`: how many bytes before `ip`, down to `i_low`,
/// end the pattern, read as the machine reads it.
fn reverse_count_pattern(buf: &[u8], ip: usize, i_low: usize, pattern: u32) -> usize {
    let mut p = ip;
    while p >= i_low + 4 {
        if read32(buf, p - 4) != pattern {
            break;
        }
        p -= 4;
    }
    let bytes = pattern_bytes(pattern);
    let mut k = 3usize;
    while p > i_low {
        if buf[p - 1] != bytes[k] {
            break;
        }
        p -= 1;
        k = k.wrapping_sub(1);
        if k == usize::MAX {
            // liblz4's byte pointer walks back out of the pattern here;
            // the bytes before it are the pattern's again only for a
            // pattern of one byte repeated, which is the only one it
            // confirms.
            k = 3;
        }
    }
    ip - p
}

/// `LZ4HC_protectDictEnd`: whether a match at `match_index` can read its 4
/// bytes before the dictionary's end.
#[inline(always)]
fn protect_dict_end(dict_limit: u32, match_index: u32) -> bool {
    (dict_limit.wrapping_sub(1)).wrapping_sub(match_index) >= 3
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Repeat {
    Untested,
    Not,
    Confirmed,
}

/// `LZ4HC_InsertAndGetWiderMatch`: the longest match for `ip`, which may
/// start up to `ip - i_low_limit` bytes before it, longer than `longest`.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn insert_and_get_wider_match(
    hc4: &mut HcState,
    v: View<'_>,
    dict_ctx: Option<&(HcState, Vec<u8>)>,
    ip: usize,
    i_low_limit: usize,
    i_high_limit: usize,
    mut longest: i32,
    max_nb_attempts: i32,
    pattern_analysis: bool,
    chain_swap: bool,
    favor_dec_speed: bool,
) -> Match {
    let buf = v.buf;
    let prefix_ptr = v.pstart;
    let prefix_idx = hc4.dict_limit;
    let ip_index = (ip - prefix_ptr) as u32 + prefix_idx;
    let within_start_distance = hc4.low_limit + (DISTANCE_MAX + 1) > ip_index;
    let lowest_match_index = if within_start_distance {
        hc4.low_limit
    } else {
        ip_index - DISTANCE_MAX
    };
    let dict = v.dict;
    let dict_idx = hc4.low_limit;
    let dict_end = dict.len();
    let look_back_length = (ip - i_low_limit) as i32;
    let mut nb_attempts = max_nb_attempts;
    let mut match_chain_pos: u32 = 0;
    let pattern = read32(buf, ip);
    let mut repeat = Repeat::Untested;
    let mut src_pattern_length = 0usize;
    let mut offset: i32 = 0;
    let mut s_back: i32 = 0;

    // First match: insert all prior positions up to ip (excluded).
    hc4.insert(buf, prefix_ptr, ip);
    let mut match_index = hc4.hash_table[hash_ptr(buf, ip)];

    while match_index >= lowest_match_index && nb_attempts > 0 {
        let mut match_length: i32 = 0;
        nb_attempts -= 1;
        debug_assert!(match_index < ip_index);
        if favor_dec_speed && ip_index - match_index < 8 {
            // favorDecSpeed intentionally skips matches with an offset
            // below 8.
        } else if match_index >= prefix_idx {
            // Within the current prefix.
            let match_ptr = prefix_ptr + (match_index - prefix_idx) as usize;
            debug_assert!(match_ptr < ip);
            debug_assert!(longest >= 1);
            let a = i_low_limit + longest as usize - 1;
            let b =
                (match_ptr as isize - look_back_length as isize + longest as isize - 1) as usize;
            if buf[a..a + 2] == buf[b..b + 2] && read32(buf, match_ptr) == pattern {
                let back = if look_back_length != 0 {
                    count_back(buf, ip, buf, match_ptr, i_low_limit, prefix_ptr) as i32
                } else {
                    0
                };
                match_length = (MINMATCH
                    + count(buf, ip + MINMATCH, buf, match_ptr + MINMATCH, i_high_limit))
                    as i32;
                match_length -= back;
                if match_length > longest {
                    longest = match_length;
                    offset = (ip_index - match_index) as i32;
                    s_back = back;
                }
            }
        } else {
            // lowestMatchIndex <= matchIndex < dictLimit: within the
            // external dictionary.
            let match_ptr = (match_index - dict_idx) as usize;
            debug_assert!(match_index >= dict_idx);
            if match_index <= prefix_idx - 4 && read32(dict, match_ptr) == pattern {
                let mut v_limit = ip + (prefix_idx - match_index) as usize;
                if v_limit > i_high_limit {
                    v_limit = i_high_limit;
                }
                match_length = (count(buf, ip + MINMATCH, dict, match_ptr + MINMATCH, v_limit)
                    + MINMATCH) as i32;
                if ip + match_length as usize == v_limit && v_limit < i_high_limit {
                    match_length += count(
                        buf,
                        ip + match_length as usize,
                        buf,
                        prefix_ptr,
                        i_high_limit,
                    ) as i32;
                }
                let back = if look_back_length != 0 {
                    count_back(buf, ip, dict, match_ptr, i_low_limit, 0) as i32
                } else {
                    0
                };
                match_length -= back;
                if match_length > longest {
                    longest = match_length;
                    offset = (ip_index - match_index) as i32;
                    s_back = back;
                }
            }
        }

        if chain_swap && match_length == longest {
            // A better match: select a better chain.
            debug_assert!(look_back_length == 0);
            if match_index + longest as u32 <= ip_index {
                const K_TRIGGER: i32 = 4;
                let mut distance_to_next_match: u32 = 1;
                let end = longest - MINMATCH as i32 + 1;
                let mut step: i32;
                let mut accel = 1 << K_TRIGGER;
                let mut pos = 0;
                while pos < end {
                    let candidate_dist = delta_next(&hc4.chain_table, match_index + pos as u32);
                    step = accel >> K_TRIGGER;
                    accel += 1;
                    if candidate_dist > distance_to_next_match {
                        distance_to_next_match = candidate_dist;
                        match_chain_pos = pos as u32;
                        accel = 1 << K_TRIGGER;
                    }
                    pos += step;
                }
                if distance_to_next_match > 1 {
                    if distance_to_next_match > match_index {
                        // Avoid overflow.
                        break;
                    }
                    match_index -= distance_to_next_match;
                    continue;
                }
            }
        }

        {
            let dist_next_match = delta_next(&hc4.chain_table, match_index);
            if pattern_analysis && dist_next_match == 1 && match_chain_pos == 0 {
                let match_candidate_idx = match_index.wrapping_sub(1);
                // May be a repeated pattern.
                if repeat == Repeat::Untested {
                    if ((pattern & 0xFFFF) == (pattern >> 16))
                        & ((pattern & 0xFF) == (pattern >> 24))
                    {
                        repeat = Repeat::Confirmed;
                        src_pattern_length = count_pattern(buf, ip + 4, i_high_limit, pattern) + 4;
                    } else {
                        repeat = Repeat::Not;
                    }
                }
                if repeat == Repeat::Confirmed
                    && match_candidate_idx >= lowest_match_index
                    && protect_dict_end(prefix_idx, match_candidate_idx)
                {
                    let ext_dict = match_candidate_idx < prefix_idx;
                    let (seg, match_ptr) = if ext_dict {
                        (dict, (match_candidate_idx - dict_idx) as usize)
                    } else {
                        (
                            buf,
                            prefix_ptr + (match_candidate_idx - prefix_idx) as usize,
                        )
                    };
                    if read32(seg, match_ptr) == pattern {
                        // A good candidate.
                        let i_limit = if ext_dict { dict_end } else { i_high_limit };
                        let mut forward_pattern_length =
                            count_pattern(seg, match_ptr + 4, i_limit, pattern) + 4;
                        if ext_dict && match_ptr + forward_pattern_length == i_limit {
                            let rotated = rotate_pattern(forward_pattern_length, pattern);
                            forward_pattern_length +=
                                count_pattern(buf, prefix_ptr, i_high_limit, rotated);
                        }
                        {
                            let lowest_match_ptr = if ext_dict { 0 } else { prefix_ptr };
                            let mut back_length =
                                reverse_count_pattern(seg, match_ptr, lowest_match_ptr, pattern);
                            if !ext_dict
                                && match_ptr - back_length == prefix_ptr
                                && dict_idx < prefix_idx
                            {
                                let rotated = rotate_pattern(
                                    (back_length as u32).wrapping_neg() as usize,
                                    pattern,
                                );
                                back_length += reverse_count_pattern(dict, dict_end, 0, rotated);
                            }
                            // Limit backLength not to go further than
                            // lowestMatchIndex.
                            back_length = (match_candidate_idx
                                - (match_candidate_idx.wrapping_sub(back_length as u32))
                                    .max(lowest_match_index))
                                as usize;
                            debug_assert!(
                                match_candidate_idx - back_length as u32 >= lowest_match_index
                            );
                            let current_segment_length = back_length + forward_pattern_length;
                            // Adjust to the end of the pattern if the source
                            // pattern fits, otherwise the beginning of the
                            // pattern.
                            if current_segment_length >= src_pattern_length
                                && forward_pattern_length <= src_pattern_length
                            {
                                // The best position, the full pattern, maybe
                                // followed by more match.
                                let new_match_index = match_candidate_idx
                                    .wrapping_add(forward_pattern_length as u32)
                                    .wrapping_sub(src_pattern_length as u32);
                                if protect_dict_end(prefix_idx, new_match_index) {
                                    match_index = new_match_index;
                                } else {
                                    // Can only happen if started in the
                                    // prefix.
                                    match_index = prefix_idx;
                                }
                            } else {
                                // The farthest position in the current
                                // segment: a match of currentSegmentLength,
                                // and maybe some back.
                                let new_match_index = match_candidate_idx - back_length as u32;
                                if !protect_dict_end(prefix_idx, new_match_index) {
                                    match_index = prefix_idx;
                                } else {
                                    match_index = new_match_index;
                                    if look_back_length == 0 {
                                        // No back possible.
                                        let max_ml = current_segment_length.min(src_pattern_length);
                                        if (longest as usize) < max_ml {
                                            if (ip - prefix_ptr) + prefix_idx as usize
                                                - match_index as usize
                                                > DISTANCE_MAX as usize
                                            {
                                                break;
                                            }
                                            longest = max_ml as i32;
                                            offset = (ip_index - match_index) as i32;
                                        }
                                        let dist_to_next_pattern =
                                            delta_next(&hc4.chain_table, match_index);
                                        if dist_to_next_pattern > match_index {
                                            // Avoid overflow.
                                            break;
                                        }
                                        match_index -= dist_to_next_pattern;
                                    }
                                }
                            }
                        }
                        continue;
                    }
                }
            }
        }

        // Follow the current chain.
        match_index = match_index.wrapping_sub(delta_next(
            &hc4.chain_table,
            match_index.wrapping_add(match_chain_pos),
        ));
    }

    if let Some((ctx, content)) = dict_ctx
        && nb_attempts > 0
        && within_start_distance
    {
        let dict_end_offset = content.len() + ctx.dict_limit as usize;
        let mut dict_match_index = ctx.hash_table[hash_ptr(buf, ip)];
        match_index = dict_match_index
            .wrapping_add(lowest_match_index)
            .wrapping_sub(dict_end_offset as u32);
        while ip_index.wrapping_sub(match_index) <= DISTANCE_MAX && nb_attempts > 0 {
            nb_attempts -= 1;
            let match_ptr = dict_match_index.wrapping_sub(ctx.dict_limit) as usize;
            if read32(content, match_ptr) == pattern {
                let mut v_limit = ip + (dict_end_offset - dict_match_index as usize);
                if v_limit > i_high_limit {
                    v_limit = i_high_limit;
                }
                let mut mlt = (count(buf, ip + MINMATCH, content, match_ptr + MINMATCH, v_limit)
                    + MINMATCH) as i32;
                let back = if look_back_length != 0 {
                    count_back(buf, ip, content, match_ptr, i_low_limit, 0) as i32
                } else {
                    0
                };
                mlt -= back;
                if mlt > longest {
                    longest = mlt;
                    offset = ip_index.wrapping_sub(match_index) as i32;
                    s_back = back;
                }
            }
            let next_offset = delta_next(&ctx.chain_table, dict_match_index);
            dict_match_index = dict_match_index.wrapping_sub(next_offset);
            match_index = match_index.wrapping_sub(next_offset);
        }
    }

    debug_assert!(longest >= 0);
    Match {
        len: longest,
        off: offset,
        back: s_back,
    }
}

/// `LZ4HC_InsertAndFindBestMatch`.
#[inline(always)]
fn insert_and_find_best_match(
    hc4: &mut HcState,
    v: View<'_>,
    dict_ctx: Option<&(HcState, Vec<u8>)>,
    ip: usize,
    i_limit: usize,
    max_nb_attempts: i32,
    pattern_analysis: bool,
) -> Match {
    insert_and_get_wider_match(
        hc4,
        v,
        dict_ctx,
        ip,
        ip,
        i_limit,
        MINMATCH as i32 - 1,
        max_nb_attempts,
        pattern_analysis,
        false,
        false,
    )
}

/// `limitedOutput_directive`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Limit {
    NotLimited,
    LimitedOutput,
    FillOutput,
}

/// `LZ4HC_encodeSequence`: a sequence of the literals from `anchor` to `ip`
/// and a match, written at `op`. Returns `true` (1) if it does not fit, and
/// then only `op` moved; else `ip` and `anchor` move past the match.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn encode_sequence(
    src: &[u8],
    dst: &mut [u8],
    ip: &mut usize,
    op: &mut usize,
    anchor: &mut usize,
    match_length: usize,
    offset: usize,
    limit: Limit,
    oend: isize,
) -> bool {
    let token = *op;
    *op += 1;

    // Encode the literal length.
    let mut length = *ip - *anchor;
    // Check the output limit.
    if limit != Limit::NotLimited
        && (*op + length / 255 + length + (2 + 1 + LASTLITERALS)) as isize > oend
    {
        return true;
    }
    if length >= RUN_MASK {
        let mut len = length - RUN_MASK;
        dst[token] = (RUN_MASK << ML_BITS) as u8;
        while len >= 255 {
            dst[*op] = 255;
            *op += 1;
            len -= 255;
        }
        dst[*op] = len as u8;
        *op += 1;
    } else {
        dst[token] = (length << ML_BITS) as u8;
    }

    // Copy the literals.
    wild_copy8_from(dst, *op, src, *anchor, *op + length);
    *op += length;

    // Encode the offset.
    debug_assert!(offset as u32 <= DISTANCE_MAX && offset > 0);
    dst[*op..*op + 2].copy_from_slice(&(offset as u16).to_le_bytes());
    *op += 2;

    // Encode the match length.
    debug_assert!(match_length >= MINMATCH);
    length = match_length - MINMATCH;
    if limit != Limit::NotLimited && (*op + length / 255 + (1 + LASTLITERALS)) as isize > oend {
        // Check the output limit.
        return true;
    }
    if length >= ML_MASK {
        dst[token] += ML_MASK as u8;
        length -= ML_MASK;
        while length >= 510 {
            dst[*op] = 255;
            dst[*op + 1] = 255;
            *op += 2;
            length -= 510;
        }
        if length >= 255 {
            length -= 255;
            dst[*op] = 255;
            *op += 1;
        }
        dst[*op] = length as u8;
        *op += 1;
    } else {
        dst[token] += length as u8;
    }

    // Prepare the next loop.
    *ip += match_length;
    *anchor = *ip;
    false
}

/// The end of the HC compressors: the last literals, as many as fit with
/// `FillOutput`. Returns the compressed size, or 0 if they do not fit with
/// `LimitedOutput`; `src_size` gets how much of the source was compressed.
#[allow(clippy::too_many_arguments)]
fn last_literals(
    src: &[u8],
    source: usize,
    iend: usize,
    anchor: usize,
    dst: &mut [u8],
    mut op: usize,
    oend: usize,
    limit: Limit,
    src_size: &mut usize,
) -> usize {
    // Literals.
    let mut last_run_size = iend - anchor;
    let mut ll_add = (last_run_size + 255 - RUN_MASK) / 255;
    let total_size = 1 + ll_add + last_run_size;
    if limit != Limit::NotLimited && op + total_size > oend {
        if limit == Limit::LimitedOutput {
            return 0;
        }
        // Adapt lastRunSize to fill dst.
        last_run_size = oend - op - 1 /* token */;
        ll_add = (last_run_size + 256 - RUN_MASK) / 256;
        last_run_size -= ll_add;
    }
    let ip = anchor + last_run_size;

    if last_run_size >= RUN_MASK {
        let mut accumulator = last_run_size - RUN_MASK;
        dst[op] = (RUN_MASK << ML_BITS) as u8;
        op += 1;
        while accumulator >= 255 {
            dst[op] = 255;
            op += 1;
            accumulator -= 255;
        }
        dst[op] = accumulator as u8;
        op += 1;
    } else {
        dst[op] = (last_run_size << ML_BITS) as u8;
        op += 1;
    }
    dst[op..op + last_run_size].copy_from_slice(&src[anchor..anchor + last_run_size]);
    op += last_run_size;

    *src_size = ip - source;
    op
}

/// `_dest_overflow` of the HC compressors, for `FillOutput`: the last
/// sequence, its match cut to what fits, if it still makes a valid block.
#[allow(clippy::too_many_arguments)]
fn fill_last_sequence(
    src: &[u8],
    dst: &mut [u8],
    ip: &mut usize,
    op: &mut usize,
    anchor: &mut usize,
    mut ml: usize,
    off: usize,
    oend: isize,
) {
    let ll = *ip - *anchor;
    let ll_addbytes = (ll + 240) / 255;
    let ll_total_cost = 1 + ll_addbytes + ll;
    // 2 for the offset, 1 for the token.
    let max_lit_pos = oend - 3;
    if (*op + ll_total_cost) as isize <= max_lit_pos {
        // ll validated; now adjust the match length.
        let bytes_left_for_ml = (max_lit_pos - (*op + ll_total_cost) as isize) as usize;
        let max_ml_size = MINMATCH + (ML_MASK - 1) + bytes_left_for_ml * 255;
        if ml > max_ml_size {
            ml = max_ml_size;
        }
        if (oend + LASTLITERALS as isize) - (*op + ll_total_cost + 2) as isize - 1 + ml as isize
            >= MFLIMIT as isize
        {
            encode_sequence(src, dst, ip, op, anchor, ml, off, Limit::NotLimited, oend);
        }
    }
}

/**************************************
 *  Mid Compression (level 2)
 **************************************/

/// `LZ4MID_fillHTable`: the hash tables filled with references into the
/// dictionary `dict`, the prefix. Only level 2 can use them.
fn mid_fill_htable(cctx: &mut HcState, dict: &[u8]) {
    let size = dict.len();
    let prefix_idx = cctx.dict_limit;
    let target = (prefix_idx as usize + size).wrapping_sub(MID_HASHSIZE) as u32;
    let mut idx = cctx.next_to_update;
    if size <= MID_HASHSIZE {
        return;
    }
    let pos = |idx: u32| (idx - prefix_idx) as usize;
    while idx < target {
        let h4 = mid_hash4_ptr(dict, pos(idx));
        cctx.hash_table[h4] = idx;
        let h8 = mid_hash8_ptr(dict, pos(idx + 1));
        cctx.hash_table[MID_HASHTABLESIZE + h8] = idx + 1;
        idx += 3;
    }

    idx = if size > 32 * KB + MID_HASHSIZE {
        target - 32 * KB as u32
    } else {
        cctx.next_to_update
    };
    while idx < target {
        let h8 = mid_hash8_ptr(dict, pos(idx));
        cctx.hash_table[MID_HASHTABLESIZE + h8] = idx;
        idx += 1;
    }

    cctx.next_to_update = target;
}

/// `LZ4HC_searchExtDict`: a match for `ip` in an attached dictionary's
/// hash chains.
#[allow(clippy::too_many_arguments)]
fn search_ext_dict(
    buf: &[u8],
    ip: usize,
    ip_index: u32,
    i_low_limit: usize,
    i_high_limit: usize,
    dict_ctx: &(HcState, Vec<u8>),
    g_dict_end_index: u32,
    mut current_best_ml: i32,
    mut nb_attempts: i32,
) -> Match {
    let (ctx, content) = dict_ctx;
    let l_dict_end_index = content.len() + ctx.dict_limit as usize;
    let mut l_dict_match_index = ctx.hash_table[hash_ptr(buf, ip)];
    let mut match_index = l_dict_match_index
        .wrapping_add(g_dict_end_index)
        .wrapping_sub(l_dict_end_index as u32);
    let mut offset = 0;
    let mut s_back = 0;
    while ip_index.wrapping_sub(match_index) <= DISTANCE_MAX && nb_attempts > 0 {
        nb_attempts -= 1;
        let match_ptr = l_dict_match_index.wrapping_sub(ctx.dict_limit) as usize;
        if read32(content, match_ptr) == read32(buf, ip) {
            let mut v_limit = ip + (l_dict_end_index - l_dict_match_index as usize);
            if v_limit > i_high_limit {
                v_limit = i_high_limit;
            }
            let mut mlt = (count(buf, ip + MINMATCH, content, match_ptr + MINMATCH, v_limit)
                + MINMATCH) as i32;
            let back = if ip > i_low_limit {
                count_back(buf, ip, content, match_ptr, i_low_limit, 0) as i32
            } else {
                0
            };
            mlt -= back;
            if mlt > current_best_ml {
                current_best_ml = mlt;
                offset = ip_index.wrapping_sub(match_index) as i32;
                s_back = back;
            }
        }
        let next_offset = delta_next(&ctx.chain_table, l_dict_match_index);
        l_dict_match_index = l_dict_match_index.wrapping_sub(next_offset);
        match_index = match_index.wrapping_sub(next_offset);
    }
    Match {
        len: current_best_ml,
        off: offset,
        back: s_back,
    }
}

/// `LZ4MID_searchExtDict`: a match for `ip` in an attached level-2
/// dictionary's hash tables, long first, then short.
fn mid_search_ext_dict(
    buf: &[u8],
    ip: usize,
    ip_index: u32,
    i_high_limit: usize,
    dict_ctx: &(HcState, Vec<u8>),
    g_dict_end_index: u32,
) -> Match {
    let (ctx, content) = dict_ctx;
    let l_dict_end_index = content.len() + ctx.dict_limit as usize;
    // Search a long match first.
    {
        let l8 = ctx.hash_table[MID_HASHTABLESIZE + mid_hash8_ptr(buf, ip)];
        let m8_index = l8
            .wrapping_add(g_dict_end_index)
            .wrapping_sub(l_dict_end_index as u32);
        if ip_index.wrapping_sub(m8_index) <= DISTANCE_MAX {
            let match_ptr = l8.wrapping_sub(ctx.dict_limit) as usize;
            let safe_len = (l_dict_end_index - l8 as usize).min(i_high_limit - ip);
            let mlt = count(buf, ip, content, match_ptr, ip + safe_len) as i32;
            if mlt >= MINMATCH as i32 {
                return Match {
                    len: mlt,
                    off: ip_index.wrapping_sub(m8_index) as i32,
                    back: 0,
                };
            }
        }
    }
    // Search a short match second.
    {
        let l4 = ctx.hash_table[mid_hash4_ptr(buf, ip)];
        let m4_index = l4
            .wrapping_add(g_dict_end_index)
            .wrapping_sub(l_dict_end_index as u32);
        if ip_index.wrapping_sub(m4_index) <= DISTANCE_MAX {
            let match_ptr = l4.wrapping_sub(ctx.dict_limit) as usize;
            let safe_len = (l_dict_end_index - l4 as usize).min(i_high_limit - ip);
            let mlt = count(buf, ip, content, match_ptr, ip + safe_len) as i32;
            if mlt >= MINMATCH as i32 {
                return Match {
                    len: mlt,
                    off: ip_index.wrapping_sub(m4_index) as i32,
                    back: 0,
                };
            }
        }
    }
    // Nothing found.
    Match::default()
}

/// `LZ4MID_compress`.
// C-style: locals set on every path the C sets them, before use.
#[allow(unused_assignments)]
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn mid_compress(
    ctx: &mut HcState,
    v: View<'_>,
    dict_ctx: Option<&(HcState, Vec<u8>)>,
    source: usize,
    dst: &mut [u8],
    src_size: &mut usize,
    max_output_size: usize,
    limit: Limit,
) -> usize {
    let buf = v.buf;
    let mut ip = source;
    let mut anchor = ip;
    let iend = ip + *src_size;
    let mflimit = iend as isize - MFLIMIT as isize;
    let matchlimit = iend - LASTLITERALS.min(iend);
    let ilimit = iend as isize - MID_HASHSIZE as isize;
    let mut op = 0usize;
    let mut oend = max_output_size as isize;

    let prefix_ptr = v.pstart;
    let prefix_idx = ctx.dict_limit;
    let ilimit_idx = (ilimit - prefix_ptr as isize + prefix_idx as isize) as u32;
    let dict = v.dict;
    let dict_idx = ctx.low_limit;
    let g_dict_end_index = ctx.low_limit;
    // The search into the attached dictionary: its hash tables if it is a
    // level-2 one, else its chains.
    let search_into_dict = dict_ctx.map(|d| {
        (
            d,
            clevel_params(d.0.compression_level).strat == Strat::Lz4Mid,
        )
    });
    let mut match_length: usize = 0;
    let mut match_distance: usize = 0;

    if *src_size > MAX_INPUT_SIZE {
        // No input may be that large.
        return 0;
    }
    if limit == Limit::FillOutput {
        // A hack for the LZ4 format restriction.
        oend -= LASTLITERALS as isize;
    }

    'last_literals: {
        if *src_size < MIN_LENGTH {
            // Input too small, no compression (all literals).
            break 'last_literals;
        }

        // Main loop.
        'main: while ip as isize <= mflimit {
            let ip_index = (ip - prefix_ptr) as u32 + prefix_idx;
            'encode: {
                // Search a long match.
                {
                    let h8 = mid_hash8_ptr(buf, ip);
                    let pos8 = ctx.hash_table[MID_HASHTABLESIZE + h8];
                    ctx.hash_table[MID_HASHTABLESIZE + h8] = ip_index;
                    if ip_index.wrapping_sub(pos8) <= DISTANCE_MAX {
                        // A match candidate found.
                        if pos8 >= prefix_idx {
                            let match_ptr = prefix_ptr + (pos8 - prefix_idx) as usize;
                            match_length = count(buf, ip, buf, match_ptr, matchlimit);
                            if match_length >= MINMATCH {
                                match_distance = (ip_index - pos8) as usize;
                                break 'encode;
                            }
                        } else if pos8 >= dict_idx {
                            // An extDict match candidate.
                            let match_ptr = (pos8 - dict_idx) as usize;
                            let safe_len = ((prefix_idx - pos8) as usize).min(matchlimit - ip);
                            match_length = count(buf, ip, dict, match_ptr, ip + safe_len);
                            if match_length >= MINMATCH {
                                match_distance = (ip_index - pos8) as usize;
                                break 'encode;
                            }
                        }
                    }
                }
                // Search a short match.
                {
                    let h4 = mid_hash4_ptr(buf, ip);
                    let pos4 = ctx.hash_table[h4];
                    ctx.hash_table[h4] = ip_index;
                    if ip_index.wrapping_sub(pos4) <= DISTANCE_MAX {
                        // A match candidate found.
                        if pos4 >= prefix_idx {
                            // Only search within the prefix.
                            let match_ptr = prefix_ptr + (pos4 - prefix_idx) as usize;
                            match_length = count(buf, ip, buf, match_ptr, matchlimit);
                            if match_length >= MINMATCH {
                                // A short match found: check ip+1 for a
                                // longer one.
                                let h8 = mid_hash8_ptr(buf, ip + 1);
                                let pos8 = ctx.hash_table[MID_HASHTABLESIZE + h8];
                                let m2_distance = (ip_index + 1).wrapping_sub(pos8);
                                match_distance = (ip_index - pos4) as usize;
                                if m2_distance <= DISTANCE_MAX
                                    && pos8 >= prefix_idx
                                    && (ip as isize) < mflimit
                                {
                                    let m2_ptr = prefix_ptr + (pos8 - prefix_idx) as usize;
                                    let ml2 = count(buf, ip + 1, buf, m2_ptr, matchlimit);
                                    if ml2 > match_length {
                                        ctx.hash_table[MID_HASHTABLESIZE + h8] = ip_index + 1;
                                        ip += 1;
                                        match_length = ml2;
                                        match_distance = m2_distance as usize;
                                    }
                                }
                                break 'encode;
                            }
                        } else if pos4 >= dict_idx {
                            // An extDict match candidate.
                            let match_ptr = (pos4 - dict_idx) as usize;
                            let safe_len = ((prefix_idx - pos4) as usize).min(matchlimit - ip);
                            match_length = count(buf, ip, dict, match_ptr, ip + safe_len);
                            if match_length >= MINMATCH {
                                match_distance = (ip_index - pos4) as usize;
                                break 'encode;
                            }
                        }
                    }
                }
                // No match found in the prefix.
                if let Some((dctx, mid)) = search_into_dict
                    && ip_index.wrapping_sub(g_dict_end_index) < DISTANCE_MAX - 8
                {
                    // Search a match in the external dictionary.
                    let d_match = if mid {
                        mid_search_ext_dict(buf, ip, ip_index, matchlimit, dctx, g_dict_end_index)
                    } else {
                        search_ext_dict(
                            buf,
                            ip,
                            ip_index,
                            ip,
                            matchlimit,
                            dctx,
                            g_dict_end_index,
                            MINMATCH as i32 - 1,
                            2,
                        )
                    };
                    if d_match.len >= MINMATCH as i32 {
                        debug_assert!(d_match.back == 0);
                        match_length = d_match.len as usize;
                        match_distance = d_match.off as usize;
                        break 'encode;
                    }
                }
                // No match found: skip faster over incompressible data.
                ip += 1 + ((ip - anchor) >> 9);
                continue 'main;
            }

            // _lz4mid_encode_sequence: catch back.
            while (ip > anchor) & ((ip - prefix_ptr) > match_distance)
                && buf[ip - 1] == buf[ip - match_distance - 1]
            {
                ip -= 1;
                match_length += 1;
            }

            // Fill the table with the beginning of the match.
            ctx.hash_table[MID_HASHTABLESIZE + mid_hash8_ptr(buf, ip + 1)] = ip_index + 1;
            ctx.hash_table[MID_HASHTABLESIZE + mid_hash8_ptr(buf, ip + 2)] = ip_index + 2;
            ctx.hash_table[mid_hash4_ptr(buf, ip + 1)] = ip_index + 1;

            // Encode. On success, ip and anchor move; op always does.
            {
                let saved_op = op;
                if encode_sequence(
                    buf,
                    dst,
                    &mut ip,
                    &mut op,
                    &mut anchor,
                    match_length,
                    match_distance,
                    limit,
                    oend,
                ) {
                    // Restore op from before the failed sequence.
                    op = saved_op;
                    // _lz4mid_dest_overflow:
                    if limit == Limit::FillOutput {
                        fill_last_sequence(
                            buf,
                            dst,
                            &mut ip,
                            &mut op,
                            &mut anchor,
                            match_length,
                            match_distance,
                            oend,
                        );
                        break 'last_literals;
                    }
                    // Compression failed.
                    return 0;
                }
            }

            // Fill the table with the end of the match.
            {
                let end_match_idx = (ip - prefix_ptr) as u32 + prefix_idx;
                let pos_m2 = end_match_idx - 2;
                if pos_m2 < ilimit_idx {
                    if ip - prefix_ptr > 5 {
                        ctx.hash_table[MID_HASHTABLESIZE + mid_hash8_ptr(buf, ip - 5)] =
                            end_match_idx - 5;
                    }
                    ctx.hash_table[MID_HASHTABLESIZE + mid_hash8_ptr(buf, ip - 3)] =
                        end_match_idx - 3;
                    ctx.hash_table[MID_HASHTABLESIZE + mid_hash8_ptr(buf, ip - 2)] =
                        end_match_idx - 2;
                    ctx.hash_table[mid_hash4_ptr(buf, ip - 2)] = end_match_idx - 2;
                    ctx.hash_table[mid_hash4_ptr(buf, ip - 1)] = end_match_idx - 1;
                }
            }
        }
    }

    // _lz4mid_last_literals:
    if limit == Limit::FillOutput {
        // Restore the correct value.
        oend += LASTLITERALS as isize;
    }
    last_literals(
        buf,
        source,
        iend,
        anchor,
        dst,
        op,
        oend as usize,
        limit,
        src_size,
    )
}

/**************************************
 *  HC Compression - hash chains
 **************************************/

/// `LZ4HC_compress_hashChain`'s labels.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    MainLoop,
    Search2,
    Search3,
}

/// `LZ4HC_compress_hashChain`: levels 3 to 9.
// C-style: locals set on every path the C sets them, before use.
#[allow(unused_assignments)]
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn compress_hash_chain(
    ctx: &mut HcState,
    v: View<'_>,
    dict_ctx: Option<&(HcState, Vec<u8>)>,
    source: usize,
    dst: &mut [u8],
    src_size: &mut usize,
    max_output_size: usize,
    max_nb_attempts: i32,
    limit: Limit,
) -> usize {
    let buf = v.buf;
    let input_size = *src_size;
    // Levels 9 and up.
    let pattern_analysis = max_nb_attempts > 128;

    let mut ip = source;
    let mut anchor = ip;
    let iend = ip + input_size;
    let mflimit = iend as isize - MFLIMIT as isize;
    let matchlimit = iend - LASTLITERALS.min(iend);

    let mut optr = 0usize;
    let mut op = 0usize;
    let mut oend = max_output_size as isize;

    let mut start0 = ip;
    let mut start2 = 0usize;
    let mut start3 = 0usize;
    let mut m0 = Match::default();
    let mut m1 = Match::default();
    let mut m2 = Match::default();
    let mut m3;
    let nomatch = Match::default();

    *src_size = 0;
    if limit == Limit::FillOutput {
        // A hack for the LZ4 format restriction.
        oend -= LASTLITERALS as isize;
    }

    let wider = |ctx: &mut HcState, at: usize, low: usize, longest: i32| {
        insert_and_get_wider_match(
            ctx,
            v,
            dict_ctx,
            at,
            low,
            matchlimit,
            longest,
            max_nb_attempts,
            pattern_analysis,
            false,
            false,
        )
    };

    'last_literals: {
        if input_size < MIN_LENGTH {
            // Input too small, no compression (all literals).
            break 'last_literals;
        }

        let mut step = Step::MainLoop;
        'dest_overflow: {
            loop {
                match step {
                    Step::MainLoop => {
                        if ip as isize > mflimit {
                            break 'last_literals;
                        }
                        m1 = insert_and_find_best_match(
                            ctx,
                            v,
                            dict_ctx,
                            ip,
                            matchlimit,
                            max_nb_attempts,
                            pattern_analysis,
                        );
                        if m1.len < MINMATCH as i32 {
                            ip += 1;
                            continue;
                        }
                        // Saved, in case we would skip too much.
                        start0 = ip;
                        m0 = m1;
                        step = Step::Search2;
                    }
                    Step::Search2 => {
                        if (ip + m1.len as usize) as isize <= mflimit {
                            start2 = ip + m1.len as usize - 2;
                            m2 = wider(ctx, start2, ip, m1.len);
                            start2 = (start2 as isize + m2.back as isize) as usize;
                        } else {
                            // Do not search further.
                            m2 = nomatch;
                        }

                        if m2.len <= m1.len {
                            // No better match: encode ML1 immediately.
                            optr = op;
                            if encode_sequence(
                                buf,
                                dst,
                                &mut ip,
                                &mut op,
                                &mut anchor,
                                m1.len as usize,
                                m1.off as usize,
                                limit,
                                oend,
                            ) {
                                break 'dest_overflow;
                            }
                            step = Step::MainLoop;
                            continue;
                        }

                        if start0 < ip && start2 < ip + m0.len as usize {
                            // The first match was skipped at least once:
                            // squeezing ML1 between ML0 (the original ML1)
                            // and ML2. Restore the initial match 1.
                            ip = start0;
                            m1 = m0;
                        }

                        // Here, start0 == ip.
                        if start2 - ip < 3 {
                            // The first match is too small: removed.
                            ip = start2;
                            m1 = m2;
                            step = Step::Search2;
                            continue;
                        }
                        step = Step::Search3;
                    }
                    Step::Search3 => {
                        if start2 - ip < OPTIMAL_ML {
                            let mut new_ml = m1.len as usize;
                            if new_ml > OPTIMAL_ML {
                                new_ml = OPTIMAL_ML;
                            }
                            if ip + new_ml > start2 + m2.len as usize - MINMATCH {
                                new_ml = (start2 - ip) + m2.len as usize - MINMATCH;
                            }
                            let correction = new_ml as isize - (start2 - ip) as isize;
                            if correction > 0 {
                                start2 += correction as usize;
                                m2.len -= correction as i32;
                            }
                        }

                        if (start2 + m2.len as usize) as isize <= mflimit {
                            start3 = start2 + m2.len as usize - 3;
                            m3 = wider(ctx, start3, start2, m2.len);
                            start3 = (start3 as isize + m3.back as isize) as usize;
                        } else {
                            // Do not search further.
                            m3 = nomatch;
                        }

                        if m3.len <= m2.len {
                            // No better match: encode ML1 and ML2. ip and the
                            // reference are known; now for ml.
                            if start2 < ip + m1.len as usize {
                                m1.len = (start2 - ip) as i32;
                            }
                            // Now, encode 2 sequences.
                            optr = op;
                            if encode_sequence(
                                buf,
                                dst,
                                &mut ip,
                                &mut op,
                                &mut anchor,
                                m1.len as usize,
                                m1.off as usize,
                                limit,
                                oend,
                            ) {
                                break 'dest_overflow;
                            }
                            ip = start2;
                            optr = op;
                            if encode_sequence(
                                buf,
                                dst,
                                &mut ip,
                                &mut op,
                                &mut anchor,
                                m2.len as usize,
                                m2.off as usize,
                                limit,
                                oend,
                            ) {
                                m1 = m2;
                                break 'dest_overflow;
                            }
                            step = Step::MainLoop;
                            continue;
                        }

                        if start3 < ip + m1.len as usize + 3 {
                            // Not enough space for match 2: remove it.
                            if start3 >= ip + m1.len as usize {
                                // Seq1 can be written now: Seq2 is removed,
                                // so Seq3 becomes Seq1.
                                if start2 < ip + m1.len as usize {
                                    let correction = (ip + m1.len as usize - start2) as i32;
                                    start2 += correction as usize;
                                    m2.len -= correction;
                                    if m2.len < MINMATCH as i32 {
                                        start2 = start3;
                                        m2 = m3;
                                    }
                                }

                                optr = op;
                                if encode_sequence(
                                    buf,
                                    dst,
                                    &mut ip,
                                    &mut op,
                                    &mut anchor,
                                    m1.len as usize,
                                    m1.off as usize,
                                    limit,
                                    oend,
                                ) {
                                    break 'dest_overflow;
                                }
                                ip = start3;
                                m1 = m3;

                                start0 = start2;
                                m0 = m2;
                                step = Step::Search2;
                                continue;
                            }

                            start2 = start3;
                            m2 = m3;
                            step = Step::Search3;
                            continue;
                        }

                        // Now there are 3 ascending matches: write the first
                        // one, ML1. ip and the reference are known; now
                        // decide ml.
                        if start2 < ip + m1.len as usize {
                            if start2 - ip < OPTIMAL_ML {
                                if m1.len as usize > OPTIMAL_ML {
                                    m1.len = OPTIMAL_ML as i32;
                                }
                                if ip + m1.len as usize > start2 + m2.len as usize - MINMATCH {
                                    m1.len = ((start2 - ip) + m2.len as usize - MINMATCH) as i32;
                                }
                                let correction = m1.len - (start2 - ip) as i32;
                                if correction > 0 {
                                    start2 += correction as usize;
                                    m2.len -= correction;
                                }
                            } else {
                                m1.len = (start2 - ip) as i32;
                            }
                        }
                        optr = op;
                        if encode_sequence(
                            buf,
                            dst,
                            &mut ip,
                            &mut op,
                            &mut anchor,
                            m1.len as usize,
                            m1.off as usize,
                            limit,
                            oend,
                        ) {
                            break 'dest_overflow;
                        }

                        // ML2 becomes ML1.
                        ip = start2;
                        m1 = m2;

                        // ML3 becomes ML2.
                        start2 = start3;
                        m2 = m3;

                        // Find a new ML3.
                        step = Step::Search3;
                    }
                }
            }
        }

        // _dest_overflow:
        if limit == Limit::FillOutput {
            // ip, anchor, optr and m1 are set.
            op = optr;
            fill_last_sequence(
                buf,
                dst,
                &mut ip,
                &mut op,
                &mut anchor,
                m1.len as usize,
                m1.off as usize,
                oend,
            );
            break 'last_literals;
        }
        // Compression failed.
        return 0;
    }

    // _last_literals:
    if limit == Limit::FillOutput {
        // Restore the correct value.
        oend += LASTLITERALS as isize;
    }
    last_literals(
        buf,
        source,
        iend,
        anchor,
        dst,
        op,
        oend as usize,
        limit,
        src_size,
    )
}

/* ================================================
 *  LZ4 Optimal parser (levels [CLEVEL_OPT_MIN - CLEVEL_MAX])
 * ===============================================*/

/// `LZ4HC_optimal_t`.
#[derive(Clone, Copy, Default)]
struct Optimal {
    price: i32,
    off: i32,
    mlen: i32,
    litlen: i32,
}

/// `LZ4HC_literalsPrice`: the price in bytes.
#[inline(always)]
fn literals_price(litlen: i32) -> i32 {
    let mut price = litlen;
    if litlen >= RUN_MASK as i32 {
        price += 1 + (litlen - RUN_MASK as i32) / 255;
    }
    price
}

/// `LZ4HC_sequencePrice`: requires `mlen >= MINMATCH`.
#[inline(always)]
fn sequence_price(litlen: i32, mlen: i32) -> i32 {
    // The token and the 16-bit offset.
    let mut price = 1 + 2;
    price += literals_price(litlen);
    if mlen >= (ML_MASK + MINMATCH) as i32 {
        price += 1 + (mlen - (ML_MASK + MINMATCH) as i32) / 255;
    }
    price
}

/// `LZ4HC_FindLongerMatch`.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn find_longer_match(
    ctx: &mut HcState,
    v: View<'_>,
    dict_ctx: Option<&(HcState, Vec<u8>)>,
    ip: usize,
    i_high_limit: usize,
    min_len: i32,
    nb_searches: i32,
    favor_dec_speed: bool,
) -> Match {
    let mut md = insert_and_get_wider_match(
        ctx,
        v,
        dict_ctx,
        ip,
        ip,
        i_high_limit,
        min_len,
        nb_searches,
        true,
        true,
        favor_dec_speed,
    );
    debug_assert!(md.back == 0);
    if md.len <= min_len {
        return Match::default();
    }
    if favor_dec_speed && (md.len > 18) & (md.len <= 36) {
        // Favor the decompression speed (shortcut).
        md.len = 18;
    }
    md
}

/// `LZ4HC_compress_optimal`: levels 10 to 12.
// C-style: locals set on every path the C sets them, before use.
#[allow(unused_assignments)]
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn compress_optimal(
    ctx: &mut HcState,
    v: View<'_>,
    dict_ctx: Option<&(HcState, Vec<u8>)>,
    source: usize,
    dst: &mut [u8],
    src_size: &mut usize,
    dst_capacity: usize,
    nb_searches: i32,
    mut sufficient_len: usize,
    limit: Limit,
    full_update: bool,
    favor_dec_speed: bool,
) -> usize {
    let buf = v.buf;
    let mut opt = vec![Optimal::default(); OPT_NUM + TRAILING_LITERALS];

    let mut ip = source;
    let mut anchor = ip;
    let iend = ip + *src_size;
    let mflimit = iend as isize - MFLIMIT as isize;
    let matchlimit = iend - LASTLITERALS.min(iend);
    let mut op = 0usize;
    let mut op_saved = 0usize;
    let mut oend = dst_capacity as isize;
    // Overflow: the last sequence.
    let mut ovml = MINMATCH;
    let mut ovoff = 0usize;
    let fdec = i32::from(favor_dec_speed);

    *src_size = 0;
    if limit == Limit::FillOutput {
        // A hack for the LZ4 format restriction.
        oend -= LASTLITERALS as isize;
    }
    if sufficient_len >= OPT_NUM {
        sufficient_len = OPT_NUM - 1;
    }

    'last_literals: {
        'dest_overflow: {
            // Main loop.
            while ip as isize <= mflimit {
                let llen = (ip - anchor) as i32;
                let best_mlen: i32;
                let best_off: i32;
                let mut cur: i32;
                let mut last_match_pos: i32;

                let first_match = find_longer_match(
                    ctx,
                    v,
                    dict_ctx,
                    ip,
                    matchlimit,
                    MINMATCH as i32 - 1,
                    nb_searches,
                    favor_dec_speed,
                );
                if first_match.len == 0 {
                    ip += 1;
                    continue;
                }

                if first_match.len as usize > sufficient_len {
                    // A good enough solution: immediate encoding.
                    let first_ml = first_match.len as usize;
                    op_saved = op;
                    if encode_sequence(
                        buf,
                        dst,
                        &mut ip,
                        &mut op,
                        &mut anchor,
                        first_ml,
                        first_match.off as usize,
                        limit,
                        oend,
                    ) {
                        ovml = first_ml;
                        ovoff = first_match.off as usize;
                        break 'dest_overflow;
                    }
                    continue;
                }

                // Set prices for the first positions (literals).
                for r_pos in 0..MINMATCH {
                    let cost = literals_price(llen + r_pos as i32);
                    opt[r_pos] = Optimal {
                        mlen: 1,
                        off: 0,
                        litlen: llen + r_pos as i32,
                        price: cost,
                    };
                }
                // Set prices using the initial match.
                {
                    // Necessarily < sufficient_len < OPT_NUM.
                    let match_ml = first_match.len;
                    let offset = first_match.off;
                    for mlen in MINMATCH as i32..=match_ml {
                        let cost = sequence_price(llen, mlen);
                        opt[mlen as usize] = Optimal {
                            mlen,
                            off: offset,
                            litlen: llen,
                            price: cost,
                        };
                    }
                }
                last_match_pos = first_match.len;
                for add_lit in 1..=TRAILING_LITERALS as i32 {
                    let at = (last_match_pos + add_lit) as usize;
                    opt[at] = Optimal {
                        mlen: 1,
                        off: 0,
                        litlen: add_lit,
                        price: opt[last_match_pos as usize].price + literals_price(add_lit),
                    };
                }

                // Check further positions.
                'encode: {
                    cur = 1;
                    while cur < last_match_pos {
                        let cur_ptr = ip + cur as usize;
                        let c = cur as usize;

                        if cur_ptr as isize > mflimit {
                            break;
                        }
                        if full_update {
                            // Not useful to search here if the next position
                            // has the same (or a lower) cost: unless the cost
                            // rises sharply after, where a small match would
                            // still be beneficial.
                            if opt[c + 1].price <= opt[c].price
                                && opt[c + MINMATCH].price < opt[c].price + 3
                            /* min seq price */
                            {
                                cur += 1;
                                continue;
                            }
                        } else if opt[c + 1].price <= opt[c].price {
                            cur += 1;
                            continue;
                        }

                        let new_match = if full_update {
                            find_longer_match(
                                ctx,
                                v,
                                dict_ctx,
                                cur_ptr,
                                matchlimit,
                                MINMATCH as i32 - 1,
                                nb_searches,
                                favor_dec_speed,
                            )
                        } else {
                            // Only test matches of the minimum length:
                            // slightly faster, but misses a few bytes.
                            find_longer_match(
                                ctx,
                                v,
                                dict_ctx,
                                cur_ptr,
                                matchlimit,
                                last_match_pos - cur,
                                nb_searches,
                                favor_dec_speed,
                            )
                        };
                        if new_match.len == 0 {
                            cur += 1;
                            continue;
                        }

                        if new_match.len as usize > sufficient_len
                            || (new_match.len + cur) as usize >= OPT_NUM
                        {
                            // Immediate encoding.
                            best_mlen = new_match.len;
                            best_off = new_match.off;
                            last_match_pos = cur + 1;
                            break 'encode;
                        }

                        // Before the match: set the prices with literals at
                        // the beginning.
                        {
                            let base_litlen = opt[c].litlen;
                            for litlen in 1..MINMATCH as i32 {
                                let price = opt[c].price - literals_price(base_litlen)
                                    + literals_price(base_litlen + litlen);
                                let pos = c + litlen as usize;
                                if price < opt[pos].price {
                                    opt[pos] = Optimal {
                                        mlen: 1,
                                        off: 0,
                                        litlen: base_litlen + litlen,
                                        price,
                                    };
                                }
                            }
                        }

                        // Set the prices using the match at position = cur.
                        {
                            let match_ml = new_match.len;
                            for ml in MINMATCH as i32..=match_ml {
                                let pos = c + ml as usize;
                                let offset = new_match.off;
                                let (price, ll) = if opt[c].mlen == 1 {
                                    let ll = opt[c].litlen;
                                    let base = if cur > ll {
                                        opt[(cur - ll) as usize].price
                                    } else {
                                        0
                                    };
                                    (base + sequence_price(ll, ml), ll)
                                } else {
                                    (opt[c].price + sequence_price(0, ml), 0)
                                };

                                if pos as i32 > last_match_pos + TRAILING_LITERALS as i32
                                    || price <= opt[pos].price - fdec
                                {
                                    if ml == match_ml && last_match_pos < pos as i32 {
                                        // The last position of the last match.
                                        last_match_pos = pos as i32;
                                    }
                                    opt[pos] = Optimal {
                                        mlen: ml,
                                        off: offset,
                                        litlen: ll,
                                        price,
                                    };
                                }
                            }
                        }
                        // Complete the following positions with literals.
                        for add_lit in 1..=TRAILING_LITERALS as i32 {
                            let at = (last_match_pos + add_lit) as usize;
                            opt[at] = Optimal {
                                mlen: 1,
                                off: 0,
                                litlen: add_lit,
                                price: opt[last_match_pos as usize].price + literals_price(add_lit),
                            };
                        }
                        cur += 1;
                    }

                    best_mlen = opt[last_match_pos as usize].mlen;
                    best_off = opt[last_match_pos as usize].off;
                    cur = last_match_pos - best_mlen;
                }

                // encode: cur, last_match_pos, best_mlen and best_off are
                // set. A reverse traversal, looking for the shortest path.
                {
                    let mut candidate_pos = cur;
                    let mut selected_match_length = best_mlen;
                    let mut selected_offset = best_off;
                    loop {
                        // From the end to the beginning.
                        let next_match_length = opt[candidate_pos as usize].mlen; // 1 for a literal
                        let next_offset = opt[candidate_pos as usize].off;
                        opt[candidate_pos as usize].mlen = selected_match_length;
                        opt[candidate_pos as usize].off = selected_offset;
                        selected_match_length = next_match_length;
                        selected_offset = next_offset;
                        if next_match_length > candidate_pos {
                            // The last match elected, the first to encode.
                            break;
                        }
                        candidate_pos -= next_match_length;
                    }
                }

                // Encode all the recorded sequences in order.
                {
                    // The position relative to ip.
                    let mut r_pos = 0;
                    while r_pos < last_match_pos {
                        let ml = opt[r_pos as usize].mlen;
                        let offset = opt[r_pos as usize].off;
                        if ml == 1 {
                            // A literal; there can be several, skipped.
                            ip += 1;
                            r_pos += 1;
                            continue;
                        }
                        r_pos += ml;
                        op_saved = op;
                        if encode_sequence(
                            buf,
                            dst,
                            &mut ip,
                            &mut op,
                            &mut anchor,
                            ml as usize,
                            offset as usize,
                            limit,
                            oend,
                        ) {
                            ovml = ml as usize;
                            ovoff = offset as usize;
                            break 'dest_overflow;
                        }
                    }
                }
            }
            break 'last_literals;
        }

        // _dest_overflow:
        if limit == Limit::FillOutput {
            // ip, anchor, ovml and ovoff are set.
            op = op_saved;
            fill_last_sequence(buf, dst, &mut ip, &mut op, &mut anchor, ovml, ovoff, oend);
            break 'last_literals;
        }
        // Compression failed.
        return 0;
    }

    // _last_literals:
    if limit == Limit::FillOutput {
        // Restore the correct value.
        oend += LASTLITERALS as isize;
    }
    last_literals(
        buf,
        source,
        iend,
        anchor,
        dst,
        op,
        oend as usize,
        limit,
        src_size,
    )
}

/**************************************
 *  Generic
 **************************************/

/// `LZ4HC_compress_generic_internal`: the source, at `source` in `v.buf`,
/// right after the prefix, compressed at `c_level`.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn compress_generic_internal(
    ctx: &mut HcState,
    v: View<'_>,
    dict_ctx: Option<&(HcState, Vec<u8>)>,
    source: usize,
    dst: &mut [u8],
    src_size: &mut usize,
    dst_capacity: usize,
    c_level: i32,
    limit: Limit,
) -> usize {
    if limit == Limit::FillOutput && dst_capacity < 1 {
        // Impossible to store anything.
        return 0;
    }
    if *src_size > MAX_INPUT_SIZE {
        // Unsupported input size.
        return 0;
    }

    ctx.prefix_size += *src_size;
    let c_param = clevel_params(c_level);
    let favor = ctx.favor_dec_speed;
    let result = match c_param.strat {
        Strat::Lz4Mid => mid_compress(ctx, v, dict_ctx, source, dst, src_size, dst_capacity, limit),
        Strat::Lz4Hc => compress_hash_chain(
            ctx,
            v,
            dict_ctx,
            source,
            dst,
            src_size,
            dst_capacity,
            c_param.nb_searches,
            limit,
        ),
        Strat::Lz4Opt => compress_optimal(
            ctx,
            v,
            dict_ctx,
            source,
            dst,
            src_size,
            dst_capacity,
            c_param.nb_searches,
            c_param.target_length,
            limit,
            // Ultra mode.
            c_level >= CLEVEL_MAX,
            favor,
        ),
    };
    if result == 0 {
        ctx.dirty = true;
    }
    result
}

/// `isStateCompatible`.
fn is_state_compatible(ctx1: &HcState, ctx2: &HcState) -> bool {
    let is_mid1 = clevel_params(ctx1.compression_level).strat == Strat::Lz4Mid;
    let is_mid2 = clevel_params(ctx2.compression_level).strat == Strat::Lz4Mid;
    is_mid1 == is_mid2
}

/// `LZ4HC_compress_generic`, and its `dictCtx` case: an attached dictionary
/// is used for the first 64 KB, copied into the context for a first block of
/// more than 4 KB (and then `dict_ctx` is dropped), and after that dropped.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compress_generic(
    ctx: &mut HcState,
    v: View<'_>,
    dict_ctx: &mut Option<DictCtx>,
    source: usize,
    dst: &mut [u8],
    src_size: &mut usize,
    dst_capacity: usize,
    c_level: i32,
    limit: Limit,
) -> usize {
    let Some(dctx) = dict_ctx.clone() else {
        return compress_generic_internal(
            ctx,
            v,
            None,
            source,
            dst,
            src_size,
            dst_capacity,
            c_level,
            limit,
        );
    };
    let position = ctx.prefix_size + (ctx.dict_limit - ctx.low_limit) as usize;
    if position >= 64 * KB {
        *dict_ctx = None;
        compress_generic_internal(
            ctx,
            v,
            None,
            source,
            dst,
            src_size,
            dst_capacity,
            c_level,
            limit,
        )
    } else if position == 0 && *src_size > 4 * KB && is_state_compatible(ctx, &dctx.0) {
        // The dictionary's context becomes this one's, and its dictionary
        // the external dictionary.
        *ctx = dctx.0.clone();
        *dict_ctx = None;
        let content = &dctx.1;
        set_external_dict(ctx, content, 0);
        ctx.compression_level = c_level;
        let view = View {
            buf: v.buf,
            pstart: source,
            dict: content,
        };
        compress_generic_internal(
            ctx,
            view,
            None,
            source,
            dst,
            src_size,
            dst_capacity,
            c_level,
            limit,
        )
    } else {
        compress_generic_internal(
            ctx,
            v,
            Some(&dctx),
            source,
            dst,
            src_size,
            dst_capacity,
            c_level,
            limit,
        )
    }
}

/// `LZ4HC_setExternalDict`: the prefix, `prefix[pstart..]` (`prefix_size`
/// bytes), becomes the external dictionary, and the next block starts a new
/// prefix. liblz4 also drops the attached dictionary (`dictCtx`), which is
/// the caller's to drop.
pub(crate) fn set_external_dict(ctx: &mut HcState, prefix: &[u8], pstart: usize) {
    if ctx.prefix_size >= 4 && clevel_params(ctx.compression_level).strat != Strat::Lz4Mid {
        // Reference the remaining dictionary content.
        let end = pstart + ctx.prefix_size;
        ctx.insert(prefix, pstart, end - 3);
    }
    // Only one memory segment for extDict, so any previous extDict is lost
    // at this stage.
    ctx.low_limit = ctx.dict_limit;
    ctx.dict_limit = ctx.dict_limit.wrapping_add(ctx.prefix_size as u32);
    ctx.prefix_size = 0;
    ctx.prefix_null = false;
    // Match referencing resumes from there.
    ctx.next_to_update = ctx.dict_limit;
}

impl HcState {
    /// `LZ4_compress_HC_extStateHC_fastReset`: `src` compressed alone, the
    /// state reset where it has to be.
    pub(crate) fn compress_ext_state_fast_reset(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        compression_level: i32,
    ) -> usize {
        self.reset_fast(compression_level);
        self.init_internal();
        let limit = if dst.len() < compress_bound(src.len()) {
            Limit::LimitedOutput
        } else {
            Limit::NotLimited
        };
        let mut src_size = src.len();
        let capacity = dst.len();
        let view = View {
            buf: src,
            pstart: 0,
            dict: &[],
        };
        compress_generic(
            self,
            view,
            &mut None,
            0,
            dst,
            &mut src_size,
            capacity,
            compression_level,
            limit,
        )
    }

    /// `LZ4_compress_HC_extStateHC`.
    pub(crate) fn compress_ext_state(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        compression_level: i32,
    ) -> usize {
        self.init_stream();
        self.compress_ext_state_fast_reset(src, dst, compression_level)
    }

    /// `LZ4_compress_HC_destSize`: as much of `src` as fits in `dst`.
    pub(crate) fn compress_dest_size(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        src_size: &mut usize,
        c_level: i32,
    ) -> usize {
        self.init_stream();
        self.init_internal();
        self.set_compression_level(c_level);
        let capacity = dst.len();
        let view = View {
            buf: src,
            pstart: 0,
            dict: &[],
        };
        compress_generic(
            self,
            view,
            &mut None,
            0,
            dst,
            src_size,
            capacity,
            c_level,
            Limit::FillOutput,
        )
    }
}

/// `LZ4_compress_HC`: `src` compressed alone into `dst` at
/// `compression_level` (2 to 12; 0 or less is 9, the default; more than 12
/// is 12). Returns the compressed size, or 0 if it does not fit in `dst`.
pub fn compress_hc(src: &[u8], dst: &mut [u8], compression_level: i32) -> usize {
    HcState::default().compress_ext_state(src, dst, compression_level)
}

/// `LZ4_streamHC_t`, as a state for the one-call compressors that take one
/// (`LZ4_compress_HC_extStateHC`, its `_fastReset` form, and
/// `LZ4_compress_HC_destSize`), so that its tables are allocated once.
#[derive(Clone, Debug, Default)]
pub struct StateHc {
    state: HcState,
}

impl StateHc {
    /// `LZ4_createStreamHC`.
    pub fn new() -> Self {
        StateHc::default()
    }

    /// `LZ4_compress_HC_extStateHC`: as [`compress_hc`], with this state,
    /// which it initialises first.
    pub fn compress_hc_ext_state(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        compression_level: i32,
    ) -> usize {
        self.state.compress_ext_state(src, dst, compression_level)
    }

    /// `LZ4_compress_HC_extStateHC_fastReset`: as
    /// [`compress_hc_ext_state`](Self::compress_hc_ext_state), with the
    /// state reset only where it has to be. The output can differ from
    /// `compress_hc`'s, as liblz4's does.
    pub fn compress_hc_ext_state_fast_reset(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        compression_level: i32,
    ) -> usize {
        self.state
            .compress_ext_state_fast_reset(src, dst, compression_level)
    }

    /// `LZ4_compress_HC_destSize`: as much of `src` as fits in `dst`,
    /// compressed. Returns the compressed size and how much of `src` it
    /// holds.
    pub fn compress_hc_dest_size(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        compression_level: i32,
    ) -> (usize, usize) {
        let mut src_size = src.len();
        let written = self
            .state
            .compress_dest_size(src, dst, &mut src_size, compression_level);
        (written, src_size)
    }
}

/**************************************
 *  Streaming Functions
 **************************************/

impl HcState {
    /// `LZ4_loadDictHC`: the state reset (keeping its level) with the last
    /// 64 KB of `dictionary` as its prefix. Returns their size; the prefix
    /// is the caller's to keep.
    pub(crate) fn load_dict(&mut self, dictionary: &[u8]) -> usize {
        let dict = &dictionary[dictionary.len() - dictionary.len().min(64 * KB)..];
        // A full initialization: there are bad side effects with the fast
        // reset.
        let c_level = self.compression_level;
        self.init_stream();
        self.set_compression_level(c_level);
        let cp = clevel_params(c_level);
        self.init_internal();
        self.prefix_size = dict.len();
        if cp.strat == Strat::Lz4Mid {
            mid_fill_htable(self, dict);
        } else if dict.len() >= HASHSIZE {
            self.insert(dict, 0, dict.len() - 3);
        }
        dict.len()
    }

    /// `LZ4_saveDictHC`'s effect on the state: the prefix is its last
    /// `dict_size` bytes (at most 64 KB; none for less than 4), moved where
    /// the caller keeps them. Returns the size kept.
    pub(crate) fn save_dict(&mut self, dict_size: usize) -> usize {
        let prefix_size = self.prefix_size;
        let mut dict_size = dict_size.min(64 * KB);
        if dict_size < 4 {
            dict_size = 0;
        }
        dict_size = dict_size.min(prefix_size);
        let end_index = (prefix_size as u32).wrapping_add(self.dict_limit);
        self.prefix_size = dict_size;
        self.prefix_null = false;
        self.dict_limit = end_index.wrapping_sub(dict_size as u32);
        self.low_limit = end_index.wrapping_sub(dict_size as u32);
        if self.next_to_update < self.dict_limit {
            self.next_to_update = self.dict_limit;
        }
        dict_size
    }
}

/// `LZ4_streamHC_t`, streaming: blocks compressed one after another at a
/// level, each with the ones before (up to 64 KB) as its history
/// (`LZ4_compress_HC_continue`), and dictionaries (`LZ4_loadDictHC`,
/// `LZ4_attach_HC_dictionary`).
///
/// Differs from liblz4: as `block::Stream`, the stream keeps a copy of its
/// history, as liblz4 does when the caller saves it after each block
/// (`LZ4_saveDictHC`, with 64 KB): the blocks are liblz4's in that case.
#[derive(Clone, Debug, Default)]
pub struct StreamHc {
    state: HcState,
    /// The prefix: the history, the state's `end - prefixStart` bytes.
    history: Vec<u8>,
    dict_ctx: Option<DictCtx>,
}

impl StreamHc {
    /// `LZ4_createStreamHC`: a stream at the default level, 9.
    pub fn new() -> Self {
        StreamHc::default()
    }

    /// `LZ4_resetStreamHC`: the stream as new, at `compression_level`.
    pub fn reset(&mut self, compression_level: i32) {
        self.state.init_stream();
        self.state.set_compression_level(compression_level);
        self.history.clear();
        self.dict_ctx = None;
    }

    /// `LZ4_resetStreamHC_fast`: the history forgotten, the tables kept
    /// where they can be.
    pub fn reset_fast(&mut self, compression_level: i32) {
        self.state.reset_fast(compression_level);
        self.history.clear();
        self.dict_ctx = None;
    }

    /// `LZ4_setCompressionLevel`: 2 to 12; 0 or less is 9, more than 12 is
    /// 12.
    pub fn set_compression_level(&mut self, compression_level: i32) {
        self.state.set_compression_level(compression_level);
    }

    /// `LZ4_favorDecompressionSpeed`: at levels 10 to 12, matches that
    /// decompress faster.
    pub fn favor_decompression_speed(&mut self, favor: bool) {
        self.state.favor_decompression_speed(favor);
    }

    /// `LZ4_loadDictHC`: the stream reset (keeping its level), with the last
    /// 64 KB of `dictionary` as the history of the next block. Returns
    /// their size.
    pub fn load_dict_hc(&mut self, dictionary: &[u8]) -> usize {
        self.dict_ctx = None;
        let size = self.state.load_dict(dictionary);
        self.history.clear();
        self.history
            .extend_from_slice(&dictionary[dictionary.len() - size..]);
        size
    }

    /// `LZ4_attach_HC_dictionary`: `dictionary`, a stream a dictionary was
    /// loaded into, as the history of the next blocks, up to 64 KB of them.
    /// The stream must have been reset (`reset_fast`) or be new.
    pub fn attach_hc_dictionary(&mut self, dictionary: &StreamHc) {
        self.dict_ctx = Some(Arc::new((
            dictionary.state.clone(),
            dictionary.history.clone(),
        )));
    }

    /// `LZ4_compress_HC_continue`: the next block, with the ones before as
    /// its history. Returns its compressed size, or 0 if it does not fit in
    /// `dst`.
    pub fn compress_hc_continue(&mut self, src: &[u8], dst: &mut [u8]) -> usize {
        let limit = if dst.len() < compress_bound(src.len()) {
            Limit::LimitedOutput
        } else {
            Limit::NotLimited
        };
        let mut src_size = src.len();
        self.continue_generic(src, dst, &mut src_size, limit)
    }

    /// `LZ4_compress_HC_continue_destSize`: as much of the next block as
    /// fits in `dst`. Returns the compressed size and how much of `src` it
    /// holds.
    pub fn compress_hc_continue_dest_size(&mut self, src: &[u8], dst: &mut [u8]) -> (usize, usize) {
        let mut src_size = src.len();
        let written = self.continue_generic(src, dst, &mut src_size, Limit::FillOutput);
        (written, src_size)
    }

    /// `LZ4_compressHC_continue_generic`, then `LZ4_saveDictHC` of 64 KB.
    fn continue_generic(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        src_size: &mut usize,
        limit: Limit,
    ) -> usize {
        let st = &mut self.state;
        let mut history = core::mem::take(&mut self.history);
        // Auto-init if forgotten.
        let first = st.prefix_null;
        if first {
            st.init_internal();
        }

        // Check for overflow.
        if st.prefix_size + st.dict_limit as usize > 2 * GB {
            let dict_size = st.prefix_size.min(64 * KB);
            let keep = history.len() - dict_size;
            history.drain(..keep);
            st.load_dict(&history);
        }

        // The blocks do not follow each other: the history becomes the
        // external dictionary.
        if !first {
            set_external_dict(st, &history, 0);
            // An external dictionary and an attached one cannot be
            // referenced at the same time.
            self.dict_ctx = None;
        }
        let dict: &[u8] = if first { &[] } else { &history };
        let view = View {
            buf: src,
            pstart: 0,
            dict,
        };
        let capacity = dst.len();
        let c_level = st.compression_level;
        let result = compress_generic(
            st,
            view,
            &mut self.dict_ctx,
            0,
            dst,
            src_size,
            capacity,
            c_level,
            limit,
        );

        // `LZ4_saveDictHC(stream, safeBuffer, 64 KB)`: the end of the block,
        // which is the prefix now.
        let size = st.save_dict(64 * KB);
        history.clear();
        history.extend_from_slice(&src[src.len() - size..]);
        self.history = history;
        result
    }

    /// `LZ4_saveDictHC`: the history cut to its last `dict_size` bytes (at
    /// most 64 KB, none for less than 4). Returns the size kept.
    pub fn save_dict_hc(&mut self, dict_size: usize) -> usize {
        let size = self.state.save_dict(dict_size);
        let len = self.history.len();
        self.history.drain(..len - size.min(len));
        size
    }

    /// The history: what the next block may refer to.
    pub fn history(&self) -> &[u8] {
        &self.history
    }
}

impl HcState {
    /// `dictLimit - lowLimit`: the size of the external dictionary, 0 when
    /// there is no prefix (the next block starts a new one).
    pub(crate) fn ext_size(&self) -> usize {
        if self.prefix_null {
            return 0;
        }
        self.dict_limit.wrapping_sub(self.low_limit) as usize
    }
}

/// What `continue_located` did to the history, for a caller that keeps
/// track of where it is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Moved {
    /// Nothing: the external dictionary is where it was.
    Nothing,
    /// The prefix became the external dictionary (`LZ4HC_setExternalDict`),
    /// and the block starts a new prefix.
    PrefixToExt,
    /// The attached dictionary's context was copied into the state
    /// (`LZ4HC_compress_generic_dictCtx`, a first block of more than 4 KB):
    /// the external dictionary is the attached dictionary's content.
    DictCtxToExt,
}

/// `LZ4_compressHC_continue_generic`, for a caller that knows where its
/// history is: the source at `source` in `buf`; `follows` whether it starts
/// where the prefix ends (`src == ctx->end`), the prefix then being the
/// state's `prefix_size` bytes before it in `buf`; else the prefix ends at
/// `prefix_end` in `prefix`. `ext` is the external dictionary.
///
/// Differs from liblz4: the case of a source that overlaps the external
/// dictionary is not taken.
#[allow(clippy::too_many_arguments)]
pub(crate) fn continue_located(
    st: &mut HcState,
    dict_ctx: &mut Option<DictCtx>,
    buf: &[u8],
    source: usize,
    follows: bool,
    prefix: &[u8],
    prefix_end: usize,
    ext: &[u8],
    dst: &mut [u8],
    src_size: &mut usize,
    limit: Limit,
) -> (usize, Moved) {
    let mut moved = Moved::Nothing;
    let mut follows = follows;
    // Auto-init if forgotten.
    if st.prefix_null {
        st.init_internal();
        follows = true;
    }

    // Check for overflow: the last 64 KB of the prefix, where they are,
    // loaded as a dictionary.
    if st.prefix_size + st.dict_limit as usize > 2 * GB {
        let dict_size = st.prefix_size.min(64 * KB);
        let (seg, end) = if follows {
            (buf, source)
        } else {
            (prefix, prefix_end)
        };
        st.load_dict(&seg[end - dict_size..end]);
    }

    // Check if the blocks follow each other.
    let view = if follows {
        View {
            buf,
            pstart: source - st.prefix_size,
            dict: ext,
        }
    } else {
        let pstart = prefix_end - st.prefix_size;
        set_external_dict(st, prefix, pstart);
        *dict_ctx = None;
        moved = Moved::PrefixToExt;
        View {
            buf,
            pstart: source,
            dict: &prefix[pstart..prefix_end],
        }
    };
    let had_dict_ctx = dict_ctx.is_some();
    let position = st.prefix_size + st.ext_size();
    let capacity = dst.len();
    let c_level = st.compression_level;
    let result = compress_generic(
        st, view, dict_ctx, source, dst, src_size, capacity, c_level, limit,
    );
    if had_dict_ctx && dict_ctx.is_none() && position == 0 {
        moved = Moved::DictCtxToExt;
    }
    (result, moved)
}
