//! The LZMA SDK's LZMA decoder: `LzmaDec.c`, for the properties that
//! `hivepack::xz`, a port of liblzma's decoder, takes none of: `lc + lp` above
//! 4. Everything else goes there, which is faster.
//!
//! Differs from the LZMA SDK, whose dictionary is the whole output, and which
//! looks ahead (`LzmaDec_TryDummy`) so as not to run past its buffer of input:
//! the dictionary is a ring no larger than it has to be, the output is whatever
//! each call asks for, and the bytes are pulled from a [`ByteIn`], which gives
//! 0 past the end of the input and remembers it. The caller then answers
//! `SZ_ERROR_DATA`, which is what `SzDecodeLzma` answers when `LzmaDec_TryDummy`
//! asks for more input than there is.

use crate::sevenz::error::{Error, Result};
use crate::sevenz::ppmd7::ByteIn;

const NUM_BIT_MODEL_TOTAL_BITS: u32 = 11;
const BIT_MODEL_TOTAL: u32 = 1 << NUM_BIT_MODEL_TOTAL_BITS;
const NUM_MOVE_BITS: u32 = 5;
const TOP_VALUE: u32 = 1 << 24;

const NUM_POS_BITS_MAX: usize = 4;
const LEN_NUM_LOW_BITS: u32 = 3;
const LEN_NUM_LOW_SYMBOLS: u32 = 1 << LEN_NUM_LOW_BITS;
const LEN_NUM_HIGH_BITS: u32 = 8;
const LEN_NUM_HIGH_SYMBOLS: usize = 1 << LEN_NUM_HIGH_BITS;

const LEN_LOW: usize = 0;
const LEN_HIGH: usize = LEN_LOW + 2 * ((1 << NUM_POS_BITS_MAX) << LEN_NUM_LOW_BITS);
const NUM_LEN_PROBS: usize = LEN_HIGH + LEN_NUM_HIGH_SYMBOLS;
const LEN_CHOICE: usize = LEN_LOW;
const LEN_CHOICE2: usize = LEN_LOW + (1 << LEN_NUM_LOW_BITS);

const NUM_STATES: usize = 12;
const NUM_STATES2: usize = 16;
const NUM_LIT_STATES: usize = 7;

const START_POS_MODEL_INDEX: u32 = 4;
const END_POS_MODEL_INDEX: u32 = 14;
const NUM_FULL_DISTANCES: usize = 1 << (END_POS_MODEL_INDEX >> 1);

const NUM_POS_SLOT_BITS: u32 = 6;
const NUM_LEN_TO_POS_STATES: u32 = 4;

const NUM_ALIGN_BITS: u32 = 4;
const ALIGN_TABLE_SIZE: usize = 1 << NUM_ALIGN_BITS;

const MATCH_MIN_LEN: u32 = 2;

const SPEC_POS: usize = 0;
const IS_REP0_LONG: usize = SPEC_POS + NUM_FULL_DISTANCES;
const REP_LEN_CODER: usize = IS_REP0_LONG + (NUM_STATES2 << NUM_POS_BITS_MAX);
const LEN_CODER: usize = REP_LEN_CODER + NUM_LEN_PROBS;
const IS_MATCH: usize = LEN_CODER + NUM_LEN_PROBS;
const ALIGN: usize = IS_MATCH + (NUM_STATES2 << NUM_POS_BITS_MAX);
const IS_REP: usize = ALIGN + ALIGN_TABLE_SIZE;
const IS_REP_G0: usize = IS_REP + NUM_STATES;
const IS_REP_G1: usize = IS_REP_G0 + NUM_STATES;
const IS_REP_G2: usize = IS_REP_G1 + NUM_STATES;
const POS_SLOT: usize = IS_REP_G2 + NUM_STATES;
const LITERAL: usize = POS_SLOT + ((NUM_LEN_TO_POS_STATES as usize) << NUM_POS_SLOT_BITS);

/// `LZMA_LIT_SIZE`.
const LIT_SIZE: usize = 0x300;

/// `kBadRepCode`: at the start of a stream, a rep match is not allowed.
const BAD_REP_CODE: u32 = 0xC000_0000 - 0x400;

/// What a symbol of the stream decodes to.
enum Symbol {
    /// A literal or a short rep.
    Byte(u8),
    /// A match, whose length is in `remain_len`.
    Match,
    /// The end marker.
    EndMark,
}

/// `CLzmaDec`.
pub(crate) struct LzmaDec {
    probs: Vec<u16>,
    lc: u32,
    lp_mask: u32,
    pb_mask: u32,
    dic_size: u32,
    dic: Vec<u8>,
    dic_pos: usize,
    processed_pos: u32,
    check_dic_size: u32,
    state: usize,
    reps: [u32; 4],
    range: u32,
    code: u32,
    remain_len: u32,
    started: bool,
}

impl LzmaDec {
    /// `LzmaDec_AllocateProbs` and `LzmaDec_Init`, for properties
    /// `LzmaProps_Decode` has checked. A match reaches no further back than
    /// the dictionary, nor than the start of the output.
    pub(crate) fn new(lc: u32, lp: u32, pb: u32, dic_size: u32, out_size: u64) -> Result<Self> {
        let num_probs = LITERAL + (LIT_SIZE << (lc + lp));
        let window = u64::from(dic_size).min(out_size).max(1) as usize;
        // That they can be had, before the allocation that cannot fail softly.
        let mut probe = Vec::<u8>::new();
        probe.try_reserve_exact(window).map_err(|_| Error::Mem)?;
        drop(probe);
        Ok(LzmaDec {
            probs: vec![(BIT_MODEL_TOTAL >> 1) as u16; num_probs],
            lc,
            lp_mask: (0x100u32 << lp) - (0x100u32 >> lc),
            pb_mask: (1 << pb) - 1,
            dic_size,
            dic: vec![0; window],
            dic_pos: 0,
            processed_pos: 0,
            check_dic_size: 0,
            state: 0,
            reps: [1; 4],
            range: 0,
            code: 0,
            remain_len: 0,
            started: false,
        })
    }

    /// The range coder's first bytes, with `LzmaDec_DecodeToDic`'s checks.
    fn start<B: ByteIn>(&mut self, bytes: &mut B) -> Result<()> {
        if self.started {
            return Ok(());
        }
        self.started = true;
        if bytes.read_byte() != 0 {
            return Err(Error::Data);
        }
        let mut code = 0;
        for _ in 0..4 {
            code = (code << 8) | u32::from(bytes.read_byte());
        }
        if code >= BAD_REP_CODE {
            return Err(Error::Data);
        }
        self.code = code;
        self.range = 0xFFFF_FFFF;
        Ok(())
    }

    /// `NORMALIZE`.
    #[inline(always)]
    fn normalize<B: ByteIn>(&mut self, bytes: &mut B) {
        if self.range < TOP_VALUE {
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(bytes.read_byte());
        }
    }

    /// `IF_BIT_0`, `UPDATE_0` and `UPDATE_1`.
    #[inline(always)]
    fn bit<B: ByteIn>(&mut self, bytes: &mut B, prob: usize) -> u32 {
        self.normalize(bytes);
        let ttt = u32::from(self.probs[prob]);
        let bound = (self.range >> NUM_BIT_MODEL_TOTAL_BITS) * ttt;
        if self.code < bound {
            self.range = bound;
            self.probs[prob] = (ttt + ((BIT_MODEL_TOTAL - ttt) >> NUM_MOVE_BITS)) as u16;
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            self.probs[prob] = (ttt - (ttt >> NUM_MOVE_BITS)) as u16;
            1
        }
    }

    /// `TREE_DECODE`.
    #[inline(always)]
    fn tree<B: ByteIn>(&mut self, bytes: &mut B, probs: usize, bits: u32) -> u32 {
        let mut i = 1;
        for _ in 0..bits {
            i = i * 2 + self.bit(bytes, probs + i as usize);
        }
        i - (1 << bits)
    }

    /// The byte `dist` back in the dictionary.
    #[inline(always)]
    fn back(&self, dist: u32) -> u8 {
        let dist = dist as usize;
        let pos = if self.dic_pos < dist {
            self.dic_pos + self.dic.len() - dist
        } else {
            self.dic_pos - dist
        };
        self.dic[pos]
    }

    /// One symbol of `LzmaDec_DecodeReal_3`'s loop. Nothing is written to the
    /// dictionary: the caller does that, when there is room in the output.
    fn symbol<B: ByteIn>(&mut self, bytes: &mut B) -> Result<Symbol> {
        let pos_state = ((self.processed_pos & self.pb_mask) << 4) as usize;
        let mut state = self.state;

        if self.bit(bytes, IS_MATCH + pos_state + state) == 0 {
            let mut prob = LITERAL;
            if self.processed_pos != 0 || self.check_dic_size != 0 {
                let prev = u32::from(self.back(1));
                let index = ((self.processed_pos << 8) + prev) & self.lp_mask;
                prob += 3 * ((index << self.lc) as usize);
            }
            let mut symbol: u32 = 1;
            if state < NUM_LIT_STATES {
                state -= if state < 4 { state } else { 3 };
                while symbol < 0x100 {
                    symbol = symbol * 2 + self.bit(bytes, prob + symbol as usize);
                }
            } else {
                let mut match_byte = u32::from(self.back(self.reps[0]));
                let mut offs: u32 = 0x100;
                state -= if state < 10 { 3 } else { 6 };
                while symbol < 0x100 {
                    match_byte += match_byte;
                    let bit = offs;
                    offs &= match_byte;
                    let lit = prob + (offs + bit + symbol) as usize;
                    if self.bit(bytes, lit) == 0 {
                        symbol *= 2;
                        offs ^= bit;
                    } else {
                        symbol = symbol * 2 + 1;
                    }
                }
            }
            self.state = state;
            return Ok(Symbol::Byte(symbol as u8));
        }

        let prob;
        if self.bit(bytes, IS_REP + state) == 0 {
            state += NUM_STATES;
            prob = LEN_CODER;
        } else {
            if self.bit(bytes, IS_REP_G0 + state) == 0 {
                if self.bit(bytes, IS_REP0_LONG + pos_state + state) == 0 {
                    self.state = if state < NUM_LIT_STATES { 9 } else { 11 };
                    return Ok(Symbol::Byte(self.back(self.reps[0])));
                }
            } else {
                let distance;
                if self.bit(bytes, IS_REP_G1 + state) == 0 {
                    distance = self.reps[1];
                } else {
                    if self.bit(bytes, IS_REP_G2 + state) == 0 {
                        distance = self.reps[2];
                    } else {
                        distance = self.reps[3];
                        self.reps[3] = self.reps[2];
                    }
                    self.reps[2] = self.reps[1];
                }
                self.reps[1] = self.reps[0];
                self.reps[0] = distance;
            }
            state = if state < NUM_LIT_STATES { 8 } else { 11 };
            prob = REP_LEN_CODER;
        }

        let mut len = if self.bit(bytes, prob + LEN_CHOICE) == 0 {
            self.tree(bytes, prob + LEN_LOW + pos_state, LEN_NUM_LOW_BITS)
        } else if self.bit(bytes, prob + LEN_CHOICE2) == 0 {
            let low = prob + LEN_LOW + pos_state + (1 << LEN_NUM_LOW_BITS);
            self.tree(bytes, low, LEN_NUM_LOW_BITS) + LEN_NUM_LOW_SYMBOLS
        } else {
            self.tree(bytes, prob + LEN_HIGH, LEN_NUM_HIGH_BITS) + LEN_NUM_LOW_SYMBOLS * 2
        };

        if state >= NUM_STATES {
            let slot = (len.min(NUM_LEN_TO_POS_STATES - 1) as usize) << NUM_POS_SLOT_BITS;
            let mut distance = self.tree(bytes, POS_SLOT + slot, NUM_POS_SLOT_BITS);
            if distance >= START_POS_MODEL_INDEX {
                let pos_slot = distance;
                let mut num_direct_bits = (distance >> 1) - 1;
                distance = 2 | (distance & 1);
                if pos_slot < END_POS_MODEL_INDEX {
                    distance <<= num_direct_bits;
                    let mut m = 1;
                    distance += 1;
                    for _ in 0..num_direct_bits {
                        if self.bit(bytes, SPEC_POS + distance as usize) == 0 {
                            distance += m;
                            m += m;
                        } else {
                            m += m;
                            distance += m;
                        }
                    }
                    distance -= m;
                } else {
                    num_direct_bits -= NUM_ALIGN_BITS;
                    for _ in 0..num_direct_bits {
                        self.normalize(bytes);
                        self.range >>= 1;
                        self.code = self.code.wrapping_sub(self.range);
                        let t = 0u32.wrapping_sub(self.code >> 31);
                        distance = (distance << 1).wrapping_add(t.wrapping_add(1));
                        self.code = self.code.wrapping_add(self.range & t);
                    }
                    distance <<= NUM_ALIGN_BITS;
                    let mut i = 1;
                    for m in [1, 2, 4] {
                        if self.bit(bytes, ALIGN + i) == 0 {
                            i += m;
                        } else {
                            i += m * 2;
                        }
                    }
                    if self.bit(bytes, ALIGN + i) == 0 {
                        i -= 8;
                    }
                    distance |= i as u32;
                    if distance == 0xFFFF_FFFF {
                        self.state = state - NUM_STATES;
                        return Ok(Symbol::EndMark);
                    }
                }
            }

            self.reps[3] = self.reps[2];
            self.reps[2] = self.reps[1];
            self.reps[1] = self.reps[0];
            self.reps[0] = distance.wrapping_add(1);
            state = if state < NUM_STATES + NUM_LIT_STATES {
                NUM_LIT_STATES
            } else {
                NUM_LIT_STATES + 3
            };
            let limit = if self.check_dic_size == 0 {
                self.processed_pos
            } else {
                self.check_dic_size
            };
            if distance >= limit {
                return Err(Error::Data);
            }
        }

        len += MATCH_MIN_LEN;
        self.remain_len = len;
        self.state = state;
        Ok(Symbol::Match)
    }

    /// A decoded byte: in the dictionary and in the count.
    #[inline(always)]
    fn put(&mut self, b: u8) {
        self.dic[self.dic_pos] = b;
        self.dic_pos += 1;
        if self.dic_pos == self.dic.len() {
            self.dic_pos = 0;
        }
        self.processed_pos = self.processed_pos.wrapping_add(1);
        // LzmaDec_DecodeReal2 and LzmaDec_WriteRem, which stop at the
        // dictionary's size to get here.
        if self.check_dic_size == 0 && self.processed_pos >= self.dic_size {
            self.check_dic_size = self.dic_size;
        }
    }

    /// `LzmaDec_DecodeToDic`, up to the end of `out`, which is no further than
    /// the end of the stream's output. The bytes past the input's end make it
    /// run on for as long as `out` lasts, at worst.
    pub(crate) fn read<B: ByteIn>(&mut self, bytes: &mut B, out: &mut [u8]) -> Result<usize> {
        self.start(bytes)?;
        let mut n = 0;
        while n < out.len() {
            if self.remain_len != 0 {
                let b = self.back(self.reps[0]);
                self.put(b);
                self.remain_len -= 1;
                out[n] = b;
                n += 1;
                continue;
            }
            match self.symbol(bytes)? {
                Symbol::Byte(b) => {
                    self.put(b);
                    out[n] = b;
                    n += 1;
                }
                Symbol::Match => {}
                // Before the end of the output.
                Symbol::EndMark => return Err(Error::Data),
            }
            self.normalize(bytes);
        }
        Ok(n)
    }

    /// `LzmaDec_DecodeToDic`'s `LZMA_FINISH_END`, at the end of the output: a
    /// match that went past it is an error, and the range coder either stops
    /// there or has an end marker to decode.
    pub(crate) fn finish<B: ByteIn>(&mut self, bytes: &mut B) -> Result<()> {
        self.start(bytes)?;
        if self.remain_len != 0 {
            return Err(Error::Data);
        }
        if self.code == 0 {
            return Ok(());
        }
        let symbol = self.symbol(bytes)?;
        self.normalize(bytes);
        match symbol {
            Symbol::EndMark if self.code == 0 => Ok(()),
            _ => Err(Error::Data),
        }
    }
}
