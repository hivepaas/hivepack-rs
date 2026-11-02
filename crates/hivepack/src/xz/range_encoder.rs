//! The range encoder and the prices of its bits: port of
//! `rangecoder/range_encoder.h`, `price.h` and `price_table.c`.
//!
//! liblzma's encoder queues up to `RC_SYMBOLS_MAX` bits with pointers to
//! their probabilities, then writes them out as the output space allows.
//! The port's probabilities are one array (see `lzma_common.rs`), so the
//! queue holds indices into it, and `encode` takes the array.

use crate::xz::range_decoder::{
    Probability, RC_BIT_MODEL_TOTAL, RC_BIT_MODEL_TOTAL_BITS, RC_MOVE_BITS, RC_SHIFT_BITS,
    RC_TOP_VALUE,
};

/// Maximum number of symbols that can be put pending into
/// lzma_range_encoder structure between calls to lzma_rc_encode(). For
/// LZMA, 48+5 is enough (match with big distance and length followed by
/// range encoder flush).
const RC_SYMBOLS_MAX: usize = 53;

/// The kinds of symbols in the queue.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Symbol {
    Bit0,
    Bit1,
    Direct0,
    Direct1,
    Flush,
}

/// `lzma_range_encoder`.
#[derive(Clone, Debug)]
pub(crate) struct RangeEncoder {
    low: u64,
    cache_size: u64,
    range: u32,
    cache: u8,
    /// Number of bytes written out by rc_encode() -> rc_shift_low()
    out_total: u64,
    /// Number of symbols in the tables
    count: usize,
    /// rc_encode()'s position in the tables
    pos: usize,
    /// Symbols to encode
    symbols: [Symbol; RC_SYMBOLS_MAX],
    /// Probabilities associated with RC_BIT_0 or RC_BIT_1, as indices
    probs: [u32; RC_SYMBOLS_MAX],
}

impl RangeEncoder {
    pub(crate) fn new() -> RangeEncoder {
        RangeEncoder {
            low: 0,
            cache_size: 1,
            range: u32::MAX,
            cache: 0,
            out_total: 0,
            count: 0,
            pos: 0,
            symbols: [Symbol::Flush; RC_SYMBOLS_MAX],
            probs: [0; RC_SYMBOLS_MAX],
        }
    }

    /// `rc_reset`.
    pub(crate) fn reset(&mut self) {
        self.low = 0;
        self.cache_size = 1;
        self.range = u32::MAX;
        self.cache = 0;
        self.out_total = 0;
        self.count = 0;
        self.pos = 0;
    }

    /// `rc_bit`.
    #[inline(always)]
    pub(crate) fn bit(&mut self, prob: usize, bit: u32) {
        self.symbols[self.count] = if bit == 0 { Symbol::Bit0 } else { Symbol::Bit1 };
        self.probs[self.count] = prob as u32;
        self.count += 1;
    }

    /// `rc_bittree`.
    #[inline(always)]
    pub(crate) fn bittree(&mut self, probs: usize, mut bit_count: u32, symbol: u32) {
        let mut model_index = 1;
        loop {
            bit_count -= 1;
            let bit = (symbol >> bit_count) & 1;
            self.bit(probs + model_index as usize, bit);
            model_index = (model_index << 1) + bit;
            if bit_count == 0 {
                break;
            }
        }
    }

    /// `rc_bittree_reverse`. `probs` may be one less than the start of an
    /// array, which the tree never reads at index 0.
    #[inline(always)]
    pub(crate) fn bittree_reverse(&mut self, probs: usize, mut bit_count: u32, mut symbol: u32) {
        let mut model_index = 1;
        loop {
            let bit = symbol & 1;
            symbol >>= 1;
            self.bit(probs + model_index as usize, bit);
            model_index = (model_index << 1) + bit;
            bit_count -= 1;
            if bit_count == 0 {
                break;
            }
        }
    }

    /// `rc_direct`.
    #[inline(always)]
    pub(crate) fn direct(&mut self, value: u32, mut bit_count: u32) {
        loop {
            bit_count -= 1;
            self.symbols[self.count] = if (value >> bit_count) & 1 == 0 {
                Symbol::Direct0
            } else {
                Symbol::Direct1
            };
            self.count += 1;
            if bit_count == 0 {
                break;
            }
        }
    }

    /// `rc_flush`.
    pub(crate) fn flush(&mut self) {
        for _ in 0..5 {
            self.symbols[self.count] = Symbol::Flush;
            self.count += 1;
        }
    }

    /// `rc_shift_low`: true if the output is full.
    #[inline(always)]
    fn shift_low(&mut self, out: &mut [u8], out_pos: &mut usize) -> bool {
        if (self.low as u32) < 0xFF00_0000 || (self.low >> 32) as u32 != 0 {
            loop {
                if *out_pos == out.len() {
                    return true;
                }
                out[*out_pos] = self.cache.wrapping_add((self.low >> 32) as u8);
                *out_pos += 1;
                self.out_total += 1;
                self.cache = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = ((self.low >> 24) & 0xFF) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low & 0x00FF_FFFF) << RC_SHIFT_BITS;
        false
    }

    /// `rc_encode`: writes out the queued symbols, updating their
    /// probabilities in `p`; true if the output got full first.
    pub(crate) fn encode(
        &mut self,
        p: &mut [Probability],
        out: &mut [u8],
        out_pos: &mut usize,
    ) -> bool {
        while self.pos < self.count {
            // Normalize
            if self.range < RC_TOP_VALUE {
                if self.shift_low(out, out_pos) {
                    return true;
                }
                self.range <<= RC_SHIFT_BITS;
            }

            // Encode a bit
            match self.symbols[self.pos] {
                Symbol::Bit0 => {
                    let at = self.probs[self.pos] as usize;
                    let mut prob = u32::from(p[at]);
                    self.range = (self.range >> RC_BIT_MODEL_TOTAL_BITS) * prob;
                    prob += (RC_BIT_MODEL_TOTAL - prob) >> RC_MOVE_BITS;
                    p[at] = prob as Probability;
                }
                Symbol::Bit1 => {
                    let at = self.probs[self.pos] as usize;
                    let mut prob = u32::from(p[at]);
                    let bound = prob * (self.range >> RC_BIT_MODEL_TOTAL_BITS);
                    self.low += u64::from(bound);
                    self.range -= bound;
                    prob -= prob >> RC_MOVE_BITS;
                    p[at] = prob as Probability;
                }
                Symbol::Direct0 => {
                    self.range >>= 1;
                }
                Symbol::Direct1 => {
                    self.range >>= 1;
                    self.low += u64::from(self.range);
                }
                Symbol::Flush => {
                    // Prevent further normalizations.
                    self.range = u32::MAX;

                    // Flush the last five bytes (see rc_flush()).
                    loop {
                        if self.shift_low(out, out_pos) {
                            return true;
                        }
                        self.pos += 1;
                        if self.pos >= self.count {
                            break;
                        }
                    }

                    // Reset the range encoder so we are ready to continue
                    // encoding if we weren't finishing the stream.
                    self.reset();
                    return false;
                }
            }
            self.pos += 1;
        }

        self.count = 0;
        self.pos = 0;
        false
    }

    /// `rc_pending`.
    pub(crate) fn pending(&self) -> u64 {
        self.cache_size + 5 - 1
    }
}

// Prices (price.h)

pub(crate) const RC_MOVE_REDUCING_BITS: u32 = 4;
pub(crate) const RC_BIT_PRICE_SHIFT_BITS: u32 = 4;
const RC_PRICE_TABLE_SIZE: usize = (RC_BIT_MODEL_TOTAL >> RC_MOVE_REDUCING_BITS) as usize;
pub(crate) const RC_INFINITY_PRICE: u32 = 1 << 30;

/// `lzma_rc_prices`, computed as `price_tablegen.c` computes it.
static RC_PRICES: [u8; RC_PRICE_TABLE_SIZE] = price_table();

const fn price_table() -> [u8; RC_PRICE_TABLE_SIZE] {
    let mut prices = [0u8; RC_PRICE_TABLE_SIZE];
    let mut i = (1 << RC_MOVE_REDUCING_BITS) / 2;
    while i < RC_BIT_MODEL_TOTAL {
        let cycles_bits = RC_BIT_PRICE_SHIFT_BITS;
        let mut w = i;
        let mut bit_count = 0;
        let mut j = 0;
        while j < cycles_bits {
            w *= w;
            bit_count <<= 1;
            while w >= 1 << 16 {
                w >>= 1;
                bit_count += 1;
            }
            j += 1;
        }
        prices[(i >> RC_MOVE_REDUCING_BITS) as usize] =
            ((RC_BIT_MODEL_TOTAL_BITS << cycles_bits) - 15 - bit_count) as u8;
        i += 1 << RC_MOVE_REDUCING_BITS;
    }
    prices
}

/// `rc_bit_price`.
#[inline(always)]
pub(crate) fn bit_price(prob: Probability, bit: u32) -> u32 {
    u32::from(
        RC_PRICES[((u32::from(prob) ^ (0u32.wrapping_sub(bit) & (RC_BIT_MODEL_TOTAL - 1)))
            >> RC_MOVE_REDUCING_BITS) as usize],
    )
}

/// `rc_bit_0_price`.
#[inline(always)]
pub(crate) fn bit_0_price(prob: Probability) -> u32 {
    u32::from(RC_PRICES[(u32::from(prob) >> RC_MOVE_REDUCING_BITS) as usize])
}

/// `rc_bit_1_price`.
#[inline(always)]
pub(crate) fn bit_1_price(prob: Probability) -> u32 {
    u32::from(
        RC_PRICES[((u32::from(prob) ^ (RC_BIT_MODEL_TOTAL - 1)) >> RC_MOVE_REDUCING_BITS) as usize],
    )
}

/// `rc_bittree_price`: of the tree at `p[probs..]`.
#[inline(always)]
pub(crate) fn bittree_price(
    p: &[Probability],
    probs: usize,
    bit_levels: u32,
    mut symbol: u32,
) -> u32 {
    let mut price = 0;
    symbol += 1 << bit_levels;
    loop {
        let bit = symbol & 1;
        symbol >>= 1;
        price += bit_price(p[probs + symbol as usize], bit);
        if symbol == 1 {
            break;
        }
    }
    price
}

/// `rc_bittree_reverse_price`.
#[inline(always)]
pub(crate) fn bittree_reverse_price(
    p: &[Probability],
    probs: usize,
    mut bit_levels: u32,
    mut symbol: u32,
) -> u32 {
    let mut price = 0;
    let mut model_index = 1;
    loop {
        let bit = symbol & 1;
        symbol >>= 1;
        price += bit_price(p[probs + model_index as usize], bit);
        model_index = (model_index << 1) + bit;
        bit_levels -= 1;
        if bit_levels == 0 {
            break;
        }
    }
    price
}

/// `rc_direct_price`.
#[inline(always)]
pub(crate) fn direct_price(bits: u32) -> u32 {
    bits << RC_BIT_PRICE_SHIFT_BITS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table as price_table.c has it.
    #[test]
    fn price_table_is_liblzmas() {
        const C_TABLE: [u8; 128] = [
            128, 103, 91, 84, 78, 73, 69, 66, 63, 61, 58, 56, 54, 52, 51, 49, 48, 46, 45, 44, 43,
            42, 41, 40, 39, 38, 37, 36, 35, 34, 34, 33, 32, 31, 31, 30, 29, 29, 28, 28, 27, 26, 26,
            25, 25, 24, 24, 23, 23, 22, 22, 22, 21, 21, 20, 20, 19, 19, 19, 18, 18, 17, 17, 17, 16,
            16, 16, 15, 15, 15, 14, 14, 14, 13, 13, 13, 12, 12, 12, 11, 11, 11, 11, 10, 10, 10, 10,
            9, 9, 9, 9, 8, 8, 8, 8, 7, 7, 7, 7, 6, 6, 6, 6, 5, 5, 5, 5, 5, 4, 4, 4, 4, 3, 3, 3, 3,
            3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1,
        ];
        assert_eq!(RC_PRICES, C_TABLE);
    }
}
