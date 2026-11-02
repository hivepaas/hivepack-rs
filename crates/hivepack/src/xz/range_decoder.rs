//! The range decoder: port of `rangecoder/range_common.h` and the parts of
//! `rangecoder/range_decoder.h` that are not macros of the LZMA decoder's
//! loop, which `lzma_decoder.rs` has.
//!
//! liblzma has branchless C and x86-64 assembly versions of the bit
//! decoders, chosen by `LZMA_RANGE_DECODER_CONFIG`; they decode the same
//! bits as the basic version, which the port follows.

use crate::xz::common::Ret;

pub(crate) const RC_SHIFT_BITS: u32 = 8;
pub(crate) const RC_TOP_BITS: u32 = 24;
pub(crate) const RC_TOP_VALUE: u32 = 1 << RC_TOP_BITS;
pub(crate) const RC_BIT_MODEL_TOTAL_BITS: u32 = 11;
pub(crate) const RC_BIT_MODEL_TOTAL: u32 = 1 << RC_BIT_MODEL_TOTAL_BITS;
pub(crate) const RC_MOVE_BITS: u32 = 5;

/// `RC_BIT_MODEL_OFFSET`: with it, the update of a probability after a 0
/// is the same subtraction as after a 1, which the branchless bit decoder
/// uses:
///
/// ```text
/// prob += (RC_BIT_MODEL_TOTAL - prob) >> RC_MOVE_BITS
/// prob -= (prob + RC_BIT_MODEL_OFFSET) >> RC_MOVE_BITS   (in u32)
/// ```
pub(crate) const RC_BIT_MODEL_OFFSET: u32 =
    ((1 << RC_MOVE_BITS) - 1u32).wrapping_sub(RC_BIT_MODEL_TOTAL);

/// `probability`.
pub(crate) type Probability = u16;

/// `bit_reset`: the probability of a bit never seen, one half.
pub(crate) const PROB_INIT: Probability = (RC_BIT_MODEL_TOTAL >> 1) as Probability;

/// `lzma_range_decoder`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RangeDecoder {
    pub(crate) range: u32,
    pub(crate) code: u32,
    pub(crate) init_bytes_left: u32,
}

impl RangeDecoder {
    /// A range decoder after `rc_reset`.
    pub(crate) fn new() -> RangeDecoder {
        let mut rc = RangeDecoder {
            range: 0,
            code: 0,
            init_bytes_left: 0,
        };
        rc.reset();
        rc
    }

    /// `rc_reset`.
    pub(crate) fn reset(&mut self) {
        self.range = u32::MAX;
        self.code = 0;
        self.init_bytes_left = 5;
    }

    /// `rc_is_finished`: when decoding has been properly finished, rc.code
    /// is always zero unless the input stream is corrupt.
    pub(crate) fn is_finished(&self) -> bool {
        self.code == 0
    }

    /// `rc_read_init`: reads the first five bytes to initialize the range
    /// decoder; `LZMA_STREAM_END` once it has them.
    pub(crate) fn read_init(&mut self, input: &[u8], in_pos: &mut usize) -> Ret {
        while self.init_bytes_left > 0 {
            if *in_pos == input.len() {
                return Ret::Ok;
            }
            // The first byte is always 0x00. It could have been omitted in
            // LZMA2 but it wasn't, so one byte is wasted in every LZMA2
            // chunk.
            if self.init_bytes_left == 5 && input[*in_pos] != 0x00 {
                return Ret::DataError;
            }
            self.code = (self.code << 8) | u32::from(input[*in_pos]);
            *in_pos += 1;
            self.init_bytes_left -= 1;
        }
        Ret::StreamEnd
    }
}
