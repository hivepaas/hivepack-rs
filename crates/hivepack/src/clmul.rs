//! Folding a reflected CRC with x86-64's carry-less multiplication
//! (`PCLMULQDQ`), for `deflate`'s CRC-32 and `xz`'s CRC-32 and CRC-64, each
//! behind its module's `unsafe-fast` feature.
//!
//! Intel's "Fast CRC Computation for Generic Polynomials Using PCLMULQDQ
//! Instruction" (2009), as zlib-ng, liblzma (`crc_x86_clmul.h`), crc32fast
//! and Linux fold: the data as blocks of 128 bits, four lanes of them, each
//! lane multiplied without carries by x^512 mod P(x) and the next four
//! blocks added, then the lanes folded into one, and the blocks left one at
//! a time by x^128 mod P(x). What is left is a block of 16 bytes whose CRC,
//! from a state of 0, is the data's: the CRC's own code reads it, and the
//! bytes after the blocks, where Intel's reduces it with more
//! multiplications. That costs 16 bytes of its table and keeps one
//! function, and its constants, for every polynomial.
//!
//! The constants are computed while compiling from the polynomial
//! ([`Keys::new`]), not copied, the same way for 32 bits and 64: for xz's
//! CRC-64 they are crc64fast's. For a CRC of 32 bits they are not Intel's
//! k1 to k4, which are reduced to 32 bits and shifted, but are as much
//! x^n mod P(x): the CRC that comes out is the same, as the tests check.
//!
//! Nothing here is `unsafe`: `std::arch`'s intrinsics are safe in a
//! function with their features. Calling [`fold`] takes `unsafe`, as the
//! compiler refuses a call to a function with a `target_feature` otherwise,
//! and its callers make it once [`available`] says the processor has them.

#![forbid(unsafe_code)]

use std::arch::x86_64::{
    __m128i, _mm_clmulepi64_si128, _mm_cvtsi128_si64, _mm_set_epi64x, _mm_unpackhi_epi64,
    _mm_xor_si128,
};

/// The least [`fold`] is given: four blocks of 16 bytes, its four lanes.
pub(crate) const LEAST: usize = 64;

/// What folds a reflected CRC: x^(D+63) and x^(D−1) mod P(x), each reflected
/// over 64 bits, for D of 512 bits (four lanes) and 128 (one).
pub(crate) struct Keys {
    four: [u64; 2],
    one: [u64; 2],
}

impl Keys {
    /// The keys of the CRC of `width` bits (32 or 64) whose polynomial is
    /// `poly`, in its normal order, its x^width term left out.
    pub(crate) const fn new(poly: u64, width: u32) -> Keys {
        Keys {
            four: [
                xpow_mod(512 + 63, poly, width).reverse_bits(),
                xpow_mod(512 - 1, poly, width).reverse_bits(),
            ],
            one: [
                xpow_mod(128 + 63, poly, width).reverse_bits(),
                xpow_mod(128 - 1, poly, width).reverse_bits(),
            ],
        }
    }
}

/// x^n mod P(x), in the normal order, P(x) of `width` bits and `poly` with
/// its x^width term left out.
const fn xpow_mod(n: u32, poly: u64, width: u32) -> u64 {
    let top = 1u64 << (width - 1);
    let mask = if width == 64 {
        u64::MAX
    } else {
        (1 << width) - 1
    };
    let mut r: u64 = 1;
    let mut i = 0;
    while i < n {
        let carry = r & top != 0;
        r = (r << 1) & mask;
        if carry {
            r ^= poly;
        }
        i += 1;
    }
    r
}

/// Whether the processor has what [`fold`] takes.
pub(crate) fn available() -> bool {
    std::arch::is_x86_feature_detected!("pclmulqdq")
}

/// `blocks`, four or more ([`LEAST`] bytes), folded by `keys` into one block
/// whose CRC from a state of 0 is theirs from `state`: `state` is added to
/// the lowest bytes of the first, as a reflected CRC's state is to the bytes
/// it reads. The CRC then reads that block, and the bytes after `blocks`.
#[target_feature(enable = "pclmulqdq,sse2")]
pub(crate) fn fold(state: u64, blocks: &[[u8; 16]], keys: &Keys) -> [u8; 16] {
    let Some((first, blocks)) = blocks.split_first_chunk::<4>() else {
        // Not called with fewer: the CRC reads them itself.
        let mut block = [0; 16];
        block[..8].copy_from_slice(&state.to_le_bytes());
        return block;
    };
    let (fours, ones) = blocks.as_chunks::<4>();
    let four = key(keys.four);
    let one = key(keys.one);

    let mut x3 = _mm_xor_si128(load(&first[0]), _mm_set_epi64x(0, state as i64));
    let mut x2 = load(&first[1]);
    let mut x1 = load(&first[2]);
    let mut x0 = load(&first[3]);
    for next in fours {
        x3 = fold_into(x3, load(&next[0]), four);
        x2 = fold_into(x2, load(&next[1]), four);
        x1 = fold_into(x1, load(&next[2]), four);
        x0 = fold_into(x0, load(&next[3]), four);
    }
    let mut x = fold_into(x3, x2, one);
    x = fold_into(x, x1, one);
    x = fold_into(x, x0, one);
    for next in ones {
        x = fold_into(x, load(next), one);
    }
    let low = _mm_cvtsi128_si64(x) as u64;
    let high = _mm_cvtsi128_si64(_mm_unpackhi_epi64(x, x)) as u64;
    let mut block = [0; 16];
    block[..8].copy_from_slice(&low.to_le_bytes());
    block[8..].copy_from_slice(&high.to_le_bytes());
    block
}

/// The two halves of a key, the first the lowest.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
fn key([low, high]: [u64; 2]) -> __m128i {
    _mm_set_epi64x(high as i64, low as i64)
}

/// 16 bytes, the first the lowest.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
fn load(block: &[u8; 16]) -> __m128i {
    let (low, high) = block.split_at(8);
    let low = u64::from_le_bytes(low.try_into().unwrap_or([0; 8]));
    let high = u64::from_le_bytes(high.try_into().unwrap_or([0; 8]));
    _mm_set_epi64x(high as i64, low as i64)
}

/// `lane` multiplied by the key's halves, its low half by the first and its
/// high by the second, and `next` added.
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
fn fold_into(lane: __m128i, next: __m128i, key: __m128i) -> __m128i {
    let low = _mm_clmulepi64_si128::<0x00>(lane, key);
    let high = _mm_clmulepi64_si128::<0x11>(lane, key);
    _mm_xor_si128(_mm_xor_si128(next, low), high)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xz's CRC-64's keys for one lane are crc64fast's (x^191 and x^127,
    /// reflected).
    #[test]
    fn keys_are_the_known_ones() {
        let crc64 = Keys::new(0x42F0_E1EB_A9EA_3693, 64);
        assert_eq!(crc64.one, [0xe05d_d497_ca39_3ae4, 0xdabe_95af_c787_5f40]);
    }
}
