//! AES with the processor's instructions, for the `unsafe-fast` feature:
//! AES-NI on x86-64, and the AES instructions of ARMv8 on arm64. Each runs a
//! round on a block in a time that does not depend on the data or the key, as
//! the processors' manuals have it, and without tables in memory.
//!
//! Not in BearSSL in this form: the round keys come from the same key schedule
//! as the bitsliced code ([`round_words`]), in constant time, and the
//! instructions only run the rounds. The equivalent inverse cipher of FIPS 197,
//! section 5.3.5, decrypts.
//!
//! The only unsafe code is calling functions with a `target_feature` once the
//! processor is known to have it, which [`HwKeys::new`] checks, and loading and
//! storing 16 bytes of an array. See `docs/unsafe.md` in the repository.
#![allow(unsafe_code)]

use crate::aes_ct64::round_words;
use crate::clear::clear;

/// Round keys, as bytes, at most 15 of them, for encrypting and for decrypting.
pub(crate) struct HwKeys {
    num_rounds: usize,
    enc: [u8; 240],
    dec: [u8; 240],
}

impl HwKeys {
    /// The round keys of `key`, or `None` if the processor has no AES
    /// instructions or the key is not of a length AES has.
    pub(crate) fn new(key: &[u8]) -> Option<HwKeys> {
        if !detected() {
            return None;
        }
        let (num_rounds, mut words) = round_words(key)?;
        let mut keys = HwKeys {
            num_rounds,
            enc: [0; 240],
            dec: [0; 240],
        };
        for (bytes, word) in keys.enc.as_chunks_mut::<4>().0.iter_mut().zip(&words) {
            *bytes = word.to_le_bytes();
        }
        clear(&mut words);
        // The first and the last swap places; those between go through
        // InvMixColumns too.
        for i in 0..=num_rounds {
            let from = (num_rounds - i) * 16;
            let mut round = [0; 16];
            round.copy_from_slice(&keys.enc[from..from + 16]);
            if i != 0 && i != num_rounds {
                // SAFETY: `detected()` was true above.
                round = unsafe { imp::inverse_mix_columns(&round) };
            }
            keys.dec[i * 16..i * 16 + 16].copy_from_slice(&round);
            clear(&mut round);
        }
        Some(keys)
    }

    pub(crate) fn encrypt4(&self, blocks: &mut [u8; 64]) {
        // SAFETY: a `HwKeys` exists only if `detected()` was true.
        unsafe { imp::encrypt4(self.round_keys(&self.enc), blocks) }
    }

    pub(crate) fn decrypt4(&self, blocks: &mut [u8; 64]) {
        // SAFETY: a `HwKeys` exists only if `detected()` was true.
        unsafe { imp::decrypt4(self.round_keys(&self.dec), blocks) }
    }

    fn round_keys<'a>(&self, keys: &'a [u8; 240]) -> &'a [[u8; 16]] {
        &keys.as_chunks::<16>().0[..=self.num_rounds]
    }
}

impl Drop for HwKeys {
    fn drop(&mut self) {
        clear(&mut self.enc);
        clear(&mut self.dec);
    }
}

#[cfg(target_arch = "x86_64")]
fn detected() -> bool {
    std::is_x86_feature_detected!("aes")
}

#[cfg(target_arch = "aarch64")]
fn detected() -> bool {
    std::arch::is_aarch64_feature_detected!("aes")
}

#[cfg(target_arch = "x86_64")]
mod imp {
    use std::arch::x86_64::{
        __m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128, _mm_aesenclast_si128,
        _mm_aesimc_si128, _mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128,
    };

    #[inline]
    #[target_feature(enable = "sse2")]
    fn load(bytes: &[u8; 16]) -> __m128i {
        // SAFETY: the 16 bytes are there, and this load takes any alignment.
        unsafe { _mm_loadu_si128(bytes.as_ptr().cast()) }
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    fn store(bytes: &mut [u8; 16], block: __m128i) {
        // SAFETY: the 16 bytes are there, and this store takes any alignment.
        unsafe { _mm_storeu_si128(bytes.as_mut_ptr().cast(), block) }
    }

    #[target_feature(enable = "aes,sse2")]
    pub(super) fn inverse_mix_columns(round: &[u8; 16]) -> [u8; 16] {
        let mut out = [0; 16];
        store(&mut out, _mm_aesimc_si128(load(round)));
        out
    }

    /// The four blocks' rounds side by side, as the instructions can overlap.
    macro_rules! rounds {
        ($keys:ident, $blocks:ident, $round:ident, $last:ident) => {{
            let (chunks, _) = $blocks.as_chunks_mut::<16>();
            let first = load(&$keys[0]);
            let mut b = [
                _mm_xor_si128(load(&chunks[0]), first),
                _mm_xor_si128(load(&chunks[1]), first),
                _mm_xor_si128(load(&chunks[2]), first),
                _mm_xor_si128(load(&chunks[3]), first),
            ];
            let last = $keys.len() - 1;
            for key in &$keys[1..last] {
                let key = load(key);
                b = [
                    $round(b[0], key),
                    $round(b[1], key),
                    $round(b[2], key),
                    $round(b[3], key),
                ];
            }
            let key = load(&$keys[last]);
            for (chunk, block) in chunks.iter_mut().zip(b) {
                store(chunk, $last(block, key));
            }
        }};
    }

    #[target_feature(enable = "aes,sse2")]
    pub(super) fn encrypt4(keys: &[[u8; 16]], blocks: &mut [u8; 64]) {
        rounds!(keys, blocks, _mm_aesenc_si128, _mm_aesenclast_si128);
    }

    #[target_feature(enable = "aes,sse2")]
    pub(super) fn decrypt4(keys: &[[u8; 16]], blocks: &mut [u8; 64]) {
        rounds!(keys, blocks, _mm_aesdec_si128, _mm_aesdeclast_si128);
    }
}

#[cfg(target_arch = "aarch64")]
mod imp {
    use std::arch::aarch64::{
        uint8x16_t, vaesdq_u8, vaeseq_u8, vaesimcq_u8, vaesmcq_u8, veorq_u8, vld1q_u8, vst1q_u8,
    };

    #[inline]
    #[target_feature(enable = "neon")]
    fn load(bytes: &[u8; 16]) -> uint8x16_t {
        // SAFETY: the 16 bytes are there, and this load takes any alignment.
        unsafe { vld1q_u8(bytes.as_ptr()) }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    fn store(bytes: &mut [u8; 16], block: uint8x16_t) {
        // SAFETY: the 16 bytes are there, and this store takes any alignment.
        unsafe { vst1q_u8(bytes.as_mut_ptr(), block) }
    }

    #[target_feature(enable = "aes,neon")]
    pub(super) fn inverse_mix_columns(round: &[u8; 16]) -> [u8; 16] {
        let mut out = [0; 16];
        store(&mut out, vaesimcq_u8(load(round)));
        out
    }

    /// The four blocks' rounds side by side, as the instructions can overlap.
    /// `aese` and `aesd` start with the round key, where x86-64's instructions
    /// end with it, so the last key is XORed apart.
    macro_rules! rounds {
        ($keys:ident, $blocks:ident, $round:ident, $mix:ident) => {{
            let (chunks, _) = $blocks.as_chunks_mut::<16>();
            let mut b = [
                load(&chunks[0]),
                load(&chunks[1]),
                load(&chunks[2]),
                load(&chunks[3]),
            ];
            let last = $keys.len() - 1;
            for key in &$keys[..last - 1] {
                let key = load(key);
                b = [
                    $mix($round(b[0], key)),
                    $mix($round(b[1], key)),
                    $mix($round(b[2], key)),
                    $mix($round(b[3], key)),
                ];
            }
            let before = load(&$keys[last - 1]);
            let key = load(&$keys[last]);
            for (chunk, block) in chunks.iter_mut().zip(b) {
                store(chunk, veorq_u8($round(block, before), key));
            }
        }};
    }

    #[target_feature(enable = "aes,neon")]
    pub(super) fn encrypt4(keys: &[[u8; 16]], blocks: &mut [u8; 64]) {
        rounds!(keys, blocks, vaeseq_u8, vaesmcq_u8);
    }

    #[target_feature(enable = "aes,neon")]
    pub(super) fn decrypt4(keys: &[[u8; 16]], blocks: &mut [u8; 64]) {
        rounds!(keys, blocks, vaesdq_u8, vaesimcq_u8);
    }
}
