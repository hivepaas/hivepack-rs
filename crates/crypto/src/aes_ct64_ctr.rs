//! The AES block cipher, on four blocks at a time: the core of
//! `aes_ct64_ctr.c`'s `br_aes_ct64_ctr_run`, without its counter, and of
//! `aes_ct64_cbcdec.c`'s `br_aes_ct64_cbcdec_run`.
//!
//! Differs from BearSSL: BearSSL offers AES with its modes (CBC, CTR, CCM,
//! GCM); WinZip AES uses a counter of its own (little-endian, as libzip
//! increments it), so this module gives the blocks encrypted, and the
//! caller XORs them into the data. BearSSL expands the subkeys at every
//! call; [`Aes`] keeps them expanded.

use crate::aes_ct64::{interleave_in, interleave_out, keysched, ortho, skey_expand};
use crate::aes_ct64_dec::bitslice_decrypt;
use crate::aes_ct64_enc::bitslice_encrypt;
#[cfg(all(
    feature = "unsafe-fast",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use crate::aes_hw::HwKeys;
use crate::clear::clear;

/// The length of an AES block, in bytes.
pub const AES_BLOCK_LENGTH: usize = 16;

/// An AES key, ready to encrypt and decrypt.
///
/// The key and the subkeys derived from it are overwritten when it is
/// dropped (best effort: see the crate's documentation).
pub struct Aes {
    num_rounds: usize,
    skey: [u64; 120],
    /// The processor's instructions, if it has them.
    #[cfg(all(
        feature = "unsafe-fast",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    hw: Option<HwKeys>,
}

impl Aes {
    /// The key schedule of `key`, AES-128, AES-192 or AES-256 for a key of
    /// 16, 24 or 32 bytes; `None` for any other length.
    pub fn new(key: &[u8]) -> Option<Aes> {
        let (num_rounds, mut comp_skey) = keysched(key)?;
        let skey = skey_expand(num_rounds, &comp_skey);
        clear(&mut comp_skey);
        Some(Aes {
            num_rounds,
            skey,
            #[cfg(all(
                feature = "unsafe-fast",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            hw: HwKeys::new(key),
        })
    }

    /// Encrypts four blocks in place, one after the other in `blocks`.
    pub fn encrypt4(&self, blocks: &mut [u8; 4 * AES_BLOCK_LENGTH]) {
        #[cfg(all(
            feature = "unsafe-fast",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if let Some(hw) = &self.hw {
            hw.encrypt4(blocks);
            return;
        }
        self.encrypt4_bitsliced(blocks);
    }

    fn encrypt4_bitsliced(&self, blocks: &mut [u8; 4 * AES_BLOCK_LENGTH]) {
        let mut w = [0u32; 16];
        for (word, bytes) in w.iter_mut().zip(blocks.as_chunks().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        let mut q = [0u64; 8];
        for (i, block) in w.as_chunks().0.iter().enumerate() {
            (q[i], q[i + 4]) = interleave_in(block);
        }
        ortho(&mut q);
        bitslice_encrypt(self.num_rounds, &self.skey, &mut q);
        ortho(&mut q);
        for (i, block) in w.as_chunks_mut().0.iter_mut().enumerate() {
            *block = interleave_out(q[i], q[i + 4]);
        }
        for (bytes, word) in blocks.as_chunks_mut().0.iter_mut().zip(w) {
            *bytes = word.to_le_bytes();
        }
    }

    /// Decrypts four blocks in place, one after the other in `blocks`.
    pub fn decrypt4(&self, blocks: &mut [u8; 4 * AES_BLOCK_LENGTH]) {
        #[cfg(all(
            feature = "unsafe-fast",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if let Some(hw) = &self.hw {
            hw.decrypt4(blocks);
            return;
        }
        self.decrypt4_bitsliced(blocks);
    }

    fn decrypt4_bitsliced(&self, blocks: &mut [u8; 4 * AES_BLOCK_LENGTH]) {
        let mut w = [0u32; 16];
        for (word, bytes) in w.iter_mut().zip(blocks.as_chunks().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        let mut q = [0u64; 8];
        for (i, block) in w.as_chunks().0.iter().enumerate() {
            (q[i], q[i + 4]) = interleave_in(block);
        }
        ortho(&mut q);
        bitslice_decrypt(self.num_rounds, &self.skey, &mut q);
        ortho(&mut q);
        for (i, block) in w.as_chunks_mut().0.iter_mut().enumerate() {
            *block = interleave_out(q[i], q[i + 4]);
        }
        for (bytes, word) in blocks.as_chunks_mut().0.iter_mut().zip(w) {
            *bytes = word.to_le_bytes();
        }
    }

    /// `br_aes_ct64_cbcdec_run`: decrypts whole blocks of `data` in place, in
    /// CBC mode, and leaves in `iv` what the next ones go on from. Bytes past
    /// the last whole block are left as they are.
    pub fn cbc_decrypt(&self, iv: &mut [u8; AES_BLOCK_LENGTH], data: &mut [u8]) {
        let whole = data.len() / AES_BLOCK_LENGTH * AES_BLOCK_LENGTH;
        let mut blocks = [0u8; 4 * AES_BLOCK_LENGTH];
        for chunk in data[..whole].chunks_mut(4 * AES_BLOCK_LENGTH) {
            blocks[..chunk.len()].copy_from_slice(chunk);
            let cipher = blocks;
            self.decrypt4(&mut blocks);
            // Each block, XORed with the cipher block before it.
            let mut before = *iv;
            let plain = blocks.as_chunks::<AES_BLOCK_LENGTH>().0;
            let ciphers = cipher.as_chunks::<AES_BLOCK_LENGTH>().0;
            let blocks_out = chunk.as_chunks_mut::<AES_BLOCK_LENGTH>().0;
            for ((out, plain), cipher) in blocks_out.iter_mut().zip(plain).zip(ciphers) {
                let word = u128::from_ne_bytes(*plain) ^ u128::from_ne_bytes(before);
                *out = word.to_ne_bytes();
                before = *cipher;
            }
            *iv = before;
        }
        clear(&mut blocks);
    }

    /// Encrypts one block in place: [`Aes::encrypt4`], with the other three
    /// blocks empty, so it takes as long.
    pub fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_LENGTH]) {
        let mut blocks = [0u8; 4 * AES_BLOCK_LENGTH];
        blocks[..AES_BLOCK_LENGTH].copy_from_slice(block);
        self.encrypt4(&mut blocks);
        block.copy_from_slice(&blocks[..AES_BLOCK_LENGTH]);
    }
}

impl Drop for Aes {
    fn drop(&mut self) {
        clear(&mut self.skey);
    }
}

/// Shows the number of rounds, not the subkeys.
impl std::fmt::Debug for Aes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes")
            .field("num_rounds", &self.num_rounds)
            .finish_non_exhaustive()
    }
}

#[cfg(all(
    test,
    feature = "unsafe-fast",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;

    /// The instructions, where they run, against the bitsliced code.
    #[test]
    fn instructions_same_as_bitsliced() {
        let mut state = 0x0123_4567_89AB_CDEFu64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        };
        for len in [16, 24, 32] {
            for _ in 0..200 {
                let key: Vec<u8> = (0..len).map(|_| next()).collect();
                let Some(aes) = Aes::new(&key) else {
                    panic!("a key of {len} bytes");
                };
                let mut plain = [0u8; 64];
                plain.fill_with(&mut next);
                let (mut a, mut b) = (plain, plain);
                aes.encrypt4(&mut a);
                aes.encrypt4_bitsliced(&mut b);
                assert_eq!(a, b);
                aes.decrypt4(&mut a);
                aes.decrypt4_bitsliced(&mut b);
                assert_eq!(a, plain);
                assert_eq!(b, plain);
            }
        }
    }
}
