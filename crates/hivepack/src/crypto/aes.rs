//! AES, from the `aes` crate, which uses the processor's instructions where it
//! has them, and otherwise fixsliced code that takes the same time whatever the
//! key and the data.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256, Block};

/// The length of an AES block, in bytes.
pub const AES_BLOCK_LENGTH: usize = 16;

/// How many blocks CBC decrypts at a time, as the instructions do them together.
const CBC_BLOCKS: usize = 8;

/// An AES key, ready to encrypt and decrypt. The key schedule is overwritten
/// when it is dropped (best effort).
#[derive(Clone)]
pub enum Aes {
    #[doc(hidden)]
    Key128(Aes128),
    #[doc(hidden)]
    Key192(Aes192),
    #[doc(hidden)]
    Key256(Aes256),
}

/// Shows nothing of the key.
impl std::fmt::Debug for Aes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes").finish_non_exhaustive()
    }
}

impl Aes {
    /// The key schedule of `key`, AES-128, AES-192 or AES-256 for a key of 16, 24
    /// or 32 bytes; `None` for any other length.
    pub fn new(key: &[u8]) -> Option<Aes> {
        match key.len() {
            16 => Aes128::new_from_slice(key).ok().map(Aes::Key128),
            24 => Aes192::new_from_slice(key).ok().map(Aes::Key192),
            32 => Aes256::new_from_slice(key).ok().map(Aes::Key256),
            _ => None,
        }
    }

    fn encrypt_blocks(&self, blocks: &mut [Block]) {
        match self {
            Aes::Key128(k) => k.encrypt_blocks(blocks),
            Aes::Key192(k) => k.encrypt_blocks(blocks),
            Aes::Key256(k) => k.encrypt_blocks(blocks),
        }
    }

    fn decrypt_blocks(&self, blocks: &mut [Block]) {
        match self {
            Aes::Key128(k) => k.decrypt_blocks(blocks),
            Aes::Key192(k) => k.decrypt_blocks(blocks),
            Aes::Key256(k) => k.decrypt_blocks(blocks),
        }
    }

    /// Encrypts four blocks in place, one after the other in `blocks`.
    pub fn encrypt4(&self, blocks: &mut [u8; 4 * AES_BLOCK_LENGTH]) {
        let (blocks, _) = Block::slice_as_chunks_mut(blocks);
        self.encrypt_blocks(blocks);
    }

    /// Decrypts four blocks in place, one after the other in `blocks`.
    pub fn decrypt4(&self, blocks: &mut [u8; 4 * AES_BLOCK_LENGTH]) {
        let (blocks, _) = Block::slice_as_chunks_mut(blocks);
        self.decrypt_blocks(blocks);
    }

    /// Decrypts whole blocks of `data` in place, in CBC mode, and leaves in `iv`
    /// what the next ones go on from. Bytes past the last whole block are left as
    /// they are.
    pub fn cbc_decrypt(&self, iv: &mut [u8; AES_BLOCK_LENGTH], data: &mut [u8]) {
        let whole = data.len() / AES_BLOCK_LENGTH * AES_BLOCK_LENGTH;
        let mut cipher = [0u8; CBC_BLOCKS * AES_BLOCK_LENGTH];
        for group in data[..whole].chunks_mut(CBC_BLOCKS * AES_BLOCK_LENGTH) {
            let cipher = &mut cipher[..group.len()];
            cipher.copy_from_slice(group);
            let (blocks, _) = Block::slice_as_chunks_mut(group);
            self.decrypt_blocks(blocks);
            let (first, rest) = group.split_at_mut(AES_BLOCK_LENGTH);
            for (byte, before) in first.iter_mut().zip(iv.iter()) {
                *byte ^= before;
            }
            for (byte, before) in rest.iter_mut().zip(cipher.iter()) {
                *byte ^= before;
            }
            iv.copy_from_slice(&cipher[cipher.len() - AES_BLOCK_LENGTH..]);
        }
    }

    /// Encrypts one block in place.
    pub fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_LENGTH]) {
        let (blocks, _) = Block::slice_as_chunks_mut(block);
        self.encrypt_blocks(blocks);
    }
}
