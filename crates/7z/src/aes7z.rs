//! `7zAES`: AES-256 in CBC mode, with a key hashed from a password, both ways.
//!
//! 7-Zip's code for it, `CPP/7zip/Crypto/7zAes.cpp`, is under the LGPL, so
//! none of it is ported. The format is the one 7-Zip's archives have, from
//! `DOC/Methods.txt` (`06 F1 07 01`) and from checking against `7zz`:
//!
//! - The coder's properties hold how many times the key is hashed, a salt and
//!   an IV. The first byte's low 6 bits are the power of 2 of the rounds; with
//!   neither of its high 2 bits set, there is nothing else. Otherwise the
//!   second byte follows, and the salt's size is the first byte's bit 7 plus
//!   the second byte's high 4 bits, and the IV's its bit 6 plus the low 4 bits.
//!   Then come the salt and the IV, which zeros fill out to 16 bytes.
//! - The key is SHA-256 of the salt, the password in UTF-16LE and a round's
//!   number in 8 bytes, little-endian, one after another for each round. With
//!   63 as the power, it is the salt and the password themselves, up to 32
//!   bytes, then zeros.
//! - The data is padded to whole blocks, and the coder's output has the size
//!   before that. `7zz` takes more whole blocks than that, and so does this,
//!   but no partial one.
//!
//! Differs from `7zz`, which, past 24 as the power of 2 of the rounds, goes on
//! without hashing, with a key of zeros: those are refused here, as nothing
//! writes them, and a file that reads with any password is no better for it.

use hivepack_crypto::{AES_BLOCK_LENGTH, Aes, Sha256};

use crate::error::{Error, Result};

/// `k_AES`.
pub(crate) const K_AES: u32 = 0x6F1_0701;

/// `K_AES`, as a coder's ID.
pub(crate) const K_AES_ID: [u8; 4] = [0x06, 0xF1, 0x07, 0x01];

/// The power of 2 of the rounds that stands for no hashing at all.
const NO_HASHING: u32 = 0x3F;

/// The most rounds 7-Zip takes, as a power of 2.
pub(crate) const MAX_KEY_CYCLES: u32 = 24;

/// How many keys are kept, which an archive's folders mostly share.
const KEYS_KEPT: usize = 16;

/// How much ciphertext is decrypted at a time.
const BUF_SIZE: usize = 1 << 14;

/// Overwrites `bytes` with zeros, as far as safe Rust can (see
/// `hivepack-crypto`'s `clear`).
fn clear(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}

/// A coder's properties.
struct Props<'a> {
    cycles: u32,
    salt: &'a [u8],
    iv: [u8; AES_BLOCK_LENGTH],
}

fn parse_props(props: &[u8]) -> Result<Props<'_>> {
    let mut parsed = Props {
        cycles: 0,
        salt: &[],
        iv: [0; AES_BLOCK_LENGTH],
    };
    let Some((&first, rest)) = props.split_first() else {
        return Ok(parsed);
    };
    parsed.cycles = u32::from(first & 0x3F);
    if first & 0xC0 == 0 {
        return if rest.is_empty() {
            Ok(parsed)
        } else {
            Err(Error::Unsupported)
        };
    }
    let Some((&second, rest)) = rest.split_first() else {
        return Err(Error::Unsupported);
    };
    let salt_size = usize::from(first >> 7) + usize::from(second >> 4);
    let iv_size = usize::from((first >> 6) & 1) + usize::from(second & 0x0F);
    if rest.len() != salt_size + iv_size {
        return Err(Error::Unsupported);
    }
    let (salt, iv) = rest.split_at(salt_size);
    parsed.salt = salt;
    parsed.iv[..iv_size].copy_from_slice(iv);
    Ok(parsed)
}

/// The key from a password, in UTF-16LE.
fn derive_key(cycles: u32, salt: &[u8], password: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    if cycles == NO_HASHING {
        for (byte, from) in key.iter_mut().zip(salt.iter().chain(password)) {
            *byte = *from;
        }
        return key;
    }
    // Rounds together in a buffer, which one hash call takes faster than
    // three a round.
    let unit = salt.len() + password.len() + 8;
    let per_batch = (4096 / unit).max(1);
    let mut batch = Vec::with_capacity(unit * per_batch);
    for _ in 0..per_batch {
        batch.extend_from_slice(salt);
        batch.extend_from_slice(password);
        batch.extend_from_slice(&[0; 8]);
    }
    let rounds = 1u64 << cycles;
    let mut round = 0;
    let mut sha = Sha256::new();
    while round < rounds {
        let n = (rounds - round).min(per_batch as u64) as usize;
        for (i, chunk) in batch.chunks_exact_mut(unit).take(n).enumerate() {
            chunk[unit - 8..].copy_from_slice(&(round + i as u64).to_le_bytes());
        }
        sha.update(&batch[..n * unit]);
        round += n as u64;
    }
    clear(&mut batch);
    key.copy_from_slice(&sha.out());
    key
}

/// What decoding a folder needs from `Options`, and the keys it has made.
pub(crate) struct Decoding {
    pub(crate) limit: u64,
    /// In UTF-16LE.
    password: Option<Vec<u8>>,
    max_key_cycles: u32,
    keys: Vec<(u32, Vec<u8>, [u8; 32])>,
}

impl Decoding {
    pub(crate) fn new(limit: u64, password: Option<&str>, max_key_cycles: u32) -> Self {
        let mut decoding = Decoding {
            limit,
            password: None,
            max_key_cycles,
            keys: Vec::new(),
        };
        if let Some(password) = password {
            decoding.set_password(password);
        }
        decoding
    }

    /// The password from now on; the keys made from another are forgotten.
    pub(crate) fn set_password(&mut self, password: &str) {
        self.forget();
        self.password = Some(password.encode_utf16().flat_map(u16::to_le_bytes).collect());
    }

    fn forget(&mut self) {
        if let Some(password) = &mut self.password {
            clear(password);
        }
        for (_, _, key) in &mut self.keys {
            clear(key);
        }
        self.keys.clear();
    }

    /// The key for a coder's properties; hashing takes long, so it is kept.
    fn key(&mut self, cycles: u32, salt: &[u8]) -> Result<[u8; 32]> {
        if let Some((_, _, key)) = self
            .keys
            .iter()
            .find(|(c, s, _)| *c == cycles && s.as_slice() == salt)
        {
            return Ok(*key);
        }
        let password = self.password.as_deref().ok_or(Error::PasswordRequired)?;
        if cycles != NO_HASHING && cycles > self.max_key_cycles {
            return Err(Error::Unsupported);
        }
        let key = derive_key(cycles, salt, password);
        if self.keys.len() == KEYS_KEPT {
            let mut oldest = self.keys.remove(0);
            clear(&mut oldest.2);
        }
        self.keys.push((cycles, salt.to_vec(), key));
        Ok(key)
    }
}

impl Drop for Decoding {
    fn drop(&mut self) {
        self.forget();
    }
}

/// The decryption of a coder's input.
pub(crate) struct AesCoder {
    aes: Aes,
    iv: [u8; AES_BLOCK_LENGTH],
    buf: Vec<u8>,
    /// What is decrypted and not yet taken: `buf[start..len]`.
    start: usize,
    len: usize,
}

impl AesCoder {
    pub(crate) fn new(props: &[u8], decoding: &mut Decoding) -> Result<Self> {
        let Props { cycles, salt, iv } = parse_props(props)?;
        let mut key = decoding.key(cycles, salt)?;
        let aes = Aes::new(&key).ok_or(Error::Fail);
        clear(&mut key);
        Ok(AesCoder {
            aes: aes?,
            iv,
            buf: vec![0; BUF_SIZE],
            start: 0,
            len: 0,
        })
    }

    /// Up to `out.len()` bytes already decrypted.
    pub(crate) fn take(&mut self, out: &mut [u8]) -> usize {
        let n = (self.len - self.start).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
        self.start += n;
        n
    }

    /// The buffer to fill with ciphertext, when all is taken.
    pub(crate) fn space(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// Decrypts the `filled` bytes at the start of the buffer, which are
    /// whole blocks.
    pub(crate) fn decrypt(&mut self, filled: usize) {
        self.aes.cbc_decrypt(&mut self.iv, &mut self.buf[..filled]);
        self.start = 0;
        self.len = filled;
    }
}

impl Drop for AesCoder {
    fn drop(&mut self) {
        clear(&mut self.buf);
    }
}

/// The encryption of a coder's output.
pub(crate) struct AesEncoder {
    aes: Aes,
    /// The block before, which the next one goes on from.
    iv: [u8; AES_BLOCK_LENGTH],
    /// Bytes short of a block.
    pending: [u8; AES_BLOCK_LENGTH],
    pending_len: usize,
    cipher: Vec<u8>,
}

impl AesEncoder {
    /// The key from a password.
    pub(crate) fn key(cycles: u32, salt: &[u8], password: &str) -> [u8; 32] {
        let mut password: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let key = derive_key(cycles, salt, &password);
        clear(&mut password);
        key
    }

    /// The coder's properties, for a salt and an IV of a whole block each.
    pub(crate) fn props(
        cycles: u32,
        salt: &[u8; AES_BLOCK_LENGTH],
        iv: &[u8; AES_BLOCK_LENGTH],
    ) -> Vec<u8> {
        // Both sizes are 16: a high bit of the first byte, and 15 in the second.
        let mut props = vec![0xC0 | cycles as u8, 0xFF];
        props.extend_from_slice(salt);
        props.extend_from_slice(iv);
        props
    }

    pub(crate) fn new(key: &[u8; 32], iv: [u8; AES_BLOCK_LENGTH]) -> Result<Self> {
        Ok(AesEncoder {
            aes: Aes::new(key).ok_or(Error::Fail)?,
            iv,
            pending: [0; AES_BLOCK_LENGTH],
            pending_len: 0,
            cipher: Vec::with_capacity(BUF_SIZE),
        })
    }

    fn block(&mut self, block: &[u8; AES_BLOCK_LENGTH]) {
        for (byte, from) in self.iv.iter_mut().zip(block) {
            *byte ^= *from;
        }
        self.aes.encrypt_block(&mut self.iv);
        self.cipher.extend_from_slice(&self.iv);
    }

    /// Gives `out` the whole blocks `data` completes, and keeps the rest.
    pub(crate) fn encrypt(
        &mut self,
        mut data: &[u8],
        out: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        if self.pending_len > 0 {
            let n = (AES_BLOCK_LENGTH - self.pending_len).min(data.len());
            self.pending[self.pending_len..self.pending_len + n].copy_from_slice(&data[..n]);
            self.pending_len += n;
            data = &data[n..];
            if self.pending_len < AES_BLOCK_LENGTH {
                return Ok(());
            }
            let block = self.pending;
            self.block(&block);
            self.pending_len = 0;
        }
        let (blocks, rest) = data.as_chunks::<AES_BLOCK_LENGTH>();
        for block in blocks {
            self.block(block);
            if self.cipher.len() >= BUF_SIZE {
                out(&self.cipher)?;
                self.cipher.clear();
            }
        }
        self.pending[..rest.len()].copy_from_slice(rest);
        self.pending_len = rest.len();
        if !self.cipher.is_empty() {
            out(&self.cipher)?;
            self.cipher.clear();
        }
        Ok(())
    }

    /// The last block, zeros making it whole.
    pub(crate) fn finish(
        &mut self,
        out: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        if self.pending_len > 0 {
            self.pending[self.pending_len..].fill(0);
            let block = self.pending;
            self.block(&block);
            self.pending_len = 0;
            out(&self.cipher)?;
            self.cipher.clear();
        }
        Ok(())
    }
}

impl Drop for AesEncoder {
    fn drop(&mut self) {
        clear(&mut self.pending);
    }
}
