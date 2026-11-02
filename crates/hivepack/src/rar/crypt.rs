// hivepack::rar: a port of UnRAR 7.3.2 to Rust. UnRAR's license says:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

//! Decrypting: UnRAR's `CryptData` (crypt.cpp, crypt1.cpp, crypt2.cpp,
//! crypt3.cpp, crypt5.cpp) and `sha1_process_rar29` (sha1.cpp).
//!
//! A password is taken as UnRAR takes it on Linux. For RAR 3 each character is
//! two bytes, so one past the first 65,536 loses what is above, and for what
//! is older the password is its UTF-8. UnRAR on Windows takes it in the code
//! page of the system, which only matters to passwords not in ASCII.

use std::fmt;

use crate::crypto::{AES_BLOCK_LENGTH, Aes, Hmac, HmacKey, Sha256};

use crate::rar::headers::CryptMethod;

/// `MAXPASSWORD`.
const MAX_PASSWORD: usize = 512;
/// `MAXPASSWORD_RAR`.
const MAX_PASSWORD_RAR: usize = 128;
/// `CRYPT5_KDF_LG2_COUNT_MAX`.
const CRYPT5_KDF_LG2_COUNT_MAX: u32 = 24;
/// `CRYPT_BLOCK_SIZE`.
const CRYPT_BLOCK_SIZE: usize = 16;
/// `SIZE_SALT30`.
const SIZE_SALT30: usize = 8;
/// `SIZE_SALT50`.
const SIZE_SALT50: usize = 16;
/// `SIZE_PSWCHECK`.
const SIZE_PSWCHECK: usize = 8;
/// `SHA256_DIGEST_SIZE`.
const SHA256_DIGEST_SIZE: usize = 32;

/// `NROUNDS`.
const NROUNDS: usize = 32;

/// `InitSubstTable20`.
static INIT_SUBST_TABLE20: [u8; 256] = [
    215, 19, 149, 35, 73, 197, 192, 205, 249, 28, 16, 119, 48, 221, 2, 42, 232, 1, 177, 233, 14,
    88, 219, 25, 223, 195, 244, 90, 87, 239, 153, 137, 255, 199, 147, 70, 92, 66, 246, 13, 216, 40,
    62, 29, 217, 230, 86, 6, 71, 24, 171, 196, 101, 113, 218, 123, 93, 91, 163, 178, 202, 67, 44,
    235, 107, 250, 75, 234, 49, 167, 125, 211, 83, 114, 157, 144, 32, 193, 143, 36, 158, 124, 247,
    187, 89, 214, 141, 47, 121, 228, 61, 130, 213, 194, 174, 251, 97, 110, 54, 229, 115, 57, 152,
    94, 105, 243, 212, 55, 209, 245, 63, 11, 164, 200, 31, 156, 81, 176, 227, 21, 76, 99, 139, 188,
    127, 17, 248, 51, 207, 120, 189, 210, 8, 226, 41, 72, 183, 203, 135, 165, 166, 60, 98, 7, 122,
    38, 155, 170, 69, 172, 252, 238, 39, 134, 59, 128, 236, 27, 240, 80, 131, 3, 85, 206, 145, 79,
    154, 142, 159, 220, 201, 133, 74, 64, 20, 129, 224, 185, 138, 103, 173, 182, 43, 34, 254, 82,
    198, 151, 231, 180, 58, 10, 118, 26, 102, 12, 50, 132, 22, 191, 136, 111, 162, 179, 45, 4, 148,
    108, 161, 56, 78, 126, 242, 222, 15, 175, 146, 23, 33, 241, 181, 190, 77, 225, 0, 46, 169, 186,
    68, 95, 237, 65, 53, 208, 253, 168, 9, 18, 100, 52, 116, 184, 160, 96, 109, 37, 30, 106, 140,
    104, 150, 5, 204, 117, 112, 84,
];

/// `InitCRC32`: CRC-32's table.
fn crc_table() -> [u32; 256] {
    let mut table = [0; 256];
    for (i, entry) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xedb8_8320
            } else {
                c >> 1
            };
        }
        *entry = c;
    }
    table
}

/// `SecPassword`, and what `SetCryptKeys` makes of it. Overwritten when
/// dropped, as far as safe Rust can tell.
#[derive(Default)]
pub(crate) struct Password {
    wide: Vec<u32>,
    /// `PwdA`.
    narrow: Vec<u8>,
}

impl Password {
    pub(crate) fn new(password: &str) -> Password {
        let wide: Vec<u32> = password
            .chars()
            .map(u32::from)
            .take_while(|&c| c != 0)
            .take((MAX_PASSWORD_RAR - 1).min(MAX_PASSWORD - 1))
            .collect();
        let mut narrow = Vec::with_capacity(wide.len());
        for &c in &wide {
            let mut bytes = [0; 4];
            if let Some(c) = char::from_u32(c) {
                narrow.extend_from_slice(c.encode_utf8(&mut bytes).as_bytes());
            }
        }
        narrow.truncate(MAX_PASSWORD_RAR - 1);
        Password { wide, narrow }
    }

    pub(crate) fn is_set(&self) -> bool {
        !self.wide.is_empty()
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.wide.fill(0);
        self.narrow.fill(0);
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password")
    }
}

/// What RAR 3's key derivation gave.
#[derive(Clone)]
struct Kdf3 {
    salt: Option<[u8; SIZE_SALT30]>,
    key: [u8; 16],
    init: [u8; 16],
}

/// What RAR 5's key derivation gave.
#[derive(Clone)]
struct Kdf5 {
    salt: [u8; SIZE_SALT50],
    lg2_count: u32,
    key: [u8; 32],
    psw_check_value: [u8; SHA256_DIGEST_SIZE],
    hash_key_value: [u8; SHA256_DIGEST_SIZE],
}

/// `KDF3Cache` and `KDF5Cache`: derivations are slow on purpose, and all the
/// entries of an archive usually have the same salt.
#[derive(Default)]
pub(crate) struct KdfCache {
    kdf3: [Option<Kdf3>; 4],
    kdf3_pos: usize,
    kdf5: [Option<Kdf5>; 4],
    kdf5_pos: usize,
}

impl Drop for KdfCache {
    fn drop(&mut self) {
        for item in self.kdf3.iter_mut().flatten() {
            item.key.fill(0);
            item.init.fill(0);
        }
        for item in self.kdf5.iter_mut().flatten() {
            item.key.fill(0);
            item.psw_check_value.fill(0);
            item.hash_key_value.fill(0);
        }
    }
}

impl fmt::Debug for KdfCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KdfCache")
    }
}

/// What decrypting goes on from: `CryptData` after `SetCryptKeys`.
pub(crate) enum CryptData {
    Rar13 {
        key: [u8; 3],
    },
    Rar15 {
        key: [u16; 4],
        crc_tab: Box<[u32; 256]>,
    },
    Rar20 {
        key: [u32; 4],
        subst: Box<[u8; 256]>,
        crc_tab: Box<[u32; 256]>,
    },
    Aes {
        aes: Box<Aes>,
        iv: [u8; AES_BLOCK_LENGTH],
    },
}

impl fmt::Debug for CryptData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CryptData")
    }
}

/// `SetCryptKeys`' other results.
#[derive(Default)]
pub(crate) struct KeyChecks {
    pub(crate) hash_key: [u8; SHA256_DIGEST_SIZE],
    pub(crate) psw_check: [u8; SIZE_PSWCHECK],
}

/// `CryptData::SetCryptKeys`: nothing for no kind of encryption, no password,
/// or a count of rounds too large.
pub(crate) fn set_crypt_keys(
    method: CryptMethod,
    password: &Password,
    cache: &mut KdfCache,
    salt: Option<&[u8]>,
    init_v: &[u8; AES_BLOCK_LENGTH],
    lg2_count: u32,
) -> Option<(CryptData, KeyChecks)> {
    if !password.is_set() {
        return None;
    }
    let mut checks = KeyChecks::default();
    let crypt = match method {
        CryptMethod::None | CryptMethod::Unknown => return None,
        CryptMethod::Rar13 => set_key13(&password.narrow),
        CryptMethod::Rar15 => set_key15(&password.narrow),
        CryptMethod::Rar20 => set_key20(&password.narrow),
        CryptMethod::Rar30 => set_key30(password, cache, salt)?,
        CryptMethod::Rar50 => set_key50(password, cache, salt, init_v, lg2_count, &mut checks)?,
    };
    Some((crypt, checks))
}

/// `CryptData::SetKey13`.
fn set_key13(password: &[u8]) -> CryptData {
    let mut key = [0u8; 3];
    for &p in password {
        key[0] = key[0].wrapping_add(p);
        key[1] ^= p;
        key[2] = key[2].wrapping_add(p).rotate_left(1);
    }
    CryptData::Rar13 { key }
}

/// `CryptData::SetKey15`.
fn set_key15(password: &[u8]) -> CryptData {
    let crc_tab = Box::new(crc_table());
    let mut crc = 0xffff_ffffu32;
    for &p in password {
        crc = crc_tab[usize::from(crc as u8 ^ p)] ^ (crc >> 8);
    }
    let mut key = [(crc & 0xffff) as u16, (crc >> 16) as u16, 0, 0];
    for &p in password {
        let entry = crc_tab[usize::from(p)];
        key[2] ^= u16::from(p) ^ entry as u16;
        key[3] = key[3].wrapping_add((u32::from(p) + (entry >> 16)) as u16);
    }
    CryptData::Rar15 { key, crc_tab }
}

/// `CryptData::SetKey20`.
fn set_key20(password: &[u8]) -> CryptData {
    let crc_tab = Box::new(crc_table());
    let mut subst = Box::new(INIT_SUBST_TABLE20);
    let byte_at = |i: usize| password.get(i).copied().unwrap_or(0);

    for j in 0..256u32 {
        for i in (0..password.len()).step_by(2) {
            let mut n1 = crc_tab[(u32::from(byte_at(i)).wrapping_sub(j) & 0xff) as usize] as u8;
            let n2 = crc_tab[(u32::from(byte_at(i + 1)).wrapping_add(j) & 0xff) as usize] as u8;
            let mut k = 1usize;
            while n1 != n2 {
                let other = (usize::from(n1) + i + k) & 0xff;
                subst.swap(usize::from(n1), other);
                n1 = n1.wrapping_add(1);
                k += 1;
            }
        }
    }

    let mut crypt = CryptData::Rar20 {
        key: [0xd3a3_b879, 0x3f6d_12f7, 0x7515_a235, 0xa4e7_f123],
        subst,
        crc_tab,
    };
    // An incomplete last block of the password is zero padded.
    for block in password.chunks(CRYPT_BLOCK_SIZE) {
        let mut buf = [0u8; CRYPT_BLOCK_SIZE];
        buf[..block.len()].copy_from_slice(block);
        crypt.encrypt_block20(&mut buf);
    }
    crypt
}

/// `sha1_context`: SHA-1, as `sha1_process_rar29` needs its insides.
#[derive(Clone)]
struct Sha1 {
    state: [u32; 5],
    count: u64,
    buffer: [u8; 64],
}

impl Sha1 {
    fn new() -> Sha1 {
        Sha1 {
            state: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
            count: 0,
            buffer: [0; 64],
        }
    }

    /// `SHA1Transform`: `workspace` keeps the last 16 words of the expansion.
    #[inline]
    fn transform(state: &mut [u32; 5], workspace: &mut [u32; 16], block: &[u8]) {
        for (word, bytes) in workspace.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *state;
        for i in 0..80 {
            let w = if i < 16 {
                workspace[i]
            } else {
                let w = (workspace[(i + 13) & 15]
                    ^ workspace[(i + 8) & 15]
                    ^ workspace[(i + 2) & 15]
                    ^ workspace[i & 15])
                    .rotate_left(1);
                workspace[i & 15] = w;
                w
            };
            let (f, k) = match i {
                0..=19 => ((b & (c ^ d)) ^ d, 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => (((b | c) & d) | (b & c), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e]) {
            *s = s.wrapping_add(v);
        }
    }

    /// `sha1_process`, or `sha1_process_rar29` with `write_back`: RAR 3's
    /// variant leaves the expansion of each whole block in the data, which is
    /// hashed again in the next round. Only a password of about 30 characters
    /// or more comes to that.
    fn process(&mut self, data: &mut [u8], write_back: bool) {
        let len = data.len();
        let mut j = (self.count & 63) as usize;
        self.count += len as u64;
        let mut i = 0;
        if j + len > 63 {
            i = 64 - j;
            self.buffer[j..64].copy_from_slice(&data[..i]);
            let mut workspace = [0; 16];
            Sha1::transform(&mut self.state, &mut workspace, &self.buffer);
            while i + 63 < len {
                Sha1::transform(&mut self.state, &mut workspace, &data[i..i + 64]);
                if write_back {
                    for (k, word) in workspace.iter().enumerate() {
                        data[i + k * 4..i + k * 4 + 4].copy_from_slice(&word.to_le_bytes());
                    }
                }
                i += 64;
            }
            j = 0;
        }
        if len > i {
            self.buffer[j..j + len - i].copy_from_slice(&data[i..]);
        }
    }

    /// `sha1_done`, on what it was given: the digest's words.
    fn done(mut self) -> [u32; 5] {
        let bit_length = self.count.wrapping_mul(8);
        let mut pos = (self.count & 63) as usize;
        self.buffer[pos] = 0x80;
        pos += 1;
        let mut workspace = [0; 16];
        if pos > 56 {
            self.buffer[pos..].fill(0);
            Sha1::transform(&mut self.state, &mut workspace, &self.buffer);
            pos = 0;
        }
        self.buffer[pos..56].fill(0);
        self.buffer[56..].copy_from_slice(&bit_length.to_be_bytes());
        Sha1::transform(&mut self.state, &mut workspace, &self.buffer);
        self.state
    }
}

/// `CryptData::SetKey30`.
fn set_key30(password: &Password, cache: &mut KdfCache, salt: Option<&[u8]>) -> Option<CryptData> {
    let salt: Option<[u8; SIZE_SALT30]> = salt.and_then(|s| s.get(..SIZE_SALT30)?.try_into().ok());
    let known = cache.kdf3.iter().flatten().find(|item| item.salt == salt);
    let (key, init) = match known {
        Some(item) => (item.key, item.init),
        None => {
            let (key, init) = derive30(password, salt.as_ref());
            cache.kdf3[cache.kdf3_pos] = Some(Kdf3 { salt, key, init });
            cache.kdf3_pos = (cache.kdf3_pos + 1) % cache.kdf3.len();
            (key, init)
        }
    };
    Some(CryptData::Aes {
        aes: Box::new(Aes::new(&key)?),
        iv: init,
    })
}

/// The derivation of `SetKey30`.
fn derive30(password: &Password, salt: Option<&[u8; SIZE_SALT30]>) -> ([u8; 16], [u8; 16]) {
    const HASH_ROUNDS: u32 = 0x40000;

    let mut raw_psw = Vec::with_capacity(2 * password.wide.len() + SIZE_SALT30);
    for &c in &password.wide {
        raw_psw.push(c as u8);
        raw_psw.push((c >> 8) as u8);
    }
    if let Some(salt) = salt {
        raw_psw.extend_from_slice(salt);
    }

    let mut init = [0u8; 16];
    let mut sha = Sha1::new();
    for i in 0..HASH_ROUNDS {
        sha.process(&mut raw_psw, true);
        let mut psw_num = [i as u8, (i >> 8) as u8, (i >> 16) as u8];
        sha.process(&mut psw_num, false);
        if i % (HASH_ROUNDS / 16) == 0 {
            let digest = sha.clone().done();
            init[(i / (HASH_ROUNDS / 16)) as usize] = digest[4] as u8;
        }
    }
    let digest = sha.done();
    let mut key = [0u8; 16];
    for (bytes, word) in key.as_chunks_mut::<4>().0.iter_mut().zip(digest) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    raw_psw.fill(0);
    (key, init)
}

/// `CryptData::SetKey50`.
fn set_key50(
    password: &Password,
    cache: &mut KdfCache,
    salt: Option<&[u8]>,
    init_v: &[u8; AES_BLOCK_LENGTH],
    lg2_count: u32,
    checks: &mut KeyChecks,
) -> Option<CryptData> {
    if lg2_count > CRYPT5_KDF_LG2_COUNT_MAX {
        return None;
    }
    // A header of RAR 5 always has it where it is asked for.
    let salt: [u8; SIZE_SALT50] = salt?.get(..SIZE_SALT50)?.try_into().ok()?;
    let known = cache
        .kdf5
        .iter()
        .flatten()
        .find(|item| item.lg2_count == lg2_count && item.salt == salt)
        .cloned();
    let item = match known {
        Some(item) => item,
        None => {
            let mut utf = Vec::with_capacity(password.wide.len() * 4);
            for &c in &password.wide {
                let mut bytes = [0; 4];
                if let Some(c) = char::from_u32(c) {
                    utf.extend_from_slice(c.encode_utf8(&mut bytes).as_bytes());
                }
            }
            // Damaged bytes ask for 2^24 rounds for each entry, as they may in
            // UnRAR too, which keeps a fuzzer from getting anywhere.
            #[cfg(fuzzing)]
            let lg2_count = lg2_count.min(4);
            let (key, hash_key_value, psw_check_value) = pbkdf2(&utf, &salt, 1 << lg2_count);
            utf.fill(0);
            let item = Kdf5 {
                salt,
                lg2_count,
                key,
                psw_check_value,
                hash_key_value,
            };
            cache.kdf5[cache.kdf5_pos] = Some(item.clone());
            cache.kdf5_pos = (cache.kdf5_pos + 1) % cache.kdf5.len();
            item
        }
    };
    checks.hash_key = item.hash_key_value;
    for (i, byte) in item.psw_check_value.iter().enumerate() {
        checks.psw_check[i % SIZE_PSWCHECK] ^= byte;
    }
    Some(CryptData::Aes {
        aes: Box::new(Aes::new(&item.key)?),
        iv: *init_v,
    })
}

/// UnRAR's `pbkdf2`: the key, then the same 16 and 32 rounds further on.
fn pbkdf2(
    password: &[u8],
    salt: &[u8; SIZE_SALT50],
    count: u32,
) -> (
    [u8; SHA256_DIGEST_SIZE],
    [u8; SHA256_DIGEST_SIZE],
    [u8; SHA256_DIGEST_SIZE],
) {
    let key = HmacKey::<Sha256>::new(password);
    let mut hmac = Hmac::new(&key);
    hmac.update(salt);
    hmac.update(&[0, 0, 0, 1]);
    let mut u = hmac.out();
    let mut f = u;
    let mut values = [[0; SHA256_DIGEST_SIZE]; 3];
    for (value, rounds) in values.iter_mut().zip([count - 1, 16, 16]) {
        for _ in 0..rounds {
            let mut hmac = Hmac::new(&key);
            hmac.update(&u);
            u = hmac.out();
            for (a, b) in f.iter_mut().zip(u) {
                *a ^= b;
            }
        }
        *value = f;
    }
    u.fill(0);
    f.fill(0);
    let [first, second, third] = values;
    (first, second, third)
}

/// `ConvertHashToMAC` for CRC-32.
pub(crate) fn crc32_to_mac(crc32: u32, key: &[u8; SHA256_DIGEST_SIZE]) -> u32 {
    let mut hmac = Hmac::new(&HmacKey::<Sha256>::new(key));
    hmac.update(&crc32.to_le_bytes());
    let digest: [u8; SHA256_DIGEST_SIZE] = hmac.out();
    let mut value = 0;
    for (i, &byte) in digest.iter().enumerate() {
        value ^= u32::from(byte) << ((i & 3) * 8);
    }
    value
}

/// `ConvertHashToMAC` for BLAKE2.
pub(crate) fn digest_to_mac(digest: &[u8; 32], key: &[u8; SHA256_DIGEST_SIZE]) -> [u8; 32] {
    let mut hmac = Hmac::new(&HmacKey::<Sha256>::new(key));
    hmac.update(digest);
    hmac.out()
}

impl CryptData {
    /// `CryptData::SetCmt13Encryption`: RAR 1.3 keeps its comments like this.
    pub(crate) fn cmt13() -> CryptData {
        CryptData::Rar13 { key: [0, 7, 77] }
    }

    /// `CryptData::DecryptBlock` of the first `size` bytes of `buf`. RAR 2's
    /// cipher goes on to the end of a block, within `buf` as nothing reads an
    /// unaligned amount here unless there is room for a block.
    pub(crate) fn decrypt_block(&mut self, buf: &mut [u8], size: usize) {
        match self {
            CryptData::Rar13 { key } => {
                for byte in &mut buf[..size] {
                    key[1] = key[1].wrapping_add(key[2]);
                    key[0] = key[0].wrapping_add(key[1]);
                    *byte = byte.wrapping_sub(key[0]);
                }
            }
            CryptData::Rar15 { key, crc_tab } => {
                for byte in &mut buf[..size] {
                    key[0] = key[0].wrapping_add(0x1234);
                    let entry = crc_tab[usize::from((key[0] & 0x1fe) >> 1)];
                    key[1] ^= entry as u16;
                    key[2] = key[2].wrapping_sub((entry >> 16) as u16);
                    key[0] ^= key[2];
                    key[3] = key[3].rotate_right(1) ^ key[1];
                    key[3] = key[3].rotate_right(1);
                    key[0] ^= key[3];
                    *byte ^= (key[0] >> 8) as u8;
                }
            }
            CryptData::Rar20 { .. } => {
                let blocks = size.div_ceil(CRYPT_BLOCK_SIZE);
                for block in buf
                    .as_chunks_mut::<CRYPT_BLOCK_SIZE>()
                    .0
                    .iter_mut()
                    .take(blocks)
                {
                    self.decrypt_block20(block);
                }
            }
            CryptData::Aes { aes, iv } => aes.cbc_decrypt(iv, &mut buf[..size]),
        }
    }

    /// The rounds of `EncryptBlock20` and `DecryptBlock20`, which only differ
    /// in the order of the keys, here `key[i & 3]`.
    fn rounds20(
        key: &[u32; 4],
        subst: &[u8; 256],
        block: &[u8; CRYPT_BLOCK_SIZE],
        order: impl Iterator<Item = usize>,
    ) -> [u8; CRYPT_BLOCK_SIZE] {
        let word = |i: usize| {
            u32::from_le_bytes([block[i], block[i + 1], block[i + 2], block[i + 3]]) ^ key[i / 4]
        };
        let subst_long = |t: u32| {
            u32::from(subst[(t & 255) as usize])
                | u32::from(subst[((t >> 8) & 255) as usize]) << 8
                | u32::from(subst[((t >> 16) & 255) as usize]) << 16
                | u32::from(subst[((t >> 24) & 255) as usize]) << 24
        };
        let (mut a, mut b, mut c, mut d) = (word(0), word(4), word(8), word(12));
        for i in order {
            let k = key[i & 3];
            let t = c.wrapping_add(d.rotate_left(11)) ^ k;
            let ta = a ^ subst_long(t);
            let t = (d ^ c.rotate_left(17)).wrapping_add(k);
            let tb = b ^ subst_long(t);
            a = c;
            b = d;
            c = ta;
            d = tb;
        }
        let mut out = [0u8; CRYPT_BLOCK_SIZE];
        for (i, value) in [c ^ key[0], d ^ key[1], a ^ key[2], b ^ key[3]]
            .into_iter()
            .enumerate()
        {
            out[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        out
    }

    /// `CryptData::UpdKeys20`.
    fn upd_keys20(key: &mut [u32; 4], crc_tab: &[u32; 256], buf: &[u8; CRYPT_BLOCK_SIZE]) {
        for chunk in buf.as_chunks::<4>().0 {
            for (k, &byte) in key.iter_mut().zip(chunk) {
                *k ^= crc_tab[usize::from(byte)];
            }
        }
    }

    /// `CryptData::EncryptBlock20`, only for what the password does to the
    /// keys: hivepack does not encrypt RAR.
    fn encrypt_block20(&mut self, buf: &mut [u8; CRYPT_BLOCK_SIZE]) {
        if let CryptData::Rar20 {
            key,
            subst,
            crc_tab,
        } = self
        {
            *buf = CryptData::rounds20(key, subst, buf, 0..NROUNDS);
            CryptData::upd_keys20(key, crc_tab, buf);
        }
    }

    /// `CryptData::DecryptBlock20`.
    fn decrypt_block20(&mut self, buf: &mut [u8; CRYPT_BLOCK_SIZE]) {
        if let CryptData::Rar20 {
            key,
            subst,
            crc_tab,
        } = self
        {
            let in_buf = *buf;
            *buf = CryptData::rounds20(key, subst, &in_buf, (0..NROUNDS).rev());
            CryptData::upd_keys20(key, crc_tab, &in_buf);
        }
    }
}

#[cfg(test)]
mod oracle_tests;
