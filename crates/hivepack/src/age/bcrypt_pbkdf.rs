//! bcrypt_pbkdf, the key derivation of OpenSSH's encrypted private keys:
//! port of `golang.org/x/crypto/ssh/internal/bcrypt_pbkdf`, itself after
//! OpenBSD's `bcrypt_pbkdf.c`.
//!
//! PBKDF2's structure with bcrypt's Blowfish setup as the hash, which is
//! slow on purpose: OpenSSH's default of 16 rounds takes about a tenth of
//! a second.

use crate::crypto::Sha512;

use crate::age::blowfish::Cipher;

/// `blockSize`: the output of one bcrypt hash.
const BLOCK_SIZE: usize = 32;

/// `magic`.
const MAGIC: &[u8; BLOCK_SIZE] = b"OxychromaticBlowfishSwatDynamite";

/// `Key`: `key_len` bytes derived from `password` and `salt` in `rounds`
/// rounds.
pub(crate) fn key(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    key_len: usize,
) -> Result<Vec<u8>, String> {
    if rounds < 1 {
        return Err("bcrypt_pbkdf: number of rounds is too small".into());
    }
    if password.is_empty() {
        return Err("bcrypt_pbkdf: empty password".into());
    }
    if salt.is_empty() || salt.len() > 1 << 20 {
        return Err("bcrypt_pbkdf: bad salt length".into());
    }
    if key_len > 1024 {
        return Err("bcrypt_pbkdf: keyLen is too large".into());
    }

    let num_blocks = key_len.div_ceil(BLOCK_SIZE);
    let mut key = vec![0u8; num_blocks * BLOCK_SIZE];

    let mut h = Sha512::new();
    h.update(password);
    let mut shapass = h.out();
    let mut tmp = [0u8; BLOCK_SIZE];
    for block in 1..=num_blocks {
        let mut h = Sha512::new();
        h.update(salt);
        h.update(&(block as u32).to_be_bytes());
        bcrypt_hash(&mut tmp, &shapass, &h.out());
        let mut out = tmp;
        for _ in 2..=rounds {
            let mut h = Sha512::new();
            h.update(&tmp);
            bcrypt_hash(&mut tmp, &shapass, &h.out());
            for (o, t) in out.iter_mut().zip(tmp) {
                *o ^= t;
            }
        }
        // The blocks' bytes are interleaved.
        for (i, &v) in out.iter().enumerate() {
            key[i * num_blocks + (block - 1)] = v;
        }
        out.fill(0);
    }
    tmp.fill(0);
    shapass.fill(0);
    key.truncate(key_len);
    Ok(key)
}

/// `bcryptHash`: the Blowfish state set up from `shapass` and `shasalt`,
/// 64 more expansions with each, then the magic encrypted 64 times.
fn bcrypt_hash(out: &mut [u8; BLOCK_SIZE], shapass: &[u8], shasalt: &[u8]) {
    let mut c = Cipher::new_salted(shapass, shasalt);
    for _ in 0..64 {
        c.expand_key(shasalt);
        c.expand_key(shapass);
    }
    out.copy_from_slice(MAGIC);
    for block in out.as_chunks_mut::<8>().0 {
        for _ in 0..64 {
            c.encrypt(block);
        }
    }
    // Each 32-bit word's bytes reversed.
    for word in out.as_chunks_mut::<4>().0 {
        word.reverse();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The vectors of golang.org/x/crypto's bcrypt_pbkdf_test.go, after
    // OpenBSD's.
    #[test]
    fn go_golden_vectors() {
        assert_eq!(
            key(b"password", b"salt", 12, 32).unwrap(),
            [
                0x1a, 0xe4, 0x2c, 0x05, 0xd4, 0x87, 0xbc, 0x02, 0xf6, 0x49, 0x21, 0xa4, 0xeb, 0xe4,
                0xea, 0x93, 0xbc, 0xac, 0xfe, 0x13, 0x5f, 0xda, 0x99, 0x97, 0x4c, 0x06, 0xb7, 0xb0,
                0x1f, 0xae, 0x14, 0x9a,
            ]
        );
        assert_eq!(
            key(b"passwordy\x00PASSWORD\x00", b"salty\x00SALT\x00", 3, 32).unwrap(),
            [
                0x7f, 0x31, 0x0b, 0xd3, 0xe7, 0x8c, 0x32, 0x80, 0xc5, 0x9c, 0xe4, 0x59, 0x52, 0x11,
                0xa2, 0x92, 0x8e, 0x8d, 0x4e, 0xc7, 0x44, 0xc1, 0xed, 0x2e, 0xfc, 0x9f, 0x76, 0x4e,
                0x33, 0x88, 0xe0, 0xad,
            ]
        );
        assert_eq!(
            key(
                "секретное слово".as_bytes(),
                "посолить немножко".as_bytes(),
                8,
                88
            )
            .unwrap(),
            [
                0x8d, 0xf4, 0x3f, 0xc6, 0xfe, 0x13, 0x1f, 0xc4, 0x7f, 0x0c, 0x9e, 0x39, 0x22, 0x4b,
                0xd9, 0x4c, 0x70, 0xb6, 0xfc, 0xc8, 0xee, 0x81, 0x35, 0xfa, 0xdd, 0xf6, 0x11, 0x56,
                0xe6, 0xcb, 0x27, 0x33, 0xea, 0x76, 0x5f, 0x31, 0x5a, 0x3e, 0x1e, 0x4a, 0xfc, 0x35,
                0xbf, 0x86, 0x87, 0xd1, 0x89, 0x25, 0x4c, 0x1e, 0x05, 0xa6, 0xfe, 0x80, 0xc0, 0x61,
                0x7f, 0x91, 0x83, 0xd6, 0x72, 0x60, 0xd6, 0xa1, 0x15, 0xc6, 0xc9, 0x4e, 0x36, 0x03,
                0xe2, 0x30, 0x3f, 0xbb, 0x43, 0xa7, 0x6a, 0x64, 0x52, 0x3f, 0xfd, 0xa6, 0x86, 0xb1,
                0xd4, 0x51, 0x85, 0x43,
            ]
        );
    }

    // TestBcryptHash, from the same file.
    #[test]
    fn bcrypt_hash_go_vector() {
        let pass: [u8; 64] = std::array::from_fn(|i| i as u8);
        let salt: [u8; 64] = std::array::from_fn(|i| i as u8 + 64);
        let mut result = [0u8; BLOCK_SIZE];
        bcrypt_hash(&mut result, &pass, &salt);
        assert_eq!(
            result,
            [
                0x87, 0x90, 0x48, 0x70, 0xee, 0xf9, 0xde, 0xdd, 0xf8, 0xe7, 0x61, 0x1a, 0x14, 0x01,
                0x06, 0xe6, 0xaa, 0xf1, 0xa3, 0x63, 0xd9, 0xa2, 0xc5, 0x04, 0xdb, 0x35, 0x64, 0x43,
                0x72, 0x1e, 0xb5, 0x55,
            ]
        );
    }

    #[test]
    fn refuses_what_go_refuses() {
        assert!(key(b"p", b"s", 0, 32).is_err());
        assert!(key(b"", b"s", 1, 32).is_err());
        assert!(key(b"p", b"", 1, 32).is_err());
        assert!(key(b"p", b"s", 1, 1025).is_err());
    }
}
