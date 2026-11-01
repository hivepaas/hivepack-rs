//! The cryptography of hivepack's formats in safe Rust, ported from
//! [BearSSL](https://bearssl.org) 0.6 where BearSSL has it.
//!
//! What ZIP's encryption needs: hivepack-zip builds WinZip AES on these,
//! as libzip builds it on OpenSSL, GnuTLS or the system's library.
//! ZipCrypto needs only CRC-32.
//!
//! - [`Aes`] is BearSSL's `aes_ct64`: AES-128, AES-192 and AES-256,
//!   bitsliced, four blocks at a time. No table is indexed with secret
//!   data, so the time it takes depends neither on the key nor on the data.
//!   It only encrypts: WinZip AES runs AES in counter mode, both ways.
//! - [`Sha1`] and [`Hmac`] are BearSSL's `sha1.c` and `hmac.c`.
//! - [`pbkdf2`] follows RFC 8018, as BearSSL has no PBKDF2.
//!
//! What age needs, the encryption tool and format hivepack-age reads:
//!
//! - [`Sha256`] and [`Sha512`] are BearSSL's `sha2small.c` and `sha2big.c`;
//!   [`Hmac`] takes them too, through the [`Digest`] trait.
//! - [`Hkdf`] is BearSSL's `hkdf.c`.
//! - [`chacha20`] and [`chacha20_poly1305`] are BearSSL's `chacha20_ct.c`
//!   and `poly1305_ctmul.c`, in constant time; [`equal`] compares the tags.
//! - [`x25519`] is BearSSL's `ec_c25519_m31.c`, in constant time.
//! - [`scrypt`] follows RFC 7914, as BearSSL has no scrypt.
//!
//! What RAR 5 hashes files with, in hivepack-rar:
//!
//! - [`Blake2sp`] and [`Blake2s`] are the BLAKE2 reference implementation's
//!   `blake2sp-ref.c` and `blake2s-ref.c`, as BearSSL has no BLAKE2.
//!
//! What XAR checks its table of contents and files with, in hivepack-xar,
//! besides SHA-1, SHA-256 and SHA-512:
//!
//! - [`Md5`] is BearSSL's `md5.c`.
//!
//! Secrets are overwritten when the values that hold them are dropped, as
//! libzip clears them with `_zip_crypto_clear`. That is best effort: safe
//! Rust has no volatile write, and the compiler could leave out the
//! zeroing of memory that is not read again.
//!
//! The rules the port follows, and how it is checked against nettle and
//! Go, are in the repository: `docs/crypto.md` and `docs/safety.md`.
//!
//! ```
//! use hivepack_crypto::{Aes, Hkdf, Hmac, HmacKey, Md5, Sha1, Sha256, pbkdf2, x25519, x25519_base};
//!
//! // FIPS-197, appendix C.1.
//! let key: Vec<u8> = (0..16).collect();
//! let aes = Aes::new(&key).expect("a 16-byte key");
//! let mut block = *b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
//! aes.encrypt_block(&mut block);
//! assert_eq!(block[..4], [0x69, 0xc4, 0xe0, 0xd8]);
//!
//! let mut sha1 = Sha1::new();
//! sha1.update(b"abc");
//! assert_eq!(sha1.out()[..4], [0xa9, 0x99, 0x3e, 0x36]);
//!
//! // RFC 1321, appendix A.5.
//! let mut md5 = Md5::new();
//! md5.update(b"abc");
//! assert_eq!(md5.out()[..4], [0x90, 0x01, 0x50, 0x98]);
//!
//! // RFC 2202, test case 2.
//! let mut hmac = Hmac::new(&HmacKey::<Sha1>::new(b"Jefe"));
//! hmac.update(b"what do ya want for nothing?");
//! assert_eq!(hmac.out()[..4], [0xef, 0xfc, 0xdf, 0x6a]);
//!
//! // RFC 6070, the second test.
//! let mut derived = [0; 20];
//! pbkdf2::<Sha1>(b"password", b"salt", 2, &mut derived);
//! assert_eq!(derived[..4], [0xea, 0x6c, 0x01, 0x4d]);
//!
//! // RFC 5869, test case 3: no salt, no info.
//! let mut hkdf = Hkdf::<Sha256>::new(None);
//! hkdf.inject(&[0x0b; 22]);
//! let mut okm = [0; 42];
//! hkdf.flip().produce(b"", &mut okm);
//! assert_eq!(okm[..4], [0x8d, 0xa4, 0xe7, 0x75]);
//!
//! // X25519: both sides of a Diffie-Hellman exchange agree.
//! let (alice, bob) = ([1; 32], [2; 32]);
//! assert_eq!(x25519(&alice, &x25519_base(&bob)), x25519(&bob, &x25519_base(&alice)));
//! ```

// No unsafe code at all, unless the `unsafe-fast` feature is on: then only
// where a module allows it (see `docs/unsafe.md`).
#![cfg_attr(not(feature = "unsafe-fast"), forbid(unsafe_code))]

mod aes_ct64;
mod aes_ct64_ctr;
mod aes_ct64_dec;
mod aes_ct64_enc;
#[cfg(all(
    feature = "unsafe-fast",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod aes_hw;
mod blake2s;
mod blake2sp;
mod chacha20_ct;
#[cfg(all(
    feature = "unsafe-fast",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod chacha_hw;
mod clear;
mod ct;
mod digest;
#[cfg_attr(target_pointer_width = "64", allow(dead_code))]
mod ec_c25519_m31;
#[cfg(target_pointer_width = "64")]
mod ec_c25519_m51;
mod hkdf;
mod hmac;
mod md5;
mod pbkdf2;
mod poly1305_ctmul;
mod random;
mod scrypt;
mod sha1;
mod sha2big;
mod sha2small;
#[cfg(all(
    feature = "unsafe-fast",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod sha_hw;

/// Whether this build has the `unsafe-fast` feature: AES with the processor's
/// instructions, SHA-1 and SHA-256 too, and ChaCha20 with its vector
/// instructions, where it has them. Cargo turns a feature on for the whole build
/// as soon as one crate asks for it, so a program can check which it got.
pub const UNSAFE_FAST: bool = cfg!(feature = "unsafe-fast");

pub use aes_ct64_ctr::{AES_BLOCK_LENGTH, Aes};
pub use blake2s::{BLAKE2S_KEY_LENGTH, BLAKE2S_LENGTH, Blake2s};
pub use blake2sp::{BLAKE2SP_LENGTH, Blake2sp};
pub use chacha20_ct::{CHACHA20_KEY_LENGTH, CHACHA20_NONCE_LENGTH, chacha20};
pub use ct::equal;
pub use digest::Digest;
pub use ec_c25519_m31::X25519_LENGTH;
#[cfg(not(target_pointer_width = "64"))]
pub use ec_c25519_m31::x25519;
pub use ec_c25519_m31::x25519_base;
#[cfg(target_pointer_width = "64")]
pub use ec_c25519_m51::x25519;
pub use hkdf::{Hkdf, HkdfExpand};
pub use hmac::{Hmac, HmacKey};
pub use md5::{MD5_LENGTH, Md5};
pub use pbkdf2::pbkdf2;
pub use poly1305_ctmul::{POLY1305_TAG_LENGTH, chacha20_poly1305};
pub use random::{RandomSource, system_random};
pub use scrypt::{ScryptError, scrypt};
pub use sha1::{SHA1_LENGTH, Sha1};
pub use sha2big::{SHA512_LENGTH, Sha512};
pub use sha2small::{SHA256_LENGTH, Sha256};

/// The BearSSL release this crate follows.
pub const UPSTREAM_VERSION: &str = "0.6";

/// The safe code behind what the `unsafe-fast` feature can replace, and SHA's
/// rounds, for `fuzz/fuzz_targets/hw_crypto.rs` to compare.
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzz_safe {
    use crate::{Aes, CHACHA20_KEY_LENGTH, CHACHA20_NONCE_LENGTH};

    pub fn aes_encrypt4(aes: &Aes, blocks: &mut [u8; 64]) {
        aes.encrypt4_bitsliced(blocks);
    }

    pub fn aes_decrypt4(aes: &Aes, blocks: &mut [u8; 64]) {
        aes.decrypt4_bitsliced(blocks);
    }

    pub fn sha1_block(block: &[u8; 64], val: &mut [u32; 5]) {
        crate::sha1::round_code(block, val);
    }

    pub fn sha1_block_any(block: &[u8; 64], val: &mut [u32; 5]) {
        crate::sha1::round(block, val);
    }

    pub fn sha256_block(block: &[u8; 64], val: &mut [u32; 8]) {
        crate::sha2small::round_code(block, val);
    }

    pub fn sha256_block_any(block: &[u8; 64], val: &mut [u32; 8]) {
        crate::sha2small::round(block, val);
    }

    pub fn chacha20(
        key: &[u8; CHACHA20_KEY_LENGTH],
        iv: &[u8; CHACHA20_NONCE_LENGTH],
        cc: u32,
        data: &mut [u8],
    ) -> u32 {
        crate::chacha20_ct::chacha20_safe(key, iv, cc, data)
    }
}
