//! The cryptography of hivepack's formats, behind one small interface.
//!
//! This crate writes no cryptography. It calls crates that many others depend on,
//! which use the processor's instructions where it has them and take the `unsafe`
//! code that needs. This crate has none of its own, and hivepack's other crates
//! see only this interface. Which crate does what, and what has been audited, is in
//! the repository: `docs/crypto.md`.
//!
//! - [`Aes`]: `aes`, the AES of ZIP's, 7z's and RAR's encryption.
//! - [`Sha1`], [`Sha256`], [`Sha512`], [`Md5`], and through [`Digest`] [`Hmac`],
//!   [`hkdf()`] and [`pbkdf2()`]: `sha1`, `sha2`, `md-5`, `hmac`, `hkdf` and `pbkdf2`.
//! - [`chacha20_poly1305_seal`] and [`chacha20_poly1305_open`]: `chacha20poly1305`,
//!   what age encrypts with.
//! - [`x25519`], [`x25519_base`] and [`ed25519_public_to_x25519`]:
//!   `curve25519-dalek`, age's keys and SSH keys.
//! - [`ed25519_public`], [`ed25519_sign`] and [`ed25519_verify`]: `ed25519-dalek`,
//!   signatures.
//! - [`mldsa65_public`], [`mldsa65_sign`] and [`mldsa65_verify`]: `ml-dsa`, signatures
//!   that hold against a quantum computer.
//! - [`scrypt()`]: `scrypt`, age's passphrases.
//! - [`xwing_hpke_seal`] and [`xwing_hpke_open`]: `hpke` and `x-wing`, age's
//!   post-quantum keys.
//! - [`Blake2s`] and [`Blake2sp`]: `blake2s_simd`, RAR 5's file hashes.
//! - [`equal`]: `subtle`, comparing tags in constant time.
//! - [`RandomSource`] and [`system_random`]: where random bytes come from.

#![forbid(unsafe_code)]

mod aead;
mod aes;
mod blake2;
mod curve;
mod digest;
mod ed25519;
mod kdf;
mod mldsa;
mod random;
mod xwing;

pub use aead::{
    CHACHA20_KEY_LENGTH, CHACHA20_NONCE_LENGTH, POLY1305_TAG_LENGTH, chacha20_poly1305_open,
    chacha20_poly1305_seal,
};
pub use aes::{AES_BLOCK_LENGTH, Aes};
pub use blake2::{BLAKE2S_KEY_LENGTH, BLAKE2S_LENGTH, BLAKE2SP_LENGTH, Blake2s, Blake2sp};
pub use curve::{X25519_LENGTH, ed25519_public_to_x25519, x25519, x25519_base};
pub use digest::{
    Digest, Hmac, HmacKey, MD5_LENGTH, Md5, SHA1_LENGTH, SHA256_LENGTH, SHA512_LENGTH, Sha1,
    Sha256, Sha512, hkdf, pbkdf2,
};
pub use ed25519::{
    ED25519_PUBLIC_LENGTH, ED25519_SEED_LENGTH, ED25519_SIGNATURE_LENGTH, ed25519_public,
    ed25519_sign, ed25519_verify,
};
pub use kdf::{ScryptError, scrypt};
pub use mldsa::{
    MLDSA65_PUBLIC_LENGTH, MLDSA65_SEED_LENGTH, MLDSA65_SIGNATURE_LENGTH, mldsa65_public,
    mldsa65_sign, mldsa65_verify,
};
pub use random::{RandomSource, system_random};
pub use xwing::{
    XWING_ENC_LENGTH, XWING_PUBLIC_LENGTH, XWING_SEED_LENGTH, XwingOpenError, xwing_hpke_open,
    xwing_hpke_seal, xwing_public, xwing_public_is_valid,
};

/// Whether `a` and `b` are the same, in a time that does not depend on where they
/// differ. Slices of different lengths are not the same.
pub fn equal(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
