//! ChaCha20-Poly1305, from the `chacha20poly1305` crate, which uses the
//! processor's vector instructions where it has them.

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};

/// The length of a key, in bytes.
pub const CHACHA20_KEY_LENGTH: usize = 32;

/// The length of a nonce, in bytes.
pub const CHACHA20_NONCE_LENGTH: usize = 12;

/// The length of a tag, in bytes.
pub const POLY1305_TAG_LENGTH: usize = 16;

/// Encrypts `data` in place with `key` and `nonce`, and gives the tag of it and
/// `aad`.
///
/// # Panics
///
/// Past the limit the construction has on its data, 256 GiB. What seals here is
/// a piece at a time, 64 KiB at most.
pub fn chacha20_poly1305_seal(
    key: &[u8; CHACHA20_KEY_LENGTH],
    nonce: &[u8; CHACHA20_NONCE_LENGTH],
    data: &mut [u8],
    aad: &[u8],
) -> [u8; POLY1305_TAG_LENGTH] {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    #[allow(clippy::expect_used)]
    let tag = cipher
        .encrypt_inout_detached(&Nonce::from(*nonce), aad, data.into())
        .expect("data within ChaCha20-Poly1305's limit");
    tag.into()
}

/// Checks `tag` against `data` and `aad`, in constant time, and decrypts `data` in
/// place if it matches. If not, this returns `false` and `data` is as it was.
pub fn chacha20_poly1305_open(
    key: &[u8; CHACHA20_KEY_LENGTH],
    nonce: &[u8; CHACHA20_NONCE_LENGTH],
    data: &mut [u8],
    aad: &[u8],
    tag: &[u8; POLY1305_TAG_LENGTH],
) -> bool {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .decrypt_inout_detached(&Nonce::from(*nonce), aad, data.into(), &Tag::from(*tag))
        .is_ok()
}
