//! The cryptography shared by the stanzas and the header: port of
//! `primitives.go`, on hivepack::crypto in place of
//! `golang.org/x/crypto`.

use crate::crypto::{
    Hmac, HmacKey, POLY1305_TAG_LENGTH, Sha256, chacha20_poly1305_open, chacha20_poly1305_seal,
    hkdf,
};

use crate::age::format::Header;

/// Why `aead_decrypt` failed.
pub(crate) enum AeadError {
    /// `errIncorrectCiphertextSize`: the ciphertext is not `size` bytes
    /// plus a tag.
    Size,
    /// The tag does not match.
    Tag,
}

/// `aeadEncrypt`: `plaintext` sealed with `key` and a zero nonce, which is
/// safe as each key wraps one file key only.
pub(crate) fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut sealed = plaintext.to_vec();
    let tag = chacha20_poly1305_seal(key, &[0; 12], &mut sealed, &[]);
    sealed.extend_from_slice(&tag);
    sealed
}

/// `aeadDecrypt`: ChaCha20-Poly1305 with `key` and a zero nonce, which is
/// safe as each key wraps one file key only. The plaintext must be `size`
/// bytes.
pub(crate) fn aead_decrypt(
    key: &[u8; 32],
    size: usize,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if ciphertext.len() != size + POLY1305_TAG_LENGTH {
        return Err(AeadError::Size);
    }
    let (data, tag) = ciphertext.split_at(size);
    let tag: &[u8; POLY1305_TAG_LENGTH] = tag.try_into().map_err(|_| AeadError::Size)?;
    let mut plaintext = data.to_vec();
    if !chacha20_poly1305_open(key, &[0; 12], &mut plaintext, &[], tag) {
        return Err(AeadError::Tag);
    }
    Ok(plaintext)
}

/// HKDF-SHA256 of `ikm` with `salt` and `info`, 32 bytes of it, as age
/// derives every key.
pub(crate) fn hkdf_32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    // 32 bytes are within what HKDF gives.
    hkdf::<Sha256>(salt, ikm, info, &mut out);
    out
}

/// `headerMAC`: HMAC-SHA256 of the header up to its `---`, with a key
/// derived from the file key.
pub(crate) fn header_mac(file_key: &[u8], hdr: &Header) -> [u8; 32] {
    let mut hmac_key = hkdf_32(file_key, None, b"header");
    let mut hh = Hmac::new(&HmacKey::<Sha256>::new(&hmac_key));
    hmac_key.fill(0);
    hh.update(&hdr.marshal_without_mac());
    hh.out()
}

/// `streamKey`: the payload's key, from the file key and the payload's
/// nonce.
pub(crate) fn stream_key(file_key: &[u8], nonce: &[u8]) -> [u8; 32] {
    hkdf_32(file_key, Some(nonce), b"payload")
}
