//! Ed25519 signatures, from `ed25519-dalek`.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// The length of a seed, the private key, in bytes.
pub const ED25519_SEED_LENGTH: usize = 32;
/// The length of a public key, in bytes.
pub const ED25519_PUBLIC_LENGTH: usize = 32;
/// The length of a signature, in bytes.
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// The public key of the private key `seed`.
pub fn ed25519_public(seed: &[u8; ED25519_SEED_LENGTH]) -> [u8; ED25519_PUBLIC_LENGTH] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// The signature of `message` by the private key `seed` (RFC 8032): the same each
/// time. The public key is the seed's own, never one given, as signing with
/// another would give the private key away.
pub fn ed25519_sign(
    seed: &[u8; ED25519_SEED_LENGTH],
    message: &[u8],
) -> [u8; ED25519_SIGNATURE_LENGTH] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

/// Whether `signature` is `public`'s of `message`, strictly: a key of small order
/// and a signature that another could be made from, without the private key, are
/// refused.
pub fn ed25519_verify(
    public: &[u8; ED25519_PUBLIC_LENGTH],
    message: &[u8],
    signature: &[u8; ED25519_SIGNATURE_LENGTH],
) -> bool {
    let Ok(public) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    public
        .verify_strict(message, &Signature::from_bytes(signature))
        .is_ok()
}
