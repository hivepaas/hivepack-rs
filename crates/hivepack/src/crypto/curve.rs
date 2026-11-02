//! X25519, and Ed25519 public keys as X25519, from `curve25519-dalek`.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;

/// The length of a scalar and of a point, in bytes.
pub const X25519_LENGTH: usize = 32;

/// X25519 of the scalar `k` and the u-coordinate `u`, as RFC 7748 defines it: the
/// scalar is clamped, and the top bit of the coordinate ignored.
///
/// It does not look at the result: a point of small order gives all zeros, which
/// callers that need a shared secret refuse (RFC 7748, section 6.1).
pub fn x25519(k: &[u8; X25519_LENGTH], u: &[u8; X25519_LENGTH]) -> [u8; X25519_LENGTH] {
    MontgomeryPoint(*u).mul_clamped(*k).to_bytes()
}

/// X25519 of the scalar `k` and the base point: the public key of the private key
/// `k`.
pub fn x25519_base(k: &[u8; X25519_LENGTH]) -> [u8; X25519_LENGTH] {
    MontgomeryPoint::mul_base_clamped(*k).to_bytes()
}

/// An Ed25519 public key as the X25519 point it is on the birational map, as SSH
/// keys are used to encrypt to: `None` if it is no point of the curve.
///
/// Its input is public, and its time depends on the key.
pub fn ed25519_public_to_x25519(public: &[u8; X25519_LENGTH]) -> Option<[u8; X25519_LENGTH]> {
    let point = CompressedEdwardsY(*public).decompress()?;
    Some(point.to_montgomery().to_bytes())
}
