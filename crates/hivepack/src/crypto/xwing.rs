//! X-Wing (ML-KEM-768 with X25519) under HPKE, with HKDF-SHA256 and
//! ChaCha20-Poly1305, from the `hpke` and `x-wing` crates: age's post-quantum keys.
//!
//! Neither crate, nor `ml-kem` under them, has been independently audited: see
//! `docs/crypto.md`.

use std::convert::Infallible;
use std::io;

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::setup_sender_with_rng;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable, setup_receiver};
use rand_core::{TryCryptoRng, TryRng};

use crate::crypto::random::{RandomSource, system_random};

/// The length of a private key, a seed, in bytes.
pub const XWING_SEED_LENGTH: usize = 32;

/// The length of a public key, in bytes.
pub const XWING_PUBLIC_LENGTH: usize = 1216;

/// The length of an encapsulated key, in bytes.
pub const XWING_ENC_LENGTH: usize = 1120;

/// The length of the X25519 point at the end of a public key and of an
/// encapsulated key, in bytes.
const POINT_LENGTH: usize = 32;

/// How many random bytes an encapsulation takes.
const ENCAPSULATION_RANDOMNESS: usize = 64;

type PublicKey = <XWing as Kem>::PublicKey;
type PrivateKey = <XWing as Kem>::PrivateKey;
type EncappedKey = <XWing as Kem>::EncappedKey;

/// Bytes taken from a source that can fail, given to what cannot.
struct Taken {
    bytes: [u8; ENCAPSULATION_RANDOMNESS],
    at: usize,
}

impl TryRng for Taken {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// The bytes taken, then zeros: an encapsulation asks for exactly as many, and
    /// the tests show it.
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Infallible> {
        let rest = &self.bytes[self.at..];
        let n = rest.len().min(out.len());
        out[..n].copy_from_slice(&rest[..n]);
        out[n..].fill(0);
        self.at += n;
        Ok(())
    }
}

impl TryCryptoRng for Taken {}

impl Drop for Taken {
    fn drop(&mut self) {
        self.bytes.fill(0);
        std::hint::black_box(&mut self.bytes);
    }
}

/// Whether the X25519 point that ends `bytes` has a low order, so that any shared
/// secret with it is all zeros. `x-wing` takes it, as X-Wing's draft does not say, and
/// its README says it will follow the RFC. age refuses it, with RFC 7748, section
/// 6.1. A clamped scalar is a multiple of the cofactor, whichever one this is, and
/// neither the point nor this scalar is secret.
fn ends_in_low_order_point(bytes: &[u8]) -> bool {
    let Some(point) = bytes.last_chunk::<POINT_LENGTH>() else {
        return true;
    };
    crate::crypto::curve::x25519(&[1; POINT_LENGTH], point) == [0; POINT_LENGTH]
}

fn private_key(seed: &[u8; XWING_SEED_LENGTH]) -> Option<PrivateKey> {
    PrivateKey::from_bytes(seed).ok()
}

/// The public key of a seed.
pub fn xwing_public(seed: &[u8; XWING_SEED_LENGTH]) -> Option<[u8; XWING_PUBLIC_LENGTH]> {
    let public = XWing::sk_to_pk(&private_key(seed)?);
    Some(public.to_bytes().into())
}

/// Whether `public` is a public key: ML-KEM's check that its numbers are in range.
pub fn xwing_public_is_valid(public: &[u8]) -> bool {
    PublicKey::from_bytes(public).is_ok()
}

/// Seals `plaintext` to `public` with HPKE in its base mode, with `info`, and no
/// associated data: the encapsulated key, and the ciphertext with its tag. The
/// random bytes come from `random`, or with `None` from the system.
pub fn xwing_hpke_seal(
    public: &[u8],
    info: &[u8],
    plaintext: &[u8],
    random: Option<&RandomSource>,
) -> io::Result<([u8; XWING_ENC_LENGTH], Vec<u8>)> {
    let invalid = |what: &str| io::Error::new(io::ErrorKind::InvalidInput, what.to_string());
    if ends_in_low_order_point(public) {
        return Err(invalid("bad input point: low order point"));
    }
    let public = PublicKey::from_bytes(public).map_err(|_| invalid("invalid X-Wing public key"))?;
    let mut rng = Taken {
        bytes: [0; ENCAPSULATION_RANDOMNESS],
        at: 0,
    };
    match random {
        Some(random) => random(&mut rng.bytes)?,
        None => system_random(&mut rng.bytes)?,
    }
    let (enc, mut context) = setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeS::Base,
        &public,
        info,
        &mut rng,
    )
    .map_err(|e| invalid(&e.to_string()))?;
    let sealed = context
        .seal(plaintext, b"")
        .map_err(|e| invalid(&e.to_string()))?;
    Ok((enc.to_bytes().into(), sealed))
}

/// Why [`xwing_hpke_open`] did not open a ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XwingOpenError {
    /// The encapsulated key's X25519 point has a low order: it is malformed.
    LowOrderPoint,
    /// It does not open, as with another key, as ML-KEM rejects implicitly and the
    /// tag then fails.
    NoMatch,
}

/// Opens what [`xwing_hpke_seal`] sealed.
pub fn xwing_hpke_open(
    seed: &[u8; XWING_SEED_LENGTH],
    enc: &[u8; XWING_ENC_LENGTH],
    info: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, XwingOpenError> {
    if ends_in_low_order_point(enc) {
        return Err(XwingOpenError::LowOrderPoint);
    }
    let no_match = |_| XwingOpenError::NoMatch;
    let private = private_key(seed).ok_or(XwingOpenError::NoMatch)?;
    let enc = EncappedKey::from_bytes(enc).map_err(no_match)?;
    let mut context =
        setup_receiver::<ChaCha20Poly1305, HkdfSha256, XWing>(&OpModeR::Base, &private, &enc, info)
            .map_err(no_match)?;
    context.open(ciphertext, b"").map_err(no_match)
}
