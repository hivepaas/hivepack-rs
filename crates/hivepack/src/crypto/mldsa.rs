//! ML-DSA-65 (FIPS 204), from the `ml-dsa` crate, which has not been independently
//! audited: see `docs/crypto.md`.

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Seed, Signature, SigningKey, VerifyingKey,
};

/// The length of a private key, a seed, in bytes.
pub const MLDSA65_SEED_LENGTH: usize = 32;
/// The length of a public key, in bytes.
pub const MLDSA65_PUBLIC_LENGTH: usize = 1952;
/// The length of a signature, in bytes.
pub const MLDSA65_SIGNATURE_LENGTH: usize = 3309;

fn signing_key(seed: &[u8; MLDSA65_SEED_LENGTH]) -> SigningKey<MlDsa65> {
    SigningKey::from_seed(&Seed::from(*seed))
}

/// The public key of the private key `seed`.
pub fn mldsa65_public(seed: &[u8; MLDSA65_SEED_LENGTH]) -> [u8; MLDSA65_PUBLIC_LENGTH] {
    let mut out = [0u8; MLDSA65_PUBLIC_LENGTH];
    out.copy_from_slice(
        signing_key(seed)
            .expanded_key()
            .verifying_key()
            .encode()
            .as_slice(),
    );
    out
}

/// The signature of `message` by the private key `seed`, with `context`, in FIPS 204's
/// deterministic form: the same each time, with no random bytes to get wrong. `None` if
/// `context` is over 255 bytes.
pub fn mldsa65_sign(
    seed: &[u8; MLDSA65_SEED_LENGTH],
    message: &[u8],
    context: &[u8],
) -> Option<[u8; MLDSA65_SIGNATURE_LENGTH]> {
    let key = signing_key(seed);
    let signature = key
        .expanded_key()
        .sign_deterministic(message, context)
        .ok()?;
    let mut out = [0u8; MLDSA65_SIGNATURE_LENGTH];
    out.copy_from_slice(signature.encode().as_slice());
    Some(out)
}

/// Whether `signature` is `public`'s of `message`, with `context`.
pub fn mldsa65_verify(
    public: &[u8; MLDSA65_PUBLIC_LENGTH],
    message: &[u8],
    context: &[u8],
    signature: &[u8; MLDSA65_SIGNATURE_LENGTH],
) -> bool {
    let public = VerifyingKey::<MlDsa65>::decode(&EncodedVerifyingKey::<MlDsa65>::from(*public));
    let Some(signature) = Signature::decode(&EncodedSignature::<MlDsa65>::from(*signature)) else {
        return false;
    };
    public.verify_with_context(message, context, &signature)
}
