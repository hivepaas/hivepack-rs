//! Hashes, HMAC, HKDF and PBKDF2, from RustCrypto's crates.

use hmac::Mac as _;
use hmac::digest::{Digest as _, KeyInit};

/// A hash function, as HMAC, HKDF and PBKDF2 take one.
pub trait Digest: Clone + std::fmt::Debug {
    /// The digest, `[u8; OUTPUT_LENGTH]`.
    type Output: Copy + AsRef<[u8]> + AsMut<[u8]>;

    /// The length of the digest, in bytes.
    const OUTPUT_LENGTH: usize;

    /// The length of a block of input, in bytes.
    const BLOCK_LENGTH: usize;

    /// HMAC with this hash, RustCrypto's.
    #[doc(hidden)]
    type Mac: hmac::Mac + KeyInit + Clone;

    /// A computation with nothing hashed.
    fn new() -> Self;

    /// More data.
    fn update(&mut self, data: &[u8]);

    /// The digest of the data so far. The computation can go on with more data.
    fn out(&self) -> Self::Output;

    /// PBKDF2 with HMAC of this hash.
    #[doc(hidden)]
    fn pbkdf2_fill(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]);

    /// HKDF with this hash: `false` if `out` is past its limit, 255 digests.
    #[doc(hidden)]
    fn hkdf_fill(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], out: &mut [u8]) -> bool;
}

macro_rules! digest {
    ($(#[$doc:meta])* $name:ident, $inner:ty, $const:ident, $length:expr, $block:expr) => {
        /// The length of the digest, in bytes.
        pub const $const: usize = $length;

        $(#[$doc])*
        #[derive(Clone, Default)]
        pub struct $name($inner);

        impl $name {
            /// A computation with nothing hashed.
            pub fn new() -> $name {
                $name(<$inner>::new())
            }

            /// More data.
            pub fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }

            /// The digest of the data so far. The computation can go on with
            /// more data.
            pub fn out(&self) -> [u8; $length] {
                self.0.clone().finalize().into()
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl Digest for $name {
            type Output = [u8; $length];
            const OUTPUT_LENGTH: usize = $length;
            const BLOCK_LENGTH: usize = $block;
            type Mac = hmac::Hmac<$inner>;

            fn new() -> Self {
                $name::new()
            }

            fn update(&mut self, data: &[u8]) {
                $name::update(self, data);
            }

            fn out(&self) -> Self::Output {
                $name::out(self)
            }

            fn pbkdf2_fill(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
                pbkdf2::pbkdf2_hmac::<$inner>(password, salt, iterations, out);
            }

            fn hkdf_fill(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], out: &mut [u8]) -> bool {
                hkdf::Hkdf::<$inner>::new(salt, ikm).expand(info, out).is_ok()
            }
        }
    };
}

digest!(
    /// SHA-1, from the `sha1` crate. It is broken for signatures: it is here for
    /// the formats that use it.
    Sha1, sha1::Sha1, SHA1_LENGTH, 20, 64
);
digest!(
    /// SHA-256, from the `sha2` crate.
    Sha256, sha2::Sha256, SHA256_LENGTH, 32, 64
);
digest!(
    /// SHA-512, from the `sha2` crate.
    Sha512, sha2::Sha512, SHA512_LENGTH, 64, 128
);
digest!(
    /// MD5, from the `md-5` crate. It is broken: it is here for the formats that
    /// use it.
    Md5, md5::Md5, MD5_LENGTH, 16, 64
);

/// An HMAC key, ready to start computations: `Hmac::new` is cheap, as the key's
/// blocks are hashed once.
#[derive(Clone)]
pub struct HmacKey<H: Digest> {
    mac: H::Mac,
}

impl<H: Digest> HmacKey<H> {
    /// The key, of any length.
    pub fn new(key: &[u8]) -> HmacKey<H> {
        // HMAC takes a key of any length, and this cannot fail.
        #[allow(clippy::expect_used)]
        let mac = H::Mac::new_from_slice(key).expect("HMAC takes a key of any length");
        HmacKey { mac }
    }
}

impl<H: Digest> std::fmt::Debug for HmacKey<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacKey").finish_non_exhaustive()
    }
}

/// An HMAC computation.
#[derive(Clone)]
pub struct Hmac<H: Digest> {
    mac: H::Mac,
}

impl<H: Digest> Hmac<H> {
    /// A computation with `key` and nothing hashed.
    pub fn new(key: &HmacKey<H>) -> Hmac<H> {
        Hmac {
            mac: key.mac.clone(),
        }
    }

    /// More data.
    pub fn update(&mut self, data: &[u8]) {
        self.mac.update(data);
    }

    /// The MAC of the data so far. The computation can go on with more data.
    pub fn out(&self) -> H::Output {
        let bytes = self.mac.clone().finalize().into_bytes();
        // Any value of the type, to fill.
        let mut out = H::new().out();
        out.as_mut().copy_from_slice(&bytes);
        out
    }
}

impl<H: Digest> std::fmt::Debug for Hmac<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hmac").finish_non_exhaustive()
    }
}

/// HKDF of `ikm` with `salt` and `info`, into all of `out`: `false` if `out` is
/// longer than its limit, 255 digests.
pub fn hkdf<H: Digest>(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], out: &mut [u8]) -> bool {
    H::hkdf_fill(salt, ikm, info, out)
}

/// PBKDF2 with HMAC of `H`, into all of `out`.
pub fn pbkdf2<H: Digest>(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    H::pbkdf2_fill(password, salt, iterations, out);
}
