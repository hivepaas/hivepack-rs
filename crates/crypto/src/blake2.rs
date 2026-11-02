//! BLAKE2s and BLAKE2sp, from the `blake2s_simd` crate, which has the tree mode
//! RAR 5 hashes files with and which RustCrypto's `blake2` crate has not.

/// The longest key, in bytes.
pub const BLAKE2S_KEY_LENGTH: usize = 32;

/// The length of a BLAKE2s digest, in bytes.
pub const BLAKE2S_LENGTH: usize = 32;

/// The length of a BLAKE2sp digest, in bytes.
pub const BLAKE2SP_LENGTH: usize = 32;

/// BLAKE2s with a digest of 32 bytes.
#[derive(Clone)]
pub struct Blake2s(blake2s_simd::State);

impl Default for Blake2s {
    fn default() -> Self {
        Blake2s::new()
    }
}

impl Blake2s {
    /// A computation with nothing hashed.
    pub fn new() -> Blake2s {
        Blake2s(blake2s_simd::Params::new().to_state())
    }

    /// A computation with a key: `None` for a key longer than 32 bytes. An empty
    /// key is no key.
    pub fn with_key(key: &[u8]) -> Option<Blake2s> {
        if key.len() > BLAKE2S_KEY_LENGTH {
            return None;
        }
        Some(Blake2s(blake2s_simd::Params::new().key(key).to_state()))
    }

    /// More data.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The digest of the data so far. The computation can go on with more data.
    pub fn out(&self) -> [u8; BLAKE2S_LENGTH] {
        *self.0.finalize().as_array()
    }
}

/// Shows nothing of what was hashed.
impl std::fmt::Debug for Blake2s {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blake2s").finish_non_exhaustive()
    }
}

/// BLAKE2sp, eight BLAKE2s side by side, with a digest of 32 bytes.
#[derive(Clone)]
pub struct Blake2sp(blake2s_simd::blake2sp::State);

impl Default for Blake2sp {
    fn default() -> Self {
        Blake2sp::new()
    }
}

impl Blake2sp {
    /// A computation with nothing hashed.
    pub fn new() -> Blake2sp {
        Blake2sp(blake2s_simd::blake2sp::Params::new().to_state())
    }

    /// A computation with a key: `None` for a key longer than 32 bytes. An empty
    /// key is no key.
    pub fn with_key(key: &[u8]) -> Option<Blake2sp> {
        if key.len() > BLAKE2S_KEY_LENGTH {
            return None;
        }
        Some(Blake2sp(
            blake2s_simd::blake2sp::Params::new().key(key).to_state(),
        ))
    }

    /// More data.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The digest of the data so far. The computation can go on with more data.
    pub fn out(&self) -> [u8; BLAKE2SP_LENGTH] {
        *self.0.finalize().as_array()
    }
}

/// Shows nothing of what was hashed.
impl std::fmt::Debug for Blake2sp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blake2sp").finish_non_exhaustive()
    }
}
