//! scrypt, from the `scrypt` crate.

/// Why [`scrypt()`] did not derive a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScryptError {
    /// The parameters are out of range.
    Parameters,
    /// The memory could not be found.
    Memory,
}

impl std::fmt::Display for ScryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ScryptError::Parameters => "scrypt parameters out of range",
            ScryptError::Memory => "not enough memory for scrypt",
        })
    }
}

impl std::error::Error for ScryptError {}

/// Fills `out` with the key that scrypt derives from `password` and `salt` with
/// the cost N = 2^`log_n`, the block size `r` and the parallelization `p`. It takes
/// 128 × `r` × (N + `p`) bytes of memory, or more.
///
/// The crate allocates its memory in a way that aborts the program if there is
/// none, so that much is reserved and let go first, for an error in the usual case.
/// A system that overcommits memory may still find out later.
pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
    out: &mut [u8],
) -> Result<(), ScryptError> {
    if log_n == 0 {
        return Err(ScryptError::Parameters);
    }
    let params = scrypt::Params::new(log_n, r, p).map_err(|_| ScryptError::Parameters)?;
    let memory = 1usize
        .checked_shl(u32::from(log_n))
        .and_then(|n| n.checked_add(p as usize))
        .and_then(|blocks| blocks.checked_mul(128))
        .and_then(|bytes| bytes.checked_mul(r as usize))
        .ok_or(ScryptError::Parameters)?;
    Vec::<u8>::new()
        .try_reserve_exact(memory)
        .map_err(|_| ScryptError::Memory)?;
    scrypt::scrypt(password, salt, &params, out).map_err(|_| ScryptError::Parameters)
}
