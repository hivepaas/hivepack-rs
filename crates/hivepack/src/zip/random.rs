//! Random bytes for encrypting: port of `zip_random_unix.c`'s
//! `zip_secure_random`, which reads `/dev/urandom`.
//!
//! Differs from libzip: the caller can give the bytes
//! ([`Archive::set_random_source`]), and must where the system is not Unix
//! (libzip asks Windows' and Apple's own functions, which need `unsafe`
//! code). A short read of `/dev/urandom` is read on, where libzip fails.

use crate::crypto::system_random;

use crate::zip::open::Archive;

/// Where the random bytes encrypting takes come from: it fills the buffer
/// it is given, or fails. WinZip AES takes a salt of 8 to 16 bytes for
/// each entry, ZipCrypto 11 bytes for its header.
pub use crate::crypto::RandomSource;

/// `zip_secure_random`: fills `buffer` from `source`, or from the system
/// without one; `false` if it cannot.
pub(crate) fn secure_random(source: Option<&RandomSource>, buffer: &mut [u8]) -> bool {
    match source {
        Some(source) => source(buffer).is_ok(),
        None => system_random(buffer).is_ok(),
    }
}

impl<R> Archive<R> {
    /// Sets where the random bytes come from that encrypting entries takes
    /// when the archive is written: `source`, or with `None` the system
    /// (`/dev/urandom`), as libzip's `zip_secure_random` reads it. Where
    /// the system is not Unix, encrypting fails with
    /// [`ErrorCode::Internal`](crate::zip::ErrorCode::Internal) unless a source
    /// is given.
    pub fn set_random_source(&mut self, source: Option<RandomSource>) {
        self.random = source;
    }
}
