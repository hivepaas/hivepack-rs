//! Random bytes for what encrypts: keys, salts and nonces.
//!
//! Without `unsafe` code only Unix's `/dev/urandom` can be read. Windows' own
//! function needs it, so where the system is not Unix a program gives a source
//! of its own, such as the `getrandom` crate.

use std::io;
use std::sync::Arc;

/// Where random bytes come from: it fills the buffer it is given, all of it, or
/// fails. What encrypts stops if it fails, rather than go on with less.
pub type RandomSource = Arc<dyn Fn(&mut [u8]) -> io::Result<()> + Send + Sync>;

/// Fills `bytes` from the system: `/dev/urandom`, read on after a short read.
#[cfg(unix)]
pub fn system_random(bytes: &mut [u8]) -> io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(bytes)
}

/// Fails: only Unix's system source can be read without `unsafe` code.
#[cfg(not(unix))]
pub fn system_random(_bytes: &mut [u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no system source of random bytes without unsafe code: give one",
    ))
}
