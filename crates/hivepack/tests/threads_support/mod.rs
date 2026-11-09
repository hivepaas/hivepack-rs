//! The threads the tests that compare them are run with.
//!
//! Under emulation, as CI's cross jobs run the tests on s390x
//! (`HIVEPACK_EMULATED`, passed into the container by Cross.toml), one thread
//! and two only: what threads do does not hang on the machine's byte order or
//! width, which those jobs are there for, and an emulated machine runs eight
//! of them, and the work they share, many times slower. Every other machine
//! runs them all.

use hivepack::Threads;

/// Whether the tests run on an emulated machine.
pub fn emulated() -> bool {
    std::env::var_os("HIVEPACK_EMULATED").is_some_and(|v| !v.is_empty())
}

/// `all`, or under emulation those of them that are one thread or two, or
/// the first if none is.
pub fn chosen<const N: usize>(all: [Threads; N]) -> Vec<Threads> {
    if !emulated() {
        return all.to_vec();
    }
    let few: Vec<Threads> = all
        .iter()
        .copied()
        .filter(|t| matches!(t, Threads::One) || *t == Threads::of(2))
        .collect();
    if few.is_empty() {
        all.iter().copied().take(1).collect()
    } else {
        few
    }
}
