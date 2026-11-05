//! How many threads of its own a coder may use.

use std::num::NonZeroU32;

/// How many threads of its own a coder may use, besides the caller's.
///
/// A library makes none unless asked, as liblzma and libzstd do:
/// [`Threads::One`] is the default. More threads change how fast a coder
/// goes, never what it gives: the same input gives the same output with one
/// thread or many. Where a format leaves no work to share (a gzip stream, a
/// zstd frame, an xz Block without its sizes in its header), the caller's
/// thread does it all whatever this says. Each coder says where it uses them.
///
/// Each thread takes memory of its own, and each coder that uses threads
/// takes a limit on it, under which it uses fewer, one at least, and tells
/// what it would take beforehand: see `docs/memory.md`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Threads {
    /// The caller's thread alone.
    #[default]
    One,
    /// As many as the machine runs at once
    /// ([`std::thread::available_parallelism`]); one if it cannot be told.
    Auto,
    /// At most this many.
    Exactly(NonZeroU32),
}

impl Threads {
    /// `count` threads, as the tools take it: 0 for [`Threads::Auto`], as
    /// `xz -T0` and `zstd -T0`.
    pub fn of(count: u32) -> Threads {
        match NonZeroU32::new(count) {
            None => Threads::Auto,
            Some(n) if n.get() == 1 => Threads::One,
            Some(n) => Threads::Exactly(n),
        }
    }

    /// How many, at least one: [`Threads::Auto`] asks the machine.
    pub fn count(self) -> u32 {
        match self {
            Threads::One => 1,
            Threads::Exactly(n) => n.get(),
            Threads::Auto => std::thread::available_parallelism()
                .map_or(1, |n| u32::try_from(n.get()).unwrap_or(u32::MAX)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts() {
        assert_eq!(Threads::default(), Threads::One);
        assert_eq!(Threads::of(1), Threads::One);
        assert_eq!(Threads::of(0), Threads::Auto);
        assert_eq!(Threads::of(6).count(), 6);
        assert_eq!(Threads::One.count(), 1);
        assert!(Threads::Auto.count() >= 1);
    }
}
