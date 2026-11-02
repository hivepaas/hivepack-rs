//! The raw reads and writes behind the `unsafe-fast` feature: pieces of up
//! to 32 bytes, without a bounds check. Only the decoder's fast loop uses
//! them, through the `Mode` [`Unchecked`]; making one is `unsafe`, and
//! `lz4::decompress_generic` does it once, with a `SAFETY` comment that
//! shows each of the fast loop's pieces in bounds. That block and this
//! module are the crate's only `unsafe` code. See `docs/unsafe.md`.

#![allow(unsafe_code)]

use crate::lz4::lz4::Mode;

/// Pieces read and written without bounds checks: the `Mode` of the
/// decoder's fast loop when the feature is on.
///
/// Only `Unchecked::new` makes one, and it is `unsafe`, so safe code
/// holding a `Mode` can never reach these accesses by itself.
#[derive(Clone, Copy)]
pub(crate) struct Unchecked(());

impl Unchecked {
    /// # Safety
    ///
    /// Every piece the returned mode reads or writes must be in its
    /// buffer: for `read::<N>(buf, at)` and `write::<N>(buf, at, _)`,
    /// `at + N <= buf.len()`.
    #[inline(always)]
    pub(crate) unsafe fn new() -> Self {
        Unchecked(())
    }
}

impl Mode for Unchecked {
    const CHECKED: bool = false;

    #[inline(always)]
    fn read<const N: usize>(self, buf: &[u8], at: usize) -> [u8; N] {
        debug_assert!(
            at <= buf.len() && N <= buf.len() - at,
            "read of {N} at {at} of {}",
            buf.len()
        );
        // SAFETY: the promise of `Unchecked::new`: the `N` bytes are in
        // `buf`. An unaligned read allows any address.
        unsafe { buf.as_ptr().add(at).cast::<[u8; N]>().read_unaligned() }
    }

    #[inline(always)]
    fn write<const N: usize>(self, buf: &mut [u8], at: usize, bytes: [u8; N]) {
        debug_assert!(
            at <= buf.len() && N <= buf.len() - at,
            "write of {N} at {at} of {}",
            buf.len()
        );
        // SAFETY: the promise of `Unchecked::new`: the `N` bytes are in
        // `buf`. An unaligned write allows any address.
        unsafe {
            buf.as_mut_ptr()
                .add(at)
                .cast::<[u8; N]>()
                .write_unaligned(bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    //! The reads and writes against slice indexing, everywhere in a buffer,
    //! under Miri too (see CI).

    use super::*;
    use crate::lz4::lz4::Checked;

    #[test]
    fn reads_and_writes_are_the_bytes_at_their_index() {
        // SAFETY: every piece below is in its buffer.
        let m = unsafe { Unchecked::new() };
        let mut buf: Vec<u8> = (0..100u8).collect();
        for at in 0..=buf.len() - 32 {
            assert_eq!(m.read::<1>(&buf, at), Checked.read::<1>(&buf, at));
            assert_eq!(m.read::<8>(&buf, at), Checked.read::<8>(&buf, at));
            assert_eq!(m.read::<32>(&buf, at), Checked.read::<32>(&buf, at));
        }
        let mut want = buf.clone();
        for at in (0..=buf.len() - 32).step_by(7) {
            Checked.write(&mut want, at, [!(at as u8); 32]);
            Checked.write(&mut want, at, [at as u8; 16]);
            m.write(&mut buf, at, [!(at as u8); 32]);
            m.write(&mut buf, at, [at as u8; 16]);
        }
        assert_eq!(buf, want);
    }
}
