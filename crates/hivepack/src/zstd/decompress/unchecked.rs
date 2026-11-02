//! The few raw reads and writes behind the `unsafe-fast` feature: 16 and 32
//! bytes at a time, without a bounds check. They are used only by the
//! fast path of the main sequence loop in `zstd_decompress_block.rs`,
//! through the `Mode` [`Unchecked`]. Making one is `unsafe`; the loop does
//! it once, after checking its buffers, and its `SAFETY` comment shows the
//! fast path's copies in bounds. That block and this module are the crate's
//! only `unsafe` code. See `docs/unsafe.md`.

#![allow(unsafe_code)]

use super::zstd_decompress_block::{Mode, Source};

/// Pieces read and written without bounds checks: the `Mode` of the main
/// sequence loop's fast path when the feature is on.
///
/// Only `Unchecked::new` makes one, and it is `unsafe`, so safe code holding
/// a `Mode` can never reach these accesses by itself.
#[derive(Clone, Copy)]
pub(crate) struct Unchecked(());

impl Unchecked {
    /// # Safety
    ///
    /// Every piece the returned mode reads or writes must be in its buffer:
    /// for `read16(src, out, at)`, `at + 16 <= src.slice(out).len()`; for
    /// `read32(out, at)`, `at + 32 <= out.len()`; for `write16` and
    /// `write32`, `at + 16` and `at + 32 <= out.len()`.
    #[inline(always)]
    pub(crate) unsafe fn new() -> Self {
        Unchecked(())
    }
}

impl Mode for Unchecked {
    #[inline(always)]
    fn read16<S: Source>(self, src: S, out: &[u8], at: usize) -> [u8; 16] {
        // SAFETY: the promise of `Unchecked::new`.
        unsafe { read16(src.slice(out), at) }
    }

    #[inline(always)]
    fn read32(self, out: &[u8], at: usize) -> [u8; 32] {
        // SAFETY: the promise of `Unchecked::new`.
        unsafe { read32(out, at) }
    }

    #[inline(always)]
    fn write16(self, out: &mut [u8], at: usize, piece: [u8; 16]) {
        // SAFETY: the promise of `Unchecked::new`.
        unsafe { write16(out, at, piece) }
    }

    #[inline(always)]
    fn write32(self, out: &mut [u8], at: usize, piece: [u8; 32]) {
        // SAFETY: the promise of `Unchecked::new`.
        unsafe { write32(out, at, piece) }
    }
}

/// 16 bytes of `buf` from `at`.
///
/// # Safety
///
/// `at + 16 <= buf.len()`.
#[inline(always)]
pub(crate) unsafe fn read16(buf: &[u8], at: usize) -> [u8; 16] {
    // SAFETY: the caller guarantees the 16 bytes are in `buf`; an unaligned
    // read allows any address.
    unsafe { buf.as_ptr().add(at).cast::<[u8; 16]>().read_unaligned() }
}

/// 32 bytes of `buf` from `at`.
///
/// # Safety
///
/// `at + 32 <= buf.len()`.
#[inline(always)]
pub(crate) unsafe fn read32(buf: &[u8], at: usize) -> [u8; 32] {
    // SAFETY: as in `read16`.
    unsafe { buf.as_ptr().add(at).cast::<[u8; 32]>().read_unaligned() }
}

/// Writes `bytes` to `buf` at `at`.
///
/// # Safety
///
/// `at + 16 <= buf.len()`.
#[inline(always)]
pub(crate) unsafe fn write16(buf: &mut [u8], at: usize, bytes: [u8; 16]) {
    // SAFETY: the caller guarantees the 16 bytes are in `buf`; an unaligned
    // write allows any address.
    unsafe {
        buf.as_mut_ptr()
            .add(at)
            .cast::<[u8; 16]>()
            .write_unaligned(bytes)
    }
}

/// Writes `bytes` to `buf` at `at`.
///
/// # Safety
///
/// `at + 32 <= buf.len()`.
#[inline(always)]
pub(crate) unsafe fn write32(buf: &mut [u8], at: usize, bytes: [u8; 32]) {
    // SAFETY: as in `write16`.
    unsafe {
        buf.as_mut_ptr()
            .add(at)
            .cast::<[u8; 32]>()
            .write_unaligned(bytes)
    }
}

#[cfg(test)]
mod tests {
    //! The reads and writes against slice indexing, everywhere in a buffer,
    //! under Miri too (see CI).

    use super::*;

    #[test]
    fn reads_and_writes_are_the_bytes_at_their_index() {
        let mut buf: Vec<u8> = (0..100u8).collect();
        for at in 0..=buf.len() - 32 {
            // SAFETY: `at + 32 <= buf.len()`.
            let (r16, r32) = unsafe { (read16(&buf, at), read32(&buf, at)) };
            assert_eq!(r16[..], buf[at..at + 16]);
            assert_eq!(r32[..], buf[at..at + 32]);
        }
        let mut want = buf.clone();
        for at in (0..=buf.len() - 32).step_by(7) {
            let bytes16 = [at as u8; 16];
            let bytes32 = [!(at as u8); 32];
            want[at..at + 32].copy_from_slice(&bytes32);
            want[at..at + 16].copy_from_slice(&bytes16);
            // SAFETY: `at + 32 <= buf.len()`.
            unsafe {
                write32(&mut buf, at, bytes32);
                write16(&mut buf, at, bytes16);
            }
            assert_eq!(buf, want);
        }
    }
}
