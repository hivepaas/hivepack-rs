//! Little-endian reads: port of the parts of `common/mem.h` the port needs.
//!
//! Differs from libzstd: these read from a slice at an index instead of
//! through a pointer, so a read past the end is a bounds-check panic instead
//! of undefined behaviour. Callers keep the same guarantees as in C, which
//! makes the panic unreachable.

/// `at`, as an index no slice can reach past: no slice is longer than
/// `isize::MAX`, so this changes no index that could be valid, and lets the
/// compiler see that `at + N` does not overflow, which saves a check.
#[inline(always)]
pub(crate) const fn idx(at: usize) -> usize {
    at & (isize::MAX as usize)
}

/// `MEM_readLE16`
#[inline(always)]
pub(crate) fn read_le16(src: &[u8], at: usize) -> u16 {
    let bytes: [u8; 2] = [src[at], src[at + 1]];
    u16::from_le_bytes(bytes)
}

/// `MEM_readLE32`
#[inline(always)]
pub(crate) fn read_le32(src: &[u8], at: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&src[at..at + 4]);
    u32::from_le_bytes(bytes)
}

/// `MEM_readLE64`, which is also `MEM_readLEST` on 64-bit machines.
#[inline(always)]
pub(crate) fn read_le64(src: &[u8], at: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&src[at..at + 8]);
    u64::from_le_bytes(bytes)
}

/// `MEM_readLE24`
#[inline(always)]
pub(crate) fn read_le24(src: &[u8], at: usize) -> u32 {
    u32::from(read_le16(src, at)) + (u32::from(src[at + 2]) << 16)
}

/// `MEM_writeLE16`
#[inline(always)]
pub(crate) fn write_le16(dst: &mut [u8], at: usize, value: u16) {
    dst[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

/// `MEM_writeLE32`
#[inline(always)]
pub(crate) fn write_le32(dst: &mut [u8], at: usize, value: u32) {
    dst[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// `MEM_writeLE64`, which is also `MEM_writeLEST` on 64-bit machines.
#[inline(always)]
pub(crate) fn write_le64(dst: &mut [u8], at: usize, value: u64) {
    let at = idx(at);
    dst[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
