//! CRC-32 with the processor's instructions, the `unsafe-fast` feature of
//! hivepack::deflate, and xz's CRC32 and CRC64 folded, that of hivepack::xz,
//! against the code without them: a difference is a bug, and the sanitizer
//! takes any read or write out of bounds.
//!
//! Without the feature both sides are the safe code. Run it with
//! `--features unsafe-fast`.
//!
//! The first eight bytes are where it starts from (the first four for
//! CRC-32), and the rest is the data.

#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (start, data) = data.split_at(data.len().min(8));
    let mut bytes = [0; 8];
    bytes[..start.len()].copy_from_slice(start);
    let start = u64::from_le_bytes(bytes);
    assert_eq!(
        hivepack::deflate::crc32(start as u32, data),
        hivepack::deflate::fuzz_crc32_braided(start as u32, data)
    );
    let ((crc32, sliced32), (crc64, sliced64)) = hivepack::xz::fuzz_crcs(data, start);
    assert_eq!(crc32, sliced32);
    assert_eq!(crc64, sliced64);
});
