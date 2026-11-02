//! CRC-32 with the processor's instructions, the `unsafe-fast` feature of
//! hivepack-deflate, against the safe code: a difference is a bug, and the
//! sanitizer takes any read or write out of bounds.
//!
//! Without the feature both sides are the safe code. Run it with
//! `--features unsafe-fast`.
//!
//! The first four bytes are where it starts from, and the rest is the data.

#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (start, data) = data.split_at(data.len().min(4));
    let mut bytes = [0; 4];
    bytes[..start.len()].copy_from_slice(start);
    let start = u32::from_le_bytes(bytes);
    assert_eq!(
        hivepack_deflate::crc32(start, data),
        hivepack_deflate::fuzz_crc32_braided(start, data)
    );
});
