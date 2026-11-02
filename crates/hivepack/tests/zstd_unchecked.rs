//! The `unsafe-fast` feature on the frames committed to the repository,
//! valid and damaged, in one call and streamed in small pieces. It needs no
//! libzstd, so CI runs it under Miri, which catches any access outside the
//! buffers; without Miri, the other tests run with the feature too.

#![cfg(feature = "zstd-unsafe-fast")]
#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::Path;

use hivepack::zstd::{DCtx, InBuffer, OutBuffer};

/// The `.zst` files of a committed set, each with what it decodes to, if
/// the set has it.
fn frames(set: &str) -> Vec<(String, Vec<u8>, Option<Vec<u8>>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(set);
    let mut frames = Vec::new();
    for entry in fs::read_dir(&dir).expect("set readable") {
        let path = entry.expect("set readable").path();
        if path.extension().is_some_and(|e| e == "zst") {
            let frame = fs::read(&path).expect("frame readable");
            let original = fs::read(path.with_extension("")).ok();
            frames.push((path.display().to_string(), frame, original));
        }
    }
    frames.sort();
    assert!(!frames.is_empty(), "no frames in {}", dir.display());
    frames
}

/// Streams `frame` in pieces of `piece` bytes in and out; the output, or
/// `None` on an error.
fn stream(frame: &[u8], piece: usize) -> Option<Vec<u8>> {
    let mut dctx = DCtx::new();
    let mut decoded = Vec::new();
    let mut out = vec![0; piece];
    let mut pos = 0;
    loop {
        let end = (pos + piece).min(frame.len());
        let mut input = InBuffer::new(&frame[pos..end]);
        let mut output = OutBuffer::new(&mut out);
        let hint = dctx.decompress_stream(&mut output, &mut input).ok()?;
        let written = output.pos;
        decoded.extend_from_slice(&out[..written]);
        pos += input.pos;
        if hint == 0 && pos == frame.len() {
            return Some(decoded);
        }
        if input.pos == 0 && written == 0 && pos == frame.len() {
            // The input ends inside a frame.
            return None;
        }
    }
}

#[test]
fn unchecked_decodes_the_committed_frames() {
    for set in ["aircompressor", "klauspost/good", "klauspost/bad"] {
        for (name, frame, original) in frames(set) {
            let mut out = vec![0; original.as_ref().map_or(1 << 16, Vec::len)];
            let decoded = hivepack::zstd::decompress(&mut out, &frame).map(|n| out[..n].to_vec());
            let streamed = stream(&frame, 1000);
            // The other tests compare the errors with libzstd's; here they
            // only have to be errors rather than accesses out of bounds.
            if let Some(original) = &original {
                assert_eq!(decoded.as_ref().ok(), Some(original), "{name}");
                assert_eq!(streamed.as_ref(), Some(original), "{name}, streamed");
            }
        }
    }
}
