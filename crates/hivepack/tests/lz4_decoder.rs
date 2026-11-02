//! `Decoder`, the reader of `.lz4` files: frames that liblz4 compressed one
//! after another, skippable frames between them, legacy frames, and what
//! ends a stream.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "lz4_support/mod.rs"]
mod support;

use std::io::{ErrorKind, Read};

use hivepack::lz4::{Decoder, LEGACY_BLOCKSIZE, LEGACY_MAGICNUMBER};
use support::{FrameSettings, Rng, c_compress_block, c_compress_frame, damage, input};

/// Reads all of `stream` through a `Decoder`, in reads of random sizes.
fn read_all(rng: &mut Rng, stream: &[u8]) -> (std::io::Result<Vec<u8>>, Vec<u8>) {
    let mut decoder = Decoder::new(stream);
    let mut out = Vec::new();
    let mut buf = vec![0; 1 << 20];
    loop {
        let size = rng.pick(&[1, 13, 4096, 65536, 1 << 20]);
        match decoder.read(&mut buf[..size]) {
            Ok(0) => return (Ok(out.clone()), out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return (Err(e), out),
        }
    }
}

fn skippable(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut frame = (0x184D_2A50u32 + rng.below(16) as u32)
        .to_le_bytes()
        .to_vec();
    frame.extend_from_slice(&(len as u32).to_le_bytes());
    frame.extend((0..len).map(|_| rng.next() as u8));
    frame
}

/// `data` in the legacy format, as `lz4 -l` writes it: blocks of 8 MB,
/// each compressed by liblz4.
fn legacy(data: &[u8], level: i32) -> Vec<u8> {
    let mut stream = LEGACY_MAGICNUMBER.to_le_bytes().to_vec();
    for block in data.chunks(LEGACY_BLOCKSIZE) {
        let compressed = c_compress_block(block, level);
        stream.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        stream.extend_from_slice(&compressed);
    }
    stream
}

#[test]
fn frames_one_after_another() {
    let mut rng = Rng(0x5eed_1220);
    for round in 0..40 {
        let mut stream = Vec::new();
        let mut want = Vec::new();
        for _ in 0..1 + rng.below(4) {
            let len = rng.pick(&[0, 10, 1000, 70_000, 300_000, 3_000_000]);
            let data = input(&mut rng, len);
            match rng.below(4) {
                0 => {
                    let len = rng.below(100) as usize;
                    stream.extend_from_slice(&skippable(&mut rng, len));
                }
                1 => {
                    stream.extend_from_slice(&legacy(&data, 0));
                    want.extend_from_slice(&data);
                }
                _ => {
                    let settings = FrameSettings::random(&mut rng);
                    stream.extend_from_slice(&c_compress_frame(&mut rng, &data, settings));
                    want.extend_from_slice(&data);
                }
            }
        }
        let (out, _) = read_all(&mut rng, &stream);
        let out = out.unwrap_or_else(|e| panic!("round {round}: {e}"));
        assert!(out == want, "round {round}");
    }
}

#[test]
fn legacy_blocks_of_8_mb() {
    let mut rng = Rng(0x5eed_1221);
    let data = input(&mut rng, 2 * LEGACY_BLOCKSIZE + 12_345);
    let mut stream = legacy(&data, 0);
    // A second legacy frame, then a frame: each magic number ends the frame
    // before it.
    stream.extend_from_slice(&legacy(&data[..1000], 9));
    let settings = FrameSettings::random(&mut rng);
    stream.extend_from_slice(&c_compress_frame(&mut rng, &data[..5000], settings));
    let (out, _) = read_all(&mut rng, &stream);
    let out = out.unwrap();
    assert_eq!(out.len(), data.len() + 6000);
    assert!(out[..data.len()] == data[..] && out[data.len()..data.len() + 1000] == data[..1000]);
}

#[test]
fn what_ends_a_stream() {
    let mut rng = Rng(0x5eed_1222);
    let data = input(&mut rng, 100_000);
    let settings = FrameSettings::random(&mut rng);
    let frame = c_compress_frame(&mut rng, &data, settings);

    // Empty: an empty stream, as `lz4 -d` decodes an empty file.
    assert_eq!(read_all(&mut rng, &[]).0.unwrap(), b"");

    // Not LZ4 data at the start, or a magic number cut short.
    for bad in [&b"hello, world"[..], b"\x04", b"\x04\x22\x4d"] {
        let error = read_all(&mut rng, bad).0.unwrap_err();
        assert!(
            matches!(
                error.kind(),
                ErrorKind::InvalidData | ErrorKind::UnexpectedEof
            ),
            "{bad:?}"
        );
    }

    // Anything after a frame is an error, once the frame is read.
    let mut followed = frame.clone();
    followed.extend_from_slice(b"trailing garbage");
    let (out, read) = read_all(&mut rng, &followed);
    assert_eq!(out.unwrap_err().kind(), ErrorKind::InvalidData);
    assert!(read == data);

    // A frame cut short anywhere is an error.
    for _ in 0..50 {
        let at = rng.below(frame.len() as u64 - 1) as usize + 1;
        let error = read_all(&mut rng, &frame[..at]).0.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof, "cut at {at}");
    }

    // A legacy frame cut short in a block.
    let stream = legacy(&data, 0);
    let error = read_all(&mut rng, &stream[..stream.len() - 1])
        .0
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnexpectedEof);

    // Damaged frames: an error or the data, never a panic.
    for _ in 0..200 {
        let damaged = damage(&mut rng, &frame);
        let _ = read_all(&mut rng, &damaged);
        let damaged = damage(&mut rng, &stream);
        let _ = read_all(&mut rng, &damaged);
    }
}
