//! Comparison with liblz4 1.10.0 through the lz4 crate, on every machine CI
//! tests (Windows, 32-bit and big-endian ones included, where the oracle
//! of `tests/oracle.rs` is not built): blocks and frames that liblz4
//! compressed, decoded by the port whole and in pieces, and damaged ones
//! decoded by both.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "lz4_support/mod.rs"]
mod support;

use std::io::Read;

use hivepack::lz4::block;
use hivepack::lz4::frame::{DecompressOptions, DecompressionContext, InBuffer, OutBuffer};
use support::{FrameSettings, Rng, c_compress_block, c_compress_frame, damage, input};

/// A frame decoded by the port, with the input and output in pieces of at
/// most `in_piece` and `out_piece` bytes, until the frame ends.
fn port_decode_frame(frame: &[u8], in_piece: usize, out_piece: usize) -> Result<Vec<u8>, String> {
    let mut dctx = DecompressionContext::new();
    let mut out = Vec::new();
    let mut at = 0;
    let mut buffer = vec![0; out_piece];
    loop {
        let end = (at + in_piece).min(frame.len());
        let mut input = InBuffer::new(&frame[at..end]);
        let mut output = OutBuffer::new(&mut buffer);
        let hint = dctx
            .decompress(&mut output, &mut input, DecompressOptions::default())
            .map_err(|e| e.name().to_string())?;
        let (read, written) = (input.pos, output.pos);
        out.extend_from_slice(&buffer[..written]);
        at += read;
        if hint == 0 {
            return Ok(out);
        }
        if read == 0 && written == 0 && at == frame.len() {
            return Err("cut short".into());
        }
    }
}

/// A frame decoded by liblz4, through the lz4 crate.
fn c_decode_frame(frame: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = lz4::Decoder::new(frame).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

#[test]
fn blocks_liblz4_compressed_decode() {
    let mut rng = Rng(0x5eed_1214);
    for round in 0..300 {
        let len = match round % 4 {
            0 => rng.below(100) as usize,
            1 => rng.below(10_000) as usize,
            2 => rng.below(300_000) as usize,
            _ => rng.below(2_000_000) as usize,
        };
        let data = input(&mut rng, len);
        let level = match rng.below(4) {
            0 => -(1 + rng.below(70) as i32),
            1 => 0,
            _ => 1 + rng.below(12) as i32,
        };
        let compressed = c_compress_block(&data, level);
        let mut out = vec![0; len];
        assert_eq!(
            block::decompress_safe(&compressed, &mut out),
            Ok(len),
            "round {round}, level {level}"
        );
        assert!(out == data, "round {round}, level {level}");

        // Partially, up to a random target.
        let target = rng.below(len as u64 + 1) as usize;
        let mut part = vec![0; len];
        let got = block::decompress_safe_partial(&compressed, &mut part, target).unwrap();
        assert!(got <= len && part[..got] == data[..got], "round {round}");

        // Damaged: liblz4 and the port agree on whether it decodes, and
        // on what.
        let damaged = damage(&mut rng, &compressed);
        let mut port = vec![0; len];
        let port_result = block::decompress_safe(&damaged, &mut port);
        let c_result = lz4::block::decompress(&damaged, Some(len as i32));
        match (port_result, c_result) {
            (Ok(n), Ok(c)) => assert!(port[..n] == c[..], "round {round}"),
            (Err(_), Err(_)) => {}
            (port, c) => panic!(
                "round {round}: port {port:?}, liblz4 {:?}",
                c.map(|c| c.len())
            ),
        }
    }
}

#[test]
fn frames_liblz4_compressed_decode() {
    let mut rng = Rng(0x5eed_1215);
    for round in 0..200 {
        let len = match round % 4 {
            0 => rng.below(100) as usize,
            1 => rng.below(100_000) as usize,
            2 => rng.below(1_000_000) as usize,
            _ => rng.below(6_000_000) as usize,
        };
        let data = input(&mut rng, len);
        let settings = FrameSettings::random(&mut rng);
        let frame = c_compress_frame(&mut rng, &data, settings);
        let in_piece = rng.pick(&[1, 7, 100, 65536, usize::MAX / 2]);
        let out_piece = rng.pick(&[1, 100, 65536, 4 << 20, 5 << 20]);
        let out = port_decode_frame(&frame, in_piece, out_piece)
            .unwrap_or_else(|e| panic!("round {round}, {settings:?}: {e}"));
        assert!(out == data, "round {round}, {settings:?}");

        let damaged = damage(&mut rng, &frame);
        let port = port_decode_frame(&damaged, usize::MAX / 2, 5 << 20);
        let c = c_decode_frame(&damaged);
        // The lz4 crate reads past a frame's end as more frames, and stops
        // at a cut-short frame without an error: only the frames both
        // decode are compared.
        if let (Ok(port), Ok(c)) = (&port, &c) {
            assert!(c.starts_with(port) || port.starts_with(c), "round {round}");
        }
        if port.is_ok() && damaged.len() == frame.len() && c.is_err() {
            panic!("round {round}: the port decoded a frame liblz4 refused: {c:?}");
        }
    }
}
