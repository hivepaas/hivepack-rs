//! The block and frame compressors against liblz4 1.10.0 through the lz4
//! crate, on every machine CI tests: the same blocks and frames, byte for
//! byte; and frames made every way decompressed again.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "lz4_support/mod.rs"]
mod support;

use std::io::{Read, Write};
use std::sync::Arc;

use hivepack::lz4::frame::{
    self, BlockMode, BlockSizeId, CDict, CompressionContext, FrameInfo, Preferences,
};
use hivepack::lz4::{Decoder, Encoder, block};
use support::{Rng, c_compress_block, input};

#[test]
fn blocks_are_liblz4s() {
    let mut rng = Rng(0x5eed_1230);
    for round in 0..600 {
        let len = match round % 5 {
            0 => rng.below(40) as usize,
            1 => rng.below(2000) as usize,
            2 => 60_000 + rng.below(10_000) as usize,
            3 => rng.below(300_000) as usize,
            _ => rng.below(3_000_000) as usize,
        };
        let data = input(&mut rng, len);
        // 0 is LZ4_compress_default; negative values are accelerations.
        let level = match rng.below(3) {
            0 => 0,
            1 => -(1 + rng.below(10) as i32),
            _ => -(1 + rng.below(70_000) as i32),
        };
        let want = c_compress_block(&data, level);
        let mut got = vec![0; block::compress_bound(len)];
        let n = block::compress_fast(&data, &mut got, if level == 0 { 1 } else { -level });
        assert_eq!(n, want.len(), "round {round}, {len} bytes, level {level}");
        assert!(
            got[..n] == want[..],
            "round {round}, {len} bytes, level {level}"
        );

        let mut back = vec![0; len];
        assert_eq!(block::decompress_safe(&got[..n], &mut back), Ok(len));
        assert!(back == data);
    }
}

#[test]
fn hc_blocks_are_liblz4s() {
    let mut rng = Rng(0x5eed_1231);
    for round in 0..260 {
        let len = match round % 5 {
            0 => rng.below(40) as usize,
            1 => rng.below(2000) as usize,
            2 => 60_000 + rng.below(10_000) as usize,
            3 => rng.below(200_000) as usize,
            _ => rng.below(700_000) as usize,
        };
        let data = input(&mut rng, len);
        let level = rng.pick(&[1, 2, 2, 3, 4, 6, 9, 9, 10, 11, 12, 13]);
        let want = c_compress_block(&data, level);
        let mut got = vec![0; block::compress_bound(len)];
        let n = hivepack::lz4::hc::compress_hc(&data, &mut got, level);
        assert_eq!(n, want.len(), "round {round}, {len} bytes, level {level}");
        assert!(
            got[..n] == want[..],
            "round {round}, {len} bytes, level {level}"
        );

        let mut back = vec![0; len];
        assert_eq!(block::decompress_safe(&got[..n], &mut back), Ok(len));
        assert!(back == data);
    }
}

/// Random preferences the lz4 crate can give liblz4 (no negative levels, no
/// dictionary ID), and the same for the port.
fn frame_prefs(rng: &mut Rng, len: usize) -> (lz4::EncoderBuilder, Preferences) {
    let id = rng.pick(&[0u32, 4, 4, 5, 6, 7]);
    let independent = rng.below(3) == 0;
    let block_checksum = rng.below(3) == 0;
    let content_checksum = rng.below(2) == 0;
    let content_size = if rng.below(3) == 0 { len as u64 } else { 0 };
    let level = rng.pick(&[0u32, 0, 1, 2, 3, 6, 9, 10, 11, 12, 16]);
    let auto_flush = rng.below(3) == 0;
    let favor_dec_speed = rng.below(4) == 0;
    let mut builder = lz4::EncoderBuilder::new();
    builder
        .block_size(match id {
            4 => lz4::BlockSize::Max64KB,
            5 => lz4::BlockSize::Max256KB,
            6 => lz4::BlockSize::Max1MB,
            7 => lz4::BlockSize::Max4MB,
            _ => lz4::BlockSize::Default,
        })
        .block_mode(if independent {
            lz4::BlockMode::Independent
        } else {
            lz4::BlockMode::Linked
        })
        .block_checksum(if block_checksum {
            lz4::liblz4::BlockChecksum::BlockChecksumEnabled
        } else {
            lz4::liblz4::BlockChecksum::NoBlockChecksum
        })
        .checksum(if content_checksum {
            lz4::ContentChecksum::ChecksumEnabled
        } else {
            lz4::ContentChecksum::NoChecksum
        })
        .content_size(content_size)
        .level(level)
        .auto_flush(auto_flush)
        .favor_dec_speed(favor_dec_speed);
    let prefs = Preferences {
        frame_info: FrameInfo {
            block_size_id: match id {
                4 => BlockSizeId::Max64Kb,
                5 => BlockSizeId::Max256Kb,
                6 => BlockSizeId::Max1Mb,
                7 => BlockSizeId::Max4Mb,
                _ => BlockSizeId::Default,
            },
            block_mode: if independent {
                BlockMode::Independent
            } else {
                BlockMode::Linked
            },
            content_checksum,
            content_size,
            block_checksum,
            ..FrameInfo::default()
        },
        compression_level: level as i32,
        auto_flush,
        favor_dec_speed,
    };
    (builder, prefs)
}

#[test]
fn frames_are_liblz4s() {
    let mut rng = Rng(0x5eed_1232);
    for round in 0..160 {
        let len = match round % 4 {
            0 => rng.below(2000) as usize,
            1 => rng.below(100_000) as usize,
            2 => rng.below(400_000) as usize,
            _ => rng.below(1_500_000) as usize,
        };
        let data = input(&mut rng, len);
        let (builder, prefs) = frame_prefs(&mut rng, len);
        // The same writes and flushes, in pieces of every size.
        let mut c = builder.build(Vec::new()).expect("an encoder");
        let mut port = Encoder::new(Vec::new(), Some(&prefs)).unwrap();
        let mut at = 0;
        while at < len {
            let piece = match rng.below(4) {
                0 => 1 + rng.below(100) as usize,
                1 => 1 + rng.below(70_000) as usize,
                _ => 1 + rng.below(300_000) as usize,
            }
            .min(len - at);
            c.write_all(&data[at..at + piece]).unwrap();
            port.write_all(&data[at..at + piece]).unwrap();
            if rng.below(6) == 0 {
                c.flush().unwrap();
                port.flush().unwrap();
            }
            at += piece;
        }
        let (want, ret) = c.finish();
        ret.unwrap();
        let got = port.finish().unwrap();
        assert_eq!(
            got.len(),
            want.len(),
            "round {round}, {len} bytes, {prefs:?}"
        );
        assert!(got == want, "round {round}, {len} bytes, {prefs:?}");

        let mut back = Vec::new();
        Decoder::new(&got[..]).read_to_end(&mut back).unwrap();
        assert!(back == data, "round {round}");
    }
}

#[test]
fn frames_decompress_to_their_input() {
    let mut rng = Rng(0x5eed_1233);
    for round in 0..120 {
        let len = rng.below(300_000) as usize;
        let data = input(&mut rng, len);
        let (_, mut prefs) = frame_prefs(&mut rng, len);
        prefs.compression_level = rng.pick(&[-1, -9, -70_000, 0, 2, 9, 12]);
        prefs.frame_info.dict_id = rng.next() as u32;

        // In one call.
        let mut frame = vec![0; frame::compress_frame_bound(len, Some(&prefs))];
        let n = frame::compress_frame(&mut frame, &data, Some(&prefs)).unwrap();
        let mut back = Vec::new();
        Decoder::new(&frame[..n]).read_to_end(&mut back).unwrap();
        assert!(back == data, "round {round}, {prefs:?}");
        // liblz4 reads them too.
        let mut back = Vec::new();
        lz4::Decoder::new(&frame[..n])
            .unwrap()
            .read_to_end(&mut back)
            .unwrap();
        assert!(back == data, "round {round}, {prefs:?}");

        // With a dictionary, loaded or digested, call by call, some of the
        // input stored as it is when the blocks are independent.
        let dict_len = rng.below(100_000) as usize;
        let dict = input(&mut rng, dict_len);
        let cdict = Arc::new(CDict::new(&dict));
        let use_cdict = rng.below(2) == 0;
        let mut cctx = CompressionContext::new();
        let mut out = vec![0; frame::HEADER_SIZE_MAX];
        let n = if use_cdict {
            cctx.compress_begin_using_cdict(&mut out, &cdict, Some(&prefs))
        } else {
            cctx.compress_begin_using_dict(&mut out, &dict, Some(&prefs))
        }
        .unwrap();
        out.truncate(n);
        let independent = prefs.frame_info.block_mode == BlockMode::Independent;
        let mut at = 0;
        while at < len {
            let piece = (1 + rng.below(100_000) as usize).min(len - at);
            let mut dst = vec![0; frame::compress_bound(piece, Some(&prefs)) + (64 << 10) + 8];
            let n = if independent && rng.below(4) == 0 {
                cctx.uncompressed_update(&mut dst, &data[at..at + piece])
            } else {
                cctx.compress_update(&mut dst, &data[at..at + piece])
            }
            .unwrap();
            out.extend_from_slice(&dst[..n]);
            at += piece;
        }
        let mut dst = vec![0; frame::compress_bound(0, Some(&prefs))];
        let n = cctx.compress_end(&mut dst).unwrap();
        out.extend_from_slice(&dst[..n]);

        let mut dctx = frame::DecompressionContext::new();
        let mut back = vec![0; len + 1];
        let (mut src_pos, mut dst_pos) = (0, 0);
        loop {
            let mut input = frame::InBuffer::new(&out[src_pos..]);
            let mut output = frame::OutBuffer::new(&mut back[dst_pos..]);
            let hint = dctx
                .decompress_using_dict(&mut output, &mut input, &dict, Default::default())
                .unwrap();
            src_pos += input.pos;
            dst_pos += output.pos;
            if hint == 0 {
                break;
            }
        }
        assert_eq!(dst_pos, len, "round {round}, {prefs:?}");
        assert!(back[..len] == data[..], "round {round}, {prefs:?}");
    }
}
