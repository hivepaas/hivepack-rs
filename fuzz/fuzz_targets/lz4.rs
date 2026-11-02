//! hivepack::lz4 against liblz4. A panic or a difference is a bug.
//!
//! The first byte chooses what is done with the rest, after eight bytes
//! that seed the sizes:
//!
//! - 0 mod 8: the rest is a block, decoded by both with
//!   `LZ4_decompress_safe` into an output of a size from the seed, first
//!   filled the same way. Both must succeed or fail together, with the same
//!   size, and leave the same bytes in all of the output, past what they
//!   decoded too.
//! - 1 mod 8: the rest is a frame, read by the lz4 crate's `Decoder` and by
//!   the same loop over the port's context, in reads of sizes from the
//!   seed. Every read must agree: the same bytes, or both an error.
//! - 2 mod 8: the rest is a block, decoded by the port partially, with a
//!   dictionary, after a prefix, or in a stream, which the lz4 crate cannot
//!   do: no panic (`tests/oracle.rs` compares them with liblz4).
//! - 3 mod 8: the rest is read by the port's `Decoder`, in reads of sizes
//!   from the seed: no panic.
//! - 4 mod 8: the rest is compressed into a block by both, fast or high
//!   compression at a level from the seed: the same block, which
//!   decompresses to the rest.
//! - 5 mod 8: the rest is compressed into a frame by both, the lz4 crate's
//!   `Encoder` and the port's, with preferences, writes and flushes from
//!   the seed: the same frame, which decompresses to the rest.
//! - 6 mod 8: the rest is compressed by the port into blocks and frames
//!   the lz4 crate cannot make: with dictionaries, digested or not,
//!   negative levels, stored blocks, outputs too small, as much as fits.
//!   No panic, and what is made decompresses to what was given
//!   (`tests/oracle.rs` compares them with liblz4).
//!
//! (0 to 3 are taken mod 4 as well, for the corpus of mode bytes 0 to 3.)

#![no_main]

use std::io::{Read, Write};
use std::sync::Arc;

use hivepack::lz4::block;
use hivepack::lz4::frame::{
    self, BlockMode, BlockSizeId, CDict, CompressionContext, DecompressOptions,
    DecompressionContext, FrameInfo, InBuffer, OutBuffer, Preferences,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let Some((seed, data)) = rest.split_first_chunk::<8>() else { return };
    let mut rng = u64::from_le_bytes(*seed) | 1;
    let mut next = move |n: usize| {
        rng ^= rng >> 12;
        rng ^= rng << 25;
        rng ^= rng >> 27;
        (rng.wrapping_mul(0x2545_f491_4f6c_dd1d) % n as u64) as usize
    };
    match mode % 8 {
        0 => block_safe(data, &mut next),
        1 => frame(data, &mut next),
        2 => block_other(data, &mut next),
        3 | 7 => reader(data, &mut next),
        4 => compress_block(data, &mut next),
        5 => compress_frame(data, &mut next),
        _ => compress_other(data, &mut next),
    }
});

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 7 + 3) & 255) as u8).collect()
}

fn output_size(next: &mut impl FnMut(usize) -> usize, len: usize) -> usize {
    match next(4) {
        0 => next(100),
        1 => next(len * 4 + 100),
        2 => len * 255,
        _ => next(1 << 20),
    }
    .min(4 << 20)
}

fn block_safe(src: &[u8], next: &mut impl FnMut(usize) -> usize) {
    let capacity = output_size(next, src.len());
    let mut c_out = pattern(capacity);
    let mut p_out = pattern(capacity);
    let want = lz4::block::decompress_to_buffer(src, Some(capacity as i32), &mut c_out).ok();
    let got = block::decompress_safe(src, &mut p_out).ok();
    assert_eq!(got, want, "result");
    assert!(p_out == c_out, "output");
}

fn block_other(src: &[u8], next: &mut impl FnMut(usize) -> usize) {
    let capacity = output_size(next, src.len());
    let dict_len = [0, 1, 100, 65535, 65536, 70_000][next(6)];
    let dict: Vec<u8> = (0..dict_len).map(|i| (i % 251) as u8).collect();
    let target = next(capacity + 1);

    let mut out = vec![0; capacity];
    let _ = block::decompress_safe_using_dict(src, &mut out, &dict);
    let _ = block::decompress_safe_partial_using_dict(src, &mut out, target, &dict);
    let _ = block::decompress_safe_partial(src, &mut out, target);
    let mut buffer = dict.clone();
    buffer.resize(dict_len + capacity, 0);
    let _ = block::decompress_safe_with_prefix(src, &mut buffer, dict_len);
    let _ = block::decompress_safe_partial_with_prefix(src, &mut buffer, dict_len, target);

    // The same block, again and again, in a stream.
    let mut stream = block::StreamDecode::new();
    stream.set_dict(&dict);
    for _ in 0..1 + next(4) {
        let _ = stream.decompress_safe_continue(src, &mut out);
    }
}

/// The lz4 crate's `Decoder::read`, over the port's context: the same
/// calls, so that each read can be compared.
struct PortDecoder<'a> {
    dctx: DecompressionContext,
    src: &'a [u8],
    at: usize,
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    next: usize,
}

impl PortDecoder<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        if self.next == 0 || buf.is_empty() {
            return Ok(0);
        }
        let mut dst_offset = 0;
        while dst_offset == 0 {
            if self.pos >= self.len {
                let need = self.buf.len().min(self.next);
                let n = need.min(self.src.len() - self.at);
                self.buf[..n].copy_from_slice(&self.src[self.at..self.at + n]);
                self.at += n;
                self.len = n;
                self.pos = 0;
                self.next -= self.len;
            }
            while dst_offset < buf.len() && (self.pos < self.len || self.len == 0) {
                let mut input = InBuffer::new(&self.buf[self.pos..self.len]);
                let mut output = OutBuffer::new(&mut buf[dst_offset..]);
                let len = self
                    .dctx
                    .decompress(&mut output, &mut input, DecompressOptions::default())
                    .map_err(|_| ())?;
                self.pos += input.pos;
                dst_offset += output.pos;
                if output.pos == 0 && input.pos == 0 {
                    return Ok(dst_offset);
                }
                if len == 0 {
                    self.next = 0;
                    return Ok(dst_offset);
                } else if self.next < len {
                    self.next = len;
                }
            }
        }
        Ok(dst_offset)
    }
}

fn frame(src: &[u8], next: &mut impl FnMut(usize) -> usize) {
    let Ok(mut c) = lz4::Decoder::new(src) else { return };
    let mut port = PortDecoder {
        dctx: DecompressionContext::new(),
        src,
        at: 0,
        buf: vec![0; 32 * 1024],
        pos: 32 * 1024,
        len: 32 * 1024,
        next: 11,
    };
    let mut c_buf = vec![0; 1 << 20];
    let mut p_buf = vec![0; 1 << 20];
    for _ in 0..10_000 {
        let size = [1, 7, 100, 4096, 65536, 1 << 20][next(6)];
        let want = c.read(&mut c_buf[..size]);
        let got = port.read(&mut p_buf[..size]);
        match (want, got) {
            (Ok(c_n), Ok(p_n)) => {
                assert_eq!(p_n, c_n, "read size");
                assert!(p_buf[..p_n] == c_buf[..c_n], "read bytes");
                if c_n == 0 {
                    return;
                }
            }
            (Err(_), Err(())) => return,
            (want, got) => panic!("liblz4 {want:?}, port {got:?}"),
        }
    }
}

fn reader(src: &[u8], next: &mut impl FnMut(usize) -> usize) {
    let mut decoder = hivepack::lz4::Decoder::new(src);
    let mut buf = vec![0; 1 << 16];
    for _ in 0..100_000 {
        let size = 1 + next(buf.len());
        match decoder.read(&mut buf[..size]) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

fn compress_block(src: &[u8], next: &mut impl FnMut(usize) -> usize) {
    let mode = match next(4) {
        0 => lz4::block::CompressionMode::DEFAULT,
        1 => lz4::block::CompressionMode::FAST(1 + next(70_000) as i32),
        _ => lz4::block::CompressionMode::HIGHCOMPRESSION(1 + next(13) as i32),
    };
    let want = lz4::block::compress(src, Some(mode), false).expect("liblz4 compresses");
    let mut got = vec![0; block::compress_bound(src.len())];
    let n = match mode {
        lz4::block::CompressionMode::DEFAULT => block::compress_default(src, &mut got),
        lz4::block::CompressionMode::FAST(accel) => block::compress_fast(src, &mut got, accel),
        lz4::block::CompressionMode::HIGHCOMPRESSION(level) => {
            hivepack::lz4::hc::compress_hc(src, &mut got, level)
        }
    };
    assert!(got[..n] == want[..], "block");
    let mut back = vec![0; src.len()];
    assert_eq!(block::decompress_safe(&got[..n], &mut back), Ok(src.len()));
    assert!(back == src, "decompressed");
}

fn random_prefs(next: &mut impl FnMut(usize) -> usize, len: usize) -> Preferences {
    Preferences {
        frame_info: FrameInfo {
            block_size_id: [
                BlockSizeId::Default,
                BlockSizeId::Max64Kb,
                BlockSizeId::Max256Kb,
                BlockSizeId::Max1Mb,
                BlockSizeId::Max4Mb,
            ][next(5)],
            block_mode: if next(2) == 0 {
                BlockMode::Linked
            } else {
                BlockMode::Independent
            },
            content_checksum: next(2) == 0,
            block_checksum: next(2) == 0,
            content_size: if next(3) == 0 { len as u64 } else { 0 },
            ..FrameInfo::default()
        },
        compression_level: next(14) as i32,
        auto_flush: next(2) == 0,
        favor_dec_speed: next(2) == 0,
    }
}

fn decompress_frame(frame: &[u8], dict: &[u8]) -> Vec<u8> {
    let mut dctx = DecompressionContext::new();
    let mut out = vec![0; 1 << 16];
    let mut back = Vec::new();
    let mut at = 0;
    loop {
        let mut input = InBuffer::new(&frame[at..]);
        let mut output = OutBuffer::new(&mut out);
        let hint = dctx
            .decompress_using_dict(&mut output, &mut input, dict, DecompressOptions::default())
            .expect("the frame decompresses");
        let (read, written) = (input.pos, output.pos);
        at += read;
        back.extend_from_slice(&out[..written]);
        if hint == 0 {
            return back;
        }
        assert!(read > 0 || written > 0, "the frame decompresses");
    }
}

fn compress_frame(src: &[u8], next: &mut impl FnMut(usize) -> usize) {
    let prefs = random_prefs(next, src.len());
    let fi = &prefs.frame_info;
    let mut builder = lz4::EncoderBuilder::new();
    builder
        .block_size(match fi.block_size_id {
            BlockSizeId::Max64Kb => lz4::BlockSize::Max64KB,
            BlockSizeId::Max256Kb => lz4::BlockSize::Max256KB,
            BlockSizeId::Max1Mb => lz4::BlockSize::Max1MB,
            BlockSizeId::Max4Mb => lz4::BlockSize::Max4MB,
            BlockSizeId::Default => lz4::BlockSize::Default,
        })
        .block_mode(match fi.block_mode {
            BlockMode::Linked => lz4::BlockMode::Linked,
            BlockMode::Independent => lz4::BlockMode::Independent,
        })
        .block_checksum(if fi.block_checksum {
            lz4::liblz4::BlockChecksum::BlockChecksumEnabled
        } else {
            lz4::liblz4::BlockChecksum::NoBlockChecksum
        })
        .checksum(if fi.content_checksum {
            lz4::ContentChecksum::ChecksumEnabled
        } else {
            lz4::ContentChecksum::NoChecksum
        })
        .content_size(fi.content_size)
        .level(prefs.compression_level as u32)
        .auto_flush(prefs.auto_flush)
        .favor_dec_speed(prefs.favor_dec_speed);
    let mut c = builder.build(Vec::new()).expect("an encoder");
    let mut port = hivepack::lz4::Encoder::new(Vec::new(), Some(&prefs)).expect("an encoder");
    let mut at = 0;
    while at < src.len() {
        let piece = (1 + next(src.len())).min(src.len() - at);
        c.write_all(&src[at..at + piece]).expect("liblz4 compresses");
        port.write_all(&src[at..at + piece]).expect("the port compresses");
        if next(4) == 0 {
            c.flush().expect("liblz4 flushes");
            port.flush().expect("the port flushes");
        }
        at += piece;
    }
    let (want, ret) = c.finish();
    ret.expect("liblz4 ends the frame");
    let got = port.finish().expect("the port ends the frame");
    assert!(got == want, "frame");
    assert!(decompress_frame(&got, &[]) == src, "decompressed");
}

fn compress_other(src: &[u8], next: &mut impl FnMut(usize) -> usize) {
    // The first part of the input is a dictionary.
    let split = next(src.len() + 1);
    let (dict, src) = src.split_at(split);

    // Blocks into outputs of every size, and as much as fits.
    let bound = block::compress_bound(src.len());
    let capacity = [0, 1, next(bound + 1), bound][next(4)];
    let mut out = vec![0; capacity];
    let accel = [-1, 0, 1, 9, 70_000][next(5)];
    let n = block::compress_fast(src, &mut out, accel);
    if n > 0 {
        let mut back = vec![0; src.len()];
        assert_eq!(block::decompress_safe(&out[..n], &mut back), Ok(src.len()));
    }
    let mut state = hivepack::lz4::hc::StateHc::new();
    let level = next(14) as i32;
    for hc in [false, true] {
        let (n, read) = if hc {
            state.compress_hc_dest_size(src, &mut out, level)
        } else {
            block::compress_dest_size(src, &mut out)
        };
        // 0: nothing fits.
        if n > 0 {
            let mut back = vec![0; read];
            assert_eq!(block::decompress_safe(&out[..n], &mut back), Ok(read));
            assert!(back == src[..read], "as much as fits");
        }
    }

    // Streams of blocks after the dictionary.
    let mut stream = block::Stream::new();
    stream.load_dict(dict);
    let mut stream_hc = hivepack::lz4::hc::StreamHc::new();
    stream_hc.reset(next(14) as i32);
    stream_hc.load_dict_hc(dict);
    let mut history = dict[dict.len() - dict.len().min(64 << 10)..].to_vec();
    let mut history_hc = history.clone();
    let mut at = 0;
    while at < src.len() {
        let piece = (1 + next(src.len())).min(src.len() - at);
        let block_src = &src[at..at + piece];
        for hc in [false, true] {
            let mut out = vec![0; block::compress_bound(piece)];
            let (n, history) = if hc {
                (stream_hc.compress_hc_continue(block_src, &mut out), &mut history_hc)
            } else {
                (stream.compress_fast_continue(block_src, &mut out, accel), &mut history)
            };
            let mut back = vec![0; piece];
            assert_eq!(
                block::decompress_safe_using_dict(&out[..n], &mut back, history),
                Ok(piece),
                "a block of a stream"
            );
            assert!(back == block_src, "a block of a stream");
            history.extend_from_slice(block_src);
            let keep = history.len().min(64 << 10);
            history.drain(..history.len() - keep);
        }
        at += piece;
    }

    // Frames, with the dictionary, digested or not, call by call, some
    // pieces stored, into outputs of every size.
    let mut prefs = random_prefs(next, src.len());
    prefs.compression_level = [-70_000, -9, -1, 0, 2, 9, 12, 13][next(8)];
    prefs.frame_info.dict_id = next(1000) as u32;
    let cdict = Arc::new(CDict::new(dict));
    let mut cctx = CompressionContext::new();
    let mut frame = vec![0; frame::HEADER_SIZE_MAX];
    let n = match next(3) {
        0 => cctx.compress_begin(&mut frame, Some(&prefs)),
        1 => cctx.compress_begin_using_dict(&mut frame, dict, Some(&prefs)),
        _ => cctx.compress_begin_using_cdict(&mut frame, &cdict, Some(&prefs)),
    }
    .expect("a header");
    frame.truncate(n);
    let mut at = 0;
    let mut whole = true;
    while at < src.len() {
        let piece = (1 + next(src.len())).min(src.len() - at);
        let bound = frame::compress_bound(piece, Some(&prefs)) + (4 << 20) + 8;
        let mut out = vec![0; [bound, next(bound + 1)][next(2)]];
        let ret = if next(4) == 0 {
            cctx.uncompressed_update(&mut out, &src[at..at + piece])
        } else {
            cctx.compress_update(&mut out, &src[at..at + piece])
        };
        match ret {
            Ok(n) => frame.extend_from_slice(&out[..n]),
            Err(_) => {
                whole = false;
                break;
            }
        }
        at += piece;
    }
    let mut out = vec![0; frame::compress_bound(0, Some(&prefs))];
    match cctx.compress_end(&mut out) {
        Ok(n) if whole => {
            frame.extend_from_slice(&out[..n]);
            assert!(decompress_frame(&frame, dict) == src, "a frame call by call");
        }
        _ => {}
    }

    // In one call.
    let mut out = vec![0; frame::compress_frame_bound(src.len(), Some(&prefs))];
    let n = cctx
        .compress_frame_using_cdict(&mut out, src, Some(&cdict), Some(&prefs))
        .expect("a frame");
    assert!(decompress_frame(&out[..n], dict) == src, "a frame in one call");
}
