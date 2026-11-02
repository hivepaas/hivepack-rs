//! Compresses the input with hivepack::deflate and with zlib, given in the
//! same pieces with the same flushes, and checks that every call agrees:
//! the same result, the same bytes read and written, and the same bytes. A
//! panic or a difference is a bug.
//!
//! The first byte chooses the level and wrapper, the next eight seed the
//! piece sizes and flushes, and the rest is the data.

#![no_main]

use flate2::{Compress, Compression, FlushCompress};
use hivepack::deflate::{Deflate, ErrorCode, Flush, InBuffer, OutBuffer, Status};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, PartialEq)]
enum Outcome {
    Ok,
    Buf,
    End,
    Fail,
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let Some((seed, input)) = rest.split_first_chunk::<8>() else { return };
    let level = u32::from(mode % 10);
    let wbits = 9 + (mode / 10) % 7;
    let (mut zlib, window_bits) = match (mode / 70) % 3 {
        0 => (Compress::new_with_window_bits(Compression::new(level), false, wbits), -i32::from(wbits)),
        1 => (Compress::new_with_window_bits(Compression::new(level), true, wbits), i32::from(wbits)),
        _ => (Compress::new_gzip(Compression::new(level), wbits), i32::from(wbits) + 16),
    };
    let Ok(mut port) = Deflate::new(level as i32, window_bits, 8, 0) else { panic!("level {level}") };
    let mut rng = u64::from_le_bytes(*seed) | 1;
    let mut next = move |n: usize| {
        rng ^= rng >> 12;
        rng ^= rng << 25;
        rng ^= rng >> 27;
        (rng.wrapping_mul(0x2545_f491_4f6c_dd1d) % n as u64) as usize
    };
    let mut z_out = vec![0u8; 1 << 16];
    let mut p_out = vec![0u8; 1 << 16];
    let mut pos = 0;
    for _ in 0..100_000 {
        let left = input.len() - pos;
        let input_len = if next(4) == 0 { left } else { next(left.min(256) + 1) };
        let output_len = if next(4) == 0 { z_out.len() } else { 1 + next(600) };
        let finish = pos + input_len == input.len() && next(2) == 0;
        let (z_flush, p_flush) = match (finish, next(10)) {
            (true, _) => (FlushCompress::Finish, Flush::Finish),
            (false, 0) => (FlushCompress::Sync, Flush::SyncFlush),
            (false, 1) => (FlushCompress::Full, Flush::FullFlush),
            (false, 2) => (FlushCompress::Partial, Flush::PartialFlush),
            _ => (FlushCompress::None, Flush::NoFlush),
        };
        let piece = &input[pos..pos + input_len];

        let (before_in, before_out) = (zlib.total_in(), zlib.total_out());
        let want = match zlib.compress(piece, &mut z_out[..output_len], z_flush) {
            Ok(flate2::Status::Ok) => Outcome::Ok,
            Ok(flate2::Status::BufError) => Outcome::Buf,
            Ok(flate2::Status::StreamEnd) => Outcome::End,
            Err(_) => Outcome::Fail,
        };
        let read = (zlib.total_in() - before_in) as usize;
        let written = (zlib.total_out() - before_out) as usize;

        let mut source = InBuffer::new(piece);
        let mut output = OutBuffer::new(&mut p_out[..output_len]);
        let got = match port.deflate(&mut output, &mut source, p_flush) {
            Ok(Status::Ok) => Outcome::Ok,
            Ok(Status::StreamEnd) => Outcome::End,
            Ok(Status::NeedDict) => Outcome::Fail,
            Err(e) if e.code() == ErrorCode::Buf => Outcome::Buf,
            Err(_) => Outcome::Fail,
        };
        let (got_read, got_written) = (source.pos, output.pos);

        assert_eq!((&got, got_read, got_written), (&want, read, written));
        assert!(p_out[..written] == z_out[..written], "different output");
        pos += read;
        if want == Outcome::End || want == Outcome::Fail {
            return;
        }
    }
});
