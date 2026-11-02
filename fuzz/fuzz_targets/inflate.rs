//! Decodes the input with hivepack::deflate and with zlib, given in the same
//! pieces, and checks that every call agrees: the same result and message,
//! the same bytes read and written, and the same output. A panic or a
//! difference is a bug.
//!
//! The first byte chooses the wrapper (raw, zlib or gzip) and the window
//! size, the next eight seed the piece sizes, and the rest is the stream.

#![no_main]

use flate2::{Decompress, FlushDecompress};
use hivepack::deflate::{ErrorCode, Flush, InBuffer, Inflate, OutBuffer, Status};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, PartialEq)]
enum Outcome {
    Ok,
    Buf,
    End,
    NeedDict(u32),
    Fail(Option<String>),
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let Some((seed, stream)) = rest.split_first_chunk::<8>() else { return };
    let wbits = 9 + mode % 7;
    let (mut zlib, window_bits) = match (mode / 7) % 3 {
        0 => (Decompress::new_with_window_bits(false, wbits), -i32::from(wbits)),
        1 => (Decompress::new_with_window_bits(true, wbits), i32::from(wbits)),
        _ => (Decompress::new_gzip(wbits), i32::from(wbits) + 16),
    };
    let Ok(mut port) = Inflate::new(window_bits) else { panic!("window bits {window_bits}") };
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
        let left = stream.len() - pos;
        let input_len = if next(4) == 0 { left } else { next(left.min(64) + 1) };
        let output_len = if next(4) == 0 { z_out.len() } else { 1 + next(600) };
        let finish = next(10) == 0;
        let input = &stream[pos..pos + input_len];

        let (before_in, before_out) = (zlib.total_in(), zlib.total_out());
        let flush = if finish { FlushDecompress::Finish } else { FlushDecompress::None };
        let want = match zlib.decompress(input, &mut z_out[..output_len], flush) {
            Ok(flate2::Status::Ok) => Outcome::Ok,
            Ok(flate2::Status::BufError) => Outcome::Buf,
            Ok(flate2::Status::StreamEnd) => Outcome::End,
            Err(e) => match e.needs_dictionary() {
                Some(id) => Outcome::NeedDict(id),
                None => Outcome::Fail(e.message().map(String::from)),
            },
        };
        let read = (zlib.total_in() - before_in) as usize;
        let written = (zlib.total_out() - before_out) as usize;

        let mut source = InBuffer::new(input);
        let mut output = OutBuffer::new(&mut p_out[..output_len]);
        let flush = if finish { Flush::Finish } else { Flush::NoFlush };
        let got = match port.inflate(&mut output, &mut source, flush) {
            Ok(Status::Ok) => Outcome::Ok,
            Ok(Status::StreamEnd) => Outcome::End,
            Ok(Status::NeedDict) => Outcome::NeedDict(port.adler()),
            Err(e) if e.code() == ErrorCode::Buf => Outcome::Buf,
            Err(e) => Outcome::Fail(e.msg().map(String::from)),
        };
        let (got_read, got_written) = (source.pos, output.pos);

        assert_eq!((&got, got_read, got_written), (&want, read, written));
        assert!(p_out[..written] == z_out[..written], "different output");
        pos += read;
        match want {
            Outcome::End | Outcome::Fail(_) | Outcome::NeedDict(_) => return,
            Outcome::Buf if pos == stream.len() && written == 0 => return,
            _ => {}
        }
    }
});
