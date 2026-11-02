//! Decodes the input as a Deflate64 stream with hivepack::deflate's
//! `InflateBack9`, all given at the start and in pieces, and checks that
//! both agree: the same result and message, the same input used, and the
//! same output in the same calls. Then decodes it with `Inflate9`, in
//! pieces of input and output, which must end as `InflateBack9` does, with
//! the same message, and give its output (which `InflateBack9` gives a
//! full window at a time before an error, and in full at the end). A panic
//! or a difference is a bug. zlib's
//! `contrib/infback9`, which the port follows, is not in libz-sys:
//! `crates/hivepack/tests/deflate_deflate64.rs` compares the two through the oracle.
//!
//! The first eight bytes seed the piece sizes, and the rest is the stream.

#![no_main]

use hivepack::deflate::{
    Back9, BackIn, BackOut, ErrorCode, InBuffer, Inflate9, InflateBack9, OutBuffer, Status,
};
use libfuzzer_sys::fuzz_target;

/// The input after the first piece, in pieces of random sizes.
struct Pieces<'a> {
    stream: &'a [u8],
    given: usize,
    rng: u64,
}

impl BackIn for Pieces<'_> {
    fn input(&mut self) -> &[u8] {
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        let left = self.stream.len() - self.given;
        let size = (self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d) % 300) as usize;
        let size = size.clamp(1, left.max(1)).min(left);
        let start = self.given;
        self.given += size;
        &self.stream[start..start + size]
    }
}

/// Each call's output.
struct Calls(Vec<Vec<u8>>);

impl BackOut for Calls {
    fn output(&mut self, data: &[u8]) -> bool {
        self.0.push(data.to_vec());
        false
    }
}

/// The result, the message, and the input used: given less what is unused,
/// or `None` if the input ran out.
fn outcome(back: &Back9, decoder: &InflateBack9, given: usize) -> (String, Option<usize>) {
    let result = format!("{:?} {:?}", back.result, decoder.msg());
    (result, back.unused.map(|unused| given - unused))
}

fuzz_target!(|data: &[u8]| {
    let Some((seed, stream)) = data.split_first_chunk::<8>() else { return };
    let rng = u64::from_le_bytes(*seed) | 1;

    let mut whole = Pieces { stream, given: stream.len(), rng };
    let mut whole_out = Calls(Vec::new());
    let mut decoder = InflateBack9::new();
    let back = decoder.inflate_back9(stream, &mut whole, &mut whole_out);
    let want = outcome(&back, &decoder, whole.given);

    let first = (rng % 64) as usize % (stream.len() + 1);
    let mut pieces = Pieces { stream, given: first, rng };
    let mut pieces_out = Calls(Vec::new());
    let back = decoder.inflate_back9(&stream[..first], &mut pieces, &mut pieces_out);
    let got = outcome(&back, &decoder, pieces.given);

    assert_eq!(got, want);
    assert!(pieces_out.0 == whole_out.0, "different output");

    // Inflate9, with input and output in pieces the seed picks.
    let mut rng = rng;
    let mut next = move |n: usize| {
        rng ^= rng >> 12;
        rng ^= rng << 25;
        rng ^= rng >> 27;
        (rng.wrapping_mul(0x2545_f491_4f6c_dd1d) % n as u64) as usize
    };
    let mut inflate = Inflate9::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 70_000];
    let mut pos = 0;
    let end = loop {
        let left = stream.len() - pos;
        let in_len = if next(3) == 0 { left } else { next(left.min(300) + 1) };
        let space = 1 + next(buf.len());
        let mut input = InBuffer::new(&stream[pos..pos + in_len]);
        let mut output = OutBuffer::new(&mut buf[..space]);
        let ret = inflate.inflate(&mut output, &mut input);
        pos += input.pos;
        let written = output.pos;
        out.extend_from_slice(&buf[..written]);
        match ret {
            Ok(Status::Ok) => {}
            Err(e) if e.code() == ErrorCode::Buf && pos < stream.len() => {}
            ret => break ret,
        }
    };
    let back_out: Vec<u8> = whole_out.0.concat();
    match back.result {
        Ok(_) => {
            assert_eq!(end, Ok(Status::StreamEnd));
            assert!(out == back_out, "different output from Inflate9");
        }
        Err(e) => {
            assert_eq!(end.map_err(|e| e.code()), Err(e.code()));
            assert_eq!(inflate.msg(), decoder.msg());
            assert!(out.starts_with(&back_out), "different output from Inflate9");
        }
    }
});
