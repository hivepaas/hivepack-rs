//! The port's compressor against zlib 1.3.2's (through libz-sys and
//! flate2): the same input, given in the same pieces with the same
//! flushes, must give the same result from every call, read and write the
//! same number of bytes, and the same bytes.
//!
//! flate2 creates zlib streams with the default memory level (8) and
//! strategy; `tests/oracle.rs` covers the others.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::panic)]

use flate2::{Compress, Compression, FlushCompress};
use hivepack::deflate::{Deflate, ErrorCode, Flush, InBuffer, OutBuffer, Status};

/// xorshift64*, so that failures can be replayed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Wrap {
    Raw,
    Zlib,
    Gzip,
}

/// Test inputs: text, random bytes, runs, matches across the whole window
/// and beyond it, the uncompressed files in testdata, and pieces of the
/// Silesia corpus when it is fetched.
fn inputs() -> Vec<(String, Vec<u8>)> {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut inputs = vec![
        ("empty".to_string(), Vec::new()),
        ("one byte".to_string(), vec![b'x']),
    ];

    let words = [
        "zlib", "deflate", "the", "window", "of", "a", "stream", "block", "\n", ", ", "match",
    ];
    let mut text = Vec::new();
    while text.len() < 150_000 {
        text.extend_from_slice(words[rng.below(words.len())].as_bytes());
        text.push(b' ');
    }
    inputs.push(("text".to_string(), text));

    inputs.push((
        "random".to_string(),
        (0..70_000).map(|_| rng.next() as u8).collect(),
    ));

    let mut runs = Vec::new();
    while runs.len() < 80_000 {
        let byte = rng.next() as u8;
        runs.extend(std::iter::repeat_n(byte, 1 + rng.below(600)));
    }
    inputs.push(("runs".to_string(), runs));

    // Pieces repeated from up to 40 KiB back, so that some matches reach
    // past the window.
    let mut far = Vec::new();
    while far.len() < 200_000 {
        if far.len() > 1000 && rng.below(3) != 0 {
            let back = 1 + rng.below(far.len().min(40_000));
            for i in 0..3 + rng.below(300) {
                far.push(far[far.len() - back + i % back]);
            }
        } else {
            far.extend((0..1 + rng.below(50)).map(|_| rng.next() as u8 & 0x3f));
        }
    }
    inputs.push(("far matches".to_string(), far));

    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    for entry in std::fs::read_dir(format!("{root}/testdata/zstd/golden-compression")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        inputs.push((name, std::fs::read(&path).unwrap()));
    }
    let silesia = std::env::var_os("HIVEPACK_TESTDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(root).join("target/testdata"))
        .join("silesia");
    for name in ["dickens", "mozilla", "nci", "x-ray", "xml"] {
        if let Ok(data) = std::fs::read(silesia.join(name)) {
            // A piece from the middle: the whole corpus is too slow for a
            // debug build.
            let start = data.len() / 3;
            inputs.push((
                format!("silesia/{name}"),
                data[start..start + 400_000.min(data.len() - start)].to_vec(),
            ));
        }
    }
    inputs
}

/// What a call returned, in terms both libraries can say.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Outcome {
    Ok,
    Buf,
    End,
    Fail,
}

fn zlib_flush(flush: Flush) -> FlushCompress {
    match flush {
        Flush::NoFlush => FlushCompress::None,
        Flush::PartialFlush => FlushCompress::Partial,
        Flush::SyncFlush => FlushCompress::Sync,
        Flush::FullFlush => FlushCompress::Full,
        _ => FlushCompress::Finish,
    }
}

fn reference_call(
    c: &mut Compress,
    input: &[u8],
    out: &mut [u8],
    flush: Flush,
) -> (Outcome, usize, usize) {
    let (before_in, before_out) = (c.total_in(), c.total_out());
    let outcome = match c.compress(input, out, zlib_flush(flush)) {
        Ok(flate2::Status::Ok) => Outcome::Ok,
        Ok(flate2::Status::BufError) => Outcome::Buf,
        Ok(flate2::Status::StreamEnd) => Outcome::End,
        Err(_) => Outcome::Fail,
    };
    (
        outcome,
        (c.total_in() - before_in) as usize,
        (c.total_out() - before_out) as usize,
    )
}

fn port_call(
    d: &mut Deflate,
    input: &[u8],
    out: &mut [u8],
    flush: Flush,
) -> (Outcome, usize, usize) {
    let mut source = InBuffer::new(input);
    let mut output = OutBuffer::new(out);
    let outcome = match d.deflate(&mut output, &mut source, flush) {
        Ok(Status::Ok) => Outcome::Ok,
        Ok(Status::StreamEnd) => Outcome::End,
        Ok(Status::NeedDict) => Outcome::Fail,
        Err(e) if e.code() == ErrorCode::Buf => Outcome::Buf,
        Err(_) => Outcome::Fail,
    };
    (outcome, source.pos, output.pos)
}

/// A piece size: often small, sometimes all that is left.
fn piece(rng: &mut Rng, left: usize, small: usize) -> usize {
    match rng.below(6) {
        0 => left,
        1 => 1,
        2 => rng.below(small) + 1,
        3 => rng.below(70_000) + 1,
        _ => rng.below(4 * small) + 1,
    }
}

/// Compresses `data` with both, in the same random pieces and flushes,
/// comparing every call, and returns the stream.
fn compare(
    data: &[u8],
    wrap: Wrap,
    level: i32,
    wbits: u8,
    flushes: bool,
    rng: &mut Rng,
    what: &str,
) -> Vec<u8> {
    let compression = Compression::new(level as u32);
    let mut reference = match wrap {
        Wrap::Raw => Compress::new_with_window_bits(compression, false, wbits),
        Wrap::Zlib => Compress::new_with_window_bits(compression, true, wbits),
        Wrap::Gzip => Compress::new_gzip(compression, wbits),
    };
    let window_bits = match wrap {
        Wrap::Raw => -i32::from(wbits),
        Wrap::Zlib => i32::from(wbits),
        Wrap::Gzip => i32::from(wbits) + 16,
    };
    let mut port = Deflate::new(level, window_bits, 8, 0).unwrap();
    let mut stream = Vec::new();
    let mut ref_out = vec![0; 1 << 17];
    let mut port_out = vec![0; 1 << 17];
    let mut pos = 0;
    let mut calls = 0;
    loop {
        calls += 1;
        let input_len = piece(rng, data.len() - pos, 300).min(data.len() - pos);
        let output_len = piece(rng, ref_out.len(), 600).min(ref_out.len());
        let end = pos + input_len == data.len();
        let flush = if end && rng.below(3) != 0 {
            Flush::Finish
        } else if flushes {
            match rng.below(10) {
                0 => Flush::SyncFlush,
                1 => Flush::FullFlush,
                2 => Flush::PartialFlush,
                _ => Flush::NoFlush,
            }
        } else {
            Flush::NoFlush
        };
        let input = &data[pos..pos + input_len];
        let r = reference_call(&mut reference, input, &mut ref_out[..output_len], flush);
        let p = port_call(&mut port, input, &mut port_out[..output_len], flush);
        assert_eq!(p, r, "{what}: call {calls} ({flush:?}), at input {pos}");
        assert_eq!(
            &port_out[..p.2],
            &ref_out[..r.2],
            "{what}: call {calls}, output differs"
        );
        stream.extend_from_slice(&ref_out[..r.2]);
        pos += r.1;
        if r.0 == Outcome::End {
            assert_eq!(port.total_in(), reference.total_in(), "{what}");
            assert_eq!(port.total_out(), reference.total_out(), "{what}");
            return stream;
        }
        assert!(calls < 2_000_000, "{what}: no end");
    }
}

/// Every input, at every level, with each wrapper and a few window sizes.
#[test]
fn every_level() {
    let mut rng = Rng(1);
    for (name, data) in inputs() {
        for level in -1..=9 {
            for (wrap, wbits) in [
                (Wrap::Raw, 15),
                (Wrap::Zlib, 15),
                (Wrap::Gzip, 15),
                (Wrap::Raw, 9),
                (Wrap::Zlib, 12),
            ] {
                let what = format!("{name}, level {level}, {wrap:?}, window {wbits}");
                compare(&data, wrap, level, wbits, false, &mut rng, &what);
            }
        }
    }
}

/// Sync, full and partial flushes between pieces.
#[test]
fn flushes() {
    let mut rng = Rng(2);
    for (name, data) in inputs() {
        for level in [0, 1, 3, 4, 6, 9] {
            for wrap in [Wrap::Raw, Wrap::Zlib, Wrap::Gzip] {
                let what = format!("{name}, level {level}, {wrap:?}, flushed");
                compare(&data, wrap, level, 15, true, &mut rng, &what);
            }
        }
    }
}

/// What the port writes, zlib reads back.
#[test]
fn round_trip() {
    let mut rng = Rng(3);
    for (name, data) in inputs().into_iter().take(6) {
        let stream = compare(&data, Wrap::Zlib, 6, 15, true, &mut rng, &name);
        let mut out = vec![0; data.len() + 1];
        let mut d = flate2::Decompress::new(true);
        let status = d
            .decompress(&stream, &mut out, flate2::FlushDecompress::Finish)
            .unwrap();
        assert_eq!(status, flate2::Status::StreamEnd, "{name}");
        assert_eq!(&out[..d.total_out() as usize], &data[..], "{name}");
    }
}
