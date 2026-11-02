//! The port against zlib 1.3.2 itself (through libz-sys and flate2): the
//! same streams, given in the same pieces, must give the same result from
//! every call, read and write the same number of bytes, and fail with the
//! same message.
//!
//! The streams come from zlib's own compressor, at several levels, window
//! sizes and flushes, raw and with the zlib and gzip wrappers, then damaged
//! in places chosen at random.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::panic)]

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
use hivepack::deflate::{ErrorCode, Flush, GzHeader, InBuffer, Inflate, OutBuffer, Status};

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

impl Wrap {
    /// The `windowBits` that inflateInit2 takes for this wrapper.
    fn window_bits(self, wbits: u8) -> i32 {
        match self {
            Wrap::Raw => -i32::from(wbits),
            Wrap::Zlib => i32::from(wbits),
            Wrap::Gzip => i32::from(wbits) + 16,
        }
    }

    fn reference(self, wbits: u8) -> Decompress {
        match self {
            Wrap::Raw => Decompress::new_with_window_bits(false, wbits),
            Wrap::Zlib => Decompress::new_with_window_bits(true, wbits),
            Wrap::Gzip => Decompress::new_gzip(wbits),
        }
    }
}

/// Test inputs: text, random bytes, runs, matches across the whole window
/// and beyond it, and the uncompressed files in testdata.
fn inputs() -> Vec<(String, Vec<u8>)> {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut inputs = vec![
        ("empty".to_string(), Vec::new()),
        ("one byte".to_string(), vec![b'x']),
    ];

    let words = [
        "zlib", "inflate", "the", "window", "of", "a", "stream", "block", "\n", ", ", "deflate",
    ];
    let mut text = Vec::new();
    while text.len() < 100_000 {
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
        let len = 1 + rng.below(600);
        runs.extend(std::iter::repeat_n(byte, len));
    }
    inputs.push(("runs".to_string(), runs));

    // Pieces repeated from up to 40 KiB back, so that some matches reach
    // into the window, and some would reach past a small one.
    let mut far = Vec::new();
    while far.len() < 200_000 {
        if far.len() > 1000 && rng.below(3) != 0 {
            let back = 1 + rng.below(far.len().min(40_000));
            let len = 3 + rng.below(300);
            for i in 0..len {
                let byte = far[far.len() - back + i % back];
                far.push(byte);
            }
        } else {
            far.extend((0..1 + rng.below(50)).map(|_| rng.next() as u8 & 0x3f));
        }
    }
    inputs.push(("far matches".to_string(), far));

    let folder = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/zstd/golden-compression"
    );
    for entry in std::fs::read_dir(folder).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        inputs.push((name, std::fs::read(&path).unwrap()));
    }
    inputs
}

/// `data` compressed by zlib, in pieces, with a flush now and then when
/// `flushes` is on.
fn compress(data: &[u8], wrap: Wrap, level: u32, wbits: u8, flushes: Option<&mut Rng>) -> Vec<u8> {
    let level = Compression::new(level);
    let mut c = match wrap {
        Wrap::Raw => Compress::new_with_window_bits(level, false, wbits),
        Wrap::Zlib => Compress::new_with_window_bits(level, true, wbits),
        Wrap::Gzip => Compress::new_gzip(level, wbits),
    };
    let mut out = Vec::with_capacity(data.len() + 1024);
    let mut pos = 0;
    let mut rng = flushes;
    loop {
        let (piece, flush) = match &mut rng {
            Some(rng) => {
                let piece = (1 + rng.below(20_000)).min(data.len() - pos);
                let flush = match rng.below(8) {
                    0 => FlushCompress::Sync,
                    1 => FlushCompress::Full,
                    2 => FlushCompress::Partial,
                    _ => FlushCompress::None,
                };
                (piece, flush)
            }
            None => (data.len() - pos, FlushCompress::None),
        };
        let end = pos + piece;
        let flush = if end == data.len() {
            FlushCompress::Finish
        } else {
            flush
        };
        loop {
            if out.capacity() - out.len() < 1024 {
                out.reserve(64 * 1024);
            }
            let before = c.total_in();
            let status = c.compress_vec(&data[pos..end], &mut out, flush).unwrap();
            pos += (c.total_in() - before) as usize;
            if status == flate2::Status::StreamEnd {
                return out;
            }
            // The piece is done, flush included, once all of it is read
            // and the output was not filled.
            if pos == end && out.capacity() > out.len() {
                break;
            }
        }
    }
}

/// What a call returned, in terms both libraries can say.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Outcome {
    Ok,
    Buf,
    End,
    NeedDict(u32),
    Fail(Option<String>),
}

fn reference_call(
    d: &mut Decompress,
    input: &[u8],
    out: &mut [u8],
    finish: bool,
) -> (Outcome, usize, usize) {
    let (before_in, before_out) = (d.total_in(), d.total_out());
    let flush = if finish {
        FlushDecompress::Finish
    } else {
        FlushDecompress::None
    };
    let outcome = match d.decompress(input, out, flush) {
        Ok(flate2::Status::Ok) => Outcome::Ok,
        Ok(flate2::Status::BufError) => Outcome::Buf,
        Ok(flate2::Status::StreamEnd) => Outcome::End,
        Err(e) => match e.needs_dictionary() {
            Some(id) => Outcome::NeedDict(id),
            None => Outcome::Fail(e.message().map(String::from)),
        },
    };
    (
        outcome,
        (d.total_in() - before_in) as usize,
        (d.total_out() - before_out) as usize,
    )
}

fn port_call(
    i: &mut Inflate,
    input: &[u8],
    out: &mut [u8],
    finish: bool,
) -> (Outcome, usize, usize) {
    let mut source = InBuffer::new(input);
    let mut output = OutBuffer::new(out);
    let flush = if finish {
        Flush::Finish
    } else {
        Flush::NoFlush
    };
    let outcome = match i.inflate(&mut output, &mut source, flush) {
        Ok(Status::Ok) => Outcome::Ok,
        Ok(Status::StreamEnd) => Outcome::End,
        Ok(Status::NeedDict) => Outcome::NeedDict(i.adler()),
        Err(e) if e.code() == ErrorCode::Buf => Outcome::Buf,
        Err(e) => Outcome::Fail(e.msg().map(String::from)),
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

/// Decompresses `stream` with both, in the same random pieces, comparing
/// every call. Returns how the stream ended.
fn compare(
    stream: &[u8],
    wrap: Wrap,
    wbits: u8,
    dictionary: Option<&[u8]>,
    rng: &mut Rng,
    what: &str,
) -> Outcome {
    let mut reference = wrap.reference(wbits);
    let mut port = Inflate::new(wrap.window_bits(wbits)).unwrap();
    if wrap == Wrap::Raw
        && let Some(dictionary) = dictionary
    {
        reference.set_dictionary(dictionary).unwrap();
        port.set_dictionary(dictionary).unwrap();
    }
    let mut ref_out = vec![0; 1 << 17];
    let mut port_out = vec![0; 1 << 17];
    let mut pos = 0;
    let mut calls = 0;
    let mut needed_dictionary = false;
    loop {
        calls += 1;
        let input_len = piece(rng, stream.len() - pos, 300).min(stream.len() - pos);
        let output_len = piece(rng, ref_out.len(), 600).min(ref_out.len());
        let finish = rng.below(10) == 0;
        let input = &stream[pos..pos + input_len];
        let r = reference_call(&mut reference, input, &mut ref_out[..output_len], finish);
        let p = port_call(&mut port, input, &mut port_out[..output_len], finish);
        assert_eq!(p, r, "{what}: call {calls}, at input {pos}");
        assert_eq!(&port_out[..p.2], &ref_out[..r.2], "{what}: call {calls}");
        pos += r.1;
        match r.0 {
            Outcome::End | Outcome::Fail(_) => {
                // flate2 counts what each call read. zlib's own total_in,
                // which the port keeps, leaves out the header and
                // dictionary ID read before Z_NEED_DICT, as inflate()
                // returns that without updating it.
                if !needed_dictionary {
                    assert_eq!(port.total_in(), reference.total_in(), "{what}");
                }
                assert_eq!(port.total_out(), reference.total_out(), "{what}");
                return r.0;
            }
            Outcome::NeedDict(_) => {
                needed_dictionary = true;
                let dictionary = dictionary.unwrap_or(b"not the dictionary");
                let r = reference
                    .set_dictionary(dictionary)
                    .map_err(|e| e.message().map(String::from));
                let p = port
                    .set_dictionary(dictionary)
                    .map_err(|e| e.msg().map(String::from));
                assert_eq!(p.is_ok(), r.is_ok(), "{what}: set_dictionary");
                if r.is_err() {
                    return Outcome::Fail(None);
                }
            }
            Outcome::Buf if pos == stream.len() && r.2 == 0 => {
                // No input left and nothing more to write: the stream is
                // truncated. One more call with Finish, then stop.
                let r = reference_call(&mut reference, &[], &mut ref_out, true);
                let p = port_call(&mut port, &[], &mut port_out, true);
                assert_eq!(p, r, "{what}: at the end");
                return r.0;
            }
            _ => {}
        }
        assert!(calls < 1_000_000, "{what}: no end");
    }
}

/// Every input, compressed at several levels and window sizes, with every
/// wrapper, decompressed in random pieces.
#[test]
fn zlib_streams() {
    let mut rng = Rng(1);
    for (name, data) in inputs() {
        for wrap in [Wrap::Raw, Wrap::Zlib, Wrap::Gzip] {
            for (level, wbits) in [(0, 15), (1, 15), (6, 15), (9, 15), (6, 9), (9, 12)] {
                let stream = compress(&data, wrap, level, wbits, None);
                let what = format!("{name}, {wrap:?}, level {level}, window {wbits}");
                assert_eq!(
                    compare(&stream, wrap, wbits, None, &mut rng, &what),
                    Outcome::End,
                    "{what}"
                );
            }
        }
    }
}

/// Streams with sync, full and partial flushes, which leave empty stored
/// and fixed blocks between the others.
#[test]
fn flushed_streams() {
    let mut rng = Rng(2);
    for (name, data) in inputs() {
        for wrap in [Wrap::Raw, Wrap::Zlib, Wrap::Gzip] {
            for level in [1, 6] {
                let stream = compress(&data, wrap, level, 15, Some(&mut rng));
                let what = format!("{name}, {wrap:?}, level {level}, flushed");
                assert_eq!(
                    compare(&stream, wrap, 15, None, &mut rng, &what),
                    Outcome::End,
                    "{what}"
                );
            }
        }
    }
}

/// Decompressing with a smaller window than the stream's: refused by the
/// zlib header, and matches too far back in a raw stream.
#[test]
fn small_windows() {
    let mut rng = Rng(3);
    for (name, data) in inputs()
        .into_iter()
        .filter(|(name, _)| name == "far matches" || name == "text")
    {
        for wrap in [Wrap::Raw, Wrap::Zlib, Wrap::Gzip] {
            let stream = compress(&data, wrap, 6, 15, None);
            for wbits in [9, 10, 14] {
                let what = format!("{name}, {wrap:?}, window {wbits} for 15");
                compare(&stream, wrap, wbits, None, &mut rng, &what);
            }
        }
    }
}

/// Preset dictionaries: a zlib stream names its dictionary, and a raw one
/// is given it before it starts.
#[test]
fn dictionaries() {
    let mut rng = Rng(4);
    let data = &inputs()[2].1; // the text
    let dictionary: Vec<u8> = data[..40_000].to_vec();
    for wrap in [Wrap::Raw, Wrap::Zlib] {
        let mut c = Compress::new_with_window_bits(Compression::new(6), wrap == Wrap::Zlib, 15);
        c.set_dictionary(&dictionary).unwrap();
        let mut stream = Vec::with_capacity(data.len());
        c.compress_vec(&data[10_000..], &mut stream, FlushCompress::Finish)
            .unwrap();
        for _ in 0..20 {
            let what = format!("{wrap:?} with a dictionary");
            assert_eq!(
                compare(&stream, wrap, 15, Some(&dictionary), &mut rng, &what),
                Outcome::End
            );
        }
        if wrap == Wrap::Zlib {
            let what = "zlib with the wrong dictionary";
            assert_eq!(
                compare(&stream, wrap, 15, None, &mut rng, what),
                Outcome::Fail(None)
            );
        }
    }
}

/// Streams with bytes changed, bits flipped, and cut short: the same
/// output up to the same error, with the same message.
#[test]
fn damaged_streams() {
    let mut rng = Rng(5);
    let mut failures = 0;
    for (name, data) in inputs() {
        if data.len() < 100 {
            continue;
        }
        let data = &data[..data.len().min(30_000)];
        for wrap in [Wrap::Raw, Wrap::Zlib, Wrap::Gzip] {
            for level in [0, 1, 6, 9] {
                let stream = compress(data, wrap, level, 15, None);
                for round in 0..30 {
                    let mut damaged = stream.clone();
                    let at = rng.below(damaged.len());
                    match round % 3 {
                        0 => damaged[at] ^= 1 << rng.below(8),
                        1 => damaged[at] = rng.next() as u8,
                        _ => damaged.truncate(at),
                    }
                    let what =
                        format!("{name}, {wrap:?}, level {level}, damaged at {at} ({round})");
                    if let Outcome::Fail(_) = compare(&damaged, wrap, 15, None, &mut rng, &what) {
                        failures += 1;
                    }
                }
            }
        }
    }
    // Most damage is found: the comparison covered the error paths.
    assert!(failures > 500, "only {failures} damaged streams failed");
}

/// A gzip header with every field, read by both; the port also hands the
/// fields back.
#[test]
fn gzip_header() {
    let data = b"a gzip member with every header field";
    let deflated = compress(data, Wrap::Raw, 6, 15, None);
    let extra = b"AB\x04\0abcd";
    let mut header = vec![0x1f, 0x8b, 8, 0x1f, 0x78, 0x56, 0x34, 0x12, 2, 3];
    header.extend_from_slice(&(extra.len() as u16).to_le_bytes());
    header.extend_from_slice(extra);
    header.extend_from_slice(b"name.txt\0a comment\0");
    let hcrc = hivepack::deflate::crc32(0, &header) as u16;
    header.extend_from_slice(&hcrc.to_le_bytes());
    let mut stream = header;
    stream.extend_from_slice(&deflated);
    stream.extend_from_slice(&hivepack::deflate::crc32(0, data).to_le_bytes());
    stream.extend_from_slice(&(data.len() as u32).to_le_bytes());

    let mut rng = Rng(6);
    for _ in 0..50 {
        assert_eq!(
            compare(&stream, Wrap::Gzip, 15, None, &mut rng, "gzip header"),
            Outcome::End
        );
    }

    // With buffers too small for the extra field and the name, which keep
    // what fits, and none for the comment.
    for (extra_max, name_max) in [(64, 64), (3, 4)] {
        let mut inflate = Inflate::new(31).unwrap();
        inflate
            .get_header(GzHeader::new(extra_max, name_max, 0))
            .unwrap();
        let mut out = [0; 64];
        let mut output = OutBuffer::new(&mut out);
        let status = inflate
            .inflate(&mut output, &mut InBuffer::new(&stream), Flush::Finish)
            .unwrap();
        assert_eq!(status, Status::StreamEnd);
        assert_eq!(&out[..data.len()], data);
        let head = inflate.header().unwrap();
        assert_eq!(
            (head.text, head.time, head.xflags, head.os),
            (1, 0x1234_5678, 2, 3)
        );
        assert_eq!((head.hcrc, head.done, head.extra_len), (1, 1, 8));
        let kept = extra.len().min(extra_max);
        assert_eq!(&head.extra.as_ref().unwrap()[..kept], &extra[..kept]);
        let name = b"name.txt\0";
        let kept = name.len().min(name_max);
        assert_eq!(&head.name.as_ref().unwrap()[..kept], &name[..kept]);
        assert_eq!(head.comment, None);
    }

    // The header crc damaged: refused by both.
    let mut damaged = stream.clone();
    damaged[10 + 2 + extra.len() + 19] ^= 1;
    let mut rng = Rng(7);
    let outcome = compare(&damaged, Wrap::Gzip, 15, None, &mut rng, "header crc");
    assert_eq!(
        outcome,
        Outcome::Fail(Some("header crc mismatch".to_string()))
    );
}
