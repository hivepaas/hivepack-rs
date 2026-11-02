//! Comparison with libbzip2 1.0.8 through the bzip2 crate, which builds it
//! from bzip2-sys's bundled sources, on every machine CI tests: streams
//! compressed whole and in pieces, byte for byte, and streams decompressed
//! in pieces, call by call, with randomised blocks, the release's own
//! samples, and streams followed by more.
//!
//! `tests/oracle.rs` reaches what the crate hides (a run that can do
//! nothing, calls the crate refuses to make) through the C oracle.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "bzip2_support/mod.rs"]
mod support;

use hivepack::bzip2::{
    Action, Compress, Decompress, Error, InBuffer, OutBuffer, Status, buff_to_buff_compress,
    buff_to_buff_decompress,
};
use support::{Rng, c_compress, cache, damage, input, randomised};

/// The port's stream for `data`, in one call.
fn compress(data: &[u8], block_size: i32, work_factor: i32) -> Vec<u8> {
    let mut strm = Compress::new(block_size, work_factor).unwrap();
    let mut out = vec![0; data.len() + data.len() / 50 + 1000];
    let mut output = OutBuffer::new(&mut out);
    let status = strm
        .compress(&mut output, &mut InBuffer::new(data), Action::Finish)
        .unwrap();
    assert_eq!(status, Status::StreamEnd);
    let len = output.pos;
    out.truncate(len);
    out
}

/// The port's output for `stream`, in one call, with room for `max`
/// bytes.
fn decompress(stream: &[u8], small: bool, max: usize) -> (Result<Status, Error>, Vec<u8>, u64) {
    let mut strm = Decompress::new(small);
    let mut out = vec![0; max];
    let mut output = OutBuffer::new(&mut out);
    let status = strm.decompress(&mut output, &mut InBuffer::new(stream));
    let len = output.pos;
    out.truncate(len);
    (status, out, strm.total_in())
}

fn c_code(ret: Result<bzip2::Status, bzip2::Error>) -> i32 {
    match ret {
        Ok(bzip2::Status::Ok) => 0,
        Ok(bzip2::Status::RunOk) => 1,
        Ok(bzip2::Status::FlushOk) => 2,
        Ok(bzip2::Status::FinishOk) => 3,
        Ok(bzip2::Status::StreamEnd) => 4,
        Ok(bzip2::Status::MemNeeded) => -3,
        Err(bzip2::Error::Sequence) => -1,
        Err(bzip2::Error::Param) => -2,
        Err(bzip2::Error::Data) => -4,
        Err(bzip2::Error::DataMagic) => -5,
    }
}

fn code(ret: hivepack::bzip2::Result<Status>) -> i32 {
    match ret {
        Ok(status) => status.number(),
        Err(e) => e.number(),
    }
}

#[test]
fn compresses_as_libbzip2() {
    let mut rng = Rng(0x5eed_b211);
    for round in 0..120 {
        let len = match round % 4 {
            0 => rng.below(100) as usize,
            1 => rng.below(20_000) as usize,
            2 => 9000 + rng.below(3000) as usize,
            _ => rng.below(400_000) as usize,
        };
        let data = input(&mut rng, len);
        let block_size = 1 + rng.below(9) as i32;
        let work_factor = rng.pick(&[0, 1, 2, 4, 30, 100, 250]);
        let want = c_compress(&data, block_size as u32, work_factor as u32);
        assert!(
            compress(&data, block_size, work_factor) == want,
            "{len} bytes, block size {block_size}, work factor {work_factor}"
        );
    }
}

/// Several blocks of the largest size, and data repetitive enough to send
/// the main sort to the fallback, at the default work factor and others.
#[test]
fn compresses_large_and_repetitive_blocks_as_libbzip2() {
    let mut rng = Rng(0x5eed_b212);
    let mut text = Vec::new();
    while text.len() < 2_100_000 {
        text.extend_from_slice(&input(&mut rng, 5000));
    }
    let mut repetitive = Vec::new();
    for i in 0..1_000_000u32 {
        repetitive.push(b"abcabcabd"[(i % 9) as usize]);
    }
    for (data, work_factor) in [
        (&text, 0),
        (&repetitive, 0),
        (&repetitive, 1),
        (&repetitive, 250),
    ] {
        let want = c_compress(data, 9, work_factor as u32);
        assert!(
            compress(data, 9, work_factor) == want,
            "work factor {work_factor}"
        );
    }
}

/// Compressing in pieces, with flushes and the end in pieces too, as the
/// bzip2 crate lets libbzip2 be called: every call reads, writes and
/// returns the same.
#[test]
fn compresses_in_pieces_as_libbzip2() {
    let mut rng = Rng(0x5eed_b213);
    for _ in 0..150 {
        let max = if rng.below(4) == 0 { 300_000 } else { 20_000 };
        let len = rng.below(max) as usize;
        let data = input(&mut rng, len);
        let block_size = 1 + rng.below(9) as i32;
        let work_factor = rng.pick(&[0, 1, 30, 250]);
        let mut c = bzip2::Compress::new(
            bzip2::Compression::new(block_size as u32),
            work_factor as u32,
        );
        let mut port = Compress::new(block_size, work_factor).unwrap();
        let mut c_out = vec![0u8; 1 << 17];
        let mut p_out = vec![0u8; 1 << 17];
        let (mut pos, mut window) = (0, None);
        let mut stream = Vec::new();
        for call in 0.. {
            assert!(call < 100_000, "the stream never ends");
            let left = data.len() - pos;
            let (input_len, action) = match window {
                Some((end, action)) => (end - pos, action),
                None if left == 0 || rng.below(40) == 0 => {
                    // The end takes all the input left; a flush, some of
                    // it.
                    let action = if left == 0 || rng.below(3) != 0 {
                        Action::Finish
                    } else {
                        Action::Flush
                    };
                    let n = if action == Action::Finish || rng.below(2) == 0 {
                        left
                    } else {
                        rng.below(left as u64 + 1) as usize
                    };
                    window = Some((pos + n, action));
                    (n, action)
                }
                // The crate does not call libbzip2 for a run with nothing
                // to read.
                None => (1 + rng.below(left.min(9000) as u64) as usize, Action::Run),
            };
            let output_len = if rng.below(4) == 0 {
                c_out.len()
            } else {
                1 + rng.below(3000) as usize
            };
            let piece = &data[pos..pos + input_len];

            let c_action = match action {
                Action::Run => bzip2::Action::Run,
                Action::Flush => bzip2::Action::Flush,
                Action::Finish => bzip2::Action::Finish,
            };
            let (before_in, before_out) = (c.total_in(), c.total_out());
            let want = c_code(c.compress(piece, &mut c_out[..output_len], c_action));
            let c_read = (c.total_in() - before_in) as usize;
            let c_written = (c.total_out() - before_out) as usize;

            let mut p_input = InBuffer::new(piece);
            let mut p_output = OutBuffer::new(&mut p_out[..output_len]);
            let got = code(port.compress(&mut p_output, &mut p_input, action));
            assert_eq!(
                (got, p_input.pos, p_output.pos),
                (want, c_read, c_written),
                "call {call}"
            );
            assert!(p_out[..c_written] == c_out[..c_written], "call {call}");
            stream.extend_from_slice(&p_out[..c_written]);
            pos += c_read;
            match want {
                1 if action == Action::Flush => window = None,
                4 => break,
                _ => {}
            }
        }
        assert_eq!(
            (port.total_in(), port.total_out()),
            (c.total_in(), c.total_out())
        );
        let (status, out, _) = decompress(&stream, rng.below(2) == 0, data.len() + 1);
        assert_eq!(status, Ok(Status::StreamEnd));
        assert!(out == data);
    }
}

/// Decompressing in pieces, fast and small, valid streams and damaged
/// ones: every call, up to the first error, reads, writes and returns the
/// same as libbzip2.
#[test]
fn decompresses_in_pieces_as_libbzip2() {
    let mut rng = Rng(0x5eed_b214);
    for round in 0..300 {
        let len = rng.below(if round % 5 == 0 { 300_000 } else { 30_000 }) as usize;
        let data = input(&mut rng, len);
        let block_size = 1 + rng.below(9) as u32;
        let mut stream = c_compress(&data, block_size, 0);
        match rng.below(6) {
            0 | 1 => stream = damage(&mut rng, &stream),
            2 if !data.is_empty() => stream[14] ^= 0x80,
            _ => {}
        }
        let small = rng.below(2) == 0;
        let mut c = bzip2::Decompress::new(small);
        let mut port = Decompress::new(small);
        let mut c_out = vec![0u8; 1 << 16];
        let mut p_out = vec![0u8; 1 << 16];
        let mut pos = 0;
        for call in 0..200_000 {
            let left = stream.len() - pos;
            let input_len = if rng.below(4) == 0 {
                left
            } else {
                rng.below(left.min(3000) as u64 + 1) as usize
            };
            let output_len = if rng.below(4) == 0 {
                c_out.len()
            } else {
                rng.below(3000) as usize
            };
            let piece = &stream[pos..pos + input_len];

            let (before_in, before_out) = (c.total_in(), c.total_out());
            let want = c_code(c.decompress(piece, &mut c_out[..output_len]));
            let c_read = (c.total_in() - before_in) as usize;
            let c_written = (c.total_out() - before_out) as usize;

            let mut p_input = InBuffer::new(piece);
            let mut p_output = OutBuffer::new(&mut p_out[..output_len]);
            let got = code(port.decompress(&mut p_output, &mut p_input));
            assert_eq!(
                (got, p_input.pos, p_output.pos),
                (want, c_read, c_written),
                "round {round}, call {call}"
            );
            assert!(
                p_out[..c_written] == c_out[..c_written],
                "round {round}, call {call}"
            );
            pos += c_read;
            if want < 0 || want == 4 || (left == 0 && c_written == 0 && output_len > 0) {
                break;
            }
        }
    }
}

/// Randomised blocks, which bzip2 0.9.0 and earlier wrote, decompress as
/// in libbzip2, fast and small.
#[test]
fn decompresses_randomised_blocks() {
    let mut rng = Rng(0x5eed_b215);
    for round in 0..40 {
        let len = 1 + rng.below(if round % 4 == 0 { 95_000 } else { 5000 }) as usize;
        let mut last = 0;
        let data: Vec<u8> = (0..len)
            .map(|_| {
                let mut byte = rng.next() as u8;
                if byte == last {
                    byte ^= 0x40;
                }
                last = byte;
                byte
            })
            .collect();
        let block_size = 1 + rng.below(9) as u32;
        let stream = randomised(&data, block_size);
        for small in [false, true] {
            let (status, out, _) = decompress(&stream, small, len + 1);
            assert_eq!(
                status,
                Ok(Status::StreamEnd),
                "round {round}, small {small}"
            );
            assert!(out == data, "round {round}, small {small}");
            let mut c = bzip2::Decompress::new(small);
            let mut c_out = vec![0; len + 1];
            assert_eq!(
                c.decompress(&stream, &mut c_out),
                Ok(bzip2::Status::StreamEnd)
            );
            assert!(c_out[..len] == data[..]);
        }
    }
}

/// The samples of the bzip2 release, which its `make test` compresses at
/// block sizes 1, 2 and 3 and decompresses, fast and small.
#[test]
fn compresses_and_decompresses_the_release_samples() {
    let folder = cache().join("bzip2-1.0.8-source/bzip2-1.0.8");
    if !folder.join("sample1.ref").exists() {
        eprintln!(
            "skipping: the bzip2 sources are not fetched (scripts/testdata.py fetch --group generated)"
        );
        return;
    }
    for n in 1..=3 {
        let original = std::fs::read(folder.join(format!("sample{n}.ref"))).unwrap();
        let stream = std::fs::read(folder.join(format!("sample{n}.bz2"))).unwrap();
        assert!(compress(&original, n, 0) == stream, "sample{n}");
        for small in [false, true] {
            let (status, out, _) = decompress(&stream, small, original.len() + 1);
            assert_eq!(status, Ok(Status::StreamEnd));
            assert!(out == original, "sample{n}, small {small}");
        }
    }
}

/// A stream ends where its end is: the input after it is left unread, and
/// a later call fails with `BZ_SEQUENCE_ERROR`. A damaged stream's error is
/// returned again by every later call.
#[test]
fn stops_at_the_end_of_the_stream_and_after_an_error() {
    let first = c_compress(b"one stream", 9, 0);
    let mut both = first.clone();
    both.extend_from_slice(&c_compress(b"and another", 9, 0));
    let mut strm = Decompress::new(false);
    let mut out = [0u8; 100];
    let mut output = OutBuffer::new(&mut out);
    let mut input = InBuffer::new(&both);
    assert_eq!(
        strm.decompress(&mut output, &mut input),
        Ok(Status::StreamEnd)
    );
    assert_eq!((input.pos, output.pos), (first.len(), 10));
    assert_eq!(
        strm.decompress(&mut output, &mut input),
        Err(Error::Sequence)
    );

    let mut damaged = first.clone();
    damaged[20] ^= 0x10;
    let mut strm = Decompress::new(true);
    let mut output = OutBuffer::new(&mut out);
    let error = strm
        .decompress(&mut output, &mut InBuffer::new(&damaged))
        .unwrap_err();
    assert_eq!(error, Error::Data);
    assert_eq!(
        strm.decompress(&mut output, &mut InBuffer::new(&first)),
        Err(error)
    );
    assert_eq!(error.to_string(), "DATA_ERROR");
}

#[test]
fn buffer_to_buffer() {
    let data = input(&mut Rng(0x5eed_b216), 50_000);
    let stream = c_compress(&data, 3, 0);
    let mut out = vec![0u8; stream.len()];
    assert_eq!(
        buff_to_buff_compress(&mut out, &data, 3, 0),
        Ok(stream.len())
    );
    assert!(out == stream);
    assert_eq!(
        buff_to_buff_compress(&mut out[..stream.len() - 1], &data, 3, 0),
        Err(Error::OutbuffFull)
    );
    assert_eq!(
        buff_to_buff_compress(&mut out, &data, 10, 0),
        Err(Error::Param)
    );

    let mut decoded = vec![0u8; data.len()];
    assert_eq!(
        buff_to_buff_decompress(&mut decoded, &stream, true),
        Ok(data.len())
    );
    assert!(decoded == data);
    assert_eq!(
        buff_to_buff_decompress(&mut decoded[..data.len() - 1], &stream, false),
        Err(Error::OutbuffFull)
    );
    // Cut short: where the output fills up first, libbzip2 says so rather
    // than that the input ended.
    let short = &stream[..stream.len() - 1];
    assert_eq!(
        buff_to_buff_decompress(&mut decoded, short, false),
        Err(Error::OutbuffFull)
    );
    let mut room = vec![0u8; data.len() + 1];
    assert_eq!(
        buff_to_buff_decompress(&mut room, short, false),
        Err(Error::UnexpectedEof)
    );
    assert_eq!(
        buff_to_buff_decompress(&mut decoded, b"BZh0", false),
        Err(Error::DataMagic)
    );
}

#[test]
fn version() {
    assert_eq!(hivepack::bzip2::version(), "1.0.8, 13-Jul-2019");
    assert_eq!(hivepack::bzip2::UPSTREAM_VERSION, "1.0.8");
}
