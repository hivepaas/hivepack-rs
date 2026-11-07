//! zstd in frames of a fixed size, compressed in threads
//! (`zstd::CompressFrames`): the same output whatever the threads and the
//! buffers, each frame `CCtx::compress2`'s, and a seek table that libzstd's
//! seekable format reads (`contrib/seekable_format`, built into the reference
//! library here). libzstd and this crate's decoder read it all back as one
//! stream.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hivepack::Threads;
use hivepack::zstd::{
    CCtx, CParameter, CompressFrames, DCtx, EndDirective, ErrorCode, FramesOptions, InBuffer,
    OutBuffer, compress_bound,
};

/// A small generator, for inputs and the sizes of calls.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// `len` bytes that compress somewhat: words, runs and noise.
fn input(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed | 1);
    let words: [&[u8]; 6] = [
        b"archive ",
        b"thread ",
        b"frame ",
        b"\n",
        b"zstd ",
        b"hive ",
    ];
    let mut data = Vec::with_capacity(len);
    while data.len() < len {
        match rng.below(10) {
            0 => data.extend(std::iter::repeat_n(b'.', rng.below(300))),
            1 => data.extend((0..rng.below(200)).map(|_| rng.next() as u8)),
            _ => data.extend_from_slice(words[rng.below(words.len())]),
        }
    }
    data.truncate(len);
    data
}

/// `data` compressed in one call of each directive: with room for all.
fn compress(data: &[u8], options: &FramesOptions) -> Vec<u8> {
    let mut frames = CompressFrames::new(options).unwrap();
    let mut out = vec![0; compress_bound(data.len()).unwrap() + 4096];
    let mut output = OutBuffer::new(&mut out);
    let mut input = InBuffer::new(data);
    while frames
        .compress_stream(&mut output, &mut input, EndDirective::End)
        .unwrap()
        != 0
    {}
    let n = output.pos;
    assert_eq!(frames.total_in(), data.len() as u64);
    assert_eq!(frames.total_out(), n as u64);
    out.truncate(n);
    out
}

/// `data` compressed a little at a time: input given in pieces of random
/// sizes, output taken through a buffer of random sizes, some of 1 byte.
fn compress_in_bits(data: &[u8], options: &FramesOptions, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed | 1);
    let mut frames = CompressFrames::new(options).unwrap();
    let mut out = Vec::new();
    let mut buf = vec![0; 1 << 16];
    let mut at = 0;
    loop {
        let end = (at + rng.below(100_000)).min(data.len());
        let last = end == data.len();
        let directive = if last {
            EndDirective::End
        } else {
            EndDirective::Continue
        };
        let mut input = InBuffer::new(&data[at..end]);
        loop {
            let room = if rng.below(4) == 0 {
                1
            } else {
                1 + rng.below(buf.len() - 1)
            };
            let mut output = OutBuffer::new(&mut buf[..room]);
            let left = frames
                .compress_stream(&mut output, &mut input, directive)
                .unwrap();
            let n = output.pos;
            out.extend_from_slice(&buf[..n]);
            let done = if last {
                left == 0
            } else {
                input.pos == input.src.len()
            };
            if done {
                break;
            }
        }
        at = end;
        if last {
            return out;
        }
    }
}

/// What the frames should be: each piece of `frame_size` through
/// `CCtx::compress2`, at `level`, with a checksum; then the seek table.
fn expected(data: &[u8], level: i32, frame_size: usize) -> Vec<u8> {
    let mut cctx = CCtx::new();
    cctx.set_parameter(CParameter::CompressionLevel(level))
        .unwrap();
    cctx.set_parameter(CParameter::ChecksumFlag(true)).unwrap();
    let mut out = Vec::new();
    let mut entries = Vec::new();
    let pieces: Vec<&[u8]> = if data.is_empty() {
        vec![&[]]
    } else {
        data.chunks(frame_size).collect()
    };
    for piece in pieces {
        let mut frame = vec![0; compress_bound(piece.len()).unwrap()];
        let n = cctx.compress2(&mut frame, piece).unwrap();
        out.extend_from_slice(&frame[..n]);
        entries.push((n as u32, piece.len() as u32));
    }
    out.extend_from_slice(&0x184D_2A5Eu32.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32 * 8 + 9).to_le_bytes());
    for (c, d) in &entries {
        out.extend_from_slice(&c.to_le_bytes());
        out.extend_from_slice(&d.to_le_bytes());
    }
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    out.push(0);
    out.extend_from_slice(&0x8F92_EAB1u32.to_le_bytes());
    out
}

/// `data` decoded by this crate's streaming decoder, frame after frame.
fn decode(data: &[u8]) -> Vec<u8> {
    let mut dctx = DCtx::new();
    let mut out = Vec::new();
    let mut buf = vec![0; 1 << 17];
    let mut input = InBuffer::new(data);
    while input.pos < data.len() {
        let mut output = OutBuffer::new(&mut buf);
        dctx.decompress_stream(&mut output, &mut input).unwrap();
        let n = output.pos;
        out.extend_from_slice(&buf[..n]);
    }
    out
}

fn options(level: i32, frame_size: usize, threads: u32) -> FramesOptions {
    FramesOptions {
        level,
        frame_size,
        threads: Threads::of(threads),
        ..FramesOptions::default()
    }
}

#[test]
fn the_same_frames_whatever_the_threads_and_buffers() {
    let data = input(3_000_000, 7);
    for (level, frame_size) in [(1, 256 << 10), (3, 300_000), (9, 1 << 20), (19, 700_000)] {
        let want = expected(&data, level, frame_size);
        for threads in [1, 2, 3, 8] {
            let o = options(level, frame_size, threads);
            assert!(
                compress(&data, &o) == want,
                "level {level}, {threads} threads"
            );
            assert!(
                compress_in_bits(&data, &o, u64::from(threads) * 31 + level as u64) == want,
                "level {level}, {threads} threads, in bits"
            );
        }
        assert_eq!(decode(&want), data, "level {level}");
        assert_eq!(zstd::decode_all(&want[..]).unwrap(), data, "level {level}");
    }
}

#[test]
fn an_input_of_one_frame_or_none() {
    for data in [Vec::new(), b"hello".to_vec(), input(1 << 20, 3)] {
        let o = options(3, 1 << 20, 4);
        let made = compress(&data, &o);
        assert!(made == expected(&data, 3, 1 << 20), "{} bytes", data.len());
        assert_eq!(zstd::decode_all(&made[..]).unwrap(), data);
        assert_eq!(decode(&made), data);
    }
}

#[test]
fn libzstd_seekable_format_reads_the_seek_table() {
    use zstd_safe::seekable::Seekable;
    let data = input(2_500_000, 11);
    let frame_size = 256 << 10;
    let made = compress(&data, &options(3, frame_size, 4));
    let mut seekable = Seekable::create();
    seekable.init_buff(&made).unwrap();
    let frames = data.len().div_ceil(frame_size);
    assert_eq!(seekable.num_frames() as usize, frames);
    let mut at = 0u64;
    for i in 0..frames as u32 {
        assert_eq!(seekable.frame_compressed_offset(i).unwrap(), at);
        assert_eq!(
            seekable.frame_decompressed_offset(i).unwrap(),
            u64::from(i) * frame_size as u64
        );
        at += seekable.frame_compressed_size(i).unwrap() as u64;
    }
    // Reads from anywhere, a frame or two decoded.
    let mut rng = Rng(5);
    for _ in 0..20 {
        let from = rng.below(data.len() - 1000);
        let mut got = vec![0; 1 + rng.below(400_000.min(data.len() - from))];
        let n = seekable.decompress(&mut got[..], from as u64).unwrap();
        assert!(n > 0);
        assert!(got[..n] == data[from..from + n], "from {from}");
    }
}

#[test]
fn a_flush_ends_a_frame_and_no_seek_table_is_asked() {
    let data = input(500_000, 13);
    let mut frames = CompressFrames::new(&FramesOptions {
        seek_table: false,
        ..options(3, 1 << 20, 2)
    })
    .unwrap();
    let mut out = vec![0; 1 << 20];
    let mut output = OutBuffer::new(&mut out);
    let mut first = InBuffer::new(&data[..100_000]);
    while frames
        .compress_stream(&mut output, &mut first, EndDirective::Flush)
        .unwrap()
        != 0
    {}
    // A frame of its own: what was given so far decodes.
    let flushed = output.pos;
    let mut second = InBuffer::new(&data[100_000..]);
    while frames
        .compress_stream(&mut output, &mut second, EndDirective::End)
        .unwrap()
        != 0
    {}
    let n = output.pos;
    let made = &out[..n];
    assert_eq!(
        zstd::decode_all(&made[..flushed]).unwrap(),
        &data[..100_000]
    );
    assert_eq!(zstd::decode_all(made).unwrap(), data);
    // Two frames, nothing after them.
    let mut cctx = CCtx::new();
    cctx.set_parameter(CParameter::ChecksumFlag(true)).unwrap();
    let mut want = Vec::new();
    for piece in [&data[..100_000], &data[100_000..]] {
        let mut frame = vec![0; compress_bound(piece.len()).unwrap()];
        let n = cctx.compress2(&mut frame, piece).unwrap();
        want.extend_from_slice(&frame[..n]);
    }
    assert!(made == want);
}

#[test]
fn a_stream_after_the_end_is_another() {
    let (a, b) = (input(400_000, 17), input(300_000, 19));
    let o = options(3, 128 << 10, 3);
    let mut frames = CompressFrames::new(&o).unwrap();
    let mut out = vec![0; 2 << 20];
    let mut output = OutBuffer::new(&mut out);
    for data in [&a, &b] {
        let mut input = InBuffer::new(data);
        while frames
            .compress_stream(&mut output, &mut input, EndDirective::End)
            .unwrap()
            != 0
        {}
    }
    let n = output.pos;
    let mut want = expected(&a, 3, 128 << 10);
    want.extend(expected(&b, 3, 128 << 10));
    assert!(out[..n] == want);
}

#[test]
fn out_of_order_calls_and_sizes_are_refused() {
    let data = input(300_000, 23);
    let mut frames = CompressFrames::new(&options(3, 1 << 20, 2)).unwrap();
    let mut out = [0u8; 16];
    let mut output = OutBuffer::new(&mut out);
    let mut input = InBuffer::new(&data);
    // The end begun, and not done: with little room for output.
    assert_ne!(
        frames
            .compress_stream(&mut output, &mut input, EndDirective::End)
            .unwrap(),
        0
    );
    let mut output = OutBuffer::new(&mut out);
    let e = frames
        .compress_stream(&mut output, &mut input, EndDirective::Continue)
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::StageWrong);
    // Refused, and nothing lost: the end goes on, as libzstd's does.
    let mut made = out[..16].to_vec();
    loop {
        let mut output = OutBuffer::new(&mut out);
        let left = frames
            .compress_stream(&mut output, &mut input, EndDirective::End)
            .unwrap();
        let n = output.pos;
        made.extend_from_slice(&out[..n]);
        if left == 0 {
            break;
        }
    }
    assert_eq!(zstd::decode_all(&made[..]).unwrap(), data);

    let too_large = FramesOptions {
        frame_size: (1 << 30) + 1,
        ..FramesOptions::default()
    };
    assert_eq!(
        CompressFrames::new(&too_large).unwrap_err().code(),
        ErrorCode::ParameterOutOfBound
    );
}

#[test]
fn a_memory_limit_lowers_the_threads() {
    let o = options(19, 0, 16);
    let one = o.memory_usage(1).unwrap();
    let two = o.memory_usage(2).unwrap();
    assert!(two > one);
    // A frame's input and room for it, and a context of level 19, each thread.
    assert!(two - one > 64 << 20, "{} a thread", two - one);
    assert_eq!(o.threads_used().unwrap(), 16);
    let limited = FramesOptions {
        memory_limit: o.memory_usage(3).unwrap(),
        ..o
    };
    assert_eq!(limited.threads_used().unwrap(), 3);
    let none = FramesOptions {
        memory_limit: 1,
        ..o
    };
    assert_eq!(none.threads_used().unwrap(), 1);
    assert_eq!(CompressFrames::new(&none).unwrap().threads(), 1);
}
