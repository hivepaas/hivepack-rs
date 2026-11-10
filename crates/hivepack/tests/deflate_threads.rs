//! Deflate in threads, as pigz does it (`deflate::DeflateMt`): the same
//! output whatever the threads and the buffers, pigz's byte for byte where
//! pigz is installed, read back by the port's inflate and by `gzip`, with
//! flushes that leave what was given readable. With libdeflate's
//! compressor (`Library::Libdeflate`), the same, and the stream is its
//! blocks compressed one by one, joined.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "threads_support/mod.rs"]
mod threads_support;

use std::io::Write;
use std::process::{Command, Stdio};

use hivepack::Threads;
use hivepack::deflate::{
    BLOCK_SIZE, Compressor, DeflateMt, ErrorCode, Flush, InBuffer, Inflate, LIBDEFLATE_BLOCK_SIZE,
    Library, MtOptions, OutBuffer, Status, Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY, Z_FILTERED,
    Z_FIXED, Z_HUFFMAN_ONLY, Z_RLE, crc32,
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
        b"block ",
        b"\n",
        b"deflate ",
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

fn threads() -> Vec<Threads> {
    threads_support::chosen([Threads::One, Threads::of(2), Threads::of(8), Threads::Auto])
}

/// Room for `len` bytes compressed, header and trailer.
fn room(len: usize) -> usize {
    len + len / 100 + (64 << 10)
}

/// `data` compressed in one call with `Flush::Finish`, with room for all.
fn compress(data: &[u8], options: &MtOptions) -> Vec<u8> {
    let mut mt = DeflateMt::new(options).unwrap();
    let mut out = vec![0; room(data.len())];
    let mut output = OutBuffer::new(&mut out);
    let mut input = InBuffer::new(data);
    let status = mt.deflate(&mut output, &mut input, Flush::Finish).unwrap();
    assert_eq!(status, Status::StreamEnd);
    let n = output.pos;
    assert_eq!(mt.total_in(), data.len() as u64);
    assert_eq!(mt.total_out(), n as u64);
    out.truncate(n);
    out
}

/// `data` compressed a little at a time: input given in pieces of random
/// sizes, output taken through a buffer of random sizes, some of 1 byte.
/// Each call reads all its input, or fills its output.
fn compress_in_bits(data: &[u8], options: &MtOptions, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed | 1);
    let mut mt = DeflateMt::new(options).unwrap();
    let mut out = Vec::new();
    let mut buf = vec![0; 1 << 16];
    let mut at = 0;
    loop {
        let end = (at + rng.below(100_000)).min(data.len());
        let finish = end == data.len();
        let flush = if finish {
            Flush::Finish
        } else {
            Flush::NoFlush
        };
        let mut input = InBuffer::new(&data[at..end]);
        loop {
            let room = if rng.below(4) == 0 {
                1
            } else {
                1 + rng.below(buf.len())
            };
            let mut output = OutBuffer::new(&mut buf[..room]);
            let status = mt.deflate(&mut output, &mut input, flush).unwrap();
            let (made, full) = (output.pos, output.pos == room);
            out.extend_from_slice(&buf[..made]);
            if status == Status::StreamEnd {
                assert_eq!(at + input.pos, data.len());
                return out;
            }
            assert!(full || input.pos == input.src.len(), "returned early");
            if !full && !finish {
                break;
            }
        }
        at = end;
    }
}

/// What the port's inflate reads of `stream`: gzip, or raw deflate.
fn inflate(stream: &[u8], raw: bool) -> Vec<u8> {
    let mut inflate = Inflate::new(if raw { -15 } else { 31 }).unwrap();
    let mut out = Vec::new();
    let mut buf = vec![0; 1 << 16];
    let mut input = InBuffer::new(stream);
    loop {
        let mut output = OutBuffer::new(&mut buf);
        let status = inflate
            .inflate(&mut output, &mut input, Flush::NoFlush)
            .unwrap();
        let made = output.pos;
        out.extend_from_slice(&buf[..made]);
        if status == Status::StreamEnd {
            assert_eq!(input.pos, stream.len(), "bytes after the stream");
            return out;
        }
        assert!(made > 0 || input.pos < stream.len(), "cut short");
    }
}

#[test]
fn the_output_is_the_same_whatever_the_threads_and_the_buffers() {
    let sizes = [
        0,
        1,
        1000,
        (32 << 10) - 1,
        BLOCK_SIZE - 1,
        BLOCK_SIZE,
        BLOCK_SIZE + 1,
        3 * BLOCK_SIZE,
        5 * BLOCK_SIZE + 12_345,
    ];
    for (i, &size) in sizes.iter().enumerate() {
        let data = input(size, i as u64 + 1);
        for (level, strategy, block_size) in [
            (Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY, 0),
            (0, Z_DEFAULT_STRATEGY, 0),
            (1, Z_DEFAULT_STRATEGY, 0),
            (9, Z_DEFAULT_STRATEGY, 0),
            (6, Z_FILTERED, 0),
            (6, Z_HUFFMAN_ONLY, 0),
            (6, Z_RLE, 0),
            (6, Z_FIXED, 0),
            (6, Z_DEFAULT_STRATEGY, 1000),
            (6, Z_DEFAULT_STRATEGY, 50_000),
        ] {
            let mut want = None;
            for threads in threads() {
                let options = MtOptions {
                    level,
                    strategy,
                    threads,
                    block_size,
                    ..MtOptions::default()
                };
                let what = format!("{size} bytes, {options:?}");
                let whole = compress(&data, &options);
                let bits = compress_in_bits(&data, &options, size as u64 + 7);
                assert_eq!(whole, bits, "{what}: in bits");
                assert_eq!(inflate(&whole, false), data, "{what}: read back");
                match &want {
                    None => want = Some(whole),
                    Some(want) => assert_eq!(&whole, want, "{what}"),
                }
            }
        }
    }
}

#[test]
fn the_member_is_gzip_s() {
    let data = input(3 * BLOCK_SIZE + 99, 5);
    for (level, xfl) in [(1, 4), (2, 0), (6, 0), (9, 2)] {
        let gz = compress(
            &data,
            &MtOptions {
                level,
                threads: Threads::of(4),
                ..MtOptions::default()
            },
        );
        assert_eq!(&gz[..8], [0x1f, 0x8b, 8, 0, 0, 0, 0, 0], "level {level}");
        assert_eq!(gz[8], xfl, "level {level}");
        let n = gz.len();
        assert_eq!(gz[n - 8..n - 4], crc32(0, &data).to_le_bytes());
        assert_eq!(gz[n - 4..], (data.len() as u32).to_le_bytes());
        // Raw: the same stream, without the header and the trailer.
        let raw = compress(
            &data,
            &MtOptions {
                level,
                raw: true,
                threads: Threads::of(4),
                ..MtOptions::default()
            },
        );
        assert_eq!(raw, gz[10..n - 8], "level {level}");
        assert_eq!(inflate(&raw, true), data);
    }
}

#[test]
fn an_empty_input_is_an_empty_block() {
    let gz = compress(&[], &MtOptions::default());
    assert_eq!(gz[10..], [3, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let raw = compress(
        &[],
        &MtOptions {
            raw: true,
            ..MtOptions::default()
        },
    );
    assert_eq!(raw, [3, 0]);
}

/// `data` compressed with a flush after each of `cuts`; with what was
/// written at each flush.
fn compress_flushed(
    data: &[u8],
    cuts: &[usize],
    flush: Flush,
    options: &MtOptions,
) -> (Vec<u8>, Vec<usize>) {
    let mut mt = DeflateMt::new(options).unwrap();
    let mut out = Vec::new();
    let mut ends = Vec::new();
    let mut buf = vec![0; 1000];
    let mut at = 0;
    for &cut in cuts.iter().chain([&data.len()]) {
        let last = cut == data.len();
        let mut input = InBuffer::new(&data[at..cut]);
        loop {
            let mut output = OutBuffer::new(&mut buf);
            let status = mt
                .deflate(
                    &mut output,
                    &mut input,
                    if last { Flush::Finish } else { flush },
                )
                .unwrap();
            let made = output.pos;
            out.extend_from_slice(&buf[..made]);
            if status == Status::StreamEnd || (!last && made < buf.len()) {
                break;
            }
        }
        assert_eq!(input.pos, cut - at);
        ends.push(out.len());
        at = cut;
    }
    (out, ends)
}

/// What inflate reads of `part`, which ends where a flush did.
fn inflate_part(part: &[u8], raw: bool) -> Vec<u8> {
    let mut inflate = Inflate::new(if raw { -15 } else { 31 }).unwrap();
    let mut out = vec![0; 4 << 20];
    let mut output = OutBuffer::new(&mut out);
    let mut input = InBuffer::new(part);
    let status = inflate
        .inflate(&mut output, &mut input, Flush::SyncFlush)
        .unwrap();
    assert_eq!(status, Status::Ok);
    assert_eq!(input.pos, part.len());
    let n = output.pos;
    out.truncate(n);
    out
}

#[test]
fn a_flush_leaves_what_was_given_readable() {
    let data = input(4 * BLOCK_SIZE, 11);
    let cuts = [
        10,
        5000,
        5000,
        BLOCK_SIZE + 7,
        2 * BLOCK_SIZE,
        3 * BLOCK_SIZE + 1,
    ];
    for flush in [Flush::SyncFlush, Flush::FullFlush] {
        let mut want = None;
        for threads in threads() {
            let options = MtOptions {
                threads,
                ..MtOptions::default()
            };
            let (gz, ends) = compress_flushed(&data, &cuts, flush, &options);
            assert_eq!(inflate(&gz, false), data, "{flush:?}");
            for (&cut, &end) in cuts.iter().zip(&ends) {
                assert_eq!(
                    inflate_part(&gz[..end], false),
                    data[..cut],
                    "{flush:?} at {cut}"
                );
            }
            // After a full flush, what follows needs nothing before it.
            if flush == Flush::FullFlush {
                for (&cut, &end) in cuts.iter().zip(&ends) {
                    let rest = inflate(&gz[end..gz.len() - 8], true);
                    assert_eq!(rest, data[cut..], "after {cut}");
                }
            }
            match &want {
                None => want = Some(gz),
                Some(want) => assert_eq!(&gz, want, "{flush:?}, {threads:?}"),
            }
        }
    }
}

#[test]
fn calls_are_checked() {
    let mut mt = DeflateMt::new(&MtOptions::default()).unwrap();
    let mut buf = vec![0; 1 << 16];
    for flush in [Flush::PartialFlush, Flush::Block, Flush::Trees] {
        let mut output = OutBuffer::new(&mut buf);
        let e = mt
            .deflate(&mut output, &mut InBuffer::new(b"abc"), flush)
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::Stream);
    }
    // Refused calls change nothing.
    let mut input = InBuffer::new(b"hello");
    let mut output = OutBuffer::new(&mut buf[..5]);
    let status = mt.deflate(&mut output, &mut input, Flush::Finish).unwrap();
    assert_eq!(status, Status::Ok);
    let mut output = OutBuffer::new(&mut buf[5..]);
    let e = mt
        .deflate(&mut output, &mut input, Flush::NoFlush)
        .unwrap_err();
    assert_eq!((e.code(), output.pos), (ErrorCode::Stream, 0));
    let mut output = OutBuffer::new(&mut buf[5..]);
    let status = mt.deflate(&mut output, &mut input, Flush::Finish).unwrap();
    assert_eq!(status, Status::StreamEnd);
    let n = 5 + output.pos;
    assert_eq!(inflate(&buf[..n], false), b"hello");
    let mut output = OutBuffer::new(&mut buf);
    let status = mt
        .deflate(&mut output, &mut InBuffer::new(b""), Flush::Finish)
        .unwrap();
    assert_eq!((status, output.pos), (Status::StreamEnd, 0));

    for options in [
        MtOptions {
            level: 10,
            ..MtOptions::default()
        },
        MtOptions {
            level: -2,
            ..MtOptions::default()
        },
        MtOptions {
            strategy: Z_FIXED + 1,
            ..MtOptions::default()
        },
        MtOptions {
            block_size: (1 << 30) + 1,
            ..MtOptions::default()
        },
    ] {
        let e = DeflateMt::new(&options).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Stream, "{options:?}");
        assert!(options.memory_usage(1).is_err());
    }

    fn send<T: Send>(_: &T) {}
    send(&mt);
}

#[test]
fn a_memory_limit_lowers_the_threads() {
    let options = MtOptions {
        threads: Threads::of(8),
        ..MtOptions::default()
    };
    assert_eq!(options.threads_used().unwrap(), 8);
    let one = options.memory_usage(1).unwrap();
    let three = options.memory_usage(3).unwrap();
    assert!(one < three && three < 2 << 20 << 2, "{one} {three}");
    for (limit, threads) in [(0, 1), (one, 1), (three, 3), (three - 1, 2), (u64::MAX, 8)] {
        let limited = MtOptions {
            memory_limit: limit,
            ..options
        };
        assert_eq!(limited.threads_used().unwrap(), threads, "{limit}");
        assert_eq!(DeflateMt::new(&limited).unwrap().threads(), threads);
    }
}

/// What `tool` with `args` writes of `stdin`; none if it is not installed.
fn run(tool: &str, args: &[&str], stdin: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let mut writer = child.stdin.take().unwrap();
    let stdin = stdin.to_vec();
    let feeder = std::thread::spawn(move || writer.write_all(&stdin));
    let output = child.wait_with_output().unwrap();
    feeder.join().unwrap().unwrap();
    assert!(output.status.success(), "{tool} {args:?}: {output:?}");
    Some(output.stdout)
}

#[test]
fn gzip_reads_it() {
    let data = input(3 * BLOCK_SIZE + 5, 13);
    let gz = compress(
        &data,
        &MtOptions {
            threads: Threads::of(4),
            ..MtOptions::default()
        },
    );
    match run("gzip", &["-dc"], &gz) {
        Some(out) => assert_eq!(out, data),
        None => eprintln!("gzip is not installed: skipped"),
    }
}

#[test]
fn it_is_pigz_s_byte_for_byte() {
    // Its header has no name nor time with -n, and says Unix wherever it
    // runs; the rest is the same.
    for (i, size) in [
        0,
        1,
        1000,
        BLOCK_SIZE,
        2 * BLOCK_SIZE,
        7 * BLOCK_SIZE + 3333,
    ]
    .into_iter()
    .enumerate()
    {
        let data = input(size, 20 + i as u64);
        for level in [1, 2, 6, 9] {
            let Some(pigz) = run(
                "pigz",
                &["-n", "-c", "-p", "3", &format!("-{level}")],
                &data,
            ) else {
                eprintln!("pigz is not installed: skipped");
                return;
            };
            let gz = compress(
                &data,
                &MtOptions {
                    level,
                    threads: Threads::of(3),
                    ..MtOptions::default()
                },
            );
            assert_eq!(gz[..9], pigz[..9], "{size} bytes, level {level}");
            assert_eq!(gz[10..], pigz[10..], "{size} bytes, level {level}");
        }
    }
}

/// libdeflate's options at `level`, in `threads`, with blocks of
/// `block_size` (0 for the default).
fn libdeflate(level: i32, threads: Threads, block_size: usize) -> MtOptions {
    MtOptions {
        level,
        threads,
        block_size,
        library: Library::Libdeflate,
        ..MtOptions::default()
    }
}

/// The raw stream libdeflate's blocks make of `data`, compressed one by
/// one: every block but the last a part, then the last.
fn libdeflate_joined(data: &[u8], level: i32, block_size: usize) -> Vec<u8> {
    let mut compressor = Compressor::new(level).unwrap();
    let mut stream = Vec::new();
    let mut blocks: Vec<&[u8]> = data.chunks(block_size).collect();
    let last = blocks.pop().unwrap_or(&[]);
    for block in blocks {
        let mut out = vec![0; compressor.deflate_compress_part_bound(block.len())];
        let n = compressor.deflate_compress_part(block, &mut out);
        stream.extend_from_slice(&out[..n]);
    }
    let mut out = vec![0; compressor.deflate_compress_bound(last.len())];
    let n = compressor.deflate_compress(last, &mut out);
    stream.extend_from_slice(&out[..n]);
    stream
}

#[test]
fn libdeflate_is_the_same_whatever_the_threads_and_the_buffers() {
    const MIB: usize = LIBDEFLATE_BLOCK_SIZE;
    let sizes = [0, 1, 1000, MIB - 1, MIB, MIB + 1, 3 * MIB + 12_345];
    for (i, &size) in sizes.iter().enumerate() {
        let data = input(size, i as u64 + 31);
        let mut cases = vec![(Z_DEFAULT_COMPRESSION, 0), (1, 0), (12, 0), (9, 50_000)];
        if size <= MIB + 1 {
            cases.extend([(0, 0), (6, 0), (10, 0), (11, 0), (6, 1000)]);
        }
        for (level, block_size) in cases {
            let mut want = None;
            for threads in threads() {
                let mut options = libdeflate(level, threads, block_size);
                options.raw = true;
                let what = format!("{size} bytes, {options:?}");
                let whole = compress(&data, &options);
                let bits = compress_in_bits(&data, &options, size as u64 + 7);
                assert!(whole == bits, "{what}: in bits");
                assert!(inflate(&whole, true) == data, "{what}: read back");
                match &want {
                    None => {
                        let block = if block_size == 0 { MIB } else { block_size };
                        let joined = libdeflate_joined(&data, level, block);
                        assert!(whole == joined, "{what}: not its blocks joined");
                        want = Some(whole);
                    }
                    Some(want) => assert!(&whole == want, "{what}"),
                }
            }
        }
    }
}

#[test]
fn libdeflate_s_member_is_gzip_s() {
    let data = input(2 * LIBDEFLATE_BLOCK_SIZE + 99, 35);
    for (level, xfl) in [(0, 4), (1, 4), (2, 0), (7, 0), (8, 2), (12, 2)] {
        let gz = compress(&data, &libdeflate(level, Threads::of(4), 0));
        assert_eq!(&gz[..8], [0x1f, 0x8b, 8, 0, 0, 0, 0, 0], "level {level}");
        assert_eq!(gz[8], xfl, "level {level}");
        let n = gz.len();
        assert_eq!(gz[n - 8..n - 4], crc32(0, &data).to_le_bytes());
        assert_eq!(gz[n - 4..], (data.len() as u32).to_le_bytes());
        let mut options = libdeflate(level, Threads::of(4), 0);
        options.raw = true;
        let raw = compress(&data, &options);
        assert!(raw == gz[10..n - 8], "level {level}");
        assert!(inflate(&gz, false) == data);
        // Reading it is no business of the compressor's: gzip reads it.
        if level == 12
            && let Some(out) = run("gzip", &["-dc"], &gz)
        {
            assert!(out == data);
        }
    }
    // An empty input is libdeflate's empty stream: a stored block, final.
    let mut options = libdeflate(12, Threads::One, 0);
    options.raw = true;
    assert_eq!(compress(&[], &options), [1, 0, 0, 0xFF, 0xFF]);
}

#[test]
fn libdeflate_flushes_leave_what_was_given_readable() {
    let data = input(3 * LIBDEFLATE_BLOCK_SIZE, 37);
    let cuts = [
        10,
        5000,
        5000,
        LIBDEFLATE_BLOCK_SIZE + 7,
        2 * LIBDEFLATE_BLOCK_SIZE,
    ];
    for flush in [Flush::SyncFlush, Flush::FullFlush] {
        let mut want = None;
        for threads in threads() {
            let options = libdeflate(9, threads, 0);
            let (gz, ends) = compress_flushed(&data, &cuts, flush, &options);
            assert!(inflate(&gz, false) == data, "{flush:?}");
            for (&cut, &end) in cuts.iter().zip(&ends) {
                assert!(
                    inflate_part(&gz[..end], false) == data[..cut],
                    "{flush:?} at {cut}"
                );
                // Each block alone: what follows any flush needs nothing
                // before it.
                let rest = inflate(&gz[end..gz.len() - 8], true);
                assert!(rest == data[cut..], "after {cut}");
            }
            match &want {
                None => want = Some(gz),
                Some(want) => assert!(&gz == want, "{flush:?}, {threads:?}"),
            }
        }
    }
}

#[test]
fn libdeflate_options_are_checked() {
    for level in [-1, 0, 1, 9, 10, 12] {
        let options = libdeflate(level, Threads::One, 0);
        assert!(DeflateMt::new(&options).is_ok(), "{level}");
    }
    for options in [
        libdeflate(13, Threads::One, 0),
        libdeflate(-2, Threads::One, 0),
        MtOptions {
            strategy: Z_FILTERED,
            ..libdeflate(6, Threads::One, 0)
        },
        libdeflate(6, Threads::One, (1 << 30) + 1),
    ] {
        let e = DeflateMt::new(&options).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Stream, "{options:?}");
        assert!(options.memory_usage(1).is_err());
    }
}

#[test]
fn libdeflate_memory_is_counted_by_level() {
    let usage = |level| {
        libdeflate(level, Threads::of(8), 0)
            .memory_usage(1)
            .unwrap()
    };
    // A block of 1 MiB, its room twice, and libdeflate's compressor: 0.2,
    // 0.7 and 9 MB.
    assert!(usage(1) < usage(6) && usage(6) < usage(12));
    assert!(usage(12) - usage(6) > 7 << 20, "{} {}", usage(12), usage(6));
    let options = libdeflate(12, Threads::of(8), 0);
    let one = options.memory_usage(1).unwrap();
    let three = options.memory_usage(3).unwrap();
    for (limit, threads) in [(0, 1), (one, 1), (three, 3), (three - 1, 2), (u64::MAX, 8)] {
        let limited = MtOptions {
            memory_limit: limit,
            ..options
        };
        assert_eq!(limited.threads_used().unwrap(), threads, "{limit}");
        assert_eq!(DeflateMt::new(&limited).unwrap().threads(), threads);
    }
}
