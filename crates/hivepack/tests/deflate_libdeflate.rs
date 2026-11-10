//! Comparison of `hivepack::deflate::Compressor` with libdeflate 1.26's
//! compressor, through `tools/libdeflate-oracle`.
//!
//! The oracle is a small C program built with libdeflate's sources by
//! `scripts/testdata.py`. It answers requests such as `compress 12
//! 1000,57,0 68656c6c6f...` by compressing the bytes at that level into
//! buffers of each size, with one compressor per level kept from one
//! request to the next. [`answer`] answers the same requests with the port,
//! in the same format, so the two can be compared as text: what each call
//! returned, and a hash of the bytes it wrote.
//!
//! The inputs are generated: text, random bytes, runs, repeated pieces,
//! matches of the longest length, small alphabets, records, text with
//! bytes changed, prefixes of one string, words of three bytes, and pieces
//! of each joined, which move the blocks' ends; from no bytes to a few MB,
//! sizes about where blocks end, and inputs that fill the parsers'
//! sequences and the near-optimal parser's match cache. Each is compressed
//! at every level, into buffers of the bound, of exactly the size needed,
//! of one byte less and one more, of a few bytes, and of sizes at random
//! below. Every stream must also inflate back to its input with hivepack's
//! own `Inflate`.
//!
//! `HIVEPACK_LIBDEFLATE_INPUTS` sets how many inputs of each kind are
//! compared (12 by default), and `HIVEPACK_LIBDEFLATE_SEED` the seed, for
//! longer runs by hand.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "deflate_support/mod.rs"]
mod support;

use std::fmt::Write as _;

use hivepack::deflate::{Compressor, Flush, InBuffer, Inflate, OutBuffer, Status};
use support::{Oracle, Rng, fnv64, hex, repository};

/// Every level libdeflate takes, -1 (its default, 6) among them.
const LEVELS: [i32; 14] = [-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

/// Inflates a raw deflate stream that should hold `want`.
fn inflate(stream: &[u8], want: &[u8]) -> Vec<u8> {
    let mut inflate = Inflate::new(-15).unwrap();
    let mut out = vec![0u8; want.len() + 1];
    let mut output = OutBuffer::new(&mut out);
    let mut input = InBuffer::new(stream);
    let status = inflate.inflate(&mut output, &mut input, Flush::Finish);
    let written = output.pos;
    assert_eq!(status, Ok(Status::StreamEnd), "the stream does not end");
    assert_eq!(input.pos, stream.len(), "bytes after the stream");
    out.truncate(written);
    out
}

/// The port's answer to `compress <level> <capacities> <data>`, in the
/// oracle's format. Each stream that fits is inflated back.
fn answer(
    compressors: &mut [Option<Compressor>],
    level: i32,
    capacities: &[usize],
    data: &[u8],
) -> String {
    let Some(compressor) = &mut compressors[(level + 1) as usize] else {
        return "null".into();
    };
    let mut text = String::from("ok");
    let mut done: Option<(usize, u64)> = None;
    for &capacity in capacities {
        let mut out = vec![0xA5u8; capacity];
        let ret = compressor.deflate_compress(data, &mut out);
        let hash = fnv64(&out[..ret]);
        let _ = write!(text, " {ret}/{hash:016x}");
        if ret == 0 {
            continue;
        }
        // Whatever the room, a stream that fits is the same.
        match done {
            Some(first) => assert_eq!(first, (ret, hash), "level {level}, room {capacity}"),
            None => {
                assert!(
                    inflate(&out[..ret], data) == data,
                    "level {level}: inflates to other bytes"
                );
                done = Some((ret, hash));
            }
        }
    }
    text
}

fn request(level: i32, capacities: &[usize], data: &[u8]) -> String {
    let capacities: Vec<String> = capacities.iter().map(usize::to_string).collect();
    format!("compress {level} {} {}", capacities.join(","), hex(data))
}

const WORDS: [&str; 24] = [
    "the",
    "deflate",
    "block",
    "window",
    "of",
    "a",
    "match",
    "\n",
    "libdeflate",
    ", ",
    "Huffman",
    "code",
    "literal",
    "length",
    "offset",
    ". ",
    "zlib",
    "near-optimal",
    "parser",
    " ",
    "and",
    "cost",
    "\t",
    "hash",
];

/// A number below one of `limits`, chosen at random: sizes spread over
/// several scales.
fn below_one_of(rng: &mut Rng, limits: &[u64]) -> u64 {
    let limit = rng.pick(limits);
    rng.below(limit)
}

/// Text from a vocabulary.
fn text(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len + 16);
    while data.len() < len {
        data.extend_from_slice(rng.pick(&WORDS).as_bytes());
        if rng.below(9) == 0 {
            data.push(b' ');
        }
    }
    data.truncate(len);
    data
}

/// How many kinds of data `piece` makes.
const KINDS: u64 = 10;

/// One kind of data, `len` bytes of it.
fn piece(rng: &mut Rng, kind: u64, len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len + 300);
    match kind {
        // Text.
        0 => data = text(rng, len),
        // Random bytes.
        1 => data.extend((0..len).map(|_| rng.next() as u8)),
        // Runs of a byte, short and long.
        2 => {
            while data.len() < len {
                let random = rng.next() as u8;
                let byte = rng.pick(&[0u8, 0xFF, b'a', random]);
                let run = 1 + below_one_of(rng, &[4, 40, 600, 70_000]) as usize;
                data.extend(std::iter::repeat_n(byte, run));
            }
        }
        // A piece repeated, now and then changed: many matches, of every
        // length up to the longest.
        3 => {
            let period = 1 + below_one_of(rng, &[8, 300, 5000, 40_000]) as usize;
            let seed: Vec<u8> = (0..period).map(|_| rng.next() as u8).collect();
            let change = rng.pick(&[0, 50, 1000, 30_000]);
            while data.len() < len {
                let at = data.len() % period;
                let mut byte = seed[at];
                if change != 0 && rng.below(change) == 0 {
                    byte = rng.next() as u8;
                }
                data.push(byte);
            }
        }
        // Matches of 258 bytes and more, from near and far.
        4 => {
            let block: Vec<u8> = (0..rng.pick(&[259, 300, 1000, 33_000]))
                .map(|_| rng.next() as u8)
                .collect();
            while data.len() < len {
                data.extend_from_slice(&block);
                data.extend((0..rng.below(4)).map(|_| rng.next() as u8));
            }
        }
        // A small alphabet, as DNA: literals cheap, short matches not.
        5 => {
            let letters = rng.pick(&[&b"ACGT"[..], b"01", b"abcdefgh"]);
            data.extend((0..len).map(|_| letters[rng.below(letters.len() as u64) as usize]));
        }
        // Records: numbers that grow, with a little text.
        6 => {
            let mut n: u32 = rng.next() as u32;
            while data.len() < len {
                n = n.wrapping_add(1 + below_one_of(rng, &[2, 300, 70_000]) as u32);
                data.extend_from_slice(&n.to_le_bytes());
                data.extend_from_slice(&(n as u16).to_be_bytes());
                if rng.below(3) == 0 {
                    data.extend_from_slice(rng.pick(&WORDS).as_bytes());
                }
            }
        }
        // Prefixes of one string, each a byte longer than the last: at each
        // position, matches of many lengths, which fill the near-optimal
        // parser's match cache before its block is long.
        8 => {
            let prefix: Vec<u8> = (0..250).map(|_| rng.next() as u8).collect();
            let longest = 2 + rng.below(248) as usize;
            'fill: loop {
                for k in 1..longest {
                    if data.len() >= len {
                        break 'fill;
                    }
                    data.extend_from_slice(&prefix[..k]);
                    data.push(rng.next() as u8);
                }
            }
        }
        // Words of three bytes from a few dozen: matches of three to five
        // bytes, close, many enough to fill the greedy and lazy parsers'
        // sequences before their block is long.
        9 => {
            let words: Vec<[u8; 3]> = (0..1 + rng.below(64))
                .map(|_| [rng.next() as u8, rng.next() as u8, rng.next() as u8])
                .collect();
            while data.len() < len {
                data.extend_from_slice(&words[rng.below(words.len() as u64) as usize]);
            }
        }
        // Text with bytes changed: matches of many lengths at each position.
        _ => {
            data = text(rng, len);
            let changes = len / rng.pick(&[7, 60, 900]).max(1);
            for _ in 0..changes {
                if !data.is_empty() {
                    let at = rng.below(data.len() as u64) as usize;
                    data[at] = rng.next() as u8;
                }
            }
        }
    }
    data.truncate(len);
    data
}

/// An input of about `len` bytes: one kind, or pieces of several, whose
/// changes the block splitting has to find.
fn input(rng: &mut Rng, len: usize) -> Vec<u8> {
    if rng.below(3) != 0 || len < 64 {
        let kind = rng.below(KINDS);
        return piece(rng, kind, len);
    }
    let mut data = Vec::with_capacity(len);
    while data.len() < len {
        let size = (1 + below_one_of(rng, &[2000, 20_000, 200_000]) as usize).min(len - data.len());
        let kind = rng.below(KINDS);
        data.extend(piece(rng, kind, size));
    }
    data
}

/// The sizes of output buffer to try for `data`: the bound, exactly what
/// the stream takes, one byte less, one more, none, a few bytes, and some
/// at random below the size. Fewer for large inputs, which take long at
/// every size.
fn capacities(rng: &mut Rng, compressor: &mut Compressor, data: &[u8]) -> Vec<usize> {
    let bound = compressor.deflate_compress_bound(data.len());
    let mut out = vec![0u8; bound];
    let exact = compressor.deflate_compress(data, &mut out);
    assert!(exact > 0, "the bound is too small for {} bytes", data.len());
    let mut sizes = vec![bound, exact, exact - 1];
    if data.len() > 1 << 20 {
        sizes.push(exact / 2);
        return sizes;
    }
    sizes.extend([exact + 1, 0, 1, 4, 5, 6]);
    for _ in 0..3 {
        sizes.push(rng.below(exact as u64) as usize);
    }
    sizes
}

fn compressors() -> Vec<Option<Compressor>> {
    LEVELS.iter().map(|&level| Compressor::new(level)).collect()
}

/// Compares `data` at every level; returns how many calls were compared.
fn compare(
    oracle: &mut Oracle,
    rng: &mut Rng,
    compressors: &mut [Option<Compressor>],
    name: &str,
    data: &[u8],
) -> usize {
    let mut compared = 0;
    for level in LEVELS {
        let Some(compressor) = &mut compressors[(level + 1) as usize] else {
            panic!("level {level}");
        };
        let sizes = capacities(rng, compressor, data);
        let want = oracle.ask(&request(level, &sizes, data));
        let got = answer(compressors, level, &sizes, data);
        if want != got {
            // Where the streams part, for the report.
            let exact = sizes[1];
            let theirs = oracle.ask(&format!("output {level} {exact} {}", hex(data)));
            let mut out = vec![0u8; exact];
            let compressor = compressors[(level + 1) as usize].as_mut().unwrap();
            let ours = compressor.deflate_compress(data, &mut out);
            let theirs_hex = theirs.split(' ').nth(1).unwrap_or("-");
            let ours_hex = hex(&out[..ours]);
            let parted = theirs_hex
                .bytes()
                .zip(ours_hex.bytes())
                .position(|(a, b)| a != b)
                .unwrap_or(theirs_hex.len().min(ours_hex.len()))
                / 2;
            panic!(
                "{name} ({} bytes), level {level}, rooms {sizes:?}:\n libdeflate {want}\n port       {got}\n the streams part at byte {parted}",
                data.len()
            );
        }
        compared += sizes.len();
    }
    compared
}

fn seed_and_count() -> (u64, usize) {
    let seed = std::env::var("HIVEPACK_LIBDEFLATE_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0x1DEF_1A7E);
    let count = std::env::var("HIVEPACK_LIBDEFLATE_INPUTS")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(12);
    (seed, count)
}

#[test]
fn small_inputs_match_libdeflate() {
    let Some(mut oracle) = Oracle::spawn_named("libdeflate-oracle") else {
        return;
    };
    let (seed, count) = seed_and_count();
    let mut rng = Rng(seed);
    let mut compressors = compressors();
    let mut compared = 0;
    // Every size up to past the largest that is not compressed (51, at
    // level 1), then more at random below the shortest block.
    for len in 0..64 {
        let data = input(&mut rng, len);
        compared += compare(&mut oracle, &mut rng, &mut compressors, "tiny", &data);
    }
    for _ in 0..count * 8 {
        let len = below_one_of(&mut rng, &[300, 5000, 12_000]) as usize;
        let data = input(&mut rng, len);
        compared += compare(&mut oracle, &mut rng, &mut compressors, "small", &data);
    }
    eprintln!("{compared} calls compared");
}

#[test]
fn medium_inputs_match_libdeflate() {
    let Some(mut oracle) = Oracle::spawn_named("libdeflate-oracle") else {
        return;
    };
    let (seed, count) = seed_and_count();
    let mut rng = Rng(seed ^ 0x55);
    let mut compressors = compressors();
    let mut compared = 0;
    for _ in 0..count * 2 {
        let len = 12_000 + below_one_of(&mut rng, &[70_000, 400_000, 700_000]) as usize;
        let data = input(&mut rng, len);
        compared += compare(&mut oracle, &mut rng, &mut compressors, "medium", &data);
    }
    eprintln!("{compared} calls compared");
}

/// Sizes about where blocks end: an uncompressed block's longest, the
/// shortest block, the longest of the fastest compressor's, and the soft
/// longest of the others' with the shortest after it.
#[test]
fn block_sizes_match_libdeflate() {
    let Some(mut oracle) = Oracle::spawn_named("libdeflate-oracle") else {
        return;
    };
    let (seed, _) = seed_and_count();
    let mut rng = Rng(seed ^ 0xB10C);
    let mut compressors = compressors();
    let mut compared = 0;
    for len in [
        4999, 5000, 5001, 9999, 10_000, 65_534, 65_535, 65_536, 70_534, 70_535, 70_536, 131_070,
        131_071, 299_999, 300_000, 304_999, 305_000, 305_001, 305_258, 600_000, 610_000,
    ] {
        // Random bytes, which go uncompressed, and one other kind.
        for kind in [1, rng.below(KINDS)] {
            let data = piece(&mut rng, kind, len);
            compared += compare(&mut oracle, &mut rng, &mut compressors, "block size", &data);
        }
    }
    eprintln!("{compared} calls compared");
}

/// Inputs that take the paths random ones seldom do: blocks ended because
/// the greedy and lazy parsers' sequences, or the near-optimal parser's
/// match cache, are full.
#[test]
fn full_stores_match_libdeflate() {
    let Some(mut oracle) = Oracle::spawn_named("libdeflate-oracle") else {
        return;
    };
    let (seed, _) = seed_and_count();
    let mut rng = Rng(seed ^ 0xF011);
    let mut compressors = compressors();
    let mut compared = 0;
    // Words of three bytes from 256, at random: most matches of three bytes,
    // more than 50,000 in 300,000 bytes.
    let words: Vec<[u8; 3]> = (0..256)
        .map(|_| [rng.next() as u8, rng.next() as u8, rng.next() as u8])
        .collect();
    let mut data = Vec::new();
    while data.len() < 700_000 {
        data.extend_from_slice(&words[rng.below(256) as usize]);
    }
    compared += compare(
        &mut oracle,
        &mut rng,
        &mut compressors,
        "short words",
        &data,
    );
    // Random bits, a byte each: at each position, the binary trees find
    // matches of every length up to about 15, more than five a position.
    let data: Vec<u8> = (0..1_200_000)
        .map(|_| b'0' + (rng.next() & 1) as u8)
        .collect();
    compared += compare(&mut oracle, &mut rng, &mut compressors, "bits", &data);
    eprintln!("{compared} calls compared");
}

#[test]
fn large_inputs_match_libdeflate() {
    let Some(mut oracle) = Oracle::spawn_named("libdeflate-oracle") else {
        return;
    };
    let (seed, count) = seed_and_count();
    let mut rng = Rng(seed ^ 0xAA);
    let mut compressors = compressors();
    let mut compared = 0;
    for _ in 0..count.div_ceil(4) {
        let len = (1 << 20) + rng.below(3 << 20) as usize;
        let data = input(&mut rng, len);
        compared += compare(&mut oracle, &mut rng, &mut compressors, "large", &data);
    }
    eprintln!("{compared} calls compared");
}

/// The files of the repository's test data that are not compressed
/// already, and Silesia's where it is fetched, a piece of each.
#[test]
fn files_match_libdeflate() {
    let Some(mut oracle) = Oracle::spawn_named("libdeflate-oracle") else {
        return;
    };
    let (seed, _) = seed_and_count();
    let mut rng = Rng(seed ^ 0xF11E);
    let mut compressors = compressors();
    let mut compared = 0;
    let root = repository();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root.join("testdata/zstd/golden-compression")).unwrap() {
        let path = entry.unwrap().path();
        files.push((path.display().to_string(), std::fs::read(&path).unwrap()));
    }
    let cache = std::env::var_os("HIVEPACK_TESTDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| root.join("target/testdata"));
    for name in [
        "dickens", "mozilla", "nci", "ooffice", "osdb", "sao", "x-ray", "xml",
    ] {
        if let Ok(data) = std::fs::read(cache.join("silesia").join(name)) {
            let start = data.len() / 3;
            let piece = data[start..start + (1 << 20).min(data.len() - start)].to_vec();
            files.push((format!("silesia/{name}"), piece));
        }
    }
    for (name, data) in &files {
        compared += compare(&mut oracle, &mut rng, &mut compressors, name, data);
    }
    eprintln!("{compared} calls compared on {} files", files.len());
}

#[test]
fn bounds_match_libdeflate() {
    let Some(mut oracle) = Oracle::spawn_named("libdeflate-oracle") else {
        return;
    };
    let compressors = compressors();
    for level in LEVELS {
        let compressor = compressors[(level + 1) as usize].as_ref().unwrap();
        for len in [0, 1, 4999, 5000, 5001, 65535, 1 << 20, usize::MAX / 8] {
            let want = oracle.ask(&format!("bound {level} {len}"));
            assert_eq!(
                want,
                compressor.deflate_compress_bound(len).to_string(),
                "level {level}, {len}"
            );
        }
    }
    for level in [-2, 13, 100] {
        assert_eq!(oracle.ask(&format!("bound {level} 1")), "null");
        assert!(Compressor::new(level).is_none());
    }
}

/// Without the oracle too: every level, a few kinds of data, and every
/// stream inflates back; a buffer one byte short gives 0.
#[test]
fn streams_inflate_back() {
    let mut rng = Rng(7);
    let mut compressors = compressors();
    for len in [0, 1, 2, 7, 52, 1000, 5000, 70_000, 400_000] {
        let data = input(&mut rng, len);
        for level in LEVELS {
            let compressor = compressors[(level + 1) as usize].as_mut().unwrap();
            let mut out = vec![0u8; compressor.deflate_compress_bound(len)];
            let size = compressor.deflate_compress(&data, &mut out);
            assert!(size > 0, "level {level}, {len} bytes");
            assert!(
                inflate(&out[..size], &data) == data,
                "level {level}, {len} bytes"
            );
            let mut short = vec![0u8; size - 1];
            assert_eq!(
                compressor.deflate_compress(&data, &mut short),
                0,
                "level {level}, {len} bytes"
            );
            // The same again, after a call that did not fit.
            let again = compressor.deflate_compress(&data, &mut out);
            assert_eq!(again, size);
        }
    }
}

/// The near-optimal levels make smaller streams than zlib's level 9 on
/// text, as they are meant to.
#[test]
fn near_optimal_is_smaller() {
    let mut rng = Rng(11);
    let data = piece(&mut rng, 7, 300_000);
    let mut sizes = Vec::new();
    for level in [6, 9, 12] {
        let mut compressor = Compressor::new(level).unwrap();
        let mut out = vec![0u8; compressor.deflate_compress_bound(data.len())];
        sizes.push(compressor.deflate_compress(&data, &mut out));
    }
    assert!(sizes[2] < sizes[1] && sizes[1] <= sizes[0], "{sizes:?}");
}
