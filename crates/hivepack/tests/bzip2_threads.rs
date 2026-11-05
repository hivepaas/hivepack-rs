//! bzip2 in threads: `CompressMt`'s streams, the same whatever the
//! threads and the pieces the input and output come in, each the port's
//! stream of its piece, read back by `bzip2 -d` where it is installed and
//! by the opener with one thread or many; and the opener's threads reading
//! what one thread reads, from other files too: one stream, damaged, cut
//! short, followed by other data, and with bzip2's magic where no stream
//! starts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "bzip2_support/mod.rs"]
mod support;

use std::io::{self, Cursor, Read, Write};
use std::process::{Command, Stdio};

use hivepack::Threads;
use hivepack::bzip2::{
    Action, Compress, CompressMt, Error, InBuffer, MtOptions, OutBuffer, Status, piece_size,
};
use hivepack::open::{Layer, Opener};
use support::Rng;

/// One thread, two, eight, and as many as the machine has.
fn threads() -> [Threads; 4] {
    [Threads::One, Threads::of(2), Threads::of(8), Threads::Auto]
}

/// Data of every kind bzip2 meets, `len` bytes: words with indents of
/// four spaces (runs of exactly 4, which the first run-length coding
/// makes longer), runs of zeros, random bytes, and bzip2's own magic.
fn mixed(rng: &mut Rng, len: usize) -> Vec<u8> {
    let words: [&[u8]; 8] = [
        b"the ",
        b"bzip2 ",
        b"stream\n",
        b"    indented ",
        b"BZh91AY&SY",
        b"BZh9\x17\x72\x45\x38\x50\x90",
        b"\n\n",
        b"threads ",
    ];
    let mut out = Vec::with_capacity(len + 4096);
    while out.len() < len {
        match rng.below(20) {
            0 => out.extend(std::iter::repeat_n(0, rng.below(3000) as usize)),
            1 => out.extend((0..rng.below(2000)).map(|_| rng.next() as u8)),
            _ => {
                out.extend_from_slice(rng.pick(&words));
                out.extend_from_slice(format!("{} ", rng.below(1000)).as_bytes());
            }
        }
    }
    out.truncate(len);
    out
}

/// What `options` makes of `data`, given in pieces of `input` bytes
/// with room for `output`, `flushes` cutting it where they are.
fn compress_mt(
    data: &[u8],
    options: &MtOptions,
    input: usize,
    output: usize,
    flushes: &[usize],
) -> Vec<u8> {
    let mut c = CompressMt::with_options(options).unwrap();
    let mut file = Vec::new();
    let mut room = vec![0; output];
    let mut at = 0;
    let mut cuts = flushes.to_vec();
    cuts.push(data.len());
    for (i, &cut) in cuts.iter().enumerate() {
        let finish = i == cuts.len() - 1;
        while at < cut {
            let end = (at + input).min(cut);
            let mut src = InBuffer::new(&data[at..end]);
            while src.pos < src.src.len() {
                let mut dst = OutBuffer::new(&mut room);
                assert_eq!(
                    c.compress(&mut dst, &mut src, Action::Run).unwrap(),
                    Status::RunOk
                );
                let made = dst.pos;
                file.extend_from_slice(&room[..made]);
            }
            at = end;
        }
        let action = if finish {
            Action::Finish
        } else {
            Action::Flush
        };
        let mut src = InBuffer::new(&[]);
        loop {
            let mut dst = OutBuffer::new(&mut room);
            let status = c.compress(&mut dst, &mut src, action).unwrap();
            let made = dst.pos;
            file.extend_from_slice(&room[..made]);
            match (status, finish) {
                (Status::StreamEnd, true) | (Status::RunOk, false) => break,
                (Status::FinishOk, true) | (Status::FlushOk, false) => {}
                other => panic!("{other:?}"),
            }
        }
    }
    assert_eq!(c.total_in(), data.len() as u64);
    assert_eq!(c.total_out(), file.len() as u64);
    file
}

/// The port's stream of `data`, in one call.
fn compress(data: &[u8], block_size: i32) -> Vec<u8> {
    let mut c = Compress::new(block_size, 0).unwrap();
    let mut out = vec![0; data.len() + data.len() / 100 + 601];
    let mut output = OutBuffer::new(&mut out);
    let status = c
        .compress(&mut output, &mut InBuffer::new(data), Action::Finish)
        .unwrap();
    assert_eq!(status, Status::StreamEnd);
    let len = output.pos;
    out.truncate(len);
    out
}

/// The port's streams of `data` cut where `cuts` say, one after another.
fn streams(data: &[u8], block_size: i32, cuts: &[usize]) -> Vec<u8> {
    let mut file = Vec::new();
    let mut at = 0;
    for &cut in cuts.iter().chain([&data.len()]) {
        if cut > at || (at == 0 && data.is_empty()) {
            file.extend(compress(&data[at..cut], block_size));
        }
        at = cut;
    }
    file
}

/// Where pieces of `size` end, and flushes, from 0 to `len`.
fn cuts(len: usize, size: usize, flushes: &[usize]) -> Vec<usize> {
    let mut cuts = Vec::new();
    let mut start = 0;
    for &end in flushes.iter().chain([&len]) {
        let mut at = start + size;
        while at < end {
            cuts.push(at);
            at += size;
        }
        if end < len {
            cuts.push(end);
        }
        start = end;
    }
    cuts
}

#[test]
fn the_streams_are_the_same_whatever_the_threads() {
    let mut rng = Rng(0x5eed_b21b);
    let data = mixed(&mut rng, 700_000);
    for (block_size, piece) in [(1, 0), (1, 45_000), (3, 100_000)] {
        let size = if piece == 0 {
            piece_size(block_size)
        } else {
            piece
        };
        let flushes = [250_000, 250_001, 400_000];
        let expected_plain = streams(&data, block_size, &cuts(data.len(), size, &[]));
        let expected_flushed = streams(&data, block_size, &cuts(data.len(), size, &flushes));
        for threads in threads() {
            let options = MtOptions {
                block_size_100k: block_size,
                threads,
                piece_size: piece,
                ..MtOptions::default()
            };
            for (input, output) in [(data.len(), 1 << 20), (65_536, 4096), (7_777, 999)] {
                assert!(
                    compress_mt(&data, &options, input, output, &[]) == expected_plain,
                    "{block_size} {piece} {threads:?} {input} {output}"
                );
            }
            assert!(
                compress_mt(&data, &options, 30_000, 5000, &flushes) == expected_flushed,
                "{block_size} {piece} {threads:?} flushed"
            );
        }
    }
    // A byte at a time, in and out.
    let small = &data[..60_000];
    let options = MtOptions {
        block_size_100k: 1,
        threads: Threads::of(3),
        piece_size: 20_000,
        ..MtOptions::default()
    };
    assert!(
        compress_mt(small, &options, 1, 1, &[]) == streams(small, 1, &[20_000, 40_000]),
        "a byte at a time"
    );
}

/// The blocks in `file`: their magic, at any bit.
fn blocks(file: &[u8]) -> usize {
    const MAGIC: u64 = 0x3141_5926_5359;
    let mut window = 0u64;
    let mut found = 0;
    for (i, byte) in file.iter().enumerate() {
        for bit in (0..8).rev() {
            window = (window << 1 | u64::from(byte >> bit & 1)) & 0xFFFF_FFFF_FFFF;
            if window == MAGIC && i >= 5 {
                found += 1;
            }
        }
    }
    found
}

#[test]
fn each_stream_is_one_block() {
    // The default pieces fit in a block, runs of exactly four spaces and
    // all: a block's magic once in each stream.
    let mut rng = Rng(7);
    let data = mixed(&mut rng, 3 * piece_size(1) + 1234);
    let options = MtOptions {
        block_size_100k: 1,
        ..MtOptions::default()
    };
    let file = compress_mt(&data, &options, data.len(), 1 << 20, &[]);
    assert_eq!(blocks(&file), 4);
    // Where more than one byte in five is in a run of exactly four, the
    // first run-length coding makes more than a block of a piece.
    let indented = b"    ab\n".repeat(20_000);
    let file = compress_mt(&indented, &options, indented.len(), 1 << 20, &[]);
    assert_eq!(blocks(&file), 3);
    assert_eq!(file.windows(4).filter(|w| w == b"BZh1").count(), 2);
    assert_eq!(piece_size(9), 855_000);
    assert_eq!(piece_size(1), 95_000);
}

#[test]
fn an_empty_input_is_one_empty_stream() {
    for threads in threads() {
        let options = MtOptions {
            threads,
            ..MtOptions::default()
        };
        let file = compress_mt(&[], &options, 1, 100, &[]);
        assert_eq!(file, compress(&[], 9));
        assert_eq!(file.len(), 14);
        // A flush of nothing writes nothing.
        let file = compress_mt(b"abc", &options, 1, 100, &[0, 0, 3, 3]);
        assert_eq!(file, compress(b"abc", 9));
    }
}

#[test]
fn calls_are_checked_as_libbzip2_checks_them() {
    let mut c = CompressMt::new(9, 0, Threads::of(2)).unwrap();
    let mut room = [0u8; 1000];
    // Nothing to read and nothing to write.
    let mut output = OutBuffer::new(&mut room);
    assert_eq!(
        c.compress(&mut output, &mut InBuffer::new(&[]), Action::Run),
        Err(Error::Param)
    );
    // The end, with input that changed on the way.
    let data = vec![b'x'; 2_000_000];
    let mut input = InBuffer::new(&data);
    let mut tiny = [0u8; 10];
    let mut output = OutBuffer::new(&mut tiny);
    assert_eq!(
        c.compress(&mut output, &mut input, Action::Finish),
        Ok(Status::FinishOk)
    );
    let mut output = OutBuffer::new(&mut room);
    assert_eq!(
        c.compress(&mut output, &mut InBuffer::new(b"other"), Action::Finish),
        Err(Error::Sequence)
    );
    assert_eq!(
        c.compress(&mut output, &mut input, Action::Run),
        Err(Error::Sequence)
    );
    loop {
        let mut output = OutBuffer::new(&mut room);
        match c.compress(&mut output, &mut input, Action::Finish) {
            Ok(Status::FinishOk) => {}
            Ok(Status::StreamEnd) => break,
            other => panic!("{other:?}"),
        }
    }
    let mut output = OutBuffer::new(&mut room);
    assert_eq!(
        c.compress(&mut output, &mut InBuffer::new(&[]), Action::Finish),
        Err(Error::Sequence)
    );
    // It can go to another thread, as Compress can.
    fn send<T: Send>(_: &T) {}
    send(&c);
    // What Compress::new refuses.
    for (block_size, work_factor) in [(0, 0), (10, 0), (9, 251), (9, -1)] {
        assert_eq!(
            CompressMt::new(block_size, work_factor, Threads::Auto).err(),
            Some(Error::Param)
        );
    }
    // A buffer past its end.
    let mut c = CompressMt::new(1, 0, Threads::One).unwrap();
    let mut output = OutBuffer::new(&mut room);
    let mut input = InBuffer::new(b"abc");
    input.pos = 4;
    assert_eq!(
        c.compress(&mut output, &mut input, Action::Run),
        Err(Error::Param)
    );
}

/// What `file` reads to through an opener with `threads`, a piece of
/// `piece` bytes at a time up to an error, and the error.
fn read_with(file: &[u8], threads: Threads, piece: usize) -> (Vec<u8>, Option<String>) {
    let mut opener = Opener::new(|| Ok(Cursor::new(file))).threads(threads);
    let mut opened = match opener.open() {
        Ok(opened) => opened,
        Err(e) => return (Vec::new(), Some(e.to_string())),
    };
    let mut data = Vec::new();
    let mut buf = vec![0; piece];
    loop {
        match opened.read(&mut buf) {
            Ok(0) => return (data, None),
            Ok(n) => data.extend(&buf[..n]),
            Err(e) => return (data, Some(e.to_string())),
        }
    }
}

/// `file` reads the same with each of [`threads`], in pieces of two
/// sizes, as with one thread: what it reads.
fn reads_as_one(what: &str, file: &[u8]) -> (Vec<u8>, Option<String>) {
    let alone = read_with(file, Threads::One, 1 << 16);
    for threads in threads() {
        for piece in [1 << 16, 1000] {
            assert!(
                read_with(file, threads, piece) == alone,
                "{what}, {threads:?}, pieces of {piece}: not as with one thread"
            );
        }
    }
    alone
}

#[test]
fn the_opener_reads_streams_in_threads_as_in_one() {
    let mut rng = Rng(0xb2);
    let data = mixed(&mut rng, 600_000);
    let options = MtOptions {
        block_size_100k: 1,
        threads: Threads::of(4),
        ..MtOptions::default()
    };
    let file = compress_mt(&data, &options, data.len(), 1 << 20, &[]);
    let one = compress(&data, 1);
    // One stream larger than a thread takes: one thread reads it.
    let large = mixed(&mut rng, 3_000_000);
    let random: Vec<u8> = (0..3_000_000).map(|_| rng.next() as u8).collect();
    let mut cases: Vec<(&str, Vec<u8>, &[u8])> = vec![
        ("streams", file.clone(), &data),
        ("one stream", one.clone(), &data),
        ("one large stream", compress(&large, 9), &large),
        ("one stream of random data", compress(&random, 9), &random),
        ("an empty stream", compress(&[], 9), &[]),
    ];
    // One stream, then streams.
    let mut both = one.clone();
    both.extend(&file);
    let twice = [data.clone(), data.clone()].concat();
    cases.push(("one stream, then streams", both, &twice));
    // Streams with empty ones among them, and zeros after them.
    let mut empties = compress(&[], 1);
    empties.extend(&file);
    empties.extend(compress(&[], 5));
    empties.extend(compress(&[], 5));
    empties.extend([0; 5000]);
    cases.push(("empty streams and zeros", empties, &data));
    for (what, file, expected) in &cases {
        let alone = reads_as_one(what, file);
        assert!(alone == (expected.to_vec(), None), "{what}");
    }
}

#[test]
fn errors_are_the_same_in_threads() {
    let mut rng = Rng(0xe7);
    let data = mixed(&mut rng, 500_000);
    let options = MtOptions {
        block_size_100k: 1,
        ..MtOptions::default()
    };
    let file = compress_mt(&data, &options, data.len(), 1 << 20, &[]);
    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
    for cut in [1, 5, 13, 14, 15, file.len() / 3, file.len() / 2] {
        cases.push((
            format!("without {cut} bytes"),
            file[..file.len() - cut].to_vec(),
        ));
    }
    for at in [20, file.len() / 2, file.len() - 3] {
        let mut damaged = file.clone();
        damaged[at] ^= 0x21;
        cases.push((format!("byte {at} damaged"), damaged));
    }
    // Other data after the streams, and between them; a stream's magic
    // where no stream starts, after the last and between.
    let (first, second) = file.split_at(compress(&data[..piece_size(1)], 1).len());
    assert!(second.starts_with(b"BZh1"));
    let mut magic = b"BZh91AY&SY".to_vec();
    magic.extend(b"not a stream after all");
    let mut empty_magic = b"BZh9".to_vec();
    empty_magic.extend([0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 1, 2, 3]);
    for (what, between) in [
        ("junk", b"\0\0\0junk".to_vec()),
        ("zeros", vec![0; 7]),
        ("BZh9 and no magic", b"BZh9\0\0\0\0\0\0\0".to_vec()),
        ("a block's magic", magic),
        ("the end's magic, a wrong CRC", empty_magic),
    ] {
        let mut after = file.clone();
        after.extend(&between);
        cases.push((format!("{what} after"), after));
        let mut inside = first.to_vec();
        inside.extend(&between);
        inside.extend(second);
        cases.push((format!("{what} between"), inside));
    }
    for (what, file) in &cases {
        let alone = reads_as_one(what, file);
        if what == "zeros after" {
            assert!(alone == (data.clone(), None), "{what}");
            continue;
        }
        assert!(alone.1.is_some(), "{what}: read through");
        // A damaged block is written out before its CRC is checked.
        assert!(
            what.contains("damaged") || data.starts_with(&alone.0),
            "{what}: other data"
        );
    }
}

/// A reader that fails after `data`, as a layer under bzip2 can, and is
/// interrupted between reads.
struct Failing<'a> {
    data: &'a [u8],
    interrupted: bool,
}

impl Read for Failing<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.interrupted = !self.interrupted;
        if self.interrupted {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.data.is_empty() {
            return Err(io::Error::other("the disk is gone"));
        }
        let n = buf.len().min(self.data.len()).min(5000);
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

#[test]
fn errors_of_the_reader_under_come_through_in_threads() {
    let mut rng = Rng(0xfa11);
    let data = mixed(&mut rng, 500_000);
    let options = MtOptions {
        block_size_100k: 1,
        ..MtOptions::default()
    };
    let file = compress_mt(&data, &options, data.len(), 1 << 20, &[]);
    for cut in [file.len() / 3, file.len() - 1, file.len()] {
        let read = |threads: Threads| {
            let mut opener = Opener::new(|| {
                Ok(Failing {
                    data: &file[..cut],
                    interrupted: false,
                })
            })
            .threads(threads);
            let mut opened = opener.open().unwrap();
            assert_eq!(opened.layers(), [Layer::Bzip2]);
            let mut out: Vec<u8> = Vec::new();
            let mut buf = vec![0; 4096];
            let error = loop {
                match opened.read(&mut buf) {
                    Ok(0) => break None,
                    Ok(n) => out.extend(&buf[..n]),
                    Err(e) => break Some(e.to_string()),
                }
            };
            (out, error)
        };
        let alone = read(Threads::One);
        assert_eq!(alone.1.as_deref(), Some("the disk is gone"));
        for threads in threads() {
            assert!(read(threads) == alone, "{cut}, {threads:?}");
        }
    }
}

/// `bzip2`, if it is installed.
fn system_bzip2() -> Option<&'static str> {
    Command::new("bzip2")
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .map(|_| "bzip2")
}

#[test]
fn bzip2_reads_the_streams() {
    let Some(tool) = system_bzip2() else {
        eprintln!("bzip2 is not installed: skipped");
        return;
    };
    let mut rng = Rng(0xb21b);
    let data = mixed(&mut rng, 1_500_000);
    for (block_size, flushes) in [(9, vec![]), (1, vec![100_000, 100_001]), (9, vec![0])] {
        for threads in [Threads::One, Threads::Auto] {
            let options = MtOptions {
                block_size_100k: block_size,
                threads,
                ..MtOptions::default()
            };
            let file = compress_mt(&data, &options, 100_000, 1 << 16, &flushes);
            let mut child = Command::new(tool)
                .args(["-d", "-c"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut stdin = child.stdin.take().unwrap();
            let writer = std::thread::spawn(move || stdin.write_all(&file));
            let out = child.wait_with_output().unwrap();
            writer.join().unwrap().unwrap();
            assert!(out.status.success(), "{block_size} {threads:?}");
            assert!(out.stdout == data, "{block_size} {threads:?}");
        }
    }
    let mut child = Command::new(tool)
        .args(["-d", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&compress_mt(&[], &MtOptions::default(), 1, 100, &[]))
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success() && out.stdout.is_empty());
}

#[test]
fn bzip2_s_streams_read_in_threads() {
    // What `bzip2` writes, one stream, and `cat` of several.
    let Some(tool) = system_bzip2() else {
        eprintln!("bzip2 is not installed: skipped");
        return;
    };
    let mut rng = Rng(0xcafe);
    let data = mixed(&mut rng, 400_000);
    let run = |data: &[u8]| {
        let mut child = Command::new(tool)
            .args(["-1", "-c"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let data = data.to_vec();
        let writer = std::thread::spawn(move || stdin.write_all(&data));
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap().unwrap();
        assert!(out.status.success());
        out.stdout
    };
    let one = run(&data);
    assert_eq!(reads_as_one("bzip2's stream", &one), (data.clone(), None));
    let mut file = Vec::new();
    for piece in data.chunks(90_000) {
        file.extend(run(piece));
    }
    assert_eq!(reads_as_one("bzip2's streams", &file), (data, None));
}
