//! Comparison with libbzip2 1.0.8 through `tools/bzip2-oracle`, call by
//! call: what each call returns, reads and writes, the totals, and a hash
//! of the output, for the compressor and the decompressor in every mode,
//! and for the buffer-to-buffer functions.
//!
//! The oracle is a small C program built with libbzip2's sources by
//! `scripts/testdata.py`. It answers requests such as
//! `decompress 0 d10/5,d=/100 425a68...` by calling libbzip2, one line per
//! request. [`answer`] answers the same requests with the port, in the same
//! format, so the two can be compared as text.
//!
//! - With the oracle built, generated requests are compared with libbzip2
//!   directly: inputs of many kinds compressed in random pieces with every
//!   action, block size and work factor (some out of range), and streams
//!   from libbzip2's compressor decompressed in random pieces, some
//!   damaged, cut short, followed by more, or randomised.
//! - Everywhere, including where the oracle cannot be built (Windows, and
//!   the emulated i686 and s390x jobs), `testdata/oracle/bzip2.txt` replays
//!   answers libbzip2 gave earlier. `cargo test -p hivepack --all-features --test
//!   bzip2_oracle record_oracle_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "bzip2_support/mod.rs"]
mod support;

use std::fmt::Write as _;
use std::path::PathBuf;

use hivepack::bzip2::{
    Action, Compress, Decompress, InBuffer, OutBuffer, Result, Status, buff_to_buff_compress,
    buff_to_buff_decompress,
};
use support::{
    Oracle, Rng, c_compress, damage, fnv64, hex, input, randomised, recorded_form, repository,
    unhex,
};

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/bzip2.txt")
}

/// libbzip2's return code for a result.
fn code(ret: Result<Status>) -> i32 {
    match ret {
        Ok(status) => status.number(),
        Err(e) => e.number(),
    }
}

fn action(number: u32) -> Action {
    match number {
        0 => Action::Run,
        1 => Action::Flush,
        _ => Action::Finish,
    }
}

/// The output space all the steps can ask for.
fn output_space(steps: &str) -> usize {
    steps
        .split(',')
        .map(|step| step.split('/').nth(1).unwrap().parse::<usize>().unwrap())
        .sum()
}

/// The input of a step: `=` keeps what the last call left of its input,
/// a number gives that many more bytes from where it stopped reading.
fn step_input(word: &str, len: usize, consumed: usize, end: &mut usize) {
    if word != "=" {
        let n: usize = word.parse().unwrap();
        *end = consumed + n.min(len - consumed);
    }
}

/// The port's answer to a request, in the oracle's format.
fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    match words[..] {
        ["compress", block_size, work_factor, steps, data] => {
            let mut strm =
                match Compress::new(block_size.parse().unwrap(), work_factor.parse().unwrap()) {
                    Ok(strm) => strm,
                    Err(e) => return format!("err {}", e.number()),
                };
            let data = unhex(data);
            let mut out = vec![0u8; output_space(steps)];
            let (mut consumed, mut written, mut end) = (0, 0, 0);
            let mut text = String::from("ok");
            for step in steps.split(',') {
                let args: Vec<&str> = step.strip_prefix('c').unwrap().split('/').collect();
                step_input(args[0], data.len(), consumed, &mut end);
                let room: usize = args[1].parse().unwrap();
                let mut input = InBuffer {
                    src: &data[..end],
                    pos: consumed,
                };
                let mut output = OutBuffer::new(&mut out[written..written + room]);
                let ret =
                    code(strm.compress(&mut output, &mut input, action(args[2].parse().unwrap())));
                let read = input.pos - consumed;
                let made = output.pos;
                consumed += read;
                written += made;
                let _ = write!(text, " {ret}/{read}/{made}");
            }
            let _ = write!(
                text,
                " {}/{} {:016x}",
                strm.total_in(),
                strm.total_out(),
                fnv64(&out[..written])
            );
            text
        }
        ["decompress", small, steps, data] => {
            let mut strm = Decompress::new(small == "1");
            let data = unhex(data);
            let mut out = vec![0u8; output_space(steps)];
            let (mut consumed, mut written, mut end) = (0, 0, 0);
            let mut text = String::from("ok");
            for step in steps.split(',') {
                let args: Vec<&str> = step.strip_prefix('d').unwrap().split('/').collect();
                step_input(args[0], data.len(), consumed, &mut end);
                let room: usize = args[1].parse().unwrap();
                let mut input = InBuffer {
                    src: &data[..end],
                    pos: consumed,
                };
                let mut output = OutBuffer::new(&mut out[written..written + room]);
                let ret = code(strm.decompress(&mut output, &mut input));
                let read = input.pos - consumed;
                let made = output.pos;
                consumed += read;
                written += made;
                let _ = write!(text, " {ret}/{read}/{made}");
                if ret < 0 {
                    break;
                }
            }
            let _ = write!(
                text,
                " {}/{} {:016x}",
                strm.total_in(),
                strm.total_out(),
                fnv64(&out[..written])
            );
            text
        }
        ["buffc", block_size, work_factor, dest_len, data] => {
            let dest_len: usize = dest_len.parse().unwrap();
            let mut out = vec![0u8; dest_len];
            let ret = buff_to_buff_compress(
                &mut out,
                &unhex(data),
                block_size.parse().unwrap(),
                work_factor.parse().unwrap(),
            );
            buff_answer(ret, dest_len, &out)
        }
        ["buffd", small, dest_len, data] => {
            let dest_len: usize = dest_len.parse().unwrap();
            let mut out = vec![0u8; dest_len];
            let ret = buff_to_buff_decompress(&mut out, &unhex(data), small == "1");
            buff_answer(ret, dest_len, &out)
        }
        _ => panic!("not a request: {request:.100}"),
    }
}

fn buff_answer(ret: Result<usize>, dest_len: usize, out: &[u8]) -> String {
    match ret {
        Ok(len) => format!("0 {len} {:016x}", fnv64(&out[..len])),
        Err(e) => format!("{} {dest_len} {:016x}", e.number(), fnv64(&[])),
    }
}

/// How much input a step offers: a little, some, or all that is left.
fn chunk(rng: &mut Rng, left: usize) -> usize {
    match rng.below(5) {
        0 => rng.below(8) as usize,
        1 | 2 => rng.below(300) as usize,
        3 => rng.below(5000) as usize,
        _ => left,
    }
}

/// How much output space a step gives: none, a little, some, or plenty.
fn room(rng: &mut Rng) -> usize {
    match rng.below(8) {
        0 => 0,
        1..=3 => 1 + rng.below(100) as usize,
        4..=6 => rng.below(5000) as usize,
        _ => 100_000,
    }
}

/// The steps of a `compress` request for `len` bytes of input: runs in
/// pieces, flushes on the way, then the end, with now and then a call
/// libbzip2 refuses.
fn compress_steps(rng: &mut Rng, len: usize, room_at_end: usize) -> String {
    let mut steps = Vec::new();
    let mut offered = 0;
    while offered < len && steps.len() < 120 {
        match rng.below(20) {
            0..=12 => {
                let n = chunk(rng, len - offered);
                offered += n;
                steps.push(format!("c{n}/{}/0", room(rng)));
            }
            13 => steps.push(format!("c=/{}/0", room(rng))),
            14 | 15 => {
                // A flush, called again with what is left until done, or
                // not quite, and now and then with another action, which
                // is refused.
                let n = chunk(rng, len - offered);
                offered += n;
                steps.push(format!("c{n}/{}/1", room(rng)));
                for _ in 0..rng.below(6) {
                    let action = if rng.below(8) == 0 {
                        rng.pick(&[0, 2])
                    } else {
                        1
                    };
                    steps.push(format!("c=/{}/{action}", room(rng)));
                }
                steps.push(format!("c=/{}/1", rng.pick(&[100, 300_000, 300_000])));
            }
            16 => {
                // A run with nothing to read: refused, unless there is
                // something left to write.
                steps.push(rng.pick(&["c0/0/0", "c=/0/0", "c0/10/0"]).to_string());
            }
            _ => {
                let n = chunk(rng, len - offered);
                offered += n;
                steps.push(format!("c{n}/0/0"));
            }
        }
    }
    steps.push(format!("c{len}/{}/2", room(rng)));
    for _ in 0..rng.below(5) {
        let action = if rng.below(8) == 0 {
            rng.pick(&[0, 1])
        } else {
            2
        };
        steps.push(format!("c=/{}/{action}", room(rng)));
    }
    steps.push(format!("c=/{room_at_end}/2"));
    if rng.below(3) == 0 {
        // After the end.
        steps.push(rng.pick(&["c=/10/2", "c0/10/0", "c1/10/1"]).to_string());
    }
    steps.join(",")
}

/// The steps of a `decompress` request for a stream of `len` bytes that
/// decompresses to about `out_len`.
fn decompress_steps(rng: &mut Rng, len: usize, out_len: usize) -> String {
    let mut steps = Vec::new();
    let mut offered = 0;
    while offered < len && steps.len() < 120 {
        if rng.below(6) == 0 {
            steps.push(format!("d=/{}", room(rng)));
        } else {
            let n = chunk(rng, len - offered);
            offered += n;
            steps.push(format!("d{n}/{}", room(rng)));
        }
    }
    steps.push(format!("d{len}/{}", room(rng)));
    steps.push(format!("d=/{}", out_len + 100));
    if rng.below(3) == 0 {
        steps.push(format!("d=/{}", rng.below(10)));
    }
    steps.join(",")
}

/// A length for an input: empty, short, around the 10,000 bytes below
/// which a block goes to the fallback sort, or up to `max`.
fn length(rng: &mut Rng, max: usize) -> usize {
    match rng.below(10) {
        0 => rng.below(3) as usize,
        1..=3 => rng.below(1000) as usize,
        4 | 5 => 9000 + rng.below(2000) as usize,
        6 | 7 => rng.below(30_000) as usize,
        _ => rng.below(max as u64 + 1) as usize,
    }
}

/// Generated requests: `count` of each kind, with inputs up to `max`
/// bytes.
fn requests(rng: &mut Rng, count: usize, max: usize, with_randomised: bool) -> Vec<String> {
    let mut requests = Vec::new();

    // A few by hand: empty and cut-short streams, wrong magic, block sizes
    // out of range in the header.
    for data in [
        "-",
        "42",
        "425a",
        "425a68",
        "425a6830",
        "425a683a",
        "425a6839",
        "425a68393141",
        "425a683917724538509000000000",
        "425a683917724538509000000001",
        "425a68391772453850",
        "585a6839",
        "425a6939",
    ] {
        for small in [0, 1] {
            requests.push(format!("decompress {small} d100/10,d=/10 {data}"));
        }
    }
    for (block_size, work_factor) in [(0, 0), (10, 0), (1, -1), (9, 251), (-1, 30)] {
        requests.push(format!("compress {block_size} {work_factor} c1/100/2 61"));
    }
    // A flush or an end whose input changed before it was done.
    let text = hex(&input(rng, 3000));
    for steps in [
        "c100/0/1,c50/100/1,c=/9000/1,c=/9000/0",
        "c100/5/1,c=/9000/1,c10/0/1,c=/9000/1",
        "c3000/0/2,c=/10/2,c5/10/2,c=/9000/2",
        "c100/9000/1,c0/9000/1,c3000/9000/2",
    ] {
        requests.push(format!("compress 1 0 {steps} {text}"));
    }

    for _ in 0..count {
        let len = length(rng, max);
        let data = input(rng, len);
        let block_size = rng.pick(&[1, 1, 1, 2, 3, 5, 9]);
        let work_factor = rng.pick(&[0, 0, 0, 1, 2, 3, 4, 30, 100, 101, 250]);
        let steps = compress_steps(rng, len, len + len / 50 + 1000);
        requests.push(format!(
            "compress {block_size} {work_factor} {steps} {}",
            hex(&data)
        ));
    }

    for _ in 0..count {
        let len = length(rng, max);
        let data = input(rng, len);
        let block_size = rng.pick(&[1, 1, 2, 4, 9]);
        let mut stream = c_compress(&data, block_size, 0);
        let mut out_len = data.len();
        match rng.below(10) {
            0 | 1 => stream = damage(rng, &stream),
            2 if !data.is_empty() => {
                // The first block marked randomised: the same block undone
                // another way, which ends in a wrong CRC.
                stream[14] ^= 0x80;
            }
            3 => {
                // More after the end: another stream, or anything.
                let more = if rng.below(2) == 0 {
                    c_compress(&data[..data.len() / 2], block_size, 0)
                } else {
                    (0..rng.below(20)).map(|_| rng.next() as u8).collect()
                };
                stream.extend_from_slice(&more);
            }
            4 => {
                let at = rng.below(stream.len() as u64) as usize;
                stream.truncate(at);
            }
            5 if with_randomised => {
                // A valid randomised stream.
                let mut last = 0;
                let data: Vec<u8> = (0..len.min(99_000))
                    .map(|_| {
                        let mut byte = rng.next() as u8;
                        if byte == last {
                            byte ^= 0x40;
                        }
                        last = byte;
                        byte
                    })
                    .collect();
                if !data.is_empty() {
                    stream = randomised(&data, block_size);
                    out_len = data.len();
                }
            }
            _ => {}
        }
        let small = rng.below(2);
        let steps = decompress_steps(rng, stream.len(), out_len);
        requests.push(format!("decompress {small} {steps} {}", hex(&stream)));
    }

    for _ in 0..count / 4 {
        let len = length(rng, max.min(50_000));
        let data = input(rng, len);
        let block_size = rng.pick(&[1, 2, 9]);
        let stream = c_compress(&data, block_size, 0);
        let room = |rng: &mut Rng, len: usize| match rng.below(3) {
            0 => rng.below(len as u64 + 1) as usize,
            _ => len + rng.below(100) as usize,
        };
        let dest_len = room(rng, stream.len());
        requests.push(format!(
            "buffc {block_size} {} {dest_len} {}",
            rng.below(251),
            hex(&data)
        ));
        let stream = if rng.below(4) == 0 {
            damage(rng, &stream)
        } else {
            stream
        };
        let dest_len = room(rng, data.len());
        requests.push(format!(
            "buffd {} {dest_len} {}",
            rng.below(2),
            hex(&stream)
        ));
    }
    requests
}

#[test]
fn port_matches_libbzip2() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x5eed_b201);
    let requests = requests(&mut rng, 400, 250_000, true);
    let mut seen = std::collections::BTreeMap::new();
    for request in &requests {
        let want = oracle.ask(request);
        assert_eq!(answer(request), want, "{request:.300}");
        // How each request ended, by kind: at the end of the stream, or
        // with the last code returned.
        let kind = request.split(' ').next().unwrap();
        let codes: Vec<&str> = want
            .split(' ')
            .skip(1)
            .filter_map(|token| token.split_once('/').map(|(code, _)| code))
            .collect();
        let end = if kind.starts_with("buff") || want.starts_with("err") {
            want.split(' ').next().unwrap()
        } else if codes.contains(&"4") {
            "end"
        } else {
            codes
                .get(codes.len().saturating_sub(2))
                .copied()
                .unwrap_or("none")
        };
        *seen.entry(format!("{kind} {end}")).or_insert(0) += 1;
    }
    // Most compress and decompress requests reach the end, and the others
    // fail in every way.
    let count = |key: &str| seen.get(key).copied().unwrap_or(0);
    assert!(count("compress end") > 300, "{seen:?}");
    assert!(count("decompress end") > 200, "{seen:?}");
    for key in [
        "decompress -4",
        "decompress -5",
        "decompress 0",
        "buffd -7",
        "buffd -8",
        "buffc -8",
    ] {
        assert!(count(key) > 0, "no {key}: {seen:?}");
    }
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/bzip2.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(recorded_form(&answer(request)), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > 500, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/bzip2.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng(0x5eed_b202);
    let mut text = String::from(
        "# Answers from libbzip2 1.0.8 (tools/bzip2-oracle), replayed by crates/bzip2/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test bzip2_oracle record_oracle_answers -- --ignored\n",
    );
    for request in requests(&mut rng, 400, 3000, true) {
        // Keep the file small: the large inputs are for the live comparison.
        if request.len() > 6_000 {
            continue;
        }
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::create_dir_all(recorded_path().parent().expect("folder")).expect("folder");
    std::fs::write(recorded_path(), text).expect("written");
}

/// A sanity check of the harness on requests whose answers are known.
#[test]
fn answers_known_requests() {
    // "a" compressed in one call, then decompressed in pieces.
    let stream = c_compress(b"a", 9, 0);
    let answer_c = answer("compress 9 0 c1/100/2 61");
    assert_eq!(
        answer_c,
        format!(
            "ok 4/1/{} 1/{} {:016x}",
            stream.len(),
            stream.len(),
            fnv64(&stream)
        )
    );
    let answer_d = answer(&format!("decompress 0 d10/0,d=/1,d100/5 {}", hex(&stream)));
    assert!(answer_d.starts_with("ok 0/10/0 0/"), "{answer_d}");
    assert!(
        answer_d.contains(&format!(" {}/1 {:016x}", stream.len(), fnv64(b"a"))),
        "{answer_d}"
    );
}
