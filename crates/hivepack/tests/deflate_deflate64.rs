//! Deflate64 decompression ([`InflateBack9`]) compared with zlib's
//! `contrib/infback9` through `tools/zlib-oracle`, the same way as
//! `tests/oracle.rs` compares the rest.
//!
//! zlib has no Deflate64 compressor, so [`Encoder`] makes the streams: valid
//! stored, fixed and dynamic blocks with lengths up to 65538 and distances
//! up to 65536, knowing the data they decode to. Some are then damaged, and
//! zlib-format deflate streams and random bytes are given too.
//!
//! - With the oracle built, its `inflate9` requests are compared with zlib
//!   directly.
//! - Everywhere, `testdata/oracle/inflate9.txt` replays answers zlib gave
//!   earlier. `cargo test -p hivepack --all-features --test deflate_deflate64
//!   record_inflate9_answers -- --ignored` rewrites that file.
//! - Everywhere, the generated streams decode to their data.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "deflate_support/mod.rs"]
mod support;

use std::fmt::Write as _;
use std::path::PathBuf;

use hivepack::deflate::{
    BackIn, BackOut, Deflate, ErrorCode, Flush, InBuffer, Inflate9, InflateBack9, OutBuffer,
    Result, Status,
};
use support::{Oracle, Rng, damage, fnv64, hex, recorded_form, repository, unhex};

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/inflate9.txt")
}

/// The input of a request: the first piece is given at the start, each next
/// one by one `input()` call, then the rest, then nothing.
struct Input<'a> {
    data: &'a [u8],
    given: usize,
    pieces: std::vec::IntoIter<usize>,
    calls: u64,
}

impl BackIn for Input<'_> {
    fn input(&mut self) -> &[u8] {
        self.calls += 1;
        let mut size = self.data.len() - self.given;
        if let Some(piece) = self.pieces.next() {
            size = size.min(piece);
        }
        let start = self.given;
        self.given += size;
        &self.data[start..start + size]
    }
}

/// The output of a request: call number `fail` fails.
struct Output {
    fail: i64,
    calls: u64,
    written: u64,
    hash: u64,
    data: Vec<u8>,
}

impl BackOut for Output {
    fn output(&mut self, data: &[u8]) -> bool {
        for &byte in data {
            self.hash = (self.hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
        self.written += data.len() as u64;
        self.data.extend_from_slice(data);
        let fail = self.calls as i64 == self.fail;
        self.calls += 1;
        fail
    }
}

/// Decodes as an `inflate9` request asks: the port's answer, in the
/// oracle's format, and all the output.
fn decode(pieces: &str, fail: i64, data: &[u8]) -> (String, Vec<u8>) {
    let mut sizes = pieces.split(',').map(|p| p.parse::<usize>().unwrap());
    let first = sizes.next().unwrap().min(data.len());
    let mut input = Input {
        data,
        given: first,
        pieces: sizes.collect::<Vec<_>>().into_iter(),
        calls: 0,
    };
    let mut output = Output {
        fail,
        calls: 0,
        written: 0,
        hash: 0xcbf2_9ce4_8422_2325,
        data: Vec::new(),
    };
    let mut back = InflateBack9::new();
    let result = back.inflate_back9(&data[..first], &mut input, &mut output);
    let ret = match result.result {
        Ok(Status::StreamEnd) => 1,
        Ok(status) => panic!("{status:?}"),
        Err(e) => e.code().number(),
    };
    let unused = result.unused.map_or("null".to_string(), |n| n.to_string());
    let msg = back.msg().map_or("-".to_string(), |m| hex(m.as_bytes()));
    let answer = format!(
        "ok {ret}/{unused}/{msg}/{}/{}/{} {:016x}",
        input.calls, output.calls, output.written, output.hash
    );
    (answer, output.data)
}

/// The port's answer to an `inflate9` request.
fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    let [_, pieces, fail, data] = words[..] else {
        panic!("{request:.100}")
    };
    decode(pieces, fail.parse().unwrap(), &unhex(data)).0
}

/// Writes bits the way deflate packs them: from the low bit of each byte.
struct Bits {
    bytes: Vec<u8>,
    hold: u64,
    count: u32,
}

impl Bits {
    fn put(&mut self, value: u32, count: u32) {
        self.hold |= u64::from(value) << self.count;
        self.count += count;
        while self.count >= 8 {
            self.bytes.push(self.hold as u8);
            self.hold >>= 8;
            self.count -= 8;
        }
    }

    /// A Huffman code, whose first bit is its highest.
    fn code(&mut self, code: u32, len: u8) {
        self.put(code.reverse_bits() >> (32 - u32::from(len)), u32::from(len));
    }

    fn align(&mut self) {
        if self.count > 0 {
            self.put(0, 8 - self.count);
        }
    }
}

/// The canonical code of each symbol with these lengths.
fn canonical(lens: &[u8]) -> Vec<u32> {
    let mut count = [0u32; 16];
    for &len in lens {
        count[len as usize] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; 16];
    let mut code = 0;
    for bits in 1..16 {
        code = (code + count[bits - 1]) << 1;
        next[bits] = code;
    }
    lens.iter()
        .map(|&len| {
            let code = next[len as usize];
            next[len as usize] += 1;
            code
        })
        .collect()
}

/// Lengths of a random complete prefix code with `leaves` codes no longer
/// than `max`: a single code is one bit long, as inflate_table9 allows.
fn random_lengths(rng: &mut Rng, leaves: usize, max: u8) -> Vec<u8> {
    if leaves == 1 {
        return vec![1];
    }
    let mut depths = vec![0u8];
    let mut last = 0;
    while depths.len() < leaves {
        // Split the last split leaf now and then, for long codes.
        let mut at = if rng.below(3) == 0 {
            last
        } else {
            rng.below(depths.len() as u64) as usize
        };
        while depths[at] >= max {
            at = rng.below(depths.len() as u64) as usize;
        }
        depths[at] += 1;
        depths.push(depths[at]);
        last = depths.len() - 1;
    }
    depths
}

/// Lengths for `count` symbols, of which `used` must have a code: either all
/// of them get one, or only the used ones, in random order.
fn code_lengths(rng: &mut Rng, count: usize, used: &[bool], max: u8) -> Vec<u8> {
    let mut symbols: Vec<usize> = if rng.below(2) == 0 {
        (0..count).collect()
    } else {
        (0..count).filter(|&s| used[s]).collect()
    };
    for i in (1..symbols.len()).rev() {
        symbols.swap(i, rng.below(i as u64 + 1) as usize);
    }
    let mut lens = vec![0u8; count];
    for (&symbol, len) in symbols.iter().zip(random_lengths(rng, symbols.len(), max)) {
        lens[symbol] = len;
    }
    lens
}

/// Deflate64's length codes 257..285: base and extra bits.
const LENGTHS: [(u32, u32); 29] = [
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 1),
    (13, 1),
    (15, 1),
    (17, 1),
    (19, 2),
    (23, 2),
    (27, 2),
    (31, 2),
    (35, 3),
    (43, 3),
    (51, 3),
    (59, 3),
    (67, 4),
    (83, 4),
    (99, 4),
    (115, 4),
    (131, 5),
    (163, 5),
    (195, 5),
    (227, 5),
    (3, 16),
];
/// Deflate64's distance codes 0..31: base and extra bits.
const DISTANCES: [(u32, u32); 32] = [
    (1, 0),
    (2, 0),
    (3, 0),
    (4, 0),
    (5, 1),
    (7, 1),
    (9, 2),
    (13, 2),
    (17, 3),
    (25, 3),
    (33, 4),
    (49, 4),
    (65, 5),
    (97, 5),
    (129, 6),
    (193, 6),
    (257, 7),
    (385, 7),
    (513, 8),
    (769, 8),
    (1025, 9),
    (1537, 9),
    (2049, 10),
    (3073, 10),
    (4097, 11),
    (6145, 11),
    (8193, 12),
    (12289, 12),
    (16385, 13),
    (24577, 13),
    (32769, 14),
    (49153, 14),
];

/// A literal, or a match of a length and a distance coded with these codes.
enum Token {
    Literal(u8),
    Match {
        code: usize,
        extra: u32,
        dcode: usize,
        dextra: u32,
    },
}

/// Makes Deflate64 streams, and the data they decode to.
struct Encoder<'r> {
    rng: &'r mut Rng,
    bits: Bits,
    data: Vec<u8>,
    /// False once a code the stream's tables leave out was written.
    valid: bool,
}

impl Encoder<'_> {
    /// Literals and matches adding about `len` bytes to the data.
    fn tokens(&mut self, len: usize) -> Vec<Token> {
        let start = self.data.len();
        let mut tokens = Vec::new();
        let small = self.rng.below(2) == 0;
        while self.data.len() < start + len {
            if self.data.is_empty() || self.rng.below(3) == 0 {
                let byte = if small {
                    self.rng.below(8) as u8 + b'a'
                } else {
                    self.rng.next() as u8
                };
                self.data.push(byte);
                tokens.push(Token::Literal(byte));
                continue;
            }
            let length = match self.rng.below(10) {
                0 => 3 + self.rng.below(65536) as u32,
                1 => 259 + self.rng.below(2000) as u32,
                _ => 3 + self.rng.below(256) as u32,
            };
            let reach = self.data.len().min(65536) as u64;
            let distance = match self.rng.below(4) {
                0 => reach as u32 - self.rng.below(reach.min(100)) as u32,
                1 => 1 + self.rng.below(reach.min(16)) as u32,
                _ => 1 + self.rng.below(reach) as u32,
            };
            // Length 285 can code any length: use it now and then.
            let code = if length > 258 || self.rng.below(20) == 0 {
                28
            } else {
                LENGTHS[..28]
                    .iter()
                    .rposition(|&(base, _)| base <= length)
                    .unwrap()
            };
            let dcode = DISTANCES
                .iter()
                .rposition(|&(base, _)| base <= distance)
                .unwrap();
            for _ in 0..length {
                self.data
                    .push(self.data[self.data.len() - distance as usize]);
            }
            tokens.push(Token::Match {
                code,
                extra: length - LENGTHS[code].0,
                dcode,
                dextra: distance - DISTANCES[dcode].0,
            });
        }
        tokens
    }

    /// With `bad`, the first distance is the code a one-code distance table
    /// leaves out, a 1 bit: "invalid distance code".
    fn write_tokens(&mut self, tokens: &[Token], lit: &[u8], dist: &[u8], mut bad: bool) {
        let lit_codes = canonical(lit);
        let dist_codes = canonical(dist);
        for token in tokens {
            match *token {
                Token::Literal(byte) => {
                    self.bits.code(lit_codes[byte as usize], lit[byte as usize])
                }
                Token::Match {
                    code,
                    extra,
                    dcode,
                    dextra,
                } => {
                    self.bits.code(lit_codes[257 + code], lit[257 + code]);
                    self.bits.put(extra, LENGTHS[code].1);
                    if bad {
                        self.bits.put(1, 1);
                        self.valid = false;
                        bad = false;
                    }
                    self.bits.code(dist_codes[dcode], dist[dcode]);
                    self.bits.put(dextra, DISTANCES[dcode].1);
                }
            }
        }
        self.bits.code(lit_codes[256], lit[256]);
    }

    fn stored(&mut self, last: bool) {
        self.bits.put(u32::from(last), 1);
        self.bits.put(0, 2);
        self.bits.align();
        let len = match self.rng.below(4) {
            0 => 0,
            1 => 65535,
            _ => self.rng.below(3000) as usize,
        };
        self.bits.put(len as u32, 16);
        self.bits.put(!len as u32 & 0xffff, 16);
        for _ in 0..len {
            let byte = self.rng.next() as u8;
            self.data.push(byte);
            self.bits.put(u32::from(byte), 8);
        }
    }

    fn fixed(&mut self, last: bool, len: usize) {
        self.bits.put(u32::from(last), 1);
        self.bits.put(1, 2);
        let tokens = self.tokens(len);
        let lit: Vec<u8> = (0..288)
            .map(|s| match s {
                0..144 => 8,
                144..256 => 9,
                256..280 => 7,
                _ => 8,
            })
            .collect();
        self.write_tokens(&tokens, &lit, &[5; 32], false);
    }

    fn dynamic(&mut self, last: bool, len: usize) {
        self.bits.put(u32::from(last), 1);
        self.bits.put(2, 2);
        let tokens = self.tokens(len);
        let mut lit_used = vec![false; 286];
        let mut dist_used = vec![false; 32];
        lit_used[256] = true;
        for token in &tokens {
            match *token {
                Token::Literal(byte) => lit_used[byte as usize] = true,
                Token::Match { code, dcode, .. } => {
                    lit_used[257 + code] = true;
                    dist_used[dcode] = true;
                }
            }
        }
        // infback9 wants at least one distance code.
        if !dist_used.contains(&true) {
            dist_used[self.rng.below(32) as usize] = true;
        }
        let nlen = 1 + lit_used.iter().rposition(|&u| u).unwrap();
        let nlen = nlen.max(257) + self.rng.below(287 - nlen.max(257) as u64) as usize;
        let ndist = 1 + dist_used.iter().rposition(|&u| u).unwrap();
        let ndist = ndist + self.rng.below(33 - ndist as u64) as usize;
        let lit = code_lengths(self.rng, nlen, &lit_used, 15);
        let dist = code_lengths(self.rng, ndist, &dist_used, 15);

        // The lengths, with runs coded by 16, 17 and 18 now and then.
        let all: Vec<u8> = lit.iter().chain(&dist).copied().collect();
        let mut symbols = Vec::new(); // (symbol, extra)
        let mut i = 0;
        while i < all.len() {
            let mut run = all[i..].iter().take_while(|&&l| l == all[i]).count();
            if all[i] == 0 && run >= 3 && self.rng.below(4) != 0 {
                run = run.min(138);
                if run >= 11 {
                    symbols.push((18u8, run as u32 - 11));
                } else {
                    symbols.push((17, run as u32 - 3));
                }
                i += run;
            } else if i > 0 && all[i - 1] == all[i] && run >= 3 && self.rng.below(2) == 0 {
                run = run.min(6);
                symbols.push((16, run as u32 - 3));
                i += run;
            } else {
                symbols.push((all[i], 0));
                i += 1;
            }
        }
        let mut cl_used = [false; 19];
        for &(symbol, _) in &symbols {
            cl_used[symbol as usize] = true;
        }
        // A code length code must be complete: two codes at least.
        if cl_used.iter().filter(|&&u| u).count() < 2 {
            let other = cl_used.iter().position(|&u| !u).unwrap();
            cl_used[other] = true;
        }
        let cl = code_lengths(self.rng, 19, &cl_used, 7);
        const ORDER: [usize; 19] = [
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
        ];
        let ncode = (4..=19).rev().find(|&n| cl[ORDER[n - 1]] != 0).unwrap_or(4);
        self.bits.put(nlen as u32 - 257, 5);
        self.bits.put(ndist as u32 - 1, 5);
        self.bits.put(ncode as u32 - 4, 4);
        for &symbol in &ORDER[..ncode] {
            self.bits.put(u32::from(cl[symbol]), 3);
        }
        let cl_codes = canonical(&cl);
        for &(symbol, extra) in &symbols {
            self.bits
                .code(cl_codes[symbol as usize], cl[symbol as usize]);
            match symbol {
                16 => self.bits.put(extra, 2),
                17 => self.bits.put(extra, 3),
                18 => self.bits.put(extra, 7),
                _ => {}
            }
        }
        let bad = dist.iter().filter(|&&l| l != 0).count() == 1 && self.rng.below(4) == 0;
        self.write_tokens(&tokens, &lit, &dist, bad);
    }
}

/// A Deflate64 stream of a few blocks, and its data, or `None` if the
/// stream is not valid.
fn deflate64(rng: &mut Rng, size: usize) -> (Vec<u8>, Option<Vec<u8>>) {
    let mut encoder = Encoder {
        rng,
        bits: Bits {
            bytes: Vec::new(),
            hold: 0,
            count: 0,
        },
        data: Vec::new(),
        valid: true,
    };
    let blocks = 1 + encoder.rng.below(5);
    for block in 0..blocks {
        let last = block + 1 == blocks;
        let len = encoder.rng.below(size as u64 + 1) as usize;
        match encoder.rng.below(5) {
            0 => encoder.stored(last),
            1 => encoder.fixed(last, len),
            _ => encoder.dynamic(last, len),
        }
    }
    encoder.bits.align();
    let data = encoder.valid.then_some(encoder.data);
    (encoder.bits.bytes, data)
}

/// A raw deflate stream from the port's compressor.
fn deflate(rng: &mut Rng, data: &[u8]) -> Vec<u8> {
    let level = rng.below(10) as i32;
    let mut stream = Deflate::new(level, -15, 8, 0).unwrap();
    let mut out = vec![0; stream.bound(data.len() as u64) as usize];
    let mut output = OutBuffer::new(&mut out);
    let ret = stream.deflate(&mut output, &mut InBuffer::new(data), Flush::Finish);
    assert_eq!(ret, Ok(Status::StreamEnd));
    let written = output.pos;
    out.truncate(written);
    out
}

/// How the input is given: pieces of random sizes, sometimes a zero one
/// (the end), sometimes everything at the start.
fn pieces(rng: &mut Rng, len: usize) -> Vec<usize> {
    let mut pieces = Vec::new();
    match rng.below(4) {
        0 => pieces.push(len + rng.below(3) as usize),
        1 => pieces.push(0),
        _ => {
            for _ in 0..1 + rng.below(8) {
                let piece = match rng.below(10) {
                    0 => 0,
                    1..4 => 1 + rng.below(4) as usize,
                    _ => rng.below(len as u64 + 1) as usize,
                };
                pieces.push(piece);
            }
            // A zero piece only rarely, as it ends the input.
            if rng.below(4) != 0 {
                for piece in pieces.iter_mut().skip(1) {
                    *piece = (*piece).max(1);
                }
            }
        }
    }
    pieces
}

/// `count` streams, as requests: Deflate64 streams, sometimes damaged or
/// with bytes after them, deflate streams, and random bytes.
fn requests(rng: &mut Rng, count: usize, size: usize) -> Vec<(String, Option<Vec<u8>>)> {
    let mut requests = Vec::new();
    for _ in 0..count {
        let len = 1 + rng.below(size as u64) as usize;
        let (mut stream, data) = deflate64(rng, len);
        let mut data = data.unwrap_or_default();
        match rng.below(8) {
            0..3 => {}
            3 => stream.extend((0..1 + rng.below(10)).map(|_| rng.next() as u8)),
            4 | 5 => {
                stream = damage(rng, &stream);
                data.clear();
            }
            6 => {
                let plain: Vec<u8> = (0..rng.below(5000)).map(|_| rng.below(6) as u8).collect();
                stream = deflate(rng, &plain);
                data.clear();
            }
            _ => {
                stream = (0..rng.below(200)).map(|_| rng.next() as u8).collect();
                data.clear();
            }
        }
        // out() fails now and then.
        let fail = if rng.below(6) == 0 {
            rng.below(4) as i64
        } else {
            -1
        };
        let pieces = pieces(rng, stream.len());
        // The data comes out whole if neither the input nor the output
        // ends early.
        let whole = fail == -1 && !data.is_empty() && !pieces[1..].contains(&0);
        let pieces: Vec<String> = pieces.iter().map(ToString::to_string).collect();
        let request = format!("inflate9 {} {fail} {}", pieces.join(","), hex(&stream));
        let whole = whole.then_some(data);
        requests.push((request, whole));
    }
    requests
}

#[test]
fn decodes_generated_streams() {
    let mut rng = Rng(0x5eed_0064);
    let mut checked = 0;
    for (request, data) in requests(&mut rng, 300, 200_000) {
        let Some(data) = data else { continue };
        let words: Vec<&str> = request.split(' ').collect();
        let (answer, out) = decode(words[1], -1, &unhex(words[3]));
        assert!(answer.starts_with("ok 1/"), "{answer} {request:.200}");
        assert!(
            out == data,
            "{} bytes, not {}: {request:.200}",
            out.len(),
            data.len()
        );
        checked += 1;
    }
    assert!(checked > 80, "only {checked} streams");
}

#[test]
fn port_matches_zlib() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x5eed_0065);
    for (request, data) in requests(&mut rng, 600, 200_000) {
        let want = oracle.ask(&request);
        assert_eq!(answer(&request), want, "{request:.300}");
        // zlib decodes the generated streams to their data too.
        if let Some(data) = data {
            let hash = format!("{:016x}", fnv64(&data));
            assert!(want.starts_with("ok 1/") && want.ends_with(&hash), "{want}");
        }
    }
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/inflate9.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(recorded_form(&answer(request)), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > 300, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/inflate9.txt from the oracle"]
fn record_inflate9_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng(0x5eed_0066);
    let mut text = String::from(
        "# Answers from zlib 1.3.2 contrib/infback9 (tools/zlib-oracle), replayed by crates/deflate/tests/deflate64.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test deflate_deflate64 record_inflate9_answers -- --ignored\n",
    );
    for (request, _) in requests(&mut rng, 500, 3_000) {
        // Keep the file small: the large inputs are for the live comparison.
        if request.len() > 4_000 {
            continue;
        }
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::write(recorded_path(), text).expect("written");
}

/// Decodes `stream` with [`Inflate9`], giving it input and output space in
/// pieces of random sizes: the result, and all the output. The result is
/// `ErrorCode::Buf` if the stream needs more input than there is.
fn decode9(rng: &mut Rng, stream: &[u8]) -> (Result<Status>, Vec<u8>, Option<&'static str>) {
    let mut inflate = Inflate9::new();
    let mut out = Vec::new();
    let mut pos = 0;
    let whole = rng.below(4) == 0;
    loop {
        let left = stream.len() - pos;
        let in_len = if whole || rng.below(3) == 0 {
            left
        } else {
            (1 + rng.below(300) as usize).min(left)
        };
        let space = if whole {
            stream.len() * 1100 + 70_000
        } else {
            1 + rng.below(70_000) as usize
        };
        let mut buf = vec![0; space];
        let mut input = InBuffer::new(&stream[pos..pos + in_len]);
        let mut output = OutBuffer::new(&mut buf);
        let ret = inflate.inflate(&mut output, &mut input);
        pos += input.pos;
        let written = output.pos;
        out.extend_from_slice(&buf[..written]);
        match ret {
            Ok(Status::Ok) => {}
            Err(e) if e.code() == ErrorCode::Buf && pos < stream.len() => {}
            ret => return (ret, out, inflate.msg()),
        }
    }
}

/// Whether [`Inflate9`] decodes `stream` as infback9.c answered `want`
/// (the oracle's `inflate9` answer, with out() never failing): the same
/// end and message, and the same output, of which infback9.c gives out
/// only full windows before an error.
fn check9(rng: &mut Rng, stream: &[u8], want: &str) {
    let (ret, out, msg) = decode9(rng, stream);
    let fields: Vec<&str> = want
        .split_once(' ')
        .unwrap()
        .1
        .split(&['/', ' '][..])
        .collect();
    let [code, _, want_msg, _, _, written, hash] = fields[..] else {
        panic!("{want}")
    };
    let written: usize = written.parse().unwrap();
    let got_msg = msg.map_or("-".to_string(), |m| hex(m.as_bytes()));
    match code {
        "1" => assert_eq!(ret, Ok(Status::StreamEnd), "{want}"),
        "-3" => {
            assert_eq!(ret.map_err(|e| e.code()), Err(ErrorCode::Data), "{want}");
            assert_eq!(got_msg, want_msg, "{want}");
        }
        _ => assert_eq!(ret.map_err(|e| e.code()), Err(ErrorCode::Buf), "{want}"),
    }
    if code == "1" {
        assert_eq!(out.len(), written, "{want}");
    }
    assert!(
        out.len() >= written,
        "{} bytes, not {written}: {want}",
        out.len()
    );
    assert_eq!(format!("{:016x}", fnv64(&out[..written])), hash, "{want}");
}

/// The stream of an `inflate9` request, if infback9.c gets all of it
/// (no zero piece ends its input) and out() never fails.
fn stream_of(request: &str) -> Option<Vec<u8>> {
    let words: Vec<&str> = request.split(' ').collect();
    let whole = !words[1].split(',').skip(1).any(|p| p == "0");
    (whole && words[2] == "-1").then(|| unhex(words[3]))
}

#[test]
fn inflate9_decodes_generated_streams() {
    let mut rng = Rng(0x5eed_0067);
    let mut checked = 0;
    for (request, data) in requests(&mut rng, 300, 200_000) {
        let Some(data) = data else { continue };
        let stream = stream_of(&request).unwrap();
        let (ret, out, _) = decode9(&mut rng, &stream);
        assert_eq!(ret, Ok(Status::StreamEnd), "{request:.200}");
        assert!(
            out == data,
            "{} bytes, not {}: {request:.200}",
            out.len(),
            data.len()
        );
        checked += 1;
    }
    assert!(checked > 80, "only {checked} streams");
}

#[test]
fn inflate9_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/inflate9.txt");
    let mut rng = Rng(0x5eed_0068);
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        let Some(stream) = stream_of(request) else {
            continue;
        };
        if want.starts_with("fnv64:") {
            continue;
        }
        check9(&mut rng, &stream, want);
        checked += 1;
    }
    assert!(checked > 250, "only {checked} recorded answers");
}

#[test]
fn inflate9_matches_zlib() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x5eed_0069);
    for (request, _) in requests(&mut rng, 600, 200_000) {
        let Some(stream) = stream_of(&request) else {
            continue;
        };
        let want = oracle.ask(&request);
        check9(&mut rng, &stream, &want);
    }
}
