//! Comparison with liblzo2 2.10's `lzo1x_decompress_safe`, and with
//! lzokay's own decompressor, through `tools/lzo-oracle`.
//!
//! The oracle is a small C++ program built with liblzo2's and lzokay's
//! sources by `scripts/testdata.py`. It compresses with liblzo2's LZO1X
//! compressors (`lzo1x_1` and its `1_11`, `1_12` and `1_15` forms, and
//! `lzo1x_999` at every level), and answers `decompress <capacity> <hex>`
//! with what liblzo2 and lzokay return and leave in an output of exactly
//! that size, filled with a pattern before. [`answer`] gives the port's
//! answer in the same form as liblzo2's, so the two compare as text: the
//! result, the length on success, and a hash of the whole output, past
//! what was written too.
//!
//! - With the oracle built, generated requests are compared with liblzo2
//!   directly: inputs of many kinds and sizes (empty, random, runs and
//!   short periods, text, sizes around the 49,152 bytes `lzo1x_1` works
//!   in and SquashFS's blocks of 128 KiB and 1 MiB), compressed by every
//!   compressor, decoded into outputs of exactly their size, one byte
//!   short, empty and larger, whole and damaged (bits flipped, bytes
//!   changed, cut short, bytes inserted). The port must give liblzo2's
//!   answer to every one. lzokay must give the same bytes on every valid
//!   stream; on the others it fails where liblzo2 does not, or with
//!   another error, as `docs/lzo.md` explains, and the test counts how.
//! - With the Silesia corpus fetched too (`--group bench`), its files are
//!   compressed in SquashFS's blocks and decoded by both.
//! - Everywhere, including where the oracle cannot be built (Windows, and
//!   the emulated i686 and s390x jobs), `testdata/oracle/lzo.txt` replays
//!   answers liblzo2 gave earlier. `cargo test -p hivepack --test
//!   lzo_oracle record_oracle_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use hivepack::lzo::{Error, decompress};

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Where `scripts/testdata.py` keeps what it fetches and generates.
fn cache() -> PathBuf {
    std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"))
}

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/lzo.txt")
}

/// The oracle program, running.
struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Oracle {
    /// The oracle built by `scripts/testdata.py`, or `None` with a note when
    /// it has not been built. CI lists the `generated` group in
    /// `HIVEPACK_TESTDATA_REQUIRED` where it builds the oracle, and then a
    /// missing oracle fails the test.
    fn spawn() -> Option<Oracle> {
        let folder = cache().join("lzo-oracle");
        if !folder.join(".complete").exists() {
            let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
            assert!(
                !required.split(',').any(|g| g == "all" || g == "generated"),
                "the oracle is missing: run `python3 scripts/testdata.py fetch --group generated`"
            );
            eprintln!(
                "skipping: the oracle is not built (scripts/testdata.py fetch --group generated)"
            );
            return None;
        }
        let mut child = Command::new(folder.join("oracle"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the oracle starts");
        let input = child.stdin.take().expect("stdin");
        let output = BufReader::new(child.stdout.take().expect("stdout"));
        Some(Oracle {
            child,
            input,
            output,
        })
    }

    fn ask(&mut self, request: &str) -> String {
        writeln!(self.input, "{request}").expect("request sent");
        self.input.flush().expect("request sent");
        let mut line = String::new();
        self.output.read_line(&mut line).expect("answer read");
        let line = line.trim_end().to_string();
        assert!(
            line != "bad" && !line.is_empty(),
            "the oracle answered {line:?} to {request:.200}"
        );
        line
    }

    /// `data` compressed by liblzo2's compressor `method`.
    fn compress(&mut self, method: &str, data: &[u8]) -> Vec<u8> {
        let answer = self.ask(&format!("compress {method} {}", hex(data)));
        let (len, stream) = answer.split_once(' ').unwrap();
        let stream = unhex(stream);
        assert_eq!(stream.len(), len.parse::<usize>().unwrap());
        stream
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".into();
    }
    let mut text = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn fnv64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// xorshift64*, so that failures can be replayed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<T: Copy>(&mut self, values: &[T]) -> T {
        values[self.below(values.len() as u64) as usize]
    }
}

/// The output buffer before a call, as the oracle fills it: byte `i` is
/// `i * 31 + 7`.
fn pattern(capacity: usize) -> Vec<u8> {
    (0..capacity)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
        .collect()
}

/// The port's answer to `decompress <capacity> <hex>`: the result as
/// liblzo2 numbers it, the length on success (`-` on an error, where the
/// port returns none), and the hash of the whole output.
fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    let ["decompress", capacity, data] = words[..] else {
        panic!("not a request: {request:.100}");
    };
    let mut out = pattern(capacity.parse().unwrap());
    let result = decompress(&unhex(data), &mut out);
    form(result, &out)
}

fn form(result: Result<usize, Error>, out: &[u8]) -> String {
    match result {
        Ok(len) => format!("0 {len} {:016x}", fnv64(out)),
        Err(e) => format!("{} - {:016x}", e.number(), fnv64(out)),
    }
}

/// liblzo2's and lzokay's answers, from the oracle's, in [`answer`]'s
/// form.
fn split_answer(oracle: &str) -> (String, (i32, usize, String)) {
    let words: Vec<&str> = oracle.split(' ').collect();
    let [ret, len, hash, k_ret, k_len, k_hash] = words[..] else {
        panic!("the oracle answered {oracle:?}");
    };
    let liblzo2 = if ret == "0" {
        format!("0 {len} {hash}")
    } else {
        format!("{ret} - {hash}")
    };
    (
        liblzo2,
        (
            k_ret.parse().unwrap(),
            k_len.parse().unwrap(),
            k_hash.to_string(),
        ),
    )
}

/// liblzo2's compressors, as the oracle names them; the 999 ones are slow,
/// and get the smaller inputs.
const FAST_METHODS: &[&str] = &["1", "1_11", "1_12", "1_15"];
const SLOW_METHODS: &[&str] = &[
    "999", "999_1", "999_2", "999_3", "999_4", "999_5", "999_6", "999_7", "999_8", "999_9",
];

/// Inputs of many kinds: random bytes from alphabets of every size, runs
/// (some long, whose matches take lengths of many zero bytes), short
/// periods, text, and mixes of random and repeated parts with matches at
/// every distance up to LZO1X's 48 KiB.
fn input(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len + 300);
    match rng.below(7) {
        0 => {
            while data.len() < len {
                data.push(rng.next() as u8);
            }
        }
        1 => {
            let alphabet = 1 + rng.below(256);
            while data.len() < len {
                data.push(rng.below(alphabet) as u8);
            }
        }
        2 => {
            while data.len() < len {
                let run = match rng.below(3) {
                    0 => 1 + rng.below(10),
                    1 => 250 + rng.below(20),
                    _ => 1 + rng.below(5000),
                };
                let byte = rng.below(4) as u8;
                data.resize(data.len() + run as usize, byte);
            }
        }
        3 => {
            let period = 1 + rng.below(40) as usize;
            let unit: Vec<u8> = (0..period).map(|_| rng.next() as u8).collect();
            while data.len() < len {
                data.extend_from_slice(&unit);
            }
        }
        4 => {
            let words: &[&[u8]] = &[
                b"the ",
                b"LZO ",
                b"block ",
                b"of ",
                b"a ",
                b"SquashFS ",
                b"image ",
                b"and ",
                b"its ",
                b"literals, ",
                b"matches\n",
                b"Oberhumer ",
            ];
            while data.len() < len {
                data.extend_from_slice(rng.pick(words));
            }
        }
        _ => {
            // Random pieces, and copies of earlier ones from up to 49,152
            // bytes back, of every length.
            while data.len() < len {
                if data.len() < 16 || rng.below(3) == 0 {
                    for _ in 0..1 + rng.below(300) {
                        data.push(rng.next() as u8);
                    }
                } else {
                    let back = 1 + rng.below(data.len().min(49_200) as u64) as usize;
                    let n = match rng.below(4) {
                        0 => 2 + rng.below(8),
                        1 => 2 + rng.below(40),
                        2 => 250 + rng.below(300),
                        _ => 1 + rng.below(3000),
                    } as usize;
                    let from = data.len() - back;
                    for i in 0..n {
                        data.push(data[from + i]);
                    }
                }
            }
        }
    }
    data.truncate(len);
    data
}

/// A length for an input: empty or tiny, around where `lzo1x_1` gives up
/// matching (20 bytes) or works in pieces (49,152 bytes), around the first
/// literal run's longest (238 bytes), or up to `max`.
fn length(rng: &mut Rng, max: usize) -> usize {
    let len = match rng.below(10) {
        0 => rng.below(4) as usize,
        1 => 10 + rng.below(20) as usize,
        2 => 230 + rng.below(20) as usize,
        3 => 49_152 - 3 + rng.below(7) as usize,
        4 | 5 => rng.below(4000) as usize,
        6 | 7 => rng.below(60_000) as usize,
        _ => rng.below(max as u64 + 1) as usize,
    };
    len.min(max)
}

/// Bytes changed, bits flipped, cut short or lengthened.
fn damage(rng: &mut Rng, stream: &[u8]) -> Vec<u8> {
    let mut damaged = stream.to_vec();
    for _ in 0..1 + rng.below(3) {
        if damaged.is_empty() {
            break;
        }
        let at = rng.below(damaged.len() as u64) as usize;
        match rng.below(5) {
            0 => damaged[at] ^= 1 << rng.below(8),
            1 => damaged[at] = rng.next() as u8,
            2 => damaged.truncate(at),
            3 => damaged.insert(at, rng.next() as u8),
            // Near the end, where the marker is.
            _ => {
                let at = damaged.len() - 1 - rng.below(damaged.len().min(4) as u64) as usize;
                damaged[at] ^= 1 << rng.below(8);
            }
        }
    }
    damaged
}

/// A request, and whether its stream is liblzo2's, whole, into an output
/// large enough.
struct Request {
    text: String,
    valid: bool,
}

/// Generated requests: `count` inputs of up to `max` bytes, each
/// compressed by one of liblzo2's compressors and decoded several ways,
/// and the larger sizes SquashFS's blocks have.
fn requests(oracle: &mut Oracle, rng: &mut Rng, count: usize, max: usize) -> Vec<Request> {
    let mut requests = Vec::new();
    let push = |requests: &mut Vec<Request>, capacity: usize, stream: &[u8], valid| {
        requests.push(Request {
            text: format!("decompress {capacity} {}", hex(stream)),
            valid,
        });
    };

    // A few by hand: empty and tiny inputs, the end-of-stream marker alone,
    // with more after it and with other lengths, and an M4 instruction
    // first, whose distance reaches before the output.
    for stream in [
        &[][..],
        &[0x11],
        &[0x11, 0x00],
        &[0x11, 0x00, 0x00],
        &[0x11, 0x00, 0x00, 0x00],
        &[0x12, 0x00, 0x00],
        &[0x10, 0x00, 0x00, 0x00],
        &[0x10, 0x00, 0x05, 0x00, 0x00],
        &[0x11, 0x04, 0x00],
        &[0x12, b'a', 0x11, 0x00, 0x00],
        &[0x12, b'a', 0x00, 0x00, 0x11, 0x00, 0x00],
        &[0x15, b'a', b'b', b'c', b'd', 0x00, 0x00, 0x11, 0x00, 0x00],
        &[0x00, 0x00, 0x01, b'a', 0x11, 0x00, 0x00],
        &[0x01, b'a', b'b', b'c', b'd', 0x11, 0x00, 0x00],
        &[0x20, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00],
        &[0xff, 0x00],
    ] {
        for capacity in [0, 1, 4, 100] {
            push(&mut requests, capacity, stream, false);
        }
    }

    for i in 0..count {
        let len = length(rng, max);
        let data = input(rng, len);
        let method = if len <= 70_000 && i % 3 == 0 {
            rng.pick(SLOW_METHODS)
        } else {
            rng.pick(FAST_METHODS)
        };
        let stream = oracle.compress(method, &data);
        // Exactly the size, one byte short, empty, and larger.
        push(&mut requests, len, &stream, true);
        if len > 0 {
            push(&mut requests, len - 1, &stream, false);
        }
        if rng.below(4) == 0 {
            push(&mut requests, 0, &stream, len == 0);
        }
        push(
            &mut requests,
            len + 1 + rng.below(100) as usize,
            &stream,
            true,
        );
        for _ in 0..1 + rng.below(3) {
            let damaged = damage(rng, &stream);
            let capacity = if rng.below(3) == 0 { len } else { len + 300 };
            push(&mut requests, capacity, &damaged, false);
        }
    }
    requests
}

/// SquashFS's block sizes, and around them: inputs that fill a block.
fn block_requests(oracle: &mut Oracle, rng: &mut Rng) -> Vec<Request> {
    let mut requests = Vec::new();
    for (len, method) in [
        (131_072, "1"),
        (131_071, "1_15"),
        (131_073, "999"),
        (131_072, "999"),
        (1_048_576, "1"),
        (1_048_576, "1_11"),
        (1_048_576, "999"),
    ] {
        let data = input(rng, len);
        let stream = oracle.compress(method, &data);
        for capacity in [len, len - 1, 1_048_576 + 1] {
            requests.push(Request {
                text: format!("decompress {capacity} {}", hex(&stream)),
                valid: capacity >= len,
            });
        }
        let damaged = damage(rng, &stream);
        requests.push(Request {
            text: format!("decompress {len} {}", hex(&damaged)),
            valid: false,
        });
    }
    requests
}

/// How lzokay's answer stands beside liblzo2's, by kind, for the counts.
fn lzokay_kind(liblzo2: &str, port: &str, lzokay: (i32, usize, String)) -> String {
    let (k_ret, k_len, k_hash) = lzokay;
    let code = liblzo2.split(' ').next().unwrap();
    let same_bytes = port.ends_with(&k_hash);
    match (code, k_ret) {
        ("0", 0) if port == format!("0 {k_len} {k_hash}") => "both decode".into(),
        // lzokay's InputNotConsumed is a success code, 1.
        ("-8", 1) if same_bytes => "both: input not consumed".into(),
        ("-4", -2) => "both: input overrun".into(),
        ("-5", -3) => "both: output overrun".into(),
        ("-6", -4) => "both: lookbehind overrun".into(),
        _ => format!(
            "liblzo2 {code}, lzokay {k_ret}{}",
            if same_bytes { "" } else { ", other bytes" }
        ),
    }
}

#[test]
fn port_matches_liblzo2() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x5eed_1201);
    let mut requests = requests(&mut oracle, &mut rng, 600, 300_000);
    requests.extend(block_requests(&mut oracle, &mut rng));
    let mut codes = BTreeMap::new();
    let mut lzokay = BTreeMap::new();
    for request in &requests {
        let (want, lzokay_answer) = split_answer(&oracle.ask(&request.text));
        let got = answer(&request.text);
        assert_eq!(got, want, "{:.300}", request.text);
        *codes
            .entry(want.split(' ').next().unwrap().to_string())
            .or_insert(0) += 1;
        let kind = lzokay_kind(&want, &got, lzokay_answer);
        if request.valid {
            // lzokay decodes every one of liblzo2's streams as liblzo2
            // does.
            assert_eq!(kind, "both decode", "{:.300}", request.text);
        }
        if kind == "both decode" && !request.valid {
            // Where lzokay decodes a damaged stream, so does liblzo2, the
            // same.
            assert!(got.starts_with("0 "), "{:.300}", request.text);
        }
        *lzokay
            .entry(format!(
                "{} {kind}",
                if request.valid { "valid" } else { "other" }
            ))
            .or_insert(0) += 1;
    }
    eprintln!(
        "{} requests compared with liblzo2: {codes:?}",
        requests.len()
    );
    eprintln!("lzokay beside liblzo2: {lzokay:#?}");
    for code in ["0", "-4", "-5", "-6", "-8"] {
        assert!(
            codes.get(code).copied().unwrap_or(0) > 0,
            "no {code}: {codes:?}"
        );
    }
}

/// The Silesia corpus, when fetched (`--group bench`), compressed in
/// SquashFS's blocks by `lzo1x_1` (whole files) and `lzo1x_999` (the first
/// 4 MiB of each): every block decodes to the file, as liblzo2 decodes it.
#[test]
fn port_matches_liblzo2_on_silesia() {
    let silesia = cache().join("silesia");
    if !silesia.join(".complete").exists() {
        eprintln!("skipping: Silesia is not fetched (scripts/testdata.py fetch --group bench)");
        return;
    }
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("lzo-silesia");
    std::fs::create_dir_all(&scratch).unwrap();
    let mut files: Vec<PathBuf> = std::fs::read_dir(&silesia)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| !p.file_name().unwrap().to_string_lossy().starts_with('.'))
        .collect();
    files.sort();
    let mut blocks = 0;
    for file in &files {
        let data = std::fs::read(file).unwrap();
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        let head = scratch.join(format!("{name}.head"));
        std::fs::write(&head, &data[..data.len().min(4 << 20)]).unwrap();
        for (method, block, source) in [
            ("1", 131_072, file.as_path()),
            ("1", 1_048_576, file.as_path()),
            ("999", 131_072, head.as_path()),
        ] {
            let compressed = scratch.join(format!("{name}.{method}.{block}"));
            oracle.ask(&format!(
                "compressfile {method} {block} {} {}",
                source.display(),
                compressed.display()
            ));
            let want = oracle.ask(&format!("decompressfile {}", compressed.display()));
            let original = std::fs::read(source).unwrap();
            let got = decode_blocks(&compressed, &original);
            blocks += got.split(' ').next().unwrap().parse::<usize>().unwrap();
            assert_eq!(got, want, "{name}, lzo1x_{method}, blocks of {block}");
            std::fs::remove_file(&compressed).unwrap();
        }
        std::fs::remove_file(&head).unwrap();
    }
    eprintln!(
        "{blocks} blocks of {} Silesia files decoded as liblzo2 does",
        files.len()
    );
}

/// The blocks of a file the oracle's `compressfile` wrote, each decoded
/// into exactly its length and checked against `original`: the answer to
/// `decompressfile`.
fn decode_blocks(path: &Path, original: &[u8]) -> String {
    let file = std::fs::read(path).unwrap();
    let mut out = vec![0u8; original.len()];
    let (mut at, mut written, mut count, mut bad) = (0, 0, 0, 0);
    while at < file.len() {
        let compressed = u32::from_le_bytes(file[at..at + 4].try_into().unwrap()) as usize;
        let len = u32::from_le_bytes(file[at + 4..at + 8].try_into().unwrap()) as usize;
        let block = &file[at + 8..at + 8 + compressed];
        if decompress(block, &mut out[written..written + len]) != Ok(len) {
            bad += 1;
        }
        written += len;
        at += 8 + compressed;
        count += 1;
    }
    assert!(
        out == original,
        "{} does not decode to its file",
        path.display()
    );
    format!("{count} {bad} {written} {:016x}", fnv64(&out))
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/lzo.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(answer(request), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > 500, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/lzo.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng(0x5eed_1202);
    let mut text = String::from(
        "# Answers from liblzo2 2.10's lzo1x_decompress_safe (tools/lzo-oracle), replayed by crates/hivepack/tests/lzo_oracle.rs.\n\
         # Each line: the request, a tab, then the result, the length on success and the FNV-1a hash of the whole output.\n\
         # Regenerate with: cargo test -p hivepack --test lzo_oracle record_oracle_answers -- --ignored\n",
    );
    for request in requests(&mut oracle, &mut rng, 400, 1500) {
        // Keep the file small: the large inputs are for the live comparison.
        if request.text.len() > 3_000 {
            continue;
        }
        let (reply, _) = split_answer(&oracle.ask(&request.text));
        let _ = writeln!(text, "{}\t{reply}", request.text);
    }
    std::fs::write(recorded_path(), text).expect("written");
}
