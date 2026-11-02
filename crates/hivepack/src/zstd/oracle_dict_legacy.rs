//! Comparison of the dictionary builder's own parts with libzstd's: the
//! suffix arrays of `divsufsort`, and the segments and content of the
//! legacy trainer (`ZDICT_trainBuffer_legacy`, with the checks and the
//! selection of `ZDICT_trainFromBuffer_unsafe_legacy` around it), through
//! the oracle's `divsufsort` and `legacy` requests (see
//! `tools/zstd-oracle/oracle.c`). The oracle also runs the whole of
//! `ZDICT_trainFromBuffer_legacy` for each `legacy` request, and answers
//! "bad" unless its result agrees: the same failure, or the same content
//! after its entropy tables.
//!
//! The inputs: random bytes, text, few symbols, runs, periods short and
//! long, every byte value, Fibonacci words, blocks repeated with changes,
//! from nothing to a few MB; every file of the committed test data, and
//! pieces of the Silesia corpus where it is fetched. Large inputs go to the
//! oracle as pieces of files (`file:<offset>:<length>:<path>`), generated
//! ones through a temporary file. The samples for the trainer are records
//! made of shared words and phrases, binary data, and pieces of files, cut
//! at random, with every selectivity, notification level and dictionary
//! size that matters.
//!
//! As for the other requests, the tests compare thousands of requests with
//! libzstd live where the oracle is built, and replay recorded answers
//! everywhere, from `testdata/oracle/dict-legacy.txt`, of small inputs.
//! `cargo test -p hivepack --all-features record_dict_legacy_answers -- --ignored`
//! rewrites it.

use std::fmt::Write as _;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::zstd::dict_builder::divsufsort::divsufsort;
use crate::zstd::dict_builder::legacy::{
    LegacyParams, NOISELENGTH, fill_noise, legacy_content, legacy_segments,
    train_from_buffer_legacy,
};
use crate::zstd::dict_builder::zdict::DictParams;
use crate::zstd::oracle::{
    Oracle, Rng, failed, fnv64, hex, list, recorded_form, repository, unlist,
};

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/dict-legacy.txt")
}

/// The bytes of a request's source: hexadecimal, or
/// `file:<offset>:<length>:<path>`, that piece of a file.
fn source(text: &str) -> Vec<u8> {
    let Some(piece) = text.strip_prefix("file:") else {
        return crate::zstd::oracle::unhex(text);
    };
    let mut parts = piece.splitn(3, ':');
    let offset: u64 = parts.next().and_then(|p| p.parse().ok()).expect("offset");
    let length: usize = parts.next().and_then(|p| p.parse().ok()).expect("length");
    let mut file = std::fs::File::open(parts.next().expect("path")).expect("source file");
    file.seek(SeekFrom::Start(offset)).expect("seek");
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes).expect("the piece");
    bytes
}

/// The answer to `divsufsort`: the suffix array, or its hash past 4096
/// bytes.
fn suffix_array_answer(text: &[u8]) -> String {
    let mut sa = vec![0i32; text.len()];
    if divsufsort(text, &mut sa).is_err() {
        return "err -1".into();
    }
    if text.len() <= 4096 {
        format!("ok {}", list(&sa))
    } else {
        let bytes: Vec<u8> = sa.iter().flat_map(|s| s.to_le_bytes()).collect();
        format!("ok {}:{:016x}", text.len(), fnv64(&bytes))
    }
}

/// The answer to `legacy`: the segments and the content, as the oracle
/// answers.
fn legacy_answer(
    max_dict_size: usize,
    params: &LegacyParams,
    sizes: &[usize],
    bytes: &[u8],
) -> String {
    let total: usize = sizes.iter().sum();
    assert!(total <= bytes.len(), "the samples are in the source");
    let mut dict = vec![0u8; max_dict_size];
    if total < 512 {
        // `ZDICT_trainFromBuffer_legacy`: no dictionary.
        return match train_from_buffer_legacy(&mut dict, bytes, sizes, *params) {
            Ok(0) => "none".into(),
            other => format!("{other:?}"),
        };
    }
    // `ZDICT_trainFromBuffer_legacy`'s copy, with the guard band.
    let mut samples = bytes[..total].to_vec();
    samples.resize(total + NOISELENGTH, 0);
    fill_noise(&mut samples[total..]);
    let mut dict_list = match legacy_segments(max_dict_size, &samples, sizes, params) {
        Ok(list) => list,
        Err(error) => return failed(error),
    };
    let count = dict_list[0].pos as usize;
    let mut text = String::from("ok ");
    if count <= 1 {
        text.push('-');
    }
    for (i, d) in dict_list[1..count].iter().enumerate() {
        let comma = if i > 0 { "," } else { "" };
        let _ = write!(text, "{comma}{}:{}:{}", d.pos, d.length, d.savings);
    }
    match legacy_content(&mut dict_list, &mut dict, &samples) {
        Ok(size) => {
            let _ = write!(
                text,
                " {} {size} {}",
                dict_list[0].pos,
                hex(&dict[max_dict_size - size..])
            );
        }
        Err(error) => {
            let _ = write!(text, " e{}", error.code().number());
        }
    }
    text
}

/// The port's answer to a dictionary builder request, in the oracle's
/// format.
pub(crate) fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    match words[..] {
        ["divsufsort", src] => suffix_array_answer(&source(src)),
        [
            "legacy",
            max_dict_size,
            selectivity,
            notification,
            sizes,
            src,
        ] => {
            let params = LegacyParams {
                selectivity_level: selectivity.parse().expect("selectivity"),
                z_params: DictParams {
                    notification_level: notification.parse().expect("notificationLevel"),
                    ..DictParams::default()
                },
            };
            let sizes: Vec<usize> = unlist(sizes).into_iter().map(|s| s as usize).collect();
            legacy_answer(
                max_dict_size.parse().expect("maxDictSize"),
                &params,
                &sizes,
                &source(src),
            )
        }
        _ => "bad".into(),
    }
}

/// Texts for `divsufsort`, of each kind its parts treat differently.
pub(crate) fn text(rng: &mut Rng, len: usize) -> Vec<u8> {
    match rng.range(0, 13) {
        0 => rng.bytes(len),
        1 => {
            // Few symbols.
            let alphabet = rng.range(1, 4);
            (0..len).map(|_| rng.range(0, alphabet - 1) as u8).collect()
        }
        2 => {
            // A period, short or long, sometimes broken.
            let period = if rng.range(0, 1) == 0 {
                rng.range(1, 8)
            } else {
                rng.range(9, 3000)
            } as usize;
            let unit = rng.bytes(period);
            let mut text: Vec<u8> = (0..len).map(|i| unit[i % period]).collect();
            if !text.is_empty() && rng.range(0, 1) == 0 {
                let at = rng.range(0, len as u64 - 1) as usize;
                text[at] = text[at].wrapping_add(1);
            }
            text
        }
        3 => rng.huffman_data(len),
        4 => rng.lz_data(len),
        5 => {
            // Runs of a few bytes, of every length.
            let mut text = Vec::with_capacity(len);
            while text.len() < len {
                let run = rng.range(1, 400) as usize;
                let byte = rng.range(0, 3) as u8;
                text.extend(std::iter::repeat_n(byte, run));
            }
            text.truncate(len);
            text
        }
        6 => {
            // A Fibonacci word: tandem repeats at every scale.
            let (mut a, mut b) = (vec![b'a'], vec![b'a', b'b']);
            while b.len() < len {
                let next = [b.clone(), a].concat();
                a = b;
                b = next;
            }
            b.truncate(len);
            b
        }
        7 => {
            // Every byte value, in order, backwards, or with a stride.
            let stride = [1, 255, 3, 7, 101][rng.range(0, 4) as usize];
            (0..len).map(|i| (i * stride % 256) as u8).collect()
        }
        8 => {
            // A random block repeated, a few bytes changed.
            let block_len = rng.range(1, 5000) as usize;
            let block = rng.bytes(block_len);
            let mut text = Vec::with_capacity(len + block_len);
            while text.len() < len {
                text.extend_from_slice(&block);
                if rng.range(0, 2) == 0 {
                    let at = rng.range(0, text.len() as u64 - 1) as usize;
                    text[at] ^= 0x20;
                }
            }
            text.truncate(len);
            text
        }
        9 => words(rng, len),
        10 => {
            // Squares within squares: x, x x c, (x x c) (x x c) d, ...
            let mut text = vec![rng.range(0, 3) as u8];
            while text.len() < len {
                text = [text.clone(), text, vec![rng.range(0, 3) as u8]].concat();
            }
            text.truncate(len);
            text
        }
        11 => vec![rng.next() as u8; len],
        12 => spent_budget(rng, len),
        _ => {
            // Two halves, the second a copy of the first: suffixes that
            // share half the text.
            let half = rng.bytes(len / 2);
            let mut text = [half.clone(), half].concat();
            text.resize(len, 0);
            text
        }
    }
}

/// Two copies of random bytes followed by a tandem repeat, in two ranges
/// of byte values: sorting the copies spends `trsort`'s budget, which then
/// runs out within the tandem repeat, the one way to `tr_partialcopy`.
fn spent_budget(rng: &mut Rng, len: usize) -> Vec<u8> {
    let random_len = rng.range(len as u64 / 16, len as u64 / 4) as usize;
    let mut half: Vec<u8> = (0..random_len).map(|_| (rng.next() % 128) as u8).collect();
    let unit_len = rng.range(1, 40) as usize;
    let unit: Vec<u8> = (0..unit_len).map(|_| 128 | rng.next() as u8).collect();
    while half.len() < len / 2 {
        for _ in 0..rng.range(0, 8) {
            half.push(128 | rng.next() as u8);
        }
        for _ in 0..rng.range(20, 200) {
            half.extend_from_slice(&unit);
        }
    }
    half.truncate(len / 2);
    let mut text = [half.clone(), half].concat();
    text.resize(len, 0);
    text
}

/// Text made of a vocabulary of words and phrases, as records repeat them.
fn words(rng: &mut Rng, len: usize) -> Vec<u8> {
    let vocabulary: Vec<Vec<u8>> = (0..rng.range(5, 300))
        .map(|_| {
            let word_len = rng.range(2, 12) as usize;
            (0..word_len)
                .map(|_| b'a' + rng.range(0, 25) as u8)
                .collect()
        })
        .collect();
    let mut text = Vec::with_capacity(len + 16);
    while text.len() < len {
        // The smaller of two draws favours the first words.
        let pick = rng
            .range(0, vocabulary.len() as u64 - 1)
            .min(rng.range(0, vocabulary.len() as u64 - 1));
        text.extend_from_slice(&vocabulary[pick as usize]);
        text.push(match rng.range(0, 9) {
            0 => b'\n',
            1 => b',',
            _ => b' ',
        });
    }
    text.truncate(len);
    text
}

/// Samples for the legacy trainer, `count` of them, about `size` bytes
/// each: records sharing fields, words and phrases, or binary data with
/// repeats; their bytes one after the other, and their sizes.
fn samples(rng: &mut Rng, count: usize, size: usize) -> (Vec<u8>, Vec<usize>) {
    let kind = rng.range(0, 3);
    let fields: Vec<Vec<u8>> = (0..rng.range(3, 40))
        .map(|_| {
            let name_len = rng.range(2, 14) as usize;
            (0..name_len)
                .map(|_| b'a' + rng.range(0, 25) as u8)
                .collect()
        })
        .collect();
    let phrases: Vec<Vec<u8>> = (0..rng.range(1, 60))
        .map(|_| {
            let phrase_len = rng.range(4, 80) as usize;
            words(rng, phrase_len)
        })
        .collect();
    let shared = text(rng, 4096);
    let mut bytes = Vec::new();
    let mut sizes = Vec::new();
    for _ in 0..count {
        let len = rng.range(0, 2 * size as u64) as usize;
        let start = bytes.len();
        match kind {
            0 => {
                // JSON-like records.
                while bytes.len() - start < len {
                    bytes.push(b'{');
                    for _ in 0..rng.range(1, 8) {
                        let field = &fields[rng.range(0, fields.len() as u64 - 1) as usize];
                        bytes.push(b'"');
                        bytes.extend_from_slice(field);
                        bytes.extend_from_slice(b"\": ");
                        if rng.range(0, 1) == 0 {
                            let _ = write!(Bytes(&mut bytes), "{}", rng.range(0, 100_000));
                        } else {
                            let phrase = &phrases[rng.range(0, phrases.len() as u64 - 1) as usize];
                            bytes.push(b'"');
                            bytes.extend_from_slice(phrase);
                            bytes.push(b'"');
                        }
                        bytes.extend_from_slice(b", ");
                    }
                    bytes.extend_from_slice(b"}\n");
                }
            }
            1 => {
                // Phrases in a random order.
                while bytes.len() - start < len {
                    let phrase = &phrases[rng.range(0, phrases.len() as u64 - 1) as usize];
                    bytes.extend_from_slice(phrase);
                    bytes.push(b' ');
                }
            }
            2 => {
                // Pieces of a shared block, between random bytes.
                while bytes.len() - start < len {
                    let at = rng.range(0, shared.len() as u64 - 1) as usize;
                    let piece = rng.range(1, 200) as usize;
                    bytes.extend_from_slice(&shared[at..(at + piece).min(shared.len())]);
                    let noise = rng.range(0, 20) as usize;
                    bytes.extend(rng.bytes(noise));
                }
            }
            _ => {
                let piece = text(rng, len);
                bytes.extend(piece);
            }
        }
        bytes.truncate(start + len);
        sizes.push(len);
    }
    (bytes, sizes)
}

/// Samples with more segments than the list of `ZDICT_trainBuffer_legacy`
/// holds: `phrases` distinct ones, each in about 5 of the samples.
fn many_segments(rng: &mut Rng, phrases: usize) -> (Vec<u8>, Vec<usize>) {
    let mut uses: Vec<usize> = (0..phrases).flat_map(|p| [p; 5]).collect();
    // Shuffled (Fisher-Yates).
    for i in (1..uses.len()).rev() {
        let j = rng.range(0, i as u64) as usize;
        uses.swap(i, j);
    }
    let vocabulary: Vec<Vec<u8>> = (0..phrases)
        .map(|_| {
            let len = rng.range(12, 30) as usize;
            (0..len).map(|_| b'a' + rng.range(0, 25) as u8).collect()
        })
        .collect();
    let mut bytes = Vec::new();
    let mut sizes = Vec::new();
    for chunk in uses.chunks(200) {
        let start = bytes.len();
        for &p in chunk {
            bytes.extend_from_slice(&vocabulary[p]);
            bytes.push(b' ');
        }
        sizes.push(bytes.len() - start);
    }
    (bytes, sizes)
}

/// `write!` into a vector of bytes.
struct Bytes<'a>(&'a mut Vec<u8>);

impl std::fmt::Write for Bytes<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// A file of bytes for the oracle to read, removed when dropped.
struct TempFile(PathBuf);

impl TempFile {
    fn new(bytes: &[u8]) -> TempFile {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "hivepack-dict-legacy-{}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, bytes).expect("temporary file written");
        TempFile(path)
    }

    /// The source for the whole file.
    fn source(&self, len: usize) -> String {
        file_source(&self.0, 0, len)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn file_source(path: &Path, offset: u64, len: usize) -> String {
    format!("file:{offset}:{len}:{}", path.display())
}

/// The committed test files, sorted, without the recorded answers.
fn committed_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name() != Some("oracle".as_ref()) {
                    walk(&path, out);
                }
            } else {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(&repository().join("testdata"), &mut files);
    files.sort();
    files
}

/// The Silesia corpus's files, where it is fetched.
fn silesia_files() -> Vec<PathBuf> {
    let cache = std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"));
    let Ok(entries) = std::fs::read_dir(cache.join("silesia")) else {
        eprintln!("not using silesia: not fetched (scripts/testdata.py fetch --group bench)");
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name() != Some(".complete".as_ref()))
        .collect();
    files.sort();
    files
}

/// A `legacy` request for the samples, with a dictionary size, a
/// selectivity and a notification level drawn from those that matter.
fn legacy_request(rng: &mut Rng, sizes: &[usize], src: &str) -> String {
    const DICT_SIZES: [usize; 10] = [
        0, 100, 255, 256, 1024, 4096, 16_384, 65_536, 112_640, 300_000,
    ];
    let max_dict_size = if rng.range(0, 3) == 0 {
        rng.range(200, 200_000) as usize
    } else {
        DICT_SIZES[rng.range(0, DICT_SIZES.len() as u64 - 1) as usize]
    };
    let selectivity = match rng.range(0, 5) {
        0 | 1 => 0,
        2 => rng.range(1, 3),
        3 => rng.range(4, 12),
        4 => rng.range(13, 30),
        _ => rng.range(31, 40),
    };
    let notification = rng.range(0, 4);
    format!(
        "legacy {max_dict_size} {selectivity} {notification} {} {src}",
        list(sizes)
    )
}

/// Requests whose sources are written inline, `small` ones for the file of
/// recorded answers.
fn inline_requests(rng: &mut Rng, count: usize, small: bool) -> Vec<String> {
    let mut requests = Vec::new();
    // Every text of up to 3 bytes over 3 symbols, then a few edges.
    for len in 0..=3u32 {
        for code in 0..3u32.pow(len) {
            let t: Vec<u8> = (0..len).map(|i| (code / 3u32.pow(i) % 3) as u8).collect();
            requests.push(format!("divsufsort {}", hex(&t)));
        }
    }
    for t in [
        &b"banana"[..],
        b"mississippi",
        b"abracadabra",
        &[0xff; 300],
        &(0..=255u8).collect::<Vec<_>>(),
        &(0..=255u8).rev().collect::<Vec<_>>(),
    ] {
        requests.push(format!("divsufsort {}", hex(t)));
    }
    for i in 0..count {
        // Mostly small texts; on both sides of the block size of sssort
        // (1024) and its square, in the live runs.
        let len = match (small, i % 10) {
            (true, 0) => rng.range(1000, 3000),
            (true, _) => rng.range(0, 600),
            (false, 0..=5) => rng.range(0, 4096),
            (false, 6) => rng.range(1000, 1100),
            (false, 7) => rng.range(4097, 70_000),
            _ => rng.range(4097, 400_000),
        } as usize;
        requests.push(format!("divsufsort {}", hex(&text(rng, len))));
    }
    for i in 0..count / 4 {
        // Samples: few or many, so that the selectivity counts, from too
        // few bytes to plenty.
        let (nb, size) = match (small, i % 6) {
            (true, 0) => (rng.range(1, 10), rng.range(30, 400)),
            (true, _) => (rng.range(5, 60), rng.range(20, 120)),
            (false, 0) => (rng.range(1, 10), rng.range(30, 400)),
            (false, 1) => (rng.range(200, 3000), rng.range(10, 200)),
            (false, 2) => (rng.range(20, 200), rng.range(200, 2000)),
            (false, 3) => (rng.range(10, 100), rng.range(1000, 6000)),
            _ => (rng.range(5, 500), rng.range(20, 600)),
        };
        let (bytes, sizes) = samples(rng, nb as usize, size as usize);
        requests.push(legacy_request(rng, &sizes, &hex(&bytes)));
    }
    requests
}

/// Compares `requests` with the oracle; returns the differences.
fn compare(oracle: &mut Oracle, requests: &[String], problems: &mut Vec<String>) {
    for request in requests {
        let want = oracle.ask(request);
        let got = answer(request);
        if got != want {
            problems.push(format!(
                "{request:.300}\n  libzstd: {want:.300}\n  port:    {got:.300}"
            ));
        }
    }
}

fn check(problems: &[String], checked: usize) {
    assert!(
        problems.is_empty(),
        "{checked} requests checked, {} differences:\n{}",
        problems.len(),
        problems[..problems.len().min(10)].join("\n")
    );
}

/// Checks that every path counted ran.
fn paths_reached(runs: &[std::sync::atomic::AtomicUsize], what: &str) {
    let runs: Vec<usize> = runs
        .iter()
        .map(|r| r.load(std::sync::atomic::Ordering::Relaxed))
        .collect();
    eprintln!("paths of {what} run: {runs:?}");
    assert!(
        runs.iter().all(|&r| r > 0),
        "some paths of {what} never ran: {runs:?}"
    );
}

#[test]
fn port_matches_libzstd_divsufsort() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let release = !cfg!(debug_assertions);
    let mut rng = Rng::new(0x5EED_D155);
    let mut problems = Vec::new();
    let mut checked = 0;

    let requests: Vec<String> = inline_requests(&mut rng, if release { 1500 } else { 200 }, false)
        .into_iter()
        .filter(|r| r.starts_with("divsufsort"))
        .collect();
    compare(&mut oracle, &requests, &mut problems);
    checked += requests.len();

    // Budgets spent within tandem repeats, of which about one in 30 reaches
    // `tr_partialcopy`.
    let requests: Vec<String> = (0..if release { 300 } else { 200 })
        .map(|_| {
            let len = rng.range(2000, 70_000) as usize;
            format!("divsufsort {}", hex(&spent_budget(&mut rng, len)))
        })
        .collect();
    compare(&mut oracle, &requests, &mut problems);
    checked += requests.len();

    // Large texts, through files: up to 4 MB.
    let large = if release { 24 } else { 3 };
    for i in 0..large {
        let len = if release {
            rng.range(1 << 20, 4 << 20)
        } else {
            rng.range(100_000, 300_000)
        } as usize;
        let t = text(&mut rng, len);
        let file = TempFile::new(&t);
        let request = format!("divsufsort {}", file.source(len));
        compare(&mut oracle, &[request], &mut problems);
        checked += 1;
        if i == 0 {
            // A 7-byte text repeated, and one byte: the deepest tandem
            // repeats.
            let t: Vec<u8> = (0..len).map(|i| b"abcdefg"[i % 7]).collect();
            let file = TempFile::new(&t);
            compare(
                &mut oracle,
                &[format!("divsufsort {}", file.source(len))],
                &mut problems,
            );
            let file = TempFile::new(&vec![b'x'; len]);
            compare(
                &mut oracle,
                &[format!("divsufsort {}", file.source(len))],
                &mut problems,
            );
            checked += 2;
        }
    }

    // The test data: every committed file, and pieces of it.
    for path in committed_files() {
        let len = std::fs::metadata(&path).expect("test file").len() as usize;
        if !release && len > 65_536 {
            continue;
        }
        let mut requests = vec![format!("divsufsort {}", file_source(&path, 0, len))];
        if len > 16 && rng.range(0, 3) == 0 {
            let at = rng.range(0, len as u64 / 2);
            let piece = rng.range(1, len as u64 - at) as usize;
            requests.push(format!("divsufsort {}", file_source(&path, at, piece)));
        }
        compare(&mut oracle, &requests, &mut problems);
        checked += requests.len();
    }
    // Pieces of the Silesia corpus, up to 4 MB.
    for path in silesia_files() {
        let len = std::fs::metadata(&path).expect("silesia file").len();
        let pieces = if release { 2 } else { 1 };
        for _ in 0..pieces {
            let piece = if release {
                rng.range(1 << 20, 4 << 20)
            } else {
                rng.range(10_000, 150_000)
            }
            .min(len);
            let at = rng.range(0, len - piece);
            let request = format!("divsufsort {}", file_source(&path, at, piece as usize));
            compare(&mut oracle, &[request], &mut problems);
            checked += 1;
        }
    }
    eprintln!("compared {checked} suffix arrays with libzstd");
    check(&problems, checked);
    paths_reached(
        &crate::zstd::dict_builder::divsufsort::PATH_RUNS,
        "divsufsort",
    );
}

#[test]
fn port_matches_libzstd_legacy_trainer() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let release = !cfg!(debug_assertions);
    let mut rng = Rng::new(0x5EED_1E6A);
    let mut problems = Vec::new();
    let mut checked = 0;
    // How the requests went, by libzstd's answers.
    let mut outcomes = std::collections::BTreeMap::<String, usize>::new();
    let mut count = |answer: &str| {
        let words: Vec<&str> = answer.split(' ').collect();
        let outcome = match words[..] {
            ["none"] => "none".to_string(),
            ["err", code] => format!("err {code}"),
            ["ok", _, code] => format!("content {code}"),
            ["ok", "-", ..] => "content, no segment".to_string(),
            ["ok", _, kept, ..] => {
                if kept == "1" {
                    "content, no segment kept".to_string()
                } else {
                    "content".to_string()
                }
            }
            _ => answer.chars().take(20).collect(),
        };
        *outcomes.entry(outcome).or_default() += 1;
    };

    let requests: Vec<String> = inline_requests(&mut rng, if release { 800 } else { 120 }, false)
        .into_iter()
        .filter(|r| r.starts_with("legacy"))
        .collect();
    for request in &requests {
        let want = oracle.ask(request);
        count(&want);
        let got = answer(request);
        if got != want {
            problems.push(format!(
                "{request:.300}\n  libzstd: {want:.300}\n  port:    {got:.300}"
            ));
        }
    }
    checked += requests.len();

    // Many samples, and large ones, through files: up to 2 MB, enough for
    // the list of segments to fill up.
    let large = if release { 14 } else { 3 };
    let full_lists = if release { 2 } else { 1 };
    for i in 0..large {
        let (nb, size) = if release {
            (rng.range(100, 20_000), rng.range(50, 3000))
        } else {
            (rng.range(50, 400), rng.range(50, 300))
        };
        let (mut bytes, mut sizes) = if i < full_lists {
            // More segments than the list holds (10000, for dictionaries
            // up to 160 KB).
            many_segments(&mut rng, 16_000)
        } else {
            samples(&mut rng, nb as usize, size as usize)
        };
        while bytes.len() > 2 << 20 {
            let last = sizes.pop().expect("a sample");
            bytes.truncate(bytes.len() - last);
        }
        let file = TempFile::new(&bytes);
        let request = if i < full_lists {
            // libzstd's default dictionary size, 110 KB.
            let src = file.source(bytes.len());
            format!("legacy 112640 0 0 {} {src}", list(&sizes))
        } else {
            legacy_request(&mut rng, &sizes, &file.source(bytes.len()))
        };
        let want = oracle.ask(&request);
        count(&want);
        if answer(&request) != want {
            problems.push(format!("{request:.300}\n  libzstd: {want:.300}"));
        }
        checked += 1;
    }

    // Samples cut from the test data: the Silesia corpus where it is
    // fetched, else the committed files.
    let mut sources = silesia_files();
    if sources.is_empty() {
        sources = committed_files()
            .into_iter()
            .filter(|p| std::fs::metadata(p).map_or(0, |m| m.len()) > 20_000)
            .collect();
    }
    for path in sources.iter().take(if release { 12 } else { 2 }) {
        let len = std::fs::metadata(path).expect("test file").len();
        let total = if release {
            rng.range(100_000, 1 << 20)
        } else {
            rng.range(5_000, 40_000)
        }
        .min(len);
        let at = rng.range(0, len - total);
        // Samples of about the same size, as files or records are.
        let mut sizes = Vec::new();
        let mut left = total as usize;
        let typical = rng.range(100, 8000) as usize;
        while left > 0 {
            let size = (rng.range(typical as u64 / 2, typical as u64 * 3 / 2) as usize).min(left);
            sizes.push(size);
            left -= size;
        }
        let request = legacy_request(&mut rng, &sizes, &file_source(path, at, total as usize));
        let want = oracle.ask(&request);
        count(&want);
        if answer(&request) != want {
            problems.push(format!("{request:.300}\n  libzstd: {want:.300}"));
        }
        checked += 1;
    }
    eprintln!("compared {checked} trainings with libzstd: {outcomes:?}");
    check(&problems, checked);
    paths_reached(
        &crate::zstd::dict_builder::legacy::PATH_RUNS,
        "the legacy trainer",
    );
}

#[test]
fn port_matches_recorded_dict_legacy_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/dict-legacy.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(recorded_form(&answer(request)), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked >= 300, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/dict-legacy.txt from the oracle"]
fn record_dict_legacy_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng::new(0x5EED_D156);
    let mut text = String::from(
        "# Answers from libzstd 1.5.7 (tools/zstd-oracle) about divsufsort and the legacy\n\
         # dictionary trainer, replayed by crates/hivepack/src/zstd/oracle_dict_legacy.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features record_dict_legacy_answers -- --ignored\n",
    );
    for request in inline_requests(&mut rng, 320, true) {
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::write(recorded_path(), text).expect("written");
}
