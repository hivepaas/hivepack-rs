//! Comparison of the dictionary builder with libzstd's: the COVER and fast
//! COVER trainers with explicit parameters and their optimizers (on one
//! thread), `ZDICT_finalizeDictionary`, `ZDICT_addEntropyTablesFromBuffer`
//! (`_advanced`), `ZDICT_analyzeEntropy`, `COVER_selectDict` (shrinking
//! included, which libzstd's optimizers never reach), `COVER_computeEpochs`
//! and `ZDICT_getDictHeaderSize`, through the `zd*` requests of
//! `tools/zstd-oracle` (see its comment for the formats). zstd-safe offers
//! only `ZDICT_trainFromBuffer`, which `tests/dict_builder.rs` compares.
//!
//! The samples: text, records and log lines drawn from a vocabulary, data
//! with LZ77's structure, random bytes, runs of a short pattern, the
//! systemd unit files of the test data (`testdata/ruzstd/dict/files`) and
//! pieces of its other files; tiny and empty samples among them.
//!
//! As for the other requests, the tests compare generated requests with
//! libzstd live where the oracle is built, and replay recorded answers
//! everywhere, from `testdata/oracle/zdict.txt`, of small samples.
//! `cargo test -p hivepack --all-features record_zdict_answers -- --ignored` rewrites
//! it.
//!
//! The oracle on macOS sorts COVER's suffix array with glibc's merge sort,
//! as on Linux, where libzstd's dictionaries are the port's (see
//! `train_from_buffer_cover`).

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::zstd::common::error_private::Result;
use crate::zstd::dict_builder::cover::{
    CoverParams, cover_compute_epochs, cover_select_dict, optimize_train_from_buffer_cover,
    sample_offsets, train_from_buffer_cover,
};
use crate::zstd::dict_builder::fastcover::{
    FastCoverParams, optimize_train_from_buffer_fast_cover, train_from_buffer_fast_cover,
};
use crate::zstd::dict_builder::legacy::{LegacyParams, train_from_buffer_legacy};
use crate::zstd::dict_builder::zdict::{
    DictParams, finalize_dictionary, get_dict_header_size, train_from_buffer,
    zdict_add_entropy_tables_from_buffer_advanced, zdict_analyze_entropy,
};
use crate::zstd::oracle::{
    Oracle, Rng, failed, list, mutate, recorded_form, repository, unhex, unlist,
};

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/zdict.txt")
}

/// Bytes as the oracle answers them, in hex: nothing for none.
fn hex_answer(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        String::new()
    } else {
        crate::zstd::oracle::hex(bytes)
    }
}

fn number<T: std::str::FromStr>(text: &str) -> T {
    text.parse()
        .unwrap_or_else(|_| panic!("a number, not {text:.40}"))
}

fn samples_of(sizes: &str, bytes: &str) -> (Vec<u8>, Vec<usize>) {
    let sizes: Vec<usize> = unlist(sizes).into_iter().map(|s| s as usize).collect();
    (unhex(bytes), sizes)
}

fn z_params(v: &[i64]) -> DictParams {
    DictParams {
        compression_level: v[0] as i32,
        notification_level: v[1] as u32,
        dict_id: v[2] as u32,
    }
}

fn cover_params(text: &str) -> CoverParams {
    let v = unlist(text);
    assert_eq!(v.len(), 10, "cover parameters {text}");
    CoverParams {
        k: v[0] as u32,
        d: v[1] as u32,
        steps: v[2] as u32,
        nb_threads: v[3] as u32,
        split_point: v[4] as f64 / 1000.0,
        shrink_dict: v[5] as u32 != 0,
        shrink_dict_max_regression: v[6] as u32,
        z_params: z_params(&v[7..10]),
    }
}

fn fast_cover_params(text: &str) -> FastCoverParams {
    let v = unlist(text);
    assert_eq!(v.len(), 12, "fast cover parameters {text}");
    FastCoverParams {
        k: v[0] as u32,
        d: v[1] as u32,
        f: v[2] as u32,
        steps: v[3] as u32,
        nb_threads: v[4] as u32,
        split_point: v[5] as f64 / 1000.0,
        accel: v[6] as u32,
        shrink_dict: v[7] as u32 != 0,
        shrink_dict_max_regression: v[8] as u32,
        z_params: z_params(&v[9..12]),
    }
}

fn z_params_text(p: &DictParams) -> String {
    format!(
        "{},{},{}",
        p.compression_level, p.notification_level, p.dict_id
    )
}

fn cover_params_text(p: &CoverParams) -> String {
    format!(
        "{},{},{},{},{:016x},{},{},{}",
        p.k,
        p.d,
        p.steps,
        p.nb_threads,
        p.split_point.to_bits(),
        u32::from(p.shrink_dict),
        p.shrink_dict_max_regression,
        z_params_text(&p.z_params)
    )
}

fn fast_cover_params_text(p: &FastCoverParams) -> String {
    format!(
        "{},{},{},{},{},{:016x},{},{},{},{}",
        p.k,
        p.d,
        p.f,
        p.steps,
        p.nb_threads,
        p.split_point.to_bits(),
        p.accel,
        u32::from(p.shrink_dict),
        p.shrink_dict_max_regression,
        z_params_text(&p.z_params)
    )
}

/// "ok <dictionary>" and `tail`, or the error; "ok" alone for no
/// dictionary (the legacy trainer's for too few samples), as the oracle's
/// line, trimmed, reads.
fn dict_answer(dict: &[u8], result: Result<usize>, tail: &str) -> String {
    match result {
        Ok(size) => format!("ok {}{tail}", hex_answer(&dict[..size]))
            .trim_end()
            .to_string(),
        Err(error) => failed(error),
    }
}

/// The port's answer to a `zd*` request of the oracle, in its format.
pub(crate) fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    match words[..] {
        ["zdcover", capacity, params, sizes, bytes] => {
            let (samples, sizes) = samples_of(sizes, bytes);
            let mut dict = vec![0u8; number(capacity)];
            let result = train_from_buffer_cover(&mut dict, &samples, &sizes, cover_params(params));
            dict_answer(&dict, result, "")
        }
        ["zdcoveropt", capacity, params, sizes, bytes] => {
            let (samples, sizes) = samples_of(sizes, bytes);
            let mut dict = vec![0u8; number(capacity)];
            let mut params = cover_params(params);
            let result = optimize_train_from_buffer_cover(&mut dict, &samples, &sizes, &mut params);
            dict_answer(&dict, result, &format!(" {}", cover_params_text(&params)))
        }
        ["zdfast", capacity, params, sizes, bytes] => {
            let (samples, sizes) = samples_of(sizes, bytes);
            let mut dict = vec![0u8; number(capacity)];
            let result = train_from_buffer_fast_cover(
                &mut dict,
                &samples,
                &sizes,
                fast_cover_params(params),
            );
            dict_answer(&dict, result, "")
        }
        ["zdfastopt", capacity, params, sizes, bytes] => {
            let (samples, sizes) = samples_of(sizes, bytes);
            let mut dict = vec![0u8; number(capacity)];
            let mut params = fast_cover_params(params);
            let result =
                optimize_train_from_buffer_fast_cover(&mut dict, &samples, &sizes, &mut params);
            dict_answer(
                &dict,
                result,
                &format!(" {}", fast_cover_params_text(&params)),
            )
        }
        ["zdlegacy", capacity, selectivity, params, sizes, bytes] => {
            let (samples, sizes) = samples_of(sizes, bytes);
            let mut dict = vec![0u8; number(capacity)];
            let params = LegacyParams {
                selectivity_level: number(selectivity),
                z_params: z_params(&unlist(params)),
            };
            let result = train_from_buffer_legacy(&mut dict, &samples, &sizes, params);
            dict_answer(&dict, result, "")
        }
        ["zdfinalize", capacity, params, content, sizes, bytes] => {
            let (samples, sizes) = samples_of(sizes, bytes);
            let mut dict = vec![0u8; number(capacity)];
            let result = finalize_dictionary(
                &mut dict,
                &unhex(content),
                &samples,
                &sizes,
                z_params(&unlist(params)),
            );
            dict_answer(&dict, result, "")
        }
        ["zdadd", content_size, params, buffer, sizes, bytes] => {
            let (samples, sizes) = samples_of(sizes, bytes);
            let mut dict = unhex(buffer);
            let result = zdict_add_entropy_tables_from_buffer_advanced(
                &mut dict,
                number(content_size),
                &samples,
                &sizes,
                z_params(&unlist(params)),
            );
            dict_answer(&dict, result, "")
        }
        ["zdentropy", capacity, level, content, sizes, bytes] => {
            let (samples, sizes) = samples_of(sizes, bytes);
            let mut dst = vec![0u8; number(capacity)];
            let result = zdict_analyze_entropy(
                &mut dst,
                number(level),
                &samples,
                &sizes,
                &unhex(content),
                0,
            );
            dict_answer(&dst, result, "")
        }
        [
            "zdselect",
            capacity,
            params,
            content,
            nb_finalize,
            nb_check,
            sizes,
            bytes,
        ] => {
            let (samples, sizes) = samples_of(sizes, bytes);
            let content = unhex(content);
            let capacity: usize = number(capacity);
            // The content at the end of the buffer, zeros before it.
            let mut buffer = vec![0u8; capacity];
            let tail = capacity - content.len();
            buffer[tail..].copy_from_slice(&content);
            let offsets = sample_offsets(&sizes).expect("offsets");
            match cover_select_dict(
                &buffer,
                tail,
                &samples,
                &sizes,
                number(nb_finalize),
                number(nb_check),
                sizes.len(),
                &cover_params(params),
                &offsets,
            ) {
                Ok(selection) => format!(
                    "ok {} {}",
                    selection.total_compressed_size,
                    hex_answer(&selection.dict_content)
                ),
                Err(error) => failed(error),
            }
        }
        ["zdheader", dict] => match get_dict_header_size(&unhex(dict)) {
            Ok(size) => format!("ok {size}"),
            Err(error) => failed(error),
        },
        ["zdepochs", max_dict_size, nb_dmers, k, passes] => {
            let epochs = cover_compute_epochs(
                number(max_dict_size),
                number(nb_dmers),
                number(k),
                number(passes),
            );
            format!("ok {} {}", epochs.num, epochs.size)
        }
        _ => panic!("unknown request {request:.200}"),
    }
}

// ---------------------------------------------------------------------------
// Requests

/// Words to draw text from.
const WORDS: [&str; 64] = [
    "the", "of", "and", "to", "in", "is", "you", "that", "it", "he", "was", "for", "on", "are",
    "as", "with", "his", "they", "at", "be", "this", "have", "from", "or", "one", "had", "by",
    "word", "but", "not", "what", "all", "were", "we", "when", "your", "can", "said", "there",
    "use", "an", "each", "which", "she", "do", "how", "their", "if", "will", "up", "other",
    "about", "out", "many", "then", "them", "these", "so", "some", "her", "would", "make", "like",
    "service",
];

/// The files of the test data to draw samples from: the systemd units of
/// ruzstd's dictionary set, each whole, then pieces of larger files.
struct Files {
    units: Vec<Vec<u8>>,
    others: Vec<Vec<u8>>,
}

fn files() -> Files {
    let folder = repository().join("testdata/ruzstd/dict/files");
    let mut names: Vec<PathBuf> = std::fs::read_dir(&folder)
        .expect("testdata/ruzstd/dict/files")
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| path.extension().is_none_or(|e| e != "zst"))
        .collect();
    names.sort();
    let units = names
        .iter()
        .map(|path| std::fs::read(path).expect("a unit file"))
        .collect();
    let others = [
        "testdata/zstd/golden-compression/http",
        "testdata/zstd/golden-compression/large-literal-and-match-lengths",
        "testdata/zstd/golden-compression/PR-3517-block-splitter-corruption-test",
        "testdata/ruzstd/dict/dictionary",
    ]
    .iter()
    .map(|path| std::fs::read(repository().join(path)).expect("a test file"))
    .collect();
    Files { units, others }
}

/// One sample of `len` bytes, about, of the kind `kind`.
fn sample(rng: &mut Rng, files: &Files, kind: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    match kind {
        // Text.
        0 => {
            while out.len() < len {
                let top = rng.range(8, 63);
                let word = WORDS[rng.range(0, top) as usize];
                out.extend_from_slice(word.as_bytes());
                out.push(match rng.range(0, 12) {
                    0 => b'.',
                    1 => b',',
                    2 => b'\n',
                    _ => b' ',
                });
                if rng.range(0, 15) == 0 {
                    out.extend_from_slice(rng.range(0, 99_999).to_string().as_bytes());
                    out.push(b' ');
                }
            }
        }
        // Records.
        1 => {
            while out.len() < len {
                let record = format!(
                    "{{\"id\":{},\"user\":\"{}{}\",\"score\":{}.{},\"tags\":[\"{}\",\"{}\"],\"active\":{}}}\n",
                    rng.range(0, 1_000_000),
                    WORDS[rng.range(0, 63) as usize],
                    rng.range(0, 99),
                    rng.range(0, 99),
                    rng.range(0, 9),
                    WORDS[rng.range(0, 20) as usize],
                    WORDS[rng.range(0, 63) as usize],
                    rng.range(0, 1) == 0
                );
                out.extend_from_slice(record.as_bytes());
            }
        }
        // Log lines.
        2 => {
            while out.len() < len {
                let line = format!(
                    "2026-10-{:02}T{:02}:{:02}:{:02}Z {} {}[{}]: GET /api/v1/{}/{} took {}ms\n",
                    rng.range(1, 30),
                    rng.range(0, 23),
                    rng.range(0, 59),
                    rng.range(0, 59),
                    ["INFO", "WARN", "DEBUG", "ERROR"][rng.range(0, 3) as usize],
                    WORDS[rng.range(0, 63) as usize],
                    rng.range(100, 40_000),
                    WORDS[rng.range(0, 63) as usize],
                    rng.range(0, 5000),
                    rng.range(0, 999)
                );
                out.extend_from_slice(line.as_bytes());
            }
        }
        // LZ77's structure.
        3 => out = rng.lz_data(len),
        // Noise.
        4 => out = rng.bytes(len),
        // A short pattern repeated.
        5 => {
            let period = rng.range(1, 4) as usize;
            let pattern = rng.bytes(period);
            while out.len() < len {
                out.extend_from_slice(&pattern);
            }
        }
        // A systemd unit file, whole, or a piece.
        6 => {
            let unit = &files.units[rng.range(0, files.units.len() as u64 - 1) as usize];
            if rng.range(0, 1) == 0 || unit.len() <= len {
                // Whole, but for a sample meant to be tiny.
                let whole = if len < 16 { len } else { unit.len() };
                return unit[..whole.min(unit.len())].to_vec();
            } else {
                let at = rng.range(0, (unit.len() - len) as u64) as usize;
                out.extend_from_slice(&unit[at..at + len]);
            }
        }
        // A piece of another test file.
        _ => {
            let file = &files.others[rng.range(0, files.others.len() as u64 - 1) as usize];
            let len = len.min(file.len());
            let at = rng.range(0, (file.len() - len) as u64) as usize;
            out.extend_from_slice(&file[at..at + len]);
        }
    }
    out.truncate(len);
    out
}

/// Samples of about `budget` bytes in all: their bytes, and their sizes.
fn sample_set(rng: &mut Rng, files: &Files, budget: usize) -> (Vec<u8>, Vec<usize>) {
    let kind = rng.range(0, 9);
    let count = match rng.range(0, 11) {
        0 => rng.range(0, 7),
        1..=7 => rng.range(5, 80),
        _ => rng.range(80, 400),
    } as usize;
    let mean = (budget / count.max(1)).max(1);
    let mut bytes = Vec::new();
    let mut sizes = Vec::new();
    for _ in 0..count {
        let len = match rng.range(0, 19) {
            // Empty and tiny samples.
            0 => 0,
            1 => rng.range(1, 9) as usize,
            _ => rng.range((mean / 4) as u64, (mean * 7 / 4).max(1) as u64) as usize,
        };
        // One kind, or a mix (8).
        let sample_kind = if kind == 8 { rng.range(0, 7) } else { kind };
        let piece = sample(rng, files, sample_kind, len);
        if bytes.len() + piece.len() > budget * 2 {
            break;
        }
        sizes.push(piece.len());
        bytes.extend_from_slice(&piece);
    }
    (bytes, sizes)
}

const LEVELS: [i64; 17] = [-7, -1, 0, 1, 2, 3, 4, 5, 6, 7, 9, 12, 13, 16, 18, 19, 22];

fn level(rng: &mut Rng) -> i64 {
    LEVELS[rng.range(0, LEVELS.len() as u64 - 1) as usize]
}

/// `compressionLevel,notificationLevel,dictID`.
fn z_params_request(rng: &mut Rng) -> String {
    let dict_id = match rng.range(0, 5) {
        0 => rng.next() as u32,
        1 => rng.range(1, 32767) as u32,
        _ => 0,
    };
    format!("{},{},{}", level(rng), rng.range(0, 4), dict_id)
}

/// A capacity for a dictionary: around the samples' size, from below the
/// smallest (256) to large.
fn capacity(rng: &mut Rng, samples: usize) -> usize {
    match rng.range(0, 11) {
        0 => rng.range(0, 255) as usize,
        1 => 256,
        2 => rng.range(257, 600) as usize,
        3..=6 => rng.range(256, (samples as u64 / 4).max(512)) as usize,
        7 | 8 => rng.range(256, (samples as u64).max(1024)) as usize,
        _ => rng.range(256, 4 * samples as u64 + 1024) as usize,
    }
}

/// A split point, in thousandths, that keeps the training samples' bytes
/// at 16 or more where they are fewer than all: libzstd crashes, or reads
/// past the samples, below `max(d, 8)` (see `split_samples`). The fast
/// COVER optimizer's default (0 and below) is 750.
fn split_point(rng: &mut Rng, sizes: &[usize], fast: bool) -> i64 {
    let split = match rng.range(0, 9) {
        0 => 0,
        1 => -250,
        2 => 1000,
        3 => 750,
        4 => 500,
        5 => rng.range(100, 999) as i64,
        6 => 1500,
        7 => 1001,
        _ => 900,
    };
    let resolved = match split {
        ..=0 if fast => 750,
        ..=0 => 1000,
        _ => split,
    };
    if resolved < 1000 {
        let nb_train = (sizes.len() as f64 * (resolved as f64 / 1000.0)) as usize;
        let training: usize = sizes[..nb_train.min(sizes.len())].iter().sum();
        if training < 16 {
            return 1000;
        }
    }
    split
}

/// `k,d,steps,nbThreads,splitPoint,shrinkDict,shrinkDictMaxRegression` and
/// the dictionary parameters, for the COVER trainer (`optimize`: its
/// optimizer, with few values of k).
fn cover_request_params(rng: &mut Rng, capacity: usize, sizes: &[usize], optimize: bool) -> String {
    let d = match rng.range(0, 11) {
        0 if optimize => 0,
        0 => rng.range(0, 1),
        1..=3 => 8,
        4..=6 => 6,
        7 | 8 => rng.range(1, 16),
        _ => rng.range(9, 24),
    };
    let k = match rng.range(0, 11) {
        0 if optimize => 0,
        0 => rng.range(0, d),
        1 => capacity as u64 + rng.range(1, 100),
        2..=4 => rng.range(16, 200).max(d),
        _ => rng.range(d.max(1), capacity.clamp(1, 3000) as u64),
    };
    let steps = match rng.range(0, 7) {
        0 if !optimize => 0,
        // The default, 40 values of k, now and then.
        0 if k != 0 || rng.range(0, 3) == 0 => 0,
        _ => rng.range(1, 6),
    };
    let nb_threads = rng.range(0, 1);
    let split = if optimize {
        split_point(rng, sizes, false)
    } else {
        rng.range(0, 1000) as i64
    };
    format!(
        "{k},{d},{steps},{nb_threads},{split},{},{},{}",
        rng.range(0, 1),
        rng.range(0, 30),
        z_params_request(rng)
    )
}

/// `k,d,f,steps,nbThreads,splitPoint,accel,shrinkDict,
/// shrinkDictMaxRegression` and the dictionary parameters, for the fast
/// COVER trainer or its optimizer.
fn fast_cover_request_params(
    rng: &mut Rng,
    capacity: usize,
    sizes: &[usize],
    optimize: bool,
) -> String {
    let d = match rng.range(0, 11) {
        0 if optimize => 0,
        0 => 0,
        1 => [5, 7, 9][rng.range(0, 2) as usize],
        2..=6 => 8,
        _ => 6,
    };
    let k = match rng.range(0, 11) {
        0 if optimize => 0,
        0 => rng.range(0, d),
        1 => capacity as u64 + rng.range(1, 100),
        2..=4 => rng.range(16, 200).max(d),
        _ => rng.range(d.max(1), capacity.clamp(1, 3000) as u64),
    };
    let f = match rng.range(0, 7) {
        0 => 0,
        1 if !optimize => [32, 40][rng.range(0, 1) as usize],
        2 => rng.range(1, 8),
        _ => rng.range(9, 22),
    };
    let accel = match rng.range(0, 7) {
        0 => 0,
        1 => rng.range(11, 13),
        2 | 3 => 1,
        _ => rng.range(2, 10),
    };
    let steps = match rng.range(0, 7) {
        0 if !optimize => 0,
        0 if k != 0 || rng.range(0, 3) == 0 => 0,
        _ => rng.range(1, 6),
    };
    let nb_threads = rng.range(0, 1);
    let split = if optimize {
        split_point(rng, sizes, true)
    } else {
        rng.range(0, 1000) as i64
    };
    format!(
        "{k},{d},{f},{steps},{nb_threads},{split},{accel},{},{},{}",
        rng.range(0, 1),
        rng.range(0, 30),
        z_params_request(rng)
    )
}

/// A content for a dictionary: a piece of the samples, other bytes, or
/// nothing, of up to `most` bytes.
fn content(rng: &mut Rng, samples: &[u8], most: usize) -> Vec<u8> {
    let len = match rng.range(0, 7) {
        0 => 0,
        1 => rng.range(1, 8) as usize,
        2 => rng.range(0, most as u64) as usize,
        _ => rng.range(8, most.max(8) as u64) as usize,
    };
    if rng.range(0, 4) == 0 || samples.len() < len {
        return rng.bytes(len);
    }
    let at = rng.range(0, (samples.len() - len) as u64) as usize;
    samples[at..at + len].to_vec()
}

/// One request of each command, for samples of about `budget` bytes (a
/// third of that for the optimizers, whose trials compress them over and
/// over).
fn requests(rng: &mut Rng, files: &Files, count: usize, budget: usize) -> Vec<String> {
    let mut requests = Vec::new();
    for i in 0..count {
        // The trainers.
        for command in ["zdcover", "zdfast", "zdcoveropt", "zdfastopt"] {
            let optimize = command.ends_with("opt");
            let budget = if optimize { budget / 3 } else { budget };
            let (samples, sizes) = sample_set(rng, files, budget);
            let capacity = capacity(rng, samples.len());
            let params = if command.starts_with("zdcover") {
                cover_request_params(rng, capacity, &sizes, optimize)
            } else {
                fast_cover_request_params(rng, capacity, &sizes, optimize)
            };
            requests.push(format!(
                "{command} {capacity} {params} {} {}",
                list(&sizes),
                crate::zstd::oracle::hex(&samples)
            ));
        }

        // ZDICT_trainFromBuffer_legacy, whole: its segments and content are
        // compared on their own in `oracle_dict_legacy.rs`.
        {
            let (samples, sizes) = sample_set(rng, files, budget);
            let capacity = capacity(rng, samples.len());
            requests.push(format!(
                "zdlegacy {capacity} {} {} {} {}",
                rng.range(0, 12),
                z_params_request(rng),
                list(&sizes),
                crate::zstd::oracle::hex(&samples)
            ));
        }

        // ZDICT_finalizeDictionary.
        {
            let (samples, sizes) = sample_set(rng, files, budget / 2);
            let content = content(rng, &samples, (budget / 4).max(300));
            let capacity = match rng.range(0, 7) {
                0 => content.len().saturating_sub(rng.range(1, 10) as usize),
                1 => rng.range(0, 300) as usize,
                2 => content.len().max(256),
                3 => content.len() + rng.range(1, 400) as usize,
                _ => content.len().max(256) + rng.range(0, 3000) as usize,
            };
            requests.push(format!(
                "zdfinalize {capacity} {} {} {} {}",
                z_params_request(rng),
                crate::zstd::oracle::hex(&content),
                list(&sizes),
                crate::zstd::oracle::hex(&samples)
            ));
        }

        // ZDICT_addEntropyTablesFromBuffer_advanced: the content at the end
        // of the buffer, the header running into it now and then.
        {
            let (samples, sizes) = sample_set(rng, files, budget / 2);
            let capacity = match rng.range(0, 5) {
                0 => rng.range(8, 200) as usize,
                _ => rng.range(200, (budget as u64 / 4).max(2000)) as usize,
            };
            let mut buffer = content(rng, &samples, capacity);
            buffer.resize(capacity, 0);
            let content_size = match rng.range(0, 5) {
                0 => capacity,
                1 => capacity - rng.range(0, capacity.min(200) as u64) as usize,
                2 => 0,
                _ => rng.range(0, capacity as u64) as usize,
            };
            requests.push(format!(
                "zdadd {content_size} {} {} {} {}",
                z_params_request(rng),
                crate::zstd::oracle::hex(&buffer),
                list(&sizes),
                crate::zstd::oracle::hex(&samples)
            ));
        }

        // ZDICT_analyzeEntropy, in rooms from none to plenty.
        {
            let (samples, sizes) = sample_set(rng, files, budget / 2);
            let content = content(rng, &samples, (budget / 4).max(300));
            let capacity =
                [0, 1, 10, 60, 100, 129, 140, 160, 200, 248, 256, 1000][rng.range(0, 11) as usize];
            requests.push(format!(
                "zdentropy {capacity} {} {} {} {}",
                level(rng),
                crate::zstd::oracle::hex(&content),
                list(&sizes),
                crate::zstd::oracle::hex(&samples)
            ));
        }

        // COVER_selectDict, shrinking or not.
        {
            let (samples, sizes) = sample_set(rng, files, budget / 3);
            let content = content(rng, &samples, (budget / 3).max(600));
            let capacity = match rng.range(0, 3) {
                0 => content.len().max(256),
                _ => content.len().max(256) + rng.range(0, 1000) as usize,
            };
            let n = sizes.len() as u64;
            let nb_finalize = rng.range(0, n);
            let nb_check = rng.range(0, n);
            let split = [1000, 750, 500, 1000][rng.range(0, 3) as usize];
            let params = format!(
                "0,0,0,0,{split},{},{},{}",
                u64::from(rng.range(0, 3) != 0),
                rng.range(0, 25),
                z_params_request(rng)
            );
            requests.push(format!(
                "zdselect {capacity} {params} {} {nb_finalize} {nb_check} {} {}",
                crate::zstd::oracle::hex(&content),
                list(&sizes),
                crate::zstd::oracle::hex(&samples)
            ));
        }

        // ZDICT_getDictHeaderSize, of dictionaries the port trains, cut and
        // damaged, and of other bytes.
        {
            let (samples, sizes) = sample_set(rng, files, budget / 3);
            let mut dict = vec![0u8; rng.range(256, 2000) as usize];
            let dict = match train_from_buffer(&mut dict, &samples, &sizes) {
                Ok(size) if rng.range(0, 3) != 0 => dict[..size].to_vec(),
                _ => {
                    let len = rng.range(0, 400) as usize;
                    let mut bytes = rng.bytes(len);
                    if bytes.len() >= 4 && rng.range(0, 1) == 0 {
                        bytes[..4].copy_from_slice(&0xEC30_A437u32.to_le_bytes());
                    }
                    bytes
                }
            };
            let dict = match rng.range(0, 3) {
                0 => mutate(rng, &dict),
                1 => {
                    let keep = rng.range(0, dict.len() as u64) as usize;
                    dict[..keep].to_vec()
                }
                _ => dict,
            };
            requests.push(format!("zdheader {}", crate::zstd::oracle::hex(&dict)));
        }

        // COVER_computeEpochs, of no dmers excluded (a division by zero).
        if i % 2 == 0 {
            let k = match rng.range(0, 3) {
                0 => rng.range(1, 64),
                1 => rng.range(1, 3000),
                _ => rng.range(1, u64::from(u32::MAX)),
            };
            let max_dict_size = rng.range(0, u64::from(u32::MAX));
            let top = [1000, 1 << 20, u64::from(u32::MAX)][rng.range(0, 2) as usize];
            let nb_dmers = rng.range(1, top);
            let passes = [1, 4, rng.range(1, 8)][rng.range(0, 2) as usize];
            requests.push(format!("zdepochs {max_dict_size} {nb_dmers} {k} {passes}"));
        }
    }
    requests
}

/// The command and how libzstd answered: ok, or the error's code.
fn outcome(request: &str, want: &str) -> String {
    let command = request.split(' ').next().unwrap_or_default();
    let words: Vec<&str> = want.split(' ').collect();
    match words[..] {
        ["err", code, ..] => format!("{command} err {code}"),
        _ => format!("{command} {}", words[0]),
    }
}

#[test]
fn port_matches_libzstd_dict_builder() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let files = files();
    let mut rng = Rng::new(0x5EED_0201);
    let (count, budget) = if cfg!(debug_assertions) {
        (12, 12_000)
    } else {
        (60, 60_000)
    };
    let mut requests = requests(&mut rng, &files, count, budget);
    // The statistics at every level, of many samples each: their context
    // goes on from sample to sample with its tables (see
    // CCtx::compress_block_using_cdict), whose entries from the samples
    // before every match finder must leave alone.
    for level in (-7..=22).filter(|&level| level != 0) {
        let (samples, sizes) = sample_set(&mut rng, &files, budget);
        let content = content(&mut rng, &samples, (budget / 4).max(1000));
        requests.push(format!(
            "zdentropy 248 {level} {} {} {}",
            crate::zstd::oracle::hex(&content),
            list(&sizes),
            crate::zstd::oracle::hex(&samples)
        ));
    }
    let mut problems = Vec::new();
    let mut outcomes = std::collections::BTreeMap::<String, usize>::new();
    for request in &requests {
        let want = oracle.ask(request);
        let got = answer(request);
        if got != want {
            problems.push(format!(
                "{request:.300}\n  libzstd: {want:.300}\n  port:    {got:.300}"
            ));
        }
        *outcomes.entry(outcome(request, &want)).or_default() += 1;
    }
    eprintln!(
        "compared {} requests with libzstd: {outcomes:?}",
        requests.len()
    );
    assert!(
        problems.is_empty(),
        "{} requests checked, {} differences:\n{}",
        requests.len(),
        problems.len(),
        problems[..problems.len().min(10)].join("\n")
    );
    // Each trainer must have made dictionaries, and failed too.
    for command in [
        "zdcover",
        "zdfast",
        "zdcoveropt",
        "zdfastopt",
        "zdlegacy",
        "zdfinalize",
        "zdadd",
    ] {
        assert!(
            outcomes.get(&format!("{command} ok")).copied().unwrap_or(0) > 0,
            "{command} never succeeded: {outcomes:?}"
        );
    }
}

#[test]
fn port_matches_recorded_zdict_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/zdict.txt");
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
#[ignore = "rewrites testdata/oracle/zdict.txt from the oracle"]
fn record_zdict_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let files = files();
    let mut rng = Rng::new(0x5EED_0202);
    let mut text = String::from(
        "# Answers from libzstd 1.5.7 (tools/zstd-oracle) about the dictionary builder,\n\
         # replayed by crates/hivepack/src/zstd/oracle_zdict.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features record_zdict_answers -- --ignored\n",
    );
    for request in requests(&mut rng, &files, 36, 1500) {
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::write(recorded_path(), text).expect("written");
}
