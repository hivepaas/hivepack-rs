//! Trains dictionaries with the port and with libzstd 1.5.7's default
//! trainer, `ZDICT_trainFromBuffer` (zstd-safe's `train_from_buffer`), on
//! the same samples into the same room, and compares them byte for byte,
//! or their errors; then uses every dictionary the port trains: frames
//! compressed with it, by the port and by libzstd, must be the same and
//! decode back with either.
//!
//! The samples: the files of the test data (the systemd units of ruzstd's
//! dictionary set, the originals of its frames, pieces of zstd's golden
//! files; the JSON files of zstd's `github` regression set, and pieces of
//! Silesia, where fetched), text-like and record-like data, noise, a byte
//! repeated, and sets of tiny, empty or too few samples. The rooms: from
//! below the smallest dictionary (256 bytes) to 110 KB.
//!
//! zstd-safe offers no other function of the dictionary builder: the
//! oracle's tests compare those (`src/oracle_zdict.rs`). Here also: the
//! optimizers give the same dictionary on any number of threads, and the
//! parameters' defaults and bounds.
//!
//! The samples are smaller in debug builds, and smaller still on the
//! machines CI emulates (32-bit and big-endian).

#![allow(clippy::expect_used, clippy::panic)]

#[path = "zstd_support/mod.rs"]
mod support;

use hivepack::zstd::{
    CCtx, CDict, CoverParams, DCtx, DDict, DictParams, ErrorCode, FastCoverParams,
};
use support::{Kind, Problems, Rng};
use zstd::zstd_safe;

/// Builds without optimizations, and emulated machines.
const SLOW: bool = cfg!(debug_assertions) || EMULATED;
/// The machines CI runs under emulation, far slower still.
const EMULATED: bool = cfg!(any(target_pointer_width = "32", target_endian = "big"));

/// `n` bytes, less for slower runs.
fn scaled(n: usize) -> usize {
    if EMULATED {
        n / 8
    } else if SLOW {
        n / 4
    } else {
        n
    }
}

/// Samples, one after the other, and their sizes.
struct SampleSet {
    name: String,
    samples: Vec<u8>,
    sizes: Vec<usize>,
}

impl SampleSet {
    fn new(
        name: impl Into<String>,
        pieces: impl IntoIterator<Item = Vec<u8>>,
        budget: usize,
    ) -> Self {
        let mut samples = Vec::new();
        let mut sizes = Vec::new();
        for piece in pieces {
            if samples.len() + piece.len() > budget {
                break;
            }
            sizes.push(piece.len());
            samples.extend_from_slice(&piece);
        }
        SampleSet {
            name: name.into(),
            samples,
            sizes,
        }
    }

    fn sample(&self, i: usize) -> &[u8] {
        let at: usize = self.sizes[..i].iter().sum();
        &self.samples[at..at + self.sizes[i]]
    }
}

/// The files of a tar archive, as `ustar` stores them.
fn tar_files(tar: &[u8]) -> Vec<Vec<u8>> {
    let mut files = Vec::new();
    let mut at = 0;
    while at + 512 <= tar.len() && tar[at] != 0 {
        let size_field = std::str::from_utf8(&tar[at + 124..at + 136]).expect("a size");
        let size = usize::from_str_radix(size_field.trim_matches(|c| c == '\0' || c == ' '), 8)
            .expect("an octal size");
        let kind = tar[at + 156];
        at += 512;
        if (kind == b'0' || kind == 0) && size > 0 {
            files.push(tar[at..at + size].to_vec());
        }
        at += size.div_ceil(512) * 512;
    }
    files
}

/// `x` cut into pieces of `low` to `high` bytes.
fn pieces(rng: &mut Rng, x: &[u8], low: u64, high: u64) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < x.len() {
        let len = (rng.range(low, high) as usize).min(x.len() - at);
        out.push(x[at..at + len].to_vec());
        at += len;
    }
    out
}

/// A JSON record, of the kind dictionaries help.
fn record(rng: &mut Rng) -> Vec<u8> {
    const NAMES: [&str; 8] = [
        "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
    ];
    format!(
        "{{\"id\":{},\"name\":\"{}\",\"email\":\"{}{}@example.com\",\"age\":{},\"active\":{},\"roles\":[\"user\"{}]}}",
        rng.range(0, 1 << 20),
        NAMES[rng.range(0, 7) as usize],
        NAMES[rng.range(0, 7) as usize],
        rng.range(0, 999),
        rng.range(18, 90),
        rng.range(0, 1) == 1,
        if rng.chance(3) { ",\"admin\"" } else { "" }
    )
    .into_bytes()
}

/// Every set of samples the comparisons train on.
fn sample_sets(rng: &mut Rng) -> Vec<SampleSet> {
    let budget = scaled(400_000);
    let mut sets = Vec::new();
    for set in support::manifest().sets {
        if !set.present() {
            continue;
        }
        match (set.name.as_str(), set.kind) {
            ("ruzstd-dict", _) => {
                let units: Vec<Vec<u8>> = set
                    .list()
                    .into_iter()
                    .filter(|file| {
                        file.starts_with("files") && file.extension() != Some("zst".as_ref())
                    })
                    .map(|file| set.read(&file))
                    .collect();
                sets.push(SampleSet::new("systemd units", units, budget));
            }
            (_, Kind::Frames) => {
                let originals: Vec<Vec<u8>> = set
                    .frames()
                    .iter()
                    .filter_map(|frame| set.original(frame))
                    .filter(|original| original.len() < 64 << 10)
                    .collect();
                if originals.len() >= 7 {
                    sets.push(SampleSet::new(
                        format!("{} originals", set.name),
                        originals,
                        budget,
                    ));
                }
                if set.name == "zstd-regression-data" {
                    let tar = zstd::decode_all(&set.read("github.tar.zst".as_ref())[..])
                        .expect("github.tar decodes");
                    sets.push(SampleSet::new("github JSON", tar_files(&tar), budget));
                }
            }
            (_, Kind::Inputs) => {
                let mut all = Vec::new();
                for file in set.list() {
                    all.extend(pieces(rng, &set.read(&file), 30, 3000));
                }
                rng.shuffle(&mut all);
                sets.push(SampleSet::new(format!("{} pieces", set.name), all, budget));
            }
            (_, Kind::Bench) if set.name == "silesia" => {
                for file in ["dickens", "xml", "nci"] {
                    let path = set.folder().join(file);
                    if let Ok(data) = std::fs::read(path) {
                        let data = &data[..data.len().min(budget * 2)];
                        let mut all = pieces(rng, data, 100, 2000);
                        rng.shuffle(&mut all);
                        sets.push(SampleSet::new(format!("silesia {file}"), all, budget));
                    }
                }
            }
            _ => {}
        }
    }

    // Generated.
    let text = rng.data(100_000, &[]);
    let gen_budget = scaled(200_000);
    let text_samples: Vec<Vec<u8>> = (0..2000)
        .map(|_| rng.data_between(20, 600, &text))
        .collect();
    sets.push(SampleSet::new("text", text_samples, gen_budget));
    let records: Vec<Vec<u8>> = (0..3000).map(|_| record(rng)).collect();
    sets.push(SampleSet::new("records", records, gen_budget));
    let noise: Vec<Vec<u8>> = (0..200)
        .map(|_| (0..rng.range(1, 500)).map(|_| rng.next() as u8).collect())
        .collect();
    sets.push(SampleSet::new("noise", noise, gen_budget));
    sets.push(SampleSet::new(
        "one byte repeated",
        (0..100).map(|_| vec![b'z'; 300]),
        gen_budget,
    ));
    let mixed: Vec<Vec<u8>> = (0..300)
        .map(|i| match i % 4 {
            0 => Vec::new(),
            1 => vec![b'x'; rng.range(1, 7) as usize],
            _ => record(rng),
        })
        .collect();
    sets.push(SampleSet::new(
        "records, empty and tiny ones",
        mixed,
        gen_budget,
    ));
    // Samples over a block (128 KB), whose first block alone makes the
    // statistics. Not under emulation: there libzstd's block splitter, in
    // the frames that judge the trials, hashes in the machine's byte order
    // (see tests/compress_dict.rs).
    if !SLOW {
        let large: Vec<Vec<u8>> = (0..10)
            .map(|_| rng.data_between(140_000, 200_000, &text))
            .collect();
        sets.push(SampleSet::new("large samples", large, 2_000_000));
    }
    // Too few, or too small: libzstd's errors.
    let tiny: Vec<Vec<u8>> = (0..500).map(|_| rng.data_between(0, 7, &text)).collect();
    sets.push(SampleSet::new("tiny", tiny, gen_budget));
    for n in [0, 1, 5, 6, 7, 8] {
        let few: Vec<Vec<u8>> = (0..n).map(|_| rng.data_between(100, 2000, &text)).collect();
        sets.push(SampleSet::new(format!("{n} samples"), few, gen_budget));
    }
    // Tiny training samples, the test ones large: the default trainer's
    // training set is then under 8 bytes, where libzstd reads past the
    // samples.
    let mut lopsided: Vec<Vec<u8>> = vec![vec![b'a']; 6];
    lopsided.extend((0..2).map(|_| rng.data_between(500, 1000, &text)));
    sets.push(SampleSet::new("lopsided", lopsided, gen_budget));
    sets
}

/// Whether libzstd's default trainer would read past the samples (or
/// divide by zero): enough of them, but the first three quarters, its
/// training set, under 8 bytes. The port fails with `SrcSizeWrong`.
fn libzstd_reads_past(sizes: &[usize], capacity: usize) -> bool {
    let n = sizes.len();
    let total: usize = sizes.iter().sum();
    let nb_train = (n as f64 * 0.75) as usize;
    capacity >= 256 && n >= 7 && total >= 8 && sizes[..nb_train].iter().sum::<usize>() < 8
}

fn name(code: usize) -> String {
    zstd_safe::get_error_name(code).to_string()
}

/// The dictionary at work: samples compressed with it, by the port and by
/// libzstd, the same frames, with a `CDict` and loaded for the frame,
/// decoded back by both.
fn check_dictionary(problems: &mut Problems, what: &str, dict: &[u8], set: &SampleSet) {
    if hivepack::zstd::get_dict_id(dict) != zstd_safe::get_dict_id(dict).map_or(0, |id| id.get()) {
        problems.add(format!("{what}: the dictionary IDs differ"));
    }
    let cdict = CDict::new(dict, 3).expect("the port loads its dictionary");
    let c_cdict = zstd_safe::CDict::try_create(dict, 3).expect("libzstd loads it");
    let ddict = DDict::new(dict).expect("the port's decoder loads it");
    let mut c = zstd_safe::CCtx::create();
    let mut d = zstd_safe::DCtx::create();
    let mut p = CCtx::new();
    let mut pd = DCtx::new();
    for i in (0..set.sizes.len()).step_by((set.sizes.len() / 6).max(1)) {
        let sample = set.sample(i);
        let capacity = hivepack::zstd::compress_bound(sample.len()).expect("a bound");
        for with_cdict in [true, false] {
            let mut frame = vec![0u8; capacity];
            let mut want = vec![0u8; capacity];
            let (size, want_size) = if with_cdict {
                (
                    p.compress_using_cdict(&mut frame, sample, &cdict),
                    c.compress_using_cdict(&mut want[..], sample, &c_cdict),
                )
            } else {
                (
                    p.compress_using_dict(&mut frame, sample, dict, 3),
                    c.compress_using_dict(&mut want[..], sample, dict, 3),
                )
            };
            let size = size.expect("compresses");
            frame.truncate(size);
            if want_size.ok().map(|n| &want[..n]) != Some(&frame[..]) {
                problems.add(format!(
                    "{what}: sample {i} compresses otherwise than libzstd (CDict: {with_cdict})"
                ));
            }
            let mut back = vec![0u8; sample.len()];
            let port_back = pd.decompress_using_ddict(&mut back, &frame, &ddict);
            if port_back.ok() != Some(sample.len()) || back != sample {
                problems.add(format!(
                    "{what}: sample {i} does not decode back with the port"
                ));
            }
            let mut back = vec![0u8; sample.len()];
            let c_back = d.decompress_using_dict(&mut back[..], &frame, dict);
            if c_back.ok() != Some(sample.len()) || back != sample {
                problems.add(format!(
                    "{what}: sample {i} does not decode back with libzstd"
                ));
            }
        }
    }
}

#[test]
fn train_from_buffer_trains_as_libzstd() {
    let mut rng = Rng(0x5EED_D1C7);
    let sets = sample_sets(&mut rng);
    let capacities: &[usize] = if EMULATED {
        &[255, 256, 1000, 4096]
    } else if SLOW {
        &[0, 255, 256, 1000, 4096, 16_384]
    } else {
        &[0, 100, 255, 256, 257, 1000, 4096, 16_384, 65_536, 112_640]
    };
    let mut problems = Problems::default();
    let mut outcomes = std::collections::BTreeMap::<String, usize>::new();
    for set in &sets {
        for &capacity in capacities {
            let what = format!(
                "{} ({} samples, {} bytes) into {capacity}",
                set.name,
                set.sizes.len(),
                set.samples.len()
            );
            let mut got = vec![0u8; capacity];
            let got_size = hivepack::zstd::train_from_buffer(&mut got, &set.samples, &set.sizes);
            if libzstd_reads_past(&set.sizes, capacity) {
                if got_size.map_err(|e| e.code()) != Err(ErrorCode::SrcSizeWrong) {
                    problems.add(format!("{what}: {got_size:?}, not SrcSizeWrong"));
                }
                *outcomes
                    .entry("training samples too small".into())
                    .or_default() += 1;
                continue;
            }
            let mut want = vec![0u8; capacity];
            let want_size = zstd_safe::train_from_buffer(&mut want[..], &set.samples, &set.sizes);
            match (want_size, got_size) {
                (Ok(want_size), Ok(got_size)) => {
                    if want[..want_size] != got[..got_size] {
                        problems.add(format!(
                            "{what}: {got_size} bytes, libzstd's {want_size}, not the same"
                        ));
                    } else {
                        check_dictionary(&mut problems, &what, &got[..got_size], set);
                    }
                    *outcomes.entry("trained".into()).or_default() += 1;
                }
                (Err(code), Err(error)) => {
                    if name(code) != error.code().message() {
                        problems.add(format!(
                            "{what}: {:?}, libzstd's {}",
                            error.code(),
                            name(code)
                        ));
                    }
                    *outcomes
                        .entry(format!("failed: {}", name(code)))
                        .or_default() += 1;
                }
                (want, got) => problems.add(format!(
                    "{what}: {:?}, libzstd's {:?}",
                    got.map_err(|e| e.code()),
                    want.map_err(name)
                )),
            }
        }
    }
    let names: Vec<String> = sets
        .iter()
        .map(|set| format!("{} ({} samples)", set.name, set.sizes.len()))
        .collect();
    eprintln!(
        "{} sample sets, {}: {outcomes:?}",
        sets.len(),
        names.join(", ")
    );
    assert!(
        outcomes.get("trained").copied().unwrap_or(0) >= 20,
        "{outcomes:?}"
    );
    problems.check();
}

/// The parameters an optimizer gives back, but its threads.
fn without_threads_cover(mut p: CoverParams) -> CoverParams {
    p.nb_threads = 0;
    p
}

fn without_threads_fast(mut p: FastCoverParams) -> FastCoverParams {
    p.nb_threads = 0;
    p
}

#[test]
fn optimizers_train_the_same_on_any_number_of_threads() {
    let mut rng = Rng(0x5EED_7E4D);
    let text = rng.data(50_000, &[]);
    let budget = scaled(80_000);
    let sets = [
        SampleSet::new("records", (0..2000).map(|_| record(&mut rng)), budget),
        SampleSet::new(
            "text",
            (0..1000).map(|_| rng.data_between(20, 400, &text)),
            budget,
        ),
        // Small: many trials give the same dictionary, and the same size,
        // which the first in order wins.
        SampleSet::new("few records", (0..40).map(|_| record(&mut rng)), budget),
    ];
    let mut problems = Problems::default();
    for set in &sets {
        for capacity in [512, 4096] {
            let cover = CoverParams {
                steps: 6,
                split_point: if capacity == 512 { 0.8 } else { 0.0 },
                ..CoverParams::default()
            };
            let fast = FastCoverParams {
                steps: 8,
                f: 16,
                ..FastCoverParams::default()
            };
            let mut one_cover = None;
            let mut one_fast = None;
            for threads in [1, 2, 3, 8] {
                let mut dict = vec![0u8; capacity];
                let mut params = CoverParams {
                    nb_threads: threads,
                    ..cover
                };
                let size = hivepack::zstd::optimize_train_from_buffer_cover(
                    &mut dict,
                    &set.samples,
                    &set.sizes,
                    &mut params,
                )
                .expect("trains");
                let result = (dict[..size].to_vec(), without_threads_cover(params));
                assert_eq!(params.nb_threads, threads);
                match &one_cover {
                    None => one_cover = Some(result),
                    Some(one) if *one != result => problems.add(format!(
                        "{} into {capacity}, COVER on {threads} threads: {:?}, on one {:?}",
                        set.name, result.1, one.1
                    )),
                    _ => {}
                }

                let mut dict = vec![0u8; capacity];
                let mut params = FastCoverParams {
                    nb_threads: threads,
                    ..fast
                };
                let size = hivepack::zstd::optimize_train_from_buffer_fast_cover(
                    &mut dict,
                    &set.samples,
                    &set.sizes,
                    &mut params,
                )
                .expect("trains");
                let result = (dict[..size].to_vec(), without_threads_fast(params));
                match &one_fast {
                    None => one_fast = Some(result),
                    Some(one) if *one != result => problems.add(format!(
                        "{} into {capacity}, fast COVER on {threads} threads: {:?}, on one {:?}",
                        set.name, result.1, one.1
                    )),
                    _ => {}
                }
            }
        }
    }
    problems.check();
}

#[test]
fn parameters_take_libzstds_defaults_and_bounds() {
    let mut rng = Rng(0x5EED_BA5E);
    let set = SampleSet::new("records", (0..400).map(|_| record(&mut rng)), 100_000);
    let (samples, sizes) = (&set.samples[..], &set.sizes[..]);
    let code = |r: hivepack::zstd::Result<usize>| r.map_err(|e| e.code());
    let mut dict = vec![0u8; 2048];

    // COVER: k and d are needed, d <= k <= the room.
    for (k, d) in [(0, 8), (200, 0), (100, 101), (2049, 8)] {
        let params = CoverParams {
            k,
            d,
            ..CoverParams::default()
        };
        assert_eq!(
            code(hivepack::zstd::train_from_buffer_cover(
                &mut dict, samples, sizes, params
            )),
            Err(ErrorCode::ParameterOutOfBound),
            "k {k}, d {d}"
        );
    }
    let params = CoverParams {
        k: 200,
        d: 12,
        ..CoverParams::default()
    };
    assert!(hivepack::zstd::train_from_buffer_cover(&mut dict, samples, sizes, params).is_ok());
    assert_eq!(
        code(hivepack::zstd::train_from_buffer_cover(
            &mut dict,
            samples,
            &[],
            params
        )),
        Err(ErrorCode::SrcSizeWrong)
    );
    assert_eq!(
        code(hivepack::zstd::train_from_buffer_cover(
            &mut dict[..255],
            samples,
            sizes,
            CoverParams { k: 100, ..params }
        )),
        Err(ErrorCode::DstSizeTooSmall)
    );

    // The COVER optimizer: its defaults, given back.
    let mut params = CoverParams {
        steps: 3,
        nb_threads: 2,
        shrink_dict: true,
        shrink_dict_max_regression: 7,
        z_params: DictParams {
            compression_level: 5,
            notification_level: 3,
            dict_id: 1234,
        },
        ..CoverParams::default()
    };
    let size =
        hivepack::zstd::optimize_train_from_buffer_cover(&mut dict, samples, sizes, &mut params)
            .expect("trains");
    assert!([6, 8].contains(&params.d), "{params:?}");
    assert_eq!(params.split_point, 1.0);
    assert_eq!(params.steps, 3);
    assert_eq!(params.nb_threads, 2);
    // No shrinking, as in libzstd; the notification level lowered.
    assert!(!params.shrink_dict);
    assert_eq!(params.shrink_dict_max_regression, 7);
    assert_eq!(params.z_params.notification_level, 2);
    assert_eq!(hivepack::zstd::get_dict_id(&dict[..size]), 1234);
    for split_point in [1.5, -0.0 - 1.0 + 2.0001] {
        let mut params = CoverParams {
            split_point,
            ..CoverParams::default()
        };
        assert_eq!(
            code(hivepack::zstd::optimize_train_from_buffer_cover(
                &mut dict,
                samples,
                sizes,
                &mut params
            )),
            Err(ErrorCode::ParameterOutOfBound)
        );
    }

    // Fast COVER: d is 6 or 8, f up to 31, accel up to 10.
    for (d, f, accel) in [(7, 20, 1), (8, 32, 1), (8, 20, 11)] {
        let params = FastCoverParams {
            k: 200,
            d,
            f,
            accel,
            ..FastCoverParams::default()
        };
        assert_eq!(
            code(hivepack::zstd::train_from_buffer_fast_cover(
                &mut dict, samples, sizes, params
            )),
            Err(ErrorCode::ParameterOutOfBound),
            "d {d}, f {f}, accel {accel}"
        );
    }
    let mut params = FastCoverParams {
        k: 300,
        steps: 2,
        ..FastCoverParams::default()
    };
    hivepack::zstd::optimize_train_from_buffer_fast_cover(&mut dict, samples, sizes, &mut params)
        .expect("trains");
    assert_eq!((params.k, params.f, params.accel), (300, 20, 1));
    assert_eq!(params.split_point, 0.75);

    // Sizes past the samples.
    assert_eq!(
        code(hivepack::zstd::train_from_buffer(
            &mut dict,
            samples,
            &[samples.len() + 1]
        )),
        Err(ErrorCode::SrcSizeWrong)
    );
}

#[test]
fn finalized_dictionaries_hold_their_content() {
    let mut rng = Rng(0x5EED_F1A1);
    let set = SampleSet::new("records", (0..300).map(|_| record(&mut rng)), 100_000);
    let (samples, sizes) = (&set.samples[..], &set.sizes[..]);
    let content = set.samples[..3000].to_vec();
    let code = |r: hivepack::zstd::Result<usize>| r.map_err(|e| e.code());
    let params = DictParams {
        compression_level: 3,
        notification_level: 0,
        dict_id: 0xC0FFEE,
    };

    // Room for the header and the content.
    let mut dict = vec![0u8; 4000];
    let size = hivepack::zstd::finalize_dictionary(&mut dict, &content, samples, sizes, params)
        .expect("finalizes");
    let header = hivepack::zstd::get_dict_header_size(&dict[..size]).expect("a header");
    assert_eq!(size, header + content.len());
    assert_eq!(&dict[header..size], &content[..]);
    assert_eq!(hivepack::zstd::get_dict_id(&dict[..size]), 0xC0FFEE);

    // Too little room for the content: its start kept.
    let mut dict = vec![0u8; 3000];
    let size = hivepack::zstd::finalize_dictionary(&mut dict, &content, samples, sizes, params)
        .expect("finalizes");
    let header = hivepack::zstd::get_dict_header_size(&dict[..size]).expect("a header");
    assert_eq!(size, 3000);
    assert_eq!(&dict[header..], &content[..3000 - header]);
    assert_eq!(
        code(hivepack::zstd::finalize_dictionary(
            &mut dict[..2999],
            &content,
            samples,
            sizes,
            params
        )),
        Err(ErrorCode::DstSizeTooSmall)
    );
    assert_eq!(
        code(hivepack::zstd::finalize_dictionary(
            &mut dict[..255],
            &content[..10],
            samples,
            sizes,
            params
        )),
        Err(ErrorCode::DstSizeTooSmall)
    );

    // A content shorter than the largest repeat offset: zeros before it.
    let mut dict = vec![0u8; 1000];
    let size = hivepack::zstd::finalize_dictionary(&mut dict, b"abc", samples, sizes, params)
        .expect("finalizes");
    let header = hivepack::zstd::get_dict_header_size(&dict[..size]).expect("a header");
    assert_eq!(&dict[header..size], b"\0\0\0\0\0abc");

    // The deprecated way: the content at the end of the buffer.
    let mut dict = vec![0u8; 5000];
    dict[2000..].copy_from_slice(&content);
    let size = hivepack::zstd::add_entropy_tables_from_buffer(&mut dict, 3000, samples, sizes)
        .expect("adds the tables");
    let header = hivepack::zstd::get_dict_header_size(&dict[..size]).expect("a header");
    assert_eq!(&dict[header..size], &content[..]);
    check_dictionary(
        &mut Problems::default(),
        "added tables",
        &dict[..size],
        &set,
    );
}
