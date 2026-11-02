//! Compresses with dictionaries through the port and libzstd 1.5.7, the
//! same calls on both, and compares the frames byte for byte; then decodes
//! the port's frames back with the port.
//!
//! The dictionaries: zstd dictionaries trained by libzstd in the test, and
//! those of the test data (zstd's, ruzstd's, klauspost's, decodecorpus's),
//! with the inputs they come with; raw content, pieces of the data and
//! random bytes. Every level, in one call (`ZSTD_compress_usingDict`,
//! `ZSTD_compress_usingCDict`) and through `ZSTD_compress2` with a
//! dictionary loaded, a `CDict` referenced or a prefix, with each
//! preference to attach a dictionary; the contexts compress many frames,
//! their dictionaries changed between frames. The input sizes are on both
//! sides of where libzstd stops attaching a `CDict` (8, 16 and 32 KB), and
//! where it loads one again (128 KB, and 6 times the dictionary).
//!
//! The port attaches a `CDict` of `fast` or `dfast` (their `dictMatchState`
//! block compressors), and those frames are compared too, here and on
//! their own below. It does not attach one of the other strategies yet:
//! those frames fail with `ParameterUnsupported`, and are counted apart,
//! not compared.

#![allow(clippy::expect_used, clippy::panic)]

#[path = "zstd_support/mod.rs"]
mod support;

use std::sync::Arc;

use hivepack::zstd::{
    CCtx, CDict, CParameter as P, DCtx, DictAttachPref, DictContentType, EndDirective, ErrorCode,
    ParamSwitch, ResetDirective, Strategy,
};
use support::{Kind, Problems, Rng};
use zstd::zstd_safe::{self, CParameter as C};

const LEVELS: [i32; 18] = [
    -5, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13, 16, 18, 19, 22,
];

/// Sizes on both sides of the attach cutoffs, and of 128 KB.
const EDGES: [usize; 12] = [
    8191, 8192, 8193, 16_383, 16_384, 16_385, 32_767, 32_768, 32_769, 131_071, 131_072, 131_073,
];

/// A dictionary, and data it helps with.
struct Dictionary {
    name: String,
    bytes: Vec<u8>,
    /// Inputs that come with it, if any.
    inputs: Vec<Vec<u8>>,
    /// What to draw more inputs from.
    base: Vec<u8>,
}

/// The ways a frame went.
#[derive(Default, Debug)]
struct Counts {
    /// The dictionary loaded for the frame (`ZSTD_compress_usingDict`).
    direct: usize,
    /// A `CDict` copied in.
    copied: usize,
    /// A `CDict` loaded again, for a large input.
    reloaded: usize,
    /// A prefix.
    prefix: usize,
    /// Refused by the port: they would attach the `CDict`.
    refused: usize,
}

/// On big-endian machines libzstd's block splitter, which the strategies
/// from `greedy` up use on full blocks, hashes pairs of bytes in the
/// machine's order and splits elsewhere; the port gives the same frames
/// everywhere. Those frames are left out there (from level 3, to be safe
/// with the dictionary's sizes).
fn big_endian_skip(level: i32, len: usize) -> bool {
    cfg!(target_endian = "big") && level >= 3 && len >= 128 << 10
}

fn name(code: usize) -> String {
    zstd_safe::get_error_name(code).to_string()
}

/// The dictionaries of the test data that have inputs, and those trained
/// and drawn here.
fn dictionaries(rng: &mut Rng) -> Vec<Dictionary> {
    let mut list = Vec::new();
    for set in support::manifest().sets {
        if !set.present() {
            continue;
        }
        match (set.kind, &set.dictionary) {
            (Kind::Frames, Some(dict)) => {
                // Its frames' originals, a few of them.
                let bytes = set.read(std::path::Path::new(dict));
                let inputs: Vec<Vec<u8>> = set
                    .frames()
                    .iter()
                    .filter_map(|frame| set.original(frame))
                    .step_by(9)
                    .take(12)
                    .collect();
                list.push(Dictionary {
                    name: set.name.clone(),
                    base: inputs.concat(),
                    bytes,
                    inputs,
                });
            }
            (Kind::Dictionaries, _) => {
                for (key, files) in &set.inputs {
                    let bytes = set.read(std::path::Path::new(key));
                    let inputs: Vec<Vec<u8>> = files
                        .iter()
                        .map(|file| {
                            std::fs::read(support::repository().join("testdata").join(file))
                                .expect("input readable")
                        })
                        .collect();
                    list.push(Dictionary {
                        name: format!("{}/{key}", set.name),
                        base: inputs.concat(),
                        bytes,
                        inputs,
                    });
                }
            }
            (Kind::DictFrames, _) => {
                // Each dictionary with the content of its frames, decoded
                // by libzstd.
                for file in set.list() {
                    if file.extension() != Some("dict".as_ref()) {
                        continue;
                    }
                    let bytes = set.read(&file);
                    let folder = set.folder().join(file.with_extension(""));
                    let mut inputs = Vec::new();
                    let ddict = zstd_safe::DDict::create(&bytes);
                    let mut dctx = zstd_safe::DCtx::create();
                    for entry in std::fs::read_dir(&folder).into_iter().flatten().flatten() {
                        let frame = std::fs::read(entry.path()).expect("frame readable");
                        let mut out = vec![0u8; 1 << 20];
                        if let Ok(size) = dctx.decompress_using_ddict(&mut out[..], &frame, &ddict)
                        {
                            out.truncate(size);
                            inputs.push(out);
                        }
                    }
                    inputs.sort();
                    list.push(Dictionary {
                        name: format!("{}/{}", set.name, file.display()),
                        base: inputs.concat(),
                        bytes,
                        inputs,
                    });
                }
            }
            _ => {}
        }
    }

    // Trained by libzstd, from text-like samples.
    let text = rng.data(200_000, &[]);
    for i in 0..4 {
        if let Some(bytes) = rng.trained_dict(&text) {
            list.push(Dictionary {
                name: format!("trained {i}"),
                bytes,
                inputs: Vec::new(),
                base: text.clone(),
            });
        }
    }
    // Raw content: pieces of the data, small and large, and random bytes.
    for (i, len) in [8, 9, 100, 3000, 40_000, 200_000].into_iter().enumerate() {
        let at = rng.range(0, (text.len() - len) as u64) as usize;
        list.push(Dictionary {
            name: format!("raw {i} ({len} bytes)"),
            bytes: text[at..at + len].to_vec(),
            inputs: Vec::new(),
            base: text.clone(),
        });
    }
    let random: Vec<u8> = (0..5000).map(|_| rng.next() as u8).collect();
    list.push(Dictionary {
        name: "random bytes".into(),
        base: random.clone(),
        bytes: random,
        inputs: Vec::new(),
    });
    // Under 8 bytes: left out.
    list.push(Dictionary {
        name: "7 bytes".into(),
        bytes: text[..7].to_vec(),
        inputs: Vec::new(),
        base: text.clone(),
    });
    assert!(list.len() >= 14, "only {} dictionaries", list.len());
    list
}

/// The inputs to compress with `dict`: its own, and drawn from its base at
/// sizes on both sides of the cutoffs, and some random.
fn inputs(rng: &mut Rng, dict: &Dictionary, many: bool) -> Vec<Vec<u8>> {
    let mut inputs: Vec<Vec<u8>> = dict.inputs.iter().take(4).cloned().collect();
    let mut sizes = vec![0, 1, 50, rng.range(100, 8000) as usize];
    let edges = if many { EDGES.len() } else { 3 };
    for _ in 0..edges {
        sizes.push(EDGES[rng.range(0, EDGES.len() as u64 - 1) as usize]);
    }
    // Large enough to load a CDict again: 128 KB, and 6 times the
    // dictionary, on both sides.
    let six = 6 * dict.bytes.len();
    sizes.push((six.max(128 << 10) + rng.range(0, 1000) as usize).min(1 << 20));
    sizes.push(six.saturating_sub(rng.range(1, 100) as usize).max(1));
    if many {
        sizes.push(rng.range(33_000, 400_000) as usize);
    }
    for len in sizes {
        // A copy of its own, apart from the dictionary in memory.
        inputs.push(rng.data(len, &dict.base));
    }
    inputs
}

/// Decodes `frame` with the port, with `dict` as the decoder takes it.
fn decodes_back(frame: &[u8], src: &[u8], dict: &[u8], prefix: bool) -> bool {
    let mut dctx = DCtx::new();
    let mut back = vec![0u8; src.len()];
    let result = if prefix {
        dctx.ref_prefix(dict)
            .and_then(|()| dctx.decompress(&mut back, frame))
    } else {
        dctx.decompress_using_dict(&mut back, frame, dict)
    };
    matches!(result, Ok(n) if n == src.len() && back == src)
}

/// How a comparison went.
enum Outcome {
    Compared,
    Refused,
    Failed,
}

/// Compares the frames, and decodes the port's back.
#[allow(clippy::too_many_arguments)]
fn check(
    problems: &mut Problems,
    what: &str,
    want: Result<usize, usize>,
    want_frame: &[u8],
    got: hivepack::zstd::Result<usize>,
    got_frame: &[u8],
    src: &[u8],
    dict: &[u8],
    prefix: bool,
) -> Outcome {
    match (want, got) {
        // Refused before anything else, where libzstd compresses, or fails
        // for lack of room.
        (Ok(_) | Err(_), Err(error)) if error.code() == ErrorCode::ParameterUnsupported => {
            Outcome::Refused
        }
        (Ok(want), Ok(got)) => {
            if want_frame[..want] != got_frame[..got] {
                let at = (0..want.min(got))
                    .find(|&i| want_frame[i] != got_frame[i])
                    .unwrap_or(want.min(got));
                problems.add(format!(
                    "{what}: {got} bytes, libzstd {want}, first difference at {at}"
                ));
                return Outcome::Failed;
            }
            if !decodes_back(&got_frame[..got], src, dict, prefix) {
                problems.add(format!("{what}: does not decode back"));
                return Outcome::Failed;
            }
            Outcome::Compared
        }
        (Err(want), Err(got)) if name(want) == got.code().message() => Outcome::Compared,
        (want, got) => {
            problems.add(format!(
                "{what}: libzstd {:?}, port {:?}",
                want.map_err(name),
                got.map_err(|error| error.code().message())
            ));
            Outcome::Failed
        }
    }
}

/// Whether a frame of `len` bytes with a `CDict` made for a level goes
/// through loading its content again: past 128 KB and 6 times the
/// dictionary.
fn reloads(len: usize, dict_len: usize) -> bool {
    len >= 128 << 10 && len >= 6 * dict_len
}

/// One call: `ZSTD_compress_usingDict` and `ZSTD_compress_usingCDict`, at
/// every level, with every dictionary, one context each used for every
/// frame.
#[test]
fn one_call_with_dictionaries_compresses_as_libzstd() {
    let mut rng = Rng(0xD1C7_0001);
    let dicts = dictionaries(&mut rng);
    let mut problems = Problems::default();
    let mut counts = Counts::default();
    let mut c = zstd_safe::CCtx::create();
    let mut p = CCtx::new();
    for (d, dict) in dicts.iter().enumerate() {
        for (i, src) in inputs(&mut rng, dict, true).iter().enumerate() {
            let level = LEVELS[(d + 5 * i) % LEVELS.len()];
            if big_endian_skip(level, src.len()) {
                continue;
            }
            let bound = hivepack::zstd::compress_bound(src.len()).expect("a bound");
            let mut want = vec![0u8; bound];
            let mut got = vec![0u8; bound];

            // ZSTD_compress_usingDict.
            let what = format!(
                "{}, {} bytes, level {level}, using dict",
                dict.name,
                src.len()
            );
            let w = c.compress_using_dict(&mut want[..], src, &dict.bytes, level);
            let g = p.compress_using_dict(&mut got, src, &dict.bytes, level);
            if let Outcome::Compared = check(
                &mut problems,
                &what,
                w,
                &want,
                g,
                &got,
                src,
                &dict.bytes,
                false,
            ) {
                counts.direct += 1;
            }

            // ZSTD_compress_usingCDict, at another level.
            let level = LEVELS[(d + 5 * i + 7) % LEVELS.len()];
            let what = format!(
                "{}, {} bytes, level {level}, using CDict",
                dict.name,
                src.len()
            );
            let Some(c_cdict) = zstd_safe::CDict::try_create(&dict.bytes, level) else {
                assert!(
                    CDict::new(&dict.bytes, level).is_err(),
                    "{what}: libzstd makes no CDict"
                );
                continue;
            };
            let p_cdict = match CDict::new(&dict.bytes, level) {
                Ok(cdict) => cdict,
                Err(error) => {
                    problems.add(format!("{what}: the port makes no CDict: {error}"));
                    continue;
                }
            };
            let id = c_cdict.get_dict_id().map_or(0, |id| id.get());
            if p_cdict.dict_id() != id {
                problems.add(format!(
                    "{what}: dictionary ID {}, libzstd {id}",
                    p_cdict.dict_id()
                ));
            }
            if big_endian_skip(level, src.len()) {
                continue;
            }
            let w = c.compress_using_cdict(&mut want[..], src, &c_cdict);
            let g = p.compress_using_cdict(&mut got, src, &p_cdict);
            match check(
                &mut problems,
                &what,
                w,
                &want,
                g,
                &got,
                src,
                &dict.bytes,
                false,
            ) {
                Outcome::Compared if reloads(src.len(), dict.bytes.len()) => counts.reloaded += 1,
                Outcome::Compared => counts.copied += 1,
                Outcome::Refused => counts.refused += 1,
                Outcome::Failed => {}
            }
        }
    }
    eprintln!("{counts:?}");
    assert!(counts.direct > 150, "{counts:?}");
    assert!(counts.copied > 50, "{counts:?}");
    // A CDict is loaded again for inputs of 128 KB or more, which
    // big-endian machines leave out (see `big_endian_skip`).
    if cfg!(target_endian = "little") {
        assert!(counts.reloaded > 15, "{counts:?}");
    }
    // The port attaches every CDict libzstd attaches.
    assert_eq!(counts.refused, 0, "{counts:?}");
    problems.check();
}

/// How the contexts get their dictionary for a frame.
#[derive(Clone, Copy, Debug)]
enum Way {
    Load,
    RefCDict,
    Prefix,
    None,
}

/// `ZSTD_compress2` with a dictionary loaded, a `CDict` referenced or a
/// prefix, with each preference to attach a dictionary, the dictionary ID
/// flag on or off, and other parameters; two contexts used for all the
/// frames, the dictionary changed between them (or kept, which keeps a
/// loaded dictionary's `CDict` and its parameters).
#[test]
#[allow(clippy::too_many_lines)]
fn compress2_with_dictionaries_compresses_as_libzstd() {
    let mut rng = Rng(0xD1C7_0002);
    let dicts = dictionaries(&mut rng);
    // The CDicts first: the libzstd context must not outlive them.
    let mut c_cdicts = Vec::new();
    let mut p_cdicts = Vec::new();
    for (d, dict) in dicts.iter().enumerate() {
        let level = LEVELS[(3 * d) % LEVELS.len()];
        let made = (
            zstd_safe::CDict::try_create(&dict.bytes, level),
            CDict::new(&dict.bytes, level),
        );
        match made {
            (Some(c), Ok(p)) => {
                c_cdicts.push(Some(c));
                p_cdicts.push(Some(Arc::new(p)));
            }
            (None, Err(_)) => {
                c_cdicts.push(None);
                p_cdicts.push(None);
            }
            (c, p) => panic!(
                "{}: libzstd {}, port {p:?}",
                dict.name,
                if c.is_some() {
                    "made a CDict"
                } else {
                    "did not"
                }
            ),
        }
    }
    let mut problems = Problems::default();
    let mut counts = Counts::default();
    let mut c = zstd_safe::CCtx::create();
    let mut p = CCtx::new();
    let set_both = |c: &mut zstd_safe::CCtx<'_>, p: &mut CCtx, (pp, cp): (P, C)| {
        let want = c.set_parameter(cp).map(|_| ()).map_err(name);
        let got = p
            .set_parameter(pp)
            .map_err(|error| error.code().message().to_string());
        assert_eq!(want, got, "setting {pp:?}");
    };
    let mut way = Way::None;
    let mut current = 0;
    for round in 0..600 {
        // Sometimes the same dictionary again: a loaded one keeps its CDict,
        // made for the first frame's parameters. A prefix serves one frame.
        let change = round == 0 || rng.chance(2) || matches!(way, Way::Prefix | Way::None);
        if change {
            current = rng.range(0, dicts.len() as u64 - 1) as usize;
            way = match rng.range(0, 9) {
                0..=2 => Way::Load,
                3..=5 => Way::RefCDict,
                6..=8 => Way::Prefix,
                _ => Way::None,
            };
            if matches!(way, Way::RefCDict) && c_cdicts[current].is_none() {
                way = Way::Load;
            }
        }
        let dict = &dicts[current];
        let level = LEVELS[rng.range(0, LEVELS.len() as u64 - 1) as usize];
        let pref = match rng.range(0, 7) {
            0 => (
                DictAttachPref::DefaultAttach,
                zstd_safe::DictAttachPref::DefaultAttach,
            ),
            1 => (
                DictAttachPref::ForceAttach,
                zstd_safe::DictAttachPref::ForceAttach,
            ),
            2..=4 => (
                DictAttachPref::ForceCopy,
                zstd_safe::DictAttachPref::ForceCopy,
            ),
            _ => (
                DictAttachPref::ForceLoad,
                zstd_safe::DictAttachPref::ForceLoad,
            ),
        };
        set_both(
            &mut c,
            &mut p,
            (P::CompressionLevel(level), C::CompressionLevel(level)),
        );
        set_both(
            &mut c,
            &mut p,
            (P::ForceAttachDict(pref.0), C::ForceAttachDict(pref.1)),
        );
        let flag = !rng.chance(4);
        set_both(&mut c, &mut p, (P::DictIdFlag(flag), C::DictIdFlag(flag)));
        let checksum = rng.chance(3);
        set_both(
            &mut c,
            &mut p,
            (P::ChecksumFlag(checksum), C::ChecksumFlag(checksum)),
        );
        if rng.chance(5) {
            let window_log = rng.range(10, 20) as u32;
            set_both(
                &mut c,
                &mut p,
                (P::WindowLog(window_log), C::WindowLog(window_log)),
            );
        }
        if rng.chance(5) {
            let (pm, cm) = [
                (ParamSwitch::Auto, zstd_safe::ParamSwitch::Auto),
                (ParamSwitch::Enable, zstd_safe::ParamSwitch::Enable),
                (ParamSwitch::Disable, zstd_safe::ParamSwitch::Disable),
            ][rng.range(0, 2) as usize];
            set_both(
                &mut c,
                &mut p,
                (P::UseRowMatchFinder(pm), C::UseRowMatchFinder(cm)),
            );
        }
        if rng.chance(8) {
            // Long distance matching takes a raw dictionary's content too.
            set_both(
                &mut c,
                &mut p,
                (
                    P::EnableLongDistanceMatching(ParamSwitch::Enable),
                    C::EnableLongDistanceMatching(true),
                ),
            );
            set_both(&mut c, &mut p, (P::LdmMinMatch(16), C::LdmMinMatch(16)));
            set_both(&mut c, &mut p, (P::WindowLog(18), C::WindowLog(18)));
        } else {
            set_both(
                &mut c,
                &mut p,
                (
                    P::EnableLongDistanceMatching(ParamSwitch::Auto),
                    C::EnableLongDistanceMatching(false),
                ),
            );
        }
        // The dictionary, when it changes.
        if change {
            match way {
                Way::Load => {
                    c.load_dictionary(&dict.bytes).expect("libzstd loads it");
                    p.load_dictionary(&dict.bytes).expect("the port loads it");
                }
                Way::RefCDict => {
                    let Some(c_cdict) = &c_cdicts[current] else {
                        unreachable!()
                    };
                    c.ref_cdict(c_cdict).expect("libzstd takes it");
                    p.ref_cdict(p_cdicts[current].clone())
                        .expect("the port takes it");
                }
                Way::Prefix => {
                    c.ref_prefix(&dict.bytes).expect("libzstd takes it");
                    p.ref_prefix(&dict.bytes).expect("the port takes it");
                }
                Way::None => {
                    c.disable_dictionary().expect("libzstd drops it");
                    p.ref_cdict(None).expect("the port drops it");
                }
            }
        }

        let all = inputs(&mut rng, dict, false);
        let src = &all[rng.range(0, all.len() as u64 - 1) as usize];
        if big_endian_skip(level, src.len()) {
            // Drops a prefix on both, unused.
            c.reset(zstd_safe::ResetDirective::SessionAndParameters)
                .expect("libzstd resets");
            p.reset(ResetDirective::SessionAndParameters)
                .expect("the port resets");
            way = Way::None;
            continue;
        }
        let bound = hivepack::zstd::compress_bound(src.len()).expect("a bound");
        let room = if rng.chance(10) {
            rng.range(0, bound as u64) as usize
        } else {
            bound
        };
        let mut want = vec![0u8; room];
        let mut got = vec![0u8; room];
        let w = c.compress2(&mut want[..], src);
        let g = p.compress2(&mut got, src);
        let what = format!(
            "round {round}, {} {way:?}, {} bytes, level {level}, {:?}",
            dict.name,
            src.len(),
            pref.0
        );
        let prefix = matches!(way, Way::Prefix);
        match check(
            &mut problems,
            &what,
            w,
            &want,
            g,
            &got,
            src,
            &dict.bytes,
            prefix,
        ) {
            Outcome::Compared => match way {
                Way::Prefix => counts.prefix += 1,
                Way::None => counts.direct += 1,
                _ if pref.0 == DictAttachPref::ForceLoad => counts.reloaded += 1,
                _ => counts.copied += 1,
            },
            Outcome::Refused => {
                counts.refused += 1;
                // The port's context waits for a reset; libzstd's ended its
                // frame.
                p.reset(ResetDirective::SessionOnly)
                    .expect("the port resets");
            }
            Outcome::Failed => {}
        }
        // libzstd's context waits for a reset after an error.
        c.reset(zstd_safe::ResetDirective::SessionOnly)
            .expect("libzstd resets");
        p.reset(ResetDirective::SessionOnly)
            .expect("the port resets");
        if prefix {
            way = Way::None;
        }
    }
    eprintln!("{counts:?}");
    assert!(counts.prefix > 50, "{counts:?}");
    assert!(counts.copied > 100, "{counts:?}");
    assert!(counts.reloaded > 50, "{counts:?}");
    // The port attaches every CDict libzstd attaches.
    assert_eq!(counts.refused, 0, "{counts:?}");
    problems.check();
}

/// The parameters of a `CDict` made from parameters, and dictionaries read
/// as raw content or as zstd dictionaries only, through libzstd's
/// `ZSTD_createCDict_advanced2` and `ZSTD_CCtx_loadDictionary_advanced`,
/// are compared through the oracle (`src/oracle_compress.rs`), which the
/// `zstd` crate cannot reach. Here: what the port refuses and accepts.
#[test]
fn dictionaries_fail_as_libzstd_fails() {
    let mut rng = Rng(0xD1C7_0003);
    let text = rng.data(100_000, &[]);
    let trained = rng.trained_dict(&text).expect("a dictionary");
    // A zstd dictionary cut short: it starts with the magic number.
    let cut = &trained[..40];
    assert!(zstd_safe::CDict::try_create(cut, 3).is_none());
    assert_eq!(
        CDict::new(cut, 3).map(|_| ()).map_err(|e| e.code()),
        Err(ErrorCode::DictionaryCorrupted)
    );
    // As raw content, it is fine.
    let raw = CDict::with_parameters(cut, DictContentType::RawContent, &[]).expect("raw content");
    assert_eq!(raw.dict_id(), 0);
    // Not a zstd dictionary, but required to be.
    assert_eq!(
        CDict::with_parameters(&text[..100], DictContentType::FullDict, &[])
            .map(|_| ())
            .map_err(|e| e.code()),
        Err(ErrorCode::DictionaryWrong)
    );
    // A parameter out of bounds.
    assert_eq!(
        CDict::with_parameters(&trained, DictContentType::Auto, &[P::WindowLog(40)])
            .map(|_| ())
            .map_err(|e| e.code()),
        Err(ErrorCode::ParameterOutOfBound)
    );

    // Loaded, a zstd dictionary that cannot be read fails the frame, as an
    // allocation failure, as libzstd reports it.
    let src = rng.data(50_000, &text);
    let mut c = zstd_safe::CCtx::create();
    let mut p = CCtx::new();
    c.load_dictionary(cut).expect("libzstd loads it");
    p.load_dictionary(cut).expect("the port loads it");
    let mut out = vec![0u8; 100_000];
    let want = c.compress2(&mut out[..], &src).map_err(name);
    let got = p
        .compress2(&mut out, &src)
        .map_err(|error| error.code().message().to_string());
    assert_eq!(want, got);
    assert_eq!(got, Err(ErrorCode::MemoryAllocation.message().to_string()));
    // In one call, as corrupted.
    let want = c
        .compress_using_dict(&mut out[..], &src, cut, 3)
        .map_err(name);
    let got = p
        .compress_using_dict(&mut out, &src, cut, 3)
        .map_err(|error| error.code().message().to_string());
    assert_eq!(want, got);

    // Dictionaries are set between frames only.
    p.reset(ResetDirective::SessionAndParameters)
        .expect("the port resets");
    let mut output = hivepack::zstd::OutBuffer::new(&mut out);
    let mut input = hivepack::zstd::InBuffer::new(&src[..1000]);
    p.compress_stream2(
        &mut output,
        &mut input,
        hivepack::zstd::EndDirective::Continue,
    )
    .expect("a frame starts");
    for result in [
        p.load_dictionary(&trained),
        p.ref_prefix(&trained),
        p.ref_cdict(None),
        p.set_parameter(P::ForceAttachDict(DictAttachPref::ForceCopy)),
    ] {
        assert_eq!(result.map_err(|e| e.code()), Err(ErrorCode::StageWrong));
    }
    // Resetting the parameters drops the dictionaries.
    p.reset(ResetDirective::SessionOnly)
        .expect("the port resets");
    p.load_dictionary(&trained).expect("loaded");
    p.reset(ResetDirective::Parameters)
        .expect("the port resets");
    c.reset(zstd_safe::ResetDirective::Parameters)
        .expect("libzstd resets");
    c.load_dictionary(&trained).expect("loaded");
    c.reset(zstd_safe::ResetDirective::Parameters)
        .expect("libzstd resets");
    let mut want = vec![0u8; 100_000];
    let mut got = vec![0u8; 100_000];
    let w = c
        .compress2(&mut want[..], &src)
        .expect("libzstd compresses");
    let g = p.compress2(&mut got, &src).expect("the port compresses");
    assert_eq!(want[..w], got[..g]);
}

/// A `CDict` serves several contexts at once, across threads.
#[test]
fn cdicts_and_contexts_go_across_threads() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<CDict>();
    send_sync::<CCtx>();
    let mut rng = Rng(0xD1C7_0004);
    let text = rng.data(100_000, &[]);
    let dict = &text[..20_000];
    let cdict = Arc::new(CDict::new(dict, 5).expect("a CDict"));
    let piece = |i: usize| &text[40_000 + i * 10_000..60_000 + i * 10_000];
    let frames: Vec<Vec<u8>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|i| {
                let cdict = cdict.clone();
                let src = piece(i);
                scope.spawn(move || {
                    let mut cctx = CCtx::new();
                    cctx.set_parameter(P::ForceAttachDict(DictAttachPref::ForceCopy))
                        .expect("set");
                    cctx.ref_cdict(Some(cdict)).expect("referenced");
                    let mut out = vec![0u8; 40_000];
                    let size = cctx.compress2(&mut out, src).expect("compressed");
                    out.truncate(size);
                    out
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("the thread ends"))
            .collect()
    });
    for (i, frame) in frames.iter().enumerate() {
        assert!(decodes_back(frame, piece(i), dict, false), "frame {i}");
    }
}

/// The strategies whose `dictMatchState` block compressors the port has:
/// a frame with one of them that attaches a `CDict` compresses.
const ATTACH_STRATEGIES: [(Strategy, zstd_safe::Strategy); 2] = [
    (Strategy::Fast, zstd_safe::Strategy::ZSTD_fast),
    (Strategy::Dfast, zstd_safe::Strategy::ZSTD_dfast),
];

/// Levels whose `CDict`s are `fast` or `dfast`, whatever the size of the
/// dictionary (0 is 3).
const ATTACH_LEVELS: [i32; 8] = [-7, -5, -2, -1, 0, 1, 2, 3];

/// Inputs for frames that attach a `CDict`: of sizes around the cutoffs of
/// `fast` and `dfast` (8 and 16 KB), small ones, and larger ones that
/// attach when told to, in many blocks. Some repeat their start after the
/// dictionary's end, where a match in the dictionary runs on into the
/// input.
fn attach_inputs(rng: &mut Rng, dict: &Dictionary, count: usize) -> Vec<Vec<u8>> {
    let mut inputs: Vec<Vec<u8>> = dict.inputs.iter().take(1).cloned().collect();
    for _ in 0..count {
        if rng.chance(8) {
            let rest = rng.range(0, 20_000) as usize;
            inputs.push(running_on(rng, dict, rest));
            continue;
        }
        let len = match rng.range(0, 9) {
            0 => rng.range(0, 16),
            1 => rng.range(16, 2000),
            2 => rng.range(2000, 8191),
            3 => [8191, 8192, 8193][rng.range(0, 2) as usize],
            4 => rng.range(8193, 16_383),
            5 => [16_383, 16_384, 16_385][rng.range(0, 2) as usize],
            6 | 7 => rng.range(16_385, 100_000),
            _ => rng.range(100_000, 300_000),
        } as usize;
        inputs.push(rng.data(len, &dict.base));
    }
    inputs
}

/// An input that repeats its start after the dictionary's last bytes, and
/// `rest` bytes more: a match there in the dictionary runs on into the
/// input's start.
fn running_on(rng: &mut Rng, dict: &Dictionary, rest: usize) -> Vec<u8> {
    let head = rng.data_between(8, 3000, &dict.base);
    let tail = rng.range(1, 64).min(dict.bytes.len() as u64) as usize;
    let mut input = head.clone();
    input.extend_from_slice(&dict.bytes[dict.bytes.len() - tail..]);
    input.extend_from_slice(&head);
    input.extend(rng.data(rest, &dict.base));
    input
}

/// Random parameters for a frame that attaches a `CDict` of `fast` or
/// `dfast`, whose tables and strategy it takes, and the window its own: a
/// small window sometimes, which slides past the dictionary within the
/// frame, small blocks, long distance matching, the block splitter after
/// the sequences, the frame's flags.
fn attach_parameters(rng: &mut Rng) -> Vec<(P, C)> {
    let mut list = Vec::new();
    if rng.chance(2) {
        let value = rng.range(10, 18) as u32;
        list.push((P::WindowLog(value), C::WindowLog(value)));
    }
    if rng.chance(3) {
        let value = [1024, 2000, 4096, 8192, 65_536, 0][rng.range(0, 5) as usize];
        list.push((P::MaxBlockSize(value), C::MaxBlockSize(value)));
    }
    if rng.chance(6) {
        // Long distance matching, with small parameters, so that it finds
        // matches; the block compressor runs between its matches.
        list.push((
            P::EnableLongDistanceMatching(ParamSwitch::Enable),
            C::EnableLongDistanceMatching(true),
        ));
        list.push((P::LdmMinMatch(16), C::LdmMinMatch(16)));
        list.push((P::LdmHashRateLog(2), C::LdmHashRateLog(2)));
    } else {
        list.push((
            P::EnableLongDistanceMatching(ParamSwitch::Auto),
            C::EnableLongDistanceMatching(false),
        ));
    }
    let (p, c) = if rng.chance(6) {
        (ParamSwitch::Enable, zstd_safe::ParamSwitch::Enable)
    } else {
        (ParamSwitch::Auto, zstd_safe::ParamSwitch::Auto)
    };
    list.push((P::SplitAfterSequences(p), C::UseBlockSplitter(c)));
    let flag = rng.chance(3);
    list.push((P::ChecksumFlag(flag), C::ChecksumFlag(flag)));
    let flag = !rng.chance(4);
    list.push((P::DictIdFlag(flag), C::DictIdFlag(flag)));
    let flag = !rng.chance(4);
    list.push((P::ContentSizeFlag(flag), C::ContentSizeFlag(flag)));
    if rng.chance(5) {
        let (p, c) = [
            (ParamSwitch::Enable, zstd_safe::ParamSwitch::Enable),
            (ParamSwitch::Disable, zstd_safe::ParamSwitch::Disable),
        ][rng.range(0, 1) as usize];
        list.push((P::LiteralCompressionMode(p), C::LiteralCompressionMode(c)));
    }
    list
}

/// The parameters of a `CDict` a context makes of the dictionary it
/// loads, with `fast` or `dfast` set at any level: its tables' sizes, its
/// shortest match, its step (the target length, for `fast`).
fn local_cdict_parameters(rng: &mut Rng) -> Vec<(P, C)> {
    let mut list = Vec::new();
    let level = rng.range(0, 22) as i32 - 3;
    list.push((P::CompressionLevel(level), C::CompressionLevel(level)));
    let (p, c) = ATTACH_STRATEGIES[rng.range(0, 1) as usize];
    list.push((P::Strategy(Some(p)), C::Strategy(c)));
    if rng.chance(2) {
        let value = rng.range(6, 24) as u32;
        list.push((P::HashLog(value), C::HashLog(value)));
    }
    if rng.chance(2) {
        let value = rng.range(6, 24) as u32;
        list.push((P::ChainLog(value), C::ChainLog(value)));
    }
    if rng.chance(2) {
        let value = rng.range(3, 7) as u32;
        list.push((P::MinMatch(value), C::MinMatch(value)));
    }
    if rng.chance(3) {
        let value = [0, 1, 2, 7, 100, 4096][rng.range(0, 5) as usize];
        list.push((P::TargetLength(value), C::TargetLength(value)));
    }
    list
}

/// Sets the parameters on both; they must agree on whether each works.
fn set_all(c: &mut zstd_safe::CCtx<'_>, p: &mut CCtx, list: &[(P, C)]) -> Result<(), String> {
    for &(pp, cp) in list {
        let want = c.set_parameter(cp).map(|_| ()).map_err(name);
        let got = p
            .set_parameter(pp)
            .map_err(|error| error.code().message().to_string());
        if want != got {
            return Err(format!("setting {pp:?}: libzstd {want:?}, port {got:?}"));
        }
    }
    Ok(())
}

/// Whether a frame of `len` bytes (`None` when unknown) surely attaches
/// its `CDict` of `fast` or `dfast`, of a dictionary of `dict_len` bytes,
/// made for a level (`for_level`) or from parameters, with `pref`: up to
/// the cutoff of `fast` (8 KB) or of an unknown size, or with
/// `ForceAttach` unless its content is loaded again. A dictionary of under
/// 8 bytes is never attached (nor a zstd dictionary without content,
/// which these are not).
fn attaches(len: Option<usize>, dict_len: usize, for_level: bool, pref: DictAttachPref) -> bool {
    let reloaded = for_level && len.is_some_and(|len| reloads(len, dict_len));
    dict_len >= 8
        && !reloaded
        && match pref {
            DictAttachPref::ForceAttach => true,
            DictAttachPref::DefaultAttach => len.is_none_or(|len| len <= 8 << 10),
            _ => false,
        }
}

/// Compares the frames of an attached `CDict`, as [`check`] does; one the
/// port refuses is a problem.
#[allow(clippy::too_many_arguments)]
fn check_attached(
    problems: &mut Problems,
    what: &str,
    want: Result<usize, usize>,
    want_frame: &[u8],
    got: hivepack::zstd::Result<usize>,
    got_frame: &[u8],
    src: &[u8],
    dict: &[u8],
) -> bool {
    match check(
        problems, what, want, want_frame, got, got_frame, src, dict, false,
    ) {
        Outcome::Compared => true,
        Outcome::Refused => {
            problems.add(format!("{what}: refused"));
            false
        }
        Outcome::Failed => false,
    }
}

/// Frames that attach a `CDict` of `fast` or `dfast`, in one call, against
/// libzstd: `ZSTD_compress_usingCDict` with `CDict`s made for the levels
/// of `fast` and `dfast` (attached up to the strategy's cutoff), and
/// `ZSTD_compress2` with them referenced and `ZSTD_c_forceAttachDict` set
/// to attach, or with a dictionary loaded and `fast` or `dfast` set at any
/// level, at sizes on both sides of the cutoffs and of many blocks; with
/// every dictionary, raw and zstd ones, on two contexts used for every
/// frame. Small windows that slide past the dictionary within the frame,
/// small blocks, long distance matching.
#[test]
#[allow(clippy::too_many_lines)]
fn frames_attached_to_cdicts_of_fast_and_dfast_compress_as_libzstd() {
    let mut rng = Rng(0xD1C7_0005);
    let dicts = dictionaries(&mut rng);
    // CDicts made by both for the levels of fast and dfast, half of them
    // for each dictionary; the libzstd context must not outlive them.
    let mut cdicts = Vec::new();
    for (d, dict) in dicts.iter().enumerate() {
        for (k, &level) in ATTACH_LEVELS.iter().enumerate() {
            if (d + k) % 2 == 1 {
                continue;
            }
            let Some(c_cdict) = zstd_safe::CDict::try_create(&dict.bytes, level) else {
                assert!(CDict::new(&dict.bytes, level).is_err(), "{}", dict.name);
                continue;
            };
            let p_cdict = Arc::new(CDict::new(&dict.bytes, level).expect("a CDict"));
            cdicts.push((d, level, c_cdict, p_cdict));
        }
    }
    let mut problems = Problems::default();
    let mut compared = 0;
    let mut attached = 0;
    let mut c = zstd_safe::CCtx::create();
    let mut p = CCtx::new();
    for (d, dict) in dicts.iter().enumerate() {
        for (_, level, c_cdict, p_cdict) in cdicts.iter().filter(|cdict| cdict.0 == d) {
            let level = *level;
            for src in attach_inputs(&mut rng, dict, 10) {
                let bound = hivepack::zstd::compress_bound(src.len()).expect("a bound");
                let mut want = vec![0u8; bound];
                let mut got = vec![0u8; bound];

                // ZSTD_compress_usingCDict, attached up to the cutoff.
                let what = format!(
                    "{}, {} bytes, level {level}, using CDict",
                    dict.name,
                    src.len()
                );
                let w = c.compress_using_cdict(&mut want[..], &src, c_cdict);
                let g = p.compress_using_cdict(&mut got, &src, p_cdict);
                if check_attached(&mut problems, &what, w, &want, g, &got, &src, &dict.bytes) {
                    compared += 1;
                    attached += usize::from(attaches(
                        Some(src.len()),
                        dict.bytes.len(),
                        true,
                        DictAttachPref::DefaultAttach,
                    ));
                }

                // ZSTD_compress2 with the CDict referenced, told to attach
                // it (or not told), with other parameters.
                let pref = if rng.chance(4) {
                    (
                        DictAttachPref::DefaultAttach,
                        zstd_safe::DictAttachPref::DefaultAttach,
                    )
                } else {
                    (
                        DictAttachPref::ForceAttach,
                        zstd_safe::DictAttachPref::ForceAttach,
                    )
                };
                let mut list = attach_parameters(&mut rng);
                list.push((P::ForceAttachDict(pref.0), C::ForceAttachDict(pref.1)));
                if let Err(problem) = set_all(&mut c, &mut p, &list) {
                    problems.add(format!("{}: {problem}", dict.name));
                    continue;
                }
                c.ref_cdict(c_cdict).expect("libzstd takes it");
                p.ref_cdict(Some(p_cdict.clone()))
                    .expect("the port takes it");
                let room = if rng.chance(10) {
                    rng.range(0, bound as u64) as usize
                } else {
                    bound
                };
                let what = format!(
                    "{}, {} bytes, level {level}, compress2, {:?}, {list:?}",
                    dict.name,
                    src.len(),
                    pref.0
                );
                let w = c.compress2(&mut want[..room], &src);
                let g = p.compress2(&mut got[..room], &src);
                if check_attached(&mut problems, &what, w, &want, g, &got, &src, &dict.bytes) {
                    compared += 1;
                    attached +=
                        usize::from(attaches(Some(src.len()), dict.bytes.len(), true, pref.0));
                }
                c.reset(zstd_safe::ResetDirective::SessionAndParameters)
                    .expect("libzstd resets");
                p.reset(ResetDirective::SessionAndParameters)
                    .expect("the port resets");
            }
        }

        // ZSTD_compress2 with the dictionary loaded, its CDict made with
        // fast or dfast at any level, and told to attach it (or not told).
        for src in attach_inputs(&mut rng, dict, 16) {
            let bound = hivepack::zstd::compress_bound(src.len()).expect("a bound");
            let mut want = vec![0u8; bound];
            let mut got = vec![0u8; bound];
            let pref = if rng.chance(3) {
                (
                    DictAttachPref::DefaultAttach,
                    zstd_safe::DictAttachPref::DefaultAttach,
                )
            } else {
                (
                    DictAttachPref::ForceAttach,
                    zstd_safe::DictAttachPref::ForceAttach,
                )
            };
            let mut list = local_cdict_parameters(&mut rng);
            list.extend(attach_parameters(&mut rng));
            list.push((P::ForceAttachDict(pref.0), C::ForceAttachDict(pref.1)));
            if let Err(problem) = set_all(&mut c, &mut p, &list) {
                problems.add(format!("{}: {problem}", dict.name));
                continue;
            }
            c.load_dictionary(&dict.bytes).expect("libzstd loads it");
            p.load_dictionary(&dict.bytes).expect("the port loads it");
            let what = format!(
                "{}, {} bytes, loaded, {:?}, {list:?}",
                dict.name,
                src.len(),
                pref.0
            );
            let w = c.compress2(&mut want[..], &src);
            let g = p.compress2(&mut got, &src);
            if check_attached(&mut problems, &what, w, &want, g, &got, &src, &dict.bytes) {
                compared += 1;
                // Never loaded again: made from parameters.
                attached += usize::from(attaches(Some(src.len()), dict.bytes.len(), false, pref.0));
            }
            c.reset(zstd_safe::ResetDirective::SessionAndParameters)
                .expect("libzstd resets");
            p.reset(ResetDirective::SessionAndParameters)
                .expect("the port resets");
        }
    }
    eprintln!("{compared} frames compared, {attached} attached");
    // About 1100 with all the test data; fewer without the sets fetched
    // (the core group), whose frames give some dictionaries' inputs.
    assert!(attached > 600, "only {attached} frames attached");
    problems.check();
}

/// One frame of `data` through both contexts, streaming, in the same
/// calls: the same pieces of input, the same room for output (all of one
/// buffer with a stable output buffer), the same directives. Every call
/// must return the same, read and write as far, and write the same.
/// Returns the frame, and whether the first call ended it (which makes
/// its size known: all the input given then), or `None` where both failed
/// alike.
fn stream_both_frame(
    c: &mut zstd_safe::CCtx<'_>,
    p: &mut CCtx,
    data: &[u8],
    rng: &mut Rng,
    stable_out: bool,
) -> Result<Option<(Vec<u8>, bool)>, String> {
    use zstd_safe::zstd_sys::ZSTD_EndDirective as D;
    let bound = hivepack::zstd::compress_bound(data.len()).expect("a bound") + 32;
    let room = if stable_out && rng.chance(10) {
        rng.range(0, 64) as usize
    } else {
        bound
    };
    let (mut c_stable, mut p_stable) = (vec![0u8; room], vec![0u8; room]);
    let mut stable_pos = 0;
    let mut frame = Vec::new();
    let mut taken = 0;
    for call in 0..200_000 {
        let size = match rng.range(0, 3) {
            0 => rng.range(0, 8),
            1 => rng.range(1, 3000),
            _ => rng.range(1, 70_000),
        } as usize;
        let end = (taken + size).min(data.len());
        let directive = if end == data.len() && !rng.chance(4) {
            EndDirective::End
        } else if rng.chance(8) {
            EndDirective::Flush
        } else {
            EndDirective::Continue
        };
        let (mut c_fresh, mut p_fresh) = if stable_out {
            (Vec::new(), Vec::new())
        } else {
            let room = rng.range(0, 140_000) as usize;
            (vec![0u8; room], vec![0u8; room])
        };
        let (c_dst, p_dst, out_pos) = if stable_out {
            (&mut c_stable[..], &mut p_stable[..], stable_pos)
        } else {
            (&mut c_fresh[..], &mut p_fresh[..], 0)
        };
        let src = &data[taken..end];
        let (want, ci, co) = {
            let mut output = zstd_safe::OutBuffer::around_pos(&mut *c_dst, out_pos);
            let mut input = zstd_safe::InBuffer::around(src);
            let mode = match directive {
                EndDirective::Continue => D::ZSTD_e_continue,
                EndDirective::Flush => D::ZSTD_e_flush,
                EndDirective::End => D::ZSTD_e_end,
            };
            let result = c.compress_stream2(&mut output, &mut input, mode);
            (result.map_err(name), input.pos(), output.pos())
        };
        let (got, pi, po) = {
            let mut output = hivepack::zstd::OutBuffer {
                dst: &mut *p_dst,
                pos: out_pos,
            };
            let mut input = hivepack::zstd::InBuffer { src, pos: 0 };
            let result = p
                .compress_stream2(&mut output, &mut input, directive)
                .map_err(|error| error.code().message().to_string());
            (result, input.pos, output.pos)
        };
        if (&want, ci, co) != (&got, pi, po) {
            return Err(format!(
                "call {call} ({directive:?}, input {taken}..{end}, output from {out_pos} of {}): \
                 libzstd {want:?} read to {ci} wrote to {co}, port {got:?} read to {pi} wrote to \
                 {po}",
                c_dst.len()
            ));
        }
        if c_dst[out_pos..co] != p_dst[out_pos..po] {
            return Err(format!("call {call} ({directive:?}): the output differs"));
        }
        frame.extend_from_slice(&c_dst[out_pos..co]);
        if stable_out {
            stable_pos = co;
        }
        taken += ci;
        match want {
            Err(_) => return Ok(None),
            Ok(0) if directive == EndDirective::End => return Ok(Some((frame, call == 0))),
            Ok(_) => {}
        }
    }
    Err("no end".into())
}

/// Streaming frames that attach a `CDict` of `fast` or `dfast`, as
/// libzstd does for inputs of unknown size: contexts used for several
/// frames, the dictionary kept or changed between them (referenced, or
/// loaded with `fast` or `dfast` set at any level), call by call against
/// libzstd. Sometimes a size pledged, on either side of the cutoffs, or
/// told to attach; a stable output buffer; small windows, where the input
/// buffer wraps around and the dictionary goes out of reach within the
/// frame, and small blocks before that.
#[test]
#[allow(clippy::too_many_lines)]
fn streaming_attached_to_cdicts_of_fast_and_dfast_compresses_as_libzstd() {
    let mut rng = Rng(0xD1C7_0006);
    let dicts = dictionaries(&mut rng);
    // CDicts made by both for the levels of fast and dfast; the libzstd
    // contexts must not outlive them.
    let cdicts: Vec<(usize, zstd_safe::CDict<'static>, Arc<CDict>)> = dicts
        .iter()
        .enumerate()
        .filter_map(|(d, dict)| {
            let level = ATTACH_LEVELS[d % ATTACH_LEVELS.len()];
            let c = zstd_safe::CDict::try_create(&dict.bytes, level)?;
            let p = CDict::new(&dict.bytes, level).expect("a CDict");
            Some((d, c, Arc::new(p)))
        })
        .collect();
    let mut problems = Problems::default();
    let mut compared = 0;
    let mut attached = 0;
    for context in 0..250 {
        let mut c = zstd_safe::CCtx::create();
        let mut p = CCtx::new();
        // The dictionary of the frames, and whether its CDict was made for
        // a level (referenced) rather than from parameters (loaded).
        let mut current: Option<(usize, bool)> = None;
        for round in 0..rng.range(2, 5) {
            let tag = format!("context {context}, frame {round}");
            let change = current.is_none() || rng.chance(2);
            let mut list = attach_parameters(&mut rng);
            let pref = match rng.range(0, 5) {
                0 => (
                    DictAttachPref::ForceAttach,
                    zstd_safe::DictAttachPref::ForceAttach,
                ),
                _ => (
                    DictAttachPref::DefaultAttach,
                    zstd_safe::DictAttachPref::DefaultAttach,
                ),
            };
            list.push((P::ForceAttachDict(pref.0), C::ForceAttachDict(pref.1)));
            let stable_out = rng.chance(4);
            list.push((
                P::StableOutBuffer(stable_out),
                C::StableOutBuffer(stable_out),
            ));
            // A loaded dictionary's CDict takes the parameters of then.
            let load = change && rng.chance(3);
            if load {
                list.extend(local_cdict_parameters(&mut rng));
            }
            if let Err(problem) = set_all(&mut c, &mut p, &list) {
                problems.add(format!("{tag}: {problem}"));
                break;
            }
            if change {
                let k = rng.range(0, cdicts.len() as u64 - 1) as usize;
                let (d, c_cdict, p_cdict) = &cdicts[k];
                if load {
                    c.load_dictionary(&dicts[*d].bytes)
                        .expect("libzstd loads it");
                    p.load_dictionary(&dicts[*d].bytes)
                        .expect("the port loads it");
                } else {
                    c.ref_cdict(c_cdict).expect("libzstd takes it");
                    p.ref_cdict(Some(p_cdict.clone()))
                        .expect("the port takes it");
                }
                current = Some((*d, !load));
            }
            let Some((d, for_level)) = current else {
                unreachable!()
            };
            let dict = &dicts[d];
            let len = match rng.range(0, 4) {
                0 => rng.range(0, 9000),
                1 => rng.range(0, 20_000),
                2 => rng.range(20_000, 150_000),
                _ => rng.range(100_000, 500_000),
            } as usize;
            let data = if rng.chance(6) {
                running_on(&mut rng, dict, len)
            } else {
                rng.data(len, &dict.base)
            };
            let len = data.len();
            let pledged = rng.chance(4).then_some(len);
            if let Some(size) = pledged {
                let want = c
                    .set_pledged_src_size(Some(size as u64))
                    .map(|_| ())
                    .map_err(name);
                let got = p
                    .set_pledged_src_size(size as u64)
                    .map_err(|error| error.code().message().to_string());
                if want != got {
                    problems.add(format!("{tag}: pledging: libzstd {want:?}, port {got:?}"));
                    break;
                }
            }
            let what = format!(
                "{tag}: {}, {len} bytes, pledged {pledged:?}, stable output {stable_out}, {list:?}",
                dict.name
            );
            match stream_both_frame(&mut c, &mut p, &data, &mut rng, stable_out) {
                Err(problem) => {
                    problems.add(format!("{what}: {problem}"));
                    break;
                }
                Ok(None) => {
                    c.reset(zstd_safe::ResetDirective::SessionOnly)
                        .expect("libzstd resets");
                    p.reset(ResetDirective::SessionOnly)
                        .expect("the port resets");
                }
                Ok(Some((frame, whole))) => {
                    if !decodes_back(&frame, &data, &dict.bytes, false) {
                        problems.add(format!("{what}: does not decode back"));
                    }
                    compared += 1;
                    attached += usize::from(attaches(
                        pledged.or(whole.then_some(len)),
                        dict.bytes.len(),
                        for_level,
                        pref.0,
                    ));
                }
            }
        }
    }
    eprintln!("{compared} frames compared, {attached} attached");
    assert!(attached > 400, "only {attached} frames attached");
    problems.check();
}
