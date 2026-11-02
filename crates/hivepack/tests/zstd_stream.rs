//! Streams every file in the test data through the port's
//! `decompress_stream` and libzstd 1.5.7's `ZSTD_decompressStream`, cut
//! into the same pieces, and compares every call: what it returns, how far
//! it reads and writes, and what it writes. Then frames made to stress the
//! window the stream keeps: much longer than their window, so that the
//! decoder's buffer wraps around many times, with dictionaries, damaged.
//!
//! As in `tests/decompress.rs`, libzstd behaves as the port does only on
//! 64-bit little-endian machines; elsewhere only what it decodes is
//! compared.

#![allow(clippy::expect_used, clippy::panic)]

#[path = "zstd_support/mod.rs"]
mod support;

use std::path::Path;
use std::sync::Arc;

use support::{Kind, Pieces, Problems, Rng, Set, skippable_frame, stream_both};
use zstd::zstd_safe::{self, CParameter, DParameter, FrameFormat};

/// Whether libzstd here behaves as the port does everywhere.
const SAME_AS_LIBZSTD: bool = cfg!(all(target_pointer_width = "64", target_endian = "little"));

/// How much output to allow: what libzstd says the frames decode to, or a
/// bound on it, capped; the same for both sides.
fn capacity(src: &[u8]) -> usize {
    const CAP: u64 = 64 << 20;
    match zstd_safe::find_decompressed_size(src) {
        Ok(Some(size)) if size <= CAP => size as usize,
        _ => match zstd_safe::decompress_bound(src) {
            Ok(bound) if bound <= CAP => bound as usize,
            _ => 1 << 20,
        },
    }
}

/// The dictionary both sides use, if any.
#[derive(Clone, Copy)]
enum Dict<'a> {
    None,
    /// `ZSTD_DCtx_loadDictionary`
    Load(&'a [u8]),
    /// `ZSTD_DCtx_refDDict`
    Ref(&'a [u8]),
}

/// Two fresh contexts with `dict`, streaming `src` in `pieces`.
fn compare(problems: &mut Problems, name: &str, src: &[u8], dict: Dict<'_>, pieces: Pieces) {
    let c_ddict = match dict {
        Dict::Ref(dict) => Some(zstd_safe::DDict::create(dict)),
        _ => None,
    };
    let mut c = zstd_safe::DCtx::create();
    let mut p = hivepack::zstd::DCtx::new();
    match dict {
        Dict::None => {}
        Dict::Load(dict) => {
            c.load_dictionary(dict).expect("libzstd loads");
            if p.load_dictionary(dict).is_err() {
                problems.add(format!("{name}: the port does not load the dictionary"));
                return;
            }
        }
        Dict::Ref(dict) => {
            if let Some(c_ddict) = &c_ddict {
                c.ref_ddict(c_ddict).expect("libzstd references");
            }
            // A DDict libzstd cannot create is NULL, which means none.
            let ddict = hivepack::zstd::DDict::new(dict).ok().map(Arc::new);
            p.ref_ddict(ddict).expect("port references");
        }
    }
    let capacity = capacity(src);
    let raw = match dict {
        Dict::None => None,
        Dict::Load(dict) | Dict::Ref(dict) => Some(dict),
    };
    if !SAME_AS_LIBZSTD && !libzstd_decodes(src, raw, false, capacity) {
        // Only what libzstd decodes, and not how it fails.
        return;
    }
    if let Err(problem) = stream_both(&mut c, &mut p, src, capacity, pieces) {
        problems.add(format!("{name} ({pieces:?}): {problem}"));
    }
}

/// Whether libzstd decodes `src` in one call: elsewhere than on 64-bit
/// little-endian machines, only those inputs are compared.
fn libzstd_decodes(src: &[u8], dict: Option<&[u8]>, magicless: bool, capacity: usize) -> bool {
    let mut c = zstd_safe::DCtx::create();
    if magicless {
        c.set_parameter(DParameter::Format(FrameFormat::Magicless))
            .expect("format");
    }
    let mut out = Vec::with_capacity(capacity);
    match dict {
        Some(dict) => c.decompress_using_dict(&mut out, src, dict).is_ok(),
        None => c.decompress(&mut out, src).is_ok(),
    }
}

/// The ways each file is cut.
fn pieces_for(src: &[u8], seed: u64) -> Vec<Pieces> {
    let mut all = vec![
        Pieces::Whole,
        Pieces::Blocks,
        Pieces::Random(seed),
        Pieces::Random(seed ^ 0x5555),
        Pieces::Stable(seed),
    ];
    if src.len() <= 16 << 10 && capacity(src) <= 128 << 10 {
        all.push(Pieces::Bytes);
    }
    all
}

fn sets() -> Vec<Set> {
    support::manifest()
        .sets
        .into_iter()
        .filter(|set| set.present())
        .collect()
}

/// The files of a set that are inputs to decode.
fn decodable(set: &Set) -> Vec<std::path::PathBuf> {
    match set.kind {
        Kind::Frames | Kind::BadFrames | Kind::DictFrames => set.frames(),
        Kind::Fuzz => set.list(),
        _ => Vec::new(),
    }
}

#[test]
fn every_test_file_streams_as_libzstd_streams_it() {
    let mut problems = Problems::default();
    let mut count = 0;
    for set in sets() {
        let dictionaries: Vec<Vec<u8>> = match (&set.dictionary, set.kind) {
            (Some(dictionary), _) => vec![set.read(Path::new(dictionary))],
            (None, Kind::DictFrames) => set
                .list()
                .into_iter()
                .filter(|f| f.extension() == Some("dict".as_ref()))
                .map(|f| set.read(&f))
                .collect(),
            _ => Vec::new(),
        };
        for (n, file) in decodable(&set).into_iter().enumerate() {
            let src = set.read(&file);
            let name = format!("{}/{}", set.name, file.display());
            let seed = 0x5EED_0030 + n as u64;
            let wanted = hivepack::zstd::get_dict_id_from_frame(&src);
            let dictionary = dictionaries.iter().find(|d| {
                set.dictionary.is_some() || hivepack::zstd::get_dict_id_from_dict(d) == wanted
            });
            for pieces in pieces_for(&src, seed) {
                match dictionary {
                    None => compare(&mut problems, &name, &src, Dict::None, pieces),
                    Some(dictionary) => {
                        compare(&mut problems, &name, &src, Dict::Load(dictionary), pieces);
                        compare(&mut problems, &name, &src, Dict::Ref(dictionary), pieces);
                    }
                }
            }
            count += 1;
        }
    }
    eprintln!("streamed {count} files");
    assert!(count > 200);
    problems.check();
}

/// Frames much longer than their window, so that the stream's buffer wraps
/// around many times, from libzstd's compressor with random parameters:
/// several frames in a row, skippable frames between them, a dictionary or
/// not, and some damaged.
#[test]
fn long_frames_with_small_windows_stream_as_in_libzstd() {
    let mut rng = Rng(0x5EED_0040);
    let mut problems = Problems::default();
    let mut outcomes = std::collections::BTreeMap::<String, usize>::new();
    for case in 0..120 {
        let base = rng.data_between(2000, 20_000, &[]);
        let dict = match rng.range(0, 2) {
            0 => rng.trained_dict(&base),
            1 => Some(rng.raw_dict(&base)),
            _ => None,
        };
        let magicless = rng.chance(8);
        let window_log = rng.range(10, 17) as u32;
        let mut src = Vec::new();
        for _ in 0..rng.range(1, 3) {
            // Up to 40 windows long.
            let len = rng.range(0, 40 << window_log) as usize;
            let data = rng.data(len, &base);
            let mut cctx = zstd_safe::CCtx::create();
            let level = [-3, 1, 3, 6, 12, 19][rng.range(0, 5) as usize];
            let set = |cctx: &mut zstd_safe::CCtx<'_>, param| {
                cctx.set_parameter(param).expect("parameter")
            };
            set(&mut cctx, CParameter::CompressionLevel(level));
            set(&mut cctx, CParameter::WindowLog(window_log));
            set(&mut cctx, CParameter::ChecksumFlag(rng.chance(2)));
            set(&mut cctx, CParameter::ContentSizeFlag(!rng.chance(3)));
            if magicless {
                set(&mut cctx, CParameter::Format(FrameFormat::Magicless));
            }
            if let Some(dict) = &dict {
                cctx.load_dictionary(dict).expect("dictionary loads");
            }
            let mut frame = Vec::with_capacity(zstd_safe::compress_bound(data.len()));
            cctx.compress2(&mut frame, &data).expect("compresses");
            if !magicless && rng.chance(4) {
                src.extend_from_slice(&skippable_frame(
                    rng.range(0, 15) as u32,
                    &rng.data_between(0, 3000, &[]),
                ));
            }
            src.extend_from_slice(&frame);
        }
        match rng.range(0, 5) {
            0 => {
                for _ in 0..rng.range(1, 3) {
                    let at = rng.range(0, src.len() as u64 - 1) as usize;
                    src[at] ^= 1 << rng.range(0, 7);
                }
            }
            1 => src.truncate(rng.range(0, src.len() as u64 - 1) as usize),
            _ => {}
        }

        let pieces = match rng.range(0, 3) {
            0 => Pieces::Blocks,
            1 => Pieces::Stable(rng.next()),
            _ => Pieces::Random(rng.next()),
        };
        let mut c = zstd_safe::DCtx::create();
        let mut p = hivepack::zstd::DCtx::new();
        if magicless {
            c.set_parameter(DParameter::Format(FrameFormat::Magicless))
                .expect("format");
            p.set_parameter(hivepack::zstd::DParameter::Format(
                hivepack::zstd::Format::Zstd1Magicless,
            ))
            .expect("format");
        }
        if let Some(dict) = &dict {
            c.load_dictionary(dict).expect("libzstd loads");
            p.load_dictionary(dict).expect("port loads");
        }
        let capacity = capacity(&src);
        if !SAME_AS_LIBZSTD && !libzstd_decodes(&src, dict.as_deref(), magicless, capacity) {
            continue;
        }
        match stream_both(&mut c, &mut p, &src, capacity, pieces) {
            Ok(outcome) => {
                let kind = match outcome.split(" at ").next().unwrap_or_default() {
                    ok if ok.starts_with("ok") => "ok".to_string(),
                    other => other.to_string(),
                };
                *outcomes.entry(kind).or_default() += 1;
            }
            Err(problem) => problems.add(format!("case {case} ({pieces:?}): {problem}")),
        }
    }
    eprintln!("{outcomes:?}");
    problems.check();
}

/// Changing parameters or the dictionary is refused in the middle of a
/// frame, as in libzstd, and allowed again after a reset.
#[test]
fn settings_wait_for_the_end_of_the_frame_as_in_libzstd() {
    let mut rng = Rng(0x5EED_0050);
    let data = rng.data(300_000, &[]);
    let frame = zstd::bulk::compress(&data, 3).expect("compresses");
    let dict = rng.raw_dict(&data);
    let c_ddict = zstd_safe::DDict::create(&dict);
    let p_ddict = Arc::new(hivepack::zstd::DDict::new(&dict).expect("DDict"));

    let mut c = zstd_safe::DCtx::create();
    let mut p = hivepack::zstd::DCtx::new();
    // Into the frame: the header and part of the first block.
    let mut c_out = vec![0u8; 1000];
    let mut p_out = vec![0u8; 1000];
    let mut c_output = zstd_safe::OutBuffer::around(&mut c_out[..]);
    let mut c_input = zstd_safe::InBuffer::around(&frame[..100]);
    c.decompress_stream(&mut c_output, &mut c_input)
        .expect("libzstd streams");
    let mut p_output = hivepack::zstd::OutBuffer::new(&mut p_out);
    let mut p_input = hivepack::zstd::InBuffer::new(&frame[..100]);
    p.decompress_stream(&mut p_output, &mut p_input)
        .expect("port streams");

    let name = |r: Result<usize, usize>| r.map_err(zstd_safe::get_error_name);
    let port = |r: hivepack::zstd::Result<()>| r.map(|()| 0).map_err(|e| e.code().message());
    let mut seen = Vec::new();
    for _ in 0..2 {
        let pairs = [
            (
                name(c.set_parameter(DParameter::WindowLogMax(20))),
                port(p.set_parameter(hivepack::zstd::DParameter::WindowLogMax(20))),
            ),
            (
                name(c.load_dictionary(&dict)),
                port(p.load_dictionary(&dict)),
            ),
            (name(c.ref_prefix(&dict)), port(p.ref_prefix(&dict))),
            (
                name(c.ref_ddict(&c_ddict)),
                port(p.ref_ddict(Some(p_ddict.clone()))),
            ),
            (
                name(c.reset(zstd_safe::ResetDirective::Parameters)),
                port(p.reset(hivepack::zstd::ResetDirective::Parameters)),
            ),
        ];
        for (want, got) in pairs {
            assert_eq!(got, want);
            seen.push(got.is_ok());
        }
        // A new session: everything is allowed again.
        c.reset(zstd_safe::ResetDirective::SessionOnly)
            .expect("libzstd resets");
        p.reset(hivepack::zstd::ResetDirective::SessionOnly)
            .expect("port resets");
    }
    assert_eq!(
        seen,
        [
            false, false, false, false, false, true, true, true, true, true
        ]
    );
}

/// Calls in any order, with any inputs, never panic: streams cut short and
/// taken up again after errors, one-call decompression in the middle of a
/// stream, resets, parameters and dictionaries changed on the way. libzstd
/// is not compared here: some of these orders reach memory it has freed.
#[test]
fn any_order_of_calls_is_safe() {
    let mut rng = Rng(0x5EED_0060);
    let base = rng.data_between(5000, 20_000, &[]);
    let dicts: Vec<Vec<u8>> = (0..3)
        .filter_map(|i| {
            if i == 0 {
                rng.trained_dict(&base)
            } else {
                Some(rng.raw_dict(&base))
            }
        })
        .collect();
    let ddicts: Vec<Arc<hivepack::zstd::DDict>> = dicts
        .iter()
        .filter_map(|d| hivepack::zstd::DDict::new(d).ok().map(Arc::new))
        .collect();
    for _ in 0..60 {
        // A few frames, some with a dictionary, some damaged.
        let mut src = Vec::new();
        for _ in 0..rng.range(1, 3) {
            let data = rng.data_between(0, 400_000, &base);
            let mut cctx = zstd_safe::CCtx::create();
            cctx.set_parameter(CParameter::WindowLog(rng.range(10, 20) as u32))
                .expect("parameter");
            cctx.set_parameter(CParameter::ChecksumFlag(rng.chance(2)))
                .expect("parameter");
            if rng.chance(2) {
                let d = rng.range(0, dicts.len() as u64 - 1) as usize;
                cctx.load_dictionary(&dicts[d]).expect("dictionary loads");
            }
            let mut frame = Vec::with_capacity(zstd_safe::compress_bound(data.len()));
            cctx.compress2(&mut frame, &data).expect("compresses");
            if rng.chance(3) {
                let at = rng.range(0, frame.len() as u64 - 1) as usize;
                frame[at] ^= 1 << rng.range(0, 7);
            }
            src.extend_from_slice(&frame);
        }

        let mut p = hivepack::zstd::DCtx::new();
        let mut out = vec![0u8; 1 << 20];
        let (mut in_pos, mut out_pos) = (0usize, 0usize);
        for _ in 0..rng.range(1, 400) {
            match rng.range(0, 19) {
                0 => {
                    let _ = p.decompress(&mut out, &src);
                }
                1 => {
                    let _ = p.reset(hivepack::zstd::ResetDirective::SessionOnly);
                }
                2 => {
                    let _ = p.reset(hivepack::zstd::ResetDirective::SessionAndParameters);
                }
                3 => {
                    let stable = rng.chance(2);
                    let _ = p.set_parameter(hivepack::zstd::DParameter::StableOutBuffer(stable));
                }
                4 => {
                    let size = [0, 1024, 4096, 100_000][rng.range(0, 3) as usize];
                    let _ = p.set_parameter(hivepack::zstd::DParameter::MaxBlockSize(size));
                }
                5 => {
                    let log = rng.range(10, 27) as u32;
                    let _ = p.set_parameter(hivepack::zstd::DParameter::WindowLogMax(log));
                }
                6 => {
                    let d = rng.range(0, dicts.len() as u64 - 1) as usize;
                    let _ = p.load_dictionary(&dicts[d]);
                }
                7 => {
                    let d = rng.range(0, dicts.len() as u64 - 1) as usize;
                    let _ = p.ref_prefix(&dicts[d]);
                }
                8 => {
                    let ddict = (!ddicts.is_empty() && rng.chance(4))
                        .then(|| ddicts[rng.range(0, ddicts.len() as u64 - 1) as usize].clone());
                    let _ = p.ref_ddict(ddict);
                }
                9 => {
                    let multiple = rng.chance(2);
                    let _ =
                        p.set_parameter(hivepack::zstd::DParameter::RefMultipleDDicts(multiple));
                }
                10 => {
                    let _ = p.init_dstream();
                }
                11 if rng.chance(4) => {
                    // Move around in the input or output.
                    in_pos = rng.range(0, src.len() as u64) as usize;
                    out_pos = rng.range(0, out.len() as u64) as usize;
                }
                11 => {
                    // Start over.
                    let _ = p.reset(hivepack::zstd::ResetDirective::SessionOnly);
                    (in_pos, out_pos) = (0, 0);
                }
                _ => {
                    // Stream a piece, into a buffer of any size, sometimes
                    // another one.
                    let in_end = src.len().min(in_pos + rng.range(0, 70_000) as usize);
                    let out_end = out.len().min(out_pos + rng.range(0, 200_000) as usize);
                    let mut other = vec![0u8; out_end];
                    let dst = if rng.chance(10) {
                        &mut other[..]
                    } else {
                        &mut out[..out_end]
                    };
                    match p.decompress_stream_simple_args(
                        dst,
                        &mut out_pos,
                        &src[..in_end],
                        &mut in_pos,
                    ) {
                        Ok(0) if in_pos == src.len() => in_pos = 0,
                        Ok(_) => {}
                        Err(_) => {
                            // Usually start over; sometimes go on.
                            if !rng.chance(4) {
                                let _ = p.reset(hivepack::zstd::ResetDirective::SessionOnly);
                                (in_pos, out_pos) = (0, 0);
                            }
                        }
                    }
                    if out_pos == out.len() {
                        out_pos = 0;
                    }
                }
            }
        }
    }
}
