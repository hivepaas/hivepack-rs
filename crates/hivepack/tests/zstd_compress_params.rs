//! The parameters for dictionaries and prefixes: `ZSTD_c_forceMaxWindow`,
//! `ZSTD_c_deterministicRefPrefix` and `ZSTD_c_prefetchCDictTables`.
//! Frames through the port and libzstd 1.5.7, the same calls on both,
//! compared byte for byte and decoded back with the port: with a dictionary
//! loaded, a `CDict` referenced or a prefix, larger than the window or
//! not, in one call and streamed, several frames per context.
//!
//! A prefix that ends where the input starts in memory makes one segment
//! with it in libzstd, unless `deterministicRefPrefix` is on, and a segment
//! of its own in the port (see `docs/porting.md`): with the parameter on,
//! those frames are the same too.

#![allow(clippy::expect_used, clippy::panic)]

#[path = "zstd_support/mod.rs"]
mod support;

use std::sync::Arc;

use hivepack::zstd::{
    CCtx, CDict, CParameter as P, CParameterKind as K, DCtx, DictAttachPref, EndDirective,
    ErrorCode, InBuffer, OutBuffer, ParamSwitch,
};
use support::{Problems, Rng};
use zstd::zstd_safe::{self, CParameter as C, zstd_sys::ZSTD_EndDirective};

/// Levels of every strategy.
const LEVELS: [i32; 10] = [-3, 1, 3, 5, 7, 9, 12, 15, 17, 19];

/// Debug builds and emulated machines take fewer.
const ROUNDS: usize = if cfg!(debug_assertions) || cfg!(target_endian = "big") {
    60
} else {
    240
};

fn name(code: usize) -> String {
    zstd_safe::get_error_name(code).to_string()
}

fn message(error: hivepack::zstd::Error) -> String {
    error.code().message().to_string()
}

/// Bytes with repeats near and far, text-like, so that a dictionary drawn
/// from the same helps.
fn data(rng: &mut Rng, len: usize) -> Vec<u8> {
    const WORDS: [&[u8]; 8] = [
        b"window ",
        b"prefix ",
        b"dictionary ",
        b"segment ",
        b"match ",
        b"frame ",
        b"the ",
        b"zstd ",
    ];
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        match rng.range(0, 9) {
            0..=5 => out.extend_from_slice(WORDS[rng.range(0, 7) as usize]),
            6 if out.len() > 64 => {
                let back = rng.range(1, out.len().min(70_000) as u64) as usize;
                let at = out.len() - back;
                let n = (rng.range(4, 200) as usize).min(back);
                out.extend_from_within(at..at + n);
            }
            7 => out.push(rng.range(0, 255) as u8),
            _ => out.extend(std::iter::repeat_n(b'.', rng.range(1, 30) as usize)),
        }
    }
    out.truncate(len);
    out
}

/// How the dictionary is given.
#[derive(Clone, Copy, Debug)]
enum Way {
    /// `ZSTD_CCtx_loadDictionary`, its content raw.
    Loaded,
    /// `ZSTD_CCtx_refCDict`, a `CDict` made at a level.
    Cdict(i32),
    /// `ZSTD_CCtx_refPrefix`, the prefix in a buffer of its own.
    Prefix,
    /// `ZSTD_CCtx_refPrefix`, the prefix just before the input in one
    /// buffer, with `deterministicRefPrefix` on.
    PrefixBefore,
}

fn port_frame(
    p: &mut CCtx,
    cdict: Option<&Arc<CDict>>,
    way: Way,
    dict: &[u8],
    src: &[u8],
    pieces: usize,
) -> Result<Vec<u8>, String> {
    match way {
        Way::Loaded => p.load_dictionary(dict).map_err(message)?,
        Way::Cdict(_) => p.ref_cdict(cdict.cloned()).map_err(message)?,
        Way::Prefix | Way::PrefixBefore => p.ref_prefix(dict).map_err(message)?,
    }
    let mut out = vec![0u8; hivepack::zstd::compress_bound(src.len()).unwrap_or(0) + 64];
    if pieces <= 1 {
        let n = p.compress2(&mut out, src).map_err(message)?;
        out.truncate(n);
        return Ok(out);
    }
    let mut frame = Vec::new();
    let piece = src.len().div_ceil(pieces).max(1);
    let mut taken = 0;
    loop {
        let end = (taken + piece).min(src.len());
        let directive = if end == src.len() {
            EndDirective::End
        } else {
            EndDirective::Continue
        };
        let mut input = InBuffer::new(&src[taken..end]);
        let mut output = OutBuffer::new(&mut out);
        let remaining = p
            .compress_stream2(&mut output, &mut input, directive)
            .map_err(message)?;
        let written = output.pos;
        taken += input.pos;
        frame.extend_from_slice(&out[..written]);
        if directive == EndDirective::End && remaining == 0 && taken == src.len() {
            return Ok(frame);
        }
    }
}

fn libzstd_frame<'a>(
    c: &mut zstd_safe::CCtx<'a>,
    cdict: Option<&'a zstd_safe::CDict<'a>>,
    way: Way,
    dict: &'a [u8],
    src: &[u8],
    pieces: usize,
) -> Result<Vec<u8>, String> {
    match way {
        Way::Loaded => c.load_dictionary(dict).map_err(name)?,
        Way::Cdict(_) => c.ref_cdict(cdict.expect("a CDict")).map_err(name)?,
        Way::Prefix | Way::PrefixBefore => c.ref_prefix(dict).map_err(name)?,
    };
    let mut out = vec![0u8; zstd_safe::compress_bound(src.len()) + 64];
    if pieces <= 1 {
        let n = c.compress2(&mut out[..], src).map_err(name)?;
        out.truncate(n);
        return Ok(out);
    }
    let mut frame = Vec::new();
    let piece = src.len().div_ceil(pieces).max(1);
    let mut taken = 0;
    loop {
        let end = (taken + piece).min(src.len());
        let last = end == src.len();
        let directive = if last {
            ZSTD_EndDirective::ZSTD_e_end
        } else {
            ZSTD_EndDirective::ZSTD_e_continue
        };
        let mut input = zstd_safe::InBuffer::around(&src[taken..end]);
        let mut output = zstd_safe::OutBuffer::around(&mut out[..]);
        let remaining = c
            .compress_stream2(&mut output, &mut input, directive)
            .map_err(name)?;
        let written = output.pos();
        taken += input.pos;
        frame.extend_from_slice(&out[..written]);
        if last && remaining == 0 && taken == src.len() {
            return Ok(frame);
        }
    }
}

/// Frames at random parameters, dictionaries and ways, on both sides.
#[test]
fn frames_with_the_window_and_prefix_parameters_are_libzstds() {
    let mut rng = Rng(0x5EED_F0CE);
    let mut problems = Problems::default();
    let mut compared = 0;
    for round in 0..ROUNDS {
        let level = LEVELS[rng.range(0, LEVELS.len() as u64 - 1) as usize];
        let base = data(&mut rng, 300_000);
        let dict_len = rng.range(1, 70_000) as usize;
        let dict_at = rng.range(0, (base.len() - dict_len) as u64) as usize;
        let way = match rng.range(0, 3) {
            0 => Way::Loaded,
            1 => Way::Cdict([1, 3, 6, 12][rng.range(0, 3) as usize]),
            2 => Way::Prefix,
            _ => Way::PrefixBefore,
        };
        let window_log = rng.chance(2).then(|| rng.range(10, 18) as u32);
        let force_window = rng.chance(2);
        let deterministic = matches!(way, Way::PrefixBefore) || rng.chance(2);
        let prefetch = [ParamSwitch::Auto, ParamSwitch::Enable, ParamSwitch::Disable]
            [rng.range(0, 2) as usize];
        let attach = [
            DictAttachPref::DefaultAttach,
            DictAttachPref::ForceAttach,
            DictAttachPref::ForceCopy,
            DictAttachPref::ForceLoad,
        ][rng.range(0, 3) as usize];
        let frames = 1 + rng.range(0, 2) as usize;
        // Workers, a third of the time: streamed, the size unknown, they
        // take the frame, the jobs after the first loading their prefix as
        // part of the window.
        let workers = if rng.chance(3) { 2 } else { 0 };

        // The dictionary, and the buffer that holds it and the inputs:
        // for PrefixBefore, the prefix ends where each input starts.
        let dict = base[dict_at..dict_at + dict_len].to_vec();
        let lens: Vec<usize> = (0..frames)
            .map(|_| match rng.range(0, 3) {
                0 => rng.range(0, 2_000),
                1 => rng.range(2_000, 40_000),
                _ => rng.range(40_000, 127_000),
            } as usize)
            .collect();
        let inputs: Vec<Vec<u8>> = lens
            .iter()
            .map(|&len| {
                let at = rng.range(0, (base.len() - len) as u64) as usize;
                let mut input = dict.clone();
                input.extend_from_slice(&base[at..at + len]);
                input
            })
            .collect();
        let pieces = [1, 1, 3, 17][rng.range(0, 3) as usize];

        let p_cdict = match way {
            Way::Cdict(cdict_level) => {
                Some(Arc::new(CDict::new(&dict, cdict_level).expect("a CDict")))
            }
            _ => None,
        };
        let c_cdict = match way {
            Way::Cdict(cdict_level) => {
                Some(zstd_safe::CDict::try_create(&dict, cdict_level).expect("a CDict"))
            }
            _ => None,
        };
        let mut p = CCtx::new();
        let mut c = zstd_safe::CCtx::create();
        let mut set = |pp: P, cp: C| {
            let want = c.set_parameter(cp).map(|_| ()).map_err(name);
            let got = p.set_parameter(pp).map_err(message);
            if want != got {
                problems.add(format!(
                    "round {round}: setting {pp:?}: {want:?}, port {got:?}"
                ));
            }
        };
        set(P::CompressionLevel(level), C::CompressionLevel(level));
        if let Some(window_log) = window_log {
            set(P::WindowLog(window_log), C::WindowLog(window_log));
        }
        set(
            P::ForceMaxWindow(force_window),
            C::ForceMaxWindow(force_window),
        );
        set(
            P::DeterministicRefPrefix(deterministic),
            C::DeterministicRefPrefix(deterministic),
        );
        set(
            P::PrefetchCDictTables(prefetch),
            C::PrefetchCDictTables(match prefetch {
                ParamSwitch::Auto => zstd_safe::ParamSwitch::Auto,
                ParamSwitch::Enable => zstd_safe::ParamSwitch::Enable,
                ParamSwitch::Disable => zstd_safe::ParamSwitch::Disable,
            }),
        );
        set(
            P::ForceAttachDict(attach),
            C::ForceAttachDict(match attach {
                DictAttachPref::DefaultAttach => zstd_safe::DictAttachPref::DefaultAttach,
                DictAttachPref::ForceAttach => zstd_safe::DictAttachPref::ForceAttach,
                DictAttachPref::ForceCopy => zstd_safe::DictAttachPref::ForceCopy,
                DictAttachPref::ForceLoad => zstd_safe::DictAttachPref::ForceLoad,
            }),
        );
        set(P::ChecksumFlag(true), C::ChecksumFlag(true));
        set(P::NbWorkers(workers), C::NbWorkers(workers));

        for (n, input) in inputs.iter().enumerate() {
            let (c_dict, src) = match way {
                // The prefix just before the input, in the same buffer.
                Way::PrefixBefore => (&input[..dict_len], &input[dict_len..]),
                _ => (&dict[..], &input[dict_len..]),
            };
            let want = libzstd_frame(&mut c, c_cdict.as_ref(), way, c_dict, src, pieces);
            let got = port_frame(&mut p, p_cdict.as_ref(), way, &dict, src, pieces);
            let what = format!(
                "round {round}, frame {n}: level {level}, {way:?}, window log {window_log:?}, \
                 force window {force_window}, deterministic {deterministic}, {attach:?}, \
                 {workers} workers, {} bytes in {pieces} pieces",
                src.len()
            );
            match (want, got) {
                (Ok(want), Ok(got)) => {
                    compared += 1;
                    if want != got {
                        problems.add(format!("{what}: the frames differ"));
                        continue;
                    }
                    let mut back = vec![0u8; src.len()];
                    match DCtx::new().decompress_using_dict(&mut back, &got, &dict) {
                        Ok(size) if back[..size] == *src => {}
                        other => problems.add(format!("{what}: decodes to {other:?}")),
                    }
                }
                (want, got) => {
                    if want.as_ref().err() != got.as_ref().err() {
                        problems.add(format!(
                            "{what}: libzstd {:?}, port {:?}",
                            want.err(),
                            got.err()
                        ));
                    }
                }
            }
        }
    }
    assert!(compared > ROUNDS, "only {compared} frames compared");
    problems.check();
}

/// `ZSTD_c_forceMaxWindow` with a dictionary larger than the window: the
/// parts of it more than a window behind are not searched, so the frames
/// differ from those without, and are libzstd's.
#[test]
fn a_forced_window_leaves_a_large_dictionary_out_of_reach() {
    let mut rng = Rng(0xF0_4CED);
    let base = data(&mut rng, 200_000);
    let dict = base[..100_000].to_vec();
    // The input repeats the dictionary's start, out of a 16 KB window's
    // reach from it.
    let mut src = base[..20_000].to_vec();
    src.extend_from_slice(&base[150_000..170_000]);
    let mut frames = Vec::new();
    for force in [false, true] {
        let mut p = CCtx::new();
        let mut c = zstd_safe::CCtx::create();
        for (pp, cp) in [
            (P::CompressionLevel(3), C::CompressionLevel(3)),
            (P::WindowLog(14), C::WindowLog(14)),
            (P::ForceMaxWindow(force), C::ForceMaxWindow(force)),
        ] {
            c.set_parameter(cp).expect("libzstd sets it");
            p.set_parameter(pp).expect("the port sets it");
        }
        let want = libzstd_frame(&mut c, None, Way::Loaded, &dict, &src, 1).expect("libzstd");
        let got = port_frame(&mut p, None, Way::Loaded, &dict, &src, 1).expect("the port");
        assert!(want == got, "force window {force}: the frames differ");
        frames.push(got);
    }
    assert!(frames[0] != frames[1], "the forced window changes nothing");
    assert!(frames[1].len() > frames[0].len());
}

/// The three parameters' values, defaults and bounds, as libzstd's
/// `ZSTD_CCtx_getParameter` gives them; not while a frame is streamed.
#[test]
fn the_parameters_get_what_was_set() {
    let mut p = CCtx::new();
    for kind in [
        K::ForceMaxWindow,
        K::DeterministicRefPrefix,
        K::PrefetchCDictTables,
    ] {
        assert_eq!(p.get_parameter(kind), 0, "{kind:?} by default");
    }
    for (param, kind, value) in [
        (P::ForceMaxWindow(true), K::ForceMaxWindow, 1),
        (P::ForceMaxWindow(false), K::ForceMaxWindow, 0),
        (
            P::DeterministicRefPrefix(true),
            K::DeterministicRefPrefix,
            1,
        ),
        (
            P::DeterministicRefPrefix(false),
            K::DeterministicRefPrefix,
            0,
        ),
        (
            P::PrefetchCDictTables(ParamSwitch::Enable),
            K::PrefetchCDictTables,
            1,
        ),
        (
            P::PrefetchCDictTables(ParamSwitch::Disable),
            K::PrefetchCDictTables,
            2,
        ),
        (
            P::PrefetchCDictTables(ParamSwitch::Auto),
            K::PrefetchCDictTables,
            0,
        ),
    ] {
        p.set_parameter(param).expect("set");
        assert_eq!(p.get_parameter(kind), value, "{param:?}");
    }
    // While a frame is streamed, none can be set.
    let mut out = vec![0u8; 100];
    let mut output = OutBuffer::new(&mut out);
    let mut input = InBuffer::new(b"some input");
    p.compress_stream2(&mut output, &mut input, EndDirective::Continue)
        .expect("starts");
    for param in [
        P::ForceMaxWindow(true),
        P::DeterministicRefPrefix(true),
        P::PrefetchCDictTables(ParamSwitch::Enable),
    ] {
        let error = p.set_parameter(param).expect_err("refused");
        assert_eq!(error.code(), ErrorCode::StageWrong, "{param:?}");
    }
}
