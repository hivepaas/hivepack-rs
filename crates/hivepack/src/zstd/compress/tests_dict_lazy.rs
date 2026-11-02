//! Frames that attach a `CDict` of `greedy`, `lazy` or `lazy2`
//! (`ZSTD_resetCCtx_byAttachingCDict`, then the `dictMatchState` and
//! `dedicatedDictSearch` block compressors, with the hash chain or the row
//! match finder) against libzstd's, byte for byte, and decoded back with
//! the port's decoder.
//!
//! Through the `zstd` crate: `ZSTD_compress_usingCDict` with `CDict`s made
//! for the levels of those strategies; and on contexts used for many
//! frames, `ZSTD_compress2` and streaming (of a pledged size or not) with a
//! `CDict` referenced or a dictionary loaded, whose `CDict` the context
//! makes with its parameters: the strategy set, the row match finder on,
//! off or left to the window, `ZSTD_c_enableDedicatedDictSearch`, each
//! preference to attach, small windows the dictionary goes out of, other
//! table sizes. Through the oracle: `CDict`s made from parameters
//! (`ZSTD_createCDict_advanced2`), which the `zstd` crate cannot make,
//! with the dedicated dictionary search too.
//!
//! The dictionaries are raw content of sizes on both sides of the tables'
//! and the cutoffs, and zstd dictionaries libzstd trains; the inputs have
//! runs from the dictionary, so that the frames find matches there, and
//! repcodes, through its end into the input too.

use std::sync::Arc;

use crate::zstd::compress::zstd_cdict::CDict;
use crate::zstd::compress::zstd_compress::{CCtx, CParameter, EndDirective, zstd_compress_bound};
use crate::zstd::compress::zstd_compress_internal::{DictAttachPref, ParamSwitch, Strategy};
use crate::zstd::compress::zstd_lazy::DICT_MATCH_STATE_BLOCKS;
use crate::zstd::decompress::zstd_decompress::{InBuffer, OutBuffer};
use crate::zstd::decompress::zstd_decompress_internal::DCtx;
use crate::zstd::oracle::{Oracle, Rng, hex, list};
use crate::zstd::oracle_compress::answer;
use zstd::zstd_safe::{self, zstd_sys::ZSTD_EndDirective};

/// A parameter for both: the port's, and libzstd's.
type Both = (CParameter, zstd_safe::CParameter);

/// The blocks compressed so far in this thread with a lazy `CDict`
/// attached: with the hash chain, the row match finder, the dedicated
/// dictionary search.
fn attached_blocks() -> [usize; 3] {
    DICT_MATCH_STATE_BLOCKS.with(std::cell::Cell::get)
}

/// The blocks of each kind since `before`.
fn attached_since(before: [usize; 3]) -> [usize; 3] {
    let now = attached_blocks();
    [now[0] - before[0], now[1] - before[1], now[2] - before[2]]
}

fn is_lazy(strategy: Strategy) -> bool {
    matches!(
        strategy,
        Strategy::Greedy | Strategy::Lazy | Strategy::Lazy2
    )
}

/// On big-endian machines libzstd's block splitter, which these strategies
/// use on full blocks, hashes bytes in the machine's order (see
/// `tests.rs`): those frames are left out there.
fn big_endian_skip(len: usize) -> bool {
    cfg!(target_endian = "big") && len >= 128 << 10
}

/// How much to do: less in debug builds, where the parsers are slow.
fn rounds(release: usize) -> usize {
    if cfg!(debug_assertions) {
        release / 5
    } else {
        release
    }
}

fn strategy_pair(strategy: Strategy) -> Both {
    let c = match strategy {
        Strategy::Greedy => zstd_safe::Strategy::ZSTD_greedy,
        Strategy::Lazy => zstd_safe::Strategy::ZSTD_lazy,
        _ => zstd_safe::Strategy::ZSTD_lazy2,
    };
    (
        CParameter::Strategy(Some(strategy)),
        zstd_safe::CParameter::Strategy(c),
    )
}

fn row_pair(mode: ParamSwitch) -> Both {
    let c = match mode {
        ParamSwitch::Auto => zstd_safe::ParamSwitch::Auto,
        ParamSwitch::Enable => zstd_safe::ParamSwitch::Enable,
        ParamSwitch::Disable => zstd_safe::ParamSwitch::Disable,
    };
    (
        CParameter::UseRowMatchFinder(mode),
        zstd_safe::CParameter::UseRowMatchFinder(c),
    )
}

fn attach_pair(pref: DictAttachPref) -> Both {
    let c = match pref {
        DictAttachPref::DefaultAttach => zstd_safe::DictAttachPref::DefaultAttach,
        DictAttachPref::ForceAttach => zstd_safe::DictAttachPref::ForceAttach,
        DictAttachPref::ForceCopy => zstd_safe::DictAttachPref::ForceCopy,
        DictAttachPref::ForceLoad => zstd_safe::DictAttachPref::ForceLoad,
    };
    (
        CParameter::ForceAttachDict(pref),
        zstd_safe::CParameter::ForceAttachDict(c),
    )
}

/// A dictionary drawn from `base`: raw content of a size on either side
/// of the cutoffs and of the tables' sizes, or a zstd dictionary libzstd
/// trains on it.
fn dictionary(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    if rng.range(0, 3) == 0 {
        let size = rng.range(100, 2000) as usize;
        let samples: Vec<&[u8]> = base[..base.len().min(300_000)].chunks(size).collect();
        let capacity = [2 << 10, 8 << 10, 30 << 10][rng.range(0, 2) as usize];
        if let Ok(dict) = zstd::dict::from_samples(&samples, capacity) {
            return dict;
        }
    }
    let len = [
        8, 9, 64, 1000, 4000, 15_000, 16_500, 40_000, 130_000, 300_000,
    ][rng.range(0, 9) as usize]
        .min(base.len());
    let at = rng.range(0, (base.len() - len) as u64) as usize;
    base[at..at + len].to_vec()
}

/// Data the dictionary helps with: runs copied from it, some with a byte
/// changed, among stretches of `base` and repeats of its own.
fn dict_data(rng: &mut Rng, dict: &[u8], base: &[u8], len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len + 3000);
    while data.len() < len {
        match rng.range(0, 4) {
            0 | 1 if dict.len() >= 8 => {
                let n = (rng.range(4, 3000) as usize).min(dict.len());
                let at = rng.range(0, (dict.len() - n) as u64) as usize;
                data.extend_from_slice(&dict[at..at + n]);
                if rng.range(0, 2) == 0 {
                    let i = data.len() - 1 - rng.range(0, n as u64 - 1) as usize;
                    data[i] = rng.next() as u8;
                }
            }
            2 => {
                let n = (rng.range(1, 3000) as usize).min(base.len());
                let at = rng.range(0, (base.len() - n) as u64) as usize;
                data.extend_from_slice(&base[at..at + n]);
            }
            3 if data.len() >= 8 => {
                let n = (rng.range(4, 500) as usize).min(data.len());
                let at = rng.range(0, (data.len() - n) as u64) as usize;
                data.extend_from_within(at..at + n);
            }
            _ => {
                let n = rng.range(1, 20) as usize;
                data.extend(rng.bytes(n));
            }
        }
    }
    data.truncate(len);
    data
}

/// An input size: mostly up to the cutoff of 32 KB under which a frame
/// attaches the `CDict` of these strategies, some just past it, some of
/// several blocks.
fn input_len(rng: &mut Rng) -> usize {
    match rng.range(0, 9) {
        0 => rng.range(0, 64) as usize,
        1 => [8191, 16_385, 32_767, 32_768, 32_769][rng.range(0, 4) as usize],
        2 => rng.range(
            40_000,
            if cfg!(debug_assertions) {
                200_000
            } else {
                600_000
            },
        ) as usize,
        _ => rng.range(64, 32_768) as usize,
    }
}

/// Whether `frame` decodes back to `src` with `dict`.
fn decodes_back(frame: &[u8], src: &[u8], dict: &[u8]) -> bool {
    let mut back = vec![0u8; src.len()];
    matches!(
        DCtx::new().decompress_using_dict(&mut back, frame, dict),
        Ok(n) if n == src.len() && back == src
    )
}

/// What differs between libzstd's frame and the port's, if anything.
fn compare(
    want: Result<Vec<u8>, String>,
    got: Result<Vec<u8>, String>,
    src: &[u8],
    dict: &[u8],
) -> Option<String> {
    match (want, got) {
        (Ok(want), Ok(got)) if want == got => {
            (!decodes_back(&got, src, dict)).then(|| "does not decode back".to_string())
        }
        (Ok(want), Ok(got)) => {
            let at = want
                .iter()
                .zip(&got)
                .position(|(a, b)| a != b)
                .unwrap_or(want.len().min(got.len()));
            Some(format!(
                "{} bytes, libzstd {}, first difference at {at}",
                got.len(),
                want.len()
            ))
        }
        (want, got) => Some(format!("libzstd {want:?}, port {got:?}")),
    }
}

/// `ZSTD_compress_usingCDict` at the levels of greedy, lazy and lazy2,
/// with `CDict`s made for them, on one context each: the inputs up to
/// 32 KB attach them, with the hash chain for the dictionaries the window
/// keeps under 16 KB, the row match finder for larger ones.
#[test]
fn one_call_with_attached_lazy_cdicts_matches_libzstd() {
    let mut rng = Rng::new(0x5EED_D150);
    let mut problems = Vec::new();
    let mut frames = 0;
    let before = attached_blocks();
    let mut p = CCtx::new();
    let mut c = zstd_safe::CCtx::create();
    for _ in 0..rounds(400) {
        let base_len = rng.range(50_000, 400_000) as usize;
        let base = rng.lz_data(base_len);
        let dict = dictionary(&mut rng, &base);
        let level = rng.range(4, 12) as i32;
        let p_cdict = match CDict::new(&dict, level) {
            Ok(cdict) => cdict,
            Err(error) => {
                problems.push(format!("{} bytes, level {level}: {error:?}", dict.len()));
                continue;
            }
        };
        if !is_lazy(p_cdict.c_params().strategy) {
            continue;
        }
        let c_cdict = zstd_safe::CDict::create(&dict, level);
        for _ in 0..4 {
            let len = input_len(&mut rng);
            if big_endian_skip(len) {
                continue;
            }
            let src = dict_data(&mut rng, &dict, &base, len);
            let bound = zstd_compress_bound(len).expect("a bound");
            let mut want = vec![0u8; bound];
            let mut got = vec![0u8; bound];
            let w = c
                .compress_using_cdict(&mut want[..], &src, &c_cdict)
                .map(|n| want[..n].to_vec())
                .map_err(|code| zstd_safe::get_error_name(code).to_string());
            let g = p
                .compress_using_cdict(&mut got, &src, &p_cdict)
                .map(|n| got[..n].to_vec())
                .map_err(|error| format!("{error:?}"));
            if let Some(problem) = compare(w, g, &src, &dict) {
                problems.push(format!(
                    "a dictionary of {} bytes, level {level} ({:?}), {len} bytes: {problem}",
                    dict.len(),
                    p_cdict.c_params().strategy
                ));
            }
            frames += 1;
        }
    }
    let attached = attached_since(before);
    eprintln!("{frames} frames, blocks attached (hash chain, row, dedicated): {attached:?}");
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(frames > rounds(800), "only {frames} frames");
    assert!(
        attached[0] > rounds(150),
        "only {attached:?} blocks attached"
    );
    assert!(
        attached[1] > rounds(150),
        "only {attached:?} blocks attached"
    );
}

/// `data` through `compress_stream2` of the port, in pieces drawn from
/// `seed`, as one frame.
fn stream_port(cctx: &mut CCtx, data: &[u8], seed: u64) -> Result<Vec<u8>, String> {
    let mut rng = Rng::new(seed);
    let mut frame = Vec::new();
    let mut piece = vec![0u8; 1 << 17];
    let mut taken = 0;
    for _ in 0..1_000_000 {
        let end = (taken + rng.range(1, 70_000) as usize).min(data.len());
        let directive = if end == data.len() {
            EndDirective::End
        } else if rng.range(0, 9) == 0 {
            EndDirective::Flush
        } else {
            EndDirective::Continue
        };
        let room = rng.range(1, piece.len() as u64) as usize;
        let mut output = OutBuffer::new(&mut piece[..room]);
        let mut input = InBuffer::new(&data[taken..end]);
        let remaining = cctx
            .compress_stream2(&mut output, &mut input, directive)
            .map_err(|error| format!("{error:?}"))?;
        taken += input.pos;
        let written = output.pos;
        frame.extend_from_slice(&piece[..written]);
        if directive == EndDirective::End && remaining == 0 {
            return Ok(frame);
        }
    }
    Err("no end".into())
}

/// [`stream_port`] through libzstd's, in the same pieces.
fn stream_libzstd(
    cctx: &mut zstd_safe::CCtx<'_>,
    data: &[u8],
    seed: u64,
) -> Result<Vec<u8>, String> {
    let mut rng = Rng::new(seed);
    let mut frame = Vec::new();
    let mut piece = vec![0u8; 1 << 17];
    let mut taken = 0;
    for _ in 0..1_000_000 {
        let end = (taken + rng.range(1, 70_000) as usize).min(data.len());
        let directive = if end == data.len() {
            ZSTD_EndDirective::ZSTD_e_end
        } else if rng.range(0, 9) == 0 {
            ZSTD_EndDirective::ZSTD_e_flush
        } else {
            ZSTD_EndDirective::ZSTD_e_continue
        };
        let room = rng.range(1, piece.len() as u64) as usize;
        let mut output = zstd_safe::OutBuffer::around(&mut piece[..room]);
        let mut input = zstd_safe::InBuffer::around(&data[taken..end]);
        let remaining = cctx
            .compress_stream2(&mut output, &mut input, directive)
            .map_err(|code| zstd_safe::get_error_name(code).to_string())?;
        taken += input.pos();
        let written = output.pos();
        frame.extend_from_slice(&piece[..written]);
        if directive == ZSTD_EndDirective::ZSTD_e_end && remaining == 0 {
            return Ok(frame);
        }
    }
    Err("no end".into())
}

/// Two contexts, libzstd's and the port's, used for many frames: in one
/// call (`ZSTD_compress2`) or streamed, of a pledged size or not, with a
/// `CDict` made for a lazy level referenced, or a dictionary loaded, whose
/// `CDict` the context makes with its parameters at the first frame: a
/// lazy strategy, the row match finder on, off or left to the window, the
/// dedicated dictionary search or not, other table sizes and shortest
/// matches; each preference to attach (a `CDict` with the dedicated search
/// is always attached, unless loaded again), small windows the dictionary
/// goes out of, and parameters reset between frames.
#[test]
#[allow(clippy::too_many_lines)]
fn contexts_with_attached_lazy_cdicts_match_libzstd() {
    let mut rng = Rng::new(0x5EED_D151);
    let base = rng.lz_data(700_000);
    let dicts: Vec<Vec<u8>> = (0..12).map(|_| dictionary(&mut rng, &base)).collect();
    // CDicts made for a lazy level, by both; before libzstd's context,
    // which must not outlive them.
    let mut cdicts = Vec::new();
    for (i, dict) in dicts.iter().enumerate() {
        for _ in 0..4 {
            let level = rng.range(4, 12) as i32;
            let cdict = CDict::new(dict, level).expect("a CDict");
            if is_lazy(cdict.c_params().strategy) {
                cdicts.push((
                    i,
                    level,
                    Arc::new(cdict),
                    zstd_safe::CDict::create(dict, level),
                ));
            }
        }
    }
    assert!(cdicts.len() > 10, "only {} CDicts", cdicts.len());

    let mut problems = Vec::new();
    let mut frames = 0;
    let mut attached_frames = [0usize; 3];
    let before = attached_blocks();
    let mut c = zstd_safe::CCtx::create();
    let mut p = CCtx::new();
    let mut current: Option<usize> = None;
    for round in 0..rounds(2500) {
        let mut set = |(pp, cp): Both, c: &mut zstd_safe::CCtx<'_>, p: &mut CCtx| {
            let want = c
                .set_parameter(cp)
                .map(|_| ())
                .map_err(zstd_safe::get_error_name);
            let got = p.set_parameter(pp).map_err(|error| error.code().message());
            if want != got {
                problems.push(format!(
                    "round {round}: setting {pp:?}: libzstd {want:?}, port {got:?}"
                ));
            }
        };
        if rng.range(0, 5) == 0 {
            // Back to the defaults, without a dictionary.
            c.reset(zstd_safe::ResetDirective::SessionAndParameters)
                .expect("libzstd resets");
            p.reset(crate::zstd::ResetDirective::SessionAndParameters)
                .expect("the port resets");
            current = None;
        }
        let strategy =
            [Strategy::Greedy, Strategy::Lazy, Strategy::Lazy2][rng.range(0, 2) as usize];
        let level = rng.range(1, 12) as i32;
        let mut parameters = vec![
            (
                CParameter::CompressionLevel(level),
                zstd_safe::CParameter::CompressionLevel(level),
            ),
            strategy_pair(strategy),
            row_pair(
                [ParamSwitch::Auto, ParamSwitch::Enable, ParamSwitch::Disable]
                    [rng.range(0, 2) as usize],
            ),
        ];
        let dds = rng.range(0, 1) == 0;
        parameters.push((
            CParameter::EnableDedicatedDictSearch(dds),
            zstd_safe::CParameter::EnableDedicatedDictSearch(dds),
        ));
        parameters.push(attach_pair(match rng.range(0, 9) {
            0..=3 => DictAttachPref::DefaultAttach,
            4..=6 => DictAttachPref::ForceAttach,
            7 => DictAttachPref::ForceCopy,
            _ => DictAttachPref::ForceLoad,
        }));
        if rng.range(0, 3) == 0 {
            // Small windows: the dictionary goes out of reach.
            let window_log = rng.range(10, 17) as u32;
            parameters.push((
                CParameter::WindowLog(window_log),
                zstd_safe::CParameter::WindowLog(window_log),
            ));
        }
        for (make, low, high) in [
            (
                (|v| (CParameter::HashLog(v), zstd_safe::CParameter::HashLog(v)))
                    as fn(u32) -> Both,
                6,
                20,
            ),
            (
                |v| (CParameter::ChainLog(v), zstd_safe::CParameter::ChainLog(v)),
                6,
                20,
            ),
            (
                |v| {
                    (
                        CParameter::SearchLog(v),
                        zstd_safe::CParameter::SearchLog(v),
                    )
                },
                1,
                9,
            ),
            (
                |v| (CParameter::MinMatch(v), zstd_safe::CParameter::MinMatch(v)),
                3,
                7,
            ),
            (
                |v| {
                    (
                        CParameter::TargetLength(v),
                        zstd_safe::CParameter::TargetLength(v),
                    )
                },
                0,
                300,
            ),
        ] {
            if rng.range(0, 5) == 0 {
                parameters.push(make(rng.range(low, high) as u32));
            }
        }
        let checksum = rng.range(0, 3) == 0;
        parameters.push((
            CParameter::ChecksumFlag(checksum),
            zstd_safe::CParameter::ChecksumFlag(checksum),
        ));
        // Long distance matching, sometimes: it calls the block compressor
        // between its matches, on pieces of the block. Small, so that it
        // finds some; with its window under those above.
        let ldm = rng.range(0, 5) == 0;
        parameters.push((
            CParameter::EnableLongDistanceMatching(if ldm {
                ParamSwitch::Enable
            } else {
                ParamSwitch::Disable
            }),
            zstd_safe::CParameter::EnableLongDistanceMatching(ldm),
        ));
        if ldm {
            parameters.push((
                CParameter::LdmMinMatch(16),
                zstd_safe::CParameter::LdmMinMatch(16),
            ));
            parameters.push((
                CParameter::LdmHashRateLog(4),
                zstd_safe::CParameter::LdmHashRateLog(4),
            ));
            let window_log = rng.range(10, 20) as u32;
            parameters.push((
                CParameter::WindowLog(window_log),
                zstd_safe::CParameter::WindowLog(window_log),
            ));
        }
        for parameter in parameters {
            set(parameter, &mut c, &mut p);
        }

        // The dictionary, when it changes: a CDict referenced, or a
        // dictionary loaded, which keeps its CDict, made at the next frame.
        if current.is_none() || rng.range(0, 2) == 0 {
            if rng.range(0, 1) == 0 {
                let k = rng.range(0, cdicts.len() as u64 - 1) as usize;
                let (_, _, p_cdict, c_cdict) = &cdicts[k];
                c.ref_cdict(c_cdict).expect("libzstd takes it");
                p.ref_cdict(Some(p_cdict.clone()))
                    .expect("the port takes it");
                current = Some(cdicts[k].0);
            } else {
                let i = rng.range(0, dicts.len() as u64 - 1) as usize;
                c.load_dictionary(&dicts[i]).expect("libzstd loads it");
                p.load_dictionary(&dicts[i]).expect("the port loads it");
                current = Some(i);
            }
        }
        let Some(i) = current else { unreachable!() };
        let dict = &dicts[i];

        let len = input_len(&mut rng);
        if big_endian_skip(len) {
            continue;
        }
        let src = dict_data(&mut rng, dict, &base, len);
        let blocks = attached_blocks();
        let how = rng.range(0, 2);
        let (want, got) = match how {
            0 => {
                let bound = zstd_compress_bound(len).expect("a bound");
                let mut want = vec![0u8; bound];
                let mut got = vec![0u8; bound];
                (
                    c.compress2(&mut want[..], &src)
                        .map(|n| want[..n].to_vec())
                        .map_err(|code| zstd_safe::get_error_name(code).to_string()),
                    p.compress2(&mut got, &src)
                        .map(|n| got[..n].to_vec())
                        .map_err(|error| format!("{error:?}")),
                )
            }
            _ => {
                if how == 2 {
                    // A pledged size: the frame attaches as in one call.
                    c.set_pledged_src_size(Some(len as u64))
                        .expect("libzstd takes it");
                    p.set_pledged_src_size(len as u64)
                        .expect("the port takes it");
                }
                let seed = rng.next();
                (
                    stream_libzstd(&mut c, &src, seed),
                    stream_port(&mut p, &src, seed),
                )
            }
        };
        let failed = want.is_err() || got.is_err();
        if let Some(problem) = compare(want, got, &src, dict) {
            problems.push(format!(
                "round {round}: a dictionary of {} bytes, {strategy:?}, dedicated search {dds}, \
                 {len} bytes, {}: {problem}",
                dict.len(),
                ["one call", "streamed", "streamed, pledged"][how as usize]
            ));
        }
        if failed {
            c.reset(zstd_safe::ResetDirective::SessionOnly)
                .expect("libzstd resets");
            p.reset(crate::zstd::ResetDirective::SessionOnly)
                .expect("the port resets");
        }
        let attached = attached_since(blocks);
        for kind in 0..3 {
            attached_frames[kind] += usize::from(attached[kind] > 0);
        }
        frames += 1;
    }
    let attached = attached_since(before);
    eprintln!(
        "{frames} frames, attached (hash chain, row, dedicated): {attached_frames:?} frames, \
         {attached:?} blocks"
    );
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    for kind in 0..3 {
        assert!(
            attached_frames[kind] > rounds(150),
            "only {attached_frames:?} frames attached"
        );
    }
}

/// `CDict`s made from parameters (`ZSTD_createCDict_advanced2` with the
/// context's, the oracle's step 17), with the dedicated dictionary search
/// or not, a lazy strategy, the row match finder on, off or left to the
/// window, other table sizes; and dictionaries loaded with the same
/// parameters (step 11): frames that attach them, streamed or in one
/// call, several on the context, against the oracle's.
#[test]
fn attached_cdicts_made_from_parameters_match_libzstd() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng::new(0x5EED_D152);
    let mut problems = Vec::new();
    let before = attached_blocks();
    let mut requests = 0;
    for _ in 0..rounds(500) {
        let base_len = rng.range(20_000, 300_000) as usize;
        let base = rng.lz_data(base_len);
        let dict = dictionary(&mut rng, &base);
        let mut steps: Vec<i64> = Vec::new();
        steps.extend([7, 100, rng.range(1, 15) as i64]);
        steps.extend([7, 107, rng.range(3, 5) as i64]);
        steps.extend([7, 1011, rng.range(0, 2) as i64]);
        steps.extend([7, 1005, i64::from(rng.range(0, 3) != 0)]);
        for (number, low, high) in [
            (101, 10, 20),
            (102, 6, 22),
            (103, 6, 24),
            (104, 1, 9),
            (105, 3, 7),
            (106, 0, 300),
        ] {
            if rng.range(0, 4) == 0 {
                steps.extend([7, number, rng.range(low, high) as i64]);
            }
        }
        if rng.range(0, 3) == 0 {
            // A dictionary loaded: its CDict, made at the first frame.
            steps.extend([11, 0, dict.len() as i64]);
        } else {
            // A CDict made now, as auto, raw content or a zstd dictionary.
            steps.extend([17, dict.len() as i64, rng.range(0, 1) as i64]);
        }
        let mut src = Vec::new();
        let mut capacity = 0;
        for _ in 0..rng.range(1, 3) {
            // Each frame: the preference to attach, maybe the level and the
            // window, maybe a pledged size; then streamed or in one call.
            steps.extend([7, 1001, [0, 0, 1, 1, 2, 3][rng.range(0, 5) as usize]]);
            if rng.range(0, 2) == 0 {
                steps.extend([7, 100, rng.range(1, 15) as i64]);
            }
            if rng.range(0, 3) == 0 {
                steps.extend([7, 101, rng.range(10, 18) as i64]);
            }
            let len = input_len(&mut rng).min(250_000);
            if big_endian_skip(len) {
                continue;
            }
            src.extend(dict_data(&mut rng, &dict, &base, len));
            let room = zstd_compress_bound(len).expect("a bound") as i64 + 64;
            capacity += room;
            if rng.range(0, 2) == 0 {
                steps.extend([6, len as i64, room]);
            } else {
                if rng.range(0, 1) == 0 {
                    steps.extend([9, len as i64, 0]);
                }
                let mut left = len as i64;
                while left > 0 && rng.range(0, 2) != 0 {
                    let piece = (rng.range(1, 40_000) as i64).min(left);
                    steps.extend([0, piece, room]);
                    left -= piece;
                }
                steps.extend([2, left, room]);
            }
        }
        let request = format!(
            "cstream {capacity} {} {} {}",
            list(&steps),
            hex(&src),
            hex(&dict)
        );
        let want = oracle.ask(&request);
        let got = answer(&request);
        if want != got {
            problems.push(format!(
                "{request:.300}\n  libzstd: {want:.300}\n  port:    {got:.300}"
            ));
        }
        requests += 1;
    }
    let attached = attached_since(before);
    eprintln!("{requests} requests, blocks attached (hash chain, row, dedicated): {attached:?}");
    assert!(
        problems.is_empty(),
        "{} differences:\n{}",
        problems.len(),
        problems[..problems.len().min(10)].join("\n")
    );
    for kind in 0..3 {
        assert!(
            attached[kind] > rounds(150),
            "only {attached:?} blocks attached"
        );
    }
}
