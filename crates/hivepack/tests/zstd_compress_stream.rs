//! Streams data through the port's `compress_stream2` and libzstd 1.5.7's
//! `ZSTD_compressStream2`, with the same parameters, cut into the same
//! pieces, with the same directives and the same room for output, and
//! compares every call: what it returns, how far it reads and writes, and
//! what it writes. Contexts are used for several frames, with parameters
//! changed between them (and tried while streaming), and dictionaries
//! loaded, referenced as `CDict`s or prefixes, changed between them too.
//! Then `compress2`. After each call, `ZSTD_getFrameProgression` too.
//!
//! The data has repeats near and far, and the windows are small: the input
//! buffer wraps around, and matches reach into the window's older segment.
//!
//! The `zstd` crate does not let the input buffer be stable, nor set the
//! block splitter level; the oracle tests those (`src/oracle_compress.rs`).

#![allow(clippy::expect_used, clippy::panic)]

#[path = "zstd_support/mod.rs"]
mod support;

use std::sync::Arc;

use hivepack::zstd::{
    CCtx, CDict, CParameter as P, DCtx, DictAttachPref, EndDirective, Format, FrameProgression,
    ParamSwitch, ResetDirective, Strategy,
};
use support::{Problems, Rng};
use zstd::zstd_safe::{self, CParameter as C, FrameFormat, zstd_sys::ZSTD_EndDirective};

/// Calls more than this for one frame mean no progress.
const MAX_CALLS: usize = 200_000;

/// Room past the end of the room libzstd's output buffers are given: with a
/// target size for compressed blocks and little room, libzstd's superblocks
/// write past it (see `tests/compress_target.rs`).
const SLACK: usize = 1 << 18;

/// Data with repeats near and far: text-like pieces, and copies of larger
/// pieces from anywhere before.
fn data(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len + 70_000);
    while data.len() < len {
        match rng.range(0, 5) {
            0 if data.len() > 1024 => {
                let size = rng.range(16, 65_536).min(data.len() as u64 / 2) as usize;
                let at = rng.range(0, (data.len() - size) as u64) as usize;
                data.extend_from_within(at..at + size);
            }
            1 => {
                let byte = rng.next() as u8;
                let n = rng.range(1, 300) as usize;
                data.resize(data.len() + n, byte);
            }
            2 => {
                for _ in 0..rng.range(1, 2000) {
                    data.push(rng.next() as u8);
                }
            }
            _ => {
                let n = rng.range(100, 5000) as usize;
                data.extend(rng.data(n, &[]));
            }
        }
    }
    data.truncate(len);
    data
}

/// A random piece size: mostly small ones, sometimes blocks.
fn piece(rng: &mut Rng) -> usize {
    let size = match rng.range(0, 4) {
        0 => rng.range(0, 8),
        1 => rng.range(1, 300),
        2 => rng.range(1, 20_000),
        _ => rng.range(1, 2 * 131_075),
    };
    size as usize
}

/// Random parameters, the same for both; some out of bounds.
fn parameters(rng: &mut Rng) -> Vec<(P, C)> {
    let mut list = Vec::new();
    let level = [
        -7, -3, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13, 15, 16, 17, 18, 19, 20, 22,
    ][rng.range(0, 21) as usize];
    list.push((P::CompressionLevel(level), C::CompressionLevel(level)));
    if rng.chance(2) {
        let value = rng.range(9, 20) as u32;
        list.push((P::WindowLog(value), C::WindowLog(value)));
    }
    if rng.chance(3) {
        let value = rng.range(5, 20) as u32;
        list.push((P::HashLog(value), C::HashLog(value)));
    }
    if rng.chance(3) {
        let value = rng.range(5, 20) as u32;
        list.push((P::ChainLog(value), C::ChainLog(value)));
    }
    if rng.chance(4) {
        let value = rng.range(0, 8) as u32;
        list.push((P::SearchLog(value), C::SearchLog(value)));
    }
    if rng.chance(3) {
        // Often 3, for the optimal parser's 3-byte hash table.
        let value = if rng.chance(2) {
            3
        } else {
            rng.range(2, 8) as u32
        };
        list.push((P::MinMatch(value), C::MinMatch(value)));
    }
    if rng.chance(4) {
        let value = [0, 1, 7, 100, 4096, 131_072, 131_073][rng.range(0, 6) as usize];
        list.push((P::TargetLength(value), C::TargetLength(value)));
    }
    if rng.chance(3) {
        use zstd_safe::Strategy as S;
        let (p, c) = [
            (Strategy::Fast, S::ZSTD_fast),
            (Strategy::Dfast, S::ZSTD_dfast),
            (Strategy::Greedy, S::ZSTD_greedy),
            (Strategy::Lazy, S::ZSTD_lazy),
            (Strategy::Lazy2, S::ZSTD_lazy2),
            (Strategy::Btlazy2, S::ZSTD_btlazy2),
            (Strategy::Btopt, S::ZSTD_btopt),
            (Strategy::Btultra, S::ZSTD_btultra),
            (Strategy::Btultra2, S::ZSTD_btultra2),
        ][rng.range(0, 8) as usize];
        list.push((P::Strategy(Some(p)), C::Strategy(c)));
    }
    // The block splitter after the sequences, which the optimal parser's
    // strategies use with windows of 128 KB or more: the port refuses it
    // for now, so mostly off.
    if !rng.chance(8) {
        let (p, c) = if rng.chance(8) {
            (ParamSwitch::Auto, zstd_safe::ParamSwitch::Auto)
        } else {
            (ParamSwitch::Disable, zstd_safe::ParamSwitch::Disable)
        };
        list.push((P::SplitAfterSequences(p), C::UseBlockSplitter(c)));
    }
    if rng.chance(2) {
        let (p, c) = match rng.range(0, 2) {
            0 => (ParamSwitch::Auto, zstd_safe::ParamSwitch::Auto),
            1 => (ParamSwitch::Enable, zstd_safe::ParamSwitch::Enable),
            _ => (ParamSwitch::Disable, zstd_safe::ParamSwitch::Disable),
        };
        list.push((P::UseRowMatchFinder(p), C::UseRowMatchFinder(c)));
    }
    if rng.chance(2) {
        // The block splitter after the sequences; `Auto` is off below
        // btopt.
        let (p, c) = match rng.range(0, 2) {
            0 => (ParamSwitch::Auto, zstd_safe::ParamSwitch::Auto),
            1 => (ParamSwitch::Enable, zstd_safe::ParamSwitch::Enable),
            _ => (ParamSwitch::Disable, zstd_safe::ParamSwitch::Disable),
        };
        list.push((P::SplitAfterSequences(p), C::UseBlockSplitter(c)));
    }
    if rng.chance(2) {
        let flag = rng.chance(2);
        list.push((P::ChecksumFlag(flag), C::ChecksumFlag(flag)));
    }
    if rng.chance(4) {
        let flag = rng.chance(2);
        list.push((P::ContentSizeFlag(flag), C::ContentSizeFlag(flag)));
    }
    if rng.chance(4) {
        let flag = rng.chance(2);
        list.push((P::DictIdFlag(flag), C::DictIdFlag(flag)));
    }
    if rng.chance(6) {
        let (p, c) = if rng.chance(2) {
            (Format::Zstd1Magicless, FrameFormat::Magicless)
        } else {
            (Format::Zstd1, FrameFormat::One)
        };
        list.push((P::Format(p), C::Format(c)));
    }
    if rng.chance(4) {
        let (p, c) = match rng.range(0, 2) {
            0 => (ParamSwitch::Auto, zstd_safe::ParamSwitch::Auto),
            1 => (ParamSwitch::Enable, zstd_safe::ParamSwitch::Enable),
            _ => (ParamSwitch::Disable, zstd_safe::ParamSwitch::Disable),
        };
        list.push((P::LiteralCompressionMode(p), C::LiteralCompressionMode(c)));
    }
    if rng.chance(5) {
        let value = rng.range(0, 1 << 20) as u32;
        list.push((P::SrcSizeHint(value), C::SrcSizeHint(value)));
    }
    if rng.chance(4) {
        let value = [0, 1000, 1024, 5000, 65_536, 131_072, 131_073][rng.range(0, 6) as usize];
        list.push((P::MaxBlockSize(value), C::MaxBlockSize(value)));
    }
    if rng.chance(5) {
        // A target size for compressed blocks, some below the smallest
        // (raised to it) and above the largest (refused), or none.
        let value = [0, 1, 1340, 1500, 4096, 20_000, 131_072, 131_073][rng.range(0, 7) as usize];
        list.push((P::TargetCBlockSize(value), C::TargetCBlockSize(value)));
    }
    if rng.chance(3) {
        // Long distance matching, with small parameters, so that it finds
        // matches in these inputs, some of them out of bounds. zstd-safe
        // sets it on (1) or to 0, auto in libzstd, which is off below btopt.
        let on = !rng.chance(4);
        let p = if on {
            ParamSwitch::Enable
        } else {
            ParamSwitch::Auto
        };
        list.push((
            P::EnableLongDistanceMatching(p),
            C::EnableLongDistanceMatching(on),
        ));
        if rng.chance(2) {
            let value = rng.range(3, 100) as u32;
            list.push((P::LdmMinMatch(value), C::LdmMinMatch(value)));
        }
        if rng.chance(2) {
            let value = rng.range(0, 4) as u32;
            list.push((P::LdmHashRateLog(value), C::LdmHashRateLog(value)));
        }
        if rng.chance(3) {
            let value = rng.range(5, 20) as u32;
            list.push((P::LdmHashLog(value), C::LdmHashLog(value)));
        }
        if rng.chance(3) {
            let value = rng.range(0, 9) as u32;
            list.push((P::LdmBucketSizeLog(value), C::LdmBucketSizeLog(value)));
        }
        // A small window: the input buffer then wraps around, and matches
        // reach into the window's older segment. Without one set, long
        // distance matching takes 2^27 bytes, and its hash table, from a
        // small hash rate log, up to 2^26 entries.
        let value = rng.range(10, 20) as u32;
        list.push((P::WindowLog(value), C::WindowLog(value)));
    }
    // On big-endian machines libzstd's block splitter, which the strategies
    // from `greedy` up use on full blocks, hashes pairs of bytes in the
    // machine's order and splits elsewhere; the port gives the same frames
    // everywhere. There `fast` or `dfast` instead.
    if cfg!(target_endian = "big") {
        let (p, c) = if rng.chance(2) {
            (Strategy::Fast, zstd_safe::Strategy::ZSTD_fast)
        } else {
            (Strategy::Dfast, zstd_safe::Strategy::ZSTD_dfast)
        };
        list.push((P::Strategy(Some(p)), C::Strategy(c)));
    }
    list
}

fn name(code: usize) -> String {
    zstd_safe::get_error_name(code).to_string()
}

fn message(error: hivepack::zstd::Error) -> String {
    error.code().message().to_string()
}

/// Sets the same parameter on both; they must agree on whether it works.
fn set_both(c: &mut zstd_safe::CCtx<'_>, p: &mut CCtx, (pp, cp): (P, C)) -> Result<(), String> {
    let want = c.set_parameter(cp).map(|_| ()).map_err(name);
    let got = p.set_parameter(pp).map_err(message);
    if want != got {
        return Err(format!("setting {pp:?}: libzstd {want:?}, port {got:?}"));
    }
    Ok(())
}

/// How a frame ended.
enum Ended {
    /// Complete, with the frame.
    Frame(Vec<u8>),
    /// Both failed the same way.
    Failed,
    /// The port refused the frame as it started: none should be.
    Refused,
}

/// `ZSTD_getFrameProgression` on both: without workers, the same at every
/// step.
fn same_progression(c: &zstd_safe::CCtx<'_>, p: &CCtx) -> Result<(), String> {
    let fp = c.get_frame_progression();
    let want = FrameProgression {
        ingested: fp.ingested,
        consumed: fp.consumed,
        produced: fp.produced,
        flushed: fp.flushed,
        current_job_id: fp.currentJobID,
        nb_active_workers: fp.nbActiveWorkers,
    };
    let got = p.get_frame_progression();
    if want != got {
        return Err(format!("frame progression: libzstd {want:?}, port {got:?}"));
    }
    if p.to_flush_now() != 0 {
        return Err(format!("{} to flush now without workers", p.to_flush_now()));
    }
    Ok(())
}

/// One frame of `data` through both contexts, in the same calls.
#[allow(clippy::too_many_lines)]
fn stream_frame(
    c: &mut zstd_safe::CCtx<'_>,
    p: &mut CCtx,
    data: &[u8],
    rng: &mut Rng,
    stable_out: bool,
) -> Result<Ended, String> {
    let mut frame = Vec::new();
    // With a stable output buffer, one buffer for the whole frame, its room
    // the same at each call.
    let stable_room = if rng.chance(8) {
        rng.range(0, 64) as usize
    } else {
        hivepack::zstd::compress_bound(data.len()).expect("a bound") + 32
    };
    let (mut c_stable, mut p_stable) = if stable_out {
        (vec![0u8; stable_room + SLACK], vec![0u8; stable_room])
    } else {
        (Vec::new(), Vec::new())
    };
    let mut stable_pos = 0;
    let mut taken = 0;
    for call in 0..MAX_CALLS {
        // The input: from where the last call stopped, sometimes in a slice
        // that starts before it.
        let in_end = (taken + piece(rng)).min(data.len());
        let back = if rng.chance(4) {
            rng.range(0, taken.min(16) as u64) as usize
        } else {
            0
        };
        let src = &data[taken - back..in_end];
        let all_given = in_end == data.len();
        let directive = if all_given && !rng.chance(4) {
            EndDirective::End
        } else if rng.chance(8) {
            EndDirective::Flush
        } else {
            EndDirective::Continue
        };
        // The helpers, sometimes: ZSTD_compressStream for Continue, and
        // ZSTD_flushStream and ZSTD_endStream when no input is left.
        let helper = rng.chance(4) && (directive == EndDirective::Continue || src.len() == back);

        // The output.
        let (mut c_fresh, mut p_fresh, out_pos) = if stable_out {
            (Vec::new(), Vec::new(), stable_pos)
        } else {
            let lead = if rng.chance(4) {
                rng.range(0, 8) as usize
            } else {
                0
            };
            let room = piece(rng);
            (vec![0u8; lead + room], vec![0u8; lead + room], lead)
        };
        let (c_dst, p_dst) = if stable_out {
            (&mut c_stable[..stable_room], &mut p_stable[..])
        } else {
            (&mut c_fresh[..], &mut p_fresh[..])
        };

        let (want, ci, co) = {
            let mut output = zstd_safe::OutBuffer::around_pos(&mut *c_dst, out_pos);
            let mut input = zstd_safe::InBuffer::around(src);
            input.set_pos(back);
            let result = match (directive, helper) {
                (EndDirective::Continue, true) => c.compress_stream(&mut output, &mut input),
                (EndDirective::Flush, true) => c.flush_stream(&mut output),
                (EndDirective::End, true) => c.end_stream(&mut output),
                (EndDirective::Continue, false) => {
                    c.compress_stream2(&mut output, &mut input, ZSTD_EndDirective::ZSTD_e_continue)
                }
                (EndDirective::Flush, false) => {
                    c.compress_stream2(&mut output, &mut input, ZSTD_EndDirective::ZSTD_e_flush)
                }
                (EndDirective::End, false) => {
                    c.compress_stream2(&mut output, &mut input, ZSTD_EndDirective::ZSTD_e_end)
                }
            };
            (result.map_err(name), input.pos(), output.pos())
        };
        let (got, pi, po) = {
            let mut output = hivepack::zstd::OutBuffer {
                dst: &mut *p_dst,
                pos: out_pos,
            };
            let mut input = hivepack::zstd::InBuffer { src, pos: back };
            let result = match (directive, helper) {
                (EndDirective::Continue, true) => p.compress_stream(&mut output, &mut input),
                (EndDirective::Flush, true) => p.flush_stream(&mut output),
                (EndDirective::End, true) => p.end_stream(&mut output),
                (directive, false) => p.compress_stream2(&mut output, &mut input, directive),
            };
            (result, input.pos, output.pos)
        };
        if call == 0
            && got
                .as_ref()
                .is_err_and(|error| error.code() == hivepack::zstd::ErrorCode::ParameterUnsupported)
        {
            return Ok(Ended::Refused);
        }
        let got = got.map_err(message);

        if (&want, ci, co) != (&got, pi, po) {
            return Err(format!(
                "call {call} ({directive:?}{}, input {taken}..{in_end} from {back}, output from \
                 {out_pos} of {}): libzstd {want:?} read to {ci} wrote to {co}, port {got:?} read \
                 to {pi} wrote to {po}",
                if helper { " helper" } else { "" },
                c_dst.len()
            ));
        }
        if c_dst[out_pos..co] != p_dst[out_pos..po] {
            let at = (out_pos..co)
                .find(|&i| c_dst[i] != p_dst[i])
                .unwrap_or(out_pos);
            return Err(format!(
                "call {call} ({directive:?}): the output differs at byte {at}"
            ));
        }
        same_progression(c, p)
            .map_err(|problem| format!("call {call} ({directive:?}): {problem}"))?;
        frame.extend_from_slice(&c_dst[out_pos..co]);
        if stable_out {
            stable_pos = co;
        }
        taken = taken - back + ci;
        match want {
            Err(_) => return Ok(Ended::Failed),
            Ok(0) if directive == EndDirective::End => return Ok(Ended::Frame(frame)),
            Ok(_) => {}
        }
    }
    Err(format!("no end after {MAX_CALLS} calls"))
}

/// Dictionaries for the streaming comparisons: pieces of a corpus, raw
/// content, and zstd dictionaries libzstd trains on it; the frames' data
/// is drawn from it too. With `CDict`s of them, made by both.
struct Dicts {
    corpus: Vec<u8>,
    dicts: Vec<Vec<u8>>,
    c_cdicts: Vec<zstd_safe::CDict<'static>>,
    p_cdicts: Vec<Arc<CDict>>,
}

impl Dicts {
    fn new(rng: &mut Rng) -> Self {
        let corpus = data(rng, 400_000);
        let mut dicts = Vec::new();
        for _ in 0..4 {
            if let Some(dict) = rng.trained_dict(&corpus) {
                dicts.push(dict);
            }
        }
        for len in [8, 1000, 20_000, 70_000] {
            let at = rng.range(0, (corpus.len() - len) as u64) as usize;
            dicts.push(corpus[at..at + len].to_vec());
        }
        let mut c_cdicts = Vec::new();
        let mut p_cdicts = Vec::new();
        // On big-endian machines, CDicts of `fast` and `dfast` only, levels
        // up to 3 (level 4 is `greedy` for dictionaries of up to 16 KB): a
        // frame that attaches one takes its strategy over the one
        // `parameters` sets there, and libzstd's block splitter of `greedy`
        // and up hashes pairs of bytes in the machine's order.
        let levels = if cfg!(target_endian = "big") {
            [1, 3, 2, 3, -2, 1, 0, 2]
        } else {
            [1, 3, 5, 19, -2, 9, 0, 16]
        };
        for (i, dict) in dicts.iter().enumerate() {
            let level = levels[i % 8];
            c_cdicts.push(zstd_safe::CDict::create(dict, level));
            p_cdicts.push(Arc::new(CDict::new(dict, level).expect("a CDict")));
        }
        Dicts {
            corpus,
            dicts,
            c_cdicts,
            p_cdicts,
        }
    }

    /// Data with pieces of the corpus, and of its own.
    fn data(&self, rng: &mut Rng, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 70_000);
        while out.len() < len {
            if rng.chance(2) {
                let n = rng.range(10, 5000) as usize;
                let at = rng.range(0, (self.corpus.len() - n) as u64) as usize;
                out.extend_from_slice(&self.corpus[at..at + n]);
            } else {
                let n = rng.range(10, 20_000) as usize;
                out.extend(data(rng, n));
            }
        }
        out.truncate(len);
        out
    }
}

/// The dictionary the frames of a context use, as the decoder needs it.
#[derive(Clone, Copy)]
enum Active<'a> {
    None,
    Dict(&'a [u8]),
    Prefix(&'a [u8]),
}

/// Contexts used for several frames, compared call by call; with `dicts`,
/// a dictionary loaded, a `CDict` referenced or a prefix for some frames,
/// changed between them. Returns the frames compared; the frames the port
/// refuses go to `refused`.
#[allow(clippy::too_many_lines)]
fn compare_contexts(
    problems: &mut Problems,
    seed: u64,
    dicts: Option<&Dicts>,
    refused: &mut usize,
) -> usize {
    let mut rng = Rng(seed);
    let mut c = zstd_safe::CCtx::create();
    let mut p = CCtx::new();
    let mut frames = 0;
    let mut active = Active::None;
    for round in 0..rng.range(1, 4) {
        let tag = format!("seed {seed}, frame {round}");
        if rng.chance(4) {
            let reset = if rng.chance(2) {
                (
                    ResetDirective::SessionAndParameters,
                    zstd_safe::ResetDirective::SessionAndParameters,
                )
            } else {
                (
                    ResetDirective::Parameters,
                    zstd_safe::ResetDirective::Parameters,
                )
            };
            let want = c.reset(reset.1).map(|_| ()).map_err(name);
            let got = p.reset(reset.0).map_err(message);
            if want != got {
                problems.add(format!("{tag}: resetting: libzstd {want:?}, port {got:?}"));
                return frames;
            }
            // Resetting the parameters drops the dictionaries.
            active = Active::None;
        }
        for parameter in parameters(&mut rng) {
            if let Err(problem) = set_both(&mut c, &mut p, parameter) {
                problems.add(format!("{tag}: {problem}"));
                return frames;
            }
        }
        let stable_out = rng.chance(4);
        if let Err(problem) = set_both(
            &mut c,
            &mut p,
            (
                P::StableOutBuffer(stable_out),
                C::StableOutBuffer(stable_out),
            ),
        ) {
            problems.add(format!("{tag}: {problem}"));
            return frames;
        }
        if let Some(dicts) = dicts {
            // Mostly copied in or loaded again: the port does not attach a
            // CDict yet.
            let (pp, cp) = match rng.range(0, 9) {
                0 => (
                    DictAttachPref::DefaultAttach,
                    zstd_safe::DictAttachPref::DefaultAttach,
                ),
                1 => (
                    DictAttachPref::ForceAttach,
                    zstd_safe::DictAttachPref::ForceAttach,
                ),
                2..=5 => (
                    DictAttachPref::ForceCopy,
                    zstd_safe::DictAttachPref::ForceCopy,
                ),
                _ => (
                    DictAttachPref::ForceLoad,
                    zstd_safe::DictAttachPref::ForceLoad,
                ),
            };
            if let Err(problem) = set_both(
                &mut c,
                &mut p,
                (P::ForceAttachDict(pp), C::ForceAttachDict(cp)),
            ) {
                problems.add(format!("{tag}: {problem}"));
                return frames;
            }
            // A dictionary for this frame and the next, a prefix for this
            // one, or as before.
            if round == 0 || rng.chance(2) {
                let i = rng.range(0, dicts.dicts.len() as u64 - 1) as usize;
                let dict = &dicts.dicts[i];
                let (want, got) = match rng.range(0, 4) {
                    0 => {
                        active = Active::Dict(dict);
                        (
                            c.load_dictionary(dict).map(|_| ()).map_err(name),
                            p.load_dictionary(dict).map_err(message),
                        )
                    }
                    1 | 2 => {
                        active = Active::Dict(dict);
                        (
                            c.ref_cdict(&dicts.c_cdicts[i]).map(|_| ()).map_err(name),
                            p.ref_cdict(Some(dicts.p_cdicts[i].clone()))
                                .map_err(message),
                        )
                    }
                    3 => {
                        active = Active::Prefix(dict);
                        (
                            c.ref_prefix(dict).map(|_| ()).map_err(name),
                            p.ref_prefix(dict).map_err(message),
                        )
                    }
                    _ => {
                        active = Active::None;
                        (
                            c.disable_dictionary().map(|_| ()).map_err(name),
                            p.load_dictionary(&[]).map_err(message),
                        )
                    }
                };
                if want != got {
                    problems.add(format!(
                        "{tag}: setting the dictionary: libzstd {want:?}, port {got:?}"
                    ));
                    return frames;
                }
            }
        }

        let len = match rng.range(0, 5) {
            0 => rng.range(0, 300),
            1 | 2 => rng.range(0, 150_000),
            3 => rng.range(100_000, 600_000),
            _ => rng.range(0, 1_500_000),
        } as usize;
        let content = match dicts {
            Some(dicts) => dicts.data(&mut rng, len),
            None => data(&mut rng, len),
        };
        if rng.chance(4) {
            // A pledged size, sometimes wrong.
            let size = match rng.range(0, 4) {
                0 => len as u64 + 1,
                1 => (len as u64).saturating_sub(1),
                _ => len as u64,
            };
            let want = c.set_pledged_src_size(Some(size)).map(|_| ()).map_err(name);
            let got = p.set_pledged_src_size(size).map_err(message);
            if want != got {
                problems.add(format!("{tag}: pledging: libzstd {want:?}, port {got:?}"));
                return frames;
            }
        }

        let frame_dict = active;
        if let Active::Prefix(_) = active {
            // For this frame only.
            active = Active::None;
        }
        match stream_frame(&mut c, &mut p, &content, &mut rng, stable_out) {
            Err(problem) => {
                problems.add(format!(
                    "{tag} ({len} bytes, stable output {stable_out}): {problem}"
                ));
                return frames;
            }
            Ok(ended @ (Ended::Failed | Ended::Refused)) => {
                if let Ended::Refused = ended {
                    *refused += 1;
                }
                // libzstd's context waits for a reset after an error; the
                // port's after refusing, and libzstd's frame was started.
                c.reset(zstd_safe::ResetDirective::SessionOnly)
                    .expect("libzstd resets");
                p.reset(ResetDirective::SessionOnly).expect("port resets");
                if let (Ended::Failed, Err(problem)) = (ended, same_progression(&c, &p)) {
                    problems.add(format!("{tag}: after the reset, {problem}"));
                    return frames;
                }
            }
            Ok(Ended::Frame(frame)) => {
                frames += 1;
                // libzstd decodes it, and so does the port, but magicless.
                if p.get_parameter(hivepack::zstd::CParameterKind::Format) == 0 {
                    let mut back = vec![0u8; content.len()];
                    let mut dctx = DCtx::new();
                    let decoded = match frame_dict {
                        Active::None => dctx.decompress(&mut back, &frame),
                        Active::Dict(dict) => dctx.decompress_using_dict(&mut back, &frame, dict),
                        Active::Prefix(prefix) => dctx
                            .ref_prefix(prefix)
                            .and_then(|()| dctx.decompress(&mut back, &frame)),
                    };
                    match decoded {
                        Ok(size) if back[..size] == content[..] => {}
                        other => problems
                            .add(format!("{tag}: the frame does not decode back: {other:?}")),
                    }
                }
            }
        }
        // A parameter set while no frame is open, or right after one.
        if rng.chance(3) {
            let parameter = if rng.chance(2) {
                (P::CompressionLevel(2), C::CompressionLevel(2))
            } else {
                (P::WindowLog(12), C::WindowLog(12))
            };
            if let Err(problem) = set_both(&mut c, &mut p, parameter) {
                problems.add(format!("{tag}: after the frame, {problem}"));
                return frames;
            }
        }
    }
    frames
}

#[test]
fn streaming_compresses_as_libzstd_does() {
    let mut problems = Problems::default();
    let mut frames = 0;
    let mut refused = 0;
    for seed in 0..150 {
        frames += compare_contexts(&mut problems, seed, None, &mut refused);
    }
    assert_eq!(refused, 0, "frames refused without a dictionary");
    println!("{frames} frames compared");
    assert!(frames > 150, "too few frames compared: {frames}");
    problems.check();
}

/// As [`streaming_compresses_as_libzstd_does`], with dictionaries: loaded,
/// referenced as `CDict`s, prefixes, mostly copied in or loaded again. The
/// frames that would attach a `CDict` (with the default preference, small
/// or of unknown size) the port refuses for now: they are counted apart.
#[test]
fn streaming_with_dictionaries_compresses_as_libzstd_does() {
    let mut problems = Problems::default();
    let dicts = Dicts::new(&mut Rng(0xD1C7));
    let mut frames = 0;
    let mut refused = 0;
    for seed in 0..150 {
        frames += compare_contexts(&mut problems, 1_000_000 + seed, Some(&dicts), &mut refused);
    }
    println!("{frames} frames compared, {refused} refused");
    assert!(frames > 150, "too few frames compared: {frames}");
    // The port attaches every CDict libzstd attaches.
    assert_eq!(refused, 0, "{refused} frames refused");
    problems.check();
}

/// A parameter refused while a frame is open, and the level accepted, for
/// the next frame.
#[test]
fn parameters_set_while_streaming_wait_for_the_next_frame() {
    let mut problems = Problems::default();
    let mut rng = Rng(7);
    let content = data(&mut rng, 400_000);
    let mut c = zstd_safe::CCtx::create();
    let mut p = CCtx::new();
    for (pp, cp) in [
        (P::CompressionLevel(1), C::CompressionLevel(1)),
        (P::WindowLog(14), C::WindowLog(14)),
    ] {
        set_both(&mut c, &mut p, (pp, cp)).expect("both set it");
    }
    let mut c_out = vec![0u8; 1 << 20];
    let mut p_out = vec![0u8; 1 << 20];
    let mut c_output = zstd_safe::OutBuffer::around(&mut c_out[..]);
    let mut c_input = zstd_safe::InBuffer::around(&content[..1000]);
    c.compress_stream2(
        &mut c_output,
        &mut c_input,
        ZSTD_EndDirective::ZSTD_e_continue,
    )
    .expect("libzstd takes it");
    let mut p_output = hivepack::zstd::OutBuffer::new(&mut p_out);
    let mut p_input = hivepack::zstd::InBuffer::new(&content[..1000]);
    p.compress_stream2(&mut p_output, &mut p_input, EndDirective::Continue)
        .expect("the port takes it");
    for parameter in [
        (P::CompressionLevel(3), C::CompressionLevel(3)),
        (P::HashLog(12), C::HashLog(12)),
        (P::WindowLog(20), C::WindowLog(20)),
        (P::ChecksumFlag(true), C::ChecksumFlag(true)),
        (
            P::Strategy(Some(Strategy::Fast)),
            C::Strategy(zstd_safe::Strategy::ZSTD_fast),
        ),
    ] {
        if let Err(problem) = set_both(&mut c, &mut p, parameter) {
            problems.add(problem);
        }
    }
    problems.check();
}

/// `compress2`, with random parameters and sometimes too little room.
#[test]
fn compress2_compresses_as_libzstd_does() {
    let mut problems = Problems::default();
    let mut compared = 0;
    for seed in 0..200 {
        let mut rng = Rng(1000 + seed);
        let mut c = zstd_safe::CCtx::create();
        let mut p = CCtx::new();
        let mut ok = true;
        for parameter in parameters(&mut rng) {
            if let Err(problem) = set_both(&mut c, &mut p, parameter) {
                problems.add(format!("seed {seed}: {problem}"));
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }
        for _ in 0..2 {
            let len = rng.range(0, 400_000) as usize;
            let content = data(&mut rng, len);
            let bound = hivepack::zstd::compress_bound(len).expect("a bound");
            let room = if rng.chance(5) {
                rng.range(0, bound as u64) as usize
            } else {
                bound
            };
            let mut c_out = vec![0u8; room + SLACK];
            let mut p_out = vec![0u8; room];
            let want = c.compress2(&mut c_out[..room], &content).map_err(name);
            let got = p.compress2(&mut p_out, &content).map_err(message);
            if want != got {
                problems.add(format!(
                    "seed {seed}, {len} bytes into {room}: libzstd {want:?}, port {got:?}"
                ));
                break;
            }
            if let Err(problem) = same_progression(&c, &p) {
                problems.add(format!("seed {seed}, {len} bytes, compress2: {problem}"));
                break;
            }
            if let Ok(size) = want {
                compared += 1;
                if c_out[..size] != p_out[..size] {
                    problems.add(format!("seed {seed}, {len} bytes: the frames differ"));
                    break;
                }
            }
            // libzstd's context waits for a reset after an error.
            c.reset(zstd_safe::ResetDirective::SessionOnly)
                .expect("libzstd resets");
        }
    }
    assert!(compared > 150, "too few frames compared: {compared}");
    problems.check();
}

/// More than 4 GiB in one frame, past `ZSTD_CURRENT_MAX` (3.5 GB), where
/// both lower the window's indices for real; compared call by call. The
/// last frame has long distance matching, whose window lowers its own
/// indices. Slow: run it in release, by hand.
#[test]
#[ignore = "streams 4.5 GiB; run with --release"]
fn streams_past_4_gib_as_libzstd_does() {
    const ROUNDS: usize = 72;
    let mut rng = Rng(99);
    let base = data(&mut rng, 64 << 20);
    for (level, window_log, ldm) in [(1, 0, false), (3, 12, false), (2, 20, true)] {
        let mut c = zstd_safe::CCtx::create();
        let mut p = CCtx::new();
        let mut parameters = vec![
            (P::CompressionLevel(level), C::CompressionLevel(level)),
            (P::WindowLog(window_log), C::WindowLog(window_log)),
        ];
        if ldm {
            parameters.extend([
                (
                    P::EnableLongDistanceMatching(ParamSwitch::Enable),
                    C::EnableLongDistanceMatching(true),
                ),
                (P::LdmMinMatch(16), C::LdmMinMatch(16)),
                (P::LdmHashRateLog(4), C::LdmHashRateLog(4)),
            ]);
        }
        for parameter in parameters {
            set_both(&mut c, &mut p, parameter).expect("both set it");
        }
        let mut c_out = vec![0u8; hivepack::zstd::cstream_out_size()];
        let mut p_out = vec![0u8; hivepack::zstd::cstream_out_size()];
        let mut written = 0u64;
        for round in 0..=ROUNDS {
            let last = round == ROUNDS;
            let src: &[u8] = if last { &[] } else { &base };
            let directive = if last {
                EndDirective::End
            } else {
                EndDirective::Continue
            };
            let c_directive = if last {
                ZSTD_EndDirective::ZSTD_e_end
            } else {
                ZSTD_EndDirective::ZSTD_e_continue
            };
            let mut taken = 0;
            loop {
                let end = (taken + (1 << 20)).min(src.len());
                let (want, ci, co) = {
                    let mut output = zstd_safe::OutBuffer::around(&mut c_out[..]);
                    let mut input = zstd_safe::InBuffer::around(&src[taken..end]);
                    let result = c.compress_stream2(&mut output, &mut input, c_directive);
                    (result.map_err(name), input.pos(), output.pos())
                };
                let (got, pi, po) = {
                    let mut output = hivepack::zstd::OutBuffer::new(&mut p_out);
                    let mut input = hivepack::zstd::InBuffer::new(&src[taken..end]);
                    let result = p.compress_stream2(&mut output, &mut input, directive);
                    (result.map_err(message), input.pos, output.pos)
                };
                assert_eq!(
                    (&want, ci, co),
                    (&got, pi, po),
                    "level {level}, round {round}, at {taken}, after {written} bytes out"
                );
                assert!(
                    c_out[..co] == p_out[..po],
                    "level {level}: the output differs"
                );
                written += co as u64;
                taken += ci;
                let done = if last {
                    want == Ok(0)
                } else {
                    taken == src.len() && want.is_ok()
                };
                if done {
                    break;
                }
            }
        }
        println!(
            "level {level}, long distance matching {ldm}: {written} bytes for {} GiB",
            ROUNDS as f64 / 16.0
        );
    }
}
