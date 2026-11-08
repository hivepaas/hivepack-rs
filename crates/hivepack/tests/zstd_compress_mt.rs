//! Compresses with worker threads (`ZSTD_c_nbWorkers`) through the port
//! and libzstd 1.5.7, built with its threads, with the same parameters and
//! the same calls, and compares the frames byte for byte; then decodes the
//! port's frames back.
//!
//! With workers, a frame does not depend on how many there are, nor on how
//! far they have got, but how much input each call takes and how much it
//! writes out do. So the streaming comparisons drive each side on its own
//! through the same steps (input up to a point, with a directive), each
//! step's calls repeated until it is done: all of its input taken, or with
//! a flush or the end of the frame, all written out, with the same room
//! for output at each call. They compare the frames, and how each step
//! ended. `ZSTD_compress2` is one call either way. Each side gets its own
//! number of workers, from 1 to 8: the frames must not depend on it.
//!
//! `ZSTD_getFrameProgression` depends on the threads too, but for what
//! each side has taken and written out; once a flush or the end has all
//! been written out, it is the same on both sides. Contexts that share a
//! pool of threads (`ZSTD_CCtx_refThreadPool`) write the same frames.
//!
//! Inputs are smaller in debug builds, and smaller still on the machines CI
//! emulates (32-bit and big-endian). On big-endian machines the frames
//! leave out the strategies from `greedy` up: libzstd's block splitter
//! hashes bytes in the machine's order there, and every input here is
//! large enough for it.

#![allow(clippy::expect_used, clippy::panic)]

#[path = "zstd_support/mod.rs"]
mod support;

use std::sync::Arc;

use hivepack::zstd::{
    CCtx, CDict, CParameter as P, CParameterKind as K, DCtx, DictAttachPref, EndDirective,
    ErrorCode, FrameProgression, InBuffer, OutBuffer, ParamSwitch, ResetDirective, Strategy,
    ThreadPool,
};
use support::{Problems, Rng};
use zstd::zstd_safe::{self, CParameter as C, zstd_sys::ZSTD_EndDirective};

/// Builds without optimizations, and emulated machines.
const SLOW: bool = cfg!(debug_assertions) || EMULATED;
/// The machines CI runs under emulation, far slower still.
const EMULATED: bool = cfg!(any(target_pointer_width = "32", target_endian = "big"));

/// `ZSTDMT_JOBSIZE_MIN`: the smallest job, and the largest frame of a known
/// size compressed without workers.
const JOBSIZE_MIN: usize = 512 << 10;

/// Calls more than this for one step mean no progress.
const MAX_CALLS: usize = 1_000_000;

/// Room past the end of the room the stable output buffers are given: with
/// a target size for compressed blocks and little room, libzstd's
/// superblocks write past it (see `tests/compress_target.rs`).
const SLACK: usize = 1 << 18;

/// `n` bytes, less for slower runs.
fn scaled(n: usize) -> usize {
    if EMULATED {
        n / 4
    } else if SLOW {
        n / 2
    } else {
        n
    }
}

/// Data with repeats near and far: text-like pieces, runs, noise, and
/// copies of larger pieces from anywhere before, which long distance
/// matching finds, and jobs cut through.
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

fn name(code: usize) -> String {
    zstd_safe::get_error_name(code).to_string()
}

fn message(error: hivepack::zstd::Error) -> String {
    error.code().message().to_string()
}

/// A parameter for both.
type Param = (P, C);

/// Sets the same parameter on both; they must agree on whether it works.
fn set_both(c: &mut zstd_safe::CCtx<'_>, p: &mut CCtx, (pp, cp): Param) -> Result<(), String> {
    let want = c.set_parameter(cp).map(|_| ()).map_err(name);
    let got = p.set_parameter(pp).map_err(message);
    if want != got {
        return Err(format!("setting {pp:?}: libzstd {want:?}, port {got:?}"));
    }
    Ok(())
}

fn level(level: i32) -> Param {
    (P::CompressionLevel(level), C::CompressionLevel(level))
}

fn workers(c: u32, p: u32) -> [Param; 1] {
    // Each side its own count: the frames must not depend on it.
    [(P::NbWorkers(p), C::NbWorkers(c))]
}

fn switch(pick: u64) -> (ParamSwitch, zstd_safe::ParamSwitch) {
    match pick % 3 {
        0 => (ParamSwitch::Auto, zstd_safe::ParamSwitch::Auto),
        1 => (ParamSwitch::Enable, zstd_safe::ParamSwitch::Enable),
        _ => (ParamSwitch::Disable, zstd_safe::ParamSwitch::Disable),
    }
}

fn strategy(rng: &mut Rng) -> Param {
    use zstd_safe::Strategy as S;
    let strategies = [
        (Strategy::Fast, S::ZSTD_fast),
        (Strategy::Dfast, S::ZSTD_dfast),
        (Strategy::Greedy, S::ZSTD_greedy),
        (Strategy::Lazy, S::ZSTD_lazy),
        (Strategy::Lazy2, S::ZSTD_lazy2),
        (Strategy::Btlazy2, S::ZSTD_btlazy2),
        (Strategy::Btopt, S::ZSTD_btopt),
        (Strategy::Btultra, S::ZSTD_btultra),
        (Strategy::Btultra2, S::ZSTD_btultra2),
    ];
    // On big-endian machines, fast or dfast (see the module's notes).
    let last = if cfg!(target_endian = "big") { 1 } else { 8 };
    let (p, c) = strategies[rng.range(0, last) as usize];
    (P::Strategy(Some(p)), C::Strategy(c))
}

/// A level the strategies of which the machine can compare at, and not too
/// slow ones for slow runs.
fn random_level(rng: &mut Rng) -> i32 {
    let levels: &[i32] = if cfg!(target_endian = "big") {
        &[-7, -1, 1, 2, 3]
    } else if SLOW {
        &[-5, -1, 1, 2, 3, 4, 5, 6, 7, 9, 12, 13, 16, 19]
    } else {
        &[
            -7, -3, -1, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13, 15, 16, 17, 18, 19, 20, 22,
        ]
    };
    levels[rng.range(0, levels.len() as u64 - 1) as usize]
}

/// Random parameters for both, the multithreading ones among them.
fn parameters(rng: &mut Rng) -> Vec<Param> {
    let mut list = vec![level(random_level(rng))];
    if rng.chance(2) {
        // A job size, often the smallest, for several jobs; sometimes too
        // small, raised to it.
        let value =
            [0, 1, 300_000, 512 << 10, 512 << 10, 700_000, 1 << 20][rng.range(0, 6) as usize];
        list.push((P::JobSize(value), C::JobSize(value)));
    }
    if rng.chance(2) {
        let value = rng.range(0, 9) as u32;
        list.push((P::OverlapLog(value as i32), C::OverlapSizeLog(value)));
    }
    if rng.chance(4) {
        list.push((P::Rsyncable(true), C::RSyncable(true)));
    }
    if rng.chance(2) {
        let value = rng.range(10, 23) as u32;
        list.push((P::WindowLog(value), C::WindowLog(value)));
    }
    if rng.chance(4) {
        let value = rng.range(6, 20) as u32;
        list.push((P::HashLog(value), C::HashLog(value)));
    }
    if rng.chance(4) {
        let value = rng.range(6, 20) as u32;
        list.push((P::ChainLog(value), C::ChainLog(value)));
    }
    if rng.chance(5) {
        let value = rng.range(1, 6) as u32;
        list.push((P::SearchLog(value), C::SearchLog(value)));
    }
    if rng.chance(4) {
        let value = if rng.chance(2) {
            3
        } else {
            rng.range(3, 7) as u32
        };
        list.push((P::MinMatch(value), C::MinMatch(value)));
    }
    if rng.chance(3) || cfg!(target_endian = "big") {
        list.push(strategy(rng));
    }
    if rng.chance(2) {
        let (p, c) = switch(rng.next());
        list.push((P::UseRowMatchFinder(p), C::UseRowMatchFinder(c)));
    }
    if rng.chance(2) {
        let (p, c) = switch(rng.next());
        list.push((P::SplitAfterSequences(p), C::UseBlockSplitter(c)));
    }
    if rng.chance(2) {
        list.push((P::ChecksumFlag(true), C::ChecksumFlag(true)));
    }
    if rng.chance(6) {
        list.push((P::ContentSizeFlag(false), C::ContentSizeFlag(false)));
    }
    if rng.chance(6) {
        list.push((P::DictIdFlag(false), C::DictIdFlag(false)));
    }
    if rng.chance(5) {
        // For a frame of unknown size, and the parameters changed while
        // streaming.
        let value = rng.range(1, 3_000_000) as u32;
        list.push((P::SrcSizeHint(value), C::SrcSizeHint(value)));
    }
    if rng.chance(5) {
        let value = [1024, 5000, 65_536][rng.range(0, 2) as usize];
        list.push((P::MaxBlockSize(value), C::MaxBlockSize(value)));
    }
    if rng.chance(5) {
        // A target size for compressed blocks, in the jobs too.
        let value = [1, 1340, 4096, 30_000, 131_072][rng.range(0, 4) as usize];
        list.push((P::TargetCBlockSize(value), C::TargetCBlockSize(value)));
    }
    if rng.chance(3) {
        // Long distance matching, run in order apart from the jobs, with
        // small parameters, so that it finds matches in these inputs; and a
        // window of its own, as it would take 2^27 bytes.
        list.push((
            P::EnableLongDistanceMatching(ParamSwitch::Enable),
            C::EnableLongDistanceMatching(true),
        ));
        if rng.chance(2) {
            let value = rng.range(4, 100) as u32;
            list.push((P::LdmMinMatch(value), C::LdmMinMatch(value)));
        }
        if rng.chance(2) {
            let value = rng.range(0, 4) as u32;
            list.push((P::LdmHashRateLog(value), C::LdmHashRateLog(value)));
        }
        if rng.chance(3) {
            let value = rng.range(6, 20) as u32;
            list.push((P::LdmHashLog(value), C::LdmHashLog(value)));
        }
        if rng.chance(3) {
            let value = rng.range(1, 8) as u32;
            list.push((P::LdmBucketSizeLog(value), C::LdmBucketSizeLog(value)));
        }
        let value = rng.range(10, 21) as u32;
        list.push((P::WindowLog(value), C::WindowLog(value)));
    }
    list
}

/// `ZSTD_compress2` with libzstd.
fn libzstd_compress2(c: &mut zstd_safe::CCtx<'_>, src: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; zstd_safe::compress_bound(src.len())];
    let size = c.compress2(&mut out[..], src).map_err(name)?;
    out.truncate(size);
    Ok(out)
}

/// `compress2` with the port.
fn port_compress2(p: &mut CCtx, src: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; hivepack::zstd::compress_bound(src.len()).expect("a bound")];
    let size = p.compress2(&mut out, src).map_err(message)?;
    out.truncate(size);
    Ok(out)
}

/// The dictionary a frame was made with, as the decoder needs it.
#[derive(Clone, Copy)]
enum Active<'a> {
    None,
    Dict(&'a [u8]),
    Prefix(&'a [u8]),
}

/// Decodes `frame` with the port: it must give `content`.
fn decodes(frame: &[u8], content: &[u8], dict: Active<'_>) -> Result<(), String> {
    let mut back = vec![0u8; content.len()];
    let mut dctx = DCtx::new();
    let decoded = match dict {
        Active::None => dctx.decompress(&mut back, frame),
        Active::Dict(dict) => dctx.decompress_using_dict(&mut back, frame, dict),
        Active::Prefix(prefix) => dctx
            .ref_prefix(prefix)
            .and_then(|()| dctx.decompress(&mut back, frame)),
    };
    match decoded {
        Ok(size) if back[..size] == *content => Ok(()),
        other => Err(format!("the frame does not decode back: {other:?}")),
    }
}

/// Where two frames first differ.
fn first_difference(want: &[u8], got: &[u8]) -> usize {
    want.iter()
        .zip(got)
        .position(|(a, b)| a != b)
        .unwrap_or(want.len().min(got.len()))
}

/// `compress2` of `src` with both: the same frame, or the same error.
fn compare_compress2(
    c: &mut zstd_safe::CCtx<'_>,
    p: &mut CCtx,
    src: &[u8],
    dict: Active<'_>,
) -> Result<bool, String> {
    let want = libzstd_compress2(c, src);
    let got = port_compress2(p, src);
    match (&want, &got) {
        (Ok(want), Ok(got)) if want == got => {
            decodes(got, src, dict)?;
            Ok(true)
        }
        (Ok(want), Ok(got)) => Err(format!(
            "frames of {} and {} bytes, differing at byte {}",
            want.len(),
            got.len(),
            first_difference(want, got)
        )),
        (Err(want), Err(got)) if want == got => Ok(false),
        _ => Err(format!(
            "libzstd {:?}, port {:?}",
            want.map(|frame| frame.len()),
            got.map(|frame| frame.len())
        )),
    }
}

/// At every level, frames of several jobs (the smallest job size) and of
/// the default job size, from just over the size where workers start;
/// each side with its own number of workers.
#[test]
fn compress2_at_every_level() {
    let mut problems = Problems::default();
    let mut rng = Rng(0x4D54_0001);
    let levels: Vec<i32> = if cfg!(target_endian = "big") {
        vec![-7, -1, 1, 2, 3]
    } else if EMULATED {
        vec![-5, 1, 3, 5, 9, 13, 16, 19]
    } else {
        (-7..=22)
            .filter(|&level| !SLOW || level % 2 == 1 || level < 4)
            .collect()
    };
    let mut compared = 0;
    for (i, level_) in levels.into_iter().enumerate() {
        // The optimal parser is slow without optimizations.
        let long = if level_ >= 16 { 1_000_000 } else { 2_600_000 };
        let len = JOBSIZE_MIN + 1 + rng.range(0, scaled(long) as u64) as usize;
        let src = data(&mut rng, len);
        let job_size = if i % 3 == 2 { 0 } else { JOBSIZE_MIN as u32 };
        let c_workers = 1 + (i % 8) as u32;
        let p_workers = 1 + ((i * 3 + 5) % 8) as u32;
        let mut c = zstd_safe::CCtx::create();
        let mut p = CCtx::new();
        let mut params = vec![level(level_), (P::JobSize(job_size), C::JobSize(job_size))];
        params.extend(workers(c_workers, p_workers));
        if i % 4 == 1 {
            params.push((P::ChecksumFlag(true), C::ChecksumFlag(true)));
        }
        let tag = format!("level {level_}, {len} bytes, jobs of {job_size}");
        for param in params {
            if let Err(problem) = set_both(&mut c, &mut p, param) {
                problems.add(format!("{tag}: {problem}"));
            }
        }
        match compare_compress2(&mut c, &mut p, &src, Active::None) {
            Ok(_) => compared += 1,
            Err(problem) => problems.add(format!("{tag}: {problem}")),
        }
    }
    println!("{compared} frames compared");
    problems.check();
}

/// The same frames with 1 to 8 workers, and libzstd's; frames of a known
/// size of 512 KB or less, compressed without them, as without; and the
/// smallest frames of unknown size, streamed, with them.
#[test]
fn frames_do_not_depend_on_the_number_of_workers() {
    let mut problems = Problems::default();
    let mut rng = Rng(0x4D54_0002);
    let configs: &[(i32, usize)] = &[
        (1, 2_000_000),
        (3, 1_500_000),
        (7, 1_200_000),
        (19, 800_000),
    ];
    for &(level_, len) in configs {
        if cfg!(target_endian = "big") && level_ >= 4 {
            continue;
        }
        let src = data(&mut rng, scaled(len));
        let mut want = None;
        for nb_workers in 0..=8u32 {
            let mut c = zstd_safe::CCtx::create();
            let mut p = CCtx::new();
            let params = [
                level(level_),
                (
                    P::JobSize(JOBSIZE_MIN as u32),
                    C::JobSize(JOBSIZE_MIN as u32),
                ),
                (P::NbWorkers(nb_workers), C::NbWorkers(nb_workers)),
                (P::ChecksumFlag(true), C::ChecksumFlag(true)),
            ];
            for param in params {
                set_both(&mut c, &mut p, param).expect("both set it");
            }
            let got = port_compress2(&mut p, &src).expect("the port compresses");
            // libzstd at both ends, the port at every count.
            if nb_workers <= 1 || nb_workers == 8 {
                let frame = libzstd_compress2(&mut c, &src).expect("libzstd compresses");
                if frame != got {
                    problems.add(format!(
                        "level {level_}, {nb_workers} workers: the frames differ at byte {}",
                        first_difference(&frame, &got)
                    ));
                }
            }
            if nb_workers == 0 {
                continue;
            }
            match &want {
                None => want = Some(got),
                Some(want) if *want != got => problems.add(format!(
                    "level {level_}: {nb_workers} workers give another frame than 1"
                )),
                Some(_) => {}
            }
        }
        if let Some(frame) = &want
            && let Err(problem) = decodes(frame, &src, Active::None)
        {
            problems.add(format!("level {level_}: {problem}"));
        }
    }

    // Up to 512 KB, a known size takes no workers: the frames are those
    // without; just over, they are not, here. On big-endian machines, whose
    // libzstd hashes 2 bytes otherwise in its block splitter, the frames
    // just over come out the same with and without, in libzstd as in the
    // port: both are compared with libzstd's.
    for len in [0, 1, 1000, JOBSIZE_MIN - 1, JOBSIZE_MIN, JOBSIZE_MIN + 1] {
        let src = data(&mut rng, len);
        let mut frames = Vec::new();
        for nb_workers in [0, 3] {
            let mut c = zstd_safe::CCtx::create();
            let mut p = CCtx::new();
            for param in [
                level(3),
                (P::NbWorkers(nb_workers), C::NbWorkers(nb_workers)),
            ] {
                set_both(&mut c, &mut p, param).expect("both set it");
            }
            match compare_compress2(&mut c, &mut p, &src, Active::None) {
                Ok(_) => frames.push(port_compress2(&mut p, &src).expect("compresses")),
                Err(problem) => {
                    problems.add(format!("{len} bytes, {nb_workers} workers: {problem}"))
                }
            }
        }
        let differ_over = cfg!(target_endian = "little");
        if frames.len() == 2
            && (len <= JOBSIZE_MIN || differ_over)
            && (frames[0] == frames[1]) != (len <= JOBSIZE_MIN)
        {
            problems.add(format!(
                "{len} bytes: the frames with and without workers are the same: {}",
                frames[0] == frames[1]
            ));
        }
    }
    problems.check();
}

/// Random parameters, the multithreading ones among them: job sizes,
/// overlaps, synchronization points, checksums, long distance matching,
/// the block splitters, small windows.
#[test]
fn compress2_with_parameters() {
    let mut problems = Problems::default();
    let mut compared = 0;
    let rounds = if EMULATED {
        8
    } else if SLOW {
        24
    } else {
        60
    };
    for seed in 0..rounds {
        let mut rng = Rng(0x4D54_0100 + seed);
        let mut c = zstd_safe::CCtx::create();
        let mut p = CCtx::new();
        let mut params = parameters(&mut rng);
        params.extend(workers(rng.range(1, 8) as u32, rng.range(1, 8) as u32));
        let tag = format!("seed {seed}");
        let mut set = true;
        for param in params {
            if let Err(problem) = set_both(&mut c, &mut p, param) {
                problems.add(format!("{tag}: {problem}"));
                set = false;
            }
        }
        if !set {
            continue;
        }
        let len = JOBSIZE_MIN + 1 + rng.range(0, scaled(2_500_000) as u64) as usize;
        let src = data(&mut rng, len);
        match compare_compress2(&mut c, &mut p, &src, Active::None) {
            Ok(_) => compared += 1,
            Err(problem) => problems.add(format!("{tag} ({len} bytes): {problem}")),
        }
    }
    println!("{compared} frames compared");
    assert!(compared > rounds as usize / 2, "too few frames: {compared}");
    problems.check();
}

/// Dictionaries for the comparisons: pieces of a corpus, raw content, and
/// zstd dictionaries libzstd trains on it, and `CDict`s of them made by
/// both. The frames' data is drawn from the corpus too.
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
        for _ in 0..3 {
            if let Some(dict) = rng.trained_dict(&corpus) {
                dicts.push(dict);
            }
        }
        for len in [8, 1000, 70_000] {
            let at = rng.range(0, (corpus.len() - len) as u64) as usize;
            dicts.push(corpus[at..at + len].to_vec());
        }
        let mut c_cdicts = Vec::new();
        let mut p_cdicts = Vec::new();
        for (i, dict) in dicts.iter().enumerate() {
            let level = [1, 3, 5, 19, -2, 9][i % 6];
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

    /// A dictionary set on both, as `way` picks: loaded, a `CDict`
    /// referenced, or a prefix (raw content), with an attach preference.
    fn set<'a>(
        &'a self,
        c: &mut zstd_safe::CCtx<'a>,
        p: &mut CCtx,
        rng: &mut Rng,
    ) -> Result<Active<'a>, String> {
        let (pp, cp) = match rng.range(0, 5) {
            0 => (
                DictAttachPref::ForceAttach,
                zstd_safe::DictAttachPref::ForceAttach,
            ),
            1 => (
                DictAttachPref::ForceCopy,
                zstd_safe::DictAttachPref::ForceCopy,
            ),
            2 => (
                DictAttachPref::ForceLoad,
                zstd_safe::DictAttachPref::ForceLoad,
            ),
            _ => (
                DictAttachPref::DefaultAttach,
                zstd_safe::DictAttachPref::DefaultAttach,
            ),
        };
        set_both(c, p, (P::ForceAttachDict(pp), C::ForceAttachDict(cp)))?;
        let i = rng.range(0, self.dicts.len() as u64 - 1) as usize;
        let dict = &self.dicts[i];
        let (active, want, got) = match rng.range(0, 2) {
            0 => (
                Active::Dict(dict),
                c.load_dictionary(dict).map(|_| ()).map_err(name),
                p.load_dictionary(dict).map_err(message),
            ),
            1 => (
                Active::Dict(dict),
                c.ref_cdict(&self.c_cdicts[i]).map(|_| ()).map_err(name),
                p.ref_cdict(Some(self.p_cdicts[i].clone())).map_err(message),
            ),
            _ => (
                Active::Prefix(dict),
                c.ref_prefix(dict).map(|_| ()).map_err(name),
                p.ref_prefix(dict).map_err(message),
            ),
        };
        if want != got {
            return Err(format!(
                "setting the dictionary: libzstd {want:?}, port {got:?}"
            ));
        }
        Ok(active)
    }
}

/// With a dictionary loaded, a `CDict` referenced (attached, copied in or
/// loaded again by the first job), or a prefix of raw content: the first
/// job has it, as libzstd's; long distance matching loads a prefix too.
#[test]
fn compress2_with_dictionaries() {
    let mut problems = Problems::default();
    let mut rng = Rng(0x4D54_0200);
    let dicts = Dicts::new(&mut rng);
    let mut compared = 0;
    let rounds = if EMULATED {
        6
    } else if SLOW {
        16
    } else {
        40
    };
    for round in 0..rounds {
        let mut c = zstd_safe::CCtx::create();
        let mut p = CCtx::new();
        let mut params = vec![level(random_level(&mut rng))];
        if rng.chance(2) {
            params.push((
                P::JobSize(JOBSIZE_MIN as u32),
                C::JobSize(JOBSIZE_MIN as u32),
            ));
        }
        if rng.chance(3) {
            let value = rng.range(1, 9) as u32;
            params.push((P::OverlapLog(value as i32), C::OverlapSizeLog(value)));
        }
        if rng.chance(3) {
            params.push((P::ChecksumFlag(true), C::ChecksumFlag(true)));
        }
        if rng.chance(4) {
            params.push((
                P::EnableLongDistanceMatching(ParamSwitch::Enable),
                C::EnableLongDistanceMatching(true),
            ));
            let value = rng.range(4, 40) as u32;
            params.push((P::LdmMinMatch(value), C::LdmMinMatch(value)));
            let value = rng.range(14, 21) as u32;
            params.push((P::WindowLog(value), C::WindowLog(value)));
        }
        if cfg!(target_endian = "big") {
            params.push(strategy(&mut rng));
        }
        params.extend(workers(rng.range(1, 8) as u32, rng.range(1, 8) as u32));
        let tag = format!("round {round}");
        let set = params
            .into_iter()
            .try_for_each(|param| set_both(&mut c, &mut p, param))
            .and_then(|()| dicts.set(&mut c, &mut p, &mut rng));
        let active = match set {
            Ok(active) => active,
            Err(problem) => {
                problems.add(format!("{tag}: {problem}"));
                continue;
            }
        };
        let len = JOBSIZE_MIN + 1 + rng.range(0, scaled(1_800_000) as u64) as usize;
        let src = dicts.data(&mut rng, len);
        match compare_compress2(&mut c, &mut p, &src, active) {
            Ok(_) => compared += 1,
            Err(problem) => problems.add(format!("{tag} ({len} bytes): {problem}")),
        }
    }
    println!("{compared} frames compared");
    problems.check();
}

/// A step of a stream: input up to `end`, with `directive`, in calls of
/// `room` bytes of output each (with a stable output buffer, the rest of
/// the frame's buffer); through the helpers (`ZSTD_compressStream`,
/// `ZSTD_flushStream`, `ZSTD_endStream`) with `helper`, when they apply.
#[derive(Clone, Copy, Debug)]
struct Step {
    end: usize,
    directive: EndDirective,
    room: usize,
    helper: bool,
    /// A compression parameter to set after the step, once it has flushed.
    then: Option<Param>,
}

/// How a step ended, and the frame's output so far.
#[derive(PartialEq, Eq, Debug)]
enum Ended {
    /// Done: its input taken, or all of it written out; then, after a
    /// flush or the end, how far the frame has got, the same on both
    /// sides whatever the threads did.
    Done(Option<FrameProgression>),
    /// No progress with all the room given: a stable output buffer full.
    Stalled,
    Failed(String),
}

/// What a side does at a call.
trait Side {
    fn call(
        &mut self,
        dst: &mut [u8],
        out_pos: usize,
        src: &[u8],
        directive: EndDirective,
        helper: bool,
    ) -> (Result<usize, String>, usize, usize);
    fn set(&mut self, param: Param) -> Result<(), String>;
    fn name(&self) -> &'static str;
    /// `ZSTD_getFrameProgression`.
    fn progression(&self) -> FrameProgression;
    /// `ZSTD_toFlushNow`, which zstd-safe does not offer.
    fn to_flush_now(&self) -> Option<usize>;
}

struct Libzstd<'a>(zstd_safe::CCtx<'a>);
struct Port(CCtx);

impl Side for Libzstd<'_> {
    fn call(
        &mut self,
        dst: &mut [u8],
        out_pos: usize,
        src: &[u8],
        directive: EndDirective,
        helper: bool,
    ) -> (Result<usize, String>, usize, usize) {
        let c = &mut self.0;
        let mut output = zstd_safe::OutBuffer::around_pos(dst, out_pos);
        let mut input = zstd_safe::InBuffer::around(src);
        let result = match (directive, helper && src.is_empty()) {
            (EndDirective::Continue, _) if helper => c.compress_stream(&mut output, &mut input),
            (EndDirective::Flush, true) => c.flush_stream(&mut output),
            (EndDirective::End, true) => c.end_stream(&mut output),
            (EndDirective::Continue, _) => {
                c.compress_stream2(&mut output, &mut input, ZSTD_EndDirective::ZSTD_e_continue)
            }
            (EndDirective::Flush, _) => {
                c.compress_stream2(&mut output, &mut input, ZSTD_EndDirective::ZSTD_e_flush)
            }
            (EndDirective::End, _) => {
                c.compress_stream2(&mut output, &mut input, ZSTD_EndDirective::ZSTD_e_end)
            }
        };
        (result.map_err(name), input.pos(), output.pos())
    }

    fn set(&mut self, (_, cp): Param) -> Result<(), String> {
        self.0.set_parameter(cp).map(|_| ()).map_err(name)
    }

    fn name(&self) -> &'static str {
        "libzstd"
    }

    fn progression(&self) -> FrameProgression {
        let fp = self.0.get_frame_progression();
        FrameProgression {
            ingested: fp.ingested,
            consumed: fp.consumed,
            produced: fp.produced,
            flushed: fp.flushed,
            current_job_id: fp.currentJobID,
            nb_active_workers: fp.nbActiveWorkers,
        }
    }

    fn to_flush_now(&self) -> Option<usize> {
        None
    }
}

impl Side for Port {
    fn call(
        &mut self,
        dst: &mut [u8],
        out_pos: usize,
        src: &[u8],
        directive: EndDirective,
        helper: bool,
    ) -> (Result<usize, String>, usize, usize) {
        let p = &mut self.0;
        let mut output = OutBuffer { dst, pos: out_pos };
        let mut input = InBuffer::new(src);
        let result = match (directive, helper && src.is_empty()) {
            (EndDirective::Continue, _) if helper => p.compress_stream(&mut output, &mut input),
            (EndDirective::Flush, true) => p.flush_stream(&mut output),
            (EndDirective::End, true) => p.end_stream(&mut output),
            (directive, _) => p.compress_stream2(&mut output, &mut input, directive),
        };
        (result.map_err(message), input.pos, output.pos)
    }

    fn set(&mut self, (pp, _): Param) -> Result<(), String> {
        self.0.set_parameter(pp).map_err(message)
    }

    fn name(&self) -> &'static str {
        "port"
    }

    fn progression(&self) -> FrameProgression {
        self.0.get_frame_progression()
    }

    fn to_flush_now(&self) -> Option<usize> {
        Some(self.0.to_flush_now())
    }
}

/// What `ZSTD_getFrameProgression` must say after any call, `taken` and
/// `written` so far in the frame. Without workers, or before the first job
/// is handed over, the output written out counts as produced; with
/// workers, the output written out is what the jobs have produced and the
/// caller's thread has written out, and the jobs that are compressing or
/// waiting for a thread are at most one more than the workers (8 here).
fn progression_problem(side: &dyn Side, taken: usize, written: usize) -> Option<String> {
    // In this order, for the workers go on producing between the two.
    let to_flush_now = side.to_flush_now();
    let fp = side.progression();
    let problem = if fp.ingested != taken as u64 {
        format!("ingested {} of {taken} taken", fp.ingested)
    } else if fp.consumed > fp.ingested || fp.flushed > fp.produced {
        "more consumed than ingested, or flushed than produced".into()
    } else if fp.current_job_id == 0 && (fp.flushed != fp.produced || fp.nb_active_workers > 1) {
        "before the first job, more produced than flushed, or more than one job".into()
    } else if fp.current_job_id > 0 && (fp.flushed != written as u64 || fp.nb_active_workers > 9) {
        format!("{written} bytes written, or too many active jobs")
    } else if to_flush_now.is_some_and(|now| now as u64 > fp.produced - fp.flushed) {
        format!("{to_flush_now:?} to flush now")
    } else {
        return None;
    };
    Some(format!(
        "{}: frame progression {fp:?}: {problem}",
        side.name()
    ))
}

/// One frame of `data` through `side`, step by step. Returns the frame
/// written, how each step ended, and what setting each parameter between
/// steps gave.
fn stream_frame(
    side: &mut dyn Side,
    data: &[u8],
    steps: &[Step],
    stable_room: Option<usize>,
) -> (Vec<u8>, Vec<Ended>, Vec<Result<(), String>>) {
    let mut frame = Vec::new();
    let mut ends = Vec::new();
    let mut sets = Vec::new();
    // With a stable output buffer, one buffer for the frame.
    let mut stable = vec![0u8; stable_room.unwrap_or(0) + SLACK];
    let mut fresh = Vec::new();
    let mut taken = 0;
    'steps: for step in steps {
        let mut stalled = 0;
        for _ in 0..MAX_CALLS {
            let (dst, out_pos) = match stable_room {
                Some(room) => (&mut stable[..room], frame.len()),
                None => {
                    fresh.clear();
                    fresh.resize(step.room, 0);
                    (&mut fresh[..], 0)
                }
            };
            let src = &data[taken..step.end];
            let (result, read, wrote) = side.call(dst, out_pos, src, step.directive, step.helper);
            frame.extend_from_slice(&dst[out_pos..wrote]);
            taken += read;
            let remaining = match result {
                Ok(remaining) => remaining,
                Err(error) => {
                    ends.push(Ended::Failed(error));
                    break 'steps;
                }
            };
            if let Some(problem) = progression_problem(side, taken, frame.len()) {
                ends.push(Ended::Failed(problem));
                break 'steps;
            }
            let done = match step.directive {
                EndDirective::Continue => taken == step.end,
                _ => taken == step.end && remaining == 0,
            };
            if done {
                let progression =
                    (step.directive != EndDirective::Continue).then(|| side.progression());
                ends.push(Ended::Done(progression));
                if let Some(param) = step.then {
                    sets.push(side.set(param));
                }
                continue 'steps;
            }
            if (read, wrote) == (0, out_pos) {
                stalled += 1;
                if stable_room.is_some() && stalled > 1000 {
                    ends.push(Ended::Stalled);
                    break 'steps;
                }
                // The workers have not produced anything yet.
                std::thread::yield_now();
            } else {
                stalled = 0;
            }
        }
        ends.push(Ended::Failed("no end".into()));
        break;
    }
    (frame, ends, sets)
}

/// Random steps for `len` bytes: pieces taken with `Continue`, flushes now
/// and then, after some of which a compression parameter changes, and the
/// end; small and large room for output.
fn steps(rng: &mut Rng, len: usize) -> Vec<Step> {
    let mut steps = Vec::new();
    let mut end = 0;
    let big_room = rng.chance(2);
    let room = |rng: &mut Rng| {
        if big_room {
            rng.range(1 << 16, 1 << 21) as usize
        } else {
            rng.range(1, 70_000) as usize
        }
    };
    while end < len {
        let piece = match rng.range(0, 3) {
            0 => rng.range(0, 300),
            1 => rng.range(1, 70_000),
            _ => rng.range(1, 1_200_000),
        } as usize;
        end = (end + piece).min(len);
        let directive = if rng.chance(6) {
            EndDirective::Flush
        } else {
            EndDirective::Continue
        };
        // After a flush, the jobs made so far are all written out: a
        // parameter set then goes to every job after, and to none before,
        // whatever the timing.
        let then =
            (directive == EndDirective::Flush && rng.chance(2)).then(|| match rng.range(0, 3) {
                0 => level(random_level(rng)),
                1 => strategy(rng),
                _ => {
                    let value = rng.range(10, 18) as u32;
                    (P::HashLog(value), C::HashLog(value))
                }
            });
        steps.push(Step {
            end,
            directive,
            room: room(rng),
            helper: rng.chance(4),
            then,
        });
    }
    if rng.chance(4) {
        // A flush of nothing more, then the end.
        steps.push(Step {
            end,
            directive: EndDirective::Flush,
            room: room(rng),
            helper: rng.chance(2),
            then: None,
        });
    }
    steps.push(Step {
        end,
        directive: EndDirective::End,
        room: room(rng),
        helper: rng.chance(4),
        then: None,
    });
    steps
}

/// Contexts used for several frames, streamed through the same steps; with
/// workers mostly, a frame without now and then; with dictionaries for
/// some; parameters changed between frames, and between steps after
/// flushes; pledged sizes, sometimes wrong; a stable output buffer
/// sometimes. Returns the frames compared.
#[allow(clippy::too_many_lines)]
fn compare_streams(problems: &mut Problems, seed: u64, dicts: &Dicts) -> usize {
    let mut rng = Rng(seed);
    let mut c = Libzstd(zstd_safe::CCtx::create());
    let mut p = Port(CCtx::new());
    let mut frames = 0;
    let mut active = Active::None;
    for round in 0..rng.range(1, 3) {
        let tag = format!("seed {seed}, frame {round}");
        if rng.chance(4) {
            // The parameters back to their defaults, and no dictionary.
            let want =
                c.0.reset(zstd_safe::ResetDirective::Parameters)
                    .map(|_| ())
                    .map_err(name);
            let got = p.0.reset(ResetDirective::Parameters).map_err(message);
            if want != got {
                problems.add(format!("{tag}: resetting: libzstd {want:?}, port {got:?}"));
                return frames;
            }
            active = Active::None;
        }
        let mut params = parameters(&mut rng);
        let nb_workers = if rng.chance(6) {
            (0, 0)
        } else {
            (rng.range(1, 8) as u32, rng.range(1, 8) as u32)
        };
        params.extend(workers(nb_workers.0, nb_workers.1));
        let stable_out = rng.chance(5);
        params.push((
            P::StableOutBuffer(stable_out),
            C::StableOutBuffer(stable_out),
        ));
        for param in params {
            if let Err(problem) = set_both(&mut c.0, &mut p.0, param) {
                problems.add(format!("{tag}: {problem}"));
                return frames;
            }
        }
        if rng.chance(3) {
            match dicts.set(&mut c.0, &mut p.0, &mut rng) {
                Ok(dict) => active = dict,
                Err(problem) => {
                    problems.add(format!("{tag}: {problem}"));
                    return frames;
                }
            }
        }
        let len = match rng.range(0, 4) {
            0 => rng.range(0, 100_000),
            1 => rng.range(JOBSIZE_MIN as u64 - 1000, JOBSIZE_MIN as u64 + 1000),
            _ => rng.range(0, scaled(2_500_000) as u64),
        } as usize;
        let content = dicts.data(&mut rng, len);
        let mut pledged_wrong = false;
        if rng.chance(4) {
            // A pledged size, sometimes wrong: libzstd's first job fails
            // when it gets more, its last job when it gets less; with more
            // jobs, a frame with too little input has no error.
            let size = match rng.range(0, 4) {
                0 => len as u64 + 1,
                1 => (len as u64).saturating_sub(1),
                _ => len as u64,
            };
            pledged_wrong = size != len as u64;
            let want =
                c.0.set_pledged_src_size(Some(size))
                    .map(|_| ())
                    .map_err(name);
            let got = p.0.set_pledged_src_size(size).map_err(message);
            if want != got {
                problems.add(format!("{tag}: pledging: libzstd {want:?}, port {got:?}"));
                return frames;
            }
        }
        let steps = steps(&mut rng, len);
        let stable_room = stable_out.then(|| {
            // Too small, and the frame fails without workers; with them, it
            // stops where the job table is full, which depends on their
            // number.
            if nb_workers == (0, 0) && rng.chance(4) {
                rng.range(0, 64) as usize
            } else {
                hivepack::zstd::compress_bound(len).expect("a bound") + 32
            }
        });
        let frame_dict = active;
        if let Active::Prefix(_) = active {
            // For this frame only.
            active = Active::None;
        }
        let (want, want_ends, want_sets) = stream_frame(&mut c, &content, &steps, stable_room);
        let (got, got_ends, got_sets) = stream_frame(&mut p, &content, &steps, stable_room);
        let tag =
            format!("{tag} ({len} bytes, workers {nb_workers:?}, stable output {stable_room:?})");
        if want_sets != got_sets {
            problems.add(format!(
                "{tag}: setting parameters: libzstd {want_sets:?}, port {got_sets:?}"
            ));
            return frames;
        }
        // An error comes from a job whose output need not all be written
        // out yet: only how it ended counts then.
        let failed = matches!(want_ends.last(), Some(Ended::Failed(_)));
        if want_ends != got_ends || (!failed && want != got) {
            problems.add(format!(
                "{tag}: libzstd {} bytes, ended {want_ends:?}; port {} bytes, ended {got_ends:?}; \
                 first difference at {}",
                want.len(),
                got.len(),
                first_difference(&want, &got)
            ));
            return frames;
        }
        let complete = want_ends.iter().all(|end| matches!(end, Ended::Done(_)));
        if complete {
            frames += 1;
            // A frame pledged wrong, but complete, says the wrong size.
            if !pledged_wrong && let Err(problem) = decodes(&got, &content, frame_dict) {
                problems.add(format!("{tag}: {problem}"));
            }
        } else {
            // Both start the next frame afresh; libzstd's workers done
            // with the frame first, as zstd-safe wants.
            let _ = c.0.wait_for_workers();
            let _ = c.0.reset(zstd_safe::ResetDirective::SessionOnly);
            let _ = p.0.reset(ResetDirective::SessionOnly);
        }
    }
    frames
}

#[test]
fn streaming_with_workers() {
    let mut problems = Problems::default();
    let mut rng = Rng(0x4D54_0300);
    let dicts = Dicts::new(&mut rng);
    let mut frames = 0;
    let rounds = if EMULATED {
        6
    } else if SLOW {
        24
    } else {
        80
    };
    for seed in 0..rounds {
        frames += compare_streams(&mut problems, 0x4D54_1000 + seed, &dicts);
    }
    println!("{frames} frames compared");
    assert!(
        frames > rounds as usize / 2,
        "too few frames compared: {frames}"
    );
    problems.check();
}

/// One frame of `data` through the port with a stable input buffer
/// (`ZSTD_c_stableInBuffer`, which zstd-safe does not offer): each call
/// gets the buffer from its start, up to the step's end, from where the
/// call before stopped. A call with `ZSTD_e_continue` and less than a block
/// in all before the frame starts says the input was taken, and the frame
/// takes it at the next call, from before that position.
fn stream_frame_stable_input(p: &mut CCtx, data: &[u8], steps: &[Step]) -> Result<Vec<u8>, String> {
    let mut frame = Vec::new();
    let mut piece = Vec::new();
    let mut taken = 0;
    'steps: for step in steps {
        for _ in 0..MAX_CALLS {
            piece.clear();
            piece.resize(step.room, 0);
            let mut output = OutBuffer::new(&mut piece);
            let mut input = InBuffer {
                src: &data[..step.end],
                pos: taken,
            };
            let remaining = p
                .compress_stream2(&mut output, &mut input, step.directive)
                .map_err(message)?;
            let written = output.pos;
            frame.extend_from_slice(&piece[..written]);
            taken = input.pos;
            let done = match step.directive {
                EndDirective::Continue => taken == step.end,
                _ => taken == step.end && remaining == 0,
            };
            if done {
                continue 'steps;
            }
            std::thread::yield_now();
        }
        return Err("no end".into());
    }
    Ok(frame)
}

/// With a stable input buffer, the port's frames with workers are
/// libzstd's without one: input a stable buffer gives at a call that waits
/// for a block's worth, before the frame starts, goes into the frame's
/// first job at the next call, with the input of that call; the jobs are
/// the same. But for a frame that starts with `ZSTD_e_end`, which then
/// knows its size: here the first steps are a block or more, or a flush.
#[test]
fn stable_input_buffers_with_workers() {
    let mut problems = Problems::default();
    let mut compared = 0;
    let rounds = if EMULATED {
        4
    } else if SLOW {
        12
    } else {
        40
    };
    for seed in 0..rounds {
        let mut rng = Rng(0x4D54_0500 + seed);
        let mut c = Libzstd(zstd_safe::CCtx::create());
        let mut p = CCtx::new();
        let mut params = parameters(&mut rng);
        params.extend(workers(rng.range(1, 8) as u32, rng.range(1, 8) as u32));
        let tag = format!("seed {seed}");
        if let Err(problem) = params
            .into_iter()
            .try_for_each(|param| set_both(&mut c.0, &mut p, param))
        {
            problems.add(format!("{tag}: {problem}"));
            continue;
        }
        p.set_parameter(P::StableInBuffer(true)).expect("set");
        let len = rng.range(300_000, scaled(2_000_000) as u64) as usize;
        let src = data(&mut rng, len);
        let mut steps = steps(&mut rng, len);
        for step in &mut steps {
            // No parameter changes here: libzstd's frame starts a call
            // earlier, and takes them at another call.
            step.then = None;
            step.helper = false;
        }
        // The frame starts at a call with a block or more, or a flush.
        let start = rng.range(0, 99_999) as usize;
        let first = if rng.chance(2) {
            Step {
                end: 131_072 + start,
                directive: EndDirective::Continue,
                room: 1000,
                helper: false,
                then: None,
            }
        } else {
            Step {
                end: start,
                directive: EndDirective::Flush,
                room: 1000,
                helper: false,
                then: None,
            }
        };
        steps.retain(|step| step.end > first.end || step.directive == EndDirective::End);
        steps.insert(0, first);
        if start > 0 {
            // Before it, a small piece the stable buffer only says it took.
            steps.insert(
                0,
                Step {
                    end: start / 2,
                    directive: EndDirective::Continue,
                    room: 1000,
                    helper: false,
                    then: None,
                },
            );
        }
        let (want, want_ends, _) = stream_frame(&mut c, &src, &steps, None);
        if !want_ends.iter().all(|end| matches!(end, Ended::Done(_))) {
            problems.add(format!("{tag}: libzstd ended {want_ends:?}"));
            continue;
        }
        match stream_frame_stable_input(&mut p, &src, &steps) {
            Ok(got) if got == want => {
                compared += 1;
                if let Err(problem) = decodes(&got, &src, Active::None) {
                    problems.add(format!("{tag}: {problem}"));
                }
            }
            Ok(got) => problems.add(format!(
                "{tag} ({len} bytes): frames of {} and {} bytes, differing at byte {}",
                want.len(),
                got.len(),
                first_difference(&want, &got)
            )),
            Err(problem) => problems.add(format!("{tag} ({len} bytes): the port: {problem}")),
        }
    }
    println!("{compared} frames compared");
    problems.check();
}

/// Many jobs with long distance matching and a small window: its window,
/// apart from the jobs', goes past many of them, and libzstd's round
/// buffer wraps around several times, where its window gets an older
/// segment that the port's does not have.
#[test]
fn long_distance_matching_across_many_jobs() {
    let mut problems = Problems::default();
    let mut rng = Rng(0x4D54_0400);
    let len = scaled(9_000_000);
    // Repeats from far back, past the window of the strategy's tables, and
    // past the overlap.
    let block = data(&mut rng, 300_000);
    let mut src = Vec::with_capacity(len + block.len());
    while src.len() < len {
        if rng.chance(3) {
            src.extend_from_slice(&block[..rng.range(1000, block.len() as u64 - 1) as usize]);
        } else {
            let n = rng.range(1000, 200_000) as usize;
            src.extend(data(&mut rng, n));
        }
    }
    src.truncate(len);
    for (i, (level_, window_log, overlap)) in [(1, 19, 0), (3, 20, 4), (6, 20, 9), (12, 21, 1)]
        .into_iter()
        .enumerate()
    {
        if cfg!(target_endian = "big") && level_ >= 4 {
            continue;
        }
        let mut c = zstd_safe::CCtx::create();
        let mut p = CCtx::new();
        let params = [
            level(level_),
            (P::WindowLog(window_log), C::WindowLog(window_log)),
            (
                P::EnableLongDistanceMatching(ParamSwitch::Enable),
                C::EnableLongDistanceMatching(true),
            ),
            (P::LdmMinMatch(16), C::LdmMinMatch(16)),
            (P::LdmHashRateLog(2), C::LdmHashRateLog(2)),
            (
                P::JobSize(JOBSIZE_MIN as u32),
                C::JobSize(JOBSIZE_MIN as u32),
            ),
            (P::OverlapLog(overlap), C::OverlapSizeLog(overlap as u32)),
            (P::ChecksumFlag(true), C::ChecksumFlag(true)),
            (P::NbWorkers(1 + i as u32 * 2), C::NbWorkers(2 + i as u32)),
        ];
        for param in params {
            set_both(&mut c, &mut p, param).expect("both set it");
        }
        if let Err(problem) = compare_compress2(&mut c, &mut p, &src, Active::None) {
            problems.add(format!(
                "level {level_}, window log {window_log}: {problem}"
            ));
        }
    }
    problems.check();
}

/// With a prefix of a whole window (overlap logs 8 and 9) and jobs of
/// several windows (the default size), a job's matches stop a window back,
/// though the data repeats from one to two windows back: the prefix is part
/// of the job's window, not a dictionary reached whole (libzstd sets
/// `ZSTD_c_forceMaxWindow` for it, and drops it as a dictionary at the
/// first block anyway, as it lies in the input's segment).
#[test]
fn jobs_keep_to_the_window() {
    let mut problems = Problems::default();
    let mut compared = 0;
    let mut rng = Rng(0x4D54_0600);
    let configs: &[(i32, u32, u32)] = &[
        (3, 17, 9),
        (6, 18, 8),
        (12, 17, 9),
        (16, 17, 9),
        (19, 18, 9),
    ];
    for &(level_, window_log, overlap) in configs {
        if (cfg!(target_endian = "big") || EMULATED) && level_ >= 4 {
            continue;
        }
        let window = 1usize << window_log;
        // Jobs of 1 MB, 4 windows: two of them, and some.
        let len = 2_200_000 + rng.range(0, 300_000) as usize;
        let mut src = data(&mut rng, window);
        while src.len() < len {
            // A copy from between one and two windows back.
            let back = rng.range(window as u64 + 1000, 2 * window as u64 - 1000) as usize;
            let size = (rng.range(2000, 20_000) as usize).min(src.len().saturating_sub(back));
            if back < src.len() {
                let at = src.len() - back;
                src.extend_from_within(at..at + size);
            }
            let n = rng.range(100, 3000) as usize;
            src.extend(data(&mut rng, n));
        }
        let mut c = zstd_safe::CCtx::create();
        let mut p = CCtx::new();
        let params = [
            level(level_),
            (P::WindowLog(window_log), C::WindowLog(window_log)),
            (P::OverlapLog(overlap as i32), C::OverlapSizeLog(overlap)),
            (P::NbWorkers(3), C::NbWorkers(2)),
        ];
        for param in params {
            set_both(&mut c, &mut p, param).expect("both set it");
        }
        match compare_compress2(&mut c, &mut p, &src, Active::None) {
            Ok(_) => compared += 1,
            Err(problem) => {
                problems.add(format!(
                    "level {level_}, window log {window_log}: {problem}"
                ));
            }
        }
    }
    println!("{compared} frames compared");
    problems.check();
}

/// The parameters' rules: libzstd clamps them to their bounds; the job
/// size is raised to the smallest, but 0; only between frames.
#[test]
fn parameters_follow_libzstd_rules() {
    let mut p = CCtx::new();
    let cases = [
        (P::NbWorkers(0), K::NbWorkers, 0),
        (P::NbWorkers(7), K::NbWorkers, 7),
        (P::NbWorkers(300), K::NbWorkers, 256),
        (P::NbWorkers(u32::MAX), K::NbWorkers, 256),
        (P::JobSize(0), K::JobSize, 0),
        (P::JobSize(1), K::JobSize, JOBSIZE_MIN as i32),
        (P::JobSize(600_000), K::JobSize, 600_000),
        (P::JobSize(u32::MAX), K::JobSize, 1 << 30),
        (P::OverlapLog(-3), K::OverlapLog, 0),
        (P::OverlapLog(5), K::OverlapLog, 5),
        (P::OverlapLog(12), K::OverlapLog, 9),
        (P::Rsyncable(true), K::Rsyncable, 1),
        (P::Rsyncable(false), K::Rsyncable, 0),
    ];
    for (param, kind, value) in cases {
        p.set_parameter(param).expect("set");
        assert_eq!(p.get_parameter(kind), value, "{param:?}");
    }
    // While a frame is streamed, none can be set; but the compression
    // parameters. Jobs of the default size: one of 1 GB asks for that
    // much room for its output, more than a 32-bit machine may give.
    p.set_parameter(P::JobSize(0)).expect("set");
    p.set_parameter(P::NbWorkers(2)).expect("set");
    let mut out = vec![0u8; 1000];
    let mut output = OutBuffer::new(&mut out);
    let mut input = InBuffer::new(b"some input");
    p.compress_stream2(&mut output, &mut input, EndDirective::Continue)
        .expect("starts");
    for param in [
        P::NbWorkers(3),
        P::JobSize(0),
        P::OverlapLog(3),
        P::Rsyncable(true),
    ] {
        let error = p.set_parameter(param).expect_err("refused");
        assert_eq!(error.code(), ErrorCode::StageWrong, "{param:?}");
    }
    p.set_parameter(P::CompressionLevel(9)).expect("allowed");
    // And the frame is ended with the workers, whatever the timing.
    let mut frame = Vec::new();
    loop {
        let mut output = OutBuffer::new(&mut out);
        let remaining = p.end_stream(&mut output).expect("ends");
        let written = output.pos;
        frame.extend_from_slice(&out[..written]);
        if remaining == 0 {
            break;
        }
    }
    decodes(&frame, b"some input", Active::None).expect("decodes");
}

/// The contexts move between threads; pools of threads are shared
/// between them.
#[test]
fn contexts_are_send() {
    fn send<T: Send>() {}
    fn sync<T: Send + Sync>() {}
    send::<CCtx>();
    sync::<ThreadPool>();
}

/// Contexts on threads of their own that share a pool of threads
/// (`ZSTD_CCtx_refThreadPool`) write libzstd's frames, in one call and
/// streaming: pools of fewer threads than the contexts have workers, one
/// thread for all of them; contexts that change their number of workers
/// between frames, and so resize the pool for all; one that refers to the
/// pool once its workers' context is made, which keeps its own threads as
/// in libzstd; and one dropped in the middle of a frame, whose jobs end on
/// the pool while the others go on.
#[test]
#[allow(clippy::too_many_lines)]
fn contexts_share_a_thread_pool() {
    let mut rng = Rng(0x4D54_0700);
    let len = scaled(2_000_000);
    // On big-endian machines, levels up to 3 only: from `greedy` up,
    // libzstd's block splitter hashes in the machine's byte order there.
    let levels = if cfg!(target_endian = "big") {
        [1, 3, 2, -1]
    } else {
        [1, 3, 7, 19]
    };
    let inputs: Vec<Vec<u8>> = levels.iter().map(|_| data(&mut rng, len)).collect();
    let steps: Vec<Vec<Step>> = levels.iter().map(|_| steps(&mut rng, len)).collect();
    // libzstd's frames, with threads of its own: in each of two rounds, one
    // in one call, and one streamed, whose steps set parameters for the
    // frames after too.
    let want: Vec<Vec<Vec<u8>>> = inputs
        .iter()
        .zip(&steps)
        .zip(levels)
        .map(|((input, steps), level)| {
            let mut c = zstd_safe::CCtx::create();
            c.set_parameter(C::CompressionLevel(level))
                .expect("a level");
            c.set_parameter(C::NbWorkers(2)).expect("workers");
            let mut frames = Vec::new();
            for _ in 0..2 {
                frames.push(libzstd_compress2(&mut c, input).expect("libzstd compresses"));
                let mut side = Libzstd(c);
                let (streamed, ends, _) = stream_frame(&mut side, input, steps, None);
                c = side.0;
                assert!(
                    ends.iter().all(|end| matches!(end, Ended::Done(_))),
                    "libzstd ended {ends:?}"
                );
                frames.push(streamed);
            }
            frames
        })
        .collect();

    // The pool is refused while a frame is streamed, as in libzstd.
    {
        let pool = ThreadPool::new(2).expect("a pool");
        let c_pool = zstd_safe::ThreadPool::new(2);
        let mut c = zstd_safe::CCtx::create();
        let mut p = CCtx::new();
        set_both(&mut c, &mut p, (P::NbWorkers(2), C::NbWorkers(2))).expect("workers");
        let mut out = vec![0u8; 1000];
        let mut output = zstd_safe::OutBuffer::around(&mut out[..]);
        let mut input = zstd_safe::InBuffer::around(b"some input");
        c.compress_stream2(&mut output, &mut input, ZSTD_EndDirective::ZSTD_e_continue)
            .expect("libzstd starts");
        let mut output = OutBuffer::new(&mut out);
        let mut input = InBuffer::new(b"some input");
        p.compress_stream2(&mut output, &mut input, EndDirective::Continue)
            .expect("the port starts");
        let want = c.ref_thread_pool(&c_pool).map(|_| ()).map_err(name);
        let got = p.ref_thread_pool(Some(&pool)).map_err(message);
        assert_eq!(want, got, "a pool referred to in the middle of a frame");
        assert!(want.is_err());
        assert_eq!(
            p.ref_thread_pool(None).map_err(|error| error.code()),
            Err(ErrorCode::StageWrong)
        );
    }
    assert!(zstd_safe::ThreadPool::try_new(0).is_none());
    assert_eq!(
        ThreadPool::new(0).map(|_| ()).map_err(|error| error.code()),
        Err(ErrorCode::MemoryAllocation)
    );

    for threads in [1, 2, 3] {
        let pool = ThreadPool::new(threads).expect("a pool");
        std::thread::scope(|scope| {
            // One dropped in the middle of a frame: its jobs go on, on the
            // pool.
            let pool_ = pool.clone();
            let input = &inputs[0];
            scope.spawn(move || {
                let mut p = CCtx::new();
                p.ref_thread_pool(Some(&pool_)).expect("a pool");
                p.set_parameter(P::NbWorkers(4)).expect("workers");
                p.set_parameter(P::JobSize(JOBSIZE_MIN as u32))
                    .expect("jobs");
                let mut out = vec![0u8; 1 << 16];
                let mut output = OutBuffer::new(&mut out);
                let mut input = InBuffer::new(input);
                p.compress_stream2(&mut output, &mut input, EndDirective::Continue)
                    .expect("starts");
            });
            for (i, (((input, steps), level), want)) in
                inputs.iter().zip(&steps).zip(levels).zip(&want).enumerate()
            {
                let pool = &pool;
                scope.spawn(move || {
                    let tag = format!("{threads} threads, context {i}");
                    let mut p = CCtx::new();
                    p.set_parameter(P::CompressionLevel(level))
                        .expect("a level");
                    p.set_parameter(P::NbWorkers(1 + 2 * i as u32))
                        .expect("workers");
                    if i == 3 {
                        // Its own threads first, then the pool, which it
                        // does not take.
                        let got = port_compress2(&mut p, input).expect("compresses");
                        assert!(got == want[0], "{tag}: the frames differ");
                    }
                    p.ref_thread_pool(Some(pool)).expect("a pool");
                    for round in 0..2 {
                        if round == 1 && i == 1 {
                            // Another number of workers: the pool resized.
                            p.set_parameter(P::NbWorkers(5)).expect("workers");
                        }
                        let got = port_compress2(&mut p, input).expect("compresses");
                        assert!(
                            got == want[2 * round],
                            "{tag}, round {round}: the frames differ"
                        );
                        let mut side = Port(p);
                        let (got, ends, _) = stream_frame(&mut side, input, steps, None);
                        p = side.0;
                        assert!(
                            ends.iter().all(|end| matches!(end, Ended::Done(_))),
                            "{tag}, round {round}: the port ended {ends:?}"
                        );
                        assert!(
                            got == want[2 * round + 1],
                            "{tag}, round {round}: the streams differ"
                        );
                    }
                });
            }
        });
    }
}

/// Silesia files, when fetched (the `bench` group), at levels 1, 3, 9 and
/// 19; the first few megabytes of each, in jobs of the default size and of
/// the smallest.
#[test]
fn silesia_with_workers() {
    let manifest = support::manifest();
    let Some(set) = manifest.sets.iter().find(|set| set.name == "silesia") else {
        return;
    };
    // Only where fetched, and not in slow runs.
    if SLOW || !set.folder().join(".complete").exists() {
        eprintln!("skipping: silesia is not fetched, or the run is slow");
        return;
    }
    let mut problems = Problems::default();
    let mut compared = 0;
    for (i, file) in ["dickens", "mozilla", "xml", "sao", "ooffice", "x-ray"]
        .iter()
        .enumerate()
    {
        let Ok(content) = std::fs::read(set.folder().join(file)) else {
            continue;
        };
        let src = &content[..content.len().min(6 << 20)];
        for (j, level_) in [1, 3, 9, 19].into_iter().enumerate() {
            let mut c = zstd_safe::CCtx::create();
            let mut p = CCtx::new();
            let job_size = if (i + j) % 2 == 0 {
                0
            } else {
                JOBSIZE_MIN as u32
            };
            let params = [
                level(level_),
                (P::JobSize(job_size), C::JobSize(job_size)),
                (P::ChecksumFlag(true), C::ChecksumFlag(true)),
                (P::NbWorkers(1 + (i + j) as u32 % 8), C::NbWorkers(4)),
            ];
            for param in params {
                set_both(&mut c, &mut p, param).expect("both set it");
            }
            match compare_compress2(&mut c, &mut p, src, Active::None) {
                Ok(_) => compared += 1,
                Err(problem) => problems.add(format!("{file} at level {level_}: {problem}")),
            }
        }
    }
    println!("{compared} frames compared");
    problems.check();
}

/// A context let go while its jobs compress, as a job stopped lets it go,
/// ends soon: the jobs stop at their next chunk, where libzstd waits for
/// them to be done, many seconds at the highest levels.
#[test]
fn let_go_while_compressing_ends_soon() {
    // Words and noise, which level 19 takes its time over.
    let mut rng = Rng(0x5701);
    // More than two jobs of 32 MiB, so that two are handed over.
    let mut input = Vec::with_capacity(70 << 20);
    while input.len() < 70 << 20 {
        let x = rng.next();
        match x % 8 {
            0 => input.extend((0..x % 200).map(|i| (x >> (i % 56)) as u8)),
            n => input.extend_from_slice(
                ["packwing ", "zstd ", "thread ", "job\n"][n as usize % 4].as_bytes(),
            ),
        }
    }
    let mut cctx = hivepack::zstd::CCtx::new();
    cctx.set_parameter(hivepack::zstd::CParameter::CompressionLevel(19))
        .unwrap();
    cctx.set_parameter(hivepack::zstd::CParameter::NbWorkers(2))
        .unwrap();
    let mut out = vec![0; 1 << 20];
    let mut output = hivepack::zstd::OutBuffer::new(&mut out);
    let mut from = hivepack::zstd::InBuffer::new(&input);
    while from.pos < input.len() {
        output.pos = 0;
        cctx.compress_stream2(
            &mut output,
            &mut from,
            hivepack::zstd::EndDirective::Continue,
        )
        .unwrap();
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    let at = std::time::Instant::now();
    drop(cctx);
    let took = at.elapsed();
    // 4 MiB at level 19, on this machine and in this build: a job stops
    // at its next chunk of 512 KiB, after the window of the job before is
    // loaded if it was loading, within about that; the rest of the two
    // jobs, 32 MiB each, would take many times longer.
    let at = std::time::Instant::now();
    let mut one = hivepack::zstd::CCtx::new();
    one.set_parameter(hivepack::zstd::CParameter::CompressionLevel(19))
        .unwrap();
    let mut out = vec![0; 5 << 20];
    one.compress2(&mut out, &input[..4 << 20]).unwrap();
    let four_mib = at.elapsed();
    assert!(took < four_mib * 3, "{took:?}, 4 MiB in {four_mib:?}");
}
