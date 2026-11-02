//! Compresses with a target size for compressed blocks
//! (`ZSTD_c_targetCBlockSize`, the superblocks of
//! `compress/zstd_compress_superblock.c`) through the port and libzstd
//! 1.5.7, with the same parameters, and compares the frames byte for byte;
//! then decodes the port's frames back.
//!
//! At every level and strategy, with targets from below the smallest
//! (raised to it) to the largest; on the test data; with dictionaries
//! loaded, referenced as `CDict`s and prefixes; with checksums, the block
//! splitters (which the target takes precedence over) and long distance
//! matching; streaming, with flushes; on data that does not compress, or
//! is one byte repeated; and with too little room for the frame. The
//! parameter's bounds and rules, against libzstd's.
//!
//! `tests/compress_stream.rs` and `tests/compress_mt.rs` set the target
//! among their random parameters too, streaming call by call and with
//! workers.
//!
//! Inputs are smaller in debug builds, and smaller still on the machines CI
//! emulates (32-bit and big-endian). On big-endian machines the frames
//! leave out the strategies from `greedy` up for inputs of 128 KB or more:
//! libzstd's block splitter hashes bytes in the machine's order there.

#![allow(clippy::expect_used, clippy::panic)]

#[path = "zstd_support/mod.rs"]
mod support;

use std::sync::Arc;

use hivepack::zstd::{
    CCtx, CDict, CParameter as P, CParameterKind as K, DCtx, DictAttachPref, EndDirective,
    ErrorCode, Format, ParamSwitch, ResetDirective, Strategy,
};
use support::{Kind, Problems, Rng, Set};
use zstd::zstd_safe::{self, CParameter as C, FrameFormat, zstd_sys::ZSTD_EndDirective};

/// Builds without optimizations, and emulated machines.
const SLOW: bool = cfg!(debug_assertions) || EMULATED;
/// The machines CI runs under emulation, far slower still.
const EMULATED: bool = cfg!(any(target_pointer_width = "32", target_endian = "big"));

/// The targets: below the smallest (raised to it), the smallest, small
/// ones, typical ones, large ones and the largest.
const TARGETS: [u32; 11] = [
    1, 1340, 1341, 1500, 2048, 4096, 9000, 16_384, 50_000, 100_000, 131_072,
];

/// Every level.
const LEVELS: [i32; 30] = [
    -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22,
];

/// Room past the end of the room libzstd's buffers are given, and before
/// it: where room for output is tight, libzstd's superblocks write past
/// its end (see `src/compress/zstd_compress_superblock.rs`), up to a block
/// of literals; with the slack that lands in memory of the buffer's own.
const SLACK: usize = 1 << 18;

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

fn target(value: u32) -> Param {
    (P::TargetCBlockSize(value), C::TargetCBlockSize(value))
}

fn level(level: i32) -> Param {
    (P::CompressionLevel(level), C::CompressionLevel(level))
}

fn split_after_sequences(pick: u64) -> Param {
    let (p, c) = match pick % 3 {
        0 => (ParamSwitch::Auto, zstd_safe::ParamSwitch::Auto),
        1 => (ParamSwitch::Enable, zstd_safe::ParamSwitch::Enable),
        _ => (ParamSwitch::Disable, zstd_safe::ParamSwitch::Disable),
    };
    (P::SplitAfterSequences(p), C::UseBlockSplitter(c))
}

/// Every strategy, with libzstd's.
fn strategies() -> [(Strategy, zstd_safe::Strategy); 9] {
    use zstd_safe::Strategy as S;
    [
        (Strategy::Fast, S::ZSTD_fast),
        (Strategy::Dfast, S::ZSTD_dfast),
        (Strategy::Greedy, S::ZSTD_greedy),
        (Strategy::Lazy, S::ZSTD_lazy),
        (Strategy::Lazy2, S::ZSTD_lazy2),
        (Strategy::Btlazy2, S::ZSTD_btlazy2),
        (Strategy::Btopt, S::ZSTD_btopt),
        (Strategy::Btultra, S::ZSTD_btultra),
        (Strategy::Btultra2, S::ZSTD_btultra2),
    ]
}

/// Whether the machine leaves a frame out: on big-endian machines,
/// libzstd's block splitter, which the strategies from `greedy` up use on
/// full blocks, hashes pairs of bytes in the machine's order and splits
/// elsewhere. `strong` is for a level from 4 or a strategy from `greedy`.
fn left_out(strong: bool, len: usize) -> bool {
    cfg!(target_endian = "big") && strong && len >= 128 << 10
}

/// Data with repeats near and far: text-like pieces, runs of a byte, noise,
/// and copies of larger pieces from anywhere before.
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

/// `noise` bytes of noise, then pieces of 31 bytes of it behind a `Q` each,
/// to `len` bytes: the strongest levels find every piece, so that the
/// literals of the blocks after the noise, when they start where it ends,
/// are all `Q`, which their sub-blocks store as one byte repeated.
fn rle_literals_data(rng: &mut Rng, noise: usize, len: usize) -> Vec<u8> {
    let mut data: Vec<u8> = (0..noise).map(|_| rng.next() as u8).collect();
    while data.len() < len {
        data.push(b'Q');
        let at = rng.range(0, (noise - 31) as u64) as usize;
        data.extend_from_within(at..at + 31);
    }
    data
}

/// Periods of 15 bytes of noise, then 5 fixed bytes: with a window of 4 KB
/// ([`periodic_params`]), every match is of the 5 bytes, at the first
/// repeat offset, after 15 literals, so that each kind of code is one
/// symbol, with no extra bits. In the sub-blocks after the first, which
/// use the tables again, the sequences then take one byte, which the
/// decoders of zstd 1.4.0 and earlier would refuse: they are stored raw,
/// and the repeat offsets worked out again. The first and the last byte of
/// each period are unique among the periods the window reaches, so that no
/// match reaches into them. Every `every` periods (when not 0), the fixed
/// bytes are the last one repeated: a match at another repeat offset.
fn periodic_data(rng: &mut Rng, len: usize, every: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(len + 20);
    let mut firsts: Vec<u8> = Vec::new();
    let mut lasts: Vec<u8> = Vec::new();
    let pick = |rng: &mut Rng, used: &[u8], not: Option<u8>| loop {
        let v = rng.next() as u8;
        if !v.is_ascii_uppercase()
            && Some(v) != not
            && !used.iter().rev().take(210).any(|&u| u == v)
        {
            break v;
        }
    };
    let mut k = 0;
    while data.len() < len {
        k += 1;
        let first = pick(rng, &firsts, lasts.last().copied());
        let last = pick(rng, &lasts, None);
        firsts.push(first);
        lasts.push(last);
        data.push(first);
        for _ in 0..13 {
            data.push(0x80 | rng.next() as u8);
        }
        data.push(last);
        if every != 0 && k % every == 0 {
            data.extend_from_slice(&[last; 5]);
        } else {
            data.extend_from_slice(b"ABCDE");
        }
    }
    data
}

/// The parameters for [`periodic_data`].
fn periodic_params() -> [Param; 2] {
    [
        (P::WindowLog(12), C::WindowLog(12)),
        (P::MinMatch(5), C::MinMatch(5)),
    ]
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

/// `compress2` of `src` with both, with `room` bytes for the frame (the
/// bound when `None`): the same frame, which decodes back, or the same
/// error. Returns whether there was a frame.
fn compare_compress2(
    c: &mut zstd_safe::CCtx<'_>,
    p: &mut CCtx,
    src: &[u8],
    room: Option<usize>,
    dict: Active<'_>,
) -> Result<bool, String> {
    let room = room.unwrap_or_else(|| hivepack::zstd::compress_bound(src.len()).expect("a bound"));
    let mut c_out = vec![0u8; SLACK + room + SLACK];
    let want = c
        .compress2(&mut c_out[SLACK..SLACK + room], src)
        .map(|size| c_out[SLACK..SLACK + size].to_vec())
        .map_err(name);
    // libzstd's context waits for a reset after an error.
    c.reset(zstd_safe::ResetDirective::SessionOnly)
        .expect("libzstd resets");
    let mut p_out = vec![0u8; room];
    let got = p
        .compress2(&mut p_out, src)
        .map(|size| p_out[..size].to_vec())
        .map_err(message);
    match (&want, &got) {
        (Ok(want), Ok(got)) if want == got => {
            decodes(got, src, dict)?;
            Ok(true)
        }
        (Ok(want), Ok(got)) => {
            let at = want
                .iter()
                .zip(got)
                .position(|(a, b)| a != b)
                .unwrap_or(want.len().min(got.len()));
            Err(format!(
                "frames of {} and {} bytes, differing at byte {at}",
                want.len(),
                got.len()
            ))
        }
        (Err(want), Err(got)) if want == got => Ok(false),
        // On 32-bit machines libzstd's bit streams decide whether they fit
        // 4 bytes before the end of their room, the size of their register;
        // the port decides 8 bytes before, as libzstd does on 64-bit
        // machines (`docs/porting.md`, "64-bit results"). With room for
        // less than 8 bytes past the frame, libzstd can fit it there where
        // the port finds too little room.
        (Ok(want), Err(got))
            if cfg!(target_pointer_width = "32")
                && got == "Destination buffer is too small"
                && room < want.len() + 8 =>
        {
            Ok(false)
        }
        _ => Err(format!(
            "libzstd {:?}, port {:?}",
            want.map(|frame| frame.len()),
            got.map(|frame| frame.len())
        )),
    }
}

/// Both contexts, new, with `params`.
fn contexts(params: &[Param]) -> (zstd_safe::CCtx<'static>, CCtx) {
    let mut c = zstd_safe::CCtx::create();
    let mut p = CCtx::new();
    for &param in params {
        set_both(&mut c, &mut p, param).expect("both set it");
    }
    (c, p)
}

/// The bounds, raising, refusals and default, against libzstd's; libzstd's
/// `ZSTD_CCtx_setParameter` returns the value it keeps.
#[test]
fn the_parameter_follows_libzstd_rules() {
    let mut c = zstd_safe::CCtx::create();
    let mut p = CCtx::new();
    assert_eq!(p.get_parameter(K::TargetCBlockSize), 0, "the default");
    let mut kept = 0;
    for value in [
        0,
        1,
        2,
        63,
        64,
        81,
        1000,
        1339,
        1340,
        1341,
        4096,
        100_000,
        131_071,
        131_072,
        131_073,
        1 << 20,
        i32::MAX as u32,
        0,
        5000,
    ] {
        let want = c.set_parameter(C::TargetCBlockSize(value)).map_err(name);
        let got = p.set_parameter(P::TargetCBlockSize(value)).map_err(message);
        assert_eq!(want.clone().map(drop), got, "setting {value}");
        if let Ok(value) = want {
            kept = value as i32;
        }
        assert_eq!(p.get_parameter(K::TargetCBlockSize), kept, "after {value}");
    }
    // libzstd takes an int: past i32::MAX it would read a negative value,
    // and raise it to the smallest target. The port refuses them as large.
    for value in [i32::MAX as u32 + 1, u32::MAX] {
        let got = p.set_parameter(P::TargetCBlockSize(value));
        assert_eq!(
            got.map_err(|error| error.code()),
            Err(ErrorCode::ParameterOutOfBound),
            "setting {value}"
        );
        assert_eq!(p.get_parameter(K::TargetCBlockSize), kept);
    }

    // Only between frames.
    let content = data(&mut Rng(3), 10_000);
    let mut c_out = vec![0u8; 1 << 16];
    let mut c_output = zstd_safe::OutBuffer::around(&mut c_out[..]);
    let mut c_input = zstd_safe::InBuffer::around(&content[..]);
    c.compress_stream2(
        &mut c_output,
        &mut c_input,
        ZSTD_EndDirective::ZSTD_e_continue,
    )
    .expect("libzstd takes it");
    let mut p_out = vec![0u8; 1 << 16];
    let mut p_output = hivepack::zstd::OutBuffer::new(&mut p_out);
    let mut p_input = hivepack::zstd::InBuffer::new(&content);
    p.compress_stream2(&mut p_output, &mut p_input, EndDirective::Continue)
        .expect("the port takes it");
    set_both(&mut c, &mut p, target(2000)).expect("both refuse it");
    assert_eq!(
        p.set_parameter(P::TargetCBlockSize(2000))
            .map_err(|error| error.code()),
        Err(ErrorCode::StageWrong)
    );
    assert_eq!(p.get_parameter(K::TargetCBlockSize), kept);

    // Resetting the parameters takes it back to 0.
    c.reset(zstd_safe::ResetDirective::SessionAndParameters)
        .expect("libzstd resets");
    p.reset(ResetDirective::SessionAndParameters)
        .expect("the port resets");
    assert_eq!(p.get_parameter(K::TargetCBlockSize), 0);
    let frame = compare_compress2(&mut c, &mut p, &content, None, Active::None);
    assert_eq!(frame, Ok(true));
}

/// `ZSTD_compressCCtx`, `ZSTD_compress_usingDict` and
/// `ZSTD_compress_usingCDict` take their parameters from the level or the
/// `CDict`, not from those set: the target changes nothing there. The
/// frames are those of libzstd with the target set, and without.
#[test]
fn one_call_compression_leaves_the_target_out() {
    let mut problems = Problems::default();
    let mut rng = Rng(11);
    let content = data(&mut rng, scaled(300_000));
    let dict = rng.data(5000, &content);
    let bound = hivepack::zstd::compress_bound(content.len()).expect("a bound");
    let (mut c, mut p) = contexts(&[target(1340)]);
    let mut plain = zstd_safe::CCtx::create();
    for level in [-3, 1, 3, 7, 13, 19] {
        if left_out(level >= 4, content.len()) {
            continue;
        }
        let c_cdict = zstd_safe::CDict::create(&dict, level);
        let p_cdict = CDict::new(&dict, level).expect("a CDict");
        for call in ["compress", "compress_using_dict", "compress_using_cdict"] {
            let mut want = vec![0u8; bound];
            let mut without = vec![0u8; bound];
            let mut got = vec![0u8; bound];
            let (want_size, without_size, got_size) = match call {
                "compress" => (
                    c.compress(&mut want[..], &content, level),
                    plain.compress(&mut without[..], &content, level),
                    p.compress(&mut got, &content, level),
                ),
                "compress_using_dict" => (
                    c.compress_using_dict(&mut want[..], &content, &dict, level),
                    plain.compress_using_dict(&mut without[..], &content, &dict, level),
                    p.compress_using_dict(&mut got, &content, &dict, level),
                ),
                _ => (
                    c.compress_using_cdict(&mut want[..], &content, &c_cdict),
                    plain.compress_using_cdict(&mut without[..], &content, &c_cdict),
                    p.compress_using_cdict(&mut got, &content, &p_cdict),
                ),
            };
            match (want_size, without_size, got_size) {
                (Ok(w), Ok(o), Ok(g)) if want[..w] == got[..g] && without[..o] == got[..g] => {}
                (w, o, g) => problems.add(format!(
                    "{call} at level {level}: libzstd {w:?}, without the target {o:?}, port \
                     {g:?}"
                )),
            }
        }
    }
    problems.check();
}

/// At every level, on data that changes, and with every strategy set, at
/// every target; the block splitter after the sequences (on, off or the
/// strategy's choice, which the target takes precedence over), checksums,
/// the shortest match of 3 bytes, small blocks.
#[test]
fn every_level_and_strategy_compresses_with_a_target_as_libzstd() {
    let mut problems = Problems::default();
    let mut rng = Rng(1);
    let sizes = [
        0,
        1,
        7,
        100,
        1000,
        5000,
        scaled(70_000),
        scaled(300_000),
        scaled(600_000),
    ];
    let mut compared = 0;
    for (i, &level_) in LEVELS.iter().enumerate() {
        if EMULATED && level_ > 19 {
            continue;
        }
        for (j, &len) in sizes.iter().enumerate() {
            if left_out(level_ >= 4, len) || (SLOW && level_ >= 16 && len > 100_000) {
                continue;
            }
            let content = data(&mut rng, len);
            let target_ = TARGETS[(i + j) % TARGETS.len()];
            let mut params = vec![
                level(level_),
                target(target_),
                split_after_sequences(rng.next()),
            ];
            if rng.chance(3) {
                params.push((P::ChecksumFlag(true), C::ChecksumFlag(true)));
            }
            let (mut c, mut p) = contexts(&params);
            match compare_compress2(&mut c, &mut p, &content, None, Active::None) {
                Ok(_) => compared += 1,
                Err(problem) => problems.add(format!(
                    "level {level_}, {len} bytes, target {target_}: {problem}"
                )),
            }
        }
    }
    for (s, (ps, cs)) in strategies().into_iter().enumerate() {
        for (t, &target_) in TARGETS.iter().enumerate() {
            let len = [scaled(200_000), 30_000, scaled(400_000)][t % 3];
            if left_out(ps >= Strategy::Greedy, len) {
                continue;
            }
            let content = data(&mut rng, len);
            let mut params = vec![
                level([1, 3, 6, 9, 15, 19][(s + t) % 6]),
                (P::Strategy(Some(ps)), C::Strategy(cs)),
                target(target_),
                split_after_sequences(rng.next()),
            ];
            if rng.chance(2) {
                params.push((P::MinMatch(3), C::MinMatch(3)));
            }
            if rng.chance(3) {
                let value = [1024, 4096, 65_536][rng.range(0, 2) as usize];
                params.push((P::MaxBlockSize(value), C::MaxBlockSize(value)));
            }
            if rng.chance(4) {
                params.push((
                    P::LiteralCompressionMode(ParamSwitch::Disable),
                    C::LiteralCompressionMode(zstd_safe::ParamSwitch::Disable),
                ));
            }
            if rng.chance(4) {
                params.push((
                    P::Format(Format::Zstd1Magicless),
                    C::Format(FrameFormat::Magicless),
                ));
            }
            let (mut c, mut p) = contexts(&params);
            let magicless = p.get_parameter(K::Format) == 1;
            let result = if magicless {
                // The port decodes magicless frames only when told to.
                let mut c_out = vec![0u8; hivepack::zstd::compress_bound(len).expect("a bound")];
                let mut p_out = c_out.clone();
                let want = c.compress2(&mut c_out[..], &content).map_err(name);
                let got = p.compress2(&mut p_out, &content).map_err(message);
                match (want, got) {
                    (Ok(w), Ok(g)) if c_out[..w] == p_out[..g] => Ok(true),
                    (want, got) => Err(format!("libzstd {want:?}, port {got:?}")),
                }
            } else {
                compare_compress2(&mut c, &mut p, &content, None, Active::None)
            };
            match result {
                Ok(_) => compared += 1,
                Err(problem) => problems.add(format!(
                    "{ps:?}, {len} bytes, target {target_}, {params:?}: {problem}"
                )),
            }
        }
    }
    println!("{compared} frames compared");
    assert!(compared > 250, "only {compared} frames compared");
    problems.check();
}

/// Data that does not compress, and data of one byte repeated, whose blocks
/// after the first are RLE; data that compresses and then does not within
/// a block, so that its last sub-block is stored raw and the repeat
/// offsets are worked out again; data whose sub-blocks' literals are one
/// byte repeated, and data whose sub-blocks' sequences are too short for
/// old decoders (see [`rle_literals_data`] and [`periodic_data`]); and
/// every size up to 300 bytes.
#[test]
fn incompressible_and_rle_inputs_compress_with_a_target_as_libzstd() {
    let mut problems = Problems::default();
    let mut rng = Rng(2);
    let len = scaled(400_000);
    let noise: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
    let run = vec![b'z'; len];
    let mut runs = Vec::new();
    while runs.len() < len {
        let byte = rng.next() as u8;
        let n = rng.range(1, 300_000) as usize;
        runs.resize(runs.len() + n, byte);
    }
    runs.truncate(len);
    // Text, then noise, in each block of 128 KB.
    let mut half = Vec::new();
    while half.len() < len {
        let text_len = rng.range(10_000, 120_000) as usize;
        let text = rng.data(text_len, b"the quick brown fox");
        let n = (131_072 - text.len() % 131_072).min(rng.range(10, 40_000) as usize);
        half.extend(text);
        half.extend((0..n).map(|_| rng.next() as u8));
    }
    half.truncate(len);
    // Pieces that compress and pieces that do not, in turn.
    let mut mixed = Vec::new();
    while mixed.len() < len {
        let n = rng.range(100, 20_000) as usize;
        if rng.chance(2) {
            mixed.extend((0..n).map(|_| rng.next() as u8));
        } else {
            mixed.extend(rng.data(n, b"lorem ipsum dolor sit amet"));
        }
    }
    mixed.truncate(len);
    let mut compared = 0;
    // Literals of one byte, at the levels that find every piece.
    let rle_literals = rle_literals_data(&mut rng, 131_072, 131_072 + scaled(300_000));
    for (t, &target_) in TARGETS.iter().enumerate() {
        let level_ = [16, 19][t % 2];
        if left_out(true, rle_literals.len()) || (SLOW && t % 3 != 0) {
            continue;
        }
        let (mut c, mut p) = contexts(&[level(level_), target(target_)]);
        match compare_compress2(&mut c, &mut p, &rle_literals, None, Active::None) {
            Ok(_) => compared += 1,
            Err(problem) => problems.add(format!(
                "literals of one byte at level {level_}, target {target_}: {problem}"
            )),
        }
    }
    // Sequences too short for old decoders, at every level.
    for (i, every) in [0, 150].into_iter().enumerate() {
        let periodic = periodic_data(&mut rng, scaled(200_000), every);
        for (j, &level_) in [-3, 1, 3, 5, 9, 16, 19].iter().enumerate() {
            let target_ = TARGETS[(i + j) % 3];
            let mut params = vec![level(level_), target(target_)];
            params.extend(periodic_params());
            let (mut c, mut p) = contexts(&params);
            match compare_compress2(&mut c, &mut p, &periodic, None, Active::None) {
                Ok(_) => compared += 1,
                Err(problem) => problems.add(format!(
                    "periodic data ({every}) at level {level_}, target {target_}: {problem}"
                )),
            }
        }
    }
    for (what, content) in [
        ("noise", &noise),
        ("one byte", &run),
        ("runs", &runs),
        ("text then noise", &half),
        ("mixed", &mixed),
    ] {
        for (i, &level_) in [-5, 1, 3, 5, 8, 12, 16, 19].iter().enumerate() {
            if left_out(level_ >= 4, content.len()) {
                continue;
            }
            for (t, &target_) in TARGETS.iter().enumerate() {
                if SLOW && (i + t) % 3 != 0 {
                    continue;
                }
                let mut params = vec![level(level_), target(target_)];
                if t % 4 == 1 {
                    let value = [1024, 4096, 20_000][(i + t) % 3];
                    params.push((P::MaxBlockSize(value), C::MaxBlockSize(value)));
                }
                let (mut c, mut p) = contexts(&params);
                match compare_compress2(&mut c, &mut p, content, None, Active::None) {
                    Ok(_) => compared += 1,
                    Err(problem) => problems.add(format!(
                        "{what} at level {level_}, target {target_}: {problem}"
                    )),
                }
            }
        }
    }
    // Every size up to 300 bytes, where blocks are raw, RLE or too small to
    // compress; one context for each level, used again.
    let text = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod \
        tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis \
        nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.";
    for level_ in [-1, 1, 3, 6, 13, 19] {
        let (mut c, mut p) = contexts(&[level(level_), target(1340)]);
        for len in 0..=300 {
            let a = vec![b'a'; len];
            let lorem: Vec<u8> = text.iter().copied().cycle().take(len).collect();
            for (what, content) in [("a", &a), ("text", &lorem)] {
                match compare_compress2(&mut c, &mut p, content, None, Active::None) {
                    Ok(_) => compared += 1,
                    Err(problem) => {
                        problems.add(format!("{len} of {what} at level {level_}: {problem}"));
                    }
                }
            }
        }
    }
    println!("{compared} frames compared");
    assert!(compared > 1000, "only {compared} frames compared");
    problems.check();
}

/// Dictionaries for the comparisons: zstd dictionaries libzstd trains on a
/// corpus, and pieces of it as raw content, with `CDict`s of them made by
/// both; the frames' data is drawn from the corpus too.
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
        for len in [8, 1000, 20_000, 70_000] {
            let at = rng.range(0, (corpus.len() - len) as u64) as usize;
            dicts.push(corpus[at..at + len].to_vec());
        }
        let mut c_cdicts = Vec::new();
        let mut p_cdicts = Vec::new();
        for (i, dict) in dicts.iter().enumerate() {
            let level = [1, 3, 5, 19, -2, 9, 16][i % 7];
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
        let mut out = Vec::with_capacity(len + 20_000);
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

/// With a dictionary loaded, a `CDict` referenced (attached, copied in or
/// loaded again, as libzstd decides or forced), or a prefix; at levels
/// across the strategies, and targets; contexts used for several frames.
#[test]
fn dictionaries_compress_with_a_target_as_libzstd() {
    let mut problems = Problems::default();
    let mut rng = Rng(0xD1C7);
    let dicts = Dicts::new(&mut rng);
    let mut compared = 0;
    let rounds = if EMULATED {
        20
    } else if SLOW {
        40
    } else {
        120
    };
    for round in 0..rounds {
        let mut c = zstd_safe::CCtx::create();
        let mut p = CCtx::new();
        for frame in 0..3 {
            let tag = format!("round {round}, frame {frame}");
            let level_ = [-3, 1, 2, 3, 4, 5, 6, 8, 11, 13, 16, 18, 19][rng.range(0, 12) as usize];
            let target_ = TARGETS[rng.range(0, TARGETS.len() as u64 - 1) as usize];
            let (pp, cp) = match rng.range(0, 3) {
                0 => (
                    DictAttachPref::DefaultAttach,
                    zstd_safe::DictAttachPref::DefaultAttach,
                ),
                1 => (
                    DictAttachPref::ForceAttach,
                    zstd_safe::DictAttachPref::ForceAttach,
                ),
                2 => (
                    DictAttachPref::ForceCopy,
                    zstd_safe::DictAttachPref::ForceCopy,
                ),
                _ => (
                    DictAttachPref::ForceLoad,
                    zstd_safe::DictAttachPref::ForceLoad,
                ),
            };
            let mut params = vec![
                level(level_),
                target(target_),
                (P::ForceAttachDict(pp), C::ForceAttachDict(cp)),
                split_after_sequences(rng.next()),
            ];
            if rng.chance(3) {
                params.push((P::ChecksumFlag(true), C::ChecksumFlag(true)));
            }
            for param in params {
                if let Err(problem) = set_both(&mut c, &mut p, param) {
                    problems.add(format!("{tag}: {problem}"));
                }
            }
            let i = rng.range(0, dicts.dicts.len() as u64 - 1) as usize;
            let dict = &dicts.dicts[i];
            let (want, got, active) = match rng.range(0, 3) {
                0 => (
                    c.load_dictionary(dict).map(drop).map_err(name),
                    p.load_dictionary(dict).map_err(message),
                    Active::Dict(dict),
                ),
                1 | 2 => (
                    c.ref_cdict(&dicts.c_cdicts[i]).map(drop).map_err(name),
                    p.ref_cdict(Some(dicts.p_cdicts[i].clone()))
                        .map_err(message),
                    Active::Dict(dict),
                ),
                _ => (
                    c.ref_prefix(dict).map(drop).map_err(name),
                    p.ref_prefix(dict).map_err(message),
                    Active::Prefix(dict),
                ),
            };
            if want != got {
                problems.add(format!(
                    "{tag}: the dictionary: libzstd {want:?}, port {got:?}"
                ));
                break;
            }
            let len = [
                rng.range(0, 3000),
                rng.range(0, 40_000),
                rng.range(0, scaled(400_000) as u64),
            ][rng.range(0, 2) as usize] as usize;
            if left_out(level_ >= 4, len) {
                continue;
            }
            let content = dicts.data(&mut rng, len);
            match compare_compress2(&mut c, &mut p, &content, None, active) {
                Ok(_) => compared += 1,
                Err(problem) => problems.add(format!(
                    "{tag} (level {level_}, target {target_}, {len} bytes): {problem}"
                )),
            }
        }
    }
    println!("{compared} frames compared");
    assert!(compared > rounds, "only {compared} frames compared");
    problems.check();
}

/// The test data, a frame per file: one level and one target per file,
/// all of them across the files, sometimes with a checksum and the block
/// splitter on, which the target takes precedence over; every sixth file
/// twice over, with long distance matching, which finds the second copy.
/// One context of each, used again for every frame.
#[test]
fn every_test_file_compresses_with_a_target_as_libzstd() {
    let sets: Vec<Set> = support::manifest()
        .sets
        .into_iter()
        .filter(|set| set.present())
        // Benchmark inputs are too large for the tests; sources and tools
        // are not data.
        .filter(|set| !matches!(set.kind, Kind::Bench | Kind::Source | Kind::Tool))
        .collect();
    let mut problems = Problems::default();
    let mut c = zstd_safe::CCtx::create();
    let mut p = CCtx::new();
    let mut count = 0;
    let mut i = 0;
    for set in sets {
        for file in set.list() {
            i += 1;
            let mut content = set.read(&file);
            let level_ = LEVELS[i % LEVELS.len()];
            // Slow runs leave out the slowest levels on large files.
            if SLOW && level_ >= 16 && content.len() > 64 << 10 {
                continue;
            }
            let target_ = TARGETS[(i / 3) % TARGETS.len()];
            let ldm = i % 6 == 5;
            if ldm {
                content.extend_from_within(..);
            }
            if left_out(level_ >= 4, content.len()) {
                continue;
            }
            let params = [
                level(level_),
                target(target_),
                (P::ChecksumFlag(i % 4 == 0), C::ChecksumFlag(i % 4 == 0)),
                split_after_sequences(i as u64 / 2),
                (
                    P::EnableLongDistanceMatching(if ldm {
                        ParamSwitch::Enable
                    } else {
                        ParamSwitch::Auto
                    }),
                    C::EnableLongDistanceMatching(ldm),
                ),
            ];
            let name = format!(
                "{}/{} at level {level_}, target {target_}{}",
                set.name,
                file.display(),
                if ldm { ", twice, with ldm" } else { "" }
            );
            for param in params {
                set_both(&mut c, &mut p, param).expect("both set it");
            }
            match compare_compress2(&mut c, &mut p, &content, None, Active::None) {
                Ok(_) => count += 1,
                Err(problem) => problems.add(format!("{name}: {problem}")),
            }
        }
    }
    eprintln!("compared {count} frames");
    // The committed sets alone have more than 300 files.
    let least = if SLOW { 150 } else { 300 };
    assert!(count > least, "only {count} frames compared");
    problems.check();
}

/// Where each block of `frame` ends.
fn block_ends(frame: &[u8]) -> Vec<usize> {
    let mut pos = hivepack::zstd::frame_header_size(frame).expect("a frame header");
    let mut ends = Vec::new();
    loop {
        let header = u32::from_le_bytes([frame[pos], frame[pos + 1], frame[pos + 2], 0]);
        // RLE blocks have one byte.
        let size = if (header >> 1) & 3 == 1 {
            1
        } else {
            (header >> 3) as usize
        };
        pos += 3 + size;
        ends.push(pos);
        if header & 1 == 1 {
            return ends;
        }
    }
}

/// Too little room for the frame: every room up to 64 bytes, rooms up to
/// the bound, and rooms that end just past where each block (or sub-block)
/// ends, so that the next starts with no room or a few bytes; the same
/// frame, or the same error. Where the room is that tight, libzstd's
/// superblocks write past its end, into the slack its buffers have here;
/// the port does not, and must still give libzstd's results.
#[test]
fn too_little_room_fails_as_libzstd_fails() {
    let mut problems = Problems::default();
    let mut rng = Rng(4);
    let mut frames = 0;
    let mut failures = 0;
    // Blocks of 4 KB, with room for some just past where the block before
    // ends: literals of one byte repeated, with less room than they take.
    let rle_literals = rle_literals_data(&mut rng, 16_384, 16_384 + scaled(64_000));
    let periodic = periodic_data(&mut rng, scaled(40_000), 0);
    let mut inputs: Vec<(Vec<u8>, i32, Vec<Param>)> = Vec::new();
    for (k, len) in [300, 3000, 20_000, scaled(200_000)].into_iter().enumerate() {
        let content = data(&mut rng, len);
        for (j, &level_) in [1, 3, 9, 19].iter().enumerate() {
            let target_ = TARGETS[(j + k) % TARGETS.len()];
            inputs.push((content.clone(), level_, vec![target(target_)]));
        }
    }
    inputs.push((
        rle_literals,
        19,
        vec![target(1340), (P::MaxBlockSize(4096), C::MaxBlockSize(4096))],
    ));
    let mut params = periodic_params().to_vec();
    params.push(target(1340));
    inputs.push((periodic, 5, params));
    for (content, level_, mut params) in inputs {
        if left_out(level_ >= 4, content.len()) {
            continue;
        }
        params.push(level(level_));
        let (mut c, mut p) = contexts(&params);
        let bound = hivepack::zstd::compress_bound(content.len()).expect("a bound");
        let mut whole = vec![0u8; bound];
        let size = p
            .compress2(&mut whole, &content)
            .expect("the port compresses");
        let mut rooms: Vec<usize> = (0..=64).collect();
        let steps = if SLOW { 40 } else { 200 };
        rooms.extend((0..steps).map(|_| rng.range(0, bound as u64) as usize));
        rooms.extend([bound - 1, bound]);
        for end in block_ends(&whole[..size]) {
            rooms.extend((end..end + 8).filter(|&room| room <= bound));
        }
        for room in rooms {
            match compare_compress2(&mut c, &mut p, &content, Some(room), Active::None) {
                Ok(true) => frames += 1,
                Ok(false) => failures += 1,
                Err(problem) => problems.add(format!(
                    "{} bytes at level {level_}, {params:?}, into {room}: {problem}",
                    content.len()
                )),
            }
        }
    }
    println!("{frames} frames and {failures} failures compared");
    assert!(frames > 50 && failures > 200, "too few compared");
    problems.check();
}

/// Streamed through `ZSTD_compressStream2` and the port in the same pieces
/// and calls, flushes among them, with the same room for output; every call
/// compared: what it returns, how far it reads and writes, what it writes.
/// Pieces of a block or less, so that flushes end blocks early; a stable
/// output buffer sometimes.
#[test]
fn streaming_with_flushes_compresses_with_a_target_as_libzstd() {
    let mut problems = Problems::default();
    let mut compared = 0;
    let rounds = if EMULATED {
        12
    } else if SLOW {
        30
    } else {
        100
    };
    for seed in 0..rounds {
        let mut rng = Rng(500 + seed);
        let level_ = [-5, -1, 1, 2, 3, 4, 5, 7, 9, 12, 13, 16, 19][rng.range(0, 12) as usize];
        let target_ = TARGETS[rng.range(0, TARGETS.len() as u64 - 1) as usize];
        let stable = rng.chance(4);
        let len = rng.range(0, scaled(700_000) as u64) as usize;
        if left_out(level_ >= 4, len) {
            continue;
        }
        let mut params = vec![
            level(level_),
            target(target_),
            (P::StableOutBuffer(stable), C::StableOutBuffer(stable)),
        ];
        if rng.chance(2) {
            let value = rng.range(10, 20) as u32;
            params.push((P::WindowLog(value), C::WindowLog(value)));
        }
        if rng.chance(3) {
            params.push((P::ChecksumFlag(true), C::ChecksumFlag(true)));
        }
        if rng.chance(4) {
            params.push((
                P::EnableLongDistanceMatching(ParamSwitch::Enable),
                C::EnableLongDistanceMatching(true),
            ));
            params.push((P::LdmMinMatch(16), C::LdmMinMatch(16)));
            params.push((P::WindowLog(18), C::WindowLog(18)));
        }
        let (mut c, mut p) = contexts(&params);
        let content = data(&mut rng, len);
        match stream_frame(&mut c, &mut p, &content, &mut rng, stable) {
            Ok(Some(frame)) => {
                compared += 1;
                if let Err(problem) = decodes(&frame, &content, Active::None) {
                    problems.add(format!("seed {seed}: {problem}"));
                }
            }
            Ok(None) => {}
            Err(problem) => problems.add(format!(
                "seed {seed} (level {level_}, target {target_}, {len} bytes, stable output \
                 {stable}): {problem}"
            )),
        }
    }
    println!("{compared} frames compared");
    assert!(compared > rounds / 2, "only {compared} frames compared");
    problems.check();
}

/// One frame of `data` through both, in the same calls. Returns the frame,
/// or `None` when both failed the same way.
fn stream_frame(
    c: &mut zstd_safe::CCtx<'_>,
    p: &mut CCtx,
    data: &[u8],
    rng: &mut Rng,
    stable_out: bool,
) -> Result<Option<Vec<u8>>, String> {
    let room = hivepack::zstd::compress_bound(data.len()).expect("a bound") + 32;
    // With a stable output buffer, one buffer for the whole frame, its room
    // the same at each call.
    let (mut c_stable, mut p_stable) = if stable_out {
        (vec![0u8; room + SLACK], vec![0u8; room])
    } else {
        (Vec::new(), Vec::new())
    };
    let mut frame = Vec::new();
    let mut stable_pos = 0;
    let mut taken = 0;
    for call in 0..200_000 {
        let piece = match rng.range(0, 3) {
            0 => rng.range(0, 300),
            1 => rng.range(1, 20_000),
            _ => rng.range(1, 131_072),
        } as usize;
        let in_end = (taken + piece).min(data.len());
        let src = &data[taken..in_end];
        let directive = if in_end == data.len() && !rng.chance(4) {
            EndDirective::End
        } else if rng.chance(3) {
            EndDirective::Flush
        } else {
            EndDirective::Continue
        };
        let c_directive = match directive {
            EndDirective::Continue => ZSTD_EndDirective::ZSTD_e_continue,
            EndDirective::Flush => ZSTD_EndDirective::ZSTD_e_flush,
            EndDirective::End => ZSTD_EndDirective::ZSTD_e_end,
        };
        let out_room = rng.range(1, 140_000) as usize;
        let (mut c_fresh, mut p_fresh) = (vec![0u8; out_room], vec![0u8; out_room]);
        let (c_dst, p_dst, out_pos) = if stable_out {
            (&mut c_stable[..room], &mut p_stable[..], stable_pos)
        } else {
            (&mut c_fresh[..], &mut p_fresh[..], 0)
        };
        let (want, ci, co) = {
            let mut output = zstd_safe::OutBuffer::around_pos(&mut *c_dst, out_pos);
            let mut input = zstd_safe::InBuffer::around(src);
            let result = c.compress_stream2(&mut output, &mut input, c_directive);
            (result.map_err(name), input.pos(), output.pos())
        };
        let (got, pi, po) = {
            let mut output = hivepack::zstd::OutBuffer {
                dst: &mut *p_dst,
                pos: out_pos,
            };
            let mut input = hivepack::zstd::InBuffer { src, pos: 0 };
            let result = p.compress_stream2(&mut output, &mut input, directive);
            (result.map_err(message), input.pos, output.pos)
        };
        if (&want, ci, co) != (&got, pi, po) {
            return Err(format!(
                "call {call} ({directive:?}, input {taken}..{in_end}): libzstd {want:?} read \
                 {ci} wrote to {co}, port {got:?} read {pi} wrote to {po}"
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
            Ok(0) if directive == EndDirective::End => return Ok(Some(frame)),
            Ok(_) => {}
        }
    }
    Err("no end".into())
}
