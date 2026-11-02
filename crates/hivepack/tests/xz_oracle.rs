//! Comparison with liblzma 5.8.4 through `tools/xz-oracle`, call by call:
//! what each `lzma_code()` returns, reads and writes, the totals and a
//! hash of the output, the memory usage, the limit and the check, with
//! every decoder.
//!
//! The oracle is a small C program built with liblzma's sources by
//! `scripts/testdata.py`. It answers requests such as
//! `decode stream:1000000:0 c10/5/0,q,c=/100/3 fd377a...` by calling
//! liblzma, one line per request. [`answer`] answers the same requests
//! with the port, in the same format, so the two can be compared as text.
//!
//! - With the oracle built, generated requests are compared with liblzma
//!   directly: streams that liblzma's encoders wrote (.xz at every preset
//!   and check, .lzma, raw LZMA1 and LZMA2, and .lz members made from raw
//!   LZMA1), some damaged, cut short, concatenated or followed by more;
//!   and the test files of XZ Utils, `tests/files`, good, bad and
//!   unsupported. Each is decoded in random pieces, with memory limits
//!   that are reached and raised, and with the decoders' flags.
//! - Everywhere, including where the oracle cannot be built (Windows, and
//!   the emulated i686 and s390x jobs), `testdata/oracle/xz.txt` replays
//!   answers liblzma gave earlier. `cargo test -p hivepack --all-features --test xz_oracle
//!   record_oracle_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "xz_support/mod.rs"]
mod support;

use std::fmt::Write as _;
use std::path::PathBuf;

use hivepack::xz::{
    Action, BcjOptions, CONCATENATED, Check, DeltaOptions, FAIL_FAST, FILTER_ARM, FILTER_ARM64,
    FILTER_ARMTHUMB, FILTER_DELTA, FILTER_IA64, FILTER_LZMA1, FILTER_LZMA1EXT, FILTER_LZMA2,
    FILTER_POWERPC, FILTER_RISCV, FILTER_SPARC, Filter, FilterOptions, IGNORE_CHECK, InBuffer,
    LzmaOptions, MatchFinder, Mode, MtOptions, OutBuffer, Result, Status, Stream, TELL_ANY_CHECK,
    TELL_NO_CHECK, TELL_UNSUPPORTED_CHECK,
};
use support::{Oracle, Rng, cache, damage, fnv64, hex, input, recorded_form, repository, unhex};

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/xz.txt")
}

/// liblzma's return code for a result.
fn code(ret: Result<Status>) -> i32 {
    match ret {
        Ok(status) => status.number(),
        Err(e) => e.number(),
    }
}

fn action(number: u32) -> Action {
    match number {
        0 => Action::Run,
        1 => Action::SyncFlush,
        2 => Action::FullFlush,
        3 => Action::Finish,
        _ => Action::FullBarrier,
    }
}

/// The Filter ID of an LZMA filter's `<id>` in the oracle's text: 1, 2 or
/// 21 for LZMA1, LZMA1EXT or LZMA2, or the ID itself.
fn lzma_id(id: u64) -> u64 {
    match id {
        1 => FILTER_LZMA1,
        2 => FILTER_LZMA1EXT,
        21 => FILTER_LZMA2,
        id => id,
    }
}

/// A decoder's LZMA filter from the oracle's text: `<id>:<dict>:<lc>:<lp>:
/// <pb>:<ext_flags>:<ext_size>:<preset>`.
fn parse_lzma(text: &str) -> Filter {
    let f: Vec<&str> = text.split(':').collect();
    let n = |i: usize| f[i].parse::<u64>().unwrap();
    let ext_size = n(6);
    let preset = unhex(f[7]);
    Filter {
        id: lzma_id(n(0)),
        options: Some(FilterOptions::Lzma(LzmaOptions {
            dict_size: n(1) as u32,
            preset_dict: (!preset.is_empty()).then_some(preset),
            lc: n(2) as u32,
            lp: n(3) as u32,
            pb: n(4) as u32,
            ext_flags: n(5) as u32,
            ext_size_low: ext_size as u32,
            ext_size_high: (ext_size >> 32) as u32,
            ..LzmaOptions::default()
        })),
    }
}

/// An encoder's LZMA filter from the oracle's text: `<id>:<dict>:<lc>:<lp>:
/// <pb>:<mode>:<nice_len>:<mf>:<depth>:<ext_flags>:<ext_size>:<preset>`.
fn parse_elzma(text: &str) -> Filter {
    let f: Vec<&str> = text.split(':').collect();
    let n = |i: usize| f[i].parse::<u64>().unwrap();
    let ext_size = n(10);
    let preset = unhex(f[11]);
    Filter {
        id: lzma_id(n(0)),
        options: Some(FilterOptions::Lzma(LzmaOptions {
            dict_size: n(1) as u32,
            preset_dict: (!preset.is_empty()).then_some(preset),
            lc: n(2) as u32,
            lp: n(3) as u32,
            pb: n(4) as u32,
            mode: Mode(n(5) as u32),
            nice_len: n(6) as u32,
            mf: MatchFinder(n(7) as u32),
            depth: n(8) as u32,
            ext_flags: n(9) as u32,
            ext_size_low: ext_size as u32,
            ext_size_high: (ext_size >> 32) as u32,
        })),
    }
}

/// A delta or BCJ filter from the oracle's text, without its `f`:
/// `<id>:n` without options, `3:<type>:<dist>` for delta and
/// `<id>:<start_offset>` for the others.
fn parse_simple(text: &str) -> Filter {
    let f: Vec<&str> = text.split(':').collect();
    let id: u64 = f[0].parse().unwrap();
    let n = |i: usize| f[i].parse::<u32>().unwrap();
    let options = if f[1] == "n" {
        None
    } else if id == FILTER_DELTA {
        Some(FilterOptions::Delta(DeltaOptions {
            delta_type: n(1),
            dist: n(2),
        }))
    } else {
        Some(FilterOptions::Bcj(BcjOptions { start_offset: n(1) }))
    };
    Filter { id, options }
}

/// A chain from the oracle's text: its filters joined by `+`, the LZMA ones
/// as a decoder's or, with `encoder`, an encoder's.
fn parse_chain(text: &str, encoder: bool) -> Vec<Filter> {
    text.split('+')
        .map(|element| match element.strip_prefix('f') {
            Some(simple) => parse_simple(simple),
            None if encoder => parse_elzma(element),
            None => parse_lzma(element),
        })
        .collect()
}

/// The threaded encoder's options from the oracle's text: `<threads>:
/// <block_size>:<timeout>:<preset>:<check>:<flags>:<echain>`, the chain
/// `-` for the preset.
fn parse_mt(text: &str) -> MtOptions {
    let f: Vec<&str> = text.splitn(7, ':').collect();
    let n = |i: usize| f[i].parse::<u64>().unwrap();
    MtOptions {
        threads: n(0) as u32,
        block_size: n(1),
        timeout: n(2) as u32,
        preset: n(3) as u32,
        check: Check(n(4) as u32),
        flags: n(5) as u32,
        filters: (f[6] != "-").then(|| parse_chain(f[6], true)),
        ..MtOptions::default()
    }
}

/// The port's answer to an `mtcode` request: the threaded encoder driven
/// by the steps, each call with an action other than LZMA_RUN made again
/// until it returns something else than LZMA_OK, as the oracle does.
fn mt_answer(args: &str, steps: &str, data: &str) -> String {
    let mut strm = match Stream::stream_encoder_mt(&parse_mt(args)) {
        Ok(strm) => strm,
        Err(e) => return format!("err {}", e.number()),
    };
    let data = unhex(data);
    let mut out = Vec::new();
    let (mut consumed, mut end) = (0, 0);
    let mut last = 0;
    for step in steps.split(',') {
        let Some(rest) = step.strip_prefix('c') else {
            break;
        };
        let args: Vec<&str> = rest.split('/').collect();
        if args[0] != "=" {
            let n: usize = args[0].parse().unwrap();
            end = consumed + n.min(data.len() - consumed);
        }
        let room: usize = args[1].parse().unwrap();
        let action = action(args[2].parse().unwrap());
        loop {
            let written = out.len();
            out.resize(written + room, 0);
            let mut input = InBuffer {
                src: &data[..end],
                pos: consumed,
            };
            let mut output = OutBuffer::new(&mut out[written..]);
            last = code(strm.code(&mut output, &mut input, action));
            let made = output.pos;
            consumed = input.pos;
            out.truncate(written + made);
            if action == Action::Run || last != 0 {
                break;
            }
        }
        if last != 0 && last != 1 {
            return format!("fail {last}");
        }
    }
    format!(
        "ok {last} {}/{} {:016x}",
        strm.total_in(),
        strm.total_out(),
        fnv64(&out)
    )
}

/// The port's answer to an `mtdec` request: the threaded decoder driven by
/// the steps, as the oracle does.
fn mt_decoder_answer(args: &str, steps: &str, data: &str) -> String {
    let n: Vec<u64> = args.split(':').map(|a| a.parse().unwrap()).collect();
    let options = MtOptions {
        threads: n[0] as u32,
        timeout: n[1] as u32,
        flags: n[2] as u32,
        memlimit_threading: n[3],
        memlimit_stop: n[4],
        ..MtOptions::default()
    };
    let mut strm = match Stream::stream_decoder_mt(&options) {
        Ok(strm) => strm,
        Err(e) => return format!("err {}", e.number()),
    };
    let data = unhex(data);
    let mut out = Vec::new();
    let (mut consumed, mut end) = (0, 0);
    let (mut last, mut tells) = (0, 0);
    'steps: for step in steps.split(',') {
        let Some(rest) = step.strip_prefix('c') else {
            break;
        };
        let args: Vec<&str> = rest.split('/').collect();
        if args[0] != "=" {
            let n: usize = args[0].parse().unwrap();
            end = consumed + n.min(data.len() - consumed);
        }
        let room: usize = args[1].parse().unwrap();
        let action = action(args[2].parse().unwrap());
        loop {
            let written = out.len();
            out.resize(written + room, 0);
            let mut input = InBuffer {
                src: &data[..end],
                pos: consumed,
            };
            let mut output = OutBuffer::new(&mut out[written..]);
            last = code(strm.code(&mut output, &mut input, action));
            let made = output.pos;
            consumed = input.pos;
            out.truncate(written + made);
            if (2..=4).contains(&last) {
                tells += 1;
                last = 0;
            } else if last == 10 && action == Action::Run {
                last = 0;
            }
            if last != 0 {
                break 'steps;
            }
            if action == Action::Run {
                break;
            }
        }
    }
    if last != 0 && last != 1 && options.flags & FAIL_FAST != 0 {
        return "fail".to_string();
    }
    // What the BCJ coder had not filtered when the coder after it failed.
    if last != 0 && last != 1 && n[5] != 0 {
        return format!("{last} {tells}");
    }
    let total_in = if last == 1 {
        format!(" {}", strm.total_in())
    } else {
        String::new()
    };
    format!(
        "{last} {tells} {} {:016x}{total_in}",
        strm.total_out(),
        fnv64(&out)
    )
}

/// The output space all the steps can ask for.
fn output_space(steps: &str) -> usize {
    steps
        .split(',')
        .filter(|s| s.starts_with('c'))
        .map(|s| s.split('/').nth(1).unwrap().parse::<usize>().unwrap())
        .sum()
}

/// The port's answer to a `decode` request, in the oracle's format.
fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    let ["decode" | "code", decoder, steps, data] = words[..] else {
        panic!("not a decode request: {request:.100}");
    };
    let (kind, args) = decoder.split_once(':').unwrap();
    let args_n: Vec<u64> = args.split(':').filter_map(|a| a.parse().ok()).collect();
    let made = match kind {
        "stream" => Stream::stream_decoder(args_n[0], args_n[1] as u32),
        "auto" => Stream::auto_decoder(args_n[0], args_n[1] as u32),
        "lzip" => Stream::lzip_decoder(args_n[0], args_n[1] as u32),
        "alone" => Stream::alone_decoder(args_n[0]),
        "raw" => Stream::raw_decoder(&parse_chain(args, false)),
        "easyenc" => Stream::easy_encoder(args_n[0] as u32, Check(args_n[1] as u32)),
        "streamenc" => {
            let (check, chain) = args.split_once(':').unwrap();
            Stream::stream_encoder(&parse_chain(chain, true), Check(check.parse().unwrap()))
        }
        "aloneenc" => match &parse_chain(args, true)[0].options {
            Some(FilterOptions::Lzma(options)) => Stream::alone_encoder(options),
            _ => panic!("not LZMA options: {args}"),
        },
        "rawenc" => Stream::raw_encoder(&parse_chain(args, true)),
        _ => panic!("no such coder: {decoder}"),
    };
    let mut strm = match made {
        Ok(strm) => strm,
        Err(e) => return format!("err {}", e.number()),
    };
    let data = unhex(data);
    let mut out = vec![0u8; output_space(steps)];
    let (mut consumed, mut written, mut end) = (0, 0, 0);
    let mut text = String::from("ok");
    for step in steps.split(',') {
        let (kind, rest) = step.split_at(1);
        match kind {
            "c" => {
                let args: Vec<&str> = rest.split('/').collect();
                if args[0] != "=" {
                    let n: usize = args[0].parse().unwrap();
                    end = consumed + n.min(data.len() - consumed);
                }
                let room: usize = args[1].parse().unwrap();
                let mut input = InBuffer {
                    src: &data[..end],
                    pos: consumed,
                };
                let mut output = OutBuffer::new(&mut out[written..written + room]);
                let ret =
                    code(strm.code(&mut output, &mut input, action(args[2].parse().unwrap())));
                let read = input.pos - consumed;
                let made = output.pos;
                consumed += read;
                written += made;
                let _ = write!(text, " {ret}/{read}/{made}");
            }
            "m" => {
                let ret = match strm.memlimit_set(rest.parse().unwrap()) {
                    Ok(()) => 0,
                    Err(e) => e.number(),
                };
                let _ = write!(text, " m{ret}");
            }
            _ => {
                let _ = write!(
                    text,
                    " q{}/{}/{}",
                    strm.memusage(),
                    strm.memlimit_get(),
                    strm.get_check().0
                );
            }
        }
    }
    let _ = write!(
        text,
        " {}/{} {:016x}",
        strm.total_in(),
        strm.total_out(),
        fnv64(&out[..written])
    );
    text
}

/// liblzma's encoder, through the oracle: `data` as `format` (xz, alone,
/// raw1 or raw2) at `preset`, with `check` for xz.
fn encode(oracle: &mut Oracle, format: &str, preset: u32, check: u32, data: &[u8]) -> Vec<u8> {
    let reply = oracle.ask(&format!("encode {format} {preset} {check} {}", hex(data)));
    let stream = reply
        .strip_prefix("ok ")
        .unwrap_or_else(|| panic!("encode: {reply}"));
    unhex(stream)
}

/// The dictionary size of a preset.
fn preset_dict_size(preset: u32) -> u32 {
    [
        1 << 18,
        1 << 20,
        2 << 20,
        4 << 20,
        4 << 20,
        8 << 20,
        8 << 20,
        16 << 20,
        32 << 20,
        64 << 20,
    ][preset as usize & 15]
}

/// CRC32 as .lz and .xz have it.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// An .lz member of `data`, version 0 or 1, from liblzma's raw LZMA1
/// encoder, whose presets have lzip's lc=3, lp=0 and pb=2 and end with the
/// end of payload marker that lzip needs.
fn lzip_member(oracle: &mut Oracle, rng: &mut Rng, data: &[u8]) -> Vec<u8> {
    let preset = rng.below(7) as u32;
    let lzma = encode(oracle, "raw1", preset, 0, data);
    let version = rng.below(2) as u8;
    let mut member = b"LZIP".to_vec();
    member.push(version);
    member.push(preset_dict_size(preset).trailing_zeros() as u8);
    member.extend_from_slice(&lzma);
    member.extend_from_slice(&crc32(data).to_le_bytes());
    member.extend_from_slice(&(data.len() as u64).to_le_bytes());
    if version == 1 {
        let size = member.len() as u64 + 8;
        member.extend_from_slice(&size.to_le_bytes());
    }
    member
}

/// A single .xz Stream with check ID `id` in place of its own in the
/// Stream Header and Footer, both CRC32s made again. With an ID of the same
/// size, the check can be skipped but not verified: LZMA_UNSUPPORTED_CHECK.
fn with_check_id(stream: &[u8], id: u32) -> Vec<u8> {
    let mut stream = stream.to_vec();
    let footer = stream.len() - 12;
    stream[7] = id as u8;
    let crc = crc32(&stream[6..8]);
    stream[8..12].copy_from_slice(&crc.to_le_bytes());
    stream[footer + 9] = id as u8;
    let crc = crc32(&stream[footer + 4..footer + 10]);
    stream[footer..footer + 4].copy_from_slice(&crc.to_le_bytes());
    stream
}

/// How much input a step offers: a little, some, or all that is left.
fn chunk(rng: &mut Rng, left: usize) -> usize {
    match rng.below(5) {
        0 => rng.below(8) as usize,
        1 | 2 => rng.below(300) as usize,
        3 => rng.below(5000) as usize,
        _ => left,
    }
}

/// How much output space a step gives: none, a little, some, or plenty.
fn room(rng: &mut Rng) -> usize {
    match rng.below(8) {
        0 => 0,
        1..=3 => 1 + rng.below(100) as usize,
        4..=6 => rng.below(5000) as usize,
        _ => 100_000,
    }
}

/// The steps of a request for `len` bytes of input that decode to about
/// `out_len`: pieces with LZMA_RUN, now and then a query, a memory limit
/// raised, an action a decoder does not take, then LZMA_FINISH.
fn steps(rng: &mut Rng, len: usize, out_len: usize) -> String {
    let mut steps = Vec::new();
    let mut offered = 0;
    while offered < len && steps.len() < 120 {
        match rng.below(16) {
            0 => steps.push("q".to_string()),
            1 => steps.push(format!(
                "m{}",
                rng.pick(&[0, 1, 1 << 16, 1 << 20, 1 << 24, u64::MAX])
            )),
            2 => steps.push(format!("c=/{}/{}", room(rng), rng.pick(&[1, 2, 4]))),
            3 => steps.push(format!("c=/{}/0", room(rng))),
            _ => {
                let n = chunk(rng, len - offered);
                offered += n;
                steps.push(format!("c{n}/{}/0", room(rng)));
            }
        }
    }
    steps.push(format!("c{len}/{}/3", room(rng)));
    for _ in 0..rng.below(3) {
        steps.push(format!("c=/{}/3", room(rng)));
    }
    if rng.below(3) == 0 {
        steps.push(format!("m{}", u64::MAX));
    }
    steps.push(format!("c=/{}/3", out_len + 100));
    steps.push("q".to_string());
    steps.join(",")
}

/// A memory limit: none, or one that some streams reach.
fn memlimit(rng: &mut Rng) -> u64 {
    match rng.below(6) {
        0 => rng.pick(&[0, 1, 1 << 15, 1 << 16, 300_000, 1 << 21, 9 << 20]),
        _ => u64::MAX,
    }
}

/// The flags of the .xz and .lz decoders, now and then one they refuse.
fn flags(rng: &mut Rng) -> u32 {
    let mut flags = 0;
    for flag in [
        TELL_NO_CHECK,
        TELL_UNSUPPORTED_CHECK,
        TELL_ANY_CHECK,
        CONCATENATED,
        IGNORE_CHECK,
        FAIL_FAST,
    ] {
        if rng.below(4) == 0 {
            flags |= flag;
        }
    }
    if rng.below(40) == 0 {
        flags |= 0x40;
    }
    flags
}

/// The test files of XZ Utils, `tests/files`, where they are fetched.
fn test_files() -> Vec<(String, Vec<u8>)> {
    let folder = cache().join("xz-5.8.4-source/xz-5.8.4/tests/files");
    let Ok(entries) = std::fs::read_dir(&folder) else {
        return Vec::new();
    };
    let mut files: Vec<(String, Vec<u8>)> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|x| x == "xz" || x == "lzma" || x == "lz")
        })
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(&p).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

/// A length for an input: empty, short, or up to `max`.
fn length(rng: &mut Rng, max: usize) -> usize {
    match rng.below(8) {
        0 => rng.below(3) as usize,
        1..=4 => rng.below(2000) as usize,
        5 | 6 => rng.below(30_000) as usize,
        _ => rng.below(max as u64 + 1) as usize,
    }
}

/// The alignment of a BCJ filter's start offset.
fn bcj_alignment(id: u64) -> u32 {
    match id {
        FILTER_POWERPC | FILTER_ARM | FILTER_ARM64 | FILTER_SPARC => 4,
        FILTER_IA64 => 16,
        FILTER_ARMTHUMB | FILTER_RISCV => 2,
        _ => 1,
    }
}

/// A delta or BCJ filter as the oracle reads it, with options its coders
/// take: a delta distance, or a BCJ filter's start offset (near the top
/// too, where positions wrap around) or none.
fn simple_filter(rng: &mut Rng) -> String {
    if rng.below(3) == 0 {
        let dist = match rng.below(3) {
            0 => rng.pick(&[1, 2, 4, 256]),
            _ => 1 + rng.below(256),
        };
        return format!("f3:0:{dist}");
    }
    let id = 4 + rng.below(8);
    let align = bcj_alignment(id);
    match rng.below(5) {
        0 => format!("f{id}:n"),
        1 => format!("f{id}:0"),
        2 => format!(
            "f{id}:{}",
            u32::MAX / align * align - align * rng.below(8) as u32
        ),
        _ => format!("f{id}:{}", align * rng.below(1 << 20) as u32),
    }
}

/// A delta or BCJ filter that the coders refuse: options out of range,
/// none for delta, a start offset out of alignment, or a filter liblzma
/// does not have.
fn refused_filter(rng: &mut Rng) -> String {
    match rng.below(5) {
        0 => format!("f3:0:{}", rng.pick(&[0, 257, 1 << 20])),
        1 => "f3:1:1".to_string(),
        2 => "f3:n".to_string(),
        3 => {
            let id = rng.pick(&[
                FILTER_POWERPC,
                FILTER_IA64,
                FILTER_ARM,
                FILTER_ARMTHUMB,
                FILTER_ARM64,
                FILTER_SPARC,
                FILTER_RISCV,
            ]);
            format!(
                "f{id}:{}",
                bcj_alignment(id) * (1 + rng.below(1000) as u32) - 1
            )
        }
        _ => format!(
            "f{}:n",
            rng.pick(&[0x02, 0x0C, 0x7F, 0x4000_0000_0000_0003u64])
        ),
    }
}

/// The filters before LZMA in a chain, one to three, each followed by `+`;
/// with `refused`, now and then one that the coders refuse.
fn filters_before(rng: &mut Rng, refused: bool) -> String {
    let mut text = String::new();
    for _ in 0..1 + rng.below(3) {
        let filter = if refused && rng.below(3) == 0 {
            refused_filter(rng)
        } else {
            simple_filter(rng)
        };
        text.push_str(&filter);
        text.push('+');
    }
    text
}

/// A chain that liblzma refuses for its order or length, with `lzma` as
/// its LZMA filter: LZMA before another filter, five filters, or no LZMA.
fn refused_chain(rng: &mut Rng, lzma: &str) -> String {
    match rng.below(4) {
        0 => format!("{lzma}+{}", simple_filter(rng)),
        1 => format!("{}{lzma}+{lzma}", filters_before(rng, false)),
        2 => {
            let before: String = (0..4).map(|_| simple_filter(rng) + "+").collect();
            format!("{before}{lzma}")
        }
        _ => filters_before(rng, false).trim_end_matches('+').to_string(),
    }
}

/// Input with instructions that the BCJ filters convert, in other input:
/// x86 CALL and JMP, PowerPC, ARM and ARM64 BL, ARM-Thumb BL, SPARC CALL,
/// ARM64 ADRP, RISC-V JAL, and RISC-V AUIPC with an instruction whose rs1
/// is its rd. (IA-64's come up in random input.)
fn code_input(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut data = input(rng, len);
    for _ in 0..len / 12 {
        let at = rng.below(len as u64) as usize;
        let r = rng.next().to_le_bytes();
        let pattern = match rng.below(10) {
            0 => vec![0xE8 | (r[0] & 1), r[1], r[2], r[3], rng.pick(&[0, 0xFF])],
            1 => vec![0x48 | (r[0] & 3), r[1], r[2], (r[3] & 0xFC) | 1],
            2 => vec![r[0], r[1], r[2], 0xEB],
            3 => vec![r[0], 0xF0 | (r[1] & 7), r[2], 0xF8 | (r[3] & 7)],
            4 if r[0] & 1 == 0 => vec![0x40, r[1] & 0x3F, r[2], r[3]],
            4 => vec![0x7F, 0xC0 | r[1], r[2], r[3]],
            5 => vec![r[0], r[1], r[2], 0x94 | (r[3] & 3)],
            6 => vec![
                r[0],
                r[1],
                (r[2] & 0x0F) | rng.pick(&[0, 0xF0]),
                0x90 | (r[3] & 0x60),
            ],
            7 => vec![0xEF, r[1] & 0xF2, r[2], r[3]],
            _ => {
                let rd = rng.pick(&[1u32, 3, 5, 10, 31]);
                let auipc = 0x17 | rd << 7 | u32::from_le_bytes([r[0], r[1], r[2], r[3]]) & !0xFFF;
                let inst2 = u32::from_le_bytes([r[4], r[5], r[6], r[7]]) & !0xF_8003 | rd << 15 | 3;
                [auipc.to_le_bytes(), inst2.to_le_bytes()].concat()
            }
        };
        let end = (at + pattern.len()).min(len);
        data[at..end].copy_from_slice(&pattern[..end - at]);
    }
    data
}

/// Generated requests: `count` streams of each kind, with inputs up to
/// `max` bytes, and the test files.
fn requests(oracle: &mut Oracle, rng: &mut Rng, count: usize, max: usize) -> Vec<String> {
    let mut requests = Vec::new();

    // By hand: empty input, and decoders refused.
    for decoder in [
        "stream:0:0",
        "auto:0:0",
        "lzip:0:0",
        "alone:0",
        "stream:1:64",
        "auto:1:128",
    ] {
        requests.push(format!("decode {decoder} c0/10/0,c0/10/0,q,c0/10/3 -"));
    }
    for filter in [
        "21:4096:0:0:0:0:0:-",
        "1:4096:5:0:0:0:0:-",
        "1:4096:3:0:5:0:0:-",
        "2:4096:3:0:2:2:5:-",
        "21:0:0:0:0:0:0:-",
    ] {
        requests.push(format!("decode raw:{filter} c0/10/3 -"));
        requests.push(format!("memusage {filter}"));
    }

    for _ in 0..count {
        let len = length(rng, max);
        let data = input(rng, len);
        let preset = rng.below(10) as u32 | if rng.below(6) == 0 { 1 << 31 } else { 0 };
        let check = rng.pick(&[0, 1, 4, 10, 4, 4]);
        let mut stream = encode(oracle, "xz", preset, check, &data);
        let mut out_len = data.len();
        match rng.below(10) {
            0 | 1 => stream = damage(rng, &stream),
            2 => {
                // Concatenated, with Stream Padding of 0, 4 or 8 bytes, or
                // of 3, which is invalid.
                let padding = rng.pick(&[0, 4, 8, 3]);
                stream.resize(stream.len() + padding, 0);
                let more_len = rng.below(3000) as usize;
                let more = input(rng, more_len);
                stream.extend(encode(oracle, "xz", rng.below(4) as u32, check, &more));
                out_len += more.len();
            }
            3 => stream.extend((0..1 + rng.below(20)).map(|_| rng.next() as u8)),
            5 | 6 if check != 0 => {
                let id = check + 1 + rng.below(2) as u32;
                stream = with_check_id(&stream, id);
            }
            4 => {
                let at = rng.below(stream.len() as u64) as usize;
                stream.truncate(at);
            }
            _ => {}
        }
        let decoder = if rng.below(3) == 0 { "auto" } else { "stream" };
        let steps = steps(rng, stream.len(), out_len);
        requests.push(format!(
            "decode {decoder}:{}:{} {steps} {}",
            memlimit(rng),
            flags(rng),
            hex(&stream)
        ));
    }

    for _ in 0..count / 2 {
        let len = length(rng, max);
        let data = input(rng, len);
        let mut stream = encode(oracle, "alone", rng.below(10) as u32, 0, &data);
        if rng.below(3) == 0 {
            // The size in the header, which lzma_alone_encoder leaves
            // unknown: with the end of payload marker after it, which is
            // valid, or too small or too large.
            let size = (data.len() as u64).wrapping_add(rng.pick(&[0, 0, 0, u64::MAX, 1]));
            stream[5..13].copy_from_slice(&size.to_le_bytes());
        }
        if rng.below(4) == 0 {
            stream = damage(rng, &stream);
        }
        let decoder = if rng.below(3) == 0 {
            format!("auto:{}:{}", memlimit(rng), flags(rng))
        } else {
            format!("alone:{}", memlimit(rng))
        };
        let steps = steps(rng, stream.len(), data.len());
        requests.push(format!("decode {decoder} {steps} {}", hex(&stream)));
    }

    for _ in 0..count / 2 {
        let len = length(rng, max.min(60_000));
        let data = input(rng, len);
        let mut stream = lzip_member(oracle, rng, &data);
        let mut out_len = data.len();
        match rng.below(6) {
            0 => stream = damage(rng, &stream),
            1 => {
                let more_len = rng.below(2000) as usize;
                let more = input(rng, more_len);
                stream.extend(lzip_member(oracle, rng, &more));
                out_len += more.len();
            }
            2 => stream.extend_from_slice(b"trailing data"),
            _ => {}
        }
        let decoder = if rng.below(3) == 0 { "auto" } else { "lzip" };
        let steps = steps(rng, stream.len(), out_len);
        requests.push(format!(
            "decode {decoder}:{}:{} {steps} {}",
            memlimit(rng),
            flags(rng),
            hex(&stream)
        ));
    }

    for _ in 0..count / 2 {
        let len = length(rng, max.min(60_000));
        let data = input(rng, len);
        let preset = rng.below(10) as u32;
        let lzma2 = rng.below(2) == 0;
        let mut stream = encode(
            oracle,
            if lzma2 { "raw2" } else { "raw1" },
            preset,
            0,
            &data,
        );
        if rng.below(5) == 0 {
            stream = damage(rng, &stream);
        }
        // The dictionary the decoder is given: the encoder's, a smaller
        // one, or none at all.
        let dict = match rng.below(4) {
            0 => rng.pick(&[0, 4096, 65_536]),
            _ => preset_dict_size(preset),
        };
        // Now and then a preset dictionary, which the stream does not use
        // but a damaged one may reach into, and which spares LZMA2 the
        // dictionary reset of its first chunk.
        let preset = if rng.below(4) == 0 {
            let len = 1 + rng.below(3000) as usize;
            hex(&input(rng, len))
        } else {
            "-".to_string()
        };
        let filter = if lzma2 {
            format!("21:{dict}:0:0:0:0:0:{preset}")
        } else if rng.below(2) == 0 {
            format!("1:{dict}:3:0:2:0:0:{preset}")
        } else {
            // LZMA1EXT: the size known or not, the marker allowed or not.
            let size = rng.pick(&[data.len() as u64, u64::MAX, data.len() as u64 + 1]);
            format!("2:{dict}:3:0:2:{}:{size}:{preset}", rng.below(2))
        };
        let steps = steps(rng, stream.len(), data.len());
        requests.push(format!("decode raw:{filter} {steps} {}", hex(&stream)));
    }

    for (name, data) in test_files() {
        let decoders: Vec<String> = match name.rsplit('.').next() {
            Some("lzma") => vec![
                "alone:1000000000".into(),
                format!("auto:1000000000:{}", flags(rng)),
            ],
            Some("lz") => vec![
                format!("lzip:1000000000:{}", flags(rng)),
                "auto:1000000000:8".into(),
            ],
            _ => vec![
                "stream:1000000000:0".into(),
                format!("stream:1000000000:{}", flags(rng)),
                format!("auto:{}:{}", memlimit(rng), flags(rng) | CONCATENATED),
            ],
        };
        for decoder in decoders {
            let steps = steps(rng, data.len(), 100_000);
            requests.push(format!("decode {decoder} {steps} {}", hex(&data)));
        }
    }

    // Chains of delta and BCJ filters before LZMA2 or LZMA1, which
    // liblzma's encoders wrote as .xz and raw, and chains refused.
    let lzma = "21:4096:0:0:0:0:0:-";
    for _ in 0..count / 6 {
        let chain = if rng.below(2) == 0 {
            refused_chain(rng, lzma)
        } else {
            format!("{}{lzma}", filters_before(rng, true))
        };
        requests.push(format!("decode raw:{chain} c0/10/3 -"));
        requests.push(format!("memusage {chain}"));
    }
    for _ in 0..count / 2 {
        let len = length(rng, max.min(100_000));
        let data = code_input(rng, len);
        let before = filters_before(rng, false);
        let o = LzmaOptions::preset(rng.below(7) as u32).unwrap();
        let dict = o.dict_size.min(1 << 20);
        let xz = rng.below(2) == 0;
        let id = if xz || rng.below(2) == 0 { 21 } else { 1 };
        let lzma = format!(
            "{id}:{dict}:{}:{}:{}:{}:{}:{}:{}:0:0:-",
            o.lc, o.lp, o.pb, o.mode.0, o.nice_len, o.mf.0, o.depth
        );
        // Room for LZMA1, which can grow incompressible input more than
        // LZMA2.
        let out_size = len + len / 4 + 1024;
        let check = rng.pick(&[0, 1, 4, 10]);
        let reply = oracle.ask(&if xz {
            format!("sbuf {check}:{out_size}:{before}{lzma} {}", hex(&data))
        } else {
            format!("rbuf {out_size}:{before}{lzma} {}", hex(&data))
        });
        let mut stream = unhex(reply.strip_prefix("ok ").unwrap());
        match rng.below(8) {
            0 | 1 => stream = damage(rng, &stream),
            2 => {
                let at = rng.below(stream.len() as u64 + 1) as usize;
                stream.truncate(at);
            }
            _ => {}
        }
        let decoder = if xz {
            let kind = if rng.below(3) == 0 { "auto" } else { "stream" };
            format!("{kind}:{}:{}", memlimit(rng), flags(rng))
        } else {
            format!("raw:{before}{id}:{dict}:{}:{}:{}:0:0:-", o.lc, o.lp, o.pb)
        };
        let steps = steps(rng, stream.len(), len);
        requests.push(format!("decode {decoder} {steps} {}", hex(&stream)));
    }
    requests
}

/// The port's answer to any request.
fn port_answer(request: &str) -> String {
    if let Some(chain) = request.strip_prefix("memusage ") {
        return hivepack::xz::raw_decoder_memusage(&parse_chain(chain, false)).to_string();
    }
    if let Some(chain) = request.strip_prefix("encmem ") {
        return hivepack::xz::raw_encoder_memusage(&parse_chain(chain, true)).to_string();
    }
    if let Some(preset) = request.strip_prefix("easymem ") {
        let preset = preset.parse().unwrap();
        return format!(
            "{} {}",
            hivepack::xz::easy_encoder_memusage(preset),
            hivepack::xz::easy_decoder_memusage(preset)
        );
    }
    if let Some(args) = request.strip_prefix("mtmem ") {
        return hivepack::xz::stream_encoder_mt_memusage(&parse_mt(args)).to_string();
    }
    if let Some(size) = request.strip_prefix("bound ") {
        return hivepack::xz::stream_buffer_bound(size.parse().unwrap()).to_string();
    }
    let words: Vec<&str> = request.split(' ').collect();
    if let ["mtcode", args, steps, data] = words[..] {
        return mt_answer(args, steps, data);
    }
    if let ["mtdec", args, steps, data] = words[..] {
        return mt_decoder_answer(args, steps, data);
    }
    if let ["bcj", arch, direction, start, data] = words[..] {
        let mut buf = unhex(data);
        let start = start.parse().unwrap();
        let filter = match (arch, direction) {
            ("x86", "enc") => hivepack::xz::bcj_x86_encode,
            ("x86", _) => hivepack::xz::bcj_x86_decode,
            ("arm64", "enc") => hivepack::xz::bcj_arm64_encode,
            ("arm64", _) => hivepack::xz::bcj_arm64_decode,
            ("riscv", "enc") => hivepack::xz::bcj_riscv_encode,
            _ => hivepack::xz::bcj_riscv_decode,
        };
        let done = filter(start, &mut buf);
        return format!("{done} {}", hex(&buf));
    }
    if let [kind @ ("ebuf" | "sbuf" | "rbuf"), args, data] = words[..] {
        let data = unhex(data);
        let a: Vec<&str> = args.splitn(3, ':').collect();
        let (out_size, result) = match kind {
            "ebuf" => {
                let out_size: usize = a[2].parse().unwrap();
                let mut out = vec![0; out_size];
                let mut pos = 0;
                let r = hivepack::xz::easy_buffer_encode(
                    a[0].parse().unwrap(),
                    Check(a[1].parse().unwrap()),
                    &data,
                    &mut out,
                    &mut pos,
                );
                (out_size, r.map(|()| out[..pos].to_vec()))
            }
            "sbuf" => {
                let out_size: usize = a[1].parse().unwrap();
                let mut out = vec![0; out_size];
                let mut pos = 0;
                let r = hivepack::xz::stream_buffer_encode(
                    &parse_chain(a[2], true),
                    Check(a[0].parse().unwrap()),
                    &data,
                    &mut out,
                    &mut pos,
                );
                (out_size, r.map(|()| out[..pos].to_vec()))
            }
            _ => {
                let (out_size, chain) = args.split_once(':').unwrap();
                let out_size: usize = out_size.parse().unwrap();
                let mut out = vec![0; out_size];
                let mut pos = 0;
                let r = hivepack::xz::raw_buffer_encode(
                    &parse_chain(chain, true),
                    &data,
                    &mut out,
                    &mut pos,
                );
                (out_size, r.map(|()| out[..pos].to_vec()))
            }
        };
        let _ = out_size;
        return match result {
            Ok(bytes) => format!("ok {}", hex(&bytes)),
            Err(e) => format!("err {}", e.number()),
        };
    }
    answer(request)
}

#[test]
fn port_matches_liblzma() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x5eed_c201);
    let requests = requests(&mut oracle, &mut rng, 300, 300_000);
    let mut seen = [0usize; 12];
    let (mut ends, mut chain_ends) = (0, 0);
    for request in &requests {
        let want = oracle.ask(request);
        assert_eq!(port_answer(request), want, "{request:.300}");
        for ret in returned(&want) {
            seen[ret] += 1;
        }
        ends += usize::from(returned(&want).contains(&1));
        chain_ends +=
            usize::from(request.starts_with("decode raw:f") && returned(&want).contains(&1));
    }
    eprintln!(
        "{} requests, {ends} reach LZMA_STREAM_END ({chain_ends} raw with delta or BCJ), \
         return codes seen {seen:?}",
        requests.len()
    );
    assert!(chain_ends > 20, "only {chain_ends} raw chains end");
    // Every return code from LZMA_OK to LZMA_PROG_ERROR came up, but
    // LZMA_MEM_ERROR, for which an allocation must fail.
    for (ret, count) in seen.iter().enumerate().filter(|&(ret, _)| ret != 5) {
        assert!(*count > 0, "no lzma_code() returned {ret}");
    }
    assert!(
        ends > requests.len() / 3,
        "only {ends} of {} streams end",
        requests.len()
    );
}

/// The return codes of the `lzma_code()` and `lzma_memlimit_set()` calls
/// in an answer to `decode`, or of the initialization that failed.
fn returned(answer: &str) -> Vec<usize> {
    if let Some(err) = answer.strip_prefix("err ") {
        return vec![err.parse().unwrap()];
    }
    let Some(steps) = answer.strip_prefix("ok ") else {
        return Vec::new();
    };
    let words: Vec<&str> = steps.split(' ').collect();
    // "ok <hex>" from the single-call encoders: no calls.
    if words.len() < 2 {
        return Vec::new();
    }
    words[..words.len() - 2]
        .iter()
        .filter(|w| !w.starts_with('q'))
        .filter_map(|w| w.trim_start_matches('m').split('/').next()?.parse().ok())
        .collect()
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/xz.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(recorded_form(&port_answer(request)), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > 500, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/xz.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng(0x5eed_c202);
    let mut text = String::from(
        "# Answers from liblzma 5.8.4 (tools/xz-oracle), replayed by crates/xz/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test xz_oracle record_oracle_answers -- --ignored\n",
    );
    for request in requests(&mut oracle, &mut rng, 300, 3000) {
        // Keep the file small: the large inputs are for the live comparison.
        if request.len() > 6_000 {
            continue;
        }
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::create_dir_all(recorded_path().parent().expect("folder")).expect("folder");
    std::fs::write(recorded_path(), text).expect("written");
}

// The encoders.

fn recorded_encoder_path() -> PathBuf {
    repository().join("testdata/oracle/xz-encode.txt")
}

/// An encoder's filter, as the oracle reads it: the options of a preset,
/// changed now and then, some of them to values the encoders refuse.
fn efilter(rng: &mut Rng, id: u64, max_dict: u32) -> String {
    let preset = rng.below(10) as u32
        | if rng.below(5) == 0 {
            hivepack::xz::PRESET_EXTREME
        } else {
            0
        };
    let mut o = LzmaOptions::preset(preset).unwrap();
    o.dict_size = match rng.below(12) {
        0 => rng.pick(&[0, 4095, (1 << 30) + (1 << 29) + 1]),
        1..=4 => rng.pick(&[4096, 4097, 1 << 16, 100_000, 1 << 18, 1 << 20]),
        _ => o.dict_size.min(max_dict),
    };
    if rng.below(4) == 0 {
        o.lc = rng.below(5) as u32;
        o.lp = rng.below(5) as u32;
        o.pb = rng.below(5) as u32;
    }
    match rng.below(40) {
        0 => o.mode = Mode(rng.pick(&[0, 3])),
        1..=6 => {
            o.mode = if o.mode == Mode::FAST {
                Mode::NORMAL
            } else {
                Mode::FAST
            }
        }
        _ => {}
    }
    match rng.below(40) {
        0 => o.nice_len = rng.pick(&[0, 1, 274]),
        1..=10 => o.nice_len = rng.pick(&[2, 3, 4, 5, 8, 16, 32, 64, 128, 192, 273]),
        _ => {}
    }
    match rng.below(40) {
        0 => o.mf = MatchFinder(rng.pick(&[0, 0x02, 0x05, 0x15])),
        1..=10 => {
            o.mf = rng.pick(&[
                MatchFinder::HC3,
                MatchFinder::HC4,
                MatchFinder::BT2,
                MatchFinder::BT3,
                MatchFinder::BT4,
            ])
        }
        _ => {}
    }
    if rng.below(5) == 0 {
        o.depth = rng.pick(&[0, 1, 2, 4, 16, 64, 512, 10_000]);
    }
    if id == FILTER_LZMA1EXT {
        o.ext_flags = if rng.below(30) == 0 {
            2
        } else {
            rng.below(2) as u32
        };
    }
    let preset_dict = if rng.below(5) == 0 {
        let len = 1 + rng.below(5000) as usize;
        hex(&input(rng, len))
    } else {
        "-".to_string()
    };
    let id = match id {
        FILTER_LZMA1 => 1,
        FILTER_LZMA1EXT => 2,
        FILTER_LZMA2 => 21,
        id => id,
    };
    format!(
        "{id}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{preset_dict}",
        o.dict_size,
        o.lc,
        o.lp,
        o.pb,
        o.mode.0,
        o.nice_len,
        o.mf.0,
        o.depth,
        o.ext_flags,
        rng.next() >> rng.below(64)
    )
}

/// A filter ID for the encoders: LZMA2 mostly, LZMA1 and LZMA1EXT, and now
/// and then one they do not have.
fn encoder_id(rng: &mut Rng) -> u64 {
    match rng.below(40) {
        0 => rng.pick(&[0x7F, 0x4000_0000_0000_0003, 0x21 + 0x100]),
        1..=8 => FILTER_LZMA1,
        9..=14 => FILTER_LZMA1EXT,
        _ => FILTER_LZMA2,
    }
}

/// An integrity check: the three this build has and none, now and then
/// one it has not, or a number out of range.
fn check(rng: &mut Rng) -> u32 {
    match rng.below(30) {
        0 => rng.pick(&[2, 3, 5, 9, 15, 16]),
        _ => rng.pick(&[0, 1, 4, 10]),
    }
}

/// The steps of an encoding of `len` bytes: pieces with LZMA_RUN, flushes
/// with the actions in `flushes` (each given again until it is done), now
/// and then an action the encoder does not take, queries and memory
/// limits, then LZMA_FINISH with room enough for all the output.
fn encoder_steps(rng: &mut Rng, len: usize, flushes: &[u32]) -> String {
    let mut steps = Vec::new();
    let mut offered = 0;
    while offered < len && steps.len() < 100 {
        match rng.below(30) {
            0 | 1 => steps.push("q".to_string()),
            2 => steps.push(format!("m{}", rng.pick(&[0, 1, 1 << 20, u64::MAX]))),
            3 => steps.push(format!("c=/{}/{}", room(rng), rng.pick(&[1, 2, 4]))),
            4..=7 if !flushes.is_empty() => {
                let action = rng.pick(flushes);
                let n = chunk(rng, len - offered);
                offered += n;
                steps.push(format!("c{n}/{}/{action}", room(rng)));
                for _ in 0..1 + rng.below(4) {
                    steps.push(format!("c=/{}/{action}", room(rng)));
                }
            }
            _ => {
                let n = chunk(rng, len - offered);
                offered += n;
                steps.push(format!("c{n}/{}/0", room(rng)));
            }
        }
    }
    steps.push(format!("c{len}/{}/3", room(rng)));
    for _ in 0..rng.below(4) {
        steps.push(format!("c=/{}/3", room(rng)));
    }
    steps.push(format!("c=/{}/3", len + len / 8 + 70_000));
    steps.push("q".to_string());
    steps.join(",")
}

/// Requests for the encoders: `count` encodings with each kind of encoder,
/// with inputs up to `max` bytes, the single-call encoders, and the memory
/// usage of encoders.
fn encoder_requests(rng: &mut Rng, count: usize, max: usize) -> Vec<String> {
    let mut requests = Vec::new();
    let max_dict = if max > 100_000 { 8 << 20 } else { 1 << 20 };

    for _ in 0..count {
        let len = length(rng, max);
        let data = input(rng, len);
        let (coder, flushes): (String, &[u32]) = match rng.below(8) {
            0 | 1 => {
                let preset = match rng.below(30) {
                    0 => rng.pick(&[10, 1 << 20, 15 | hivepack::xz::PRESET_EXTREME]),
                    _ => {
                        rng.below(10) as u32
                            | if rng.below(5) == 0 {
                                hivepack::xz::PRESET_EXTREME
                            } else {
                                0
                            }
                    }
                };
                // At most preset 7, whose 16 MiB dictionary is quick to
                // set up; the others are tested in one call.
                let preset = if max > 100_000 && preset & 15 > 7 {
                    preset - 2
                } else {
                    preset
                };
                (format!("easyenc:{preset}:{}", check(rng)), &[1, 2, 4])
            }
            2..=4 => {
                let id = if rng.below(20) == 0 {
                    encoder_id(rng)
                } else {
                    FILTER_LZMA2
                };
                (
                    format!("streamenc:{}:{}", check(rng), efilter(rng, id, max_dict)),
                    &[1, 2, 4],
                )
            }
            5 => (
                format!("aloneenc:{}", efilter(rng, FILTER_LZMA1, max_dict)),
                &[],
            ),
            _ => {
                let id = encoder_id(rng);
                let flushes: &[u32] = if rng.below(4) == 0 { &[1, 2] } else { &[1] };
                (format!("rawenc:{}", efilter(rng, id, max_dict)), flushes)
            }
        };
        let steps = encoder_steps(rng, len, flushes);
        requests.push(format!("code {coder} {steps} {}", hex(&data)));
    }

    // Inputs bigger than the window of small dictionaries, which slides
    // (move_window), and runs that fill LZMA2 chunks of 2 MiB.
    if max > 100_000 {
        for _ in 0..12 {
            let len = 1_000_000 + rng.below(2_500_000) as usize;
            let data = input(rng, len);
            // Options the encoder takes, so that it gets through.
            let mut filter = efilter(rng, FILTER_LZMA2, 1 << 16);
            while hivepack::xz::raw_encoder_memusage(&parse_chain(&filter, true)) == u64::MAX {
                filter = efilter(rng, FILTER_LZMA2, 1 << 16);
            }
            if rng.below(2) == 0 {
                // A dictionary of 4 KiB to 64 KiB.
                let rest = filter.split_once(':').unwrap().1.split_once(':').unwrap().1;
                filter = format!("21:{}:{rest}", 4096 << rng.below(5));
            }
            if rng.below(3) == 0 {
                filter = format!("{}{filter}", filters_before(rng, false));
            }
            let coder = if rng.below(2) == 0 {
                format!("streamenc:{}:{filter}", check(rng))
            } else {
                format!("rawenc:{filter}")
            };
            let steps = encoder_steps(rng, len, &[1]);
            requests.push(format!("code {coder} {steps} {}", hex(&data)));
        }
    }

    for _ in 0..count / 3 {
        let len = length(rng, max.min(100_000));
        let data = input(rng, len);
        let bound = hivepack::xz::stream_buffer_bound(len);
        let out_size = match rng.below(5) {
            0 => rng.below(80) as usize,
            1 => bound - rng.below(bound as u64 / 2) as usize,
            _ => bound,
        };
        let request = match rng.below(3) {
            0 => format!(
                "ebuf {}:{}:{out_size} {}",
                rng.below(10) as u32
                    | if rng.below(6) == 0 {
                        hivepack::xz::PRESET_EXTREME
                    } else {
                        0
                    },
                check(rng),
                hex(&data)
            ),
            1 => {
                let id = if rng.below(10) == 0 {
                    encoder_id(rng)
                } else {
                    FILTER_LZMA2
                };
                format!(
                    "sbuf {}:{out_size}:{} {}",
                    check(rng),
                    efilter(rng, id, max_dict),
                    hex(&data)
                )
            }
            _ => {
                let id = encoder_id(rng);
                format!(
                    "rbuf {out_size}:{} {}",
                    efilter(rng, id, max_dict),
                    hex(&data)
                )
            }
        };
        requests.push(request);
    }

    for _ in 0..count / 3 {
        let id = encoder_id(rng);
        requests.push(format!("encmem {}", efilter(rng, id, u32::MAX)));
    }
    for preset in (0..12).chain([1 << 20, 31]) {
        requests.push(format!("easymem {preset}"));
        requests.push(format!("easymem {}", preset | hivepack::xz::PRESET_EXTREME));
    }
    for size in [
        0u64,
        1,
        1000,
        1 << 20,
        1 << 40,
        (1 << 63) - 1,
        u64::MAX - 100,
    ] {
        requests.push(format!("bound {size}"));
    }

    // Chains of delta and BCJ filters before LZMA, now and then refused.
    for _ in 0..count / 2 {
        let len = length(rng, max);
        let data = code_input(rng, len);
        let id = if rng.below(4) == 0 {
            encoder_id(rng)
        } else {
            FILTER_LZMA2
        };
        let lzma = efilter(rng, id, max_dict);
        let chain = match rng.below(12) {
            0 => refused_chain(rng, &lzma),
            1 => format!("{}{lzma}", filters_before(rng, true)),
            _ => format!("{}{lzma}", filters_before(rng, false)),
        };
        let (coder, flushes): (String, &[u32]) = if rng.below(2) == 0 {
            (format!("streamenc:{}:{chain}", check(rng)), &[1, 2, 4])
        } else {
            (format!("rawenc:{chain}"), &[1, 2])
        };
        let steps = encoder_steps(rng, len, flushes);
        requests.push(format!("code {coder} {steps} {}", hex(&data)));
    }
    for _ in 0..count / 6 {
        let len = length(rng, max.min(100_000));
        let data = code_input(rng, len);
        let bound = hivepack::xz::stream_buffer_bound(len);
        let out_size = match rng.below(4) {
            0 => rng.below(80) as usize,
            _ => bound,
        };
        let lzma = efilter(rng, FILTER_LZMA2, max_dict);
        let refused = rng.below(4) == 0;
        let chain = format!("{}{lzma}", filters_before(rng, refused));
        requests.push(if rng.below(2) == 0 {
            format!("sbuf {}:{out_size}:{chain} {}", check(rng), hex(&data))
        } else {
            format!("rbuf {out_size}:{chain} {}", hex(&data))
        });
        let id = encoder_id(rng);
        let lzma = efilter(rng, id, u32::MAX);
        let chain = if rng.below(3) == 0 {
            refused_chain(rng, &lzma)
        } else {
            format!("{}{lzma}", filters_before(rng, true))
        };
        requests.push(format!("encmem {chain}"));
    }

    // The single-call BCJ filters.
    for _ in 0..count / 3 {
        let len = length(rng, max.min(30_000));
        let data = code_input(rng, len);
        let start = match rng.below(3) {
            0 => 0,
            1 => rng.next() as u32,
            _ => u32::MAX - rng.below(64) as u32,
        };
        requests.push(format!(
            "bcj {} {} {start} {}",
            rng.pick(&["x86", "arm64", "riscv"]),
            rng.pick(&["enc", "dec"]),
            hex(&data)
        ));
    }

    requests.extend(mt_requests(rng, count, max));
    requests
}

/// The threaded encoder's options as the oracle reads them, for `len`
/// bytes of input: one to four threads, Blocks from one byte to the
/// chain's own size (at most 2,000 of them), a preset or a chain, and now
/// and then options it refuses.
fn mt_options(rng: &mut Rng, len: usize) -> String {
    let threads = match rng.below(30) {
        0 => rng.pick(&[0, 16385]),
        _ => 1 + rng.below(4) as u32,
    };
    let block_size = match rng.below(10) {
        0 => 0,
        1 => rng.pick(&[(u64::MAX / 16384) + 1, u64::MAX]),
        2 => (len as u64 / 2000).max(1 + rng.below(100)),
        3 => 1 << 20,
        _ => (len as u64 / 2000).max(rng.pick(&[4096, 10_000, 65_536, 100_000])),
    };
    let preset = rng.below(7) as u32
        | if rng.below(6) == 0 {
            hivepack::xz::PRESET_EXTREME
        } else {
            0
        };
    let chain = match rng.below(3) {
        0 => {
            let id = if rng.below(10) == 0 {
                encoder_id(rng)
            } else {
                FILTER_LZMA2
            };
            let before = if rng.below(2) == 0 {
                let refused = rng.below(5) == 0;
                filters_before(rng, refused)
            } else {
                String::new()
            };
            format!("{before}{}", efilter(rng, id, 1 << 20))
        }
        _ => "-".to_string(),
    };
    let flags = u32::from(rng.below(30) == 0);
    format!(
        "{threads}:{block_size}:0:{preset}:{}:{flags}:{chain}",
        check(rng)
    )
}

/// Requests for the threaded encoder: `count / 2` encodings and the memory
/// usage of encoders. The steps give the input in pieces with LZMA_RUN and
/// room for all the output (so that each call reads all its input, as
/// liblzma's threads may otherwise not let it), with LZMA_FULL_FLUSH and
/// LZMA_FULL_BARRIER, and finish, these with random room.
fn mt_requests(rng: &mut Rng, count: usize, max: usize) -> Vec<String> {
    let mut requests = Vec::new();
    for _ in 0..count / 2 {
        let len = length(rng, max.min(300_000));
        let data = if rng.below(2) == 0 {
            code_input(rng, len)
        } else {
            input(rng, len)
        };
        let options = mt_options(rng, len);
        // Each Block may take some 100 bytes beyond its data.
        let all = len * 100 + 100_000;
        let mut steps = Vec::new();
        let mut offered = 0;
        while offered < len && steps.len() < 40 {
            let n = 1 + chunk(rng, len - offered);
            offered += n;
            let room = 1 + room(rng);
            steps.push(match rng.below(8) {
                0 => format!("c{n}/{room}/2"),
                1 => format!("c{n}/{room}/4"),
                _ => format!("c{n}/{all}/0"),
            });
        }
        steps.push(format!("c{len}/{}/3", 1 + room(rng)));
        requests.push(format!(
            "mtcode {options} {} {}",
            steps.join(","),
            hex(&data)
        ));
    }
    for _ in 0..count / 6 {
        let len = rng.below(1 << 20) as usize;
        requests.push(format!("mtmem {}", mt_options(rng, len)));
    }

    // Inputs of several Blocks of 256 KiB to 1 MiB in four threads.
    if max > 100_000 {
        for _ in 0..4 {
            let len = 2_000_000 + rng.below(3_000_000) as usize;
            let data = input(rng, len);
            let block_size = 1 << (18 + rng.below(3));
            let preset = rng.below(4);
            let room = 1 + room(rng);
            requests.push(format!(
                "mtcode 4:{block_size}:0:{preset}:4:0:- c{len}/{room}/3 {}",
                hex(&data)
            ));
        }
    }
    requests
}

#[test]
fn port_encoders_match_liblzma() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x5eed_e201);
    let requests = encoder_requests(&mut rng, 300, 300_000);
    let mut seen = [0usize; 12];
    let (mut ends, mut chain_ends) = (0, 0);
    let (mut big, mut big_ends) = (0, 0);
    let mut mt_ends = 0;
    for request in &requests {
        // liblzma's threads' structures, which the threaded encoder's
        // memory usage counts, are of another size on other systems: the
        // port counts x86-64 Linux's (glibc's mutex has 8 bytes more on
        // arm64).
        if request.starts_with("mtmem ") && !cfg!(all(target_os = "linux", target_arch = "x86_64"))
        {
            continue;
        }
        let want = oracle.ask(request);
        assert_eq!(port_answer(request), want, "{request:.300}");
        mt_ends += usize::from(request.starts_with("mtcode ") && want.starts_with("ok 1 "));
        for ret in returned(&want) {
            seen[ret] += 1;
        }
        ends += usize::from(returned(&want).contains(&1));
        let coder = request.split(' ').nth(1).unwrap_or("");
        let chain = coder.strip_prefix("rawenc:").or_else(|| {
            let rest = coder.strip_prefix("streamenc:")?;
            Some(rest.split_once(':')?.1)
        });
        chain_ends +=
            usize::from(chain.is_some_and(|c| c.starts_with('f')) && returned(&want).contains(&1));
        if request.len() > 2_000_000 {
            big += 1;
            let total_in = want
                .split(' ')
                .rev()
                .nth(1)
                .and_then(|t| t.split('/').next());
            big_ends +=
                usize::from(total_in.is_some_and(|n| n.parse::<u64>().unwrap_or(0) > 1_000_000));
        }
    }
    eprintln!(
        "{} requests, {ends} reach LZMA_STREAM_END ({chain_ends} with delta or BCJ), \
         {mt_ends} threaded encodings end, return codes seen {seen:?}",
        requests.len()
    );
    assert!(chain_ends > 20, "only {chain_ends} chains end");
    assert!(mt_ends > 60, "only {mt_ends} threaded encodings end");
    assert!(
        big_ends * 3 >= big,
        "only {big_ends} of {big} big inputs are read"
    );
    // The results encoders give, and the errors they give for options,
    // checks, actions, memory limits and output space.
    for ret in [0, 1, 3, 8, 10, 11] {
        assert!(seen[ret] > 0, "no call returned {ret}");
    }
    assert!(ends > 200, "only {ends} encodings end");
}

/// Whether `request` can be made on this machine: not a `bound` of a size
/// past `usize`, which a 32-bit `size_t` cannot hold either (the answers
/// were recorded on a 64-bit one).
fn fits_this_machine(request: &str) -> bool {
    match request.strip_prefix("bound ") {
        Some(size) => size.parse::<usize>().is_ok(),
        None => true,
    }
}

#[test]
fn port_encoders_match_recorded_answers() {
    let text =
        std::fs::read_to_string(recorded_encoder_path()).expect("testdata/oracle/xz-encode.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        if !fits_this_machine(request) {
            continue;
        }
        assert_eq!(recorded_form(&port_answer(request)), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > 300, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/xz-encode.txt from the oracle"]
fn record_encoder_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng(0x5eed_e202);
    let mut text = String::from(
        "# Answers from liblzma 5.8.4's encoders (tools/xz-oracle), replayed by crates/xz/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test xz_oracle record_encoder_answers -- --ignored\n",
    );
    for request in encoder_requests(&mut rng, 300, 3000) {
        // Keep the file small: the large inputs are for the live comparison.
        if request.len() > 8_000 {
            continue;
        }
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::write(recorded_encoder_path(), text).expect("written");
}

// The threaded decoder.

fn recorded_mt_path() -> PathBuf {
    repository().join("testdata/oracle/xz-mt.txt")
}

/// `data` as a .xz Stream: the threaded encoder's, with the sizes in its
/// Block Headers that the threaded decoder needs, or the single-threaded
/// one's, without them. `bcj` is set if it has a BCJ filter.
fn mt_stream(rng: &mut Rng, data: &[u8], bcj: &mut bool) -> Vec<u8> {
    let check = Check(rng.pick(&[0, 1, 4, 10]));
    let preset = rng.below(4) as u32;
    let mut out = vec![0; data.len() * 2 + 100_000];
    let mut output = OutBuffer::new(&mut out);
    let mut strm = if rng.below(4) == 0 {
        Stream::easy_encoder(preset, check).unwrap()
    } else {
        let filters = (rng.below(4) == 0).then(|| {
            let before = filters_before(rng, false);
            *bcj |= before
                .split('+')
                .any(|f| f.starts_with('f') && !f.starts_with("f3:"));
            let lzma = "21:65536:3:0:2:1:32:3:0:0:0:-";
            parse_chain(&format!("{before}{lzma}"), true)
        });
        Stream::stream_encoder_mt(&MtOptions {
            threads: 1 + rng.below(3) as u32,
            block_size: (data.len() as u64 / 40).max(1 + rng.below(20_000)),
            preset,
            filters,
            check,
            ..MtOptions::default()
        })
        .unwrap()
    };
    let ret = strm.code(&mut output, &mut InBuffer::new(data), Action::Finish);
    assert_eq!(ret, Ok(Status::StreamEnd));
    let len = output.pos;
    out.truncate(len);
    out
}

/// The threaded decoder's options, as the oracle reads them: one to four
/// threads, now and then refused ones, the flags, and memory limits that
/// send Blocks to the direct mode, or stop the decoder.
fn mt_decoder_options(rng: &mut Rng, concatenated: bool, bcj: bool) -> String {
    let threads = match rng.below(40) {
        0 => rng.pick(&[0, 16385]),
        _ => 1 + rng.below(4) as u32,
    };
    let mut flags = flags(rng);
    if concatenated {
        flags |= CONCATENATED;
    }
    let threading = match rng.below(3) {
        0 => rng.pick(&[0, 1, 1 << 16, 300_000, 1 << 20, 1 << 24]),
        _ => u64::MAX,
    };
    let stop = match rng.below(6) {
        0 => rng.pick(&[0, 1 << 16, 1 << 20, 9 << 20]),
        _ => u64::MAX,
    };
    format!("{threads}:0:{flags}:{threading}:{stop}:{}", u8::from(bcj))
}

/// The steps of a decoding of `len` bytes: pieces with LZMA_RUN, then
/// LZMA_FINISH with all that is left, each with some room for output.
fn mt_decoder_steps(rng: &mut Rng, len: usize) -> String {
    let mut steps = Vec::new();
    let mut offered = 0;
    while offered < len && steps.len() < 60 {
        let n = 1 + chunk(rng, len - offered);
        offered += n;
        steps.push(format!("c{n}/{}/0", 1 + room(rng)));
    }
    steps.push(format!("c{len}/{}/3", 1 + room(rng)));
    steps.join(",")
}

/// Requests for the threaded decoder: `count` Streams with inputs up to
/// `max` bytes, some concatenated, damaged, cut short or followed by more,
/// and the test files of XZ Utils.
fn mt_decoder_requests(rng: &mut Rng, count: usize, max: usize) -> Vec<String> {
    let mut requests = Vec::new();
    for _ in 0..count {
        let len = length(rng, max);
        let data = if rng.below(3) == 0 {
            code_input(rng, len)
        } else {
            input(rng, len)
        };
        let mut bcj = false;
        let mut stream = mt_stream(rng, &data, &mut bcj);
        let mut concatenated = false;
        match rng.below(10) {
            0 | 1 => stream = damage(rng, &stream),
            2 => {
                let at = rng.below(stream.len() as u64) as usize;
                stream.truncate(at);
            }
            3 | 4 => {
                concatenated = true;
                let padding = rng.pick(&[0, 4, 8, 3]);
                stream.resize(stream.len() + padding, 0);
                let more_len = rng.below(20_000) as usize;
                let more = input(rng, more_len);
                stream.extend(mt_stream(rng, &more, &mut bcj));
            }
            5 => stream.extend((0..1 + rng.below(20)).map(|_| rng.next() as u8)),
            _ => {}
        }
        let options = mt_decoder_options(rng, concatenated, bcj);
        let steps = mt_decoder_steps(rng, stream.len());
        requests.push(format!("mtdec {options} {steps} {}", hex(&stream)));
    }
    for (name, data) in test_files() {
        if name.ends_with(".xz") {
            let options = mt_decoder_options(rng, true, name.contains("bcj"));
            let steps = mt_decoder_steps(rng, data.len());
            requests.push(format!("mtdec {options} {steps} {}", hex(&data)));
        }
    }
    requests
}

#[test]
fn port_mt_decoder_matches_liblzma() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let mut rng = Rng(0x5eed_d201);
    let requests = mt_decoder_requests(&mut rng, 300, 3_000_000);
    let mut seen = [0usize; 12];
    for request in &requests {
        let want = oracle.ask(request);
        assert_eq!(port_answer(request), want, "{request:.300}");
        if let Some(ret) = want.split(' ').next().and_then(|r| r.parse::<usize>().ok()) {
            seen[ret] += 1;
        }
    }
    eprintln!("{} requests, last results {seen:?}", requests.len());
    assert!(seen[1] > 100, "only {} Streams end", seen[1]);
    for ret in [6, 9, 10] {
        assert!(seen[ret] > 0, "no decoding ended with {ret}");
    }
}

#[test]
fn port_mt_decoder_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_mt_path()).expect("testdata/oracle/xz-mt.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(recorded_form(&port_answer(request)), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > 100, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/xz-mt.txt from the oracle"]
fn record_mt_decoder_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut rng = Rng(0x5eed_d202);
    let mut text = String::from(
        "# Answers from liblzma 5.8.4's threaded decoder (tools/xz-oracle), replayed by crates/xz/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test xz_oracle record_mt_decoder_answers -- --ignored\n",
    );
    for request in mt_decoder_requests(&mut rng, 300, 3000) {
        // Keep the file small: the large inputs are for the live comparison.
        if request.len() > 6_000 {
            continue;
        }
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{}", recorded_form(&reply));
    }
    std::fs::write(recorded_mt_path(), text).expect("written");
}
