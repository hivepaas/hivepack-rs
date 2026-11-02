//! hivepack::xz's encoders against liblzma's, call by call. A panic or a
//! difference is a bug.
//!
//! The first byte chooses the encoder: .xz of a preset, .xz of LZMA2 with
//! options, .lzma, raw LZMA1 or raw LZMA2, the last three but .lzma with
//! delta and BCJ filters before LZMA now and then, or the threaded .xz
//! encoder. The next eight seed the preset, the check, the options (now
//! and then ones the encoders refuse), the filters, the threads and Block
//! size, the pieces of input and output, and the flushes. The rest is the
//! data.
//!
//! Every call must agree: the same result, the same bytes read and
//! written, the same output. The threaded encoders' calls read and write
//! as their threads let them, so for them the Streams they end with must
//! be the same.

#![no_main]

use hivepack::xz::{
    Action, Check, Filter, InBuffer, LzmaOptions, MatchFinder, Mode, MtOptions, OutBuffer,
    PRESET_EXTREME, Status, Stream,
};
use libfuzzer_sys::fuzz_target;
use liblzma::stream as c;

/// What a call returned, in liblzma's numbers.
fn port_code(ret: hivepack::xz::Result<Status>) -> i32 {
    match ret {
        Ok(status) => status.number(),
        Err(e) => e.number(),
    }
}

fn c_code(ret: Result<c::Status, c::Error>) -> i32 {
    match ret {
        Ok(c::Status::Ok) => 0,
        Ok(c::Status::StreamEnd) => 1,
        Err(c::Error::NoCheck) => 2,
        Err(c::Error::UnsupportedCheck) => 3,
        Ok(c::Status::GetCheck) => 4,
        Err(c::Error::Mem) => 5,
        Err(c::Error::MemLimit) => 6,
        Err(c::Error::Format) => 7,
        Err(c::Error::Options) => 8,
        Err(c::Error::Data) => 9,
        Ok(c::Status::MemNeeded) => 10,
        Err(c::Error::Program) => 11,
    }
}

/// Up to three delta and BCJ filters from their properties, for liblzma's
/// chain and the port's: delta's distance, and a BCJ filter's start offset
/// (in or out of alignment) or none.
fn filters_before(next: &mut impl FnMut(usize) -> usize, c_filters: &mut c::Filters, port: &mut Vec<Filter>) {
    for _ in 0..[0, 0, 1, 2, 3][next(5)] {
        let kind = next(9);
        if kind == 0 {
            let byte = next(256) as u8;
            c_filters.delta_properties(&[byte]).unwrap();
            port.push(Filter::delta(u32::from(byte) + 1));
            continue;
        }
        let id = 3 + kind as u64;
        let props: Vec<u8> = match next(4) {
            0 => Vec::new(),
            1 => (next(1 << 16) as u32).to_le_bytes().to_vec(),
            2 => (u32::MAX - next(64) as u32).to_le_bytes().to_vec(),
            _ => ((next(1 << 16) as u32) << 4).to_le_bytes().to_vec(),
        };
        let added = match id {
            4 => c_filters.x86_properties(&props),
            5 => c_filters.powerpc_properties(&props),
            6 => c_filters.ia64_properties(&props),
            7 => c_filters.arm_properties(&props),
            8 => c_filters.arm_thumb_properties(&props),
            9 => c_filters.sparc_properties(&props),
            10 => c_filters.arm64_properties(&props),
            _ => c_filters.riscv_properties(&props),
        };
        added.unwrap();
        port.push(match props.first_chunk::<4>() {
            Some(start) => Filter::bcj(id, u32::from_le_bytes(*start)),
            None => Filter { id, options: None },
        });
    }
}

fn c_action(action: Action) -> c::Action {
    match action {
        Action::Run => c::Action::Run,
        Action::SyncFlush => c::Action::SyncFlush,
        Action::FullFlush => c::Action::FullFlush,
        Action::FullBarrier => c::Action::FullBarrier,
        Action::Finish => c::Action::Finish,
    }
}

/// A threaded encoder driven through `steps` (input, output room, action):
/// LZMA_RUN once, the other actions until they are done. The Stream, or the
/// result that failed. `code` makes one call, giving its result and the
/// bytes read and written.
fn drive(
    data: &[u8],
    steps: &[(usize, usize, Action)],
    mut code: impl FnMut(&[u8], &mut [u8], Action) -> (i32, usize, usize),
) -> Result<Vec<u8>, i32> {
    let mut out = Vec::new();
    let mut consumed = 0;
    for &(n, room, action) in steps {
        // The next n bytes from where the last call stopped reading.
        let end = consumed + n.min(data.len() - consumed);
        loop {
            let written = out.len();
            out.resize(written + room, 0);
            let (ret, read, made) = code(&data[consumed..end], &mut out[written..], action);
            consumed += read;
            out.truncate(written + made);
            match ret {
                0 if action != Action::Run => {}
                0 | 1 => break,
                _ => return Err(ret),
            }
        }
    }
    Ok(out)
}

/// The threaded encoders with `preset` or `filters`: `threads` threads and
/// Blocks of `block_size`.
fn mt(
    next: &mut impl FnMut(usize) -> usize,
    data: &[u8],
    preset: u32,
    (check, c_check): (u32, c::Check),
    filters: Option<(c::Filters, Vec<Filter>)>,
) {
    let threads = 1 + next(4) as u32;
    let block_size = [0, 1, 100, 4096, 65536][next(5)];
    let mut builder = c::MtStreamBuilder::new();
    builder.threads(threads).block_size(block_size).check(c_check).preset(preset);
    let mut options = MtOptions { threads, block_size, preset, check: Check(check), ..MtOptions::default() };
    if let Some((c_filters, port_filters)) = filters {
        builder.filters(c_filters);
        options.filters = Some(port_filters);
    }
    let (mut c, mut port) = match (builder.encoder(), Stream::stream_encoder_mt(&options)) {
        (Ok(c), Ok(port)) => (c, port),
        (Err(c), Err(port)) => {
            assert_eq!(port.number(), c_code(Err(c)));
            return;
        }
        (c, port) => panic!("liblzma {:?}, the port {port:?}", c.err()),
    };

    // LZMA_RUN with room for all the output, so that each call reads all
    // its input; flushes and the end with little room.
    let all = data.len() * 100 + 100_000;
    let mut steps = Vec::new();
    let mut offered = 0;
    while offered < data.len() && steps.len() < 20 {
        let n = 1 + next((data.len() - offered).min(5000));
        offered += n;
        steps.push(match next(8) {
            0 => (n, 1 + next(300), Action::FullFlush),
            1 => (n, 1 + next(300), Action::FullBarrier),
            _ => (n, all, Action::Run),
        });
    }
    steps.push((data.len(), 1 + next(300), Action::Finish));

    let want = drive(data, &steps, |input, output, action| {
        let (before_in, before_out) = (c.total_in(), c.total_out());
        let ret = c_code(c.process(input, output, c_action(action)));
        (ret, (c.total_in() - before_in) as usize, (c.total_out() - before_out) as usize)
    });
    let got = drive(data, &steps, |input, output, action| {
        let mut p_input = InBuffer::new(input);
        let mut p_output = OutBuffer::new(output);
        let ret = port_code(port.code(&mut p_output, &mut p_input, action));
        (ret, p_input.pos, p_output.pos)
    });
    assert_eq!(got, want);
    // After an error, the input read depends on when the threads told it.
    if want.is_ok() {
        assert_eq!((port.total_in(), port.total_out()), (c.total_in(), c.total_out()));
    }
}

const CHECKS: [(u32, c::Check); 4] = [
    (0, c::Check::None),
    (1, c::Check::Crc32),
    (4, c::Check::Crc64),
    (10, c::Check::Sha256),
];

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let Some((seed, data)) = rest.split_first_chunk::<8>() else { return };
    let mut rng = u64::from_le_bytes(*seed) | 1;
    let mut next = move |n: usize| {
        rng ^= rng >> 12;
        rng ^= rng << 25;
        rng ^= rng >> 27;
        (rng.wrapping_mul(0x2545_f491_4f6c_dd1d) % n as u64) as usize
    };

    // The options: a preset's, changed now and then. Dictionaries stay
    // small enough for libFuzzer's limit for a malloc.
    let preset = next(10) as u32 | if next(5) == 0 { PRESET_EXTREME } else { 0 };
    let mut o = LzmaOptions::preset(preset).unwrap_or_default();
    o.dict_size = [4096, 1 << 16, 1 << 18, 1 << 20, 4095][next(5)];
    if next(4) == 0 {
        (o.lc, o.lp, o.pb) = (next(5) as u32, next(5) as u32, next(5) as u32);
    }
    if next(6) == 0 {
        o.mode = if o.mode == Mode::FAST { Mode::NORMAL } else { Mode::FAST };
    }
    if next(4) == 0 {
        o.nice_len = [1, 2, 3, 5, 16, 64, 273, 274][next(8)];
    }
    if next(4) == 0 {
        o.mf = [MatchFinder::HC3, MatchFinder::HC4, MatchFinder::BT2, MatchFinder::BT3, MatchFinder::BT4][next(5)];
    }
    if next(4) == 0 {
        o.depth = [0, 1, 4, 64][next(4)];
    }
    let mut c_options = c::LzmaOptions::new_preset(preset).unwrap_or_else(|_| c::LzmaOptions::new());
    c_options
        .dict_size(o.dict_size)
        .literal_context_bits(o.lc)
        .literal_position_bits(o.lp)
        .position_bits(o.pb)
        .mode(if o.mode == Mode::FAST { c::Mode::Fast } else { c::Mode::Normal })
        .nice_len(o.nice_len)
        .match_finder(match o.mf {
            MatchFinder::HC3 => c::MatchFinder::HashChain3,
            MatchFinder::HC4 => c::MatchFinder::HashChain4,
            MatchFinder::BT2 => c::MatchFinder::BinaryTree2,
            MatchFinder::BT3 => c::MatchFinder::BinaryTree3,
            _ => c::MatchFinder::BinaryTree4,
        })
        .depth(o.depth);
    let (check, c_check) = CHECKS[next(4)];

    // The encoders, and the flushes each takes.
    let mut filters = c::Filters::new();
    let mut port_filters = Vec::new();
    if mode % 6 == 5 {
        let chain = (next(2) == 0).then(|| {
            filters_before(&mut next, &mut filters, &mut port_filters);
            filters.lzma2(&c_options);
            port_filters.push(Filter::lzma2(o.clone()));
            (filters, port_filters)
        });
        mt(&mut next, data, preset, (check, c_check), chain);
        return;
    }
    if matches!(mode % 6, 1 | 3 | 4) {
        filters_before(&mut next, &mut filters, &mut port_filters);
        if mode % 6 == 3 {
            filters.lzma1(&c_options);
            port_filters.push(Filter::lzma1(o.clone()));
        } else {
            filters.lzma2(&c_options);
            port_filters.push(Filter::lzma2(o.clone()));
        }
    }
    let (made, flushes): (_, &[Action]) = match mode % 6 {
        0 => (
            (c::Stream::new_easy_encoder(preset, c_check), Stream::easy_encoder(preset, Check(check))),
            &[Action::SyncFlush, Action::FullFlush, Action::FullBarrier],
        ),
        1 => (
            (c::Stream::new_stream_encoder(&filters, c_check), Stream::stream_encoder(&port_filters, Check(check))),
            &[Action::SyncFlush, Action::FullFlush, Action::FullBarrier],
        ),
        2 => ((c::Stream::new_lzma_encoder(&c_options), Stream::alone_encoder(&o)), &[]),
        3 => ((c::Stream::new_raw_encoder(&filters), Stream::raw_encoder(&port_filters)), &[]),
        _ => ((c::Stream::new_raw_encoder(&filters), Stream::raw_encoder(&port_filters)), &[Action::SyncFlush]),
    };
    let (mut c, mut port) = match made {
        (Ok(c), Ok(port)) => (c, port),
        (Err(c), Err(port)) => {
            assert_eq!(port.number(), c_code(Err(c)));
            return;
        }
        (c, port) => panic!("liblzma {:?}, the port {port:?}", c.err()),
    };

    let mut c_out = vec![0u8; 1 << 16];
    let mut p_out = vec![0u8; 1 << 16];
    let mut pos = 0;
    // The end of the input given, and the action that must be given again
    // until it is done.
    let mut end = 0;
    let mut action = Action::Run;
    for _ in 0..200_000 {
        if action == Action::Run {
            if end == data.len() {
                action = Action::Finish;
            } else {
                end = pos + if next(4) == 0 { data.len() - pos } else { next((data.len() - pos).min(5000) + 1) };
                if !flushes.is_empty() && next(8) == 0 {
                    action = flushes[next(flushes.len())];
                }
            }
        }
        let output_len = if next(4) == 0 { c_out.len() } else { next(300) };
        let input = &data[pos..end];

        let (before_in, before_out) = (c.total_in(), c.total_out());
        let want = c_code(c.process(input, &mut c_out[..output_len], c_action(action)));
        let c_read = (c.total_in() - before_in) as usize;
        let c_written = (c.total_out() - before_out) as usize;

        let mut p_input = InBuffer::new(input);
        let mut p_output = OutBuffer::new(&mut p_out[..output_len]);
        let got = port_code(port.code(&mut p_output, &mut p_input, action));
        assert_eq!(got, want, "result at input {pos}, {action:?}");
        assert_eq!(p_input.pos, c_read, "bytes read at input {pos}");
        assert_eq!(p_output.pos, c_written, "bytes written at input {pos}");
        assert_eq!(p_out[..c_written], c_out[..c_written], "output at input {pos}");
        assert_eq!((port.total_in(), port.total_out()), (c.total_in(), c.total_out()));
        pos += c_read;
        match want {
            1 if action == Action::Finish => break,
            // A flush done: back to running.
            1 => action = Action::Run,
            0 | 10 => {}
            _ => break,
        }
    }
});
