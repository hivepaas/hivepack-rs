//! hivepack::xz against liblzma, call by call. A panic or a difference is a
//! bug.
//!
//! The first byte chooses the decoder: the .xz decoder, the auto decoder,
//! the .lz decoder, the .lzma decoder, a raw LZMA1 or LZMA2 decoder, with
//! delta and BCJ filters before it now and then, or the threaded .xz
//! decoder. The next eight seed its flags, its memory limit or its options,
//! and the pieces. The rest is its input.
//!
//! Every call must agree, up to the first error: the same result, the same
//! bytes read and written, the same output. Now and then a memory limit is
//! set between the calls, with the same result. The threaded decoders' calls
//! read and write as their threads let them, so for them the end and, after
//! a Stream that ends, the output and the bytes read must be the same.

#![no_main]

use hivepack::xz::{
    Action, CONCATENATED, FAIL_FAST, FILTER_LZMA1, FILTER_LZMA2, Filter, FilterOptions,
    IGNORE_CHECK, InBuffer, LzmaOptions, MtOptions, OutBuffer, Status, Stream, TELL_ANY_CHECK,
    TELL_NO_CHECK, TELL_UNSUPPORTED_CHECK,
};
use libfuzzer_sys::fuzz_target;

/// What a call returned, in liblzma's numbers.
fn port_code(ret: hivepack::xz::Result<Status>) -> i32 {
    match ret {
        Ok(status) => status.number(),
        Err(e) => e.number(),
    }
}

fn c_code(ret: Result<liblzma::stream::Status, liblzma::stream::Error>) -> i32 {
    use liblzma::stream::{Error, Status};
    match ret {
        Ok(Status::Ok) => 0,
        Ok(Status::StreamEnd) => 1,
        Err(Error::NoCheck) => 2,
        Err(Error::UnsupportedCheck) => 3,
        Ok(Status::GetCheck) => 4,
        Err(Error::Mem) => 5,
        Err(Error::MemLimit) => 6,
        Err(Error::Format) => 7,
        Err(Error::Options) => 8,
        Err(Error::Data) => 9,
        Ok(Status::MemNeeded) => 10,
        Err(Error::Program) => 11,
    }
}

/// Up to three delta and BCJ filters from their properties, for liblzma's
/// chain and the port's: delta's distance, and a BCJ filter's start offset
/// (in or out of alignment) or none.
fn filters_before(
    next: &mut impl FnMut(usize) -> usize,
    c_filters: &mut liblzma::stream::Filters,
    port: &mut Vec<Filter>,
) {
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

/// A threaded decoder through `steps` (input, output room): LZMA_RUN once, and
/// LZMA_FINISH with what is left until it is done. The output, how it ended,
/// and the number of LZMA_*_CHECK results. `code` makes one call, giving its
/// result and the bytes read and written.
fn drive(
    data: &[u8],
    steps: &[(usize, usize)],
    last_room: usize,
    mut code: impl FnMut(&[u8], &mut [u8], Action) -> (i32, usize, usize),
) -> (Vec<u8>, i32, usize, usize) {
    let mut out = Vec::new();
    let (mut consumed, mut tells) = (0, 0);
    let mut call = |offered: usize, room: usize, action: Action, consumed: &mut usize| {
        let written = out.len();
        out.resize(written + room, 0);
        let (ret, read, made) = code(&data[*consumed..offered], &mut out[written..], action);
        *consumed += read;
        out.truncate(written + made);
        ret
    };
    for &(n, room) in steps {
        let end = consumed + n.min(data.len() - consumed);
        match call(end, room, Action::Run, &mut consumed) {
            0 | 10 => {}
            2..=4 => tells += 1,
            ret => {
                drop(call);
                return (out, ret, tells, consumed);
            }
        }
    }
    loop {
        match call(data.len(), last_room, Action::Finish, &mut consumed) {
            0 => {}
            2..=4 => tells += 1,
            ret => {
                drop(call);
                return (out, ret, tells, consumed);
            }
        }
    }
}

/// The threaded decoders, with one to four threads and no flags, which the
/// `liblzma` crate's builder has no way to give (`tests/oracle.rs` gives them).
fn mt(next: &mut impl FnMut(usize) -> usize, data: &[u8]) {
    let threads = 1 + next(4) as u32;
    let memlimit_threading = MEMLIMITS[next(MEMLIMITS.len())];
    let memlimit_stop = if next(4) == 0 { MEMLIMITS[next(MEMLIMITS.len())] } else { 300 << 20 };
    let mut builder = liblzma::stream::MtStreamBuilder::new();
    builder
        .threads(threads)
        .memlimit_threading(memlimit_threading)
        .memlimit_stop(memlimit_stop);
    let options = MtOptions {
        threads,
        memlimit_threading,
        memlimit_stop,
        ..MtOptions::default()
    };
    let (mut c, mut port) = match (
        builder.decoder(),
        Stream::stream_decoder_mt(&options),
    ) {
        (Ok(c), Ok(port)) => (c, port),
        (Err(c), Err(port)) => {
            assert_eq!(port.number(), c_code(Err(c)));
            return;
        }
        (c, port) => panic!("liblzma {:?}, the port {port:?}", c.err()),
    };

    let mut steps = Vec::new();
    let mut offered = 0;
    while offered < data.len() && steps.len() < 20 {
        let n = 1 + next((data.len() - offered).min(5000));
        offered += n;
        steps.push((n, 1 + next(5000)));
    }
    let last_room = 1 + next(5000);

    let want = drive(data, &steps, last_room, |input, output, action| {
        let (before_in, before_out) = (c.total_in(), c.total_out());
        let c_action = match action {
            Action::Finish => liblzma::stream::Action::Finish,
            _ => liblzma::stream::Action::Run,
        };
        let ret = c_code(c.process(input, output, c_action));
        (ret, (c.total_in() - before_in) as usize, (c.total_out() - before_out) as usize)
    });
    let got = drive(data, &steps, last_room, |input, output, action| {
        let mut p_input = InBuffer::new(input);
        let mut p_output = OutBuffer::new(output);
        let ret = port_code(port.code(&mut p_output, &mut p_input, action));
        (ret, p_input.pos, p_output.pos)
    });

    assert_eq!((got.1, got.2), (want.1, want.2));

    // After an error, the bytes read depend on the threads, and so does the
    // output of a BCJ coder, which leaves what it has not filtered there when
    // the coder after it fails (`tests/oracle.rs` compares the others').
    if want.1 == 1 {
        assert_eq!(got.0, want.0);
        assert_eq!(got.3, want.3);
        assert_eq!((port.total_in(), port.total_out()), (c.total_in(), c.total_out()));
    }
}

/// Memory limits: mostly one that keeps the dictionaries below libFuzzer's
/// limit for a malloc (headers ask for up to 4 GiB), else ones streams
/// reach.
const MEMLIMITS: [u64; 8] = [
    300 << 20,
    300 << 20,
    300 << 20,
    300 << 20,
    0,
    1 << 15,
    1 << 20,
    9 << 20,
];

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let Some((seed, data)) = rest.split_first_chunk::<8>() else {
        return;
    };
    let mut rng = u64::from_le_bytes(*seed) | 1;
    let mut next = move |n: usize| {
        rng ^= rng >> 12;
        rng ^= rng << 25;
        rng ^= rng >> 27;
        (rng.wrapping_mul(0x2545_f491_4f6c_dd1d) % n as u64) as usize
    };
    let flags = [
        TELL_NO_CHECK,
        TELL_UNSUPPORTED_CHECK,
        TELL_ANY_CHECK,
        CONCATENATED,
        IGNORE_CHECK,
        FAIL_FAST,
    ]
    .into_iter()
    .filter(|_| next(3) == 0)
    .fold(0, |flags, flag| flags | flag);
    let memlimit = MEMLIMITS[next(MEMLIMITS.len())];
    if mode % 7 == 6 {
        mt(&mut next, data);
        return;
    }
    let made = match mode % 7 {
        0 => (
            liblzma::stream::Stream::new_stream_decoder(memlimit, flags),
            Stream::stream_decoder(memlimit, flags),
        ),
        // liblzma-sys builds liblzma without HAVE_LZIP_DECODER, and then
        // the auto decoder takes .lz for .lzma. Its .lz decoder is built.
        1 if data.first() == Some(&0x4C) => return,
        1 => (
            liblzma::stream::Stream::new_auto_decoder(memlimit, flags),
            Stream::auto_decoder(memlimit, flags),
        ),
        2 => (
            liblzma::stream::Stream::new_lzip_decoder(memlimit, flags),
            Stream::lzip_decoder(memlimit, flags),
        ),
        3 => (
            liblzma::stream::Stream::new_lzma_decoder(memlimit),
            Stream::alone_decoder(memlimit),
        ),
        raw => {
            // Mostly the options of the presets, now and then ones refused.
            let lzma2 = raw == 5;
            let mut option = |usual: u32| if next(4) == 0 { next(5) as u32 } else { usual };
            let (lc, lp, pb) = (option(3), option(0), option(2));
            let dict_size = 4096 << (2 * next(5));
            let mut c_options = liblzma::stream::LzmaOptions::new();
            c_options
                .dict_size(dict_size)
                .literal_context_bits(lc)
                .literal_position_bits(lp)
                .position_bits(pb);
            let mut filters = liblzma::stream::Filters::new();
            let mut port_filters = Vec::new();
            filters_before(&mut next, &mut filters, &mut port_filters);
            if lzma2 {
                filters.lzma2(&c_options);
            } else {
                filters.lzma1(&c_options);
            }
            port_filters.push(Filter {
                id: if lzma2 { FILTER_LZMA2 } else { FILTER_LZMA1 },
                options: Some(FilterOptions::Lzma(LzmaOptions {
                    dict_size,
                    lc,
                    lp,
                    pb,
                    ..LzmaOptions::default()
                })),
            });
            (
                liblzma::stream::Stream::new_raw_decoder(&filters),
                Stream::raw_decoder(&port_filters),
            )
        }
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
    // Where the input given ends. Once it is all given, LZMA_FINISH, with
    // the same input left, less what was read.
    let mut end = 0;
    for _ in 0..100_000 {
        if next(40) == 0 {
            let limit = MEMLIMITS[next(MEMLIMITS.len())];
            let want = c.set_memlimit(limit).map_err(|e| c_code(Err(e)));
            let got = port.memlimit_set(limit).map_err(|e| e.number());
            assert_eq!(got, want, "memory limit {limit} at input {pos}");
        }
        if end < data.len() {
            end = pos
                + if next(4) == 0 {
                    data.len() - pos
                } else {
                    next((data.len() - pos).min(64) + 1)
                };
        }
        let action = if end == data.len() {
            Action::Finish
        } else {
            Action::Run
        };
        let output_len = if next(4) == 0 { c_out.len() } else { next(600) };
        let input = &data[pos..end];

        let (before_in, before_out) = (c.total_in(), c.total_out());
        let c_action = match action {
            Action::Finish => liblzma::stream::Action::Finish,
            _ => liblzma::stream::Action::Run,
        };
        let want = c_code(c.process(input, &mut c_out[..output_len], c_action));
        let c_read = (c.total_in() - before_in) as usize;
        let c_written = (c.total_out() - before_out) as usize;

        let mut p_input = InBuffer::new(input);
        let mut p_output = OutBuffer::new(&mut p_out[..output_len]);
        let got = port_code(port.code(&mut p_output, &mut p_input, action));
        assert_eq!(got, want, "result at input {pos}");
        assert_eq!(p_input.pos, c_read, "bytes read at input {pos}");
        assert_eq!(p_output.pos, c_written, "bytes written at input {pos}");
        assert_eq!(
            p_out[..c_written],
            c_out[..c_written],
            "output at input {pos}"
        );
        assert_eq!(
            (port.total_in(), port.total_out()),
            (c.total_in(), c.total_out())
        );
        pos += c_read;
        // The end of the stream, an error, or no progress twice.
        if want == 1 || (5..=11).contains(&want) {
            break;
        }
    }
});
