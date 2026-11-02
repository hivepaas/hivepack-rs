//! The threaded encoder and decoder where liblzma's results depend on its
//! threads, so that the oracle tests cannot compare them: a timeout that
//! makes calls return early, the progress of the threads, many threads, and
//! a stream dropped while its threads work; and for the decoder, input that
//! stops, memory limits raised, and errors reported at once. The output,
//! which does not depend on them, is compared with liblzma's in `oracle.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "xz_support/mod.rs"]
mod support;

use hivepack::xz::{Action, Check, InBuffer, MtOptions, OutBuffer, Status, Stream};
use support::{Rng, input};

/// `data` encoded by the threaded encoder with `options`, with LZMA_FINISH
/// and `room` bytes of output space per call: the Stream, and the number
/// of calls that made no progress.
fn encode(options: &MtOptions, data: &[u8], room: usize) -> (Vec<u8>, usize) {
    let mut strm = Stream::stream_encoder_mt(options).unwrap();
    let mut out = Vec::new();
    let mut input = InBuffer::new(data);
    let mut idle = 0;
    loop {
        let written = out.len();
        out.resize(written + room, 0);
        let before = input.pos;
        let mut output = OutBuffer::new(&mut out[written..]);
        let status = strm.code(&mut output, &mut input, Action::Finish).unwrap();
        let made = output.pos;
        out.truncate(written + made);
        idle += usize::from(made == 0 && input.pos == before);
        if status == Status::StreamEnd {
            return (out, idle);
        }
    }
}

/// The data of a .xz Stream.
fn decode(xz: &[u8], len: usize) -> Vec<u8> {
    let mut strm = Stream::stream_decoder(u64::MAX, 0).unwrap();
    let mut out = vec![0; len + 1];
    let mut output = OutBuffer::new(&mut out);
    let status = strm
        .code(&mut output, &mut InBuffer::new(xz), Action::Finish)
        .unwrap();
    assert_eq!(status, Status::StreamEnd);
    let written = output.pos;
    out.truncate(written);
    out
}

fn options(threads: u32, block_size: u64, preset: u32) -> MtOptions {
    MtOptions {
        threads,
        block_size,
        preset,
        check: Check::CRC64,
        ..MtOptions::default()
    }
}

#[test]
fn a_timeout_returns_early_with_the_same_output() {
    // Random bytes, which take long to compress.
    let mut rng = Rng(0x5eed_3701);
    let data: Vec<u8> = (0..3 << 20).map(|_| rng.next() as u8).collect();
    let without = encode(&options(2, 256 << 10, 6), &data, 1 << 20).0;
    let with = MtOptions {
        timeout: 1,
        ..options(2, 256 << 10, 6)
    };
    let (out, idle) = encode(&with, &data, 1 << 20);
    assert_eq!(out, without);
    // Each Block takes much longer than a millisecond at preset 6.
    assert!(idle > 0, "no call timed out");
    assert_eq!(decode(&out, data.len()), data);
}

#[test]
fn the_progress_grows_to_the_totals() {
    let mut rng = Rng(0x5eed_3702);
    let data = input(&mut rng, 2 << 20);
    let mut strm = Stream::stream_encoder_mt(&options(3, 128 << 10, 3)).unwrap();
    let mut out = vec![0; 3 << 20];
    let mut input = InBuffer::new(&data);
    let mut written = 0;
    let mut last = (0, 0);
    loop {
        let end = (written + 4096).min(out.len());
        let mut output = OutBuffer::new(&mut out[written..end]);
        let status = strm.code(&mut output, &mut input, Action::Finish).unwrap();
        written += output.pos;
        // The output may shrink: a Block that does not compress is
        // written again as it is, in less than its compressed size.
        let progress = strm.get_progress();
        assert!(progress.0 >= last.0, "{progress:?} after {last:?}");
        assert!(progress.0 <= data.len() as u64);
        last = progress;
        if status == Status::StreamEnd {
            break;
        }
    }
    assert_eq!(last, (strm.total_in(), strm.total_out()));
    assert_eq!(decode(&out[..written], data.len()), data);
}

#[test]
fn many_threads_and_small_blocks() {
    let mut rng = Rng(0x5eed_3703);
    let data = input(&mut rng, 1 << 20);
    let (out, _) = encode(&options(16, 1000, 1), &data, 1 << 16);
    assert_eq!(decode(&out, data.len()), data);
    // The same Stream as one thread writes.
    assert_eq!(out, encode(&options(1, 1000, 1), &data, 1 << 20).0);
}

#[test]
fn a_stream_dropped_while_its_threads_work() {
    let mut rng = Rng(0x5eed_3704);
    let data: Vec<u8> = (0..4 << 20).map(|_| rng.next() as u8).collect();
    for threads in [1, 4] {
        let mut strm = Stream::stream_encoder_mt(&options(threads, 256 << 10, 6)).unwrap();
        let mut out = vec![0; 1 << 16];
        let mut input = InBuffer::new(&data);
        // Until the output is full or all the input is given.
        strm.code(&mut OutBuffer::new(&mut out), &mut input, Action::Run)
            .unwrap();
        // The workers are encoding: they are told to exit and joined.
        drop(strm);
    }
}

#[test]
fn the_number_of_hardware_threads() {
    assert!(hivepack::xz::cputhreads() > 0);
}

// The threaded decoder.

/// `data` as the threaded encoder writes it, in Blocks of `block_size`.
fn threaded_stream(data: &[u8], block_size: u64) -> Vec<u8> {
    encode(&options(4, block_size, 0), data, 1 << 20).0
}

fn decoder_options(threads: u32) -> MtOptions {
    MtOptions {
        threads,
        ..MtOptions::default()
    }
}

/// `xz` decoded by the threaded decoder with LZMA_FINISH and `room` bytes of
/// output space per call: the data, and the calls that returned with room
/// left before the end, which without a timeout they do not.
fn decode_mt(options: &MtOptions, xz: &[u8], room: usize) -> (Vec<u8>, usize) {
    let mut strm = Stream::stream_decoder_mt(options).unwrap();
    let mut out = Vec::new();
    let mut input = InBuffer::new(xz);
    let mut early = 0;
    loop {
        let written = out.len();
        out.resize(written + room, 0);
        let mut output = OutBuffer::new(&mut out[written..]);
        let status = strm.code(&mut output, &mut input, Action::Finish).unwrap();
        let made = output.pos;
        out.truncate(written + made);
        if status == Status::StreamEnd {
            return (out, early);
        }
        early += usize::from(made < room);
    }
}

#[test]
fn the_decoder_with_a_timeout_returns_early_with_the_same_output() {
    // Four symbols at random, which take long to decode.
    let mut rng = Rng(0x5eed_3711);
    let data: Vec<u8> = (0..8 << 20).map(|_| rng.below(4) as u8).collect();
    let xz = threaded_stream(&data, 1 << 20);
    let with = MtOptions {
        timeout: 1,
        ..decoder_options(1)
    };
    let (out, early) = decode_mt(&with, &xz, 1 << 24);
    assert!(out == data);
    // All of it takes much longer than a millisecond.
    assert!(early > 0, "no call timed out");
    // Without a timeout, the call returns when it has filled the output.
    let (out, early) = decode_mt(&decoder_options(1), &xz, 1 << 16);
    assert!(out == data);
    assert_eq!(early, 0);
}

#[test]
fn the_decoder_progress_grows_to_the_totals() {
    let mut rng = Rng(0x5eed_3712);
    let data = input(&mut rng, 2 << 20);
    let xz = threaded_stream(&data, 64 << 10);
    let mut strm = Stream::stream_decoder_mt(&decoder_options(3)).unwrap();
    let mut out = vec![0; data.len() + 1];
    let mut input = InBuffer::new(&xz);
    let mut written = 0;
    let mut last = (0, 0);
    loop {
        let end = (written + 4096).min(out.len());
        let mut output = OutBuffer::new(&mut out[written..end]);
        let status = strm.code(&mut output, &mut input, Action::Finish).unwrap();
        written += output.pos;
        let progress = strm.get_progress();
        assert!(progress.1 >= last.1, "{progress:?} after {last:?}");
        last = progress;
        if status == Status::StreamEnd {
            break;
        }
    }
    assert_eq!(last, (strm.total_in(), strm.total_out()));
    assert_eq!(out[..written], data[..]);
}

#[test]
fn the_decoder_with_many_threads_and_small_blocks() {
    let mut rng = Rng(0x5eed_3713);
    let data = input(&mut rng, 1 << 20);
    let xz = threaded_stream(&data, 1000);
    assert_eq!(decode_mt(&decoder_options(16), &xz, 1 << 16).0, data);
}

#[test]
fn a_decoder_dropped_while_its_threads_work() {
    let mut rng = Rng(0x5eed_3714);
    let data: Vec<u8> = (0..4 << 20).map(|_| rng.next() as u8).collect();
    let xz = threaded_stream(&data, 256 << 10);
    for threads in [1, 4] {
        // In the middle of a Block, with a worker waiting for its input.
        for given in [xz.len() / 2, xz.len()] {
            let mut strm = Stream::stream_decoder_mt(&decoder_options(threads)).unwrap();
            let mut out = vec![0; 1 << 16];
            strm.code(
                &mut OutBuffer::new(&mut out),
                &mut InBuffer::new(&xz[..given]),
                Action::Run,
            )
            .unwrap();
            drop(strm);
        }
    }
}

#[test]
fn input_that_stops_gives_buf_error_with_all_the_output_possible() {
    let mut rng = Rng(0x5eed_3715);
    let data = input(&mut rng, 1 << 20);
    let xz = threaded_stream(&data, 64 << 10);

    for action in [Action::Run, Action::Finish] {
        let mut strm = Stream::stream_decoder_mt(&decoder_options(3)).unwrap();
        let given = &xz[..xz.len() - xz.len() / 3];
        let mut input = InBuffer::new(given);
        let mut out = vec![0; data.len() + 1];
        let mut written = 0;
        let error = loop {
            let mut output = OutBuffer::new(&mut out[written..]);
            let ret = strm.code(&mut output, &mut input, action);
            written += output.pos;
            if let Err(error) = ret {
                break error;
            }
        };
        assert_eq!(error, hivepack::xz::Error::Buf, "{action:?}");
        assert!(written > 0 && written < data.len());
        assert_eq!(out[..written], data[..written]);
    }
}

#[test]
fn a_memory_limit_is_reached_and_raised() {
    let mut rng = Rng(0x5eed_3716);
    let data = input(&mut rng, 1 << 20);
    let xz = threaded_stream(&data, 64 << 10);
    let mut strm = Stream::stream_decoder_mt(&MtOptions {
        memlimit_stop: 1 << 16,
        ..decoder_options(2)
    })
    .unwrap();
    assert_eq!(strm.memlimit_get(), 1 << 16);
    let mut out = vec![0; data.len() + 1];
    let mut output = OutBuffer::new(&mut out);
    let mut input = InBuffer::new(&xz);
    assert_eq!(
        strm.code(&mut output, &mut input, Action::Run),
        Err(hivepack::xz::Error::Memlimit)
    );
    strm.memlimit_set(u64::MAX).unwrap();
    assert_eq!(
        strm.code(&mut output, &mut input, Action::Finish),
        Ok(Status::StreamEnd)
    );
    let written = output.pos;
    assert_eq!(out[..written], data[..]);
    assert!(strm.memusage() >= 1 << 15);
    assert_eq!(strm.get_check(), Check::CRC64);
    assert_eq!(strm.memlimit_set(1), Err(hivepack::xz::Error::Memlimit));
}

#[test]
fn fail_fast_reports_an_error() {
    let mut rng = Rng(0x5eed_3717);
    let data: Vec<u8> = (0..4 << 20).map(|_| rng.next() as u8).collect();
    let mut xz = threaded_stream(&data, 64 << 10);
    // Damage near the end; the Blocks before it take long enough to decode.
    let at = xz.len() - 2000;
    xz[at] ^= 0x40;
    let with = MtOptions {
        flags: hivepack::xz::FAIL_FAST,
        ..decoder_options(4)
    };
    let mut strm = Stream::stream_decoder_mt(&with).unwrap();
    let mut out = vec![0; data.len() + 1];
    let mut output = OutBuffer::new(&mut out);
    let ret = strm.code(&mut output, &mut InBuffer::new(&xz), Action::Finish);
    assert!(ret.is_err(), "{ret:?}");
    // Up to the damaged Block, whose damage may have come out before its
    // check was read. The Blocks are of 64 KiB.
    let written = output.pos.min(data.len() - (128 << 10));
    assert!(out[..written] == data[..written]);
    // Without it, all the output before the error comes first.
    let mut strm = Stream::stream_decoder_mt(&decoder_options(4)).unwrap();
    let mut output = OutBuffer::new(&mut out);
    let ret = strm.code(&mut output, &mut InBuffer::new(&xz), Action::Finish);
    assert_eq!(ret, Err(hivepack::xz::Error::Data));
    assert!(output.pos > data.len() - (256 << 10));
}
