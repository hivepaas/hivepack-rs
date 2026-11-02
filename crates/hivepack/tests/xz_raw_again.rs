//! [`Stream::raw_encoder_again`] writes what a new encoder writes, after a
//! finished run and after one given up on.

#![allow(clippy::unwrap_used)]

use hivepack::xz::{Action, Filter, InBuffer, LzmaOptions, OutBuffer, Status, Stream};

/// Text-like data that compresses, different for each `seed`.
fn data(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761) | 1;
    (0..len)
        .map(|i| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            if i % 7 < 4 {
                b'a' + (i % 5) as u8
            } else {
                state as u8
            }
        })
        .collect()
}

fn finish(stream: &mut Stream, input: &[u8]) -> Vec<u8> {
    let mut out = vec![0; input.len() * 2 + 4096];
    let mut output = OutBuffer::new(&mut out);
    let mut from = InBuffer::new(input);
    loop {
        match stream.code(&mut output, &mut from, Action::Finish).unwrap() {
            Status::StreamEnd => break,
            _ => assert!(output.pos < output.dst.len()),
        }
    }
    let made = output.pos;
    out.truncate(made);
    out
}

fn chains() -> Vec<Vec<Filter>> {
    let mut chains = Vec::new();
    for preset in [0, 1, 6] {
        chains.push(vec![Filter::lzma1(LzmaOptions::preset(preset).unwrap())]);
        chains.push(vec![Filter::lzma2(LzmaOptions::preset(preset).unwrap())]);
    }
    chains
}

#[test]
fn the_same_as_a_new_encoder_after_a_finished_run() {
    for chain in chains() {
        let mut stream = Stream::raw_encoder(&chain).unwrap();
        for seed in 1..5 {
            let input = data(seed, 100_000 / seed as usize);
            let got = finish(&mut stream, &input);
            let mut new = Stream::raw_encoder(&chain).unwrap();
            assert_eq!(got, finish(&mut new, &input));
            stream = stream.raw_encoder_again(&chain).unwrap();
        }
    }
}

#[test]
fn the_same_as_a_new_encoder_after_a_run_given_up_on() {
    for chain in chains() {
        let mut stream = Stream::raw_encoder(&chain).unwrap();
        let mut out = vec![0; 4096];
        let first = data(9, 50_000);
        let mut output = OutBuffer::new(&mut out);
        let mut from = InBuffer::new(&first);
        stream.code(&mut output, &mut from, Action::Run).unwrap();

        let input = data(10, 50_000);
        let mut again = stream.raw_encoder_again(&chain).unwrap();
        let mut new = Stream::raw_encoder(&chain).unwrap();
        assert_eq!(finish(&mut again, &input), finish(&mut new, &input));
    }
}

#[test]
fn another_kind_of_encoder_starts_anew() {
    let lzma1 = vec![Filter::lzma1(LzmaOptions::preset(1).unwrap())];
    let lzma2 = vec![Filter::lzma2(LzmaOptions::preset(6).unwrap())];
    let input = data(3, 50_000);
    let mut stream = Stream::raw_encoder(&lzma1).unwrap();
    finish(&mut stream, &input);
    let mut again = stream.raw_encoder_again(&lzma2).unwrap();
    let mut new = Stream::raw_encoder(&lzma2).unwrap();
    assert_eq!(finish(&mut again, &input), finish(&mut new, &input));
}
