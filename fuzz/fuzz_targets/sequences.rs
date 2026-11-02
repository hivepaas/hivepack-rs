//! The sequence API, which zstd-safe does not offer to compare with (the
//! oracle's tests compare it with libzstd). The first byte picks what to
//! do with the rest:
//! - generate its sequences at a level (`generate_sequences`), then
//!   compress them back with `compress_sequences`, with their block
//!   delimiters and merged without, and with `compress_sequences_and_literals`:
//!   every frame must decode back to it;
//! - read sequences from its start, any values, and compress them over the
//!   rest, as they come or as a sequence producer's for every block: a
//!   frame or an error, never a panic.

#![no_main]
#![allow(deprecated)]

use hivepack::zstd::{
    CCtx, CParameter as P, DCtx, ErrorCode, ParamSwitch, SEQUENCE_PRODUCER_ERROR, Sequence,
    SequenceFormat, SequenceProducer, Strategy, merge_block_delimiters, sequence_bound,
};
use libfuzzer_sys::fuzz_target;

const LEVELS: [i32; 8] = [-3, 1, 3, 5, 9, 13, 16, 19];

fn decodes_to(frame: &[u8], src: &[u8]) -> bool {
    let mut out = vec![0u8; src.len() + 1];
    matches!(DCtx::new().decompress(&mut out, frame), Ok(n) if out[..n] == *src)
}

/// The sequences of `src` at a level, compressed back three ways.
fn round_trip(pick: u8, src: &[u8]) {
    let level = LEVELS[usize::from(pick >> 2) % LEVELS.len()];
    let mut cctx = CCtx::new();
    let _ = cctx.set_parameter(P::CompressionLevel(level));
    if pick & 0x80 != 0 {
        let _ = cctx.set_parameter(P::SplitAfterSequences(ParamSwitch::Enable));
    }
    let mut seqs = vec![Sequence::default(); sequence_bound(src.len())];
    let Ok(n) = cctx.generate_sequences(&mut seqs, src) else {
        // A block too small to have sequences.
        return;
    };
    seqs.truncate(n);
    let capacity = hivepack::zstd::compress_bound(src.len()).unwrap_or(0);
    let mut frame = vec![0u8; capacity];
    let compress = |format, seqs: &[Sequence], frame: &mut [u8]| {
        let mut cctx = CCtx::new();
        let _ = cctx.set_parameter(P::CompressionLevel(level));
        let _ = cctx.set_parameter(P::BlockDelimiters(format));
        let _ = cctx.set_parameter(P::ValidateSequences(pick & 0x40 != 0));
        let _ = cctx.set_parameter(P::RepcodeResolution(if pick & 0x20 != 0 {
            ParamSwitch::Enable
        } else {
            ParamSwitch::Disable
        }));
        cctx.compress_sequences(frame, seqs, src)
            .expect("generated sequences compress")
    };
    let size = compress(SequenceFormat::ExplicitBlockDelimiters, &seqs, &mut frame);
    assert!(decodes_to(&frame[..size], src), "with block delimiters");

    let mut literals = Vec::new();
    let mut pos = 0;
    for seq in &seqs {
        literals.extend_from_slice(&src[pos..pos + seq.lit_length as usize]);
        pos += (seq.lit_length + seq.match_length) as usize;
    }
    let mut cctx = CCtx::new();
    let _ = cctx.set_parameter(P::CompressionLevel(level));
    let _ = cctx.set_parameter(P::BlockDelimiters(SequenceFormat::ExplicitBlockDelimiters));
    match cctx.compress_sequences_and_literals(&mut frame, &seqs, &literals, src.len()) {
        Ok(size) => assert!(decodes_to(&frame[..size], src), "literals apart"),
        // A block that does not compress, or with too many sequences for
        // the largest block of a small input.
        Err(error) => assert!(
            matches!(
                error.code(),
                ErrorCode::CannotProduceUncompressedBlock | ErrorCode::ExternalSequencesInvalid
            ),
            "literals apart: {error:?}"
        ),
    }

    let m = merge_block_delimiters(&mut seqs);
    let size = compress(SequenceFormat::NoBlockDelimiters, &seqs[..m], &mut frame);
    assert!(decodes_to(&frame[..size], src), "without block delimiters");
}

/// A length or an offset from two bytes: small, around 64 KB, or near
/// 2^32.
fn value(bytes: &[u8]) -> u32 {
    let (a, b) = (bytes[0], bytes[1]);
    let low = u32::from(u16::from_le_bytes([a, b]));
    match a >> 6 {
        0 => low & 0x3FF,
        1 => low & 0xFF,
        2 => 0x1_0000 + (low & 0x3FFF) - 0x2000,
        _ => u32::MAX - (low & 0xF),
    }
}

/// Sequences read from the start of `data`, and the rest.
fn read_sequences(data: &[u8]) -> (Vec<Sequence>, &[u8]) {
    let Some((&count, data)) = data.split_first() else {
        return (Vec::new(), data);
    };
    let count = (usize::from(count) % 40).min(data.len() / 8);
    let (seq_bytes, rest) = data.split_at(count * 8);
    let seqs = seq_bytes
        .chunks(8)
        .map(|c| Sequence {
            offset: value(&c[0..2]),
            lit_length: value(&c[2..4]),
            match_length: value(&c[4..6]),
            rep: value(&c[6..8]),
        })
        .collect();
    (seqs, rest)
}

/// A sequence producer that gives the sequences it was made with, or fails.
struct Replaying {
    seqs: Vec<Sequence>,
    calls: usize,
    fail_every: usize,
}

impl SequenceProducer for Replaying {
    fn produce_sequences(
        &mut self,
        out_seqs: &mut [Sequence],
        _src: &[u8],
        _dict: &[u8],
        _compression_level: i32,
        _window_size: usize,
    ) -> usize {
        self.calls += 1;
        if self.fail_every != 0 && self.calls % self.fail_every == 0 {
            return SEQUENCE_PRODUCER_ERROR;
        }
        let n = self.seqs.len().min(out_seqs.len());
        out_seqs[..n].copy_from_slice(&self.seqs[..n]);
        n
    }
}

/// Sequences of any values, compressed over `src`: no panic.
fn arbitrary(pick: u8, data: &[u8]) {
    let (seqs, src) = read_sequences(data);
    let mut cctx = CCtx::new();
    let _ = cctx.set_parameter(P::CompressionLevel(LEVELS[usize::from(pick >> 5)]));
    let _ = cctx.set_parameter(P::ValidateSequences(pick & 0x04 != 0));
    let _ = cctx.set_parameter(P::RepcodeResolution(if pick & 0x08 != 0 {
        ParamSwitch::Enable
    } else {
        ParamSwitch::Disable
    }));
    if pick & 0x10 != 0 {
        let _ = cctx.set_parameter(P::MaxBlockSize(1024));
    }
    let capacity = hivepack::zstd::compress_bound(src.len()).unwrap_or(0) + 64;
    let mut frame = vec![0u8; capacity];
    if pick & 0x02 == 0 {
        for format in [
            SequenceFormat::ExplicitBlockDelimiters,
            SequenceFormat::NoBlockDelimiters,
        ] {
            let _ = cctx.reset(hivepack::zstd::ResetDirective::SessionOnly);
            let _ = cctx.set_parameter(P::BlockDelimiters(format));
            let _ = cctx.compress_sequences(&mut frame, &seqs, src);
        }
        let _ = cctx.reset(hivepack::zstd::ResetDirective::SessionOnly);
        let _ = cctx.set_parameter(P::ValidateSequences(false));
        let _ = cctx.set_parameter(P::BlockDelimiters(SequenceFormat::ExplicitBlockDelimiters));
        let half = src.len() / 2;
        let _ = cctx.compress_sequences_and_literals(&mut frame, &seqs, &src[..half], src.len());
    } else {
        // As a sequence producer's, for every block; the strongest
        // strategy splits the blocks after their sequences.
        let _ = cctx.set_parameter(P::EnableSeqProducerFallback(pick & 0x20 != 0));
        if pick & 0x10 != 0 {
            let _ = cctx.set_parameter(P::Strategy(Some(Strategy::Btultra2)));
        }
        cctx.register_sequence_producer(Some(Box::new(Replaying {
            seqs,
            calls: 0,
            fail_every: usize::from(pick >> 6),
        })));
        let _ = cctx.compress2(&mut frame, src);
        let _ = cctx.reset(hivepack::zstd::ResetDirective::SessionOnly);
        let mut out_seqs = vec![Sequence::default(); sequence_bound(src.len())];
        let _ = cctx.generate_sequences(&mut out_seqs, src);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    if pick & 0x03 == 0x03 {
        round_trip(pick, rest);
    } else {
        arbitrary(pick, rest);
    }
});
