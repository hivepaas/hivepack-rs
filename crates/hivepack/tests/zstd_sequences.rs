//! The sequence API. What zstd-safe offers of it is compared with libzstd
//! 1.5.7: `ZSTD_sequenceBound`, the parameters (`ZSTD_c_blockDelimiters`,
//! `ZSTD_c_validateSequences`, `ZSTD_c_enableSeqProducerFallback`,
//! `ZSTD_c_repcodeResolution`) set between frames and refused within one,
//! and the frames of `ZSTD_compress2` with them set, which they do not
//! change; and a sequence producer that always fails, which with the
//! fallback gives libzstd's own frames. The rest, through the port alone:
//! sequences generated, compressed back (with block delimiters, merged
//! without, and with their literals apart) and decoded back; frames from a
//! sequence producer, in one call and streaming; and sequences that make no
//! sense, which must fail rather than panic. The comparisons of those with
//! libzstd are the oracle's, in `src/oracle_sequences.rs`.

#![allow(clippy::expect_used, clippy::panic, deprecated)]

#[path = "zstd_support/mod.rs"]
mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hivepack::zstd::{
    CCtx, CParameter as P, CParameterKind as K, DCtx, EndDirective, ErrorCode, InBuffer, OutBuffer,
    ParamSwitch, ResetDirective, SEQUENCE_PRODUCER_ERROR, Sequence, SequenceFormat,
    SequenceProducer, Strategy, merge_block_delimiters, sequence_bound,
};
use support::Rng;
use zstd::zstd_safe::{self, CParameter as C, zstd_sys::ZSTD_EndDirective};

fn bound(len: usize) -> usize {
    hivepack::zstd::compress_bound(len).expect("a size")
}

/// `frame` decoded with the port, with `dict` (loaded) if not empty.
fn decode(frame: &[u8], len: usize, dict: &[u8]) -> Vec<u8> {
    let mut dctx = DCtx::new();
    if !dict.is_empty() {
        dctx.load_dictionary(dict).expect("the dictionary loads");
    }
    let mut out = vec![0u8; len + 1];
    let size = dctx.decompress(&mut out, frame).expect("the frame decodes");
    out.truncate(size);
    out
}

/// The literals of `seqs` in `src`, one after the other.
fn literals_of(seqs: &[Sequence], src: &[u8]) -> Vec<u8> {
    let mut literals = Vec::new();
    let mut pos = 0;
    for seq in seqs {
        literals.extend_from_slice(&src[pos..pos + seq.lit_length as usize]);
        pos += (seq.lit_length + seq.match_length) as usize;
    }
    literals
}

#[test]
fn sequence_bound_is_libzstds() {
    let sizes = (0..5000).chain([
        1023,
        1024,
        1025,
        131_071,
        131_072,
        131_073,
        1 << 20,
        (1 << 20) + 1,
        u32::MAX as usize,
        usize::MAX / 1024,
        usize::MAX / 3,
        usize::MAX,
    ]);
    for size in sizes {
        assert_eq!(
            sequence_bound(size),
            zstd_safe::sequence_bound(size),
            "{size} bytes"
        );
    }
}

/// The sequence API's parameters on both, libzstd's as zstd-safe names
/// them.
fn sequence_parameters() -> Vec<(P, C)> {
    vec![
        (
            P::BlockDelimiters(SequenceFormat::ExplicitBlockDelimiters),
            C::BlockDelimiters(true),
        ),
        (
            P::BlockDelimiters(SequenceFormat::NoBlockDelimiters),
            C::BlockDelimiters(false),
        ),
        (P::ValidateSequences(true), C::ValidateSequences(true)),
        (P::ValidateSequences(false), C::ValidateSequences(false)),
        (
            P::EnableSeqProducerFallback(true),
            C::EnableSeqProducerFallback(true),
        ),
        (
            P::EnableSeqProducerFallback(false),
            C::EnableSeqProducerFallback(false),
        ),
        (
            P::RepcodeResolution(ParamSwitch::Enable),
            C::SearchForExternalRepcodes(zstd_safe::ParamSwitch::Enable),
        ),
        (
            P::RepcodeResolution(ParamSwitch::Disable),
            C::SearchForExternalRepcodes(zstd_safe::ParamSwitch::Disable),
        ),
        (
            P::RepcodeResolution(ParamSwitch::Auto),
            C::SearchForExternalRepcodes(zstd_safe::ParamSwitch::Auto),
        ),
    ]
}

#[test]
fn sequence_parameters_are_set_as_libzstd_sets_them() {
    // Between frames, every value; libzstd's getter gives them as
    // ZSTD_CCtx_getParameter does (zstd-safe has none, the oracle compares
    // it): 0 by default.
    let mut c = zstd_safe::CCtx::create();
    let mut p = CCtx::new();
    for kind in [
        K::BlockDelimiters,
        K::ValidateSequences,
        K::EnableSeqProducerFallback,
        K::RepcodeResolution,
    ] {
        assert_eq!(p.get_parameter(kind), 0, "{kind:?} by default");
    }
    for (pp, cp) in sequence_parameters() {
        c.set_parameter(cp).expect("libzstd sets it");
        p.set_parameter(pp).expect("the port sets it");
        let (kind, value) = match pp {
            P::BlockDelimiters(format) => (K::BlockDelimiters, format as i32),
            P::ValidateSequences(on) => (K::ValidateSequences, i32::from(on)),
            P::EnableSeqProducerFallback(on) => (K::EnableSeqProducerFallback, i32::from(on)),
            P::RepcodeResolution(mode) => (K::RepcodeResolution, mode as i32),
            _ => unreachable!(),
        };
        assert_eq!(p.get_parameter(kind), value, "{pp:?}");
    }
    p.set_parameter(P::ValidateSequences(true))
        .expect("the port sets it");
    p.reset(ResetDirective::Parameters).expect("a reset");
    assert_eq!(p.get_parameter(K::ValidateSequences), 0, "after a reset");

    // Within a frame, refused as libzstd refuses them.
    let content: Vec<u8> = (0..5000u32).map(|i| (i % 7) as u8).collect();
    let mut c_out = vec![0u8; 1 << 16];
    let mut p_out = vec![0u8; 1 << 16];
    let mut c_output = zstd_safe::OutBuffer::around(&mut c_out[..]);
    let mut c_input = zstd_safe::InBuffer::around(&content[..1000]);
    c.compress_stream2(
        &mut c_output,
        &mut c_input,
        ZSTD_EndDirective::ZSTD_e_continue,
    )
    .expect("libzstd takes it");
    let mut p_output = OutBuffer::new(&mut p_out);
    let mut p_input = InBuffer::new(&content[..1000]);
    p.compress_stream2(&mut p_output, &mut p_input, EndDirective::Continue)
        .expect("the port takes it");
    for (pp, cp) in sequence_parameters() {
        let want = c
            .set_parameter(cp)
            .map(|_| ())
            .map_err(|code| zstd_safe::get_error_name(code).to_string());
        let got = p
            .set_parameter(pp)
            .map_err(|error| error.code().message().to_string());
        assert_eq!(got, want, "{pp:?} within a frame");
        assert!(got.is_err(), "{pp:?} within a frame");
    }
}

#[test]
fn sequence_parameters_leave_the_frames_of_compress2_as_libzstds() {
    let mut rng = Rng(0x5E05_0001);
    for (i, level) in [-3, 1, 3, 6, 12, 19].into_iter().enumerate() {
        let len = [100, 5000, 70_000, 200_000][i % 4];
        // On big-endian machines libzstd's block splitter splits full
        // blocks elsewhere (see docs/porting.md).
        if cfg!(target_endian = "big") && level >= 3 && len >= 128 << 10 {
            continue;
        }
        let src = rng.data(len, &[]);
        let mut c = zstd_safe::CCtx::create();
        let mut p = CCtx::new();
        c.set_parameter(C::CompressionLevel(level))
            .expect("libzstd sets it");
        p.set_parameter(P::CompressionLevel(level))
            .expect("the port sets it");
        for (pp, cp) in sequence_parameters().into_iter().skip(i % 2) {
            c.set_parameter(cp).expect("libzstd sets it");
            p.set_parameter(pp).expect("the port sets it");
        }
        let mut want = vec![0u8; bound(len)];
        let w = c
            .compress2(&mut want[..], &src)
            .expect("libzstd compresses");
        let mut got = vec![0u8; bound(len)];
        let g = p.compress2(&mut got, &src).expect("the port compresses");
        assert_eq!(got[..g], want[..w], "level {level}, {len} bytes");
    }
}

/// A sequence producer that always fails, counting its calls.
struct Failing {
    calls: Arc<AtomicUsize>,
    how: usize,
}

impl SequenceProducer for Failing {
    fn produce_sequences(
        &mut self,
        out_seqs: &mut [Sequence],
        src: &[u8],
        _dict: &[u8],
        _compression_level: i32,
        _window_size: usize,
    ) -> usize {
        self.calls.fetch_add(1, Ordering::Relaxed);
        match self.how {
            0 => SEQUENCE_PRODUCER_ERROR,
            1 => out_seqs.len() + 1,
            // No sequences for a block that has bytes.
            _ => usize::from(src.is_empty()),
        }
    }
}

#[test]
fn a_failing_sequence_producer_falls_back_to_libzstds_frames() {
    let mut rng = Rng(0x5E05_0002);
    for (i, level) in [-1, 1, 3, 5, 9, 16, 19].into_iter().enumerate() {
        let len = [3, 6, 7, 3000, 60_000, 150_000][i % 6];
        if cfg!(target_endian = "big") && level >= 3 && len >= 128 << 10 {
            continue;
        }
        let src = rng.data(len, &[]);
        let mut want = vec![0u8; bound(len)];
        let mut c = zstd_safe::CCtx::create();
        c.set_parameter(C::CompressionLevel(level))
            .expect("libzstd sets it");
        let w = c
            .compress2(&mut want[..], &src)
            .expect("libzstd compresses");

        let calls = Arc::new(AtomicUsize::new(0));
        let mut p = CCtx::new();
        p.set_parameter(P::CompressionLevel(level))
            .expect("the port sets it");
        p.register_sequence_producer(Some(Box::new(Failing {
            calls: calls.clone(),
            how: i % 3,
        })));
        // Without the fallback, the frame fails at its first block of 7
        // bytes or more; a smaller one has no sequences to ask for.
        let mut got = vec![0u8; bound(len)];
        let result = p.compress2(&mut got, &src);
        if len < 7 {
            let g = result.expect("too small to ask the producer");
            assert_eq!(got[..g], want[..w], "level {level}, {len} bytes");
            assert_eq!(calls.load(Ordering::Relaxed), 0);
            continue;
        }
        assert_eq!(
            result.map_err(|error| error.code()),
            Err(ErrorCode::SequenceProducerFailed),
            "level {level}, {len} bytes"
        );
        // A context is reset after an error (until then, as libzstd's, it
        // is still in the frame).
        p.reset(ResetDirective::SessionOnly).expect("a reset");
        // With it, the context's own blocks: libzstd's frame.
        p.set_parameter(P::EnableSeqProducerFallback(true))
            .expect("the port sets it");
        let before = calls.load(Ordering::Relaxed);
        let g = p.compress2(&mut got, &src).expect("the port compresses");
        assert_eq!(got[..g], want[..w], "level {level}, {len} bytes");
        assert!(calls.load(Ordering::Relaxed) > before, "the producer asked");
        // And without the producer, the same.
        p.register_sequence_producer(None);
        let g = p.compress2(&mut got, &src).expect("the port compresses");
        assert_eq!(got[..g], want[..w], "level {level}, {len} bytes");
    }
}

/// A small greedy match finder over the block alone: 4-byte matches found
/// through a hash table, then the last literals as a delimiter.
fn greedy(
    out_seqs: &mut [Sequence],
    src: &[u8],
    _dict: &[u8],
    _level: i32,
    window: usize,
) -> usize {
    let mut table = vec![0usize; 1 << 12];
    let (mut pos, mut anchor, mut n) = (0, 0, 0);
    while pos + 4 <= src.len() && n + 2 < out_seqs.len() {
        let value = u32::from_le_bytes([src[pos], src[pos + 1], src[pos + 2], src[pos + 3]]);
        let h = (value.wrapping_mul(2_654_435_761) >> 20) as usize;
        let cand = table[h];
        table[h] = pos + 1;
        if cand != 0 && pos - (cand - 1) <= window {
            let c = cand - 1;
            let mut length = 0;
            while pos + length < src.len() && src[c + length] == src[pos + length] {
                length += 1;
            }
            if length >= 4 {
                out_seqs[n] = Sequence {
                    offset: (pos - c) as u32,
                    lit_length: (pos - anchor) as u32,
                    match_length: length as u32,
                    rep: 0,
                };
                n += 1;
                pos += length;
                anchor = pos;
                continue;
            }
        }
        pos += 1;
    }
    out_seqs[n] = Sequence {
        offset: 0,
        lit_length: (src.len() - anchor) as u32,
        match_length: 0,
        rep: 0,
    };
    n + 1
}

#[test]
fn frames_from_a_sequence_producer_decode_back() {
    let mut rng = Rng(0x5E05_0003);
    for i in 0..24 {
        let len = [0, 5, 100, 4000, 70_000, 300_000][i % 6];
        let src = rng.data(len, &[]);
        let mut p = CCtx::new();
        p.set_parameter(P::CompressionLevel([1, 3, 7, 19][i % 4]))
            .expect("the port sets it");
        p.set_parameter(P::ValidateSequences(i % 2 == 0))
            .expect("the port sets it");
        p.set_parameter(P::RepcodeResolution(
            [ParamSwitch::Auto, ParamSwitch::Enable, ParamSwitch::Disable][i % 3],
        ))
        .expect("the port sets it");
        p.set_parameter(P::ChecksumFlag(true))
            .expect("the port sets it");
        p.register_sequence_producer(Some(Box::new(greedy)));
        let mut frame = vec![0u8; bound(len)];
        let size = if i % 4 == 3 {
            // Streaming, in pieces.
            let mut input = InBuffer::new(&src);
            let mut output = OutBuffer::new(&mut frame);
            while input.pos < src.len() {
                let end = (input.pos + 10_000).min(src.len());
                let mut piece = InBuffer::new(&src[..end]);
                piece.pos = input.pos;
                p.compress_stream2(&mut output, &mut piece, EndDirective::Continue)
                    .expect("the port takes it");
                input.pos = piece.pos;
            }
            while p
                .compress_stream2(&mut output, &mut input, EndDirective::End)
                .expect("the port ends it")
                != 0
            {}
            output.pos
        } else {
            p.compress2(&mut frame, &src).expect("the port compresses")
        };
        assert_eq!(decode(&frame[..size], len, &[]), src, "frame {i}");
    }
}

/// A producer that counts its calls in `calls`, for the greedy parse.
struct Counting(Arc<AtomicUsize>);

impl SequenceProducer for Counting {
    fn produce_sequences(
        &mut self,
        out_seqs: &mut [Sequence],
        src: &[u8],
        dict: &[u8],
        compression_level: i32,
        window_size: usize,
    ) -> usize {
        self.0.fetch_add(1, Ordering::Relaxed);
        greedy(out_seqs, src, dict, compression_level, window_size)
    }
}

#[test]
fn a_sequence_producer_registered_while_streaming_serves_the_next_frame() {
    let src = Rng(0x5E05_0004).data(400_000, &[]);
    let (first, second) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let mut p = CCtx::new();
    p.register_sequence_producer(Some(Box::new(Counting(first.clone()))));
    let mut frame = vec![0u8; bound(src.len())];
    let mut output = OutBuffer::new(&mut frame);
    let mut input = InBuffer::new(&src[..200_000]);
    p.compress_stream2(&mut output, &mut input, EndDirective::Continue)
        .expect("the port takes it");
    assert!(first.load(Ordering::Relaxed) > 0, "a block compressed");
    // The frame goes on with the first.
    p.register_sequence_producer(Some(Box::new(Counting(second.clone()))));
    let mut input = InBuffer {
        src: &src,
        pos: input.pos,
    };
    while p
        .compress_stream2(&mut output, &mut input, EndDirective::End)
        .expect("the port ends it")
        != 0
    {}
    let size = output.pos;
    assert_eq!(second.load(Ordering::Relaxed), 0, "not in that frame");
    assert_eq!(decode(&frame[..size], src.len(), &[]), src);
    // The next frame takes the second.
    let calls = first.load(Ordering::Relaxed);
    let size = p.compress2(&mut frame, &src).expect("the port compresses");
    assert_eq!(first.load(Ordering::Relaxed), calls);
    assert!(second.load(Ordering::Relaxed) > 0, "the next frame");
    assert_eq!(decode(&frame[..size], src.len(), &[]), src);
    // A reset of the parameters drops it.
    p.reset(ResetDirective::Parameters).expect("a reset");
    let calls = second.load(Ordering::Relaxed);
    p.compress2(&mut frame, &src).expect("the port compresses");
    assert_eq!(second.load(Ordering::Relaxed), calls);
}

#[test]
fn a_sequence_producer_is_refused_with_long_distance_matching_and_workers() {
    let src = Rng(0x5E05_0005).data(20_000, &[]);
    let mut frame = vec![0u8; bound(src.len())];
    let mut p = CCtx::new();
    p.register_sequence_producer(Some(Box::new(greedy)));
    p.set_parameter(P::EnableLongDistanceMatching(ParamSwitch::Enable))
        .expect("the port sets it");
    let failed = |result: hivepack::zstd::Result<usize>| result.map_err(|error| error.code());
    assert_eq!(
        failed(p.compress2(&mut frame, &src)),
        Err(ErrorCode::ParameterCombinationUnsupported)
    );
    // At the first block that asks the producer: none, for 6 bytes.
    assert!(p.compress2(&mut frame, &src[..6]).is_ok());
    p.set_parameter(P::EnableLongDistanceMatching(ParamSwitch::Disable))
        .expect("the port sets it");
    p.set_parameter(P::NbWorkers(2)).expect("the port sets it");
    // As the frame starts, whatever its size.
    assert_eq!(
        failed(p.compress2(&mut frame, &src[..6])),
        Err(ErrorCode::ParameterCombinationUnsupported)
    );
}

#[test]
fn generated_sequences_compress_back_to_their_input() {
    let mut rng = Rng(0x5E05_0006);
    let base = rng.data(30_000, &[]);
    let mut checked = 0;
    for i in 0..40 {
        let len = [7, 100, 3000, 40_000, 131_072, 200_000, 300_000][i % 7];
        let src = rng.data(len, &base);
        let level = [-5, -1, 1, 2, 3, 4, 5, 7, 9, 12, 13, 15, 16, 18, 19, 22][i % 16];
        let dict: Vec<u8> = if i % 5 == 4 {
            base[..rng.range(100, 20_000) as usize].to_vec()
        } else {
            Vec::new()
        };
        let mut gen_ctx = CCtx::new();
        gen_ctx
            .set_parameter(P::CompressionLevel(level))
            .expect("the port sets it");
        if i % 3 == 0 {
            gen_ctx
                .set_parameter(P::SplitAfterSequences(ParamSwitch::Enable))
                .expect("the port sets it");
        }
        gen_ctx.load_dictionary(&dict).expect("a dictionary");
        let mut seqs = vec![Sequence::default(); sequence_bound(len)];
        let n = gen_ctx
            .generate_sequences(&mut seqs, &src)
            .expect("the sequences");
        seqs.truncate(n);
        let total: usize = seqs
            .iter()
            .map(|s| (s.lit_length + s.match_length) as usize)
            .sum();
        assert_eq!(total, len, "the sequences make the input");

        let compress = |format: SequenceFormat, seqs: &[Sequence]| {
            let mut cctx = CCtx::new();
            cctx.set_parameter(P::CompressionLevel(level))
                .expect("the port sets it");
            cctx.set_parameter(P::BlockDelimiters(format))
                .expect("the port sets it");
            cctx.set_parameter(P::ValidateSequences(true))
                .expect("the port sets it");
            cctx.set_parameter(P::ChecksumFlag(true))
                .expect("the port sets it");
            cctx.set_parameter(P::RepcodeResolution(
                [ParamSwitch::Enable, ParamSwitch::Disable][i % 2],
            ))
            .expect("the port sets it");
            cctx.load_dictionary(&dict).expect("a dictionary");
            let mut frame = vec![0u8; bound(len)];
            let size = cctx
                .compress_sequences(&mut frame, seqs, &src)
                .expect("the sequences compress");
            frame.truncate(size);
            frame
        };
        // With their block delimiters.
        let frame = compress(SequenceFormat::ExplicitBlockDelimiters, &seqs);
        assert_eq!(decode(&frame, len, &dict), src, "frame {i}, level {level}");

        // With their literals apart: blocks that do not compress fail.
        let literals = literals_of(&seqs, &src);
        let mut cctx = CCtx::new();
        cctx.set_parameter(P::CompressionLevel(level))
            .expect("the port sets it");
        cctx.set_parameter(P::BlockDelimiters(SequenceFormat::ExplicitBlockDelimiters))
            .expect("the port sets it");
        cctx.load_dictionary(&dict).expect("a dictionary");
        let mut frame = vec![0u8; bound(len)];
        // A block holds at most a quarter of the largest block's size in
        // sequences (a third with a shortest match of 3), its delimiter
        // included here: small inputs have small blocks.
        let crowded = seqs
            .split_inclusive(|s| s.match_length == 0)
            .any(|block| block.len() >= len.min(128 << 10) / 4);
        match cctx.compress_sequences_and_literals(&mut frame, &seqs, &literals, len) {
            Ok(size) => assert_eq!(decode(&frame[..size], len, &dict), src, "frame {i}"),
            Err(error) if crowded && error.code() == ErrorCode::ExternalSequencesInvalid => {}
            Err(error) => assert_eq!(
                error.code(),
                ErrorCode::CannotProduceUncompressedBlock,
                "frame {i}"
            ),
        }

        // Merged, without delimiters: the context cuts the blocks.
        let mut merged = seqs.clone();
        let m = merge_block_delimiters(&mut merged);
        merged.truncate(m);
        assert!(merged.iter().all(|s| s.match_length != 0));
        let frame = compress(SequenceFormat::NoBlockDelimiters, &merged);
        assert_eq!(decode(&frame, len, &dict), src, "frame {i}, level {level}");
        checked += 1;
    }
    assert_eq!(checked, 40);
}

#[test]
fn generating_sequences_fails_as_libzstd_fails() {
    let src = Rng(0x5E05_0007).data(140_000, &[]);
    let mut p = CCtx::new();
    let mut seqs = vec![Sequence::default(); sequence_bound(src.len())];
    let code = |result: hivepack::zstd::Result<usize>| result.map_err(|error| error.code());
    // A block too small to have sequences: the input's, or its last.
    assert_eq!(
        code(p.generate_sequences(&mut seqs, &src[..6])),
        Err(ErrorCode::SequenceProducerFailed)
    );
    assert_eq!(
        code(p.generate_sequences(&mut seqs, &src[..131_075])),
        Err(ErrorCode::SequenceProducerFailed)
    );
    assert_eq!(code(p.generate_sequences(&mut seqs, &[])), Ok(0));
    // Too little room: the blocks that fit are there.
    let n = p
        .generate_sequences(&mut seqs, &src[..131_072 + 100])
        .expect("the sequences");
    let first_block = seqs
        .iter()
        .position(|s| s.match_length == 0)
        .expect("a delimiter")
        + 1;
    let mut short = vec![Sequence::default(); n - 1];
    assert_eq!(
        code(p.generate_sequences(&mut short, &src[..131_072 + 100])),
        Err(ErrorCode::DstSizeTooSmall)
    );
    assert_eq!(short[..first_block], seqs[..first_block]);
    // Not with workers (once reset, after the error, as after any).
    p.reset(ResetDirective::SessionOnly).expect("a reset");
    p.set_parameter(P::NbWorkers(1)).expect("the port sets it");
    assert_eq!(
        code(p.generate_sequences(&mut seqs, &src[..1000])),
        Err(ErrorCode::ParameterUnsupported)
    );
    // Nor with a target size for compressed blocks.
    p.set_parameter(P::NbWorkers(0)).expect("the port sets it");
    p.set_parameter(P::TargetCBlockSize(1340))
        .expect("the port sets it");
    assert_eq!(
        code(p.generate_sequences(&mut seqs, &src[..1000])),
        Err(ErrorCode::ParameterUnsupported)
    );
    p.set_parameter(P::TargetCBlockSize(0))
        .expect("the port sets it");
    assert!(p.generate_sequences(&mut seqs, &src[..1000]).is_ok());
}

#[test]
fn compress_sequences_leaves_the_context_in_a_frame() {
    let src = b"abcdabcdabcdabcdabcd".repeat(10);
    let seqs = [
        Sequence {
            offset: 4,
            lit_length: 4,
            match_length: 196,
            rep: 0,
        },
        Sequence::default(),
    ];
    let mut p = CCtx::new();
    p.set_parameter(P::BlockDelimiters(SequenceFormat::ExplicitBlockDelimiters))
        .expect("the port sets it");
    let mut frame = vec![0u8; 400];
    let size = p
        .compress_sequences(&mut frame, &seqs, &src)
        .expect("the sequences compress");
    assert_eq!(decode(&frame[..size], src.len(), &[]), src);
    assert_eq!(
        p.set_parameter(P::ValidateSequences(true))
            .map_err(|error| error.code()),
        Err(ErrorCode::StageWrong)
    );
    // The level, as within any frame, can still be set.
    p.set_parameter(P::CompressionLevel(5))
        .expect("the port sets it");
    p.reset(ResetDirective::SessionOnly).expect("a reset");
    p.set_parameter(P::ValidateSequences(true))
        .expect("the port sets it");
    let size = p
        .compress_sequences(&mut frame, &seqs, &src)
        .expect("the sequences compress");
    assert_eq!(decode(&frame[..size], src.len(), &[]), src);
}

#[test]
fn sequences_that_make_no_sense_fail_without_panicking() {
    let src: Vec<u8> = (0..2000u32).map(|i| (i % 13) as u8).collect();
    let code = |result: hivepack::zstd::Result<usize>| result.map_err(|error| error.code());
    let seq = |offset, lit_length, match_length| Sequence {
        offset,
        lit_length,
        match_length,
        rep: 0,
    };
    let mut frame = vec![0u8; bound(src.len())];
    for (format, repcodes) in [
        (
            SequenceFormat::ExplicitBlockDelimiters,
            ParamSwitch::Disable,
        ),
        (SequenceFormat::ExplicitBlockDelimiters, ParamSwitch::Enable),
        (SequenceFormat::NoBlockDelimiters, ParamSwitch::Enable),
    ] {
        let mut p = CCtx::new();
        p.set_parameter(P::BlockDelimiters(format))
            .expect("the port sets it");
        p.set_parameter(P::RepcodeResolution(repcodes))
            .expect("the port sets it");
        // An offset whose offset code wraps around to 0.
        let seqs = [seq(0xFFFF_FFFD, 10, 1990), seq(0, 0, 0)];
        assert_eq!(
            code(p.compress_sequences(&mut frame, &seqs, &src)),
            Err(ErrorCode::ExternalSequencesInvalid),
            "{format:?}, {repcodes:?}"
        );
        // Lengths whose sum wraps around: literals past the block.
        let seqs = [seq(1, u32::MAX, 1), seq(1, 10, 1990), seq(0, 0, 0)];
        assert_eq!(
            code(p.compress_sequences(&mut frame, &seqs, &src)),
            Err(ErrorCode::ExternalSequencesInvalid),
            "{format:?}, {repcodes:?}"
        );
        // Too little room for the frame header.
        let seqs = [seq(13, 13, 1987), seq(0, 0, 0)];
        assert_eq!(
            code(p.compress_sequences(&mut frame[..17], &seqs, &src)),
            Err(ErrorCode::DstSizeTooSmall)
        );
    }

    // Without delimiters, a match past the input that ends the frame in a
    // block too small to hold a match: the block would end before it
    // starts.
    let mut p = CCtx::new();
    p.set_parameter(P::MaxBlockSize(1024))
        .expect("the port sets it");
    let seqs = [seq(13, 13, 1100)];
    assert_eq!(
        code(p.compress_sequences(&mut frame, &seqs, &src[..1026])),
        Err(ErrorCode::ExternalSequencesInvalid)
    );

    // Literals apart, the same offset.
    let mut p = CCtx::new();
    p.set_parameter(P::BlockDelimiters(SequenceFormat::ExplicitBlockDelimiters))
        .expect("the port sets it");
    let seqs = [seq(0xFFFF_FFFD, 10, 1990), seq(0, 0, 0)];
    assert_eq!(
        code(p.compress_sequences_and_literals(&mut frame, &seqs, &src[..10], 2000)),
        Err(ErrorCode::ExternalSequencesInvalid)
    );

    // With workers, over 512 KB.
    let big = vec![7u8; 600_000];
    let mut p = CCtx::new();
    p.set_parameter(P::NbWorkers(2)).expect("the port sets it");
    let mut big_frame = vec![0u8; bound(big.len())];
    assert_eq!(
        code(p.compress_sequences(&mut big_frame, &[seq(1, 1, 599_999)], &big)),
        Err(ErrorCode::ParameterCombinationUnsupported)
    );
    // Not over it.
    let size = p
        .compress_sequences(&mut big_frame, &[seq(1, 1, 99_999)], &big[..100_000])
        .expect("without workers");
    assert_eq!(decode(&big_frame[..size], 100_000, &[]), big[..100_000]);

    // Random sequences, any values: a frame or an error, never a panic.
    let mut rng = Rng(0x5E05_0008);
    let pick = |rng: &mut Rng| -> u32 {
        match rng.range(0, 9) {
            0 => u32::MAX - rng.range(0, 4) as u32,
            1 => 0,
            2 => rng.range(0, 3) as u32,
            3 => rng.next() as u32,
            4 => rng.range(0, 70_000) as u32,
            _ => rng.range(0, 300) as u32,
        }
    };
    for i in 0..3000 {
        let mut p = CCtx::new();
        let format = if i % 2 == 0 {
            SequenceFormat::ExplicitBlockDelimiters
        } else {
            SequenceFormat::NoBlockDelimiters
        };
        p.set_parameter(P::BlockDelimiters(format))
            .expect("the port sets it");
        p.set_parameter(P::ValidateSequences(i % 3 == 0))
            .expect("the port sets it");
        p.set_parameter(P::RepcodeResolution(
            [ParamSwitch::Enable, ParamSwitch::Disable][i % 5 % 2],
        ))
        .expect("the port sets it");
        p.set_parameter(P::Strategy(Some(Strategy::Btultra2)))
            .expect("the port sets it");
        if i % 4 == 0 {
            p.set_parameter(P::MaxBlockSize(1024))
                .expect("the port sets it");
        }
        let seqs: Vec<Sequence> = (0..rng.range(0, 12))
            .map(|_| Sequence {
                offset: pick(&mut rng),
                lit_length: pick(&mut rng),
                match_length: pick(&mut rng),
                rep: pick(&mut rng),
            })
            .collect();
        let len = rng.range(0, 2000) as usize;
        let _ = p.compress_sequences(&mut frame, &seqs, &src[..len]);
        let lits = rng.range(0, 2000) as usize;
        let _ = p.compress_sequences_and_literals(
            &mut frame,
            &seqs,
            &src[..lits],
            pick(&mut rng) as usize % 100_000,
        );
        let _ = merge_block_delimiters(&mut seqs.clone());
    }
}

/// A context with a producer moves to another thread, and compresses there.
#[test]
fn a_context_with_a_sequence_producer_moves_between_threads() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<CCtx>();
    let mut p = CCtx::new();
    p.register_sequence_producer(Some(Box::new(greedy)));
    let src = Rng(0x5E05_0009).data(50_000, &[]);
    let frame = std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let mut frame = vec![0u8; bound(src.len())];
                let size = p.compress2(&mut frame, &src).expect("the port compresses");
                frame.truncate(size);
                (frame, src)
            })
            .join()
            .expect("the thread ends")
    });
    assert_eq!(decode(&frame.0, frame.1.len(), &[]), frame.1);
}
