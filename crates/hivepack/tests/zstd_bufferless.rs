//! Decodes every file of the test data through the bufferless functions
//! (`ZSTD_decompressBegin`, `ZSTD_nextSrcSizeToDecompress`,
//! `ZSTD_decompressContinue`): with the output in one buffer, and in a
//! round buffer of `ZSTD_decodingBufferSize_min` bytes, written from its
//! start again when less than a block is left, as libzstd's documentation
//! describes (and its streaming decoder does, when the buffer is smaller
//! than the frame); with the set's dictionary loaded, and as a `DDict`. Every
//! file the one-call decoder decodes must decode to the same output, and
//! none may panic.
//!
//! zstd-safe does not offer these functions; the oracle compares them with
//! libzstd, call by call (`bufferless` in `src/oracle.rs`).

#![allow(clippy::expect_used, clippy::panic)]

#[path = "zstd_support/mod.rs"]
mod support;

use std::path::Path;
use std::sync::Arc;

use hivepack::zstd::{ContentSize, DCtx, DDict, ErrorCode, FrameHeaderState, NextInputType};
use support::{Kind, Problems};

/// Room enough for what the frames decode to, capped; as the one-call
/// decoder gets it.
fn capacity(src: &[u8]) -> usize {
    const CAP: u64 = 64 << 20;
    match hivepack::zstd::find_decompressed_size(src) {
        ContentSize::Known(size) if size <= CAP => size as usize,
        _ => match hivepack::zstd::decompress_bound(src) {
            Some(bound) if bound <= CAP => bound as usize,
            _ => 1 << 20,
        },
    }
}

/// Round buffers up to this size; frames with larger windows are decoded
/// into one buffer only.
const ROUND_MAX: usize = 64 << 20;
const TOO_LARGE: &str = "too large a round buffer";

#[derive(Clone, Copy)]
enum Dict<'a> {
    None,
    Loaded(&'a [u8]),
    Prepared(&'a Arc<DDict>),
}

/// Where each call's output goes.
#[derive(Clone, Copy, Debug)]
enum Layout {
    /// Right after the last, in one buffer of `capacity` bytes.
    OneBuffer,
    /// In a round buffer for each frame.
    Round,
}

/// The frames of `src` through `decompress_continue`, each call given what
/// `next_src_size_to_decompress` asks for. Returns the output, in order.
fn bufferless(src: &[u8], dict: Dict<'_>, layout: Layout) -> Result<Vec<u8>, String> {
    let mut dctx = DCtx::new();
    let mut output = Vec::new();
    let mut one = vec![0u8; capacity(src)];
    let mut round = Vec::new();
    let (mut ip, mut pos) = (0, 0);
    let (mut block_size_max, mut content_size) = (0, 0);
    let mut begin = true;
    for _ in 0..10_000_000 {
        if begin {
            if ip == src.len() {
                return Ok(output);
            }
            match dict {
                Dict::None => dctx.decompress_begin(),
                Dict::Loaded(dict) => dctx
                    .decompress_begin_using_dict(dict)
                    .map_err(|error| format!("begin: {error}"))?,
                Dict::Prepared(ddict) => dctx.decompress_begin_using_ddict(ddict.clone()),
            }
            if let Layout::Round = layout {
                // The frame's round buffer, from its header.
                let header = match hivepack::zstd::get_frame_header(&src[ip..]) {
                    Ok(FrameHeaderState::Complete(header)) => header,
                    _ => return Err("no frame header".into()),
                };
                let size = hivepack::zstd::decoding_buffer_size_min(
                    header.window_size,
                    header.frame_content_size,
                )
                .map_err(|error| format!("round buffer: {error}"))?;
                if size > ROUND_MAX {
                    return Err(TOO_LARGE.into());
                }
                round = vec![0u8; size];
                pos = 0;
                block_size_max = header.block_size_max as usize;
                content_size = header.frame_content_size;
            }
        }
        let next = dctx.next_src_size_to_decompress();
        let piece = &src[ip..(ip + next).min(src.len())];
        let dst = match layout {
            Layout::OneBuffer => &mut one[pos..],
            Layout::Round => {
                if (round.len() as u64) < content_size && round.len() - pos < block_size_max {
                    pos = 0;
                }
                &mut round[pos..]
            }
        };
        let kind = dctx.next_input_type();
        let written = dctx
            .decompress_continue(dst, piece)
            .map_err(|error| format!("{kind:?} at {ip}: {error}"))?;
        output.extend_from_slice(&dst[..written]);
        // Less than asked, at the end of the input, for a stored block.
        ip += piece.len();
        pos += written;
        begin = dctx.next_src_size_to_decompress() == 0;
    }
    Err("no end".into())
}

/// The one-call decoder's output, if it decodes the file.
fn one_call(src: &[u8], dict: Dict<'_>) -> Option<Vec<u8>> {
    let mut out = vec![0u8; capacity(src)];
    let mut dctx = DCtx::new();
    let size = match dict {
        Dict::None => dctx.decompress(&mut out, src),
        Dict::Loaded(dict) => dctx.decompress_using_dict(&mut out, src, dict),
        Dict::Prepared(ddict) => dctx.decompress_using_ddict(&mut out, src, ddict),
    }
    .ok()?;
    out.truncate(size);
    Some(out)
}

#[test]
fn every_test_file_decodes_bufferless_as_in_one_call() {
    let mut problems = Problems::default();
    let (mut files, mut decoded, mut skipped) = (0, 0, 0);
    for set in support::manifest().sets.iter().filter(|set| set.present()) {
        let paths = match set.kind {
            Kind::Frames | Kind::BadFrames => set.frames(),
            Kind::Fuzz => set.list(),
            _ => continue,
        };
        let dictionary = set.dictionary.as_ref().map(|d| set.read(Path::new(d)));
        let ddict = dictionary
            .as_ref()
            .and_then(|d| DDict::new(d).ok())
            .map(Arc::new);
        let dicts = match (&dictionary, &ddict) {
            (Some(dict), Some(ddict)) => vec![Dict::Loaded(dict), Dict::Prepared(ddict)],
            (Some(dict), None) => vec![Dict::Loaded(dict)],
            _ => vec![Dict::None],
        };
        for path in paths {
            let src = set.read(&path);
            files += 1;
            for &dict in &dicts {
                let want = one_call(&src, dict);
                for layout in [Layout::OneBuffer, Layout::Round] {
                    let got = bufferless(&src, dict, layout);
                    if let Some(want) = &want {
                        decoded += 1;
                        match got {
                            Ok(got) if got == *want => {}
                            Ok(got) => problems.add(format!(
                                "{}/{} ({layout:?}): {} bytes, one call {}",
                                set.name,
                                path.display(),
                                got.len(),
                                want.len()
                            )),
                            Err(error) if error == TOO_LARGE => skipped += 1,
                            Err(error) => problems.add(format!(
                                "{}/{} ({layout:?}): {error}",
                                set.name,
                                path.display()
                            )),
                        }
                    }
                }
            }
        }
    }
    eprintln!(
        "{files} files, {decoded} decodings compared, {skipped} with too large a round buffer"
    );
    assert!(decoded > 200, "only {decoded} decodings compared");
    problems.check();
}

/// The calls' order and inputs, as libzstd's documentation gives them; the
/// context refuses a call it was not begun for.
#[test]
fn calls_follow_the_frame() {
    let data = b"bufferless, bufferless, bufferless".repeat(100);
    let mut out = vec![0u8; hivepack::zstd::compress_bound(data.len()).expect("a bound")];
    let size = hivepack::zstd::compress(&mut out, &data, 3).expect("compressed");
    let frame = &out[..size];

    let mut dctx = DCtx::new();
    let mut dst = vec![0u8; data.len()];
    // Not begun.
    assert_eq!(
        dctx.decompress_continue(&mut dst, &frame[..5])
            .map_err(|error| error.code()),
        Err(ErrorCode::StageWrong)
    );
    dctx.decompress_begin();
    assert_eq!(dctx.next_input_type(), NextInputType::FrameHeader);
    let next = dctx.next_src_size_to_decompress();
    assert_eq!(next, 5);
    // The wrong size.
    assert_eq!(
        dctx.decompress_continue(&mut dst, &frame[..next - 1])
            .map_err(|error| error.code()),
        Err(ErrorCode::SrcSizeWrong)
    );
    let (mut ip, mut op) = (0, 0);
    let mut kinds = Vec::new();
    loop {
        let next = dctx.next_src_size_to_decompress();
        if next == 0 {
            break;
        }
        kinds.push(dctx.next_input_type());
        op += dctx
            .decompress_continue(&mut dst[op..], &frame[ip..ip + next])
            .expect("decoded");
        ip += next;
    }
    assert_eq!(&dst[..op], &data[..]);
    assert_eq!(
        kinds,
        [
            NextInputType::FrameHeader,
            NextInputType::FrameHeader,
            NextInputType::BlockHeader,
            NextInputType::LastBlock
        ]
    );
    // The streaming decoder's frame is not one to go on with.
    let mut output = hivepack::zstd::OutBuffer::new(&mut dst);
    let mut input = hivepack::zstd::InBuffer::new(&frame[..10]);
    dctx.decompress_stream(&mut output, &mut input)
        .expect("streams");
    assert_eq!(
        dctx.decompress_continue(&mut dst, &frame[..1])
            .map_err(|error| error.code()),
        Err(ErrorCode::StageWrong)
    );
}
