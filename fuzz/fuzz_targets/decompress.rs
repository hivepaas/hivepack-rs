//! Decodes the input with the port and with libzstd, in one call, and checks
//! that they agree: the same output, or the same error. Then with the
//! port's bufferless decoder (`ZSTD_decompressContinue`): into one buffer,
//! the same output wherever the one-call decoder succeeds, unless a block
//! is larger than the frame allows, which libzstd's one-call decoder does
//! not check and `ZSTD_decompressContinue` does; into a round buffer, only
//! that nothing panics. A panic, a difference, or (with the
//! `unsafe-fast` feature, under the sanitizer) an access out of bounds is a
//! bug.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zstd::zstd_safe;

/// Room for the output; frames that need more fail the same way in both.
const CAPACITY: usize = 1 << 20;

fuzz_target!(|src: &[u8]| {
    let mut c_out = vec![0u8; CAPACITY];
    let mut p_out = vec![0u8; CAPACITY];
    let want = zstd_safe::DCtx::create()
        .decompress(&mut c_out[..], src)
        .map(|n| &c_out[..n])
        .map_err(zstd_safe::get_error_name);
    let got = hivepack::zstd::decompress(&mut p_out, src)
        .map(|n| &p_out[..n])
        .map_err(|error| error.code().message());
    assert!(
        want == got,
        "libzstd {:?}, port {:?}",
        summary(&want),
        summary(&got)
    );
    let mut b_out = vec![0u8; CAPACITY];
    let bufferless = bufferless(src, &mut b_out, None);
    if let Ok(got) = got {
        let corrupt = hivepack::zstd::ErrorCode::CorruptionDetected.message();
        assert!(
            bufferless.as_deref() == Ok(got)
                || bufferless.as_ref().is_err_and(|error| error == corrupt),
            "one call {} bytes, bufferless {:?}",
            got.len(),
            bufferless.map(|out| out.len())
        );
    }
    let _ = bufferless_round(src);
});

/// The frames of `src` through `decompress_continue`, into `out` from its
/// start, each call right after the last; or, with `round`, into `out`
/// from its start again when less than `round` is left.
fn bufferless(src: &[u8], out: &mut [u8], round: Option<usize>) -> Result<Vec<u8>, String> {
    let mut dctx = hivepack::zstd::DCtx::new();
    let mut output = Vec::new();
    let (mut ip, mut pos, mut begin) = (0, 0, true);
    for _ in 0..1_000_000 {
        if begin {
            if ip == src.len() {
                return Ok(output);
            }
            dctx.decompress_begin();
        }
        let next = dctx.next_src_size_to_decompress();
        let piece = &src[ip..(ip + next).min(src.len())];
        if round.is_some_and(|round| out.len() - pos < round) {
            pos = 0;
        }
        let written = dctx
            .decompress_continue(&mut out[pos..], piece)
            .map_err(|error| error.code().message().to_string())?;
        output.extend_from_slice(&out[pos..pos + written]);
        ip += piece.len();
        pos += written;
        begin = dctx.next_src_size_to_decompress() == 0;
    }
    Err("no end".into())
}

/// [`bufferless`] in a round buffer for the first frame's window and
/// blocks, of a reasonable size.
fn bufferless_round(src: &[u8]) -> Result<Vec<u8>, String> {
    let Ok(hivepack::zstd::FrameHeaderState::Complete(header)) = hivepack::zstd::get_frame_header(src)
    else {
        return Err("no frame header".into());
    };
    let size = hivepack::zstd::decoding_buffer_size_min(header.window_size, header.frame_content_size)
        .map_err(|error| error.code().message().to_string())?;
    if size > CAPACITY {
        return Err("too large".into());
    }
    let mut out = vec![0u8; size];
    bufferless(src, &mut out, Some(header.block_size_max as usize))
}

fn summary(result: &Result<&[u8], &str>) -> String {
    match result {
        Ok(out) => format!("{} bytes", out.len()),
        Err(name) => format!("error {name}"),
    }
}
