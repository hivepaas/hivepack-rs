//! hivepack::bzip2 against libbzip2, call by call. A panic or a difference
//! is a bug.
//!
//! The first byte chooses what is done with the rest:
//!
//! - Even: the rest is a stream, decompressed by both in the same pieces,
//!   fast or small. Every call must agree, up to the first error: the same
//!   result, the same bytes read and written, the same output.
//! - Odd: the rest is data, compressed by both in the same pieces, with a
//!   block size and work factor from the first byte and flushes on the
//!   way. Every call must agree, and the port's stream must decompress to
//!   the data again.
//!
//! The next eight bytes seed the piece sizes.

#![no_main]

use hivepack::bzip2::{Action, Compress, Decompress, InBuffer, OutBuffer, Status};
use libfuzzer_sys::fuzz_target;

/// What a call returned, in libbzip2's numbers.
fn port_code(ret: hivepack::bzip2::Result<Status>) -> i32 {
    match ret {
        Ok(status) => status.number(),
        Err(e) => e.number(),
    }
}

fn c_code(ret: Result<bzip2::Status, bzip2::Error>) -> i32 {
    match ret {
        Ok(bzip2::Status::Ok) => 0,
        Ok(bzip2::Status::RunOk) => 1,
        Ok(bzip2::Status::FlushOk) => 2,
        Ok(bzip2::Status::FinishOk) => 3,
        Ok(bzip2::Status::StreamEnd) => 4,
        Ok(bzip2::Status::MemNeeded) => -3,
        Err(bzip2::Error::Sequence) => -1,
        Err(bzip2::Error::Param) => -2,
        Err(bzip2::Error::Data) => -4,
        Err(bzip2::Error::DataMagic) => -5,
    }
}

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
    if mode % 2 == 0 {
        decompress(mode / 2 % 2 == 1, data, &mut next);
    } else {
        compress(1 + i32::from(mode / 2 % 9), i32::from(mode / 18) * 17, data, &mut next);
    }
});

fn decompress(small: bool, stream: &[u8], next: &mut impl FnMut(usize) -> usize) {
    let mut c = bzip2::Decompress::new(small);
    let mut port = Decompress::new(small);
    let mut c_out = vec![0u8; 1 << 16];
    let mut p_out = vec![0u8; 1 << 16];
    let mut pos = 0;
    for _ in 0..100_000 {
        let left = stream.len() - pos;
        let input_len = if next(4) == 0 { left } else { next(left.min(64) + 1) };
        let output_len = if next(4) == 0 { c_out.len() } else { next(600) };
        let input = &stream[pos..pos + input_len];

        let (before_in, before_out) = (c.total_in(), c.total_out());
        let want = c_code(c.decompress(input, &mut c_out[..output_len]));
        let c_read = (c.total_in() - before_in) as usize;
        let c_written = (c.total_out() - before_out) as usize;

        let mut p_input = InBuffer::new(input);
        let mut p_output = OutBuffer::new(&mut p_out[..output_len]);
        let got = port_code(port.decompress(&mut p_output, &mut p_input));
        assert_eq!(got, want, "result at input {pos}");
        assert_eq!(p_input.pos, c_read, "bytes read at input {pos}");
        assert_eq!(p_output.pos, c_written, "bytes written at input {pos}");
        assert_eq!(p_out[..c_written], c_out[..c_written], "output at input {pos}");
        assert_eq!((port.total_in(), port.total_out()), (c.total_in(), c.total_out()));
        pos += c_read;
        if want < 0 || want == 4 || (left == 0 && c_written == 0 && output_len > 0) {
            break;
        }
    }
}

fn compress(block_size: i32, work_factor: i32, data: &[u8], next: &mut impl FnMut(usize) -> usize) {
    let mut c = bzip2::Compress::new(bzip2::Compression::new(block_size as u32), work_factor as u32);
    let Ok(mut port) = Compress::new(block_size, work_factor) else {
        panic!("block size {block_size}, work factor {work_factor}");
    };
    let mut c_out = vec![0u8; 1 << 16];
    let mut p_out = vec![0u8; 1 << 16];
    let mut stream = Vec::new();
    let mut pos = 0;
    // The end of the input given to a flush or the end, which every call
    // until it is done must give again, less what was read.
    let mut window: Option<(usize, Action)> = None;
    for _ in 0..200_000 {
        let left = data.len() - pos;
        let (input_len, action) = match window {
            Some((end, action)) => (end - pos, action),
            None if left == 0 || next(50) == 0 => {
                // The end takes all the input left; a flush, some of it.
                let action = if left == 0 || next(3) != 0 { Action::Finish } else { Action::Flush };
                let n = if action == Action::Finish || next(2) == 0 { left } else { next(left + 1) };
                window = Some((pos + n, action));
                (n, action)
            }
            // libbzip2 refuses a run that can do nothing, and the bzip2
            // crate hides that: always give it something to read.
            None => (1 + next(left.min(5000)), Action::Run),
        };
        // The same for the output: a run needs room to write, and so does
        // the end, which fails when it cannot move.
        let output_len = if next(4) == 0 { c_out.len() } else { 1 + next(600) };
        let input = &data[pos..pos + input_len];

        let c_action = match action {
            Action::Run => bzip2::Action::Run,
            Action::Flush => bzip2::Action::Flush,
            Action::Finish => bzip2::Action::Finish,
        };
        let (before_in, before_out) = (c.total_in(), c.total_out());
        let want = c_code(c.compress(input, &mut c_out[..output_len], c_action));
        let c_read = (c.total_in() - before_in) as usize;
        let c_written = (c.total_out() - before_out) as usize;

        let mut p_input = InBuffer::new(input);
        let mut p_output = OutBuffer::new(&mut p_out[..output_len]);
        let got = port_code(port.compress(&mut p_output, &mut p_input, action));
        assert_eq!(got, want, "result at input {pos}");
        assert_eq!(p_input.pos, c_read, "bytes read at input {pos}");
        assert_eq!(p_output.pos, c_written, "bytes written at input {pos}");
        assert_eq!(p_out[..c_written], c_out[..c_written], "output at input {pos}");
        stream.extend_from_slice(&p_out[..c_written]);
        pos += c_read;
        match want {
            // The end of a flush: back to running.
            1 if action == Action::Flush => window = None,
            4 => break,
            _ => {}
        }
    }
    assert_eq!((port.total_in(), port.total_out()), (c.total_in(), c.total_out()));

    // The stream decompresses to the data.
    let mut decoded = vec![0u8; data.len() + 1];
    let mut port = Decompress::new(next(2) == 0);
    let mut output = OutBuffer::new(&mut decoded);
    let status = port.decompress(&mut output, &mut InBuffer::new(&stream));
    assert_eq!(status, Ok(Status::StreamEnd));
    assert_eq!(output.pos, data.len());
    assert_eq!(&decoded[..data.len()], data);
}
