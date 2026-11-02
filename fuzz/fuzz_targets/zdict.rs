//! Trains a dictionary on samples cut from the input, with the port and
//! with libzstd's default trainer, `ZDICT_trainFromBuffer` (zstd-safe's
//! `train_from_buffer`), into a room its first two bytes pick, and checks
//! that both give the same dictionary, byte for byte, or the same error.
//! The third byte picks how the rest is cut: in samples of one size, at a
//! byte that ends each sample, or by sizes read from the input. The port's
//! dictionary is then used: a sample compressed with it decodes back.
//!
//! Where libzstd would read past the samples (its training set, the first
//! three quarters of them, under 8 bytes, with enough samples in all), it
//! is not called, and the port must fail with `SrcSizeWrong`. A panic or a
//! difference is a bug.

#![no_main]

use hivepack::zstd::{CCtx, CDict, DCtx, DDict, ErrorCode};
use libfuzzer_sys::fuzz_target;
use zstd::zstd_safe;

/// The samples of `rest`, cut as `how` says.
fn cut(how: u8, rest: &[u8]) -> Vec<usize> {
    let mut sizes = Vec::new();
    match how % 4 {
        // One size, 1 to 64 bytes, the last one shorter.
        0 => {
            let size = 1 + usize::from(how >> 2);
            let mut left = rest.len();
            while left > 0 {
                let n = size.min(left);
                sizes.push(n);
                left -= n;
            }
        }
        // Each sample ends with the byte `how` names (a newline, or 0), or
        // at the end.
        1 | 2 => {
            let end = if how % 4 == 1 { b'\n' } else { 0 };
            let mut start = 0;
            for (i, &byte) in rest.iter().enumerate() {
                if byte == end {
                    sizes.push(i + 1 - start);
                    start = i + 1;
                }
            }
            if start < rest.len() {
                sizes.push(rest.len() - start);
            }
        }
        // Sizes read from the input: each byte of the first `how >> 2` is a
        // size, the samples after them; the last one takes the rest.
        _ => {
            let count = usize::from(how >> 2).min(rest.len());
            let (head, body) = rest.split_at(count);
            let mut left = body.len();
            for &size in head {
                let n = usize::from(size).min(left);
                sizes.push(n);
                left -= n;
            }
            sizes.push(left);
            // The size bytes are samples too, at the start.
            sizes.insert(0, count);
        }
    }
    sizes
}

/// Whether libzstd's default trainer would read past the samples (or
/// divide by zero): see `split_samples` in the port.
fn libzstd_reads_past(sizes: &[usize], capacity: usize) -> bool {
    let n = sizes.len();
    let total: usize = sizes.iter().sum();
    let nb_train = (n as f64 * 0.75) as usize;
    capacity >= 256 && n >= 7 && total >= 8 && sizes[..nb_train].iter().sum::<usize>() < 8
}

fuzz_target!(|data: &[u8]| {
    let [low, high, how, rest @ ..] = data else {
        return;
    };
    // Mostly small rooms, from none to 64 KB.
    let capacity = usize::from(u16::from_le_bytes([*low, *high])) >> (high >> 6);
    let sizes = cut(*how, rest);
    let mut got = vec![0u8; capacity];
    let got_size = hivepack::zstd::train_from_buffer(&mut got, rest, &sizes);
    if libzstd_reads_past(&sizes, capacity) {
        assert_eq!(got_size.map_err(|e| e.code()), Err(ErrorCode::SrcSizeWrong));
        return;
    }
    let mut want = vec![0u8; capacity];
    let want_size = zstd_safe::train_from_buffer(&mut want[..], rest, &sizes);
    match (want_size, got_size) {
        (Ok(want_size), Ok(got_size)) => {
            assert_eq!(&got[..got_size], &want[..want_size], "the dictionaries differ");
            let dict = &got[..got_size];
            assert_eq!(
                hivepack::zstd::get_dict_id(dict),
                zstd_safe::get_dict_id(dict).map_or(0, |id| id.get())
            );
            // The dictionary at work, on the last sample.
            let sample = &rest[rest.len() - sizes.last().copied().unwrap_or(0)..];
            let cdict = CDict::new(dict, 3).expect("the port loads its dictionary");
            let mut frame = vec![0u8; hivepack::zstd::compress_bound(sample.len()).unwrap_or(0)];
            let size = CCtx::new()
                .compress_using_cdict(&mut frame, sample, &cdict)
                .expect("compresses");
            let ddict = DDict::new(dict).expect("the decoder loads it");
            let mut back = vec![0u8; sample.len()];
            let back_size = DCtx::new()
                .decompress_using_ddict(&mut back, &frame[..size], &ddict)
                .expect("decodes back");
            assert_eq!(&back[..back_size], sample);
        }
        (Err(code), Err(error)) => {
            assert_eq!(zstd_safe::get_error_name(code), error.code().message());
        }
        (want, got) => panic!(
            "libzstd: {:?}, port: {:?}",
            want.map_err(zstd_safe::get_error_name),
            got.map_err(|e| e.code())
        ),
    }
});
