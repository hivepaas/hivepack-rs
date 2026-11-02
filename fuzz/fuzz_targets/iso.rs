//! hivepack::iso on any input: every entry of the image and up to 4 MiB of
//! its data read, twice, in pieces of different sizes the first eight
//! bytes' hash picks, as an input that can seek and as one that cannot.
//! Both reads of each must give the same headers, data and end, and a panic
//! is a bug (`crates/hivepack/tests/iso_oracle.rs` compares the answers with
//! libarchive).
//!
//! Data is read up to 4 MiB an entry: a zisofs file a few kilobytes long
//! can say it has gigabytes of zeros.

#![no_main]

use std::io::{Cursor, Read};

use hivepack::iso::{Header, Reader};
use libfuzzer_sys::fuzz_target;

const MAX_DATA: usize = 4 << 20;

/// Every entry, its data, and how the image ended.
fn read<R: Read>(mut iso: Reader<R>, mut seed: u64) -> (Vec<(Header, Vec<u8>, Vec<String>)>, String) {
    let mut entries = Vec::new();
    loop {
        let header = match iso.next() {
            Ok(Some(h)) => h,
            Ok(None) => return (entries, "end".into()),
            Err(e) => return (entries, e.to_string()),
        };
        let mut body = Vec::new();
        let mut ends = Vec::new();
        while body.len() < MAX_DATA {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let mut buf = vec![0; (1 + (seed >> 47) as usize).min(MAX_DATA - body.len())];
            match iso.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&buf[..n]),
                Err(e) => {
                    let e = hivepack::iso::Error::from(e);
                    ends.push(e.to_string());
                    if !e.is_warning() {
                        break;
                    }
                }
            }
        }
        entries.push((header, body, ends));
    }
}

fuzz_target!(|data: &[u8]| {
    let seed = data.iter().take(8).fold(0u64, |h, &b| h.rotate_left(8) ^ u64::from(b));
    assert_eq!(read(Reader::new(data), seed), read(Reader::new(data), !seed));
    assert_eq!(
        read(Reader::seekable(Cursor::new(data)), seed),
        read(Reader::seekable(Cursor::new(data)), !seed)
    );
});
