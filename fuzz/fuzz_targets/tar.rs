//! hivepack::tar on any input: every entry of the archive and all of its
//! data read, twice, in pieces of different sizes the first eight bytes'
//! hash picks. Both reads must give the same headers, data and end, and a
//! panic is a bug (`crates/hivepack/tests/tar_oracle.rs` compares the answers with
//! Go's archive/tar). Going through the entries without their data gives the
//! same whether the reader seeks past it or not.
//!
//! Data is read up to 4 MiB an entry: sparse files can be terabytes of
//! holes.

#![no_main]

use std::io::{Cursor, Read};

use hivepack::tar::{Header, Reader};
use libfuzzer_sys::fuzz_target;

const MAX_DATA: usize = 4 << 20;

/// Every entry, its data, and how the archive ended.
fn read(data: &[u8], mut seed: u64) -> (Vec<(Header, Vec<u8>, String)>, String) {
    let mut tr = Reader::new(data);
    let mut entries = Vec::new();
    loop {
        let header = match tr.next() {
            Ok(Some(h)) => h,
            Ok(None) => return (entries, "end".into()),
            Err(e) => return (entries, e.to_string()),
        };
        let mut body = Vec::new();
        let mut end = String::from("-");
        while body.len() < MAX_DATA {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let mut buf = vec![0; (1 + (seed >> 48) as usize).min(MAX_DATA - body.len())];
            match tr.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&buf[..n]),
                Err(e) => {
                    end = e.to_string();
                    break;
                }
            }
        }
        entries.push((header, body, end));
    }
}

/// Every entry, its data skipped, and how the archive ended.
fn list<R: Read>(mut tr: Reader<R>) -> (Vec<Header>, String) {
    let mut entries = Vec::new();
    loop {
        match tr.next() {
            Ok(Some(h)) => entries.push(h),
            Ok(None) => return (entries, "end".into()),
            Err(e) => return (entries, e.to_string()),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let seed = data.iter().take(8).fold(0u64, |h, &b| h.rotate_left(8) ^ u64::from(b));
    assert_eq!(read(data, seed), read(data, !seed));
    assert_eq!(list(Reader::new(data)), list(Reader::seekable(Cursor::new(data))));
});
