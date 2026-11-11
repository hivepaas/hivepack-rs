//! hivepack::ar on any input: every entry of the archive and its data read,
//! twice, from an input that comes in pieces of different sizes and read in
//! pieces of different sizes, the first eight bytes' hash picking them. Both
//! reads must give the same headers, data and end; skipping the data must
//! give the same headers; and a panic is a bug
//! (`crates/hivepack/tests/ar_oracle.rs` compares the answers with
//! libarchive).

#![no_main]

use std::io::Read;

use hivepack::ar::{Header, Reader};
use libfuzzer_sys::fuzz_target;

/// The input, in pieces of sizes `seed` picks.
struct Pieces<'a> {
    data: &'a [u8],
    seed: u64,
}

impl Read for Pieces<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.seed = self
            .seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let most = 1 + (self.seed >> 50) as usize;
        let n = most.min(buf.len()).min(self.data.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

/// Every entry, its data (or, with `skip`, now and then none, left for
/// `next` to skip), and how the archive ended.
fn read(data: &[u8], skip: bool, mut seed: u64) -> (Vec<(Header, Vec<u8>, String)>, String) {
    let mut ar = Reader::new(Pieces { data, seed });
    let mut entries = Vec::new();
    loop {
        let header = match ar.next() {
            Ok(Some(h)) => h,
            Ok(None) => return (entries, "end".into()),
            Err(e) => return (entries, e.to_string()),
        };
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let mut body = Vec::new();
        let mut end = String::from("skipped");
        if !skip || seed >> 62 != 0 {
            loop {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let mut buf = vec![0; 1 + (seed >> 47) as usize];
                match ar.read(&mut buf) {
                    Ok(0) => {
                        end = "end".into();
                        break;
                    }
                    Ok(n) => body.extend_from_slice(&buf[..n]),
                    Err(e) => {
                        end = hivepack::ar::Error::from(e).to_string();
                        break;
                    }
                }
            }
        }
        entries.push((header, body, end));
    }
}

fuzz_target!(|data: &[u8]| {
    let seed = data.iter().take(8).fold(0u64, |h, &b| h.rotate_left(8) ^ u64::from(b));
    let a = read(data, false, seed);
    assert_eq!(a, read(data, false, !seed));
    // Skipping data gives the same headers as reading it.
    let skipped = read(data, true, seed);
    let headers = |r: &(Vec<(Header, Vec<u8>, String)>, String)| -> Vec<Header> {
        r.0.iter().map(|e| e.0.clone()).collect()
    };
    assert_eq!(headers(&a), headers(&skipped));
});
