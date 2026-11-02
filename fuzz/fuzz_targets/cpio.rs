//! hivepack::cpio on any input: every entry of the archive and its data
//! read, twice, from an input that comes in pieces of different sizes and
//! read in pieces of different sizes, the first eight bytes' hash picking
//! them; with and without the `pwb` option, and through the RPM filter
//! when its bid says the input is a package, as libarchive stacks it. Both
//! reads must give the same headers, data and end, and a panic is a bug
//! (`crates/hivepack/tests/cpio_oracle.rs` compares the answers with libarchive).

#![no_main]

use std::io::Read;

use hivepack::cpio::{Header, Reader, rpm};
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

/// What the RPM filter gives, and how it ended.
fn payload(data: &[u8], seed: u64) -> (Vec<u8>, String) {
    let mut out = Vec::new();
    let mut r = rpm::Reader::new(Pieces { data, seed });
    let mut seed = seed;
    loop {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mut buf = vec![0; 1 + (seed >> 48) as usize];
        match r.read(&mut buf) {
            Ok(0) => return (out, "end".into()),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return (out, hivepack::cpio::Error::from(e).to_string()),
        }
    }
}

/// Every entry, its data (or, with `skip`, now and then none, left for
/// `next` to skip), and how the archive ended.
fn read(
    data: &[u8],
    pwb: bool,
    skip: bool,
    mut seed: u64,
) -> (Vec<(Header, Vec<u8>, String)>, String) {
    let mut cpio = Reader::new(Pieces { data, seed });
    cpio.set_pwb(pwb);
    let mut entries = Vec::new();
    loop {
        let header = match cpio.next() {
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
                match cpio.read(&mut buf) {
                    Ok(0) => {
                        end = "end".into();
                        break;
                    }
                    Ok(n) => body.extend_from_slice(&buf[..n]),
                    Err(e) => {
                        end = hivepack::cpio::Error::from(e).to_string();
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
    let pwb = seed & 1 == 1;
    let a = read(data, pwb, false, seed);
    assert_eq!(a, read(data, pwb, false, !seed));
    // Skipping data gives the same headers as reading it.
    let skipped = read(data, pwb, true, seed);
    let headers = |r: &(Vec<(Header, Vec<u8>, String)>, String)| -> Vec<Header> {
        r.0.iter().map(|e| e.0.clone()).collect()
    };
    assert_eq!(headers(&a), headers(&skipped));
    if rpm::bid(data) > 0 {
        let (p, end) = payload(data, seed);
        assert_eq!((p.clone(), end.clone()), payload(data, !seed));
        if end == "end" {
            assert_eq!(read(&p, pwb, false, seed), read(&p, pwb, false, !seed));
        }
    }
});
