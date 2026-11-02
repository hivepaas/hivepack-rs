//! hivepack::xar on any input: every entry of the archive and up to 4 MiB of
//! its data read, twice, in pieces of different sizes the first eight
//! bytes' hash picks, as an input that can seek and as one that cannot.
//! Both reads of each must give the same headers, data and end, and a panic
//! is a bug (`crates/hivepack/tests/xar_oracle.rs` compares the answers with
//! libarchive).

#![no_main]

use std::io::{Cursor, Read};

use hivepack::xar::{Error, Header, Reader};
use libfuzzer_sys::fuzz_target;

const MAX_DATA: usize = 4 << 20;

/// Every entry (or the failure of `next`), its data and how it ended, and
/// how the archive ended.
type Outcome = (Vec<(Result<Header, String>, Vec<u8>, String)>, String);

fn read<R: Read>(mut xar: Reader<R>, mut seed: u64) -> Outcome {
    let mut entries = Vec::new();
    loop {
        let header = match xar.next() {
            Ok(Some(h)) => h,
            Ok(None) => return (entries, "end".into()),
            // The entry is lost, and the next one comes.
            Err(e @ Error::CannotSeek) => {
                entries.push((Err(e.to_string()), Vec::new(), String::new()));
                continue;
            }
            Err(e) => return (entries, e.to_string()),
        };
        let mut body = Vec::new();
        let mut end = String::new();
        while body.len() < MAX_DATA {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let mut buf = vec![0; (1 + (seed >> 47) as usize).min(MAX_DATA - body.len())];
            match xar.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&buf[..n]),
                Err(e) => {
                    end = Error::from(e).to_string();
                    break;
                }
            }
        }
        entries.push((Ok(header), body, end));
    }
}

/// The data is compared only where its end is the same: data that is not
/// compressed comes in the pieces asked for, so a failure at its end
/// leaves more or less of it read.
fn same(a: &Outcome, b: &Outcome) -> bool {
    a.1 == b.1
        && a.0.len() == b.0.len()
        && a.0
            .iter()
            .zip(&b.0)
            .all(|(x, y)| x.0 == y.0 && x.2 == y.2 && (x.1 == y.1 || !x.2.is_empty()))
}

fuzz_target!(|data: &[u8]| {
    let seed = data
        .iter()
        .take(8)
        .fold(0u64, |h, &b| h.rotate_left(8) ^ u64::from(b));
    let (a, b) = (
        read(Reader::new(data), seed),
        read(Reader::new(data), !seed),
    );
    assert!(same(&a, &b), "{a:?}\n{b:?}");
    let (a, b) = (
        read(Reader::seekable(Cursor::new(data)), seed),
        read(Reader::seekable(Cursor::new(data)), !seed),
    );
    assert!(same(&a, &b), "{a:?}\n{b:?}");
});
