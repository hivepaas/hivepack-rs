//! Comparison with nettle 3.10.2 through `tools/nettle-oracle`: AES with
//! every key length, SHA-1, MD5 and HMAC-SHA1 on lengths around their
//! blocks, and PBKDF2-HMAC-SHA1 with the lengths WinZip AES derives.
//!
//! The oracle is a small C program built with nettle's sources by
//! `scripts/testdata.py`. It answers requests such as `sha1 616263` by
//! calling nettle, one line per request. [`answer`] answers the same
//! requests with the port, in the same format, so the two can be compared
//! as text. The port feeds SHA-1 and HMAC their data in pieces of random
//! sizes, which nettle gets whole; MD5 too.
//!
//! - With the oracle built, generated requests are compared with nettle
//!   directly.
//! - Everywhere, including where the oracle cannot be built (Windows, and
//!   the emulated i686 and s390x jobs, the last big-endian),
//!   `testdata/oracle/crypto.txt` replays answers nettle gave earlier.
//!   `cargo test -p hivepack --all-features --test crypto_oracle record_oracle_answers --
//!   --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "crypto_support/mod.rs"]
mod support;

use std::fmt::Write as _;
use std::path::PathBuf;

use hivepack::crypto::{Aes, Hmac, HmacKey, Md5, Sha1, pbkdf2};
use support::{Oracle, Rng, hex, repository, unhex};

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/crypto.txt")
}

/// `data` in pieces of random sizes, some empty, some across blocks.
fn pieces<'a>(rng: &mut Rng, mut data: &'a [u8]) -> Vec<&'a [u8]> {
    let mut pieces = Vec::new();
    while !data.is_empty() {
        let n = (rng.below(150) as usize).min(data.len());
        let (piece, rest) = data.split_at(n);
        pieces.push(piece);
        data = rest;
    }
    pieces
}

/// The port's answer to a request, as the oracle words it.
fn answer(request: &str, rng: &mut Rng) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    match words[..] {
        ["aes", key, blocks] => {
            let Some(aes) = Aes::new(&unhex(key)) else {
                return "err".into();
            };
            let mut data = unhex(blocks);
            data.truncate(data.len() / 16 * 16);
            // Four blocks at a time where it can, then one at a time.
            let (fours, rest) = data.as_chunks_mut::<64>();
            for four in fours {
                aes.encrypt4(four);
            }
            for block in rest.as_chunks_mut().0 {
                aes.encrypt_block(block);
            }
            format!("ok {}", hex(&data))
        }
        ["sha1", data] => {
            let data = unhex(data);
            let mut sha1 = Sha1::new();
            for piece in pieces(rng, &data) {
                sha1.update(piece);
            }
            format!("ok {}", hex(&sha1.out()))
        }
        ["md5", data] => {
            let data = unhex(data);
            let mut md5 = Md5::new();
            for piece in pieces(rng, &data) {
                md5.update(piece);
            }
            format!("ok {}", hex(&md5.out()))
        }
        ["hmac", key, data] => {
            let data = unhex(data);
            let mut hmac = Hmac::new(&HmacKey::<Sha1>::new(&unhex(key)));
            for piece in pieces(rng, &data) {
                hmac.update(piece);
            }
            format!("ok {}", hex(&hmac.out()))
        }
        ["pbkdf2", iterations, length, password, salt] => {
            let mut out = vec![0; length.parse().unwrap()];
            pbkdf2::<Sha1>(
                &unhex(password),
                &unhex(salt),
                iterations.parse().unwrap(),
                &mut out,
            );
            format!("ok {}", hex(&out))
        }
        _ => panic!("unknown request {request:.100}"),
    }
}

/// Bytes: random, or one of the patterns that find mistakes in bit
/// manipulation (all zeros, all ones, one bit set).
fn bytes(rng: &mut Rng, len: usize) -> Vec<u8> {
    match rng.below(6) {
        0 => vec![0; len],
        1 => vec![0xff; len],
        2 => {
            let mut data = vec![0; len];
            if len > 0 {
                data[rng.below(len as u64) as usize] = 1 << rng.below(8);
            }
            data
        }
        _ => (0..len).map(|_| rng.next() as u8).collect(),
    }
}

/// A length around SHA-1's 64-byte blocks and the 55/56-byte limit of its
/// padding, or anything up to `max`.
fn length(rng: &mut Rng, max: usize) -> usize {
    if rng.below(2) == 0 {
        let block = 64 * rng.below(4) as usize;
        let near = rng.pick(&[0, 1, 54, 55, 56, 57, 63, 64, 65]);
        (block + near).min(max)
    } else {
        rng.below(max as u64 + 1) as usize
    }
}

/// `count` requests of each kind, with data up to `max` bytes.
fn requests(rng: &mut Rng, count: usize, max: usize) -> Vec<String> {
    let mut requests = Vec::new();
    for _ in 0..count {
        let key_len = if rng.below(20) == 0 {
            rng.pick(&[0, 1, 15, 17, 23, 25, 31, 33])
        } else {
            rng.pick(&[16, 24, 32])
        };
        let blocks = rng.pick(&[0, 1, 2, 3, 4, 5, 7, 8, 9]) * 16;
        requests.push(format!(
            "aes {} {}",
            hex(&bytes(rng, key_len)),
            hex(&bytes(rng, blocks))
        ));

        let len = length(rng, max);
        requests.push(format!("sha1 {}", hex(&bytes(rng, len))));

        // Keys up to past a block, which HMAC hashes first.
        let key_len = length(rng, 150);
        let len = length(rng, max);
        requests.push(format!(
            "hmac {} {}",
            hex(&bytes(rng, key_len)),
            hex(&bytes(rng, len))
        ));

        // WinZip AES derives 2 × 16 + 2, 2 × 24 + 2 or 2 × 32 + 2 bytes,
        // in 1000 iterations, with a salt of 8, 12 or 16 bytes.
        let iterations = if rng.below(4) == 0 {
            1000
        } else {
            1 + rng.below(40)
        };
        let out_len = if rng.below(2) == 0 {
            rng.pick(&[34, 50, 66])
        } else {
            1 + rng.below(100)
        };
        let password_len = length(rng, 100);
        let salt_len = if rng.below(2) == 0 {
            rng.pick(&[8, 12, 16])
        } else {
            rng.below(30) as usize
        };
        requests.push(format!(
            "pbkdf2 {iterations} {out_len} {} {}",
            hex(&bytes(rng, password_len)),
            hex(&bytes(rng, salt_len))
        ));
    }
    requests
}

/// `count` MD5 requests, with data up to `max` bytes: apart from
/// [`requests`], whose recorded answers came first.
fn md5_requests(rng: &mut Rng, count: usize, max: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let len = length(rng, max);
            format!("md5 {}", hex(&bytes(rng, len)))
        })
        .collect()
}

#[test]
fn port_matches_nettle() {
    let Some(mut oracle) = Oracle::spawn("nettle-oracle") else {
        return;
    };
    let mut rng = Rng(0x5eed_c001);
    let requests = requests(&mut rng, 1500, 3000);
    for request in &requests {
        let want = oracle.ask(request);
        assert_eq!(answer(request, &mut rng), want, "{request:.300}");
    }
    let mut rng = Rng(0x5eed_c0d5);
    for request in &md5_requests(&mut rng, 1500, 3000) {
        let want = oracle.ask(request);
        assert_eq!(answer(request, &mut rng), want, "{request:.300}");
    }
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/crypto.txt");
    let mut rng = Rng(0x5eed_c003);
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(answer(request, &mut rng), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked >= 1000, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/crypto.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn("nettle-oracle").expect("the oracle is built");
    let mut rng = Rng(0x5eed_c002);
    let mut text = String::from(
        "# Answers from nettle 3.10.2 (tools/nettle-oracle), replayed by crates/crypto/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test crypto_oracle record_oracle_answers -- --ignored\n",
    );
    // Short data keeps the file small: the long is for the live comparison.
    for request in requests(&mut rng, 200, 200) {
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{reply}");
    }
    let mut rng = Rng(0x5eed_c0d6);
    for request in md5_requests(&mut rng, 200, 200) {
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{reply}");
    }
    std::fs::create_dir_all(recorded_path().parent().expect("folder")).expect("folder");
    std::fs::write(recorded_path(), text).expect("written");
}
