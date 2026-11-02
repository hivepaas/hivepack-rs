//! Comparison with Go through `tools/age-oracle`: what age needs, against
//! the code age v1.3.2 runs (Go's standard library and golang.org/x/crypto
//! v0.55.0). SHA-256, SHA-512 and BLAKE2s on lengths around their blocks, HMAC with
//! both, PBKDF2-HMAC-SHA256, HKDF-SHA256, ChaCha20, ChaCha20-Poly1305 both
//! ways, X25519 with points of small order among others, and scrypt.
//!
//! The oracle is a small Go program built by `scripts/testdata.py`. It
//! answers requests such as `sha256 616263`, one line per request, and
//! [`answer`] answers the same requests with the port, in the same format.
//! The port takes hashes, HMAC and HKDF's output in pieces of random sizes,
//! which Go gets whole.
//!
//! - With the oracle built, generated requests are compared with Go
//!   directly.
//! - Everywhere, including where it is not built (Windows, and the emulated
//!   i686 and s390x jobs), `testdata/oracle/crypto-go.txt` replays answers
//!   Go gave earlier. `cargo test -p hivepack-crypto --test go_oracle
//!   record_oracle_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::fmt::Write as _;
use std::path::PathBuf;

use hivepack_crypto::{
    Blake2s, Digest, Hmac, HmacKey, Sha256, Sha512, chacha20_poly1305_open, chacha20_poly1305_seal,
    hkdf, pbkdf2, scrypt, x25519,
};
use support::{Oracle, Rng, hex, repository, unhex};

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/crypto-go.txt")
}

/// `data` in pieces of random sizes, some empty, some across blocks.
fn pieces<'a>(rng: &mut Rng, mut data: &'a [u8]) -> Vec<&'a [u8]> {
    let mut pieces = Vec::new();
    while !data.is_empty() {
        let n = (rng.below(300) as usize).min(data.len());
        let (piece, rest) = data.split_at(n);
        pieces.push(piece);
        data = rest;
    }
    pieces
}

fn ok(bytes: &[u8]) -> String {
    format!("ok {}", hex(bytes))
}

fn digest<H: Digest>(rng: &mut Rng, data: &[u8]) -> String {
    let mut h = H::new();
    for piece in pieces(rng, data) {
        h.update(piece);
    }
    ok(h.out().as_ref())
}

fn hmac<H: Digest>(rng: &mut Rng, key: &[u8], data: &[u8]) -> String {
    let mut h = Hmac::new(&HmacKey::<H>::new(key));
    for piece in pieces(rng, data) {
        h.update(piece);
    }
    ok(h.out().as_ref())
}

fn array<const N: usize>(text: &str) -> [u8; N] {
    unhex(text).try_into().unwrap()
}

/// The port's answer to a request, as the oracle words it.
fn answer(request: &str, rng: &mut Rng) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    match words[..] {
        ["sha256", data] => digest::<Sha256>(rng, &unhex(data)),
        ["sha512", data] => digest::<Sha512>(rng, &unhex(data)),
        ["blake2s", key, data] => match Blake2s::with_key(&unhex(key)) {
            None => "err".to_string(),
            Some(mut hash) => {
                for piece in pieces(rng, &unhex(data)) {
                    hash.update(piece);
                }
                ok(&hash.out())
            }
        },
        ["hmac256", key, data] => hmac::<Sha256>(rng, &unhex(key), &unhex(data)),
        ["hmac512", key, data] => hmac::<Sha512>(rng, &unhex(key), &unhex(data)),
        ["pbkdf2", iterations, length, password, salt] => {
            let mut out = vec![0; length.parse().unwrap()];
            pbkdf2::<Sha256>(
                &unhex(password),
                &unhex(salt),
                iterations.parse().unwrap(),
                &mut out,
            );
            ok(&out)
        }
        ["hkdf", salt, ikm, info, length] => {
            let salt = (salt != "none").then(|| unhex(salt));
            let mut out = vec![0; length.parse().unwrap()];
            if !hkdf::<Sha256>(salt.as_deref(), &unhex(ikm), &unhex(info), &mut out) {
                return "err".into();
            }
            ok(&out)
        }
        ["seal", key, nonce, aad, data] => {
            let mut data = unhex(data);
            let tag = chacha20_poly1305_seal(&array(key), &array(nonce), &mut data, &unhex(aad));
            data.extend_from_slice(&tag);
            ok(&data)
        }
        ["open", key, nonce, aad, sealed] => {
            let mut data = unhex(sealed);
            let Some(at) = data.len().checked_sub(16) else {
                return "err".into();
            };
            let tag: [u8; 16] = data.split_off(at).try_into().unwrap();
            if !chacha20_poly1305_open(&array(key), &array(nonce), &mut data, &unhex(aad), &tag) {
                return "err".into();
            }
            ok(&data)
        }
        ["x25519", scalar, point] => {
            let out = x25519(&array(scalar), &array(point));
            if out == [0; 32] {
                return "err".into();
            }
            ok(&out)
        }
        ["scrypt", log_n, r, p, length, password, salt] => {
            let mut out = vec![0; length.parse().unwrap()];
            match scrypt(
                &unhex(password),
                &unhex(salt),
                log_n.parse().unwrap(),
                r.parse().unwrap(),
                p.parse().unwrap(),
                &mut out,
            ) {
                Ok(()) => ok(&out),
                Err(_) => "err".into(),
            }
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

/// A length around a hash's blocks (`block` bytes) and the limit of its
/// padding (`block` - 9 or - 17), or anything up to `max`.
fn length(rng: &mut Rng, block: usize, max: usize) -> usize {
    if rng.below(2) == 0 {
        let pad = block - block / 8 - 1;
        let base = block * rng.below(4) as usize;
        let near = rng.pick(&[0, 1, pad - 1, pad, pad + 1, block - 1, block, block + 1]);
        (base + near).min(max)
    } else {
        rng.below(max as u64 + 1) as usize
    }
}

/// Some u-coordinates of points of small order, and values around the
/// field's prime p = 2^255 - 19, which X25519 reduces; with the top bit
/// set or not, which it ignores. Little-endian, as X25519 encodes them.
fn special_point(rng: &mut Rng) -> String {
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    let mut point = match rng.below(8) {
        0 => [0; 32],
        1 => {
            let mut one = [0; 32];
            one[0] = 1;
            one
        }
        // A point of order 8.
        2 => array("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        // Another one.
        3 => array("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        // p - 1, p, p + 1.
        4 => {
            p[0] = 0xec;
            p
        }
        5 => p,
        6 => {
            p[0] = 0xee;
            p
        }
        _ => [0xff; 32],
    };
    if rng.below(2) == 0 {
        point[31] ^= 0x80;
    }
    hex(&point)
}

/// `count` requests of each kind, with data up to `max` bytes.
/// BLAKE2s, without a key, with keys up to its 32 bytes, and with one too
/// long, on lengths around its blocks.
fn blake2s_requests(rng: &mut Rng, count: usize, max: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let key_len = match rng.below(4) {
                0 => 0,
                1 => 32,
                2 => 33,
                _ => rng.below(33) as usize,
            };
            let len = length(rng, 64, max);
            format!(
                "blake2s {} {}",
                hex(&bytes(rng, key_len)),
                hex(&bytes(rng, len))
            )
        })
        .collect()
}

fn requests(rng: &mut Rng, count: usize, max: usize) -> Vec<String> {
    let mut requests = Vec::new();
    for _ in 0..count {
        let len = length(rng, 64, max);
        requests.push(format!("sha256 {}", hex(&bytes(rng, len))));
        let len = length(rng, 128, max);
        requests.push(format!("sha512 {}", hex(&bytes(rng, len))));

        // Keys up to past a block, which HMAC hashes first.
        let key_len = length(rng, 64, 200);
        let len = length(rng, 64, max);
        requests.push(format!(
            "hmac256 {} {}",
            hex(&bytes(rng, key_len)),
            hex(&bytes(rng, len))
        ));
        let key_len = length(rng, 128, 300);
        let len = length(rng, 128, max);
        requests.push(format!(
            "hmac512 {} {}",
            hex(&bytes(rng, key_len)),
            hex(&bytes(rng, len))
        ));

        let iterations = if rng.below(8) == 0 {
            1000
        } else {
            1 + rng.below(20)
        };
        let out_len = 1 + rng.below(100);
        let password_len = length(rng, 64, 100);
        let salt_len = rng.below(40) as usize;
        requests.push(format!(
            "pbkdf2 {iterations} {out_len} {} {}",
            hex(&bytes(rng, password_len)),
            hex(&bytes(rng, salt_len))
        ));

        // age's HKDF: no salt or a salt of 16 or 64 bytes, 32 bytes out.
        // And the limit of 255 blocks of output.
        let salt = match rng.below(4) {
            0 => "none".to_string(),
            1 => {
                let len = rng.pick(&[0, 16, 64]);
                hex(&bytes(rng, len))
            }
            _ => {
                let len = length(rng, 64, 150);
                hex(&bytes(rng, len))
            }
        };
        let ikm_len = length(rng, 64, 150);
        let info_len = rng.below(60) as usize;
        let out_len = match rng.below(10) {
            0 => rng.pick(&[8159, 8160, 8161]),
            1..=4 => 32,
            _ => 1 + rng.below(300),
        };
        requests.push(format!(
            "hkdf {salt} {} {} {out_len}",
            hex(&bytes(rng, ikm_len)),
            hex(&bytes(rng, info_len))
        ));

        let key = hex(&bytes(rng, 32));
        let nonce = hex(&bytes(rng, 12));
        let aad_len = rng.pick(&[0, 0, 1, 15, 16, 17, 40]);
        let aad = hex(&bytes(rng, aad_len));
        let len = length(rng, 64, max);
        let data = bytes(rng, len);
        requests.push(format!("seal {key} {nonce} {aad} {}", hex(&data)));
        // Something sealed with the key, as it is or with a bit changed,
        // or anything at all.
        let mut sealed = data;
        let tag = chacha20_poly1305_seal(&array(&key), &array(&nonce), &mut sealed, &unhex(&aad));
        sealed.extend_from_slice(&tag);
        match rng.below(4) {
            0 => {
                let at = rng.below(sealed.len() as u64) as usize;
                sealed[at] ^= 1 << rng.below(8);
            }
            1 => {
                let len = rng.below(40) as usize;
                sealed = bytes(rng, len);
            }
            _ => {}
        }
        requests.push(format!("open {key} {nonce} {aad} {}", hex(&sealed)));

        let scalar = hex(&bytes(rng, 32));
        let point = if rng.below(3) == 0 {
            special_point(rng)
        } else {
            hex(&bytes(rng, 32))
        };
        requests.push(format!("x25519 {scalar} {point}"));

        // N up to 2^10; r and p small; and N = 1, which both refuse.
        let log_n = if rng.below(20) == 0 {
            0
        } else {
            1 + rng.below(10)
        };
        let r = 1 + rng.below(8);
        let p = 1 + rng.below(3);
        let out_len = 1 + rng.below(80);
        let password_len = rng.below(40) as usize;
        let salt_len = rng.pick(&[0, 16, 32]);
        requests.push(format!(
            "scrypt {log_n} {r} {p} {out_len} {} {}",
            hex(&bytes(rng, password_len)),
            hex(&bytes(rng, salt_len))
        ));
    }
    requests
}

#[test]
fn port_matches_go() {
    let Some(mut oracle) = Oracle::spawn("age-oracle") else {
        return;
    };
    let mut rng = Rng(0x60_c001);
    let mut requests = requests(&mut rng, 400, 3000);
    requests.extend(blake2s_requests(&mut rng, 400, 3000));
    for request in &requests {
        let want = oracle.ask(request);
        assert_eq!(answer(request, &mut rng), want, "{request:.300}");
    }
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/crypto-go.txt");
    let mut rng = Rng(0x60_c003);
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
#[ignore = "rewrites testdata/oracle/crypto-go.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn("age-oracle").expect("the oracle is built");
    let mut rng = Rng(0x60_c002);
    let mut text = String::from(
        "# Answers from Go and golang.org/x/crypto v0.55.0 (tools/age-oracle), replayed by crates/crypto/tests/go_oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack-crypto --test go_oracle record_oracle_answers -- --ignored\n",
    );
    // Short data keeps the file small: the long is for the live comparison.
    // BLAKE2s last, with its own generator: the others' answers stay as
    // they were.
    let mut blake2s_rng = Rng(0x60_c004);
    let recorded = requests(&mut rng, 100, 200)
        .into_iter()
        .chain(blake2s_requests(&mut blake2s_rng, 100, 200));
    for request in recorded {
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{reply}");
    }
    std::fs::create_dir_all(recorded_path().parent().expect("folder")).expect("folder");
    std::fs::write(recorded_path(), text).expect("written");
}
