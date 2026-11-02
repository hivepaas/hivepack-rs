//! BLAKE2s and BLAKE2sp: the known answers of the BLAKE2 reference
//! implementation, keyed and not, on inputs up to 255 bytes; BLAKE2sp past
//! its 512-byte buffer, against Python's `hashlib.blake2s` with its tree
//! parameters (`tests/data/blake2-kat.txt` says how each was made), and RFC
//! 7693's vector. Each is hashed whole and in pieces of different sizes.
//! `tests/go_oracle.rs` compares BLAKE2s with Go too, and hivepack::rar's
//! tests compare BLAKE2sp with UnRAR on RAR 5 archives.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "crypto_support/mod.rs"]
mod support;

use hivepack::crypto::{Blake2s, Blake2sp};
use support::{Rng, hex};

/// The hash of `data` under `key`, whole or in pieces.
trait Hash: Sized {
    fn keyed(key: &[u8]) -> Option<Self>;
    fn add(&mut self, data: &[u8]);
    fn digest(&self) -> [u8; 32];
}

impl Hash for Blake2s {
    fn keyed(key: &[u8]) -> Option<Self> {
        Blake2s::with_key(key)
    }
    fn add(&mut self, data: &[u8]) {
        self.update(data);
    }
    fn digest(&self) -> [u8; 32] {
        self.out()
    }
}

impl Hash for Blake2sp {
    fn keyed(key: &[u8]) -> Option<Self> {
        Blake2sp::with_key(key)
    }
    fn add(&mut self, data: &[u8]) {
        self.update(data);
    }
    fn digest(&self) -> [u8; 32] {
        self.out()
    }
}

/// `data` hashed whole, a byte at a time when short, and in pieces of
/// random sizes around the blocks, with a digest taken on the way, which
/// must not change what comes out.
fn check<H: Hash>(key: &[u8], data: &[u8], want: &str, rng: &mut Rng, context: &str) {
    let mut whole = H::keyed(key).unwrap();
    whole.add(data);
    assert_eq!(hex(&whole.digest()), want, "{context}, whole");
    if data.len() <= 4096 {
        let mut bytes = H::keyed(key).unwrap();
        for byte in data {
            bytes.add(std::slice::from_ref(byte));
        }
        assert_eq!(hex(&bytes.digest()), want, "{context}, a byte at a time");
    }
    for _ in 0..4 {
        let mut pieces = H::keyed(key).unwrap();
        let mut rest = data;
        while !rest.is_empty() {
            let size = match rng.below(4) {
                0 => rng.below(8),
                1 => 60 + rng.below(9),
                2 => 508 + rng.below(9),
                _ => rng.below(5000),
            } as usize;
            let (piece, tail) = rest.split_at(size.min(rest.len()));
            pieces.add(piece);
            let _ = pieces.digest();
            rest = tail;
        }
        assert_eq!(hex(&pieces.digest()), want, "{context}, in pieces");
    }
}

#[test]
fn known_answers() {
    let text = include_str!("crypto_data/blake2-kat.txt");
    let key32: Vec<u8> = (0..32).collect();
    let mut rng = Rng(0xb1a2_0001);
    let mut counts = (0, 0);
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let words: Vec<&str> = line.split(' ').collect();
        let [hash, key_len, len, want] = words[..] else {
            panic!("{line}");
        };
        let key = &key32[..key_len.parse().unwrap()];
        let data: Vec<u8> = (0..len.parse::<usize>().unwrap())
            .map(|i| i as u8)
            .collect();
        match hash {
            "blake2s" => {
                check::<Blake2s>(key, &data, want, &mut rng, line);
                counts.0 += 1;
            }
            "blake2sp" => {
                check::<Blake2sp>(key, &data, want, &mut rng, line);
                counts.1 += 1;
            }
            _ => panic!("{line}"),
        }
    }
    assert_eq!(counts, (512, 512 + 16));
}

/// RFC 7693's example of BLAKE2s, "abc".
#[test]
fn rfc_7693() {
    let mut hash = Blake2s::new();
    hash.update(b"abc");
    assert_eq!(
        hex(&hash.out()),
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
    );
}

#[test]
fn keys_past_32_bytes_are_refused() {
    assert!(Blake2s::with_key(&[0; 33]).is_none());
    assert!(Blake2sp::with_key(&[0; 33]).is_none());
    // No key is the hash without one.
    let (mut a, mut b) = (Blake2sp::with_key(&[]).unwrap(), Blake2sp::new());
    a.update(b"x");
    b.update(b"x");
    assert_eq!(a.out(), b.out());
}
