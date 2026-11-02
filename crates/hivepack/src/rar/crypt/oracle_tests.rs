// hivepack::rar: a port of UnRAR 7.3.2 to Rust. UnRAR's license says:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

//! The ciphers compared directly with UnRAR's `CryptData`: the `crypt` request
//! gives it the same password, salt and bytes. Archives at hand have short
//! passwords in ASCII, and RAR 3's derivation only goes its own way past some
//! 30 characters. These are inside the crate, as the ciphers are.

// The oracle runs on Linux.
#![cfg(target_os = "linux")]

use crate::rar::unpack::oracle_tests::support::{Oracle, Rng, hex};

use super::*;

const METHODS: [(u32, CryptMethod); 5] = [
    (1, CryptMethod::Rar13),
    (2, CryptMethod::Rar15),
    (3, CryptMethod::Rar20),
    (4, CryptMethod::Rar30),
    (5, CryptMethod::Rar50),
];

/// `chunk`: how much at a time, as a cipher goes on from where it was.
fn answer(
    method: CryptMethod,
    password: &str,
    salt: Option<&[u8]>,
    init_v: &[u8; 16],
    lg2: u32,
    chunk: usize,
    data: &[u8],
) -> String {
    let password = Password::new(password);
    let mut cache = KdfCache::default();
    let mut out = "crypt".to_string();
    match set_crypt_keys(method, &password, &mut cache, salt, init_v, lg2) {
        None => out += " set=0",
        Some((mut crypt, checks)) => {
            out += " set=1";
            // In the oracle's form, and room as it has for RAR 2's last block.
            out += &format!(" hashkey={}", hex(&checks.hash_key));
            out += &format!(" pswcheck={}", hex(&checks.psw_check));
            let mut buf = data.to_vec();
            buf.resize(data.len() + CRYPT_BLOCK_SIZE, 0);
            let mut at = 0;
            while at < data.len() {
                let size = chunk.min(data.len() - at);
                crypt.decrypt_block(&mut buf[at..], size);
                at += size;
            }
            out += &format!(" data={}", hex(&buf[..data.len()]));
        }
    }
    out
}

fn password_of(rng: &mut Rng) -> String {
    const CHARS: [char; 8] = ['a', 'Z', '7', ' ', 'é', 'ệ', '日', '😀'];
    let length = match rng.below(4) {
        0 => rng.below(8),
        1 => 28 + rng.below(8),
        2 => 60 + rng.below(8),
        _ => rng.below(140),
    } as usize
        + 1;
    let ascii = rng.below(2) == 0;
    (0..length)
        .map(|_| {
            if ascii {
                char::from(b'!' + rng.below(90) as u8)
            } else {
                CHARS[rng.below(8) as usize]
            }
        })
        .collect()
}

#[test]
fn ciphers_are_unrars() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let seed = std::env::var("HIVEPACK_RAR_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0x4152_0008);
    let mut rng = Rng(seed);
    let count: usize = std::env::var("HIVEPACK_RAR_DAMAGED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(20);
    for i in 0..count * 5 {
        let (number, method) = METHODS[i % METHODS.len()];
        let password = password_of(&mut rng);
        let bytes =
            |rng: &mut Rng, n: usize| -> Vec<u8> { (0..n).map(|_| rng.next() as u8).collect() };
        let salt_of = bytes(&mut rng, 16);
        let init: [u8; 16] = std::array::from_fn(|_| rng.next() as u8);
        let no_salt = method == CryptMethod::Rar30 && rng.below(4) == 0;
        let salt = (!no_salt).then_some(&salt_of[..]);
        let lg2 = rng.below(7) as u32;
        let size = rng.below(512) as usize;
        let data = bytes(&mut rng, size);
        // Whole blocks at a time for what works in blocks, as is read.
        let chunk = match method {
            CryptMethod::Rar13 | CryptMethod::Rar15 => 1 + rng.below(40) as usize,
            _ => 16 * (1 + rng.below(4) as usize),
        };
        let request = format!(
            "crypt {number} {} {} {} {lg2} {chunk} {}",
            hex(password.as_bytes()),
            salt.map_or("-".to_string(), hex),
            hex(&init),
            hex(&data),
        );
        let want = oracle.ask(&request);
        let got = answer(method, &password, salt, &init, lg2, chunk, &data);
        assert_eq!(got, want, "{request:.200}");
    }
}

#[test]
fn a_count_too_large_gives_no_key() {
    let password = Password::new("x");
    let mut cache = KdfCache::default();
    let keys = set_crypt_keys(
        CryptMethod::Rar50,
        &password,
        &mut cache,
        Some(&[0; 16]),
        &[0; 16],
        25,
    );
    assert!(keys.is_none());
}
