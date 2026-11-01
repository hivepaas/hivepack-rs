//! Writing age files with hivepack-age: the first byte chooses the recipients and
//! the armor, the next eight the random bytes and the pieces, and the rest is the
//! plaintext. Written whole and in pieces, the file must be the same; it must
//! decrypt to the plaintext; and, not armored, without its last byte it must not
//! decrypt in full. A panic is a bug.
//!
//! `crates/age/tests/encrypt.rs` compares the files with age's.

#![no_main]

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use hivepack_age::{
    ArmoredWriter, Identity, RandomSource, Recipient, ScryptIdentity, ScryptRecipient,
    X25519Identity, X25519Recipient, decrypt_file, encrypt,
};
use libfuzzer_sys::fuzz_target;

const KEYS: [&str; 2] = [
    "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0",
    "AGE-SECRET-KEY-1W0YVT58DJ29ACF8AJECG9HK66C9Y5UWVWJDJNFYRF9VX8LA8E3ZQPQR8XW",
];

fn step(seed: &mut u64) -> u64 {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *seed >> 32
}

/// Random bytes that follow from `seed`, the same each time it is made.
fn source(seed: u64) -> RandomSource {
    let seed = Mutex::new(seed);
    Arc::new(move |out: &mut [u8]| {
        let mut seed = seed.lock().map_err(|_| std::io::Error::other("poisoned"))?;
        for byte in out {
            *byte = step(&mut seed) as u8;
        }
        Ok(())
    })
}

/// Writes `data` in pieces that follow from `seed`, or whole if it is `None`.
fn write<W: Write>(w: &mut W, mut data: &[u8], seed: Option<u64>) {
    let Some(mut seed) = seed else {
        w.write_all(data).unwrap();
        return;
    };
    while !data.is_empty() {
        let n = (step(&mut seed) as usize % 70_000).min(data.len());
        w.write_all(&data[..n]).unwrap();
        data = &data[n..];
    }
}

fn file(
    recipients: &[&dyn Recipient],
    armored: bool,
    plaintext: &[u8],
    seed: u64,
    pieces: Option<u64>,
) -> Vec<u8> {
    let random = source(seed);
    if armored {
        let mut w = encrypt(ArmoredWriter::new(Vec::new()), recipients, Some(&random)).unwrap();
        write(&mut w, plaintext, pieces);
        w.finish().unwrap().finish().unwrap()
    } else {
        let mut w = encrypt(Vec::new(), recipients, Some(&random)).unwrap();
        write(&mut w, plaintext, pieces);
        w.finish().unwrap()
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    let (start, rest) = data.split_at(9);
    let mode = start[0];
    let seed = u64::from_le_bytes(start[1..].try_into().unwrap());
    // Longer than most inputs: across chunks, whatever came.
    let plaintext = rest.repeat(1 + usize::from(mode >> 4));
    let armored = mode & 1 == 1;

    let keys = KEYS.map(|k| X25519Identity::parse(k).unwrap());
    let to = keys
        .each_ref()
        .map(|k| X25519Recipient::parse(&k.recipient()).unwrap());
    let mut pass = ScryptRecipient::new(b"password").unwrap();
    pass.set_work_factor(1 + (mode >> 1 & 3));
    let mut identity = ScryptIdentity::new(b"password").unwrap();
    identity.set_max_work_factor(4);

    let recipients: Vec<&dyn Recipient> = match mode >> 3 & 1 {
        0 => vec![&to[0], &to[1]],
        _ => vec![&pass],
    };
    let identities: [&dyn Identity; 2] = [&keys[1], &identity];

    let whole = file(&recipients, armored, &plaintext, seed, None);
    let pieces = file(&recipients, armored, &plaintext, seed, Some(seed));
    assert!(whole == pieces, "the pieces changed the file");

    let mut out = Vec::new();
    decrypt_file(&whole[..], &identities)
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    assert!(out == plaintext, "another plaintext came back");

    if !armored {
        let cut = &whole[..whole.len() - 1];
        let mut out = Vec::new();
        let read = decrypt_file(cut, &identities)
            .unwrap()
            .read_to_end(&mut out);
        assert!(read.is_err(), "a file cut short read in full");
    }
});
