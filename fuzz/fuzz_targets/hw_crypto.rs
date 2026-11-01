//! The processor's instructions of the `unsafe-fast` feature against the safe
//! code of the same crates: AES and CBC, SHA-1, SHA-256 and ChaCha20 of
//! hivepack-crypto, and CRC-32 of hivepack-deflate. A panic or a difference is a
//! bug, and the sanitizer takes any read or write out of bounds.
//!
//! Without the feature both sides are the safe code. Run it with
//! `--features unsafe-fast`.
//!
//! The first byte chooses what is done with the rest, which gives the key, the
//! state and the data, of whatever lengths it has.

#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hivepack_crypto::{Aes, chacha20, fuzz_safe};
use libfuzzer_sys::fuzz_target;

/// `N` bytes from the front of `data`, zeros where it ends.
fn take<const N: usize>(data: &mut &[u8]) -> [u8; N] {
    let mut out = [0; N];
    let n = data.len().min(N);
    out[..n].copy_from_slice(&data[..n]);
    *data = &data[n..];
    out
}

fn aes(mut data: &[u8]) {
    let size = [16, 24, 32][usize::from(take::<1>(&mut data)[0] % 3)];
    let key = take::<32>(&mut data);
    let aes = Aes::new(&key[..size]).expect("a length AES has");

    let mut blocks = data.chunks(64).map(|chunk| {
        let mut block = [0; 64];
        block[..chunk.len()].copy_from_slice(chunk);
        block
    });
    for plain in blocks.by_ref().take(16) {
        let (mut hw, mut safe) = (plain, plain);
        aes.encrypt4(&mut hw);
        fuzz_safe::aes_encrypt4(&aes, &mut safe);
        assert_eq!(hw, safe);

        let (mut hw, mut safe) = (plain, plain);
        aes.decrypt4(&mut hw);
        fuzz_safe::aes_decrypt4(&aes, &mut safe);
        assert_eq!(hw, safe);
    }

    // CBC, on what is left, byte for byte against the safe code's blocks: a
    // partial block is left as it is.
    let iv = take::<16>(&mut data);
    let mut got = data.to_vec();
    let mut got_iv = iv;
    aes.cbc_decrypt(&mut got_iv, &mut got);
    let mut before = iv;
    let whole = data.len() / 16 * 16;
    for (i, cipher) in data[..whole].chunks(16).enumerate() {
        let mut four = [0; 64];
        four[..16].copy_from_slice(cipher);
        fuzz_safe::aes_decrypt4(&aes, &mut four);
        for (j, byte) in got[i * 16..i * 16 + 16].iter().enumerate() {
            assert_eq!(*byte, four[j] ^ before[j]);
        }
        before.copy_from_slice(cipher);
    }
    assert_eq!(got[whole..], data[whole..]);
    assert_eq!(got_iv, before);
}

fn sha(mut data: &[u8]) {
    let mut one: [u32; 5] = bytemuck(take::<20>(&mut data));
    let mut two: [u32; 8] = bytemuck(take::<32>(&mut data));
    for chunk in data.chunks(64) {
        let mut block = [0; 64];
        block[..chunk.len()].copy_from_slice(chunk);

        let mut safe = one;
        fuzz_safe::sha1_block(&block, &mut safe);
        fuzz_safe::sha1_block_any(&block, &mut one);
        assert_eq!(one, safe);

        let mut safe = two;
        fuzz_safe::sha256_block(&block, &mut safe);
        fuzz_safe::sha256_block_any(&block, &mut two);
        assert_eq!(two, safe);
    }
}

/// Words from bytes.
fn bytemuck<const B: usize, const W: usize>(bytes: [u8; B]) -> [u32; W] {
    let mut out = [0; W];
    for (word, chunk) in out.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*chunk);
    }
    out
}

fn chacha(mut data: &[u8]) {
    let key = take::<32>(&mut data);
    let iv = take::<12>(&mut data);
    let cc = u32::from_le_bytes(take::<4>(&mut data));
    // Often near the wrap of the counter, inside a group of blocks.
    let cc = if cc & 1 == 0 { cc } else { u32::MAX - (cc >> 28) };
    // Longer than most inputs: whole groups, whatever came.
    let repeat = usize::from(take::<1>(&mut data)[0] % 8) + 1;
    let (mut hw, mut safe) = (data.repeat(repeat), data.repeat(repeat));
    let got = chacha20(&key, &iv, cc, &mut hw);
    assert_eq!(got, fuzz_safe::chacha20(&key, &iv, cc, &mut safe));
    assert_eq!(hw, safe);
}

fn crc(mut data: &[u8]) {
    let start = u32::from_le_bytes(take::<4>(&mut data));
    assert_eq!(
        hivepack_deflate::crc32(start, data),
        hivepack_deflate::fuzz_crc32_braided(start, data)
    );
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 4 {
        0 => aes(rest),
        1 => sha(rest),
        2 => chacha(rest),
        _ => crc(rest),
    }
});
