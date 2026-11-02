//! The decoder's fast loop, with the `unsafe-fast` feature or without, on
//! the blocks of `testdata/oracle/lz4.txt`: the same result and output as
//! liblz4 gave, every byte of the output buffer included. Short enough to
//! run under Miri, which fails on any access out of bounds (see CI).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "lz4_support/mod.rs"]
mod support;

use hivepack::lz4::block::{self, DecodeError};
use support::{fnv64, pattern, recorded_form, repository, unhex};

fn block_ret(ret: Result<usize, DecodeError>) -> i64 {
    match ret {
        Ok(size) => size as i64,
        Err(e) => e.number(),
    }
}

/// The answer to a `block` request, as `tests/oracle.rs` gives it.
fn answer(mode: &str, capacity: usize, target: usize, dict: &[u8], data: &[u8]) -> String {
    let mut buffer = dict.to_vec();
    buffer.extend_from_slice(&pattern(capacity));
    let prefix = dict.len();
    let ret = match mode {
        "s" => block::decompress_safe(data, &mut buffer[prefix..]),
        "p" => block::decompress_safe_partial(data, &mut buffer[prefix..], target),
        "d" => block::decompress_safe_using_dict(data, &mut buffer[prefix..], dict),
        "q" => block::decompress_safe_partial_using_dict(data, &mut buffer[prefix..], target, dict),
        "x" => block::decompress_safe_with_prefix(data, &mut buffer, prefix),
        "y" => block::decompress_safe_partial_with_prefix(data, &mut buffer, prefix, target),
        _ => panic!("mode {mode}"),
    };
    format!("{} {:016x}", block_ret(ret), fnv64(&buffer[prefix..]))
}

#[test]
fn recorded_blocks_decode_as_liblz4_did() {
    // Miri is slow: there, only the blocks with small buffers.
    let limit = if cfg!(miri) { 2_000 } else { usize::MAX };
    let text =
        std::fs::read_to_string(repository().join("testdata/oracle/lz4.txt")).expect("lz4.txt");
    let mut checked = 0;
    for line in text.lines().filter(|l| l.starts_with("block ")) {
        let (request, want) = line.split_once('\t').expect("request and answer");
        let words: Vec<&str> = request.split(' ').collect();
        let capacity: usize = words[2].parse().unwrap();
        let dict = unhex(words[4]);
        if capacity + dict.len() > limit {
            continue;
        }
        let got = answer(
            words[1],
            capacity,
            words[3].parse().unwrap(),
            &dict,
            &unhex(words[5]),
        );
        assert_eq!(recorded_form(&got), want, "{request:.200}");
        checked += 1;
    }
    assert!(checked > 30, "only {checked} blocks");
}
