//! hivepack::rar on any input, its first byte choosing whether a broken main
//! header is read past: the archive opened and every header read and
//! stepped over, twice. Both reads must see the same headers, and a panic
//! is a bug (`crates/hivepack/tests/rar_oracle.rs` compares the answers with UnRAR).
//!
//! UnRAR's license, which hivepack::rar is under:
//!
//! UnRAR source code may be used in any software to handle RAR archives
//! without limitations free of charge, but cannot be used to develop RAR
//! (WinRAR) compatible archiver and to re-create RAR compression algorithm,
//! which is proprietary. Distribution of modified UnRAR source code in
//! separate form or as a part of other software is permitted, provided that
//! full text of this paragraph, starting from "UnRAR source code" words, is
//! included in license, or in documentation if license is not available, and
//! in source code comments of resulting package.

#![no_main]

use hivepack::rar::{Archive, Error, Extract};
use libfuzzer_sys::fuzz_target;

#[path = "../../crates/hivepack/tests/rar_support/patch.rs"]
#[allow(dead_code)]
mod patch;

/// What came out for each header, then how the going through ended.
fn test(first: &[u8], second: &[u8]) -> (Vec<(u64, u64)>, String) {
    let next = second.to_vec();
    let opened = Archive::open_volumes(
        first.to_vec(),
        "a.part1.rar",
        move |name: &str| (name == "a.part2.rar").then(|| next.clone()),
        true,
        "password",
    );
    let mut arc = match opened {
        Ok(arc) => arc,
        Err(e) => return (Vec::new(), format!("open: {e}")),
    };
    let comment = match arc.get_comment() {
        Ok(comment) => comment.map_or(0, |c| c.len()),
        Err(e) => return (Vec::new(), format!("comment: {e}")),
    };
    let mut extract = Extract::new();
    let mut entries = vec![(comment as u64, 0)];
    loop {
        let size = match arc.read_header() {
            Ok(size) => size,
            Err(e) => return (entries, e.to_string()),
        };
        let (mut bytes, mut sum) = (0u64, 0u64);
        let result = extract.current_file(&mut arc, size, &mut |piece| {
            bytes += piece.len() as u64;
            sum = piece
                .iter()
                .fold(sum, |s, &b| s.rotate_left(5) ^ u64::from(b));
            Ok(())
        });
        assert_eq!(bytes, extract.cur_unp_write);
        match result {
            Ok(go) => {
                entries.push((bytes, sum));
                if !go {
                    return (entries, format!("end {:?}", arc.exit_code()));
                }
            }
            Err(
                e @ (Error::NoMemory
                | Error::BadVolume { .. }
                | Error::BadSeek { .. }
                | Error::MissingPassword { .. }),
            ) => {
                return (entries, e.to_string());
            }
            Err(e) => panic!("{e}"),
        }
    }
}

// Two volumes from one input, the first two bytes saying where the second one
// starts, each with its header CRCs right if the third byte says so. With
// the comment first, as UnRAR reads it.
fuzz_target!(|data: &[u8]| {
    let (at, flags, rest) = match data {
        [a, b, c, rest @ ..] => (usize::from(*a) | usize::from(*b) << 8, *c, rest),
        _ => return,
    };
    let (first, second) = rest.split_at(at.min(rest.len()));
    let (mut first, mut second) = (first.to_vec(), second.to_vec());
    if flags & 1 != 0 {
        patch::fix_header_crcs(&mut first);
        patch::fix_header_crcs(&mut second);
    }
    assert_eq!(test(&first, &second), test(&first, &second));
});
