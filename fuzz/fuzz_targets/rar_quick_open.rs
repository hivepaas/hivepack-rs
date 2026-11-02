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
mod patch;

/// What came out for each header, then how the going through ended.
fn test(data: &[u8], password: &str) -> (Vec<(i64, u64, u64)>, String) {
    let mut arc = match Archive::open_with_password(data, true, password) {
        Ok(arc) => arc,
        Err(e) => return (Vec::new(), format!("open: {e}")),
    };
    let comment = match arc.get_comment() {
        Ok(comment) => comment.map_or(0, |c| c.len()),
        Err(e) => return (Vec::new(), format!("comment: {e}")),
    };
    let mut extract = Extract::new();
    let mut entries = Vec::new();
    loop {
        let size = match arc.read_header() {
            Ok(size) => size,
            Err(e @ (Error::MissingPassword { .. } | Error::BadSeek { .. })) => {
                return (entries, e.to_string());
            }
            Err(e) => panic!("{e}"),
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
                entries.push((arc.cur_block_pos, bytes, sum));
                if !go {
                    return (entries, format!("end {:?} {comment}", arc.exit_code()));
                }
            }
            Err(e @ (Error::NoMemory | Error::BadSeek { .. })) => return (entries, e.to_string()),
            Err(e) => panic!("{e}"),
        }
    }
}

fuzz_target!(|input: &[u8]| {
    let data = patch::with_quick_open(input);
    for password in ["", "password"] {
        assert_eq!(test(&data, password), test(&data, password));
    }
});
