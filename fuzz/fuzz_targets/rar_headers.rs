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

use hivepack::rar::{Archive, Error};
use libfuzzer_sys::fuzz_target;

/// Each header's kind, position and size, then how the reading ended.
fn read(data: &[u8], enable_broken: bool) -> (Vec<(u32, i64, i64, usize)>, String) {
    let mut archive = match Archive::open(data, enable_broken) {
        Ok(archive) => archive,
        Err(e) => return (Vec::new(), format!("open: {e}")),
    };
    let mut headers = Vec::new();
    loop {
        match archive.read_header() {
            Ok(0) => return (headers, format!("end {:?}", archive.exit_code())),
            Ok(size) => {
                headers.push((
                    archive.cur_header_type,
                    archive.cur_block_pos,
                    archive.next_block_pos,
                    size,
                ));
                // Each header is past the one before: reading ends.
                assert!(archive.next_block_pos > archive.cur_block_pos);
                archive.seek_to_next();
            }
            Err(e @ (Error::MissingPassword { .. } | Error::BadSeek { .. })) => {
                return (headers, e.to_string());
            }
            Err(e) => panic!("{e}"),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&choice, archive)) = data.split_first() else {
        return;
    };
    let first = read(archive, choice & 1 != 0);
    assert_eq!(first, read(archive, choice & 1 != 0));
});
