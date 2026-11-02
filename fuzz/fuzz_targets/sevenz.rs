//! hivepack::sevenz on any input: opened, listed, its files read one after
//! another, its folders decoded and its files extracted, with small limits
//! on what it may allocate and on how much is read, and with a password. A
//! panic is a bug.
//! `crates/hivepack/tests/sevenz_oracle.rs` compares the results with the LZMA SDK's.

#![no_main]

use std::io::{Cursor, Read};

use hivepack::sevenz::{Archive, Options};
use libfuzzer_sys::fuzz_target;

/// How much is read, at most, of what the input makes.
const MAX_OUTPUT: u64 = 1 << 23;

fuzz_target!(|data: &[u8]| {
    let options = Options {
        memory_limit: 1 << 26,
        decoder_memory_limit: 1 << 26,
        // The AES coder's paths, without the time its keys can take.
        password: Some("pw".into()),
        max_key_cycles: 8,
    };
    let Ok(mut archive) = Archive::open_with(Cursor::new(data), &options) else {
        return;
    };
    for entry in archive.entries().take(1 << 12) {
        std::hint::black_box(entry);
    }

    let mut left = MAX_OUTPUT;
    let mut files = archive.files();
    let mut buf = [0; 1 << 12];
    while left > 0 {
        match files.next() {
            Ok(Some(_)) => {}
            _ => break,
        }
        // In pieces of different sizes, up to the folder's checks at its end.
        let mut piece = 1;
        loop {
            match files.read(&mut buf[..piece]) {
                Ok(n) if n > 0 && (n as u64) < left => left -= n as u64,
                _ => break,
            }
            piece = piece % buf.len() + 1;
        }
    }

    let mut left = MAX_OUTPUT;
    for folder in 0..archive.folders() {
        let size = archive.folder_size(folder);
        if size > left {
            break;
        }
        left -= size;
        let _ = archive.decode_folder(folder);
    }
    let mut left = MAX_OUTPUT;
    for index in 0..archive.len().min(1 << 8) {
        let entry = archive.entry(index);
        let size = entry.folder.map_or(0, |folder| archive.folder_size(folder));
        if size > left {
            break;
        }
        left -= size;
        let _ = archive.extract(index);
    }
});
