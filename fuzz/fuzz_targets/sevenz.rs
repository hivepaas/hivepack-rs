//! hivepack::sevenz on any input: opened, listed, its files read one after
//! another, its folders decoded and its files extracted, with small limits
//! on what it may allocate and on how much is read, and with a password; then
//! changed with `Writer::copy_from`, kept whole and with every other file, and
//! what that writes opened again, with as many entries. A panic is a bug.
//! `crates/hivepack/tests/sevenz_oracle.rs` compares the results with the LZMA SDK's.

#![no_main]

use std::io::{Cursor, Read};

use hivepack::sevenz::{Archive, Entry, Method, Options, WriteOptions, Writer};
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

    // What each folder was compressed with, read from its description.
    for folder in 0..archive.folders().min(1 << 12) {
        let _ = archive.folder_coding(folder);
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

    // Changed: kept whole, its folders copied as they are, nothing decoded;
    // then every other file, the folders that lose one decoded and stored.
    // What is written opens again, with the entries kept.
    let total = (0..archive.folders())
        .map(|folder| archive.folder_size(folder))
        .fold(0u64, u64::saturating_add);
    for every_other in [false, true] {
        if every_other && total > MAX_OUTPUT {
            break;
        }
        let keep = |e: &Entry| !every_other || e.index.is_multiple_of(2);
        let write = WriteOptions {
            method: Method::Copy,
            ..WriteOptions::default()
        };
        let Ok(mut writer) = Writer::with_options(Cursor::new(Vec::new()), write) else {
            return;
        };
        if writer.copy_from(&mut archive, keep).is_err() {
            continue;
        }
        let Ok(out) = writer.finish() else {
            continue;
        };
        let kept = archive.entries().filter(|e| keep(e)).count();
        let back = Archive::open_with(Cursor::new(out.into_inner()), &options)
            .expect("what copy_from wrote opens");
        assert_eq!(back.len(), kept);
    }
});
