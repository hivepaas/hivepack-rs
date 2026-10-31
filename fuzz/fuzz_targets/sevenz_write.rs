//! hivepack-7z's writer on any input: its first bytes pick how the archive is
//! written, and the rest makes its entries, in writes of different sizes. What is
//! read back must be what was written, and a panic is a bug.
//! `crates/7z/tests/writer.rs` has `7zz` and the LZMA SDK read what it writes.

#![no_main]

use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use hivepack_7z::{Archive, Filter, Method, NewEntry, Options, WriteOptions, Writer};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let [method, filter, layout, rest @ ..] = input else {
        return;
    };
    let method = match method % 6 {
        0 => Method::Copy,
        1 => Method::Lzma { preset: 0 },
        2 => Method::Lzma2 { preset: 0 },
        3 => Method::Deflate { level: 1 + i32::from(method / 6 % 9) },
        4 => Method::BZip2 { level: 1 },
        _ => Method::Lzma2 { preset: 1 },
    };
    let filter = match filter % 12 {
        0 => Filter::X86,
        1 => Filter::Arm,
        2 => Filter::ArmThumb,
        3 => Filter::Arm64,
        4 => Filter::PowerPc,
        5 => Filter::Sparc,
        6 => Filter::Ia64,
        7 => Filter::RiscV,
        8 => Filter::Delta(1 + u32::from(filter / 12)),
        _ => Filter::None,
    };
    let filter = if matches!(method, Method::Lzma { .. } | Method::Lzma2 { .. }) {
        filter
    } else {
        Filter::None
    };
    let password = layout & 4 != 0;
    let options = WriteOptions {
        method,
        filter,
        solid_block_size: match layout & 3 {
            0 => None,
            1 => Some(64),
            2 => Some(4096),
            _ => Some(u64::MAX),
        },
        compress_headers: layout & 8 != 0,
        password: password.then(|| "pw".to_string()),
        encrypt_headers: password && layout & 16 != 0,
        key_cycles: 2,
        random_source: Some(Arc::new(|bytes: &mut [u8]| {
            bytes.fill(0x5A);
            Ok(())
        })),
    };

    // Each piece: a byte for its kind and length, then that much data.
    let mut w = Writer::with_options(Cursor::new(Vec::new()), options).expect("good options");
    let mut wrote: Vec<(String, Option<Vec<u8>>)> = Vec::new();
    let mut rest = rest;
    while let [head, tail @ ..] = rest {
        let len = (usize::from(head >> 2) * 37).min(tail.len());
        let (piece, tail) = tail.split_at(len);
        rest = tail;
        match head & 3 {
            0 => {
                let name = format!("dir{}", wrote.len());
                w.add_directory(NewEntry::new(name.clone())).expect("a directory");
                wrote.push((name, None));
            }
            1 if wrote.last().is_some_and(|(_, d)| d.is_some()) => {
                w.write_all(piece).expect("to memory");
                if let Some((_, Some(data))) = wrote.last_mut() {
                    data.extend_from_slice(piece);
                }
            }
            _ => {
                let name = format!("file{}", wrote.len());
                w.start_file(NewEntry::new(name.clone())).expect("a file");
                w.write_all(piece).expect("to memory");
                wrote.push((name, Some(piece.to_vec())));
            }
        }
    }
    let archive = w.finish().expect("to memory").into_inner();

    let open = Options {
        password: password.then(|| "pw".to_string()),
        ..Options::default()
    };
    let mut a = Archive::open_with(Cursor::new(archive), &open).expect("what was written opens");
    assert_eq!(a.len(), wrote.len());
    let mut files = a.files();
    for (name, data) in &wrote {
        let entry = files.next().expect("the entries read").expect("as many as written");
        assert_eq!(&entry.name, name);
        assert_eq!(entry.is_dir, data.is_none());
        let mut read = Vec::new();
        files.read_to_end(&mut read).expect("the data reads");
        assert_eq!(read, *data.as_deref().unwrap_or(&[]));
    }
});
