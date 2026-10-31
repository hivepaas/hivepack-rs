//! hivepack-tar's writer on any header: every entry the input reads to is written
//! again, as it came or changed as the first eight bytes' hash picks, and read
//! back. What the writer takes, the reader finds, with the same names, size and
//! data; a panic is a bug (`crates/tar/tests/writer.rs` compares every byte with
//! Go's archive/tar).

#![no_main]

use std::io::{Read, Write};

use hivepack_tar::{Error, Format, Reader, TYPE_GNU_SPARSE, TYPE_REG, TYPE_X_GLOBAL_HEADER, Writer};
use libfuzzer_sys::fuzz_target;

const MAX_DATA: u64 = 1 << 20;

/// What was written of an entry, to find again.
struct Written {
    name: Vec<u8>,
    linkname: Vec<u8>,
    size: i64,
    data: Vec<u8>,
}

fuzz_target!(|input: &[u8]| {
    let mut seed = input.iter().take(8).fold(0u64, |h, &b| h.rotate_left(8) ^ u64::from(b));
    let mut next = move || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        seed >> 48
    };
    let mut tr = Reader::new(input);
    let mut tw = Writer::new(Vec::new());
    let mut written = Vec::new();
    while let Ok(Some(mut h)) = tr.next() {
        let mut data = Vec::new();
        if (&mut tr).take(MAX_DATA).read_to_end(&mut data).is_err() {
            break;
        }
        match next() % 8 {
            0 => h.format = Format::UNKNOWN,
            1 => h.format = Format::USTAR,
            2 => h.format = Format::PAX,
            3 => h.format = Format::GNU,
            4 => {
                let long = next() as usize % 300;
                h.name.extend(std::iter::repeat_n(b'n', long));
            }
            _ => {}
        }
        // Go's writer has no sparse maps: an `S` entry written as it is, as Go
        // writes it, cannot be read back.
        if h.typeflag == TYPE_GNU_SPARSE {
            h.typeflag = TYPE_REG;
        }
        // What the size says must be written: only entries with their data whole.
        let header_only = matches!(h.typeflag, b'1'..=b'6');
        if h.size != data.len() as i64 && !header_only {
            h.size = data.len() as i64;
            h.typeflag = TYPE_REG;
        }
        match tw.write_header(&h) {
            Ok(()) => {}
            Err(Error::CannotEncode(_)) => continue,
            // PAX records over 1 MiB, which the reader takes with less.
            Err(Error::FieldTooLong) => return,
            Err(e) => panic!("{e}"),
        }
        if header_only {
            data.clear();
        }
        tw.write_all(&data).expect("the data fits its size");
        if h.typeflag != TYPE_X_GLOBAL_HEADER {
            written.push(Written {
                name: h.name,
                linkname: h.linkname,
                size: h.size,
                data,
            });
        }
    }
    tw.close().expect("the archive ends");
    let archive = tw.into_inner();

    let mut back = Reader::new(archive.as_slice());
    let mut found = written.iter();
    loop {
        let h = back.next().expect("the writer's archive reads");
        let Some(h) = h else {
            assert!(found.next().is_none());
            return;
        };
        if h.typeflag == TYPE_X_GLOBAL_HEADER {
            continue;
        }
        let want = found.next().expect("no more entries than written");
        assert_eq!(h.name, want.name);
        assert_eq!(h.linkname, want.linkname);
        if !matches!(h.typeflag, b'1'..=b'6') {
            assert_eq!(h.size, want.size);
        }
        let mut data = Vec::new();
        back.read_to_end(&mut data).expect("the writer's data reads");
        assert_eq!(data, want.data);
    }
});
