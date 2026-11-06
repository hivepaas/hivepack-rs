//! Data descriptors in a Zip64 archive: their sizes are 8 bytes each for an
//! entry in Zip64 format, and 4 bytes for the others, as Info-ZIP's zip and
//! libarchive (and so File Roller) write them when an archive is Zip64 only
//! for its count of entries. Both are read, and checked against the central
//! directory.

#![allow(clippy::unwrap_used)]

use std::io::Read;

use hivepack::zip::{Archive, Flags, OpenFlags};

/// A ZIP archive of `files`, stored, each with a data descriptor and a local
/// header that says neither its CRC nor its sizes, as a stream is written; the
/// descriptors' sizes are 8 bytes each if `wide`, else 4. It ends with a Zip64
/// end of central directory, as an archive of more than 65,535 entries does.
fn streamed(files: &[(&str, &[u8])], wide: bool, signed: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let offset = out.len() as u32;
        let crc = crc32(data);
        let size = data.len() as u32;
        // The local header: version 20, data descriptor, stored, a time.
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0x6000u16.to_le_bytes());
        out.extend_from_slice(&0x5c46u16.to_le_bytes());
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        if signed {
            out.extend_from_slice(b"PK\x07\x08");
        }
        out.extend_from_slice(&crc.to_le_bytes());
        if wide {
            out.extend_from_slice(&u64::from(size).to_le_bytes());
            out.extend_from_slice(&u64::from(size).to_le_bytes());
        } else {
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
        }
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&0x031eu16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&8u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0x6000u16.to_le_bytes());
        central.extend_from_slice(&0x5c46u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0; 8]);
        central.extend_from_slice(&(0o100_644_u32 << 16).to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let central_at = out.len() as u64;
    out.extend_from_slice(&central);
    let count = files.len() as u64;
    let eocd64_at = out.len() as u64;
    out.extend_from_slice(b"PK\x06\x06");
    out.extend_from_slice(&44u64.to_le_bytes());
    out.extend_from_slice(&45u16.to_le_bytes());
    out.extend_from_slice(&45u16.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&(central.len() as u64).to_le_bytes());
    out.extend_from_slice(&central_at.to_le_bytes());
    out.extend_from_slice(b"PK\x06\x07");
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&eocd64_at.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&[0xff; 4]);
    out.extend_from_slice(&[0xff; 8]);
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

const FILES: [(&str, &[u8]); 3] = [
    ("a.txt", b"hello"),
    ("empty", b""),
    ("b.txt", b"a second file, longer"),
];

/// What the archive holds, opened with its local headers checked.
fn read_back(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let archive = Archive::open(bytes, OpenFlags::CHECKCONS | OpenFlags::RDONLY).unwrap();
    (0..archive.get_num_entries(Flags::NONE))
        .map(|i| {
            let name =
                String::from_utf8(archive.get_name(i, Flags::NONE).unwrap().to_vec()).unwrap();
            let mut data = Vec::new();
            archive
                .fopen_index(i, Flags::NONE)
                .unwrap()
                .read_to_end(&mut data)
                .unwrap();
            (name, data)
        })
        .collect()
}

#[test]
fn four_byte_sizes_in_a_zip64_archive_are_read() {
    for signed in [true, false] {
        let read = read_back(&streamed(&FILES, false, signed));
        let expected: Vec<_> = FILES
            .iter()
            .map(|(name, data)| (name.to_string(), data.to_vec()))
            .collect();
        assert_eq!(read, expected, "signed: {signed}");
    }
}

#[test]
fn eight_byte_sizes_in_a_zip64_archive_are_still_read() {
    for signed in [true, false] {
        let read = read_back(&streamed(&FILES, true, signed));
        assert_eq!(read.len(), FILES.len(), "signed: {signed}");
        assert_eq!(read[2].1, FILES[2].1, "signed: {signed}");
    }
}

#[test]
fn a_descriptor_that_says_another_size_is_refused() {
    let mut bytes = streamed(&FILES[..1], false, true);
    // The descriptor's compressed size, after "hello" and its signature and CRC.
    let at = 30 + "a.txt".len() + 5 + 8;
    bytes[at] = 6;
    assert!(Archive::open(bytes.as_slice(), OpenFlags::CHECKCONS | OpenFlags::RDONLY).is_err());
}
