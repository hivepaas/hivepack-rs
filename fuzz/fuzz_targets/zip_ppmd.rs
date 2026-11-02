//! Reads the input as the data of a PPMd entry (ZIP's method 98: two bytes
//! of parameters, then the range coder's) in an archive of that one entry,
//! leniently and with `ZIP_CHECKCONS`, in pieces of one byte and of growing
//! sizes: the same bytes and the same error both ways, and no panic. The
//! decoder reads ahead of what it decodes only once it has 1 KiB of input
//! or all of it, so that the pieces it is given cannot change what it
//! reads. libzip has no PPMd: `crates/hivepack/src/zip/ppmd8_oracle.rs` compares the
//! model with 7-Zip's, and `crates/hivepack/tests/zip_ppmd.rs` whole archives with
//! `7zz`.

#![no_main]

use hivepack::zip::{Archive, Flags, OpenFlags};
use libfuzzer_sys::fuzz_target;

/// A bound on the work: the data decoded from a few bytes can be large.
const MOST: usize = 1 << 16;

/// An archive of one PPMd entry named "p", with `stream` as its data, said
/// to be of `size` bytes with the CRC `crc`.
fn archive(stream: &[u8], size: u32, crc: u32) -> Vec<u8> {
    let mut header = Vec::new();
    for (v, n) in [(63u32, 2), (0, 2), (98, 2), (0, 2), (0x5b21, 2), (crc, 4)] {
        header.extend_from_slice(&v.to_le_bytes()[..n]);
    }
    header.extend_from_slice(&(stream.len() as u32).to_le_bytes());
    header.extend_from_slice(&size.to_le_bytes());
    header.extend_from_slice(&1u16.to_le_bytes());
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend_from_slice(&header);
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(b"p");
    zip.extend_from_slice(stream);
    let cd_offset = zip.len() as u32;
    zip.extend_from_slice(b"PK\x01\x02\x3f\x03");
    zip.extend_from_slice(&header);
    zip.extend_from_slice(&[0; 12]);
    zip.extend_from_slice(&0u32.to_le_bytes());
    zip.extend_from_slice(b"p");
    let cd_size = zip.len() as u32 - cd_offset;
    zip.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
    zip.extend_from_slice(&cd_size.to_le_bytes());
    zip.extend_from_slice(&cd_offset.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip
}

/// The entry read in pieces of `first` bytes, growing if `grow`, up to
/// `MOST`: the bytes, and the error's code and system error if any.
fn read(zip: &[u8], flags: OpenFlags, first: usize, grow: bool) -> (Vec<u8>, Option<(i32, i32)>) {
    let za = Archive::open(zip, flags).expect("the archive opens");
    let mut zf = match za.fopen_index(0, Flags::NONE) {
        Ok(zf) => zf,
        Err(e) => return (Vec::new(), Some((e.code().number(), e.system()))),
    };
    let mut data = Vec::new();
    let mut buf = vec![0u8; 70_000];
    let mut piece = first;
    while data.len() < MOST {
        let want = piece.min(MOST - data.len());
        match zf.fread(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(e) => return (data, Some((e.code().number(), e.system()))),
        }
        if grow {
            piece = (piece * 3).min(buf.len());
        }
    }
    let end = (data.len() < MOST)
        .then(|| zf.fclose().err().map(|e| (e.code().number(), e.system())))
        .flatten();
    (data, end)
}

fuzz_target!(|data: &[u8]| {
    // The size and CRC of what the data decodes to, so that the CRC is
    // checked too, the length refused as it ends.
    let zip = archive(data, 0, 0);
    let (decoded, _) = read(&zip, OpenFlags(0), 70_000, false);
    let crc = hivepack::deflate::crc32(0, &decoded);
    let zip = archive(data, decoded.len() as u32, crc);
    for flags in [OpenFlags(0), OpenFlags::CHECKCONS] {
        let bytes = read(&zip, flags, 1, false);
        let grown = read(&zip, flags, 1, true);
        assert!(
            bytes.0 == grown.0,
            "{} bytes, then {}",
            bytes.0.len(),
            grown.0.len()
        );
        assert_eq!(bytes.1, grown.1);
    }
});
