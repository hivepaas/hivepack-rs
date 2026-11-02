//! Opens the input as a split archive with hivepack::zip: its first byte
//! says how many volumes (1 to 8), the next four bytes for each but the
//! last where it ends (little-endian, then taken modulo what is left), and
//! the rest is cut into those volumes, joined by `Volumes`. Leniently and
//! with `ZIP_CHECKCONS`, every entry is read, decompressed and raw, in
//! pieces: no panic, and the archive, written again as one of one disk,
//! opens with the same entries. libzip reads no split archives:
//! `crates/hivepack/tests/zip_split.rs` compares them with 7-Zip.

#![no_main]

use std::io::Cursor;

use hivepack::zip::{Archive, Closed, Flags, OpenFlags, ReadAt, Volumes};
use libfuzzer_sys::fuzz_target;

/// Reads entry `i` to its end, in pieces of growing sizes, and closes it.
fn read_all<R: ReadAt>(za: &Archive<R>, i: u64, flags: Flags) {
    let Ok(mut zf) = za.fopen_index(i, flags) else {
        return;
    };
    let mut buf = vec![0u8; 70_000];
    let mut piece = 1;
    // A bound on the work: the data of an entry can be large.
    for _ in 0..200 {
        match zf.fread(&mut buf[..piece]) {
            Ok(0) | Err(_) => break,
            Ok(_) => piece = (piece * 3).min(buf.len()),
        }
    }
    let _ = zf.fclose();
}

fuzz_target!(|data: &[u8]| {
    let Some((&count, rest)) = data.split_first() else {
        return;
    };
    let count = usize::from(count % 8) + 1;
    if rest.len() < 4 * (count - 1) {
        return;
    }
    let (ends, mut rest) = rest.split_at(4 * (count - 1));
    let mut parts = Vec::new();
    for end in ends.chunks_exact(4) {
        let end = u32::from_le_bytes(end.try_into().unwrap()) as usize % (rest.len() + 1);
        parts.push(rest[..end].to_vec());
        rest = &rest[end..];
    }
    parts.push(rest.to_vec());
    let volumes = Volumes::new(parts).unwrap();
    for flags in [OpenFlags::RDONLY, OpenFlags::RDONLY | OpenFlags::CHECKCONS] {
        let Ok(za) = Archive::open(&volumes, flags) else {
            continue;
        };
        for i in 0..za.get_num_entries(Flags::NONE) {
            let _ = za.stat_index(i, Flags::NONE);
            read_all(&za, i, Flags::NONE);
            read_all(&za, i, Flags::COMPRESSED);
        }
    }
    // Written again: an archive of one disk with the same entries, if it
    // is written.
    let Ok(mut za) = Archive::open(&volumes, OpenFlags(0)) else {
        return;
    };
    let names: Vec<Vec<u8>> = (0..za.get_num_entries(Flags::NONE))
        .filter_map(|i| za.get_name(i, Flags::ENC_RAW).ok().map(<[u8]>::to_vec))
        .collect();
    if za.set_archive_comment(b"joined").is_err() {
        return;
    }
    let mut out = Cursor::new(Vec::new());
    if let Ok(Closed::Written) = za.close_to(&mut out) {
        let joined = out.into_inner();
        let za = Archive::open(joined.as_slice(), OpenFlags(0)).expect("the joined archive opens");
        let again: Vec<Vec<u8>> = (0..za.get_num_entries(Flags::NONE))
            .filter_map(|i| za.get_name(i, Flags::ENC_RAW).ok().map(<[u8]>::to_vec))
            .collect();
        assert_eq!(names, again);
    }
});
