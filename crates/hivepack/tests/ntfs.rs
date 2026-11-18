//! NTFS file systems: a tree put into one by `mkntfs` and `ntfs-3g` and
//! read back out of it, against the bytes that went in.
//!
//! The library that reads the structures is a dependency and not a port,
//! so these tests are about the two things that makes true: that what it
//! reads comes back byte for byte, and that what it does *not* read is
//! refused rather than answered wrongly. The compressed file is the one
//! that matters most — the library hands back the compressed bytes with no
//! error at all, which `docs/ntfs.md` measures.
//!
//! See crates/hivepack/src/ntfs/ and docs/ntfs.md.

#![cfg(all(feature = "ntfs", feature = "image"))]
#![allow(clippy::unwrap_used)]

#[path = "ntfs_support/mod.rs"]
mod build;

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};

use build::{MANY, STREAM, image_or_say, sparse, squashy};
use hivepack::ntfs::{Entry, Error, Ntfs};

/// Every path in the image, and the entry at it.
fn walked<D: hivepack::image::Disk>(fs: &Ntfs<D>) -> BTreeMap<String, Entry> {
    let mut all = BTreeMap::new();
    let mut walk = fs.walk().unwrap();
    while let Some((path, entry)) = walk.next(fs).unwrap() {
        assert!(all.insert(path.clone(), entry).is_none(), "{path} twice");
    }
    all
}

#[test]
fn a_tree_reads_back_as_it_went_in() {
    let Some(built) = image_or_say() else {
        return;
    };
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    assert_eq!(fs.label(), Some("probe"));
    let all = walked(&fs);
    for (path, want) in &built.files {
        let entry = all
            .get(path)
            .unwrap_or_else(|| panic!("{path} is not in the image"));
        assert!(entry.is_file(), "{path} reads as a directory");
        assert_eq!(entry.size, want.len() as u64, "{path} is another length");
        // The compressed one is refused, which its own test is about.
        if entry.compressed {
            continue;
        }
        let mut got = Vec::new();
        fs.file(entry).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got.len(), want.len(), "{path} reads another length");
        assert!(got == *want, "{path} reads other bytes");
    }
    // Nothing invented: every file the walk found is one that was written,
    // and the directories on the way to them.
    let dirs = ["dir", "dir/sub", "many", "comp", "frag"];
    for (path, entry) in &all {
        assert!(
            built.files.contains_key(path) || dirs.contains(&path.as_str()),
            "{path} is in the image and was never written ({entry:?})"
        );
    }
}

#[test]
fn a_compressed_file_is_refused_rather_than_read_wrongly() {
    let Some(built) = image_or_say() else {
        return;
    };
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    let entry = fs.lookup_path("comp/squashy.txt").unwrap().unwrap();
    // The premise: NTFS really did compress it. Without this the test
    // could pass on an image where there was nothing to refuse.
    assert!(
        entry.compressed,
        "nothing was compressed, so there is nothing to refuse"
    );
    assert_eq!(entry.size, squashy().len() as u64);
    // The library would hand back the compressed bytes here, with no error
    // at all: docs/ntfs.md has that measurement. Refusing is the whole
    // point of this module.
    assert!(matches!(fs.file(&entry), Err(Error::Compressed)));
    assert!(matches!(entry.readable(), Err(Error::Compressed)));
}

#[test]
fn the_stream_beside_a_file_is_not_the_file() {
    let Some(built) = image_or_say() else {
        return;
    };
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    let entry = fs.lookup_path("ads.txt").unwrap().unwrap();
    assert_eq!(entry.size, b"main data\n".len() as u64);
    let mut got = Vec::new();
    fs.file(&entry).unwrap().read_to_end(&mut got).unwrap();
    // The file's own data, and not the stream that is also in its record.
    assert_eq!(got, b"main data\n");
    assert_ne!(got, STREAM);
    // And the stream is not a file of its own in the directory.
    assert!(fs.lookup_path("ads.txt:extra").unwrap().is_none());
}

#[test]
fn a_hole_reads_as_the_zeroes_it_stands_for() {
    let Some(built) = image_or_say() else {
        return;
    };
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    let entry = fs.lookup_path("sparse.bin").unwrap().unwrap();
    assert!(entry.sparse, "the file system did not keep it sparsely");
    let mut got = Vec::new();
    fs.file(&entry).unwrap().read_to_end(&mut got).unwrap();
    assert_eq!(got, sparse());
}

#[test]
fn two_names_of_one_file_are_one_record() {
    let Some(built) = image_or_say() else {
        return;
    };
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    let one = fs.lookup_path("plain.txt").unwrap().unwrap();
    let other = fs.lookup_path("hardlink.txt").unwrap().unwrap();
    assert_eq!(one.record(), other.record());
    assert_eq!(one.links, 2);
    assert_eq!(other.links, 2);
    let mut got = Vec::new();
    fs.file(&other).unwrap().read_to_end(&mut got).unwrap();
    assert_eq!(got, b"hello resident\n");
}

#[test]
fn a_directory_too_long_for_its_record_reads_all_of_it() {
    let Some(built) = image_or_say() else {
        return;
    };
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    let many = fs.lookup_path("many").unwrap().unwrap();
    assert!(many.is_dir());
    let entries = fs.read_dir(&many).unwrap();
    assert_eq!(entries.len(), MANY);
    for i in 0..MANY {
        let name = format!("file-{i:04}.txt");
        let entry = entries.iter().find(|entry| entry.name == name);
        assert!(entry.is_some(), "{name} is not in the directory");
    }
}

#[test]
fn a_file_in_many_pieces_reads_in_order() {
    let Some(built) = image_or_say() else {
        return;
    };
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    let entry = fs.lookup_path("frag/target.bin").unwrap().unwrap();
    let want = &built.files["frag/target.bin"];
    // Read in pieces that do not line up with the runs, as a reader that
    // is right only when asked for whole runs would pass otherwise.
    let mut file = fs.file(&entry).unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 777];
    loop {
        let read = file.read(&mut buf).unwrap();
        if read == 0 {
            break;
        }
        got.extend_from_slice(&buf[..read]);
    }
    assert_eq!(got.len(), want.len());
    assert!(got == *want);
    // And seeking lands where it says: the last byte, by itself.
    let mut file = fs.file(&entry).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    let mut last = [0u8; 1];
    file.read_exact(&mut last).unwrap();
    assert_eq!(last[0], *want.last().unwrap());
}

#[test]
fn what_is_not_ntfs_is_not_opened() {
    // No tools needed for this one, so it runs everywhere.
    //
    // The library checks the two bytes at the end of the boot sector and
    // never the name at its start, so each of these reaches it and is
    // turned away by whichever field it reads next happens not to hold.
    // hivepack checks the name, where "not NTFS" is the answer.
    let mut like_fat = vec![0u8; 1 << 20];
    like_fat[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    like_fat[3..11].copy_from_slice(b"MSDOS5.0");
    like_fat[11..13].copy_from_slice(&512u16.to_le_bytes());
    like_fat[13] = 8;
    like_fat[510..512].copy_from_slice(&[0x55, 0xAA]);
    for (what, bytes) in [
        ("a FAT boot sector", like_fat),
        ("nothing at all", vec![0u8; 1 << 20]),
        ("a disk shorter than a name", vec![0u8; 4]),
    ] {
        assert!(
            matches!(Ntfs::open(bytes.as_slice()), Err(Error::Unrecognized)),
            "{what} opened as NTFS"
        );
    }
}

#[test]
fn a_disk_too_short_for_a_boot_sector_is_not_opened() {
    // No tools needed for this one either.
    //
    // The library panics rather than failing when the stream ends inside
    // the boot sector: `ntfs-0.4.0/src/error.rs:236`, where
    // `From<binrw::error::Error>` ends in `unreachable!()` under a comment
    // saying no attribute it uses can give another kind of error. binrw
    // wraps an `Io` error from a derived struct in `Error::Backtrace`, so
    // the `if let Error::Io` misses and the `unreachable!` fires. Measured
    // at each of these lengths; 512 and above are refused properly.
    //
    // So hivepack has to know the whole boot sector is there before it
    // hands the disk over. A short disk is not exotic — a partition whose
    // size field is wrong is one.
    for len in [11usize, 100, 256, 460, 511] {
        let mut bytes = vec![0u8; len];
        bytes[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
        bytes[3..11].copy_from_slice(b"NTFS    ");
        assert!(
            matches!(Ntfs::open(bytes.as_slice()), Err(Error::Unrecognized)),
            "a disk of {len} bytes was not refused"
        );
    }
}
