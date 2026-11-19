//! Extracting exFAT file systems that hivepack::exfat reads: out of a
//! volume `mkfs.exfat` wrote and `fsck.exfat` calls clean, and out of
//! volumes built byte by byte, which need no tool and run everywhere.
//!
//! What is checked is the tree coming out as it went in — a name of more
//! than ASCII, a file over more than one cluster, one whose clusters are
//! not a run, a folder inside a folder — the room a file was given and
//! never written coming out as zeroes, and the two things a hostile volume
//! can hold that no tool writes: a name holding a separator, and a folder
//! whose entries lead back into it.
//!
//! See crates/hivepack/src/extract/exfat.rs and docs/extract.md.

#![cfg(all(feature = "exfat", feature = "extract"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "exfat_support/mod.rs"]
mod build;
#[path = "extract_support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::path::Path;

use build::by_hand::{CLUSTER, a_set, a_volume, cluster_at, put_fat, with_a_cut_up_file};
use build::{Volume, pattern, say_or_fail};
use hivepack::exfat::Exfat;
use hivepack::extract::{ErrorKind, NameError, OnRefused, Options, Summary, extract_exfat};
use support::{Scratch, options};

fn extract(
    volume: &[u8],
    out: &Path,
    options: &Options,
) -> Result<Summary, hivepack::extract::Error> {
    let fs = Exfat::open(volume).unwrap();
    extract_exfat(&fs, out, options)
}

/// What came out: a path for each file with its bytes, and none for a
/// folder.
fn what_came_out(at: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut found = BTreeMap::new();
    let mut stack = vec![(at.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if entry.file_type().unwrap().is_dir() {
                found.insert(path.clone(), None);
                stack.push((entry.path(), path));
            } else {
                found.insert(path, Some(std::fs::read(entry.path()).unwrap()));
            }
        }
    }
    found
}

fn kinds(summary: &Summary) -> Vec<String> {
    summary
        .skipped
        .iter()
        .map(|e| format!("{:?}", e.kind))
        .collect()
}

/// A volume `mkfs.exfat` wrote, with files put in it and `fsck.exfat` run
/// over the result, comes out as it went in.
#[test]
fn a_volume_a_tool_wrote_comes_out_as_it_went_in() {
    let s = Scratch::new();
    let scratch = build::Scratch::new("extract");
    let Some(mut volume) = Volume::new(&scratch, 64 << 20, &["-q", "-c", "32K"]) else {
        say_or_fail("mkfs.exfat cannot be run here: extracting a real volume is not checked");
        return;
    };
    let small = b"hello from exFAT\n".to_vec();
    let over_a_cluster = pattern(100_000, 7);
    let cut_up = pattern(90_000, 11);
    volume.add_file("NOTES.TXT", &small, true);
    volume.add_file("big.bin", &over_a_cluster, true);
    volume.add_file("Hồ sơ.bin", &cut_up, false);
    volume.add_dir_with_file("thư mục", "inside.txt", b"a file in a directory\n");
    let path = volume.write(&scratch, "files.img");
    Volume::fsck(&path).unwrap();
    let bytes = std::fs::read(&path).unwrap();

    let out = s.path().join("out");
    let summary = extract(&bytes, &out, &options(|_| {})).unwrap();
    assert!(summary.skipped.is_empty(), "{:?}", kinds(&summary));
    assert_eq!(summary.files, 4);
    assert_eq!(summary.directories, 1);
    let found = what_came_out(&out);
    assert_eq!(found.get("NOTES.TXT"), Some(&Some(small)));
    assert_eq!(found.get("big.bin"), Some(&Some(over_a_cluster)));
    assert_eq!(found.get("Hồ sơ.bin"), Some(&Some(cut_up)));
    assert_eq!(found.get("thư mục"), Some(&None));
    assert_eq!(
        found.get("thư mục/inside.txt"),
        Some(&Some(b"a file in a directory\n".to_vec()))
    );
}

/// Room a file was given and never written comes out as zeroes, and not as
/// whatever was in those clusters before: somebody else's deleted data is
/// what the clusters hold, and the length the file says is what it gets.
#[test]
fn room_a_file_never_filled_comes_out_as_zeroes() {
    let scratch = build::Scratch::new("extract-valid");
    let Some(mut volume) = Volume::new(&scratch, 64 << 20, &["-q", "-c", "32K"]) else {
        say_or_fail("mkfs.exfat cannot be run here: unwritten room is not checked");
        return;
    };
    let before = pattern(64 << 10, 13);
    let clusters = volume.give(2, true);
    volume.put_data(&before, &clusters);
    let set = volume.a_set("HALF.BIN", 64 << 10, 100, clusters[0], false, true);
    let root = volume.root;
    volume.add_entries(root, &[set]);
    let path = volume.write(&scratch, "valid.img");
    Volume::fsck(&path).unwrap();
    let bytes = std::fs::read(&path).unwrap();

    let s = Scratch::new();
    let out = s.path().join("out");
    extract(&bytes, &out, &options(|_| {})).unwrap();
    let came = std::fs::read(out.join("HALF.BIN")).unwrap();
    assert_eq!(came.len(), 64 << 10);
    assert_eq!(&came[..100], &before[..100]);
    assert!(
        came[100..].iter().all(|b| *b == 0),
        "room that was never written came out holding something"
    );
}

/// A volume built by hand comes out as it was built, and needs no tool at
/// all: a file over two clusters that are not next to each other, which
/// the table is what finds.
#[test]
fn a_volume_built_by_hand_comes_out_as_it_was_built() {
    let data = pattern(CLUSTER + 200, 3);
    let bytes = with_a_cut_up_file(&data);
    let s = Scratch::new();
    let out = s.path().join("out");
    let summary = extract(&bytes, &out, &options(|_| {})).unwrap();
    assert!(summary.skipped.is_empty(), "{:?}", kinds(&summary));
    assert_eq!(
        what_came_out(&out),
        BTreeMap::from([("cut.bin".to_owned(), Some(data))])
    );
}

/// A name holding a separator, which exFAT's own rules leave out and a
/// hostile volume can hold: an entry is one name, not a path, so it is
/// refused rather than written into a folder of its own.
#[test]
fn a_name_that_holds_a_separator_lands_nowhere() {
    for separator in ['/', '\\'] {
        let mut bytes = a_volume(|_| {});
        let set = a_set(&format!("a{separator}b.txt"), 10, 4, false, true);
        let root = cluster_at(2);
        bytes[root..root + set.len()].copy_from_slice(&set);
        let at = cluster_at(4);
        bytes[at..at + 10].copy_from_slice(b"0123456789");

        let s = Scratch::new();
        let out = s.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let summary = extract(&bytes, &out, &options(|o| o.on_refused = OnRefused::Skip)).unwrap();
        assert!(
            !out.join("a").exists() && !out.join("a\\b.txt").exists(),
            "{separator:?}: a name with a separator was written: {:?}",
            what_came_out(&out).keys().collect::<Vec<_>>()
        );
        assert!(
            summary
                .skipped
                .iter()
                .any(|e| matches!(e.kind, ErrorKind::Name(NameError::Separator))),
            "{separator:?}: wanted the separator refused, got {:?}",
            kinds(&summary)
        );
    }
}

/// A folder whose entry names the cluster of a folder already walked into:
/// a chain that leads back on itself, which no kernel writes. It is
/// refused, and the extraction ends rather than walking it for ever.
#[test]
fn a_folder_that_leads_back_into_itself_is_refused() {
    let mut bytes = a_volume(|_| {});
    // A folder at cluster 4 holding a file and an entry naming cluster 4
    // again — itself.
    let mut inside = a_set("inside.txt", 7, 6, false, true);
    inside.extend_from_slice(&a_set("again", CLUSTER as u64, 4, true, true));
    let at = cluster_at(4);
    bytes[at..at + inside.len()].copy_from_slice(&inside);
    let data = cluster_at(6);
    bytes[data..data + 7].copy_from_slice(b"inside\n");
    put_fat(&mut bytes, 4, 0xFFFF_FFFF);
    put_fat(&mut bytes, 6, 0xFFFF_FFFF);
    let root = cluster_at(2);
    let set = a_set("sub", CLUSTER as u64, 4, true, true);
    bytes[root..root + set.len()].copy_from_slice(&set);

    let s = Scratch::new();
    let out = s.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let summary = extract(&bytes, &out, &options(|o| o.on_refused = OnRefused::Skip)).unwrap();

    let found = what_came_out(&out);
    assert_eq!(
        found.get("sub/inside.txt"),
        Some(&Some(b"inside\n".to_vec())),
        "{:?}",
        found.keys().collect::<Vec<_>>()
    );
    assert!(
        !found.contains_key("sub/again"),
        "the folder was walked into twice: {:?}",
        found.keys().collect::<Vec<_>>()
    );
    assert!(
        summary
            .skipped
            .iter()
            .any(|e| matches!(e.kind, ErrorKind::DirectoryAgain)),
        "wanted the folder refused, got {:?}",
        kinds(&summary)
    );
}

/// A set of entries that fails its own checksum is refused, with nothing
/// of the file written: the name and the length it would be read from
/// cannot be trusted, so the file is not written from them.
#[test]
fn a_set_whose_checksum_is_wrong_is_refused() {
    let mut bytes = a_volume(|_| {});
    let good = a_set("good.txt", 4, 4, false, true);
    let mut bad = a_set("bad.txt", 4, 6, false, true);
    bad[2] ^= 1;
    let root = cluster_at(2);
    bytes[root..root + good.len()].copy_from_slice(&good);
    bytes[root + good.len()..root + good.len() + bad.len()].copy_from_slice(&bad);
    for (cluster, text) in [(4u32, b"good"), (6, b"bad!")] {
        let at = cluster_at(cluster);
        bytes[at..at + 4].copy_from_slice(text);
    }

    let s = Scratch::new();
    let out = s.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    // The directory is read as a whole, so a set that fails its checksum
    // stops the whole listing: nothing of it is guessed at.
    let failed = extract(&bytes, &out, &options(|o| o.on_refused = OnRefused::Skip));
    assert!(
        matches!(
            failed.as_ref().map_err(|e| &e.kind),
            Err(ErrorKind::ExFat(hivepack::exfat::Error::SetChecksum))
        ),
        "wanted the set refused, got {:?}",
        failed.map(|s| s.files)
    );
    assert!(
        !out.join("good.txt").exists() && !out.join("bad.txt").exists(),
        "something was written out of a directory that does not read: {:?}",
        what_came_out(&out).keys().collect::<Vec<_>>()
    );
}

/// The entries that are not files — the allocation bitmap, the upcase
/// table, the volume's label — are not written as files: a real volume
/// holds all three in its root, and what came out of one is four files and
/// one folder, which is what went in.
#[test]
fn the_entries_that_are_not_files_come_out_as_nothing() {
    let scratch = build::Scratch::new("extract-meta");
    let Some(mut volume) = Volume::new(&scratch, 64 << 20, &["-q", "-L", "Thẻ nhớ"]) else {
        say_or_fail("mkfs.exfat cannot be run here: a real volume's root is not checked");
        return;
    };
    volume.add_file("ONE.TXT", b"one\n", true);
    let path = volume.write(&scratch, "meta.img");
    Volume::fsck(&path).unwrap();
    let bytes = std::fs::read(&path).unwrap();

    let s = Scratch::new();
    let out = s.path().join("out");
    let summary = extract(&bytes, &out, &options(|_| {})).unwrap();
    assert_eq!((summary.files, summary.directories), (1, 0));
    assert_eq!(
        what_came_out(&out),
        BTreeMap::from([("ONE.TXT".to_owned(), Some(b"one\n".to_vec()))])
    );
}
