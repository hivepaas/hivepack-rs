//! Extracting FAT file systems that hivepack::fat reads, from images built
//! byte by byte: the same ones `tests/fat.rs` builds and `fsck.fat` calls
//! sound there, so these tests need no tool at all and run everywhere.
//!
//! What is checked is the tree coming out as it went in — long names,
//! short names, a name of more than ASCII, a file of no bytes, a folder
//! inside a folder — and the two things a hostile image can write that a
//! kernel cannot: a name holding a separator, and a folder whose records
//! lead back into it.

#![cfg(all(feature = "fat", feature = "extract"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "fat_support/mod.rs"]
mod build;
#[path = "extract_support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::path::Path;

use build::{Build, by_hand, record};
use hivepack::extract::{NameError, OnRefused, Options, Summary, extract_fat};
use hivepack::fat::Fat;
use support::{Scratch, options};

fn extract(
    image: &[u8],
    out: &Path,
    options: &Options,
) -> Result<Summary, hivepack::extract::Error> {
    let fs = Fat::open(image).unwrap();
    extract_fat(&fs, out, options)
}

/// What came out, as `by_hand` says what went in: a path for each file
/// with its bytes, and none for a folder.
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

/// Each of FAT12, FAT16 and FAT32, built by hand, comes out as it was
/// built: the long names as names, the folder as a folder, the file of no
/// bytes as a file of no bytes.
#[test]
fn a_file_system_built_by_hand_comes_out_as_it_was_built() {
    for bits in [12u8, 16, 32] {
        let (image, want) = by_hand(bits);
        let s = Scratch::new();
        let out = s.path().join("out");
        let summary = extract(&image, &out, &options(|_| {})).unwrap();
        assert!(
            summary.skipped.is_empty(),
            "FAT{bits}: {:?}",
            summary
                .skipped
                .iter()
                .map(|e| format!("{} {:?}", e.name.as_ref().map_or(0, |n| n.len()), e.kind))
                .collect::<Vec<_>>()
        );
        assert_eq!(what_came_out(&out), want, "FAT{bits}");
    }
}

/// A long name holding a separator, which nothing that writes a file
/// system does and a hostile image can: a record is one name, not a path,
/// so it is refused rather than written into a folder of its own.
#[test]
fn a_name_that_holds_a_separator_lands_nowhere() {
    let (image, _) = by_hand(16);
    let mut image = image;
    // The long name is UTF-16 on the disk, and **not in one piece**: each
    // record carries thirteen characters in three fields, at 1, 14 and 28,
    // so a name does not lie contiguously anywhere. Five characters that
    // sit inside the first field are what is changed here, one of them
    // into a separator, so the length and the checksum tying the name to
    // its short one stay as they were.
    let was: Vec<u8> = "a lon"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let now: Vec<u8> = "a/lon"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let at = image
        .windows(was.len())
        .position(|w| w == was)
        .expect("the long name is on the image");
    image[at..at + now.len()].copy_from_slice(&now);

    let s = Scratch::new();
    let out = s.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let summary = extract(&image, &out, &options(|o| o.on_refused = OnRefused::Skip)).unwrap();
    assert!(
        !out.join("a").exists(),
        "a name with a separator was written as a path: {:?}",
        what_came_out(&out).keys().collect::<Vec<_>>()
    );
    assert!(
        summary.skipped.iter().any(|e| matches!(
            e.kind,
            hivepack::extract::ErrorKind::Name(NameError::Separator)
        )),
        "wanted the separator refused, got {:?}",
        summary
            .skipped
            .iter()
            .map(|e| format!("{:?}", e.kind))
            .collect::<Vec<_>>()
    );
}

/// A folder whose record names the cluster of a folder already walked
/// into: a chain that leads back on itself, which no kernel writes. It is
/// refused, and the extraction ends rather than walking it for ever.
#[test]
fn a_folder_that_leads_back_into_itself_is_refused() {
    let mut build = Build::new(16, 4200);
    let text = b"inside\n".to_vec();
    let at = build.put(&text, &[3]);

    // A folder at cluster 2 holding `.`, `..`, a file, and a record naming
    // cluster 2 again — itself.
    let mut inside = Vec::new();
    inside.extend(record(b".          ", 0x10, 0, 2, 0));
    inside.extend(record(b"..         ", 0x10, 0, 0, 0));
    inside.extend(record(b"INSIDE  TXT", 0x20, 0, at, text.len() as u32));
    inside.extend(record(b"AGAIN      ", 0x10, 0, 2, 0));
    build.put(&inside, &[2]);
    build.root = record(b"SUB        ", 0x10, 0, 2, 0);

    let image = build.image();
    let s = Scratch::new();
    let out = s.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let summary = extract(&image, &out, &options(|o| o.on_refused = OnRefused::Skip)).unwrap();

    // The folder and its file came out once; the record naming it again
    // was refused for what it is.
    let found = what_came_out(&out);
    assert_eq!(
        found.get("SUB/INSIDE.TXT"),
        Some(&Some(text)),
        "{:?}",
        found.keys().collect::<Vec<_>>()
    );
    assert!(
        !found.contains_key("SUB/AGAIN"),
        "the folder was walked into twice: {:?}",
        found.keys().collect::<Vec<_>>()
    );
    assert!(
        summary
            .skipped
            .iter()
            .any(|e| matches!(e.kind, hivepack::extract::ErrorKind::DirectoryAgain)),
        "wanted the folder refused, got {:?}",
        summary
            .skipped
            .iter()
            .map(|e| format!("{:?}", e.kind))
            .collect::<Vec<_>>()
    );
}

/// The long name is what comes out where the records carry one, and the
/// 8.3 name where they do not: what a system shows, not what MS-DOS saw.
#[test]
fn the_name_that_comes_out_is_the_one_a_system_shows() {
    let (image, _) = by_hand(12);
    let s = Scratch::new();
    let out = s.path().join("out");
    extract(&image, &out, &options(|_| {})).unwrap();
    let found = what_came_out(&out);
    assert!(
        found.contains_key("a long name of more than thirteen characters.txt"),
        "the long name is not what came out: {:?}",
        found.keys().collect::<Vec<_>>()
    );
    assert!(
        !found.contains_key("ALONGN~1.TXT"),
        "the short name came out as well: {:?}",
        found.keys().collect::<Vec<_>>()
    );
    // And a record with no long name beside it comes out as its own.
    assert!(found.contains_key("README.TXT"), "{:?}", found.keys());
    // The one written in one case comes out lowercased, as the byte says.
    assert!(found.contains_key("lower.txt"), "{:?}", found.keys());
}

/// The names of more than ASCII: `tên dài.txt` is a long name, so it comes
/// out as its characters and not as the bytes of a code page.
#[test]
fn a_name_of_more_than_ascii_comes_out_as_its_characters() {
    let (image, _) = by_hand(16);
    let s = Scratch::new();
    let out = s.path().join("out");
    extract(&image, &out, &options(|_| {})).unwrap();
    let found = what_came_out(&out);
    assert!(
        found.contains_key("tên dài.txt"),
        "{:?}",
        found.keys().collect::<Vec<_>>()
    );
}
