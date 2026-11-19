//! WIM archives: what `7zz` writes and lists, read back here and compared
//! with it, and archives changed by hand for what no tool writes.
//!
//! 7-Zip writes an uncompressed WIM and reads every kind, so it is the
//! oracle for the container, the table of resources and the tree — which
//! is what this reads. XPRESS, LZX and LZMS are named and refused, and
//! their decoders come next: `docs/wim.md`.
//!
//! See crates/hivepack/src/wim/mod.rs.

#![cfg(feature = "wim")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use hivepack::wim::{Compression, Entry, Error, Unsupported, Wim};

/// Where `scripts/testdata.py` puts what it fetches and builds.
fn cache() -> PathBuf {
    std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/testdata"))
}

/// `7zz`, as `scripts/testdata.py` builds it. CI lists the `generated`
/// group in `HIVEPACK_TESTDATA_REQUIRED` where it builds it, and then a
/// missing one fails rather than being passed over.
fn seven_zip() -> Option<PathBuf> {
    let folder = cache().join("7zz");
    if folder.join(".complete").exists() {
        return Some(folder.join("7zz"));
    }
    let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
    assert!(
        !required.split(',').any(|g| g == "all" || g == "generated"),
        "7zz is missing: run `python3 scripts/testdata.py fetch --group generated`"
    );
    eprintln!("skipping: 7zz is not built (scripts/testdata.py fetch --group generated)");
    None
}

/// A folder in the system's temporary one, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(what: &str) -> Scratch {
        let path = std::env::temp_dir().join(format!("hivepack-wim-{}-{what}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(tool: &Path, args: &[&str]) -> String {
    let out = Command::new(tool).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{tool:?} {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Bytes that are the same every run, and not all alike.
fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    let mut x = seed | 1;
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        bytes.push((x >> 24) as u8);
    }
    bytes
}

/// The tree the tests put in an archive: a path for each file with its
/// bytes, and none for a folder.
fn a_tree() -> BTreeMap<&'static str, Option<Vec<u8>>> {
    BTreeMap::from([
        ("readme.txt", Some(b"hello from a wim\n".to_vec())),
        ("docs", None),
        ("docs/note.txt", Some(b"deeper\n".to_vec())),
        (
            "docs/tên có dấu.txt",
            Some("nội dung\n".as_bytes().to_vec()),
        ),
        ("empty.bin", Some(Vec::new())),
        ("big.bin", Some(pattern(200_000, 7))),
    ])
}

/// An archive of [`a_tree`], written by `7zz`, and its bytes.
fn an_archive(s: &Scratch, tool: &Path, name: &str) -> Vec<u8> {
    let tree = s.0.join("tree");
    for (path, what) in a_tree() {
        let at = tree.join(path);
        match what {
            Some(bytes) => {
                std::fs::create_dir_all(at.parent().unwrap()).unwrap();
                std::fs::write(&at, bytes).unwrap();
            }
            None => std::fs::create_dir_all(&at).unwrap(),
        }
    }
    let archive = s.0.join(name);
    run(
        tool,
        &[
            "a",
            "-twim",
            archive.to_str().unwrap(),
            tree.join(".").to_str().unwrap(),
        ],
    );
    std::fs::read(&archive).unwrap()
}

/// What the archive holds, as hivepack reads it: the paths with their
/// bytes, and none for a folder.
fn what_hivepack_reads(bytes: &[u8]) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut wim = Wim::open(std::io::Cursor::new(bytes.to_vec())).unwrap();
    let entries = wim.entries(1).unwrap();
    let mut found = BTreeMap::new();
    for entry in &entries {
        let what = if entry.is_dir() {
            None
        } else {
            Some(wim.read(entry).unwrap())
        };
        found.insert(entry.path.clone(), what);
    }
    found
}

/// What the archive holds, as `7zz l -slt` lists it: the paths with their
/// lengths, and none for a folder.
fn what_7zz_lists(tool: &Path, archive: &Path) -> BTreeMap<String, Option<u64>> {
    let listing = run(tool, &["l", "-slt", archive.to_str().unwrap()]);
    let mut found = BTreeMap::new();
    let mut path = None;
    let mut size = None;
    let mut folder = false;
    for line in listing.lines() {
        if let Some(rest) = line.strip_prefix("Path = ") {
            // The first `Path` is the archive itself.
            if let Some(path) = path.take() {
                found.insert(path, if folder { None } else { size.take() });
            }
            path = Some(rest.to_owned());
            size = None;
            folder = false;
        } else if let Some(rest) = line.strip_prefix("Size = ") {
            size = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("Folder = ") {
            folder = rest.trim() == "+";
        } else if let Some(rest) = line.strip_prefix("Attributes = ") {
            folder = folder || rest.contains('D');
        }
    }
    if let Some(path) = path {
        found.insert(path, if folder { None } else { size });
    }
    found
}

/// An archive `7zz` wrote: what hivepack reads out of it is the tree that
/// went in, and the paths and lengths `7zz` itself lists.
#[test]
fn an_archive_a_tool_wrote_reads_as_the_tree_that_went_in() {
    let Some(tool) = seven_zip() else { return };
    let s = Scratch::new("tree");
    let bytes = an_archive(&s, &tool, "out.wim");

    // What it is: uncompressed, one image, and a resource for each file
    // with bytes of its own.
    let mut wim = Wim::open(std::io::Cursor::new(bytes.clone())).unwrap();
    assert_eq!(wim.compression(), Compression::None);
    assert_eq!(wim.images().len(), 1);
    assert_eq!(wim.images()[0].index, 1);

    let read = what_hivepack_reads(&bytes);
    let want: BTreeMap<String, Option<Vec<u8>>> = a_tree()
        .into_iter()
        .map(|(path, what)| (path.to_owned(), what))
        .collect();
    assert_eq!(read, want);

    // And what 7-Zip lists out of the same archive: the same paths, the
    // same lengths. It writes paths with `\`, as Windows does.
    let listed = what_7zz_lists(&tool, &s.0.join("out.wim"));
    let mine: BTreeMap<String, Option<u64>> = wim
        .entries(1)
        .unwrap()
        .iter()
        .map(|e| (e.path.clone(), if e.is_dir() { None } else { Some(e.size) }))
        .collect();
    // The listing's first `Path` is the archive itself.
    let listed: BTreeMap<String, Option<u64>> = listed
        .into_iter()
        .filter(|(path, _)| !path.ends_with(".wim"))
        .collect();
    assert_eq!(mine, listed);
}

/// Two names of one file are one resource: the entries carry the same
/// SHA-1, and the archive holds the bytes once.
#[test]
fn two_names_of_one_file_are_one_resource() {
    let Some(tool) = seven_zip() else { return };
    let s = Scratch::new("links");
    let tree = s.0.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    let data = pattern(50_000, 11);
    std::fs::write(tree.join("one.bin"), &data).unwrap();
    std::fs::hard_link(tree.join("one.bin"), tree.join("two.bin")).unwrap();
    let archive = s.0.join("links.wim");
    run(
        tool.as_path(),
        &[
            "a",
            "-twim",
            archive.to_str().unwrap(),
            tree.join(".").to_str().unwrap(),
        ],
    );

    let mut wim = Wim::open(std::fs::File::open(&archive).unwrap()).unwrap();
    let entries = wim.entries(1).unwrap();
    let files: Vec<&Entry> = entries.iter().filter(|e| e.is_file()).collect();
    assert_eq!(files.len(), 2, "{:?}", entries);
    assert_eq!(files[0].hash, files[1].hash, "two names, two hashes");
    assert_eq!((files[0].size, files[1].size), (50_000, 50_000));
    // One resource for the bytes, one for the tree.
    assert_eq!(wim.resources(), 2);
    assert_eq!(wim.read(files[0]).unwrap(), data);
    assert_eq!(wim.read(files[1]).unwrap(), data);
}

/// A file of no bytes carries a hash of nothing and has no resource at
/// all, which is what every tool writes.
#[test]
fn a_file_of_no_bytes_has_no_resource() {
    let Some(tool) = seven_zip() else { return };
    let s = Scratch::new("empty");
    let bytes = an_archive(&s, &tool, "out.wim");
    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    let entries = wim.entries(1).unwrap();
    let empty = entries.iter().find(|e| e.name == "empty.bin").unwrap();
    assert_eq!(empty.hash, [0u8; 20]);
    assert_eq!(empty.size, 0);
    assert!(wim.read(empty).unwrap().is_empty());
}

/// A directory is not a file, and the image asked for has to be there.
#[test]
fn what_is_not_there_is_said_rather_than_guessed() {
    let Some(tool) = seven_zip() else { return };
    let s = Scratch::new("errors");
    let bytes = an_archive(&s, &tool, "out.wim");
    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    let entries = wim.entries(1).unwrap();
    let dir = entries.iter().find(|e| e.is_dir()).unwrap();
    assert!(matches!(wim.read(dir), Err(Error::NotAFile)));
    assert!(matches!(
        wim.entries(2),
        Err(Error::NoSuchImage { index: 2 })
    ));
    assert!(matches!(
        wim.entries(0),
        Err(Error::NoSuchImage { index: 0 })
    ));
}

/// The times an entry carries come out as the times the files had: 7-Zip
/// writes what the file system said, so they are compared with the file's
/// own modified time to the second.
#[test]
fn the_times_come_out_as_the_files_had_them() {
    let Some(tool) = seven_zip() else { return };
    let s = Scratch::new("times");
    let bytes = an_archive(&s, &tool, "out.wim");
    let on_disk = std::fs::metadata(s.0.join("tree/readme.txt"))
        .unwrap()
        .modified()
        .unwrap();
    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    let entries = wim.entries(1).unwrap();
    let readme = entries.iter().find(|e| e.name == "readme.txt").unwrap();
    let modified = readme.modified.expect("a modified time");
    let one = std::time::Duration::from_secs(1);
    let near = modified
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .abs_diff(
            on_disk
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
    assert!(near <= 1, "the modified time is {near}s from the file's");
    // 7-Zip writes the modified time and leaves the other two at zero,
    // which is no time at all; Windows' own tools write all three. An
    // entry that carries none says none rather than 1601.
    assert_eq!((readme.created, readme.accessed), (None, None));
    let _ = one;
}

/// Archives changed by hand: what no tool writes, and what a `.wim` from a
/// Windows disc or a `.esd` says it needs.
mod by_hand {
    use super::*;

    /// The archive, with `change` run over its header.
    fn with(s: &Scratch, tool: &Path, change: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut bytes = an_archive(s, tool, "out.wim");
        change(&mut bytes);
        bytes
    }

    #[test]
    fn what_is_not_a_wim_is_not_opened_as_one() {
        for bytes in [Vec::new(), vec![0u8; 100], vec![0u8; 4096]] {
            assert!(matches!(
                Wim::open(std::io::Cursor::new(bytes)),
                Err(Error::Unrecognized)
            ));
        }
    }

    /// The compressions a WIM in the wild is in: named, and refused by
    /// name. A `.wim` from a Windows disc is LZX and a `.esd` is LZMS.
    #[test]
    fn the_compressions_that_are_not_decoded_yet_are_named() {
        let Some(tool) = seven_zip() else { return };
        let s = Scratch::new("compressions");
        for (flags, compression, needs) in [
            (0x0002_0002u32, Compression::Xpress, Unsupported::Xpress),
            (0x0004_0002, Compression::Lzx, Unsupported::Lzx),
            (0x0008_0002, Compression::Lzms, Unsupported::Lzms),
        ] {
            // The header says the compression, and the resources say they
            // are compressed: what a real archive of that kind holds.
            let bytes = with(&s, &tool, |bytes| {
                bytes[16..20].copy_from_slice(&flags.to_le_bytes());
                bytes[20..24].copy_from_slice(&32768u32.to_le_bytes());
                // The table of resources is at the end, and its own
                // resource header is in the file header: mark the table
                // compressed as well.
                bytes[55] |= 0x04;
            });
            // Opening reads the table, which is the first thing that is
            // compressed: it says what it needs, by name.
            let opened = Wim::open(std::io::Cursor::new(bytes.clone()));
            assert!(
                matches!(opened.as_ref().err(), Some(Error::Needs(what)) if *what == needs),
                "{compression:?}: wanted {needs:?}"
            );

            // With only a file's resource compressed, the archive opens
            // and the tree reads; the file is what says what it needs.
            let bytes = with(&s, &tool, |bytes| {
                bytes[16..20].copy_from_slice(&flags.to_le_bytes());
                bytes[20..24].copy_from_slice(&32768u32.to_le_bytes());
            });
            let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
            assert_eq!(wim.compression(), compression);
            assert_eq!(wim.chunk_size(), 32768);
            assert!(wim.entries(1).is_ok(), "the tree still reads");
        }
    }

    /// A part of a split archive (`.swm`): the resources it names are in
    /// files this cannot reach, so it is refused rather than read as an
    /// archive missing most of itself.
    #[test]
    fn a_part_of_a_split_archive_is_refused() {
        let Some(tool) = seven_zip() else { return };
        let s = Scratch::new("split");
        // By the count of parts, and by the flag.
        for change in [
            |bytes: &mut Vec<u8>| bytes[42..44].copy_from_slice(&2u16.to_le_bytes()),
            |bytes: &mut Vec<u8>| bytes[16..20].copy_from_slice(&0x0000_0008u32.to_le_bytes()),
        ] {
            let bytes = with(&s, &tool, change);
            assert!(matches!(
                Wim::open(std::io::Cursor::new(bytes)),
                Err(Error::Needs(Unsupported::Spanned))
            ));
        }
    }

    /// A version this does not read, and a header that is not the size
    /// the format fixes.
    #[test]
    fn a_header_that_says_what_it_cannot_is_refused() {
        let Some(tool) = seven_zip() else { return };
        let s = Scratch::new("header");
        let bytes = with(&s, &tool, |bytes| {
            bytes[12..16].copy_from_slice(&0x0001_0e00u32.to_le_bytes());
        });
        assert!(matches!(
            Wim::open(std::io::Cursor::new(bytes)),
            Err(Error::Version {
                version: 0x0001_0e00
            })
        ));
        let bytes = with(&s, &tool, |bytes| {
            bytes[8..12].copy_from_slice(&64u32.to_le_bytes());
        });
        assert!(matches!(
            Wim::open(std::io::Cursor::new(bytes)),
            Err(Error::Says)
        ));
        // A table of resources that is not on the file.
        let bytes = with(&s, &tool, |bytes| {
            bytes[56..64].copy_from_slice(&u64::MAX.to_le_bytes());
        });
        assert!(matches!(
            Wim::open(std::io::Cursor::new(bytes)),
            Err(Error::Says)
        ));
        // A table whose length is not a whole number of entries.
        let bytes = with(&s, &tool, |bytes| {
            let size = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
            bytes[48..56].copy_from_slice(&(size - 1).to_le_bytes());
        });
        assert!(matches!(
            Wim::open(std::io::Cursor::new(bytes)),
            Err(Error::Lookup) | Err(Error::Resource)
        ));
    }

    /// A tree whose directory names a child list already walked into: a
    /// loop, which no tool writes and a crafted archive can hold.
    ///
    /// The metadata resource is not compressed here, so its bytes are
    /// changed where they lie.
    #[test]
    fn a_tree_that_leads_back_into_itself_is_told() {
        let Some(tool) = seven_zip() else { return };
        let s = Scratch::new("loop");
        let bytes = an_archive(&s, &tool, "out.wim");
        // Where the metadata resource is: the one entry of the table with
        // the metadata flag.
        let table_at = u64::from_le_bytes(bytes[56..64].try_into().unwrap()) as usize;
        let table_size =
            (u64::from_le_bytes(bytes[48..56].try_into().unwrap()) & ((1 << 56) - 1)) as usize;
        let mut meta_at = None;
        for entry in bytes[table_at..table_at + table_size].as_chunks::<50>().0 {
            let flags = u64::from_le_bytes(entry[0..8].try_into().unwrap()) >> 56;
            if flags & 0x02 != 0 {
                meta_at = Some(u64::from_le_bytes(entry[8..16].try_into().unwrap()) as usize);
            }
        }
        let meta_at = meta_at.expect("a metadata resource");

        // The root's children begin at its own `subdir_offset`; pointing
        // a directory inside them back at that offset is the loop.
        let tree_at = meta_at + 8;
        let root_children =
            u64::from_le_bytes(bytes[tree_at + 16..tree_at + 24].try_into().unwrap());
        let mut looped = bytes.clone();
        // The first directory among the root's children, pointed back at
        // the root's own child list: that is the loop.
        let mut at = meta_at + root_children as usize;
        loop {
            let length = u64::from_le_bytes(looped[at..at + 8].try_into().unwrap()) as usize;
            assert!(length != 0, "no directory among the root's children");
            let attributes = u32::from_le_bytes(looped[at + 8..at + 12].try_into().unwrap());
            if attributes & 0x10 != 0 {
                looped[at + 16..at + 24].copy_from_slice(&root_children.to_le_bytes());
                break;
            }
            at += length;
        }

        let mut wim = Wim::open(std::io::Cursor::new(looped)).unwrap();
        assert!(
            matches!(wim.entries(1), Err(Error::TreeLoops)),
            "a tree that leads back into itself was walked"
        );
    }
}
