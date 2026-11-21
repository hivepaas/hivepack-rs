//! WIM archives that `wimlib-imagex` wrote, which is the only oracle for a
//! **compressed** one.
//!
//! 7-Zip reads XPRESS and LZX but writes neither — `7zz a -twim -mm=XPRESS`
//! fails with `E_INVALIDARG` — so `tests/wim.rs` can only check the
//! container and the tree of an uncompressed archive. wimlib writes all
//! four kinds, and these say what this reader does with each of them as
//! they really come, rather than as a header turned over by hand suggests.
//!
//! wimlib is GPL-3.0-or-later. It is built by `scripts/testdata.py` and run
//! as a program here, and nothing in this repository is read from it: the
//! formats are implemented from Microsoft's own specifications.
//!
//! See crates/hivepack/src/wim/mod.rs and docs/wim.md.

#![cfg(feature = "wim")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use hivepack::wim::{Compression, Error, Unsupported, Wim};

/// Where `scripts/testdata.py` puts what it fetches and builds.
fn cache() -> PathBuf {
    std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/testdata"))
}

/// `wimlib-imagex`, as `scripts/testdata.py` builds it. CI lists the
/// `generated` group in `HIVEPACK_TESTDATA_REQUIRED` where it builds it,
/// and then a missing one fails rather than being passed over.
fn wimlib() -> Option<PathBuf> {
    let folder = cache().join("wimlib");
    if folder.join(".complete").exists() {
        return Some(folder.join("wimlib-imagex"));
    }
    let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
    assert!(
        !required.split(',').any(|g| g == "all" || g == "generated"),
        "wimlib is missing: run `python3 scripts/testdata.py fetch --group generated`"
    );
    eprintln!("skipping: wimlib is not built (scripts/testdata.py fetch --group generated)");
    None
}

/// A folder in the system's temporary one, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(what: &str) -> Scratch {
        let path =
            std::env::temp_dir().join(format!("hivepack-wimlib-{}-{what}", std::process::id()));
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

/// The tree these tests put in an archive: a path for each file with its
/// bytes, and none for a folder. It holds bytes that compress (the same
/// line over and over) and bytes that do not (a pattern), so that a
/// compressed archive really has compressed resources in it.
fn a_tree() -> BTreeMap<&'static str, Option<Vec<u8>>> {
    BTreeMap::from([
        ("readme.txt", Some(b"hello from a wim\n".to_vec())),
        ("docs", None),
        ("docs/note.txt", Some(b"deeper\n".to_vec())),
        (
            "docs/over and over.txt",
            Some(b"the quick brown fox jumps over the lazy dog\n".repeat(400)),
        ),
        ("empty.bin", Some(Vec::new())),
        ("noise.bin", Some(pattern(60_000, 11))),
    ])
}

/// An archive of [`a_tree`] that wimlib wrote with `how`, and its bytes.
/// `how` is what follows `--compress=`, or `--solid` on its own.
fn captured(s: &Scratch, tool: &Path, how: &str) -> Vec<u8> {
    let tree = s.0.join(format!("tree-{}", how.replace("--", "")));
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
    let archive = s.0.join(format!("{}.wim", how.replace("--", "")));
    let _ = std::fs::remove_file(&archive);
    let out = Command::new(tool)
        .args([
            "capture",
            tree.to_str().unwrap(),
            archive.to_str().unwrap(),
            "probe",
            "--norpfix",
            how,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "wimlib-imagex capture {how} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(&archive).unwrap()
}

/// An archive wimlib wrote with no compression: the tree that went in comes
/// back, as it does from 7-Zip's in `tests/wim.rs`. Two writers of the same
/// format, so what is read is the format and not one tool's habits.
#[test]
fn an_archive_wimlib_wrote_uncompressed_reads_as_the_tree_that_went_in() {
    let Some(tool) = wimlib() else { return };
    let s = Scratch::new("none");
    let bytes = captured(&s, &tool, "--compress=none");

    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    assert_eq!(wim.compression(), Compression::None);
    assert_eq!(wim.images().len(), 1);
    assert_eq!(wim.images()[0].name.as_deref(), Some("probe"));

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
    let want: BTreeMap<String, Option<Vec<u8>>> = a_tree()
        .into_iter()
        .map(|(path, what)| (path.to_string(), what))
        .collect();
    assert_eq!(found, want);
}

/// An archive wimlib wrote with XPRESS: the tree **and** every file come
/// back as they went in, chunk by chunk.
///
/// The tree matters as much as the files: an image's metadata is a
/// compressed resource too, so this is also the first test in which a
/// compressed metadata resource is read.
#[test]
fn an_xpress_archive_reads_as_the_tree_that_went_in() {
    let Some(tool) = wimlib() else { return };
    let s = Scratch::new("xpress");
    let bytes = captured(&s, &tool, "--compress=XPRESS");

    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    assert_eq!(wim.compression(), Compression::Xpress);
    assert_eq!(wim.chunk_size(), 32_768);

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
    let want: BTreeMap<String, Option<Vec<u8>>> = a_tree()
        .into_iter()
        .map(|(path, what)| (path.to_string(), what))
        .collect();
    assert_eq!(found, want);
}

/// A compressed archive whose compression has no decoder yet: **the tree
/// itself is compressed**, so it is not read, and the reader says which
/// compression it needs by name rather than guessing at bytes.
///
/// This is the shape a Windows disc's `install.wim` has, which is LZX.
/// What such an archive still tells without a decoder is checked here too,
/// because it is all it tells: the compression, the chunk size, how many
/// resources there are and how long each is, and the names of its images
/// from the XML.
#[test]
fn a_compressed_archive_says_which_compression_the_tree_needs() {
    let Some(tool) = wimlib() else { return };
    let s = Scratch::new("compressed");
    for (how, compression, chunk, needs) in [
        // XPRESS is decoded: `an_xpress_archive_reads_as_the_tree_that_went_in`.
        ("--compress=LZX", Compression::Lzx, 32_768, Unsupported::Lzx),
        (
            "--compress=LZMS",
            Compression::Lzms,
            131_072,
            Unsupported::Lzms,
        ),
        // Solid blocks are LZMS, and the tree is compressed on its own
        // before any solid block is reached: LZMS is what it needs first.
        ("--solid", Compression::Lzms, 131_072, Unsupported::Lzms),
    ] {
        let bytes = captured(&s, &tool, how);

        // The container reads: the table of resources is not compressed,
        // even where everything it names is.
        let mut wim = Wim::open(std::io::Cursor::new(bytes))
            .unwrap_or_else(|e| panic!("{how}: opening failed: {e:?}"));
        assert_eq!(wim.compression(), compression, "{how}");
        assert_eq!(wim.chunk_size(), chunk, "{how}");
        assert_eq!(wim.images().len(), 1, "{how}");
        assert_eq!(wim.images()[0].name.as_deref(), Some("probe"), "{how}");
        assert!(
            wim.resources() >= a_tree().len() - 2,
            "{how}: the resources"
        );

        // The tree does not: it is a resource like any other, and a
        // compressed archive compresses it.
        let tree = wim.entries(1);
        assert!(
            matches!(tree.as_ref().err(), Some(Error::Needs(what)) if *what == needs),
            "{how}: wanted {needs:?}, got {:?}",
            tree.err()
        );
    }
}
