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
        (
            "docs/over and over again.txt",
            Some(b"the quick brown fox jumps over the lazy dog\n".repeat(3000)),
        ),
        // Nothing but `E8` x86 calls, each with a displacement small
        // enough to be a target inside a file, which is what LZX's call
        // translation ([MS-PATCH] §2.2.2) rewrites. An LZX archive really
        // holds them rewritten, so reading this file back as it went in
        // is what says the translation is undone — and the same file in
        // an XPRESS archive says that compression does not translate.
        ("calls.bin", Some(b"\xe8\x00\x01\x00\x00".repeat(2000))),
        // A chunk that compresses followed by one that does not, so that
        // a compressed resource holds a **stored** chunk beside a
        // compressed one.
        ("mixed.bin", Some(mixed())),
        ("empty.bin", Some(Vec::new())),
        ("noise.bin", Some(pattern(60_000, 11))),
    ])
}

/// 32768 bytes of text that compresses, and then 32768 that do not, with
/// an `E8` x86 call every 500 bytes of them: what a compressor stores as
/// it is rather than compressing. The bytes a stored chunk holds are the
/// file's own, with no call translation done to them, which is what
/// reading this file back out of an LZX archive says.
fn mixed() -> Vec<u8> {
    let mut bytes = b"the quick brown fox jumps over the lazy dog\n".repeat(745);
    bytes.truncate(32_768);
    let mut noise = pattern(32_768, 99);
    for at in (100..32_700).step_by(500) {
        noise[at..at + 5].copy_from_slice(&[0xE8, 0x00, 0x01, 0x00, 0x00]);
    }
    bytes.extend_from_slice(&noise);
    bytes
}

/// An archive of [`a_tree`] that wimlib wrote with `how`, and its bytes.
/// `how` is the arguments that say how to compress it: `--compress=LZX`,
/// `--solid` on its own, a `--chunk-size` beside either.
fn captured(s: &Scratch, tool: &Path, how: &[&str]) -> Vec<u8> {
    let named = how.join("-").replace("--", "");
    // One tree for every archive of one test, so that two archives of it
    // differ only in how they are compressed: the files are the same
    // files, with the same times, so an image's metadata is the same
    // bytes and what is read out of one can be held against the other.
    let tree = s.0.join("tree");
    // Written once, not again for each archive: writing a file over again
    // gives it new times, and the times are in the metadata resource that
    // these archives are read against each other to check.
    if !tree.exists() {
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
    }
    let archive = s.0.join(format!("{named}.wim"));
    let _ = std::fs::remove_file(&archive);
    let out = Command::new(tool)
        .args([
            "capture",
            tree.to_str().unwrap(),
            archive.to_str().unwrap(),
            "probe",
            "--norpfix",
        ])
        .args(how)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "wimlib-imagex capture {how:?} failed: {}",
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
    let bytes = captured(&s, &tool, &["--compress=none"]);

    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    assert_eq!(wim.compression(), Compression::None);
    assert_eq!(wim.images().len(), 1);
    assert_eq!(wim.images()[0].name.as_deref(), Some("probe"));

    assert_eq!(read(&mut wim), want());
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
    let bytes = captured(&s, &tool, &["--compress=XPRESS"]);

    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    assert_eq!(wim.compression(), Compression::Xpress);
    assert_eq!(wim.chunk_size(), 32_768);

    assert_eq!(read(&mut wim), want());
}

/// Everything in `wim`'s first image, as [`a_tree`] holds it: a path for
/// each entry, with its bytes where it is a file.
fn read(wim: &mut Wim<std::io::Cursor<Vec<u8>>>) -> BTreeMap<String, Option<Vec<u8>>> {
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

/// Every field of every entry of `wim`'s first image, which is what an
/// image's metadata holds: the names, the times, the attributes, the
/// hashes and what is a hard link of what. Two archives of one tree give
/// the same lines, so this is how far a **compressed metadata resource**
/// is read -- field by field, and not only as far as the paths.
///
/// All but the time a file was last **read**, which is the one thing that
/// moves on its own: writing the second archive of a tree reads the tree
/// again, and that is a read.
fn described(wim: &mut Wim<std::io::Cursor<Vec<u8>>>) -> Vec<String> {
    let entries = wim.entries(1).unwrap();
    entries
        .iter()
        .map(|e| {
            format!(
                "{} {} {:?} {} {:?} {:?} {:?} {:?} {:#x} {:?} {:?} {}",
                e.path,
                e.name,
                e.short_name,
                e.size,
                e.hash,
                e.created,
                e.modified,
                e.unix_mode,
                e.attributes,
                e.reparse_tag,
                e.hard_link_group,
                e.extra_streams,
            )
        })
        .collect()
}

/// [`a_tree`] with the paths as a read gives them.
fn want() -> BTreeMap<String, Option<Vec<u8>>> {
    a_tree()
        .into_iter()
        .map(|(path, what)| (path.to_string(), what))
        .collect()
}

/// Archives wimlib wrote with LZX: the tree **and** every file come back
/// as they went in, over the three chunk sizes that read differently.
///
/// LZX is what a Windows disc's `install.wim` holds. These archives hold
/// what says the format is read rather than one shape of it: a file over
/// five chunks, one that does not compress at all, one whose first chunk
/// compresses and whose second is stored, an image's metadata, which is an
/// **aligned offset block** where the files are verbatim ones, and a file
/// of nothing but `E8` x86 calls, whose translation LZX undoes and the
/// other compressions do not.
///
/// The chunk size decides three things at once, so each one is read: how
/// wide the Block Size field is (16 bits up to 32768 and 24 above it), how
/// many position slots the window has (30, 32, 34), and whether a chunk
/// holds more than one block — wimlib ends a block every 100000 bytes, so
/// the 131072 chunks are the ones that hold two, each with its own trees
/// written as the difference from the trees of the block before.
#[test]
fn an_lzx_archive_reads_as_the_tree_that_went_in() {
    let Some(tool) = wimlib() else { return };
    let s = Scratch::new("lzx");
    // The same tree with nothing compressed, to hold the others against:
    // its metadata resource is the bytes theirs decompress to.
    let plain = captured(&s, &tool, &["--compress=none"]);
    let mut plain = Wim::open(std::io::Cursor::new(plain)).unwrap();
    let described_plain = described(&mut plain);

    for chunk in [32_768u32, 65_536, 131_072] {
        let size = format!("--chunk-size={chunk}");
        let bytes = captured(&s, &tool, &["--compress=LZX", &size]);

        let mut wim = Wim::open(std::io::Cursor::new(bytes))
            .unwrap_or_else(|e| panic!("{chunk}: opening failed: {e:?}"));
        assert_eq!(wim.compression(), Compression::Lzx, "{chunk}");
        assert_eq!(wim.chunk_size(), chunk, "{chunk}");
        assert_eq!(read(&mut wim), want(), "{chunk}");
        // The tree itself, field by field: the metadata resource is
        // compressed too, and this is what says it came back whole.
        assert_eq!(described(&mut wim), described_plain, "{chunk}");
    }
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
        // XPRESS and LZX are decoded, each with a test of its own above.
        (
            &["--compress=LZMS"][..],
            Compression::Lzms,
            131_072,
            Unsupported::Lzms,
        ),
        // Solid blocks are LZMS, and the tree is compressed on its own
        // before any solid block is reached: LZMS is what it needs first.
        (
            &["--solid"][..],
            Compression::Lzms,
            131_072,
            Unsupported::Lzms,
        ),
    ] {
        let bytes = captured(&s, &tool, how);

        // The container reads: the table of resources is not compressed,
        // even where everything it names is.
        let mut wim = Wim::open(std::io::Cursor::new(bytes))
            .unwrap_or_else(|e| panic!("{how:?}: opening failed: {e:?}"));
        assert_eq!(wim.compression(), compression, "{how:?}");
        assert_eq!(wim.chunk_size(), chunk, "{how:?}");
        assert_eq!(wim.images().len(), 1, "{how:?}");
        assert_eq!(wim.images()[0].name.as_deref(), Some("probe"), "{how:?}");
        assert!(
            wim.resources() >= a_tree().len() - 2,
            "{how:?}: the resources"
        );

        // The tree does not: it is a resource like any other, and a
        // compressed archive compresses it.
        let tree = wim.entries(1);
        assert!(
            matches!(tree.as_ref().err(), Some(Error::Needs(what)) if *what == needs),
            "{how:?}: wanted {needs:?}, got {:?}",
            tree.err()
        );
    }
}
