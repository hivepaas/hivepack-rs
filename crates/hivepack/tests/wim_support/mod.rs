//! Writing WIM archives with `wimlib-imagex`, which is the only oracle
//! for a **compressed** one: the tool, the tree that goes into every
//! archive these tests read, and the archive itself.
//!
//! wimlib is GPL-3.0-or-later. It is built by `scripts/testdata.py` and
//! run as a program, and nothing in this repository is read from it: the
//! formats are implemented from Microsoft's own specifications.
//!
//! Used by `tests/wim_wimlib.rs` (reading) and `tests/extract_wim.rs`
//! (extracting), so that both hold the same archive to the same tree.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where `scripts/testdata.py` puts what it fetches and builds.
pub fn cache() -> PathBuf {
    std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/testdata"))
}

/// `wimlib-imagex`, as `scripts/testdata.py` builds it. CI lists the
/// `generated` group in `HIVEPACK_TESTDATA_REQUIRED` where it builds it,
/// and then a missing one fails rather than being passed over.
pub fn wimlib() -> Option<PathBuf> {
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
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(what: &str) -> Scratch {
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
pub fn pattern(len: usize, seed: u64) -> Vec<u8> {
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
pub fn a_tree() -> BTreeMap<&'static str, Option<Vec<u8>>> {
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
pub fn mixed() -> Vec<u8> {
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
pub fn captured(s: &Scratch, tool: &Path, how: &[&str]) -> Vec<u8> {
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
    captured_from(tool, &tree, &archive, how)
}

/// An archive of the tree at `tree`, written to `archive` and read back:
/// for a test with a tree of its own, where [`captured`]'s is the one
/// every reading test holds its archives to.
pub fn captured_from(tool: &Path, tree: &Path, archive: &Path, how: &[&str]) -> Vec<u8> {
    let _ = std::fs::remove_file(archive);
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
    std::fs::read(archive).unwrap()
}

/// [`a_tree`] with the paths as a read gives them.
pub fn want() -> BTreeMap<String, Option<Vec<u8>>> {
    a_tree()
        .into_iter()
        .map(|(path, what)| (path.to_string(), what))
        .collect()
}

/// A tree with the two things a Unix file system has that a WIM keeps
/// differently: a file under two names, which becomes a set of names over
/// one resource, and a symbolic link, which becomes a **reparse point**
/// with two stream entries beside its own.
pub fn a_tree_with_links(at: &Path) {
    std::fs::create_dir_all(at.join("sub")).unwrap();
    std::fs::write(at.join("one.txt"), b"shared bytes\n").unwrap();
    std::fs::hard_link(at.join("one.txt"), at.join("two.txt")).unwrap();
    std::fs::write(at.join("sub/note.txt"), b"deeper\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("one.txt", at.join("link.txt")).unwrap();
}
