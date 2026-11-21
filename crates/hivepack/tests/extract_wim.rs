//! Extracting one image of a WIM archive that `hivepack::wim` reads, out of
//! archives `wimlib-imagex` wrote.
//!
//! What is checked: the tree coming out as it went in, for every
//! compression that is decoded; the names an image says share one file
//! coming out as one file with two names; a symbolic link, which a WIM
//! holds as a **reparse point**, refused rather than made into something
//! else; a file whose bytes were changed after the archive was written not
//! coming out at all, since the SHA-1 the image names it by is the only
//! check the format gives; and an image that is not there being an error.
//!
//! The same tree as `tests/wim_wimlib.rs` reads back (`tests/wim_support`),
//! so that what comes out of the archive is held against what went into it.
//!
//! wimlib is GPL-3.0-or-later, built by `scripts/testdata.py` and run as a
//! program: nothing here is read from it.
//!
//! See crates/hivepack/src/extract/wim.rs and docs/extract.md.

#![cfg(all(feature = "wim", feature = "extract"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "wim_support/mod.rs"]
mod build;
#[path = "extract_support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use hivepack::extract::{
    Entry as Given, ErrorKind, OnRefused, Sink, Summary, extract_wim, extract_wim_to,
};
use hivepack::wim::Wim;

use build::{a_tree_with_links, captured, captured_from, want, wimlib};
use support::{Scratch, options};

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

/// The archives wimlib wrote come out as the tree that went into them:
/// uncompressed, XPRESS and LZX, which is what a Windows disc's
/// `install.wim` holds.
#[test]
fn an_archive_wimlib_wrote_comes_out_as_the_tree_that_went_in() {
    let Some(tool) = wimlib() else { return };
    let s = build::Scratch::new("extract");
    for how in [
        &["--compress=none"][..],
        &["--compress=XPRESS"][..],
        &["--compress=LZX"][..],
    ] {
        let bytes = captured(&s, &tool, how);
        let out = Scratch::new();
        let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
        let summary = extract_wim(&mut wim, 1, &out.out(), &options(|_| {})).unwrap();
        assert_eq!(what_came_out(&out.out()), want(), "{how:?}");
        assert_eq!(summary.skipped.len(), 0, "{how:?}: {:?}", kinds(&summary));
        // The one folder of the tree, and the eight files in it.
        assert_eq!(summary.directories, 1, "{how:?}");
        assert_eq!(summary.files, 8, "{how:?}");
    }
}

/// The names an image says share one file come out as **one file with two
/// names**, not as the file written twice. A Windows image is full of them
/// — the same payload under a dozen names in `WinSxS` — so without this an
/// image of an installation would come out many times its own size.
#[test]
#[cfg(unix)]
fn the_names_that_share_one_file_come_out_as_one_file() {
    use std::os::unix::fs::MetadataExt;

    let Some(tool) = wimlib() else { return };
    let s = build::Scratch::new("links");
    let tree = s.0.join("tree");
    a_tree_with_links(&tree);
    let bytes = captured_from(&tool, &tree, &s.0.join("links.wim"), &["--compress=LZX"]);

    let out = Scratch::new();
    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    // The symbolic link is a reparse point, which is refused: left out
    // here, so that what this test is about is what it says.
    let summary = extract_wim(
        &mut wim,
        1,
        &out.out(),
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();

    let one = out.out().join("one.txt");
    let two = out.out().join("two.txt");
    assert_eq!(std::fs::read(&one).unwrap(), b"shared bytes\n");
    assert_eq!(std::fs::read(&two).unwrap(), b"shared bytes\n");
    let (first, second) = (
        std::fs::metadata(&one).unwrap(),
        std::fs::metadata(&two).unwrap(),
    );
    assert_eq!(first.ino(), second.ino(), "two names, one file");
    assert_eq!(first.nlink(), 2);
    // Both names count as files, and the bytes are written once.
    assert_eq!(summary.files, 3);
    assert_eq!(summary.bytes, b"shared bytes\n".len() as u64 + 7);
}

/// A symbolic link is a **reparse point** in a WIM, and what it stands for
/// is in reparse data this does not read: it is refused rather than made
/// into a link pointing at nothing or a file holding the reparse data.
#[test]
#[cfg(unix)]
fn a_symbolic_link_is_a_reparse_point_and_is_refused() {
    let Some(tool) = wimlib() else { return };
    let s = build::Scratch::new("reparse");
    let tree = s.0.join("tree");
    a_tree_with_links(&tree);
    let bytes = captured_from(&tool, &tree, &s.0.join("reparse.wim"), &["--compress=none"]);

    // Left out, and said: everything else comes out.
    let out = Scratch::new();
    let mut wim = Wim::open(std::io::Cursor::new(bytes.clone())).unwrap();
    let summary = extract_wim(
        &mut wim,
        1,
        &out.out(),
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();
    assert!(!out.out().join("link.txt").exists());
    assert!(out.out().join("one.txt").exists());
    let said = kinds(&summary);
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(said[0].contains("Reparse"), "{said:?}");

    // Or the whole extraction stops, which is what `OnRefused::Stop` is.
    let out = Scratch::new();
    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    let stopped = extract_wim(
        &mut wim,
        1,
        &out.out(),
        &options(|o| o.on_refused = OnRefused::Stop),
    );
    let error = stopped.expect_err("a reparse point stops it");
    assert!(matches!(error.kind, ErrorKind::Wim(_)), "{:?}", error.kind);
}

/// A file whose bytes were changed after the archive was written does not
/// come out. The SHA-1 the image names a file by is the only check a WIM
/// gives, and what fails it is removed rather than left on the disk — as a
/// ZIP archive's file that fails its CRC is.
#[test]
fn a_file_whose_bytes_were_changed_does_not_come_out() {
    let Some(tool) = wimlib() else { return };
    let s = build::Scratch::new("damaged");
    let mut bytes = captured(&s, &tool, &["--compress=none"]);
    let said = b"hello from a wim\n";
    let at = bytes
        .windows(said.len())
        .position(|at| at == said)
        .expect("the file's bytes are in the archive as themselves");
    bytes[at] ^= 0x20;

    let out = Scratch::new();
    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    let error = extract_wim(&mut wim, 1, &out.out(), &options(|_| {}))
        .expect_err("a file that fails its hash stops the extraction");
    assert!(
        matches!(error.kind, ErrorKind::Wim(hivepack::wim::Error::Hash)),
        "{:?}",
        error.kind
    );
    assert!(
        !out.out().join("readme.txt").exists(),
        "what failed its hash was left behind"
    );
}

/// An image that is not in the archive is an error, and no folder is made
/// for it.
#[test]
fn an_image_that_is_not_there_is_an_error() {
    let Some(tool) = wimlib() else { return };
    let s = build::Scratch::new("image");
    let bytes = captured(&s, &tool, &["--compress=none"]);
    let out = Scratch::new();
    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    let error = extract_wim(&mut wim, 7, &out.out(), &options(|_| {}))
        .expect_err("there is no seventh image");
    assert!(
        matches!(
            error.kind,
            ErrorKind::Wim(hivepack::wim::Error::NoSuchImage { index: 7 })
        ),
        "{:?}",
        error.kind
    );
    assert!(!out.out().exists());
}

/// A sink is given what the folder would get, in the same order: the
/// folders, the files with their bytes, and the second name of a shared
/// file as a hard link rather than as the bytes again.
#[derive(Default)]
struct Recorder {
    folders: Vec<String>,
    written: Vec<(String, u64)>,
    links: Vec<(String, String)>,
    at: u64,
}

impl Sink for Recorder {
    fn directory(&mut self, entry: &Given<'_>) -> io::Result<()> {
        self.folders.push(entry.path.join("/"));
        Ok(())
    }

    fn start_file(&mut self, entry: &Given<'_>) -> io::Result<()> {
        self.written.push((entry.path.join("/"), 0));
        self.at = 0;
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.at += data.len() as u64;
        Ok(())
    }

    fn finish_file(&mut self) -> io::Result<()> {
        if let Some(last) = self.written.last_mut() {
            last.1 = self.at;
        }
        Ok(())
    }

    fn discard_file(&mut self) {
        self.written.pop();
    }

    fn symlink(&mut self, _entry: &Given<'_>, _target: &str) -> io::Result<()> {
        unreachable!("a reparse point is refused, so no link is given")
    }

    fn hard_link(&mut self, entry: &Given<'_>, target: &[String]) -> io::Result<()> {
        self.links.push((entry.path.join("/"), target.join("/")));
        Ok(())
    }
}

#[test]
#[cfg(unix)]
fn a_sink_is_given_what_the_folder_would_get() {
    let Some(tool) = wimlib() else { return };
    let s = build::Scratch::new("sink");
    let tree = s.0.join("tree");
    a_tree_with_links(&tree);
    let bytes = captured_from(&tool, &tree, &s.0.join("sink.wim"), &["--compress=XPRESS"]);

    let mut wim = Wim::open(std::io::Cursor::new(bytes)).unwrap();
    let mut recorder = Recorder::default();
    let summary = extract_wim_to(
        &mut wim,
        1,
        &mut recorder,
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();

    assert_eq!(recorder.folders, ["sub"]);
    assert_eq!(
        recorder.written,
        [("one.txt".to_owned(), 13), ("sub/note.txt".to_owned(), 7)]
    );
    assert_eq!(
        recorder.links,
        [("two.txt".to_owned(), "one.txt".to_owned())]
    );
    assert_eq!(summary.directories, 1);
    assert_eq!(summary.files, 3);
}
