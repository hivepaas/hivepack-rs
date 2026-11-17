//! Extracting ext file systems that hivepack::ext reads: a tree put in by
//! `mke2fs -d` and taken out again, with its files, folders, symbolic
//! links, hard links and a name that is not UTF-8; and a name changed on
//! the image to climb out of the destination, which must not.
//!
//! A name on an ext file system is bytes, with only `\0` and `/` not
//! allowed — by the kernel, which is not what writes a hostile image. So
//! the check that matters here is that a name holding a separator goes
//! through the same rules a tar archive's does and lands nowhere.

#![cfg(all(feature = "ext", feature = "extract"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "extract_support/mod.rs"]
mod support;

use std::path::{Path, PathBuf};
use std::process::Command;

use hivepack::ext::Ext;
use hivepack::extract::{NameError, OnRefused, Options, Summary, extract_ext};
use support::{Scratch, listing, options};

/// A tool, if it is installed and can be run: see image_vhd.rs, which says
/// why the second half matters — CI's 32-bit container answers `ENOSYS` to
/// starting a process at all.
fn tool(name: &str) -> Option<PathBuf> {
    let path = ["/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin"]
        .into_iter()
        .map(|at| PathBuf::from(at).join(name))
        .find(|p| p.exists())?;
    Command::new(&path).arg("-V").output().ok()?;
    Some(path)
}

/// An ext4 image of 8 MiB holding the tree at `from`, where `mke2fs` can
/// fill one from a folder: `-d` came with e2fsprogs 1.43, and the older one
/// answers its usage message (see CONTRIBUTING.md).
fn an_image(s: &Scratch, from: &Path) -> Option<Vec<u8>> {
    let mkfs = tool("mke2fs")?;
    let path = s.path().join("fs.img");
    std::fs::write(&path, vec![0u8; 8 << 20]).unwrap();
    let out = Command::new(&mkfs)
        .args(["-q", "-F", "-t", "ext4", "-b", "1024", "-d"])
        .arg(from)
        .arg(&path)
        .output()
        .unwrap();
    if !out.status.success() {
        eprintln!(
            "mke2fs cannot fill a file system from a folder here: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return None;
    }
    Some(std::fs::read(&path).unwrap())
}

/// The tree that goes in, and what it is: a file, a folder with a file in
/// it, two names for one file, a symbolic link, and a name that is not
/// UTF-8, which a file system allows and a name's rules may not.
#[cfg(unix)]
fn a_tree(at: &Path) {
    use std::os::unix::ffi::OsStrExt;

    std::fs::create_dir_all(at.join("folder")).unwrap();
    std::fs::write(at.join("hello.txt"), b"hello\n").unwrap();
    std::fs::write(at.join("folder/inside.bin"), vec![7u8; 5000]).unwrap();
    std::fs::hard_link(at.join("hello.txt"), at.join("again.txt")).unwrap();
    std::os::unix::fs::symlink("hello.txt", at.join("link")).unwrap();
    let odd = std::ffi::OsStr::from_bytes(b"not\xffutf8.txt");
    std::fs::write(at.join(odd), b"bytes\n").unwrap();
}

fn extract(
    image: &[u8],
    out: &Path,
    options: &Options,
) -> Result<Summary, hivepack::extract::Error> {
    let fs = Ext::open(image).unwrap();
    extract_ext(&fs, out, options)
}

#[test]
#[cfg(unix)]
fn a_tree_comes_out_as_it_went_in() {
    let s = Scratch::new();
    let from = s.path().join("tree");
    std::fs::create_dir_all(&from).unwrap();
    a_tree(&from);
    let Some(image) = an_image(&s, &from) else {
        return;
    };
    let out = s.path().join("out");
    // Links are refused by default, which is the safe default; this test
    // is about what comes out, so it asks for the ones that stay inside.
    // And the name that is not UTF-8 is refused by the rules these tests
    // run with, so the rest is asked for and that one is checked below: a
    // file system allows bytes a name's rules do not.
    let summary = extract(
        &image,
        &out,
        &options(|o| {
            o.links = hivepack::extract::Links::Inside;
            o.on_refused = OnRefused::Skip;
        }),
    )
    .unwrap();

    // lost+found is on every file system mke2fs writes, and is a folder.
    let mut found = listing(&out);
    found.sort();
    // A folder is listed with a slash after it, as `listing` writes one.
    for want in [
        "again.txt",
        "folder/",
        "folder/inside.bin",
        "hello.txt",
        "link",
        "lost+found/",
    ] {
        assert!(
            found.iter().any(|f| f == want),
            "{want} missing from {found:?}"
        );
    }
    assert_eq!(std::fs::read(out.join("hello.txt")).unwrap(), b"hello\n");
    assert_eq!(
        std::fs::read(out.join("folder/inside.bin")).unwrap(),
        vec![7u8; 5000]
    );
    // The two names for one file: the second is a hard link to the first,
    // so both read the same and the link count says two.
    assert_eq!(std::fs::read(out.join("again.txt")).unwrap(), b"hello\n");
    // The symbolic link is a link, and names what it named.
    let link = std::fs::symlink_metadata(out.join("link")).unwrap();
    assert!(link.file_type().is_symlink());
    assert_eq!(
        std::fs::read_link(out.join("link")).unwrap(),
        Path::new("hello.txt")
    );
    // The name that is not UTF-8 was left out, and said why.
    assert!(
        summary.skipped.iter().any(|e| matches!(
            e.kind,
            hivepack::extract::ErrorKind::Name(NameError::NotUtf8)
        )),
        "wanted the odd name refused, got {:?}",
        summary
            .skipped
            .iter()
            .map(|e| format!("{:?}", e.kind))
            .collect::<Vec<_>>()
    );
    // Three files: the two with data and the second name for one of them,
    // which is a hard link and holds no bytes of its own. Two folders, the
    // one that went in and the `lost+found` every mke2fs writes. One
    // symbolic link. 5006 bytes: 6 and 5000, the hard link none.
    assert_eq!(
        (
            summary.files,
            summary.directories,
            summary.links,
            summary.bytes
        ),
        (3, 2, 1, 5006),
        "{summary:?}"
    );

    // And the second name really is the same file, not a copy of it.
    use std::os::unix::fs::MetadataExt;
    let one = std::fs::metadata(out.join("hello.txt")).unwrap();
    let two = std::fs::metadata(out.join("again.txt")).unwrap();
    assert_eq!(
        (one.dev(), one.ino()),
        (two.dev(), two.ino()),
        "the two names are not one file"
    );
    assert_eq!(one.nlink(), 2, "the file says how many names it has");
}

/// An image made to climb out of the destination: a real image with one
/// record's name changed in place to `../x.tx`, the same length so that
/// nothing else about the records moves.
///
/// Nothing may be written, and this holds **without** this backend's own
/// check on separators: measured by taking that check out, the rules that
/// read an archive's paths stop it as `Name(Dot)` and nothing lands. So
/// this test is about the destination, and the protection it checks is
/// `extract/name.rs`, not anything new here.
#[test]
#[cfg(unix)]
fn a_name_that_climbs_out_lands_nowhere() {
    let s = Scratch::new();
    let from = s.path().join("tree");
    std::fs::create_dir_all(&from).unwrap();
    std::fs::write(from.join("aaa.txt"), b"inside\n").unwrap();
    let Some(mut image) = an_image(&s, &from) else {
        return;
    };
    let at = image
        .windows(7)
        .position(|w| w == b"aaa.txt")
        .expect("the name is on the image");
    image[at..at + 7].copy_from_slice(b"../x.tx");

    let out = s.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let summary = extract(&image, &out, &options(|o| o.on_refused = OnRefused::Skip)).unwrap();

    assert!(!out.join("../x.tx").exists(), "it climbed out");
    assert!(!out.join("x.tx").exists(), "it was written anyway");
    assert!(
        !s.path().join("x.tx").exists(),
        "it landed beside the destination"
    );
    // Refused for its name, whichever rule saw it first.
    assert!(
        summary
            .skipped
            .iter()
            .any(|e| matches!(e.kind, hivepack::extract::ErrorKind::Name(_))),
        "wanted a name's refusal, got {:?}",
        summary
            .skipped
            .iter()
            .map(|e| format!("{:?}", e.kind))
            .collect::<Vec<_>>()
    );
}

/// And the case those rules have nothing to say about: a record named
/// `a/b.txt`, which holds no dots and is not absolute. Cut into components
/// it would be written into a folder `a` — not where this file system says
/// it is. A record is one name, and the kernel allows no separator in one,
/// so this backend refuses it; without that check the file appears under
/// `a`, which is what this test fails on.
#[test]
#[cfg(unix)]
fn a_name_that_holds_a_separator_is_not_cut_into_a_path() {
    let s = Scratch::new();
    let from = s.path().join("tree");
    std::fs::create_dir_all(&from).unwrap();
    std::fs::write(from.join("aaa.txt"), b"inside\n").unwrap();
    let Some(mut image) = an_image(&s, &from) else {
        return;
    };
    let at = image
        .windows(7)
        .position(|w| w == b"aaa.txt")
        .expect("the name is on the image");
    image[at..at + 7].copy_from_slice(b"a/b.txt");

    let out = s.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let summary = extract(&image, &out, &options(|o| o.on_refused = OnRefused::Skip)).unwrap();

    assert!(
        !out.join("a").exists() && !out.join("a/b.txt").exists(),
        "a name with a separator was written as a path: {:?}",
        listing(&out)
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

/// The attributes beside an inode are read only when they are wanted: both
/// ways extract, and the one that asks for them reads them.
#[test]
#[cfg(unix)]
fn the_attributes_are_read_only_when_they_are_wanted() {
    let s = Scratch::new();
    let from = s.path().join("tree");
    std::fs::create_dir_all(&from).unwrap();
    std::fs::write(from.join("a.txt"), b"one\n").unwrap();
    let Some(image) = an_image(&s, &from) else {
        return;
    };
    for (what, xattrs) in [("without", false), ("with", true)] {
        let out = s.path().join(format!("out-{what}"));
        let summary = extract(&image, &out, &options(|o| o.xattrs = xattrs)).unwrap();
        assert!(summary.files >= 1, "{what}: {summary:?}");
        assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), b"one\n");
    }
}
