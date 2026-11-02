//! Extracting cpio archives made to attack extractors, as `tests/tar.rs`
//! does for tar: names that climb out, the same path twice, symbolic and
//! hard links, devices, the limits, archives cut short or without their
//! trailer, garbage passed over, and an archive that changes between its
//! two readings. Each must stop with its reason and leave nothing outside
//! the destination, and nothing at all when the checks before writing stop
//! it. Hard links come as GNU cpio and RPM write them in newc, the data on
//! the last, and as odc has them, the data on each. Then libarchive's test
//! archives, each extracted or stopped with its reason.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "extract_support/mod.rs"]
mod support;

use std::cell::Cell;
use std::io::Cursor;
use std::path::Path;

use hivepack::extract::{
    ErrorKind, Limits, Links, NameError, OnRefused, Options, Summary, extract_cpio,
};
use support::{Scratch, listing, options};

/// What an entry of a test archive is.
#[derive(Clone, Copy)]
enum What<'a> {
    Dir,
    File(&'a [u8]),
    Symlink(&'a [u8]),
    /// A character device.
    Device,
}

/// An entry: its name, what it is, its inode and number of links (hard
/// links share an inode).
#[derive(Clone, Copy)]
struct E<'a> {
    name: &'a [u8],
    what: What<'a>,
    ino: u32,
    nlink: u32,
}

fn entry<'a>(name: &'a str, what: What<'a>) -> E<'a> {
    E {
        name: name.as_bytes(),
        what,
        ino: 0,
        nlink: 1,
    }
}

/// A second name for the file of inode `ino`, of `nlink` names.
fn link<'a>(name: &'a str, data: &'a [u8], ino: u32, nlink: u32) -> E<'a> {
    E {
        name: name.as_bytes(),
        what: What::File(data),
        ino,
        nlink,
    }
}

/// An entry's mode and data.
fn mode_and_data<'a>(what: What<'a>) -> (u32, &'a [u8]) {
    match what {
        What::Dir => (0o040755, b""),
        What::File(data) => (0o100640, data),
        What::Symlink(target) => (0o120777, target),
        What::Device => (0o020644, b""),
    }
}

/// A newc archive (`070701`) of `entries`, each inode its own unless
/// given, dated 2020-09-13 (1,600,000,000), then `TRAILER!!!`.
fn newc(entries: &[E<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut put = |name: &[u8], mode: u32, data: &[u8], ino: u32, nlink: u32| {
        let fields = [
            ino,
            mode,
            0,
            0,
            nlink,
            1_600_000_000,
            data.len() as u32,
            8,
            1,
            1,
            3,
            name.len() as u32 + 1,
            0,
        ];
        out.extend(b"070701");
        for field in fields {
            out.extend(format!("{field:08x}").as_bytes());
        }
        out.extend(name);
        out.push(0);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend(data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    };
    for (i, entry) in entries.iter().enumerate() {
        let (mode, data) = mode_and_data(entry.what);
        let ino = if entry.ino == 0 {
            1000 + i as u32
        } else {
            entry.ino
        };
        put(entry.name, mode, data, ino, entry.nlink);
    }
    put(b"TRAILER!!!", 0, b"", 0, 1);
    out
}

/// The same as odc (`070707`, POSIX.1), which pads nothing.
fn odc(entries: &[E<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut put = |name: &[u8], mode: u32, data: &[u8], ino: u32, nlink: u32| {
        out.extend(b"070707");
        for (value, width) in [
            (8, 6),
            (u64::from(ino), 6),
            (u64::from(mode), 6),
            (0, 6),
            (0, 6),
            (u64::from(nlink), 6),
            (0o401, 6),
            (1_600_000_000, 11),
            (name.len() as u64 + 1, 6),
            (data.len() as u64, 11),
        ] {
            out.extend(format!("{value:0width$o}").as_bytes());
        }
        out.extend(name);
        out.push(0);
        out.extend(data);
    };
    for (i, entry) in entries.iter().enumerate() {
        let (mode, data) = mode_and_data(entry.what);
        let ino = if entry.ino == 0 {
            1000 + i as u32
        } else {
            entry.ino
        };
        put(entry.name, mode, data, ino, entry.nlink);
    }
    put(b"TRAILER!!!", 0, b"", 0, 1);
    out
}

fn extract(
    data: &[u8],
    out: &Path,
    options: &Options,
) -> Result<Summary, hivepack::extract::Error> {
    extract_cpio(|| Ok(Cursor::new(data.to_vec())), out, options)
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

#[test]
fn extracts_directories_and_files() {
    let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    for archive in [
        newc(&[
            entry(".", What::Dir),
            entry("./docs", What::Dir),
            entry("./docs/résumé, long name.txt", What::File(b"hello\n")),
            entry("./deep/er/est.bin", What::File(&big)),
            entry("./empty", What::File(b"")),
        ]),
        odc(&[
            entry(".", What::Dir),
            entry("./docs", What::Dir),
            entry("./docs/résumé, long name.txt", What::File(b"hello\n")),
            entry("./deep/er/est.bin", What::File(&big)),
            entry("./empty", What::File(b"")),
        ]),
    ] {
        let scratch = Scratch::new();
        let summary = extract(&archive, &scratch.out(), &Options::default()).unwrap();
        assert_eq!((summary.files, summary.directories), (3, 1));
        assert_eq!(
            listing(&scratch.out()),
            [
                "deep/",
                "deep/er/",
                "deep/er/est.bin",
                "docs/",
                "docs/résumé, long name.txt",
                "empty"
            ]
        );
        assert_eq!(read(&scratch.out().join("deep/er/est.bin")), big);
        let modified = std::fs::metadata(scratch.out().join("empty"))
            .unwrap()
            .modified()
            .unwrap();
        let secs = modified
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(secs, 1_600_000_000);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(scratch.out().join("empty"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o640);
        }
    }
}

/// Whether two paths are one file: the same inode on Unix; elsewhere,
/// where hard links are made too, the same data is all that is checked.
fn same_file(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let (a, b) = (std::fs::metadata(a).unwrap(), std::fs::metadata(b).unwrap());
        a.ino() == b.ino() && a.dev() == b.dev()
    }
    #[cfg(not(unix))]
    {
        read(a) == read(b)
    }
}

/// GNU cpio and RPM write a file's names in newc with the data on the last
/// and the others empty; odc has it on each. Either way, every name holds
/// it, and is the same file.
#[test]
fn hard_links_hold_the_data_of_the_last_with_data() {
    let data = b"shared by three names".repeat(1000);
    let cases = [
        (
            "newc, data on the last",
            newc(&[
                link("a", b"", 7, 3),
                entry("other", What::File(b"x")),
                link("dir/b", b"", 7, 3),
                link("c", &data, 7, 3),
            ]),
        ),
        (
            "odc, data on each",
            odc(&[
                link("a", &data, 7, 3),
                entry("other", What::File(b"x")),
                link("dir/b", &data, 7, 3),
                link("c", &data, 7, 3),
            ]),
        ),
        (
            "newc, data on the first",
            newc(&[
                link("a", &data, 7, 3),
                entry("other", What::File(b"x")),
                link("dir/b", b"", 7, 3),
                link("c", b"", 7, 3),
            ]),
        ),
        (
            // As libarchive's extraction leaves it: the last data written.
            "newc, other data on the last",
            newc(&[
                link("a", b"not this", 7, 3),
                entry("other", What::File(b"x")),
                link("dir/b", b"nor this", 7, 3),
                link("c", &data, 7, 3),
            ]),
        ),
    ];
    for (what, archive) in &cases {
        let scratch = Scratch::new();
        let out = scratch.out();
        let summary = extract(archive, &out, &Options::default()).unwrap();
        assert_eq!(summary.files, 4, "{what}");
        assert_eq!(
            listing(&out),
            ["a", "c", "dir/", "dir/b", "other"],
            "{what}"
        );
        for name in ["a", "dir/b", "c"] {
            assert!(read(&out.join(name)) == data, "{what}: {name}");
        }
        assert!(same_file(&out.join("a"), &out.join("dir/b")), "{what}");
        assert!(same_file(&out.join("a"), &out.join("c")), "{what}");
        // Copies, with Links::AsFile, counted as written.
        let scratch = Scratch::new();
        let summary = extract(
            archive,
            &scratch.out(),
            &options(|o| o.links = Links::AsFile),
        )
        .unwrap();
        assert_eq!(
            (summary.files, summary.bytes),
            (4, 3 * data.len() as u64 + 1),
            "{what}"
        );
        assert!(read(&scratch.out().join("dir/b")) == data, "{what}");
    }
    // Names of a file with no data at all.
    let archive = newc(&[link("a", b"", 9, 2), link("b", b"", 9, 2)]);
    let scratch = Scratch::new();
    let summary = extract(&archive, &scratch.out(), &Options::default()).unwrap();
    assert_eq!((summary.files, summary.bytes), (2, 0));
    assert_eq!(read(&scratch.out().join("b")), b"");
}

/// The limits count a file with several names once, at the size of the
/// data it holds, which comes with its last name: they stop it before
/// anything is written.
#[test]
fn a_file_s_data_on_its_last_name_counts_against_the_limits() {
    let data = vec![1u8; 5000];
    let archive = newc(&[link("a", b"", 7, 2), link("b", &data, 7, 2)]);
    let scratch = Scratch::new();
    let e = extract(
        &archive,
        &scratch.out(),
        &support::limits(|l: &mut Limits| l.max_entry_size = 4999),
    )
    .unwrap_err();
    assert!(matches!(e.kind, ErrorKind::EntryTooLarge), "{e}");
    assert_eq!(e.index, Some(0));
    assert!(!scratch.out().exists());
    let summary = extract(
        &archive,
        &scratch.out(),
        &support::limits(|l: &mut Limits| l.max_entry_size = 5000),
    )
    .unwrap();
    assert_eq!((summary.files, summary.bytes), (2, 5000));
}

#[test]
fn refused_names_write_nothing() {
    for (name, error) in [
        ("../evil", NameError::Dot),
        ("/etc/passwd", NameError::Absolute),
        ("a\\b", NameError::Backslash),
        ("con", NameError::Device),
    ] {
        let archive = newc(&[
            entry("good", What::File(b"fine")),
            entry(name, What::File(b"evil")),
        ]);
        let scratch = Scratch::new();
        let e = extract(&archive, &scratch.out(), &Options::default()).unwrap_err();
        assert!(
            matches!(e.kind, ErrorKind::Name(n) if n == error),
            "{name}: {e}"
        );
        assert!(!scratch.out().exists(), "{name}");
        // Skipped, the others are extracted.
        let summary = extract(
            &archive,
            &scratch.out(),
            &options(|o| o.on_refused = OnRefused::Skip),
        )
        .unwrap();
        assert_eq!(listing(&scratch.out()), ["good"], "{name}");
        assert_eq!(summary.skipped.len(), 1, "{name}");
    }
    // The same path twice, the second a hard link to the first by its own
    // name, as libarchive gives it (the fuzz target found it).
    let archive = newc(&[link("a", b"1", 7, 2), link("a", b"2", 7, 2)]);
    let scratch = Scratch::new();
    let e = extract(&archive, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Duplicate { first: 0 }), "{e}");
    assert!(!scratch.out().exists());
    let archive = newc(&[entry("a", What::File(b"1")), entry("A", What::File(b"2"))]);
    let scratch = Scratch::new();
    let e = extract(&archive, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Duplicate { first: 0 }), "{e}");
    assert!(!scratch.out().exists());
}

#[test]
fn links_and_devices_follow_the_options() {
    let archive = newc(&[
        entry("file", What::File(b"x")),
        entry("inside", What::Symlink(b"file")),
        entry("outside", What::Symlink(b"../../etc/passwd")),
    ]);
    let scratch = Scratch::new();
    let e = extract(&archive, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Link), "{e}");
    assert!(!scratch.out().exists());
    // As files, holding their targets.
    let scratch = Scratch::new();
    extract(
        &archive,
        &scratch.out(),
        &options(|o| o.links = Links::AsFile),
    )
    .unwrap();
    assert_eq!(read(&scratch.out().join("outside")), b"../../etc/passwd");
    // Inside: the one that stays is created, the other refused.
    #[cfg(unix)]
    {
        let scratch = Scratch::new();
        let e = extract(
            &archive,
            &scratch.out(),
            &options(|o| o.links = Links::Inside),
        )
        .unwrap_err();
        assert!(matches!(e.kind, ErrorKind::LinkTarget(_)), "{e}");
        let summary = extract(
            &archive,
            &scratch.out(),
            &options(|o| {
                o.links = Links::Inside;
                o.on_refused = OnRefused::Skip;
            }),
        )
        .unwrap();
        assert_eq!(summary.links, 1);
        assert_eq!(
            std::fs::read_link(scratch.out().join("inside")).unwrap(),
            Path::new("file")
        );
    }
    // Devices are not created.
    let archive = newc(&[
        entry("dev/console", What::Device),
        entry("init", What::File(b"x")),
    ]);
    let scratch = Scratch::new();
    let e = extract(&archive, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Special), "{e}");
    let summary = extract(
        &archive,
        &scratch.out(),
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();
    assert_eq!(listing(&scratch.out()), ["init"]);
    assert!(matches!(summary.skipped[0].kind, ErrorKind::Special));
}

#[test]
fn an_archive_cut_short_or_without_its_trailer_stops_before_writing() {
    let data = vec![3u8; 3000];
    let archive = newc(&[
        entry("a", What::File(b"first")),
        entry("b", What::File(&data)),
    ]);
    let trailer = archive.len() - 124;
    for cut in [archive.len() - 1000, trailer, 50] {
        let scratch = Scratch::new();
        let e = extract(&archive[..cut], &scratch.out(), &Options::default()).unwrap_err();
        assert!(matches!(e.kind, ErrorKind::Cpio(_)), "{cut}: {e}");
        assert!(!scratch.out().exists(), "{cut}");
    }
}

/// An entry found after garbage was passed over comes with libarchive's
/// warning, and is refused: what the garbage held is lost. libarchive's
/// search goes six bytes at a time through what cannot be a newc header,
/// and finds one only where it lands on it: after 18 bytes of garbage, not
/// after 16, where the archive then ends without its trailer.
#[test]
fn entries_after_garbage_are_refused() {
    let first = newc(&[entry("a", What::File(b"one"))]);
    let with_garbage = |garbage: &[u8]| {
        let mut archive = first[..first.len() - 124].to_vec();
        archive.extend(garbage);
        archive.extend(newc(&[entry("b", What::File(b"two"))]));
        archive
    };
    let scratch = Scratch::new();
    let e = extract(
        &with_garbage(b"some garbage!!!!"),
        &scratch.out(),
        &Options::default(),
    )
    .unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Cpio(_)), "{e}");
    let archive = with_garbage(b"some garbage!!!!!!");
    let e = extract(&archive, &scratch.out(), &Options::default()).unwrap_err();
    assert!(
        matches!(
            &e.kind,
            ErrorKind::CpioEntry(hivepack::cpio::Warning::Skipped { bytes: 18 })
        ),
        "{e}"
    );
    assert!(!scratch.out().exists());
    let summary = extract(
        &archive,
        &scratch.out(),
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();
    assert_eq!(listing(&scratch.out()), ["a"]);
    assert_eq!(summary.skipped.len(), 1);
}

#[test]
fn an_archive_that_changes_between_readings_stops() {
    let first = newc(&[entry("a", What::File(b"one"))]);
    let second = newc(&[entry("b", What::File(b"one"))]);
    let readings = Cell::new(0);
    let scratch = Scratch::new();
    let e = extract_cpio(
        || {
            readings.set(readings.get() + 1);
            Ok(Cursor::new(if readings.get() == 1 {
                first.clone()
            } else {
                second.clone()
            }))
        },
        &scratch.out(),
        &Options::default(),
    )
    .unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Changed), "{e}");
    assert_eq!(readings.get(), 2);
}

/// libarchive's cpio test archives, when the core sets are there
/// (`scripts/testdata.py fetch`): each extracted, or stopped with its
/// reason.
#[test]
fn libarchive_test_archives_extract_or_stop_with_their_reason() {
    let folder = support::testdata().join("libarchive-cpio");
    if !folder.join(".complete").exists() {
        assert!(!support::required("core"), "libarchive-cpio is missing");
        eprintln!("skipping: the libarchive-cpio set is not fetched");
        return;
    }
    let mut paths: Vec<_> = std::fs::read_dir(&folder)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "cpio"))
        .collect();
    paths.sort();
    assert!(paths.len() >= 10);
    for path in paths {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let archive = std::fs::read(&path).unwrap();
        let scratch = Scratch::new();
        let options = options(|o| {
            o.links = Links::AsFile;
            o.on_refused = OnRefused::Skip;
        });
        let outcome = match extract(&archive, &scratch.out(), &options) {
            Ok(summary) => format!("{} files, {} skipped", summary.files, summary.skipped.len()),
            Err(e) => format!("stopped: {e}"),
        };
        eprintln!("{name}: {outcome}");
        for path in listing(scratch.path()) {
            assert!(path.starts_with("out/") || path == "out/", "{name}: {path}");
        }
        // afio's test is two parts of one archive, each cut short.
        let cut = name.starts_with("cpio_afio_header");
        assert_eq!(outcome.starts_with("stopped"), cut, "{name}: {outcome}");
    }
}
