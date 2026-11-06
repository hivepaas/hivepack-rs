//! Extracting 7z archives that hivepack::sevenz opens: the archives of
//! `testdata/7z`, made by `tools/7z-archives/make.sh` with 7-Zip's `7zz`
//! (LZMA2 solid, Deflate a folder a file, stored, BCJ2, AES on the data
//! and on the headers, links, two names of one path, a setuid program),
//! extracted to the files they were made of; and the stored one changed
//! where it is: a name that climbs out, data that fails its CRC. Nothing
//! may be left outside the destination, and nothing at all when the
//! checks before writing stop it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "extract_support/mod.rs"]
mod support;

use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use hivepack::extract::{
    ErrorKind, LinkOutside, Links, NameError, OnLinksOutside, OnRefused, Options, Progress,
    Summary, extract_7z,
};
use hivepack::sevenz::Archive;
use support::{Scratch, listing, options};

/// When the files were last changed: 2026-09-01 12:00 UTC.
const MTIME: u64 = 1_788_264_000;

const NOTES: &[u8] = b"Notes from inside the archive.\n";

/// The archive `testdata/7z/<name>`.
fn archive(name: &str) -> Vec<u8> {
    std::fs::read(support::repository().join("testdata/7z").join(name)).unwrap()
}

/// `pattern.bin`: bytes of a pattern, as `make.sh` writes them.
fn pattern() -> Vec<u8> {
    (0..70_000u32).map(|i| ((i * 7) % 251) as u8).collect()
}

fn extract(
    data: &[u8],
    out: &Path,
    options: &Options,
) -> Result<Summary, hivepack::extract::Error> {
    let mut archive = Archive::open(Cursor::new(data.to_vec())).unwrap();
    extract_7z(&mut archive, out, options)
}

/// What every archive of the usual files must extract to.
fn check_files(out: &Path, what: &str) {
    assert_eq!(
        listing(out),
        [
            "café.txt",
            "docs/",
            "docs/notes.txt",
            "docs/plans/",
            "docs/plans/pattern.bin",
            "empty",
            "empty folder/",
            "readme.md",
            "run.sh",
        ],
        "{what}"
    );
    assert_eq!(
        std::fs::read(out.join("docs/notes.txt")).unwrap(),
        NOTES,
        "{what}"
    );
    assert_eq!(
        std::fs::read(out.join("docs/plans/pattern.bin")).unwrap(),
        pattern(),
        "{what}"
    );
    assert_eq!(
        std::fs::read(out.join("readme.md")).unwrap(),
        b"# Read me\n",
        "{what}"
    );
    assert_eq!(
        std::fs::read(out.join("café.txt")).unwrap(),
        "café\n".as_bytes(),
        "{what}"
    );
    assert!(
        std::fs::read(out.join("empty")).unwrap().is_empty(),
        "{what}"
    );
    let modified = std::fs::metadata(out.join("readme.md"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(modified, UNIX_EPOCH + Duration::from_secs(MTIME), "{what}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &str| std::fs::metadata(out.join(p)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode("run.sh"), 0o755, "{what}");
        assert_eq!(mode("readme.md"), 0o644, "{what}");
    }
}

#[test]
fn archives_extract_to_their_files() {
    for name in ["plain.7z", "deflate.7z", "stored.7z", "bcj2.7z"] {
        let scratch = Scratch::new();
        let out = scratch.out();
        let summary =
            extract(&archive(name), &out, &portable()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            (summary.files, summary.directories, summary.links),
            (6, 3, 0),
            "{name}"
        );
        assert_eq!(
            summary.bytes,
            (NOTES.len() + 70_000 + 10 + 19 + 6) as u64,
            "{name}"
        );
        check_files(&out, name);
        for path in listing(scratch.path()) {
            assert!(path.starts_with("out/") || path == "out/", "{name}: {path}");
        }
    }
}

#[test]
fn progress_counts_what_is_written() {
    let scratch = Scratch::new();
    let last = Arc::new(Mutex::new(Progress::default()));
    let seen = Arc::clone(&last);
    let options = options(|o| {
        o.progress = Some(Arc::new(move |p: &Progress| *seen.lock().unwrap() = *p));
    });
    extract(&archive("plain.7z"), &scratch.out(), &options).unwrap();
    let p = *last.lock().unwrap();
    assert_eq!((p.entries, p.total_entries), (9, 9));
    assert_eq!(p.bytes, p.total_bytes);
    assert_eq!(p.bytes, (NOTES.len() + 70_000 + 10 + 19 + 6) as u64);
}

#[test]
fn encrypted_archives_need_their_password() {
    // The data encrypted, the names not: it opens, and the password is
    // the extraction's.
    let data = archive("encrypted.7z");
    let scratch = Scratch::new();
    let e = extract(&data, &scratch.out(), &portable()).unwrap_err();
    assert!(
        matches!(
            e.kind,
            ErrorKind::SevenZip(hivepack::sevenz::Error::PasswordRequired)
        ),
        "{e}"
    );
    // What has no data comes first, and is written; the file whose data
    // failed is removed, and nothing after it is written.
    assert_eq!(e.name.as_deref(), Some("café.txt".as_bytes()));
    assert_eq!(
        listing(&scratch.out()),
        ["docs/", "docs/plans/", "empty", "empty folder/"]
    );
    let wrong = options(|o| o.password = Some(b"wrong".to_vec()));
    let e = extract(&data, &Scratch::new().out(), &wrong).unwrap_err();
    assert!(
        matches!(
            e.kind,
            ErrorKind::SevenZip(hivepack::sevenz::Error::WrongPassword)
        ),
        "{e}"
    );
    let right = options(|o| o.password = Some(b"secret".to_vec()));
    let scratch = Scratch::new();
    extract(&data, &scratch.out(), &right).unwrap();
    check_files(&scratch.out(), "encrypted.7z");

    // The headers encrypted too: the password is the opening's.
    let data = archive("encrypted-headers.7z");
    assert_eq!(
        Archive::open(Cursor::new(data.clone())).err(),
        Some(hivepack::sevenz::Error::PasswordRequired)
    );
    let opening = hivepack::sevenz::Options {
        password: Some("secret".into()),
        ..hivepack::sevenz::Options::default()
    };
    let mut opened = Archive::open_with(Cursor::new(data), &opening).unwrap();
    let scratch = Scratch::new();
    extract_7z(&mut opened, &scratch.out(), &portable()).unwrap();
    check_files(&scratch.out(), "encrypted-headers.7z");
}

#[test]
fn links_are_refused_written_as_files_or_kept_inside() {
    let data = archive("links.7z");
    // By default the first link stops it, before anything is written.
    let scratch = Scratch::new();
    let e = extract(&data, &scratch.out(), &portable()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Link), "{e}");
    assert_eq!(e.name.as_deref(), Some(&b"docs/link"[..]));
    assert!(!scratch.out().exists());

    // As files holding their targets.
    let scratch = Scratch::new();
    let out = scratch.out();
    let summary = extract(&data, &out, &options(|o| o.links = Links::AsFile)).unwrap();
    assert_eq!((summary.files, summary.links), (3, 0));
    assert_eq!(std::fs::read(out.join("docs/link")).unwrap(), b"notes.txt");
    assert_eq!(
        std::fs::read(out.join("escape")).unwrap(),
        b"../../etc/passwd"
    );

    // Inside: the one that stays is created, the one that climbs refused.
    if cfg!(unix) {
        let inside = options(|o| o.links = Links::Inside);
        let e = extract(&data, &Scratch::new().out(), &inside).unwrap_err();
        assert!(
            matches!(e.kind, ErrorKind::LinkTarget(NameError::Dot)),
            "{e}"
        );
        let scratch = Scratch::new();
        let out = scratch.out();
        let skip = options(|o| {
            o.links = Links::Inside;
            o.on_refused = OnRefused::Skip;
        });
        let summary = extract(&data, &out, &skip).unwrap();
        assert_eq!(
            (summary.files, summary.links, summary.skipped.len()),
            (1, 1, 1)
        );
        assert_eq!(summary.skipped[0].name.as_deref(), Some(&b"escape"[..]));
        assert_eq!(
            std::fs::read_link(out.join("docs/link")).unwrap(),
            Path::new("notes.txt")
        );
        assert_eq!(std::fs::read(out.join("docs/link")).unwrap(), NOTES);
        assert!(!out.join("escape").exists());

        // Anywhere, or asked about and created: both, as the archive has them.
        let any = options(|o| o.links = Links::Any);
        let asked = Arc::new(Mutex::new(Vec::new()));
        let told = Arc::clone(&asked);
        let create = options(|o| {
            o.links = Links::Inside;
            o.on_links_outside = Some(Arc::new(move |links: &[LinkOutside]| {
                told.lock()
                    .unwrap()
                    .extend(links.iter().map(|l| l.target.clone()));
                OnLinksOutside::Create
            }));
        });
        for options in [any, create] {
            let scratch = Scratch::new();
            let out = scratch.out();
            let summary = extract(&data, &out, &options).unwrap();
            assert_eq!((summary.files, summary.links), (1, 2));
            assert_eq!(
                std::fs::read_link(out.join("escape")).unwrap(),
                Path::new("../../etc/passwd")
            );
        }
        assert_eq!(*asked.lock().unwrap(), ["../../etc/passwd"]);
    }
}

#[test]
fn two_names_of_one_path_are_refused() {
    let scratch = Scratch::new();
    let e = extract(&archive("cases.7z"), &scratch.out(), &portable()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Duplicate { first: 0 }), "{e}");
    assert!(!scratch.out().exists());
}

#[cfg(unix)]
#[test]
fn setuid_bits_are_not_kept() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new();
    extract(&archive("modes.7z"), &scratch.out(), &portable()).unwrap();
    let mode = std::fs::metadata(scratch.out().join("setuid.sh"))
        .unwrap()
        .permissions()
        .mode();
    // rwsrwxr-x, masked: no setuid bit, nothing writable by the group.
    assert_eq!(mode & 0o7777, 0o755);
}

/// `stored.7z` with `from` changed to `to` in its names, which are UTF-16
/// in its headers, not compressed; the headers' CRCs made right again.
fn renamed(from: &str, to: &str) -> Vec<u8> {
    assert_eq!(from.len(), to.len());
    let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
    let (from, to) = (utf16(from), utf16(to));
    let mut data = archive("stored.7z");
    let at = data.windows(from.len()).position(|w| w == from).unwrap();
    data[at..at + to.len()].copy_from_slice(&to);
    let le64 = |b: &[u8], at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap()) as usize;
    let header = 32 + le64(&data, 12);
    let size = le64(&data, 20);
    let crc = hivepack::deflate::crc32(0, &data[header..header + size]);
    data[28..32].copy_from_slice(&crc.to_le_bytes());
    let crc = hivepack::deflate::crc32(0, &data[12..32]);
    data[8..12].copy_from_slice(&crc.to_le_bytes());
    data
}

#[test]
fn names_that_climb_out_are_refused_before_writing() {
    // `readme.md` becomes `../dme.md`: as long in UTF-16.
    let data = renamed("readme.md", "../dme.md");
    let scratch = Scratch::new();
    let e = extract(&data, &scratch.out(), &portable()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Name(NameError::Dot)), "{e}");
    assert!(!scratch.out().exists());
    // Skipped, the rest is written, and nothing outside.
    let skip = options(|o| o.on_refused = OnRefused::Skip);
    let summary = extract(&data, &scratch.out(), &skip).unwrap();
    assert_eq!((summary.files, summary.skipped.len()), (5, 1));
    for path in listing(scratch.path()) {
        assert!(path.starts_with("out/") || path == "out/", "{path}");
    }
}

#[test]
fn data_that_fails_its_crc_is_removed() {
    // A byte of the stored notes changed: its CRC fails when it ends.
    let mut data = archive("stored.7z");
    let at = data.windows(NOTES.len()).position(|w| w == NOTES).unwrap();
    data[at] = b'M';
    let scratch = Scratch::new();
    let out = scratch.out();
    let e = extract(&data, &out, &portable()).unwrap_err();
    assert!(
        matches!(e.kind, ErrorKind::SevenZip(hivepack::sevenz::Error::Crc)),
        "{e}"
    );
    assert_eq!(e.name.as_deref(), Some(&b"docs/notes.txt"[..]));
    assert!(!out.join("docs/notes.txt").exists());
}

#[test]
fn the_limits_hold() {
    let data = archive("plain.7z");
    // What the headers say, before anything is written.
    let scratch = Scratch::new();
    let small = support::limits(|l| l.max_entry_size = 1000);
    let e = extract(&data, &scratch.out(), &small).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::EntryTooLarge), "{e}");
    assert!(!scratch.out().exists());
    let few = support::limits(|l| l.max_entries = 3);
    let e = extract(&data, &Scratch::new().out(), &few).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::TooManyEntries), "{e}");
    // The pattern against its share of the solid folder's packed data:
    // far more than 2 to 1.
    let tight = support::limits(|l| {
        l.max_ratio = 2;
        l.ratio_threshold = 1000;
    });
    let scratch = Scratch::new();
    let e = extract(&data, &scratch.out(), &tight).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Ratio), "{e}");
    assert!(!scratch.out().join("docs/plans/pattern.bin").exists());
}

#[test]
fn nothing_is_overwritten() {
    let scratch = Scratch::new();
    let out = scratch.out();
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("readme.md"), b"mine").unwrap();
    let e = extract(&archive("plain.7z"), &out, &portable()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Exists), "{e}");
    assert_eq!(std::fs::read(out.join("readme.md")).unwrap(), b"mine");
}

/// Every archive of `testdata/7z` damaged many ways (a byte changed, cut
/// short), each extracted with each choice of links, skipping or not:
/// never a panic, nothing outside the destination, and no file left cut
/// off, as the `extract_7z` fuzz target checks.
#[test]
fn damaged_archives_write_nothing_cut_off() {
    let names = [
        "plain.7z",
        "deflate.7z",
        "stored.7z",
        "bcj2.7z",
        "encrypted.7z",
        "links.7z",
    ];
    // xorshift64*, so that a failure can be replayed.
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_f491_4f6c_dd1d)
    };
    let opening = hivepack::sevenz::Options {
        memory_limit: 1 << 26,
        decoder_memory_limit: 1 << 26,
        password: Some("secret".into()),
        max_key_cycles: 20,
    };
    for name in names {
        let good = archive(name);
        for round in 0..40 {
            let mut bad = good.clone();
            if round % 4 == 3 {
                bad.truncate((next() % bad.len() as u64) as usize);
            } else {
                let at = (next() % bad.len() as u64) as usize;
                bad[at] ^= 1 << (next() % 8);
            }
            let Ok(mut opened) = Archive::open_with(Cursor::new(bad.clone()), &opening) else {
                continue;
            };
            let links = [Links::Refuse, Links::AsFile, Links::Inside, Links::Any][(round / 2) % 4];
            let skip = if round % 2 == 0 {
                OnRefused::Stop
            } else {
                OnRefused::Skip
            };
            let scratch = Scratch::new();
            let out = scratch.out();
            let last = Arc::new(Mutex::new((0u64, 0u64)));
            let seen = Arc::clone(&last);
            let options = options(|o| {
                o.links = if cfg!(unix) { links } else { Links::AsFile };
                o.on_refused = skip;
                o.progress = Some(Arc::new(move |p: &Progress| {
                    let mut seen = seen.lock().unwrap();
                    if p.entries > seen.0 {
                        *seen = (p.entries, p.bytes);
                    }
                }));
            });
            let result = extract_7z(&mut opened, &out, &options);
            for path in listing(scratch.path()) {
                assert!(
                    path.starts_with("out/") || path == "out/",
                    "{name} {round}: {path}"
                );
            }
            let on_disk: u64 = listing(&out)
                .iter()
                .filter(|p| !p.ends_with('/'))
                .map(|p| std::fs::symlink_metadata(out.join(p)).unwrap())
                .filter(|m| m.is_file())
                .map(|m| m.len())
                .sum();
            assert_eq!(
                on_disk,
                last.lock().unwrap().1,
                "{name} {round}: {result:?}"
            );
        }
    }
}

#[test]
fn cancelled_before_it_starts() {
    let cancel = hivepack::extract::Cancel::new();
    cancel.cancel();
    let scratch = Scratch::new();
    let cancelled = options(|o| o.cancel = Some(cancel));
    let e = extract(&archive("plain.7z"), &scratch.out(), &cancelled).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Cancelled), "{e}");
    assert!(!scratch.out().exists());
}

/// The options of these tests: names checked by every system's rules, as Windows
/// and a case-insensitive file system have them, wherever the tests run.
fn portable() -> hivepack::extract::Options {
    let mut options = hivepack::extract::Options::default();
    options.name_rules = hivepack::extract::NameRules::Portable;
    options
}
