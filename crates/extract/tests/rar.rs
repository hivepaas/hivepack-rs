//! `extract_rar`: on real archives, what it writes is what `hivepack-rar` reads;
//! on patched copies of one, as nothing here writes RAR, the same rules as for
//! the other formats, and the archives behind RAR's CVEs made again.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

#[path = "../../rar/tests/support/patch.rs"]
#[allow(dead_code)]
mod patch;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hivepack_extract::{
    ErrorKind, Links, NameError, Names, OnRefused, Options, RarProblem, Summary, extract_rar,
};
use hivepack_rar::{Archive, Extract, HEAD_FILE, name};
use patch::{Entry, with_entries, with_entries15, with_quick_open};
use support::Scratch;

fn options(set: impl FnOnce(&mut Options)) -> Options {
    let mut options = Options::default();
    set(&mut options);
    options
}

fn extract(data: &[u8], out: &Path, options: &Options) -> Result<Summary, hivepack_extract::Error> {
    extract_rar(
        |password| Archive::open_with_password(data, false, password),
        out,
        options,
    )
}

fn read(path: PathBuf) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

#[test]
fn files_and_directories_come_out() {
    let data = with_entries(&[
        Entry::dir(b"a"),
        Entry::file(b"a/one.txt", b"one"),
        Entry::file(b"two.txt", b"two"),
    ]);
    let scratch = Scratch::new();
    let summary = extract(&data, &scratch.out(), &Options::default()).unwrap();
    assert_eq!(
        (summary.files, summary.directories, summary.bytes),
        (2, 1, 6)
    );
    assert_eq!(read(scratch.out().join("a/one.txt")), b"one");
    assert_eq!(read(scratch.out().join("two.txt")), b"two");
}

#[test]
fn rar_4_comes_out_too() {
    let data = with_entries15(&[Entry::dir(b"a"), Entry::file(b"a/one.txt", b"one")]);
    let scratch = Scratch::new();
    let summary = extract(&data, &scratch.out(), &Options::default()).unwrap();
    assert_eq!((summary.files, summary.directories), (1, 1));
    assert_eq!(read(scratch.out().join("a/one.txt")), b"one");
}

#[test]
fn names_are_refused_before_anything_is_written() {
    for (bad, reason) in [
        (&b"../up.txt"[..], NameError::Dot),
        (b"/etc/passwd", NameError::Absolute),
    ] {
        let data = with_entries(&[Entry::file(b"fine.txt", b"x"), Entry::file(bad, b"y")]);
        let scratch = Scratch::new();
        let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
        assert!(
            matches!(error.kind, ErrorKind::Name(e) if e == reason),
            "{error}"
        );
        assert_eq!(error.index, Some(1));
        assert!(!scratch.out().exists(), "{error}");
    }
}

#[test]
fn skipped_entries_leave_the_rest() {
    let data = with_entries(&[
        Entry::file(b"../up.txt", b"y"),
        Entry::file(b"fine.txt", b"x"),
    ]);
    let scratch = Scratch::new();
    let summary = extract(
        &data,
        &scratch.out(),
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();
    assert_eq!((summary.files, summary.skipped.len()), (1, 1));
    assert_eq!(read(scratch.out().join("fine.txt")), b"x");
    assert!(!scratch.out().join("up.txt").exists());
}

#[test]
fn one_path_twice_is_refused() {
    let data = with_entries(&[
        Entry::file(b"Same.txt", b"a"),
        Entry::file(b"same.TXT", b"b"),
    ]);
    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Duplicate { .. }), "{error}");
    assert!(!scratch.out().exists());
}

#[test]
fn a_hash_that_fails_removes_the_file() {
    let bad = Entry {
        bad_crc: true,
        ..Entry::file(b"bad.txt", b"data")
    };
    for data in [
        with_entries(&[Entry::file(b"good.txt", b"ok"), bad]),
        with_entries15(&[Entry::file(b"good.txt", b"ok"), bad]),
    ] {
        let scratch = Scratch::new();
        let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
        assert!(
            matches!(error.kind, ErrorKind::RarEntry(RarProblem::BrokenData)),
            "{error}"
        );
        assert_eq!(read(scratch.out().join("good.txt")), b"ok");
        assert!(!scratch.out().join("bad.txt").exists());
    }
}

#[test]
fn an_archive_cut_short_writes_nothing() {
    let data = with_entries(&[
        Entry::file(b"a.txt", b"aaaa"),
        Entry::file(b"b.txt", b"bbbb"),
    ]);
    // Into the second header: the first file alone would otherwise come out.
    for cut in [data.len() - 8 - 10, data.len() - 8 - 30] {
        let scratch = Scratch::new();
        let error = extract(&data[..cut], &scratch.out(), &Options::default()).unwrap_err();
        assert!(!scratch.out().exists(), "{error}");
    }
}

#[test]
fn limits_are_kept() {
    let data = with_entries(&[Entry::file(b"a.txt", &[7; 1000])]);
    let scratch = Scratch::new();
    let limited = options(|o| o.limits.max_entry_size = 100);
    let error = extract(&data, &scratch.out(), &limited).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::EntryTooLarge), "{error}");
    assert!(!scratch.out().exists());

    let scratch = Scratch::new();
    let limited = options(|o| o.limits.max_entries = 1);
    let two = with_entries(&[Entry::file(b"a", b"a"), Entry::file(b"b", b"b")]);
    let error = extract(&two, &scratch.out(), &limited).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::TooManyEntries), "{error}");
}

const SYMLINK: u64 = 1;
const JUNCTION: u64 = 3;
const HARD_LINK: u64 = 4;
const FILE_COPY: u64 = 5;

#[test]
fn links_are_refused_by_default() {
    let data = with_entries(&[Entry::redirect(b"link", SYMLINK, b"target")]);
    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Link), "{error}");
    assert!(!scratch.out().exists());
}

#[cfg(unix)]
#[test]
fn links_that_stay_inside_are_created() {
    let inside = options(|o| o.links = Links::Inside);
    for data in [
        with_entries(&[
            Entry::file(b"target", b"t"),
            Entry::redirect(b"link", SYMLINK, b"target"),
        ]),
        with_entries15(&[
            Entry::file(b"target", b"t"),
            Entry::redirect(b"link", SYMLINK, b"target"),
        ]),
    ] {
        let scratch = Scratch::new();
        let summary = extract(&data, &scratch.out(), &inside).unwrap();
        assert_eq!(summary.links, 1);
        assert_eq!(
            std::fs::read_link(scratch.out().join("link")).unwrap(),
            Path::new("target")
        );
    }
}

#[test]
fn links_that_leave_are_refused() {
    let inside = options(|o| o.links = Links::Inside);
    for target in [&b"../../etc/passwd"[..], b"/etc/passwd"] {
        for data in [
            with_entries(&[Entry::redirect(b"link", SYMLINK, target)]),
            with_entries15(&[Entry::redirect(b"link", SYMLINK, target)]),
        ] {
            let scratch = Scratch::new();
            let error = extract(&data, &scratch.out(), &inside).unwrap_err();
            assert!(matches!(error.kind, ErrorKind::LinkTarget(_)), "{error}");
            assert!(!scratch.out().exists(), "{error}");
        }
    }
}

#[test]
fn a_junction_to_elsewhere_is_refused() {
    let inside = options(|o| o.links = Links::Inside);
    let data = with_entries(&[Entry {
        unix: false,
        ..Entry::redirect(b"link", JUNCTION, b"\\??\\C:\\Windows")
    }]);
    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &inside).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::LinkTarget(_)), "{error}");
}

#[test]
fn a_link_as_a_file_holds_its_target() {
    let as_file = options(|o| o.links = Links::AsFile);
    for data in [
        with_entries(&[Entry::redirect(b"link", SYMLINK, b"../../outside")]),
        with_entries15(&[Entry::redirect(b"link", SYMLINK, b"../../outside")]),
    ] {
        let scratch = Scratch::new();
        extract(&data, &scratch.out(), &as_file).unwrap();
        assert_eq!(read(scratch.out().join("link")), b"../../outside");
    }
}

#[test]
fn a_copy_and_a_hard_link_need_a_file_before_them() {
    let inside = options(|o| o.links = Links::Inside);
    for kind in [HARD_LINK, FILE_COPY] {
        let data = with_entries(&[
            Entry::file(b"first", b"data"),
            Entry::redirect(b"second", kind, b"first"),
        ]);
        let scratch = Scratch::new();
        extract(&data, &scratch.out(), &inside).unwrap();
        assert_eq!(read(scratch.out().join("second")), b"data");

        let data = with_entries(&[
            Entry::redirect(b"second", kind, b"first"),
            Entry::file(b"first", b"data"),
        ]);
        let scratch = Scratch::new();
        let error = extract(&data, &scratch.out(), &inside).unwrap_err();
        assert!(matches!(error.kind, ErrorKind::HardLinkTarget), "{error}");
    }
}

// Found by the `extract_rar` target: a file copy writes, under any of the
// options, and what is said to be written must say so.
#[test]
fn what_is_to_be_written_counts_file_copies() {
    let data = with_entries(&[
        Entry::file(b"first", b"data"),
        Entry::redirect(b"copy", FILE_COPY, b"first"),
        Entry::redirect(b"copy2", FILE_COPY, b"copy"),
    ]);
    let last = std::sync::Arc::new(std::sync::Mutex::new((0, 0)));
    let seen = std::sync::Arc::clone(&last);
    let reporting = options(|o| {
        o.links = Links::Inside;
        o.progress = Some(std::sync::Arc::new(
            move |progress: &hivepack_extract::Progress| {
                assert!(progress.bytes <= progress.total_bytes, "{progress:?}");
                *seen.lock().unwrap() = (progress.bytes, progress.total_bytes);
            },
        ));
    });
    let scratch = Scratch::new();
    let summary = extract(&data, &scratch.out(), &reporting).unwrap();
    assert_eq!((summary.files, summary.bytes), (3, 12));
    assert_eq!(*last.lock().unwrap(), (12, 12));
}

#[test]
fn a_kind_of_link_not_known_is_refused() {
    let data = with_entries(&[Entry::redirect(b"odd", 99, b"x")]);
    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &options(|o| o.links = Links::Inside)).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Special), "{error}");
}

/// What a QuickOpen record says is what comes out, as with UnRAR's library: a
/// copy of the file's header saying a size of 5, where the header says 11.
#[test]
fn a_quick_open_record_is_what_is_read() {
    let data = with_quick_open(&[0, 1 | 14 << 3, 5]);
    let scratch = Scratch::new();
    let summary = extract(&data, &scratch.out(), &Options::default()).unwrap();
    assert_eq!((summary.files, summary.bytes), (1, 5));
    assert_eq!(read(scratch.out().join("helloworld.txt")), b"hello");
}

/// WinRAR's CVE-2025-8088: NTFS streams whose names climb with `..\` to the
/// Startup folder. As with ZIP's copy of it, in `cves.rs`: what a Windows RAR
/// says `\` for is a separator, and the colon or the climb is refused.
#[test]
fn cve_2025_8088_streams_that_climb() {
    let climb: &[u8] =
        b"CV.pdf:..\\..\\..\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk";
    for unix in [false, true] {
        let entries = [
            Entry {
                unix,
                ..Entry::file(b"CV.pdf", b"%PDF")
            },
            Entry {
                unix,
                ..Entry::file(climb, b"lnk")
            },
        ];
        for data in [with_entries(&entries), with_entries15(&entries)] {
            for names in [Names::Strict, Names::Sanitize] {
                let scratch = Scratch::new();
                let refused = options(|o| {
                    o.backslash_separator = true;
                    o.names = names;
                });
                let error = extract(&data, &scratch.out(), &refused).unwrap_err();
                assert!(matches!(error.kind, ErrorKind::Name(_)), "{error}");
                assert_eq!(error.index, Some(1));
                assert!(!scratch.out().exists());
            }
        }
    }
}

/// WinRAR's CVE-2025-6218: a name that climbs out of the destination with `..\`.
/// RAR 4 takes `\` for a separator, and RAR 5 from Unix keeps it, and the climb
/// or the backslash is refused. RAR 5 from Windows has `/` for a separator and
/// so `_` for any `\`, as UnRAR on Linux reads it: one file, inside.
#[test]
fn cve_2025_6218_a_path_that_climbs() {
    let climb: &[u8] =
        b"..\\..\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk";
    for unix in [false, true] {
        let entry = Entry {
            unix,
            ..Entry::file(climb, b"lnk")
        };
        for backslash_separator in [false, true] {
            let refused = options(|o| o.backslash_separator = backslash_separator);
            let scratch = Scratch::new();
            let error = extract(&with_entries15(&[entry]), &scratch.out(), &refused).unwrap_err();
            assert!(matches!(error.kind, ErrorKind::Name(_)), "{error}");
            assert!(!scratch.out().exists());

            let scratch = Scratch::new();
            let got = extract(&with_entries(&[entry]), &scratch.out(), &refused);
            if unix {
                let error = got.unwrap_err();
                assert!(matches!(error.kind, ErrorKind::Name(_)), "{error}");
                assert!(!scratch.out().exists());
            } else {
                assert_eq!(got.unwrap().files, 1);
                let names: Vec<String> = std::fs::read_dir(scratch.out())
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                    .collect();
                assert_eq!(
                    names,
                    [
                        ".._.._AppData_Roaming_Microsoft_Windows_Start Menu_Programs_Startup_evil.lnk"
                    ]
                );
            }
        }
    }
}

/// 7-Zip's CVE-2026-58052: streams over a file's mark of origin and its data,
/// which a RAR archive can hold too. The colon is refused; skipped, the file
/// alone is written.
#[test]
fn cve_2026_58052_streams_that_replace_the_mark() {
    let data = with_entries(&[
        Entry::file(b"a.exe", b"real"),
        Entry::file(
            b"a.exe:Zone.Identifier:$DATA",
            b"[ZoneTransfer]\r\nZoneId=0",
        ),
        Entry::file(b"a.exe::$DATA", b"evil"),
    ]);
    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::Name(NameError::Colon)),
        "{error}"
    );
    assert!(!scratch.out().exists());

    let scratch = Scratch::new();
    let summary = extract(
        &data,
        &scratch.out(),
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();
    assert_eq!((summary.files, summary.skipped.len()), (1, 2));
    assert_eq!(read(scratch.out().join("a.exe")), b"real");
}

/// WinRAR's CVE-2023-38831: a file and a folder of one name, which ZIP's copy
/// in `cves.rs` also goes through.
#[test]
fn cve_2023_38831_a_file_and_a_folder_of_one_name() {
    let data = with_entries(&[
        Entry::file(b"report.pdf ", b"bait"),
        Entry::file(b"report.pdf /report.pdf .cmd", b"evil"),
    ]);
    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Name(_)), "{error}");
    assert!(!scratch.out().exists());
}

/// The archives of other projects, whole, in the testdata when it is fetched.
fn archives() -> Vec<(String, PathBuf)> {
    fn walk(folder: &Path, found: &mut Vec<PathBuf>) {
        let Ok(read) = std::fs::read_dir(folder) else {
            return;
        };
        for entry in read.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    let root = support::testdata();
    for set in [
        "libarchive-rar",
        "rarfile-tests",
        "junrar-tests",
        "unrar-rs-tests",
    ] {
        walk(&root.join(set), &mut found);
    }
    found.sort();
    found
        .into_iter()
        .filter(|path| {
            let text = path.to_string_lossy();
            std::fs::metadata(path).is_ok_and(|m| m.len() < 8 << 20)
                && (text.ends_with(".rar") || text.ends_with(".exe") || text.ends_with(".sfx"))
        })
        .map(|path| (path.to_string_lossy().into_owned(), path))
        .collect()
}

/// What hivepack-rar's going through gives out for each file, by name, or
/// nothing if the archive has anything wrong.
fn as_read(data: &[u8], password: &str) -> Option<BTreeMap<String, Vec<u8>>> {
    let mut arc = Archive::open_with_password(data, false, password).ok()?;
    let mut extract = Extract::new();
    let mut files = BTreeMap::new();
    loop {
        let size = arc.read_header().ok()?;
        let is_file = size != 0
            && arc.cur_header_type == HEAD_FILE
            && !arc.file_head.dir
            && !arc.file_head.split_before;
        let named = name::to_string_lossy(&arc.file_head.file_name);
        let mut bytes = Vec::new();
        let go = extract
            .current_file(&mut arc, size, &mut |data| {
                bytes.extend_from_slice(data);
                Ok(())
            })
            .ok()?;
        if extract.broken_file {
            return None;
        }
        if is_file {
            files.insert(named, bytes);
        }
        if !go {
            break;
        }
    }
    (arc.exit_code() == hivepack_rar::ExitCode::Success).then_some(files)
}

/// On every archive at hand that reads whole: what is written is what is read,
/// or it is refused for a rule of this crate, with nothing written when that is
/// found in the checking. An archive that does not read whole writes nothing
/// that fails.
#[test]
fn real_archives_come_out_as_they_read() {
    let lenient = options(|o| {
        o.links = Links::AsFile;
        o.on_refused = OnRefused::Skip;
        o.limits.max_ratio = u64::MAX;
    });
    let mut compared = 0;
    let mut files = 0;
    for (label, path) in archives() {
        let data = std::fs::read(&path).unwrap();
        // The projects' own passwords, with none first.
        for password in ["", "password", "junrar", "test", "rar", "1234"] {
            let with_password = options(|o| {
                o.links = lenient.links;
                o.on_refused = lenient.on_refused;
                o.limits.max_ratio = u64::MAX;
                o.password = (!password.is_empty()).then(|| password.as_bytes().to_vec());
            });
            let scratch = Scratch::new();
            let got = extract(&data, &scratch.out(), &with_password);
            let want = as_read(&data, password);
            match (got, want) {
                (Ok(summary), Some(want)) => {
                    let skipped: Vec<String> = summary
                        .skipped
                        .iter()
                        .filter_map(|e| e.name.as_ref())
                        .map(|name| String::from_utf8_lossy(name).into_owned())
                        .collect();
                    for (name, bytes) in &want {
                        if skipped.contains(name) {
                            continue;
                        }
                        let on_disk = scratch.out().join(name.replace('\\', "/"));
                        if on_disk.symlink_metadata().is_ok_and(|m| m.is_file())
                            && !bytes.is_empty()
                        {
                            assert_eq!(&read(on_disk), bytes, "{label}: {name}");
                            files += 1;
                        }
                    }
                    compared += 1;
                    break;
                }
                // Refused here, as a limit or a rule, or a wrong password.
                (Err(_), _) => {}
                // Reads with this password or none, and nothing written failed.
                (Ok(_), None) => {}
            }
        }
    }
    eprintln!("{compared} archives extracted as read, {files} files compared");
    // libarchive's archives alone give 44 and 97: Windows has only those, as
    // the other projects' come with the group it does not fetch.
    if !archives().is_empty() {
        assert!(compared >= 40, "only {compared}");
        assert!(files >= 90, "only {files}");
    }
}
